"""
DÜRÜST-TARAMA testleri — "boş tarama ≠ temiz tarama" sözleşmesi.

NEDEN: Kullanıcının yaşadığı tutarsızlığın kökleri:
1) Ölü hedef nmap'te 'completed, 0 port' → sessiz boş tarama → 'temiz' yalanı.
2) Standart-dışı HTTP portunda (3000/9200/...) canlı web servisi → has_http YANLIŞ
   → uygulama katmanı (nuclei web-yüzeyi/DAST/raid) HİÇ doğmuyordu.
3) Recon teknoloji tespiti boş dönünce web-surface nuclei + crawl kenarı doğmuyordu.
4) CWE-78 (RCE) bulgusunun deterministik doğrulayıcısı yoktu → hep 'unconfirmed'.
5) path_probe redirect'i dış host'a takip ediyor → kapsam dışı kanıt kirletiyordu.

Bu testler yukarıdaki düzeltmelerin ÇEKİRDEK kararlarını pinler (I/O'suz + MockTransport).

Çalıştır: python3 orchestrator/pipeline/test_honest_scan.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx

from pipeline.verification import verify_rce, classify_evidence_class, evidence_meta_for
from pipeline.attack_hypothesis import VERIFIABLE_CLASSES, _normalize_class
from pipeline.autonomous_engine import resolve_level, SCAN_LEVELS
from pipeline.attack_graph import Graph, COMMON_HTTP_PORTS
from pipeline.path_probe import _scope_guard_hook, _OutOfScopeRedirect


# ---- 1) RCE echo-marker doğrulayıcı (MockTransport ile in-band kanıt) ----

class _EchoCmdApp:
    """Vulnerable sahte hedef: 'q' parametresini kabuğa verir — `; echo X` çalışır,
    çıktı gövdeye yansır. Diğer parametreler yansıtmaz."""

    def __init__(self, vulnerable: bool = True):
        self.vulnerable = vulnerable
        self.hits = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(str(request.url)).query)
        val = (q.get("q") or [""])[0]
        if self.vulnerable and ";echo" in val:
            marker = val.split("echo", 1)[1].strip()
            self.hits.append(val)
            return httpx.Response(200, text=f"output: {marker}")
        return httpx.Response(200, text="sayfa içeriği — komut yok")


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(app))


def test_rce_confirmed_by_echo_marker():
    app = _EchoCmdApp(vulnerable=True)
    v = asyncio.run(verify_rce("https://victim.test/x?q=1", None, _client(app)))
    assert v.verified is True, v
    assert v.severity == "critical"
    assert "TEYİT" in v.detail
    assert v.method == "rce-echo"


def test_rce_not_confirmed_when_clean():
    app = _EchoCmdApp(vulnerable=False)
    v = asyncio.run(verify_rce("https://victim.test/x?q=1", None, _client(app)))
    assert v.verified is False
    assert v.skipped is False  # denendi, kanıt yok — FP elendi


def test_rce_skipped_without_params():
    v = asyncio.run(verify_rce("https://victim.test/x", None, _client(_EchoCmdApp())))
    assert v.verified is False
    assert v.skipped is True


def test_rce_class_mapping():
    """CWE-78/77 + başlık anahtar kelimeleri → 'rce' sınıfı (artık doğrulanabilir)."""
    assert classify_evidence_class({"cwe": ["CWE-78"]}) == "rce"
    assert classify_evidence_class({"cwe": ["CWE-77"]}) == "rce"
    assert classify_evidence_class({"title": "Remote Code Execution in cmd"}) == "rce"
    assert classify_evidence_class({"title": "OS Command Injection"}) == "rce"
    assert "rce" in VERIFIABLE_CLASSES
    assert _normalize_class("command-injection") == "rce"
    assert _normalize_class("remote code execution") == "rce"
    meta = evidence_meta_for("rce")
    assert meta["severity"] == "critical" and "CWE-78" in meta["cwe"]


# ---- 2) has_http: standart-dışı HTTP portları artık web sayılır ----

def test_common_http_ports_cover_modern_stacks():
    for p in (3000, 5000, 5601, 7001, 9090, 9200, 15672, 2375, 8500, 10250, 9000):
        assert p in COMMON_HTTP_PORTS, f"{p} eksik — Grafana/Node/Kibana/WebLogic/ES yüzeyi kör kalır"
    for p in (80, 443, 8080, 8443, 8000, 8888):
        assert p in COMMON_HTTP_PORTS


def test_nmap_port_3000_seeds_web_surface():
    """Port 3000 açık (ad tanınamadı) → eski liste web YOK derdi; yeni liste
    nuclei web-yüzeyi + pathprobe raid kenarı doğar → 'port açık ama taranmadı'
    tutarsızlığı ölür. Graf integrate gerçek sözleşmedir (unit: kenar var mı)."""
    g = Graph("victim.test", False)
    g.integrate(_fake_decision(), {
        "open_ports": [3000],
        "services": [{"port": 3000, "protocol": "tcp", "service": "unknown",
                      "product": "", "version": "", "state": "open"}],
    }, tool="nmap")
    tools = {e.tool for e in g.edges.values()}
    assert "nuclei" in tools, "port 3000'te web taraması seed edilmeli (has_http güvenlik ağı)"
    raid = any(e.tool == "pathprobe" for e in g.edges.values())
    assert raid, "pathprobe raid ( hassas yol güvenlik ağı) has_http ile seed edilmeli"


def _fake_decision():
    class _D:
        options = {}
    return _D()


# ---- 3) Recon teknoloji tespiti BOŞ olsa bile web kenarları doğar ----

def test_recon_empty_tech_still_seeds_web_and_crawl():
    g = Graph("victim.test", False)
    g.integrate(_fake_decision(), {
        "technologies": [], "subdomains": [],
    }, tool="recon")
    nuclei_web = [e for e in g.edges.values()
                  if e.tool == "nuclei" and e.from_id == g.root_id]
    crawl = [e for e in g.edges.values() if e.tool == "crawl"]
    assert nuclei_web, "recon completed + tech boş → web-yüzeyi nuclei kenarı YİNE doğmalı"
    assert crawl, "recon completed + tech boş → crawl kenarı YİNE doğmalı (URL corpus kaynağı)"


def test_recon_with_tech_seeds_dast_too():
    g = Graph("victim.test", False)
    g.integrate(_fake_decision(), {
        "technologies": ["WordPress"], "subdomains": [],
    }, tool="recon")
    tools = {e.tool for e in g.edges.values()}
    assert "nuclei" in tools and "crawl" in tools
    dast = any(e.tool == "nuclei" and e.options.get("dast") for e in g.edges.values())
    assert dast, "teknoloji biliniyorsa DAST kenarı da doğmalı"


# ---- 4) STANDARD_ALLOW_FUZZ operatör kapısı ----

def test_standard_level_fuzz_env_gate():
    os.environ.pop("STANDARD_ALLOW_FUZZ", None)
    lvl = resolve_level("standard")
    assert lvl.allow_fuzz is False, "varsayılan: dizin fuzz kapalı (gürültü doktrini)"
    os.environ["STANDARD_ALLOW_FUZZ"] = "1"
    try:
        lvl_on = resolve_level("standard")
        assert lvl_on.allow_fuzz is True
        assert "dizin fuzz" in lvl_on.label
    finally:
        os.environ.pop("STANDARD_ALLOW_FUZZ", None)
    # deep her koşulda açık; recon hiçbir env ile açılmaz
    assert resolve_level("deep").allow_fuzz is True
    os.environ["STANDARD_ALLOW_FUZZ"] = "1"
    try:
        assert resolve_level("recon").allow_fuzz is False, "kapı yalnız 'standard'ı yükseltir"
    finally:
        os.environ.pop("STANDARD_ALLOW_FUZZ", None)
    assert resolve_level("bozum-ka-level").name == SCAN_LEVELS["standard"].name


# ---- 5) path_probe redirect kapsam koruması ----

class _FakeURL:
    def __init__(self, host):
        self.host = host


class _FakeReq:
    def __init__(self, host):
        self.url = _FakeURL(host)


class _FakeResp:
    def __init__(self, host):
        self.request = _FakeReq(host)


def test_scope_guard_same_host_and_subdomain_pass():
    hook = _scope_guard_hook("victim.test")
    hook(_FakeResp("victim.test"))       # aynı host → sessiz
    hook(_FakeResp("app.victim.test"))   # alt domain → sessiz


def test_scope_guard_external_host_blocked():
    hook = _scope_guard_hook("victim.test")
    try:
        hook(_FakeResp("evil-cdn.example"))
        raise AssertionError("dış host redirect'i kesilmeliydi (_OutOfScopeRedirect beklenir)")
    except _OutOfScopeRedirect:
        pass  # doğru davranış


def test_scope_guard_empty_target_noop():
    _scope_guard_hook("")(_FakeResp("herhangi.com"))  # hedef yok → kural yok, patlamaz


# ---- 6) stage_health (degraded) — 'failed'/'timeout' görünür kalır ----

def test_degraded_statuses():
    from pipeline.stage_health import is_degraded
    assert is_degraded("failed") and is_degraded("timeout")
    assert not is_degraded("completed") and not is_degraded(None)
    assert not is_degraded("skipped")


def main():
    tests = [
        test_rce_confirmed_by_echo_marker,
        test_rce_not_confirmed_when_clean,
        test_rce_skipped_without_params,
        test_rce_class_mapping,
        test_common_http_ports_cover_modern_stacks,
        test_nmap_port_3000_seeds_web_surface,
        test_recon_empty_tech_still_seeds_web_and_crawl,
        test_recon_with_tech_seeds_dast_too,
        test_standard_level_fuzz_env_gate,
        test_scope_guard_same_host_and_subdomain_pass,
        test_scope_guard_external_host_blocked,
        test_scope_guard_empty_target_noop,
        test_degraded_statuses,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm dürüst-tarama testleri geçti.")


if __name__ == "__main__":
    main()
