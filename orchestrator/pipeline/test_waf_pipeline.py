"""
Kadim Güvenlik — WAF orkestrasyon (keşif-sonrası, host-bazlı) testleri.

waf_detect'in imza çekirdeği ayrı test edilir (test_waf_detect.py). Bu dosya PIPELINE
katmanını sınar: _web_origins_for_waf'ın grafı doğru okuması, _fingerprint_waf_origin'in
profili session'a yazıp engine.waf_profile'ı ayarlaması + host-bazlı dedup, ve
_maybe_fingerprint_waf'ın kendi client'ıyla uçtan uca çalışması. Ağ YOK — httpx.MockTransport
ile sahte WAF yanıtı verilir. Repo konvansiyonu: düz script (pytest yok).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import pipeline.scan_pipeline_v2 as spv  # noqa: E402
from pipeline.scan_pipeline_v2 import ScanPipelineV2, PipelineSession  # noqa: E402


# ---- Sahte graf/engine iskeleti (yalnız WAF yolunun okuduğu alanlar) ----
class _Edge:
    def __init__(self, tool, options=None):
        self.tool = tool
        self.options = options or {}


class _Graph:
    def __init__(self, edges):
        self.edges = {str(i): e for i, e in enumerate(edges)}


class _Level:
    def __init__(self, name):
        self.name = name


class _Engine:
    def __init__(self, target, edges, level="standard"):
        self.target = target
        self.graph = _Graph(edges)
        self.level = _Level(level)
        self.waf_profile = None
        self.waf_by_origin = {}


def _session():
    return PipelineSession(session_id="s1", scan_id="sc1", target="victim.test",
                           profile_name="autonomous")


async def _noop_narrate(*a, **k):
    return None


def _fortiweb_handler(request):
    # FortiWeb'in karakteristik cookie'si → yüksek güvenli vendor tespiti.
    return httpx.Response(200, headers={"set-cookie": "FORTIWAFSID=0123abc; path=/"},
                          text="<html>ok</html>")


def _clean_handler(request):
    # İmzasız temiz yanıt → WAF tespit edilmez (None).
    return httpx.Response(200, headers={"server": "nginx"}, text="<html>hi</html>")


# ============================================================
def test_web_origins_from_graph():
    """Yalnız web-app kenarları (crawl / nuclei-dast / nuclei-cve_sweep) origin üretir;
    pathprobe/nmap/recon üretmez. scan_target verilmişse per-host, yoksa kök hedef."""
    pipe = ScanPipelineV2(None)
    eng = _Engine("victim.test", [
        _Edge("crawl", {}),                                   # kök web → victim.test
        _Edge("nuclei", {"dast": True, "scan_target": "app.victim.test"}),  # per-host
        _Edge("nuclei", {"cve_sweep": True}),                 # kök → victim.test (tekrar)
        _Edge("pathprobe", {"scan_target": "10.0.0.5"}),      # iç host → SAYILMAZ
        _Edge("nmap", {}),                                    # SAYILMAZ
        _Edge("nuclei", {"tags": ["nginx"]}),                 # sadece tag → SAYILMAZ
    ])
    origins = pipe._web_origins_for_waf(eng)
    assert "victim.test" in origins, origins
    assert "app.victim.test" in origins, origins
    assert "10.0.0.5" not in origins, origins
    assert len(origins) == 2, origins
    print("[OK] test_web_origins_from_graph")


def test_fingerprint_detects_and_writes():
    """detect_waf FortiWeb bulursa: engine.waf_profile set, session.ai_analysis['waf'] +
    waf_by_host yazılır, olay yayınlanır."""
    async def run():
        pipe = ScanPipelineV2(None)
        eng = _Engine("victim.test", [])
        sess = _session()
        events = []

        async def narrate(etype, msg, data=None, **k):
            events.append((msg, data))

        client = httpx.AsyncClient(transport=httpx.MockTransport(_fortiweb_handler))
        prof = await pipe._fingerprint_waf_origin(sess, eng, narrate, client,
                                                  "victim.test", active=True)
        await client.aclose()
        assert prof is not None and prof.vendor == "fortiweb", prof
        assert eng.waf_profile is prof, "birincil profil ayarlanmadı"
        assert sess.ai_analysis.get("waf", {}).get("vendor") == "fortiweb"
        assert "victim.test" in sess.ai_analysis.get("waf_by_host", {})
        assert eng.waf_by_origin.get("victim.test") is prof, "önbelleğe yazılmadı"
        assert any("WAF tespit" in m for m, _ in events), "olay yayınlanmadı"
    asyncio.run(run())
    print("[OK] test_fingerprint_detects_and_writes")


def test_fingerprint_host_dedup():
    """Aynı host farklı URL biçimiyle gelse bile İKİNCİ kez ağa çıkılmaz (host-bazlı cache).
    İkinci çağrı önbellekten döner; sayaç bir kez artar."""
    calls = {"n": 0}

    def counting_handler(request):
        calls["n"] += 1
        return _fortiweb_handler(request)

    async def run():
        pipe = ScanPipelineV2(None)
        eng = _Engine("victim.test", [])
        sess = _session()
        client = httpx.AsyncClient(transport=httpx.MockTransport(counting_handler))
        # 1) bare host, 2) tam URL aynı host — ikisi de host_key='victim.test'
        p1 = await pipe._fingerprint_waf_origin(sess, eng, _noop_narrate, client,
                                                "victim.test", active=True)
        n_after_first = calls["n"]
        p2 = await pipe._fingerprint_waf_origin(sess, eng, _noop_narrate, client,
                                                "https://victim.test/login.php?id=1", active=True)
        await client.aclose()
        assert p1 is p2, "dedup aynı profili döndürmedi"
        assert calls["n"] == n_after_first, f"ikinci çağrı ağa çıktı ({calls['n']} > {n_after_first})"
    asyncio.run(run())
    print("[OK] test_fingerprint_host_dedup")


def test_no_waf_returns_none_and_caches():
    """İmzasız hedef: None döner ama önbelleğe None yazılır (tekrar deneme yok)."""
    async def run():
        pipe = ScanPipelineV2(None)
        eng = _Engine("clean.test", [])
        sess = _session()
        client = httpx.AsyncClient(transport=httpx.MockTransport(_clean_handler))
        prof = await pipe._fingerprint_waf_origin(sess, eng, _noop_narrate, client,
                                                  "clean.test", active=True)
        await client.aclose()
        assert prof is None
        assert "clean.test" in eng.waf_by_origin and eng.waf_by_origin["clean.test"] is None
        assert not sess.ai_analysis or "waf" not in sess.ai_analysis
    asyncio.run(run())
    print("[OK] test_no_waf_returns_none_and_caches")


def test_maybe_fingerprint_end_to_end():
    """_maybe_fingerprint_waf kendi client'ıyla: graftaki crawl kenarından origin çıkarır,
    WAF'ı tespit edip session'a yazar. httpx.AsyncClient mock transport'a patch'lenir."""
    async def run():
        orig_client = spv.httpx.AsyncClient
        spv.httpx.AsyncClient = lambda *a, **k: orig_client(
            transport=httpx.MockTransport(_fortiweb_handler))
        try:
            pipe = ScanPipelineV2(None)
            eng = _Engine("victim.test", [_Edge("crawl", {})], level="standard")
            sess = _session()
            await pipe._maybe_fingerprint_waf(sess, eng, _noop_narrate)
            assert eng.waf_profile is not None and eng.waf_profile.vendor == "fortiweb"
            assert sess.ai_analysis.get("waf", {}).get("vendor") == "fortiweb"
        finally:
            spv.httpx.AsyncClient = orig_client
    asyncio.run(run())
    print("[OK] test_maybe_fingerprint_end_to_end")


def test_disabled_flag_skips():
    """POC_WAF_DETECT=0 → hiç ağa çıkmadan None; önbellek boş kalır."""
    async def run():
        os.environ["POC_WAF_DETECT"] = "0"
        try:
            pipe = ScanPipelineV2(None)
            eng = _Engine("victim.test", [])
            sess = _session()
            client = httpx.AsyncClient(transport=httpx.MockTransport(_fortiweb_handler))
            prof = await pipe._fingerprint_waf_origin(sess, eng, _noop_narrate, client,
                                                      "victim.test", active=True)
            await client.aclose()
            assert prof is None
            assert eng.waf_by_origin == {}
        finally:
            os.environ.pop("POC_WAF_DETECT", None)
    asyncio.run(run())
    print("[OK] test_disabled_flag_skips")


if __name__ == "__main__":
    test_web_origins_from_graph()
    test_fingerprint_detects_and_writes()
    test_fingerprint_host_dedup()
    test_no_waf_returns_none_and_caches()
    test_maybe_fingerprint_end_to_end()
    test_disabled_flag_skips()
    print("\nTüm testler geçti.")
