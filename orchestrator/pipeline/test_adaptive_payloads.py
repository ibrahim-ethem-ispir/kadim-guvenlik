"""Türkçe: T3-A adaptif payload zanaatı testleri — sanitize/context çekirdeği SAF;
verify_adaptive fake-client ile deterministik (ağ yok).

Kök felsefe: LLM ZANAATLAR, DETERMİNİSTİK ÇEKİRDEK ONAYLAR. Testler: sanitize korkuluğu
(placeholder zorunlu + yıkıcı token reddi), _coerce_list biçimleri, craft_payloads enjekte
llm_call, verify_adaptive'in imza-onayı (xss marker / lfi imza / ssti aritmetik) + FP kapıları.

Çalıştır: python3 orchestrator/pipeline/test_adaptive_payloads.py
"""
import asyncio
import os
import re
import sys
from urllib.parse import urlsplit, parse_qsl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.adaptive_payloads import (  # noqa: E402
    sanitize_payloads, _coerce_list, build_probe_context, craft_payloads, _payload_ok,
)
from pipeline.verification import verify_adaptive  # noqa: E402


# ---------------- Madde 3: _payload_ok yeni sınıflar/kanaryalar ----------------

def test_payload_ok_sqli_error_beyazlistesi():
    """sqli_error: vektör beyazlistesi + tırnak-kırıcı tam-eşleşme; beyazliste dışı
    ve timing-vektörü ({D}-siz SLEEP) reddedilir — sınıflar birbirine sızmaz."""
    assert _payload_ok("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))-- -", "sqli_error")
    assert _payload_ok("' AND 1=CAST(@@version AS INT)-- -", "sqli_error")
    assert _payload_ok("'", "sqli_error") and _payload_ok("1\"", "sqli_error")
    assert not _payload_ok("1' UNION SELECT password FROM users", "sqli_error")
    assert not _payload_ok("' AND SLEEP(5)-- -", "sqli_error")      # timing vektörü
    assert not _payload_ok("' UNION SELECT 1; DROP TABLE t-- -", "sqli_error")  # yıkıcı


def test_sanitize_sqli_error_llm_hatti_disinda():
    """DOKTRİN PİNİ: sqli_error CORPUS-only sınıf — LLM adaptif hat bu sınıfı ÜRETEMEZ
    (ADAPTIVE_CLASSES'te yok); hata-enjeksiyon vektörleri yalnız süzülmüş dosyadan gelir."""
    assert sanitize_payloads(["' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))-- -"],
                             "sqli_error") == []


def test_payload_ok_lfi_yeni_kanaryalar():
    assert _payload_ok("/proc/self/environ", "lfi")
    assert _payload_ok("/var/log/nginx/access.log", "lfi")
    assert _payload_ok("..%252f..%252fetc%252fpasswd", "lfi")
    assert _payload_ok("..\\..\\boot.ini", "lfi")
    assert not _payload_ok("/etc/shadow", "lfi")          # kanarya dışı hassas dosya
    assert not _payload_ok("expect://id", "lfi")          # RCE wrapper — doktrin dışı


# ---------------- sanitize korkuluğu ----------------

def test_sanitize_sqli_placeholder_zorunlu():
    raw = ["' AND SLEEP({D})-- -", "' OR 1=1-- -", "'||pg_sleep({D})--"]
    out = sanitize_payloads(raw, "sqli")
    # {D} + sleep-fonksiyonu olanlar kalır; olmayan ('OR 1=1') elenir
    assert "' AND SLEEP({D})-- -" in out
    assert "'||pg_sleep({D})--" in out
    assert "' OR 1=1-- -" not in out


def test_sanitize_sqli_yikici_red():
    raw = ["'; DROP TABLE users; SLEEP({D})", "'; SELECT SLEEP({D}) INTO OUTFILE '/x'"]
    assert sanitize_payloads(raw, "sqli") == []  # yıkıcı token → hepsi elenir


def test_sanitize_xss_marker_zorunlu():
    raw = ["<svg onload=x>{MARKER}", "<script>alert(1)</script>"]
    out = sanitize_payloads(raw, "xss")
    assert out == ["<svg onload=x>{MARKER}"]  # marker'sız elenir


def test_sanitize_ssti_ab_zorunlu():
    raw = ["{{{A}*{B}}}", "${{{A}*{B}}}", "{{7*7}}"]
    out = sanitize_payloads(raw, "ssti")
    assert "{{{A}*{B}}}" in out and "{{7*7}}" not in out


def test_sanitize_lfi_kanarya_zorunlu():
    raw = ["../../../../etc/passwd", "../../../../etc/shadow", "php://filter/x/resource=y"]
    out = sanitize_payloads(raw, "lfi")
    assert "../../../../etc/passwd" in out
    assert "php://filter/x/resource=y" in out
    assert "../../../../etc/shadow" not in out  # kanarya değil (rastgele hassas dosya)


def test_sanitize_cap_ve_dedup():
    raw = ["' AND SLEEP({D})-- -"] * 5 + [f"' AND SLEEP({{D}})/*{i}*/" for i in range(20)]
    out = sanitize_payloads(raw, "sqli", cap=6)
    assert len(out) == 6 and len(set(out)) == 6


def test_sanitize_bilinmeyen_sinif():
    assert sanitize_payloads(["x"], "rce") == []


def test_coerce_list_bicimleri():
    assert _coerce_list(["a", "b"]) == ["a", "b"]
    assert _coerce_list({"suggested_payloads": ["a"]}) == ["a"]
    assert _coerce_list('["a","b"]') == ["a", "b"]
    assert _coerce_list('bla bla ["x"] son') == ["x"]  # metin sarmalı
    assert _coerce_list("düz metin") == []


def test_build_probe_context_kirpma():
    ctx = build_probe_context(vuln_class="sqli", url="https://x.com/a?q=1", param="q",
                              baseline="A" * 5000, blocked="B" * 5000)
    assert ctx["vuln_class"] == "sqli"
    assert len(ctx["baseline_snippet"]) <= 1200
    assert ctx["param"] == "q"


# ---------------- craft_payloads (enjekte llm_call) ----------------

def test_craft_payloads_enjekte_llm():
    async def fake_llm(ctx):
        return ["<svg>{MARKER}", "<img src=x onerror={MARKER}>", "<script>alert(1)</script>"]
    ctx = build_probe_context(vuln_class="xss", url="https://x.com/s?q=1", param="q")
    out = asyncio.run(craft_payloads(ctx, llm_call=fake_llm))
    assert "<svg>{MARKER}" in out
    assert "<script>alert(1)</script>" not in out  # marker'sız elendi


def test_craft_payloads_llm_hata_bos_liste():
    async def boom(ctx):
        raise RuntimeError("provider down")
    ctx = build_probe_context(vuln_class="sqli", url="https://x.com/a?q=1", param="q")
    assert asyncio.run(craft_payloads(ctx, llm_call=boom)) == []  # degrade-safe


# ---------------- verify_adaptive (fake client — imza onayı) ----------------

class FakeResp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status
        self.headers = {}


class FakeClient:
    """Reflect/LFI/SSTI-farkında sahte httpx. Query değerlerini DECODE edip davranır
    (gerçek sunucu gibi): passwd→imza, {a}*{b}→çarpım, aksi halde decoded yansıma."""
    async def get(self, url, headers=None, timeout=None, follow_redirects=None):
        vals = [v for _k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
        joined = " ".join(vals)
        if "passwd" in joined:
            return FakeResp("root:x:0:0:root:/root:/bin/bash")
        m = re.search(r"(\d+)\*(\d+)", joined)
        if m:
            prod = int(m.group(1)) * int(m.group(2))
            return FakeResp(f"sonuc: {prod} tamam")  # ham ifade YOK → değerlendirilmiş
        return FakeResp(f"<html>arama: {joined}</html>")  # HAM yansıma (escape yok)


def test_verify_adaptive_xss_confirmed():
    v = asyncio.run(verify_adaptive("https://x.com/s?q=hello", None, "xss",
                                    ['"><b>{MARKER}</b>'], FakeClient()))
    assert v.verified is True and v.method == "xss-llm-adaptive"


def test_verify_adaptive_lfi_confirmed():
    v = asyncio.run(verify_adaptive("https://x.com/dl?file=a.txt", None, "lfi",
                                    ["../../../../etc/passwd"], FakeClient()))
    assert v.verified is True and v.method == "lfi-llm-adaptive"


def test_verify_adaptive_ssti_confirmed():
    v = asyncio.run(verify_adaptive("https://x.com/p?name=bob", None, "ssti",
                                    ["{{{A}*{B}}}"], FakeClient()))
    assert v.verified is True and v.method == "ssti-llm-adaptive"


def test_verify_adaptive_bos_payload():
    v = asyncio.run(verify_adaptive("https://x.com/s?q=1", None, "xss", [], FakeClient()))
    assert v.verified is False


def test_verify_adaptive_parametresiz():
    v = asyncio.run(verify_adaptive("https://x.com/s", None, "xss", ["{MARKER}"], FakeClient()))
    assert v.verified is False and "atlandı" in v.detail


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
