"""Türkçe: Dayanıklılık & maruz-kalma probu (resilience_probe) SAF analiz testleri — ağ yok.

Kapsam: detect_cdn, analyze_cache_posture (L7-flood maruz-kalma), analyze_ratelimit,
analyze_origin_exposure (CDN-bypass), classify_ssh (parola-auth), _body_signature.

Çalıştır: python3 orchestrator/pipeline/test_resilience_probe.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.resilience_probe import (  # noqa: E402
    detect_cdn, analyze_cache_posture, analyze_ratelimit, analyze_origin_exposure,
    classify_ssh, summarize_posture, _body_signature,
)


# ---- CDN tespiti ----
def test_detect_cloudflare_by_cfray():
    assert detect_cdn({"CF-RAY": "abc123", "Server": "cloudflare"}) == "cloudflare"


def test_detect_none_for_plain_nginx():
    assert detect_cdn({"Server": "nginx/1.24"}) is None


def test_detect_fastly_and_akamai():
    assert detect_cdn({"X-Served-By": "cache-fra"}) == "fastly"
    assert detect_cdn({"Server": "AkamaiGHost"}) == "akamai"


# ---- Cache duruşu = L7-flood maruz-kalması (bu olayın kök zafiyeti) ----
def test_dynamic_homepage_behind_cdn_flagged_confirmed():
    fs = analyze_cache_posture(200, {"CF-Cache-Status": "DYNAMIC", "Server": "cloudflare"},
                               cdn="cloudflare", host="ex.com")
    assert len(fs) == 1
    assert fs[0]["confidence_tier"] == "confirmed"       # deterministik header gözlemi
    assert fs[0]["axis"] == "availability"
    assert fs[0]["severity"] == "medium"


def test_cached_homepage_no_flag():
    assert analyze_cache_posture(200, {"CF-Cache-Status": "HIT"}, cdn="cloudflare", host="x") == []


def test_no_cdn_means_no_cache_finding():
    # CDN yoksa "cache yok" beklenendir → gürültü üretme
    assert analyze_cache_posture(200, {"Cache-Control": "no-store"}, cdn=None, host="x") == []


def test_no_store_cache_control_behind_cdn_flagged():
    fs = analyze_cache_posture(200, {"Cache-Control": "private, no-store", "CF-RAY": "z"},
                               cdn="cloudflare", host="ex.com")
    assert fs and fs[0]["confidence_tier"] == "confirmed"


# ---- Rate-limit yokluğu ----
def test_no_ratelimit_all_2xx_probable():
    fs = analyze_ratelimit("ex.com", [200] * 12, cdn="cloudflare")
    assert len(fs) == 1 and fs[0]["confidence_tier"] == "probable"
    assert fs[0]["axis"] == "availability"


def test_ratelimit_present_no_flag():
    assert analyze_ratelimit("ex.com", [200, 200, 429], cdn="cloudflare") == []
    assert analyze_ratelimit("ex.com", [200, 503], cdn=None) == []


# ---- Origin ifşası / CDN-bypass (olayın 1 no'lu P0'ı) ----
def test_origin_bypass_same_app_confirmed_high():
    fs = analyze_origin_exposure("ex.com", "cloudflare", "1.2.3.4",
                                 direct_status=200, direct_body_sig="home|13", cdn_body_sig="home|13")
    assert len(fs) == 1
    assert fs[0]["severity"] == "high" and fs[0]["confidence_tier"] == "confirmed"
    assert fs[0]["axis"] == "exposure"


def test_origin_direct_but_different_content_probable_low():
    fs = analyze_origin_exposure("ex.com", "cloudflare", "1.2.3.4",
                                 direct_status=200, direct_body_sig="other|10", cdn_body_sig="home|13")
    assert len(fs) == 1 and fs[0]["severity"] == "low" and fs[0]["confidence_tier"] == "probable"


def test_origin_exposure_needs_cdn_and_ip():
    assert analyze_origin_exposure("ex.com", None, "1.2.3.4",
                                   direct_status=200, direct_body_sig="a", cdn_body_sig="a") == []
    assert analyze_origin_exposure("ex.com", "cloudflare", None,
                                   direct_status=200, direct_body_sig="a", cdn_body_sig="a") == []


# ---- SSH parola-auth (brute-force zemini — olayın ikinci vektörü) ----
def test_ssh_password_auth_internet_exposed_high_confirmed():
    fs = classify_ssh("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                      ["publickey", "password"], host="h", port=22, internet_exposed=True)
    pw = [f for f in fs if "parola kimlik" in f["title"]]
    assert pw and pw[0]["severity"] == "high" and pw[0]["confidence_tier"] == "confirmed"
    assert "T1110" in pw[0]["mitre"]


def test_ssh_keyboard_interactive_counts_as_password():
    fs = classify_ssh("SSH-2.0-OpenSSH_9.2", ["publickey", "keyboard-interactive"],
                      host="h", internet_exposed=True)
    assert any("parola kimlik" in f["title"] for f in fs)


def test_ssh_publickey_only_no_password_finding():
    fs = classify_ssh("SSH-2.0-OpenSSH_9.6", ["publickey"], host="h", internet_exposed=True)
    assert not any("parola" in f["title"] for f in fs)
    assert any("sürüm ifşası" in f["title"] for f in fs)   # yine de sürüm ifşası (info) verilir


def test_ssh_password_internal_only_medium():
    fs = classify_ssh("SSH-2.0-OpenSSH_8.0", ["password"], host="h", internet_exposed=False)
    pw = [f for f in fs if "parola kimlik" in f["title"]]
    assert pw and pw[0]["severity"] == "medium"


def test_ssh_no_banner_no_findings():
    assert classify_ssh("", None, host="h") == []


# ---- Duruş özeti ----
def test_summarize_posture_shape():
    s = summarize_posture("cloudflare", origin_exposed=True, cdn_bypassable=True,
                          homepage_cached=False, ssh_password_auth=True)
    assert s["cdn"] == "cloudflare" and s["cdn_bypassable"] is True
    assert s["ssh_password_auth"] is True


# ---- gövde imzası ----
def test_body_signature_title_tolerant():
    a = _body_signature(200, "<title>Ana Sayfa</title>" + "x" * 40)
    b = _body_signature(200, "<title>Ana Sayfa</title>" + "x" * 45)  # ufak dinamik fark, aynı kova
    assert a.startswith("ana sayfa|") and a == b   # kaba kova → aynı imza


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  ✓ {fn.__name__}")
    print(f"\n{passed}/{len(fns)} test geçti ✅")
