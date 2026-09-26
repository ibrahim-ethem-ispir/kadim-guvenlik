"""Türkçe: WAF fingerprinting (waf_detect) birim testleri — SAF çekirdek, I/O YOK.

NEDEN: Doğrulayıcılar duvara KÖR çarpmasın diye vendor'ı bilmemiz gerek — ama imza
eşleşmesi yanlış-pozitif üretirse (ör. rastgele sayfada 'fortinet' kelimesi) motor yanlış
mutasyon profili uygular. Bu testler imza kararını ve blok tespitini pinler.

Çalıştır: python3 orchestrator/pipeline/test_waf_detect.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.waf_detect import match_waf, looks_blocked, origin_of  # noqa: E402


def test_fortiweb_cookie_near_certain():
    """FORTIWAFSID cookie'si tek başına eşiği aşar (0.95) — neredeyse kesin tespit."""
    hits = match_waf({}, "FORTIWAFSID=abc123; Path=/", "<html>ok</html>", 200)
    assert hits and hits[0][0] == "fortiweb" and hits[0][1] >= 0.9


def test_fortiweb_block_page():
    """FortiWeb blok sayfası (.fgd_icon) + 'fortiweb' metni → tespit."""
    body = '<html><img src="/blocked.fgd_icon">FortiWeb — Web Page Blocked</html>'
    hits = match_waf({}, "", body, 403)
    assert hits and hits[0][0] == "fortiweb"


def test_fortiguard_webfilter_page():
    """FortiGate/FortiGuard web-filter blok sayfası FortiWeb'den AYRI tespit edilir."""
    body = "<html>FortiGuard — Web Filter Blocked. Category: Unrated. fortinet</html>"
    hits = match_waf({}, "", body, 403)
    vendors = [h[0] for h in hits]
    assert "fortiguard" in vendors


def test_cloudflare_headers():
    hits = match_waf({"Server": "cloudflare", "CF-Ray": "8abc-IST"}, "", "", 200)
    assert hits and hits[0][0] == "cloudflare"


def test_modsecurity_body():
    hits = match_waf({}, "", "<html>Mod_Security: Access denied</html>", 406)
    assert hits and hits[0][0] == "modsecurity"


def test_imperva_cookies():
    hits = match_waf({}, "incap_ses_123=xyz; visid_incap_456=abc", "", 200)
    assert hits and hits[0][0] == "imperva"


def test_weak_single_signal_below_threshold():
    """Zayıf tek imza (ör. 'fortinet' kelimesi blog yazısında) WAF SAYILMAZ — eşik altı."""
    hits = match_waf({}, "", "<html>fortinet hakkında bir yazı</html>", 200)
    assert hits == [] or all(h[0] != "fortiguard" for h in hits)


def test_no_signature_no_hit():
    assert match_waf({}, "", "<html>normal sayfa</html>", 200) == []


def test_looks_blocked():
    assert looks_blocked(403, "") is True
    assert looks_blocked(200, "Access Denied — request blocked") is True
    assert looks_blocked(200, "<html>normal içerik</html>") is False
    assert looks_blocked(404, "sayfa bulunamadı") is False


def test_origin_of():
    assert origin_of("http://example.com/a?b=1") == "http://example.com/"
    assert origin_of("example.com/x") == "http://example.com/"
    assert origin_of("javascript:x") is None
    assert origin_of("") is None


def main():
    tests = [
        test_fortiweb_cookie_near_certain, test_fortiweb_block_page,
        test_fortiguard_webfilter_page, test_cloudflare_headers,
        test_modsecurity_body, test_imperva_cookies,
        test_weak_single_signal_below_threshold, test_no_signature_no_hit,
        test_looks_blocked, test_origin_of,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
