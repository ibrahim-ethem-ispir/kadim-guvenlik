"""Türkçe: Servis derin-dalış (service_probes) SAF analiz testleri — ağ yok.

Kapsam: analyze_smtp (STARTTLS yok/VRFY/banner), analyze_dns (AXFR/version.bind).

Çalıştır: python3 orchestrator/pipeline/test_service_probes.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.service_probes import analyze_smtp, analyze_dns  # noqa: E402


def _titles(findings):
    return " | ".join(f["title"] for f in findings)


def test_smtp_no_starttls_flagged_confirmed():
    fs = analyze_smtp("220 mail.x.com ESMTP Postfix", ["mail.x.com", "SIZE", "8BITMIME"], host="x", port=25)
    starttls = [f for f in fs if "STARTTLS yok" in f["title"]]
    assert starttls and starttls[0]["severity"] == "medium"
    assert starttls[0]["confidence_tier"] == "confirmed"  # deterministik: yetenek yok


def test_smtp_with_starttls_no_flag():
    fs = analyze_smtp("220 mail.x.com ESMTP", ["mail.x.com", "STARTTLS", "SIZE"], host="x", port=587)
    assert not any("STARTTLS yok" in f["title"] for f in fs)


def test_smtp_vrfy_user_enum():
    fs = analyze_smtp("220 x ESMTP", ["x", "VRFY", "STARTTLS"], host="x", port=25)
    vrfy = [f for f in fs if "VRFY/EXPN" in f["title"]]
    assert vrfy and vrfy[0]["confidence_tier"] == "confirmed"


def test_smtp_banner_info_unconfirmed():
    fs = analyze_smtp("220 mail.x.com ESMTP Exim 4.94", ["x", "STARTTLS"], host="x", port=25)
    banner = [f for f in fs if "banner sürüm" in f["title"]]
    assert banner and banner[0]["severity"] == "info" and banner[0]["confidence_tier"] == "unconfirmed"


def test_smtp_empty_ehlo_no_starttls_flag():
    # EHLO hiç dönmediyse (boş) STARTTLS-yok bulgusu ÜRETME (yanlış pozitif önle)
    fs = analyze_smtp("220 x", [], host="x", port=25)
    assert not any("STARTTLS yok" in f["title"] for f in fs)


def test_dns_axfr_open_high_confirmed():
    fs = analyze_dns(["ns1.x.com A 1.2.3.4", "mail.x.com A 1.2.3.5"], None, host="x", port=53)
    axfr = [f for f in fs if "AXFR" in f["title"]]
    assert axfr and axfr[0]["severity"] == "high" and axfr[0]["confidence_tier"] == "confirmed"


def test_dns_no_axfr_no_flag():
    fs = analyze_dns([], None, host="x", port=53)
    assert not any("AXFR" in f["title"] for f in fs)


def test_dns_version_bind_info():
    fs = analyze_dns(None, "PowerDNS 4.9.16", host="x", port=53)
    vb = [f for f in fs if "version.bind" in f["title"] or "sürüm ifşası" in f["title"]]
    assert vb and vb[0]["severity"] == "info"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
