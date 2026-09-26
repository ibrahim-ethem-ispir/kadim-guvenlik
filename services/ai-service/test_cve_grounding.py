"""
Kadim Güvenlik — Narrative CVE grounding testleri (düz script, pytest yok)
=========================================================================
Çalıştır: `python3 test_cve_grounding.py` (services/ai-service içinden).
LLM narrative'inde taramanın kanıtında OLMAYAN (uydurma) CVE'lerin işaretlenmesini doğrular.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prompt_builder import extract_grounded_cves, annotate_ungrounded_cves, ground_cves_in_narrative

_fail = []


def ok(cond, msg):
    print(("  [OK] " if cond else "  [FAIL] ") + msg)
    if not cond:
        _fail.append(msg)


def test_grounding():
    scan_data = {"target": "bank.com.tr", "vulnerabilities": [
        {"name": "Apache RCE", "cve_id": "CVE-2021-41773", "severity": "critical"},
        {"name": "Log4Shell", "info": {"classification": {"cve-id": ["CVE-2021-44228"]}}},
    ]}
    grounded = extract_grounded_cves(scan_data)
    ok(grounded == {"CVE-2021-41773", "CVE-2021-44228"}, f"grounded küme: {sorted(grounded)}")

    narrative = (
        "1. Apache path traversal **CVE-2021-41773** kritik.\n"
        "2. Log4Shell CVE-2021-44228 mevcut.\n"
        "3. Ayrıca CVE-2099-0001 ve CVE-2014-6271 riski var (model tahmini)."
    )
    marked, ung = annotate_ungrounded_cves(narrative, grounded)
    ok(ung == ["CVE-2014-6271", "CVE-2099-0001"], f"ungrounded tespit: {ung}")
    ok("CVE-2021-41773" in marked and "CVE-2021-41773⚠️" not in marked, "grounded CVE işaretlenMEDİ")
    ok("CVE-2099-0001⚠️" in marked and "CVE-2014-6271⚠️" in marked, "uydurma CVE'ler ⚠️ işaretlendi")
    ok("DOĞRULAMA NOTU" in marked, "dipnot eklendi")


def test_clean_untouched():
    grounded = {"CVE-2021-41773"}
    clean = "Sadece CVE-2021-41773 doğrulandı."
    m, u = annotate_ungrounded_cves(clean, grounded)
    ok(m == clean and u == [], "ungrounded yoksa metin hiç değişmez")
    ok(annotate_ungrounded_cves("", grounded) == ("", []), "boş metin güvenli")


def test_case_insensitive():
    grounded = extract_grounded_cves({"x": "cve-2021-41773"})
    ok("CVE-2021-41773" in grounded, "büyük/küçük harf normalize (grounded)")
    m, u = annotate_ungrounded_cves("bakınız cve-2021-41773", grounded)
    ok(u == [], "grounded CVE küçük harfle de eşleşir")


if __name__ == "__main__":
    for fn in (test_grounding, test_clean_untouched, test_case_insensitive):
        print(f"=== {fn.__name__} ===")
        fn()
    print()
    if _fail:
        print(f"{len(_fail)} test BAŞARISIZ")
        sys.exit(1)
    print("Tüm CVE-grounding testleri geçti.")
