"""
Otonom rapor sözleşmesi (autonomous_report.build_autonomous_scan_results) testleri.

NEDEN: Otonom taramanın nihai AI raporu, motorun bulgularını AI servisine
`scan_data["results"]` altında {tool_name: tool_data} ŞEKLİNDE göndermeliydi; ama
düz (flat) gönderiyordu → scan_analyzer._format_scan_results boş sonuç üretiyordu
(AI raporu motorun bulduğu HİÇBİR ŞEYİ görmüyordu). Bu testler, düz kanıt+özeti
statik pipeline ile AYNI sözleşme şekline çeviren saf fonksiyonu pinler.

Çalıştır: python3 orchestrator/pipeline/test_autonomous_report.py
veya:     python3 -m pytest orchestrator/pipeline/test_autonomous_report.py -v
"""

import os
import sys

# Repo kökünden çalıştırılabilirlik (test_cve_intel.py deseni)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.autonomous_report import build_autonomous_scan_results


def _evidence(title, severity, target="https://bank.example.com", cve=None):
    """Evidence.to_dict() alt kümesi — fonksiyonun okuduğu alanlar."""
    return {"title": title, "severity": severity, "target": target, "cve": cve,
            "tool": "nuclei", "proof": "template matched"}


def test_evidence_becomes_nuclei_findings():
    """Kanıtlar, _format_scan_results'ın okuduğu nuclei şekline dönüşmeli."""
    ev = [
        _evidence("SQL Injection in /login", "critical", cve="CVE-2021-1234"),
        _evidence("Reflected XSS in /search", "high"),
    ]
    results = build_autonomous_scan_results(ev, summary={})

    nuclei = results["nuclei"]
    assert nuclei["findings_count"] == 2
    # severity_counts, formatter'ın okuduğu anahtarlar
    assert nuclei["severity_counts"]["critical"] == 1
    assert nuclei["severity_counts"]["high"] == 1
    # findings[*] formatter'ın beklediği iç yapı (info.severity/info.name/template-id/matched-at)
    first = nuclei["findings"][0]
    assert first["info"]["severity"] == "critical"
    assert first["info"]["name"] == "SQL Injection in /login"
    assert first["template-id"] == "CVE-2021-1234"
    assert first["matched-at"] == "https://bank.example.com"


def test_empty_evidence_yields_no_nuclei_section():
    """Kanıt yoksa nuclei bölümü HİÇ oluşmamalı (boş bölüm gürültüsü yerine yokluk)."""
    results = build_autonomous_scan_results([], summary={})
    assert "nuclei" not in results


def test_missing_severity_defaults_to_info_not_crash():
    """Severity'si olmayan/bilinmeyen kanıt patlatmamalı; 'info' sayılmalı."""
    ev = [{"title": "Bilinmeyen", "target": "https://x"}]  # severity yok
    results = build_autonomous_scan_results(ev, summary={})
    assert results["nuclei"]["findings_count"] == 1
    assert results["nuclei"]["severity_counts"]["info"] == 1
    assert results["nuclei"]["findings"][0]["info"]["severity"] == "info"


def test_recon_context_from_summary():
    """Özetteki teknoloji/real_ip/CDN bağlamı recon bölümüne taşınmalı (LLM bağlamı)."""
    summary = {
        "technologies": ["nginx", "php"],
        "real_ip": "1.2.3.4",
        "is_behind_cdn": True,
        "subdomains": ["api.example.com", "mail.example.com"],
    }
    results = build_autonomous_scan_results([], summary=summary)
    recon = results["recon"]
    assert recon["is_cloudflare"] is True
    assert recon["real_ips"] == ["1.2.3.4"]
    assert recon["technologies"] == ["nginx", "php"]
    assert "api.example.com" in recon["subdomains"]


def test_no_context_yields_empty_results():
    """Ne kanıt ne bağlam varsa boş dict dönmeli (formatter 'sonuç bulunamadı' der)."""
    assert build_autonomous_scan_results([], summary={}) == {}


def main():
    test_evidence_becomes_nuclei_findings()
    print("[OK] evidence_becomes_nuclei_findings")
    test_empty_evidence_yields_no_nuclei_section()
    print("[OK] empty_evidence_yields_no_nuclei_section")
    test_missing_severity_defaults_to_info_not_crash()
    print("[OK] missing_severity_defaults_to_info")
    test_recon_context_from_summary()
    print("[OK] recon_context_from_summary")
    test_no_context_yields_empty_results()
    print("[OK] no_context_yields_empty_results")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
