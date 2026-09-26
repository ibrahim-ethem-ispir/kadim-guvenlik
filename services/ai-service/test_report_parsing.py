"""
AI rapor ayrıştırma (report_parsing.parse_ai_analysis) testleri — §2.3.

NEDEN: Eski satır-satır regex kırılgandı: "risk score reflects 2026 ... 85/100" gibi
bir cümlede ilk sayı (2026) yakalanıp clamp'e takılıyor ve GERÇEK skor (85) kayboluyordu;
numaralı listeler (1. ...) ve JSON çıktı öneri/bulgu olarak HİÇ toplanmıyordu. Bu testler
JSON-önce + sağlam regex fallback davranışını pinler.

Çalıştır: python3 services/ai-service/test_report_parsing.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from report_parsing import parse_ai_analysis


def test_json_fenced_block_is_preferred():
    """Model fenced ```json bloğu dönerse ondan yapılandırılmış veri okunmalı."""
    text = (
        "Analiz metni burada...\n\n"
        "```json\n"
        '{"risk_score": 72, "critical_findings": ["SQLi /login", "RCE /upload"], '
        '"recommendations": ["WAF ekle", "girdi doğrula"]}\n'
        "```\n"
    )
    r = parse_ai_analysis(text)
    assert r["risk_score"] == 72
    assert r["critical_findings"] == ["SQLi /login", "RCE /upload"]
    assert r["recommendations"] == ["WAF ekle", "girdi doğrula"]


def test_year_in_sentence_does_not_become_risk_score():
    """'2026' gibi bir yıl risk skoru sanılmamalı; gerçek skor (85/100) yakalanmalı."""
    text = "Risk score reflects 2026 threat landscape. Final: 85/100."
    r = parse_ai_analysis(text)
    assert r["risk_score"] == 85


def test_turkish_risk_skoru_prefix():
    """Türkçe 'Risk Skoru: 90' formatı yakalanmalı."""
    r = parse_ai_analysis("Risk Skoru: 90\nDetaylar...")
    assert r["risk_score"] == 90


def test_out_of_range_score_rejected():
    """0-100 dışı sayı skor olamaz (None kalır, saçma değer üretme)."""
    r = parse_ai_analysis("Genel skor 250 civarı bir şey.")
    assert r["risk_score"] is None


def test_numbered_list_recommendations_captured():
    """Numaralı liste (1. 2. 3.) öneriler toplanmalı — eski parser bunu kaçırıyordu."""
    text = (
        "## Öneriler\n"
        "1. Parametreli sorgu kullan\n"
        "2. CSP header ekle\n"
        "3. Bağımlılıkları güncelle\n"
    )
    r = parse_ai_analysis(text)
    assert "Parametreli sorgu kullan" in r["recommendations"]
    assert "CSP header ekle" in r["recommendations"]
    assert len(r["recommendations"]) == 3


def test_dash_bullets_under_critical_findings():
    """Kritik bulgular başlığı altındaki - madde imleri toplanmalı."""
    text = (
        "Kritik Bulgular:\n"
        "- Açık .env dosyası\n"
        "- Default admin şifresi\n"
    )
    r = parse_ai_analysis(text)
    assert "Açık .env dosyası" in r["critical_findings"]
    assert "Default admin şifresi" in r["critical_findings"]


def test_empty_or_garbage_no_crash():
    """Boş/anlamsız girdi patlatmamalı; güvenli varsayılanlar dönmeli."""
    r = parse_ai_analysis("")
    assert r["risk_score"] is None
    assert r["recommendations"] == []
    assert r["critical_findings"] == []
    # Anahtar sözleşmesi (tüketiciler bu anahtarları bekler)
    for key in ("risk_score", "executive_summary", "critical_findings",
                "attack_chain", "recommendations", "technical_details", "next_steps"):
        assert key in r


def test_malformed_json_falls_back_to_regex():
    """Bozuk JSON bloğu regex fallback'i engellememeli."""
    text = (
        "```json\n{bu bozuk json,,}\n```\n"
        "Risk Skoru: 40\n"
        "Öneriler:\n- Yamala\n"
    )
    r = parse_ai_analysis(text)
    assert r["risk_score"] == 40
    assert "Yamala" in r["recommendations"]


def main():
    tests = [
        test_json_fenced_block_is_preferred,
        test_year_in_sentence_does_not_become_risk_score,
        test_turkish_risk_skoru_prefix,
        test_out_of_range_score_rejected,
        test_numbered_list_recommendations_captured,
        test_dash_bullets_under_critical_findings,
        test_empty_or_garbage_no_crash,
        test_malformed_json_falls_back_to_regex,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
