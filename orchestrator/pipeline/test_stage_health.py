"""
Aşama sağlığı / degraded-stage sınıflandırması (stage_health) testleri — §2.6.

NEDEN: Çekirdek pipeline'da 30+ geniş `except` başarısızlığı sessizce yutuyor; tarama
"başarılı" görünüp eksik sonuç veriyor ("nereden tutsan eksik" hissi). Bu modül hangi
aşamanın DÜŞTÜĞÜNÜ deterministik sınıflar ve operatöre görünür özet üretir. Kritik karar:
'skipped' (bilinçli atlama) düşme SAYILMAZ; 'failed'/'timeout' sayılır.

Çalıştır: python3 orchestrator/pipeline/test_stage_health.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.stage_health import is_degraded, build_degraded_record, summarize_degraded


def test_failed_and_timeout_are_degraded():
    assert is_degraded("failed") is True
    assert is_degraded("timeout") is True


def test_completed_and_skipped_are_not_degraded():
    """'skipped' bilinçli atlamadır — düşme değil (aksi halde her tarama 'bozuk' görünür)."""
    assert is_degraded("completed") is False
    assert is_degraded("skipped") is False


def test_build_record_shape():
    rec = build_degraded_record(stage_name="recon_1", tool="recon", step=3,
                                status="timeout", error="connect timeout")
    assert rec == {"stage": "recon_1", "tool": "recon", "step": 3,
                   "status": "timeout", "error": "connect timeout"}


def test_summary_counts_and_message():
    degraded = [
        {"stage": "recon_1", "tool": "recon", "step": 3, "status": "failed", "error": "x"},
        {"stage": "osint_1", "tool": "osint", "step": 5, "status": "timeout", "error": "y"},
    ]
    s = summarize_degraded(degraded, total_stages=8)
    assert s["degraded_count"] == 2
    assert s["total_stages"] == 8
    assert s["degraded_stages"] == degraded
    # Operatör-görünür mesaj araç adlarını içermeli
    assert "recon" in s["message"] and "osint" in s["message"]


def test_no_degraded_yields_clean_summary():
    s = summarize_degraded([], total_stages=6)
    assert s["degraded_count"] == 0
    assert s["degraded_stages"] == []


def main():
    for t in [test_failed_and_timeout_are_degraded, test_completed_and_skipped_are_not_degraded,
              test_build_record_shape, test_summary_counts_and_message,
              test_no_degraded_yields_clean_summary]:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
