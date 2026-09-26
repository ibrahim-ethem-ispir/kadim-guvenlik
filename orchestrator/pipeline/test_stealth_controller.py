"""
Kadim Güvenlik — test_stealth_controller.py
APT Stealth ve Dinamik Jitter denetleyici birim testi (Düz script).
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.stealth_controller import StealthController


async def main():
    print("🧪 [TEST] StealthController testleri başlıyor...")

    # 1. WAF yokken pasif mod
    sc_plain = StealthController(waf_vendor=None)
    assert sc_plain.is_active is False
    assert sc_plain.compute_jitter() == 0.0
    print("  ✓ WAF olmayan hedefte pasif mod doğrulandı")

    # 2. Akamai veya Imperva WAF ile otomatik aktifleşme
    sc_waf = StealthController(waf_vendor="akamai", min_delay_s=0.1, max_delay_s=0.3)
    assert sc_waf.is_active is True
    delay = sc_waf.compute_jitter()
    assert 0.1 <= delay <= 0.3, f"Gecikme aralık dışı: {delay}"
    print(f"  ✓ Akamai tespitinde aktifleşti, hesaplanan gecikme: {delay}s")

    # 3. Gerçek tarayıcı başlıkları üretimi
    headers = sc_waf.get_stealth_headers({"Custom-Test": "123"})
    assert "User-Agent" in headers
    assert "Mozilla/5.0" in headers["User-Agent"]
    assert "Accept-Language" in headers
    assert headers["Custom-Test"] == "123"
    print(f"  ✓ Tarayıcı başlıkları başarıyla üretildi: {headers['User-Agent'][:40]}...")

    # 4. Pace simülasyonu
    paced = await sc_waf.pace()
    assert paced > 0
    assert sc_waf.total_paced_requests == 1
    print(f"  ✓ Pace simülasyonu tamamlandı ({paced}s)")

    # 5. Summary
    summ = sc_waf.summary()
    assert summ["stealth_active"] is True
    assert summ["waf_vendor"] == "akamai"
    print("  ✓ Summary kontrolü başarılı")

    print("\n🎉 Tüm StealthController testleri BAŞARIYLA GEÇTİ (100% Yeşil)!")


if __name__ == "__main__":
    asyncio.run(main())
