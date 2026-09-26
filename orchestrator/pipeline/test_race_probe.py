"""
Kadim Güvenlik — test_race_probe.py
Race condition ve finansal eşzamanlılık probu birim testi (Düz script).
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from pipeline.race_probe import (
    is_financial_target,
    adjudicate_concurrency,
    probe_race_condition
)


class MockRaceTransport(httpx.AsyncBaseTransport):
    def __init__(self, mode="vulnerable"):
        self.mode = mode
        self.call_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.call_count += 1
        if self.mode == "vulnerable":
            # Tüm istekler başarılı kabul ediliyor (kilit yok)
            return httpx.Response(200, json={"status": "success", "balance": 100}, request=request)
        elif self.mode == "protected":
            # İlk istek 200, sonrakiler 409 veya 429
            if self.call_count == 1:
                return httpx.Response(200, json={"status": "success"}, request=request)
            return httpx.Response(409, json={"error": "Conflict: işlem devam ediyor"}, request=request)
        return httpx.Response(404, request=request)


async def main():
    print("🧪 [TEST] Race Condition & Finansal Eşzamanlılık testleri başlıyor...")

    # 1. URL filtreleme testi (SAF)
    assert is_financial_target("https://api.bank.com/v1/transfer/execute") is True
    assert is_financial_target("https://api.bank.com/v1/checkout/apply-coupon") is True
    assert is_financial_target("https://api.bank.com/v1/bakiye-sorgu") is True
    assert is_financial_target("https://bank.com/assets/app.js") is False
    assert is_financial_target("https://bank.com/about-us") is False
    print("  ✓ is_financial_target filtrelemesi doğrulandı")

    # 2. Adjudicate testi — Korumasız sunucu (Vulnerable, DURUM-DEĞİŞTİRİCİ metod)
    # NOT-1: GET/HEAD/OPTIONS idempotenttir — N×2xx BEKLENEN davranıştır, CWE-362 kanıtı
    # DEĞİLDİR (idempotent-metot FP kapısı). Race iddiası yalnız POST/PUT gibi metotlarda.
    # NOT-2: tahribatsız gözlem çift harcama kanıtlayamaz → tier en fazla 'probable'.
    mock_responses_vuln = [(200, '{"ok": true}', 0.05) for _ in range(8)]
    verdict_vuln = adjudicate_concurrency(mock_responses_vuln, "https://api.bank.com/transfer", 8, method="POST")
    assert verdict_vuln.is_vulnerable is True
    assert verdict_vuln.confidence_tier == "probable"
    assert "CWE-362" in verdict_vuln.title
    print(f"  ✓ Korumasız durum tespit edildi: {verdict_vuln.title}")

    # 2b. İdempotent metot FP kapısı: aynı 8×200 GET ile ASLA zafiyet işaretlemez
    verdict_get = adjudicate_concurrency(mock_responses_vuln, "https://api.bank.com/transfer", 8, method="GET")
    assert verdict_get.is_vulnerable is False
    print("  ✓ İdempotent metot (GET) FP kapısı doğrulandı")

    # 3. Adjudicate testi — Korumalı sunucu (Protected)
    mock_responses_prot = [(200, '{"ok": true}', 0.05)] + [(409, '{"error": "locked"}', 0.06) for _ in range(7)]
    verdict_prot = adjudicate_concurrency(mock_responses_prot, "https://api.bank.com/transfer", 8, method="POST")
    assert verdict_prot.is_vulnerable is False
    assert verdict_prot.confidence_tier == "clean"
    assert verdict_prot.replay_protection_found is True
    print(f"  ✓ Korumalı durum tespit edildi (Hız limiti / kilit devrede)")

    # 4. Async Probe uçtan uca test (Mock Transport ile)
    client_vuln = httpx.AsyncClient(transport=MockRaceTransport("vulnerable"))
    res = await probe_race_condition("https://api.bank.com/transfer", client_vuln, burst_count=6, method="POST")
    assert res.is_vulnerable is True
    assert res.success_count == 6
    print(f"  ✓ Uçtan uca probe simülasyonu başarılı ({res.success_count} paralel istek yakalandı)")

    print("\n🎉 Tüm Race Condition testleri BAŞARIYLA GEÇTİ (100% Yeşil)!")


if __name__ == "__main__":
    asyncio.run(main())
