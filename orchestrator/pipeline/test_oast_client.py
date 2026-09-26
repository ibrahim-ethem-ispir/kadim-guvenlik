"""
Kadim Güvenlik — test_oast_client.py
Düz-script test (bu projenin konvansiyonu: pytest yok, python3 ile koşar).
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.oast_client import OastClient, OastInteraction


async def main():
    print("🧪 [TEST] OastClient testleri başlıyor...")

    client = OastClient(session_id="scan-test-1234", oast_domain="oast.kadim.test", mock_mode=True)

    # 1. Payload üretimi
    token_ssrf, fqdn_ssrf = client.generate_payload("ssrf", {"url": "https://api.bank.local/fetch", "param": "url"})
    assert token_ssrf.startswith("ssrf-"), f"Hatalı token öneki: {token_ssrf}"
    assert fqdn_ssrf.endswith(".oast.kadim.test"), f"Hatalı FQDN: {fqdn_ssrf}"
    assert token_ssrf in client.registered_tokens
    print(f"  ✓ Payload üretildi: {fqdn_ssrf}")

    # 2. Polling (henüz etkileşim yok)
    hits = await client.poll_interactions()
    assert len(hits) == 0
    print("  ✓ Boş poll başarılı")

    # 3. Mock etkileşim simülasyonu (Banka backend'inden gelen DNS sorgusu)
    client.add_mock_interaction(
        token=token_ssrf,
        protocol="dns",
        remote_addr="192.168.10.55", # İç banka sunucusu
        raw_req="A ssrf-xxxx.oast.kadim.test",
    )

    hits_after = await client.poll_interactions()
    assert len(hits_after) == 1, f"Beklenen 1 etkileşim, gelen: {len(hits_after)}"
    assert hits_after[0].full_id == token_ssrf
    assert hits_after[0].protocol == "dns"
    assert hits_after[0].remote_address == "192.168.10.55"
    assert hits_after[0].marker == "ssrf"
    print(f"  ✓ Mock DNS callback yakalandı: {hits_after[0].remote_address}")

    # 4. has_interaction_for
    matched = client.has_interaction_for(token_ssrf)
    assert matched is not None
    assert matched.remote_address == "192.168.10.55"
    print("  ✓ has_interaction_for başarıyla doğrulandı")

    # 5. Summary çıktısı
    summ = client.summary()
    assert summ["tokens_generated"] == 1
    assert summ["interactions_count"] == 1
    print("  ✓ Summary doğrulaması başarılı")

    print("\n🎉 Tüm OastClient testleri BAŞARIYLA GEÇTİ (100% Yeşil)!")


if __name__ == "__main__":
    asyncio.run(main())
