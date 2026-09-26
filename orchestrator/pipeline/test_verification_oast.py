"""
Kadim Güvenlik — test_verification_oast.py
OAST destekli SSRF ve XXE doğrulama testleri (Düz script).
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from pipeline.oast_client import OastClient
from pipeline.verification import verify_ssrf, verify_xxe


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, oast_client: OastClient):
        self.oast_client = oast_client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        content_str = request.read().decode("utf-8", errors="ignore")

        # SSRF durumunda: URL parametresinde oast fqdn varsa mock callback tetikle
        for tok, data in self.oast_client.registered_tokens.items():
            if data["fqdn"] in url_str or data["fqdn"] in content_str:
                self.oast_client.add_mock_interaction(
                    token=tok,
                    protocol="dns",
                    remote_addr="10.20.30.40", # Banka iç backend sunucusu
                )
        return httpx.Response(200, text="Mock Backend Response", request=request)


async def main():
    print("🧪 [TEST] OAST destekli SSRF / XXE doğrulama testleri başlıyor...")

    oast = OastClient(session_id="test-scan-oast", oast_domain="oast.kadim.test", mock_mode=True)
    client = httpx.AsyncClient(transport=MockTransport(oast))

    # 1. Blind SSRF doğrulaması
    test_url = "https://bank.kadim.local/api/v1/preview?url=http://example.com"
    verdict_ssrf = await verify_ssrf(test_url, param="url", client=client, oast_client=oast)

    assert verdict_ssrf.verified is True, f"SSRF doğrulanmalıydı: {verdict_ssrf.detail}"
    assert verdict_ssrf.method == "ssrf-oast"
    assert "10.20.30.40" in verdict_ssrf.detail
    print(f"  ✓ Kör SSRF OAST ile TEYİT edildi: {verdict_ssrf.detail[:80]}...")

    # 2. Blind XXE doğrulaması
    xxe_url = "https://bank.kadim.local/api/v1/xml-endpoint"
    verdict_xxe = await verify_xxe(xxe_url, client=client, oast_client=oast)

    assert verdict_xxe.verified is True, f"XXE doğrulanmalıydı: {verdict_xxe.detail}"
    assert verdict_xxe.method == "xxe-oast"
    assert "10.20.30.40" in verdict_xxe.detail
    print(f"  ✓ Kör XXE OAST ile TEYİT edildi: {verdict_xxe.detail[:80]}...")

    print("\n🎉 Tüm OAST Doğrulama testleri BAŞARIYLA GEÇTİ (100% Yeşil)!")


if __name__ == "__main__":
    asyncio.run(main())
