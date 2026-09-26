"""
Kadim Güvenlik — Duraklat/Devam kapısı (§2.5)
=============================================
Türkçe: Otonom motorun SIRADAKİ hamlesini bekletebilen basit bir kapı. `cancel` geri
dönüşsüzdür; bu kapı taramayı ÖLDÜRMEDEN duraklatır ve `resume` ile kaldığı yerden sürdürür.

Anlambilim: Çalışan bir stage'i KESMEZ (stealth/ağ tutarlılığı bozulmasın) — yalnız bir
sonraki karar/aksiyon başlamadan önce beklenir. "Durdur/devam" davranışının çekirdeği.

SAF ve BAĞIMSIZ: yalnız asyncio. İzole test edilebilir (test_pause_control.py).
"""

import asyncio


class PauseGate:
    """paused=False iken bekleme anında geçer; True iken resume gelene kadar bloke eder."""

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._event.set()  # başlangıç: DURAKLATILMAMIŞ (kapı açık)

    @property
    def paused(self) -> bool:
        return not self._event.is_set()

    def pause(self) -> None:
        """Kapıyı kapat — bir sonraki `wait_while_paused()` resume'a kadar bloke olur."""
        self._event.clear()

    def resume(self) -> None:
        """Kapıyı aç — bekleyen tüm çağrılar devam eder."""
        self._event.set()

    async def wait_while_paused(self) -> None:
        """Duraklatılmışsa resume'a kadar bekle; değilse anında dön."""
        await self._event.wait()
