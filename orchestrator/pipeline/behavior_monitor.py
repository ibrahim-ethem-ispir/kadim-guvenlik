"""Davranış denetimi (loop-guard) — SAF çekirdek, ağ/DB yok, izole test edilir.

PentAGI'nin "Execution Monitoring" mekanizmasının KURAL-TABANLI karşılığı: küçük
modellerle çalışırken ajanın tek araca/takıntıya saplanmasını izler; eşik aşılınca
motorun skorlamasına deterministik ceza uygular ve operatöre narrate mesajı üretir.

Fark (bilinçli): PentAGI eşikte LLM-mentor çağırır (2-3x token). Bizde ceza ve
uyarı SAF kuraldır → token maliyeti SIFIR, tekrarlanabilir, doktrin uyumlu
("karar deterministik kural+graf skorunda").

Sözleşme:
- kaydet(tool)          her observe'da çağrılır; sayaçları işler.
- ceza(tool) -> float   next_decision skorlamasında çarpan (1.0 = etkisiz).
- bekleyen_uyarilar     next_decision bunları AGENT_THINKING olarak boşaltır.
- durum()               summary()'ye girer (şeffaflık/UI).
Flag: LOOP_GUARD_ENABLED=0 → tümü no-op (ceza hep 1.0).
"""

from __future__ import annotations

import os
from typing import Dict, List, Set


def _env_int(ad: str, varsayilan: int) -> int:
    try:
        return int(os.getenv(ad, str(varsayilan)))
    except (TypeError, ValueError):
        return varsayilan


def _env_float(ad: str, varsayilan: float) -> float:
    try:
        return float(os.getenv(ad, str(varsayilan)))
    except (TypeError, ValueError):
        return varsayilan


class BehaviorMonitor:
    """Aynı aracın tekrar tekrar seçilmesini izler; eşikte yumuşak ceza + uyarı üretir."""

    def __init__(
        self,
        enabled: bool | None = None,
        ayni_arac_limit: int | None = None,
        ceza_carpani: float | None = None,
    ):
        # None → env'den çöz (testte explicit geçilebilir; SAF kalır).
        self.enabled = (
            enabled if enabled is not None
            else os.getenv("LOOP_GUARD_ENABLED", "1").strip().lower() in ("1", "true", "yes", "on", "evet")
        )
        self.ayni_arac_limit = max(2, ayni_arac_limit if ayni_arac_limit is not None
                                   else _env_int("LOOP_GUARD_SAME_LIMIT", 5))
        # Ceza 0<a<1 aralığına kıstırılır: 0 = aracı tamamen öldürür (istenmez —
        # başka kenar yoksa yine de seçilebilmeli), 1 = ceza yok.
        _c = ceza_carpani if ceza_carpani is not None else _env_float("LOOP_GUARD_PENALTY", 0.55)
        self.ceza_carpani = min(0.95, max(0.1, _c))
        self._arac_sayac: Dict[str, int] = {}
        self._uyarilan: Set[str] = set()
        self.bekleyen_uyarilar: List[str] = []

    # --- yazma ----------------------------------------------------------
    def kaydet(self, tool: str | None) -> None:
        """Bir aksiyon çalıştıktan sonra sayacı işle (observe'dan çağrılır)."""
        if not self.enabled or not tool:
            return
        tool = str(tool)
        self._arac_sayac[tool] = self._arac_sayac.get(tool, 0) + 1
        sayi = self._arac_sayac[tool]
        # Uyarı eşik anında BİR KEZ; sonra her tam katta (2x, 3x...) tekrar —
        # takıntı sürüyorsa operatör görmeye devam etsin ama spam olmasın.
        if sayi >= self.ayni_arac_limit and (
            tool not in self._uyarilan or sayi % self.ayni_arac_limit == 0
        ):
            self._uyarilan.add(tool)
            self.bekleyen_uyarilar.append(
                f"🔁 Davranış denetimi: '{tool}' aracı {sayi} kez kullanıldı "
                f"(eşik {self.ayni_arac_limit}). Motor aynı aracın yeni kenarlarını "
                f"artık {self.ceza_carpani:.0%} skorla değerlendiriyor — bütçe farklı "
                f"yüzeylere kaydırılıyor. Takıntı sürerse taramayı durdurup çeşitliliği "
                f"artırmayı düşünün."
            )

    # --- okuma ----------------------------------------------------------
    def ceza(self, tool: str | None) -> float:
        """next_decision skor çarpanı. Eşik altı veya kapalı → 1.0 (davranış birebir)."""
        if not self.enabled or not tool:
            return 1.0
        if self._arac_sayac.get(str(tool), 0) >= self.ayni_arac_limit:
            return self.ceza_carpani
        return 1.0

    def uyarilari_bosalt(self) -> List[str]:
        """Bekleyen narrate mesajlarını döndür ve kuyruğu temizle (tek tüketim)."""
        out, self.bekleyen_uyarilar = self.bekleyen_uyarilar, []
        return out

    def durum(self) -> Dict[str, object]:
        """summary()'ye giren şeffaflık dökümü."""
        return {
            "enabled": self.enabled,
            "ayni_arac_limit": self.ayni_arac_limit,
            "ceza_carpani": self.ceza_carpani,
            "arac_sayaclari": dict(self._arac_sayac),
            "cezali_araclar": sorted(
                t for t, n in self._arac_sayac.items() if n >= self.ayni_arac_limit
            ),
        }
