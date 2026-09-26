"""
Kadim Güvenlik — Generate-and-Verify aile-kazanma hafızası (experience replay)
==============================================================================
Türkçe: Hangi ADAY AİLESİ (builtin/corpus/mutation) hangi sıklıkla KANIT üretiyor? Bu
istatistik tarama-ötesi biriktirilir ve sonraki taramalarda aday önceliğini (prior) hafifçe
besler → "model eğitmeden öğrenme". Doğrulama HÂLÂ deterministik (verifier); hafıza yalnız
ÖNCELİK sinyalidir, karar değil.

Best-effort: DB yok/erişilemez → boş istatistik (sessiz degrade). Ağ/LLM YOK.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

_COLL = "sampling_priors"
_SCOPE = "global"


def load_family_priors(db: Any, *, scope: str = _SCOPE) -> Dict[str, float]:
    """Aile → kazanma oranı (0..1). Doküman yoksa {} (soğuk başlangıç)."""
    if db is None:
        return {}
    try:
        doc = db[_COLL].find_one({"scope": scope})
        fams = (doc or {}).get("families") or {}
        return {k: float(v.get("win_rate", 0.0))
                for k, v in fams.items() if isinstance(v, dict)}
    except Exception:
        return {}


def record_family_outcomes(db: Any, delta: Dict[str, Dict[str, int]],
                           *, scope: str = _SCOPE) -> None:
    """Aile bazlı TUR DELTASINI (tried/wins) global istatistiğe EKLE (kümülatif merge).

    `delta` mutlaka artımlı olmalı (kümülatif toplamı tekrar yazmak çift sayar) — çağıran
    önceki snapshot'a göre farkı hesaplar. Best-effort; hata motoru düşürmez."""
    if db is None or not delta:
        return
    try:
        coll = db[_COLL]
        doc = coll.find_one({"scope": scope}) or {}
        fams: Dict[str, Any] = doc.get("families") or {}
        for fam, s in delta.items():
            cur = fams.get(fam) or {"tried": 0, "wins": 0}
            cur["tried"] = int(cur.get("tried", 0)) + int(s.get("tried", 0))
            cur["wins"] = int(cur.get("wins", 0)) + int(s.get("wins", 0))
            cur["win_rate"] = round(cur["wins"] / cur["tried"], 3) if cur["tried"] else 0.0
            fams[fam] = cur
        coll.update_one(
            {"scope": scope},
            {"$set": {"families": fams, "updated_at": datetime.now(timezone.utc)}},
            upsert=True,
        )
    except Exception:
        pass


def family_delta(current: Dict[str, Dict[str, int]],
                 recorded: Dict[str, Dict[str, int]]) -> Dict[str, Dict[str, int]]:
    """Kümülatif `current` ile en son kaydedilen `recorded` arasındaki fark (SAF).
    Aynı tur birden çok kez çalışırsa çift-kayıt olmasın diye yalnız ARTIM kaydedilir."""
    out: Dict[str, Dict[str, int]] = {}
    for fam, s in (current or {}).items():
        pt = (recorded or {}).get(fam) or {}
        dt = int(s.get("tried", 0)) - int(pt.get("tried", 0))
        dw = int(s.get("wins", 0)) - int(pt.get("wins", 0))
        if dt > 0 or dw > 0:
            out[fam] = {"tried": max(0, dt), "wins": max(0, dw)}
    return out