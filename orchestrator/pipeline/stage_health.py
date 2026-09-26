"""
Kadim Güvenlik — Aşama sağlığı / degraded-stage görünürlüğü (§2.6)
=================================================================
Türkçe: Otonom tarama döngüsünde bir aşama (stage) DÜŞTÜĞÜNDE bunu deterministik
sınıflar ve operatöre görünür özet üretir.

NEDEN (kök-neden düzeltmesi)
----------------------------
Çekirdek pipeline'da 30+ geniş `except Exception` başarısızlığı sessizce (debug/warning)
yutuyordu; tarama "başarılı" görünüp eksik sonuç veriyordu ("nereden tutsan eksik" hissi).
Doktrin gereği tarama DURMAZ (hard-fail yerine kısmi sonuç) — ama başarısızlık ARTIK
GÖRÜNÜR: her düşen aşama kaydedilir, WARNING olayı yayınlanır, tarama sonu özetinde
"N aşamadan M'si düştü" bildirilir.

SAF ve BAĞIMSIZ: yalnız stdlib. İzole test edilebilir.
"""

from typing import Any, Dict, List, Optional

# 'skipped' BİLİNÇLİ bir atlamadır (motor o aracı gereksiz buldu) — düşme SAYILMAZ.
# 'completed' başarı. Yalnız 'failed'/'timeout' gerçek bozulmadır.
_DEGRADED_STATUSES = frozenset({"failed", "timeout"})


def is_degraded(status: Optional[str]) -> bool:
    """Bir aşama durumu gerçek bir bozulma mı (failed/timeout) yoksa değil mi?"""
    return (status or "").lower() in _DEGRADED_STATUSES


def build_degraded_record(
    stage_name: str, tool: str, step: int, status: str, error: Optional[str] = None
) -> Dict[str, Any]:
    """Düşen bir aşamayı operatör-okunur tek kayda indir."""
    return {
        "stage": stage_name,
        "tool": tool,
        "step": step,
        "status": status,
        "error": error or "",
    }


def summarize_degraded(degraded: List[Dict[str, Any]], total_stages: int) -> Dict[str, Any]:
    """Düşen aşamalardan tarama-sonu özeti üret (görünürlük bloğu)."""
    count = len(degraded)
    if count == 0:
        return {
            "degraded_count": 0,
            "total_stages": total_stages,
            "degraded_stages": [],
            "message": "Tüm aşamalar sağlıklı tamamlandı.",
        }
    tools = ", ".join(sorted({d.get("tool", "?") for d in degraded}))
    return {
        "degraded_count": count,
        "total_stages": total_stages,
        "degraded_stages": degraded,
        "message": f"{total_stages} aşamadan {count}'i düştü ({tools}) — kısmi sonuç.",
    }
