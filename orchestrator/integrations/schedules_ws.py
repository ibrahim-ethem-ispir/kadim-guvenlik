"""
Türkçe: Scheduled scans için gerçek-zamanlı WebSocket kanalı.

Tasarım kararları (sebep/sonuç):
- `ScanEventBus.subscribe_all()` kullanır — scan_id bilmeden tüm olayları yakalar.
- İstemci bağlanınca: (1) mevcut kayıtları snapshot olarak gönder, (2) son olayları
  replay et (auto-scan'in `event_history` deseni). Sonra canlı olayları iletir.
- Schedule'a özel olaylar: SCAN_COMPLETED, SCAN_FAILED, CRITICAL_FINDING, SUBDOMAIN_FOUND
  → scheduled kayıtla eşleşiyorsa ilgili schedule_id ile birlikte frontend'e ilet.
- AuthMiddleware zaten token doğruluyor; burada ekstra auth gerekmez.
- Kopma yönetimi: istemci `WebSocketDisconnect` fırlatır, queue unsubscribe.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pymongo import MongoClient

from pipeline.scan_events import ScanEventBus, ScanEventType

logger = logging.getLogger("orchestrator.schedules_ws")

router = APIRouter()

MONGODB_URI = __import__("os").getenv("MONGODB_URI", "mongodb://mongodb:27017")
MONGODB_DATABASE = __import__("os").getenv("MONGODB_DATABASE", "kadim_security")

_mongo: MongoClient = None  # type: ignore


def _db():
    global _mongo
    if _mongo is None:
        _mongo = MongoClient(MONGODB_URI)
    return _mongo[MONGODB_DATABASE]


# İlgili event tipleri — diğerleri filtrelenir
_SCHEDULED_RELEVANT = {
    ScanEventType.SCAN_STARTED,
    ScanEventType.SCAN_COMPLETED,
    ScanEventType.SCAN_FAILED,
    ScanEventType.CRITICAL_FINDING,
    ScanEventType.SUBDOMAIN_FOUND,
}


def _event_to_ws_payload(event, schedule_match: Dict[str, Any]) -> Dict[str, Any]:
    """ScanEvent'i frontend için normalize et."""
    return {
        "type": "scan_event",
        "event_type": event.event_type.value,
        "scan_id": event.scan_id,
        "target": event.data.get("target", ""),
        "schedule_id": schedule_match.get("schedule_id"),
        "data": event.data,
        "timestamp": event.timestamp.isoformat() if isinstance(event.timestamp, datetime) else str(event.timestamp),
    }


# Gateway `/api/` önekini upstream'e göndermeden önce strip eder; uygulama içindeki
# route bu yüzden `/schedules/...` olmalı. `/api/...` yazılırsa nginx doğru iletse bile
# FastAPI route bulamaz ve WebSocket 403 ile kapanır.
@router.websocket("/schedules/ws/events")
async def schedules_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    logger.info("WS bağlandı: %s", websocket.client)
    queue = await ScanEventBus.subscribe_all()
    try:
        # 1) Snapshot: mevcut aktif schedule'lar ve anomaly'ler
        schedules_col = _db()["scan_schedules"]
        active = list(schedules_col.find({"enabled": True}, {"_id": 1, "target": 1, "label": 1}))
        await websocket.send_json({
            "type": "snapshot",
            "active_schedules": [
                {"schedule_id": str(s["_id"]), "target": s.get("target"), "label": s.get("label")}
                for s in active
            ],
            "server_time": datetime.now(timezone.utc).isoformat(),
        })

        # 2) Canlı event loop
        while True:
            # Hem istemciden ping gelirse (uygulama dead check) hem de event gelirse işle
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Heartbeat — istemci bağlantı koptuğunda bunu almayınca disconnect olur
                await websocket.send_json({"type": "heartbeat", "ts": datetime.now(timezone.utc).isoformat()})
                continue

            if event.event_type not in _SCHEDULED_RELEVANT:
                continue

            target = event.data.get("target", "")
            # Bu target için aktif bir schedule var mı?
            sched = schedules_col.find_one({"target": target, "enabled": True})
            await websocket.send_json(_event_to_ws_payload(event, {
                "schedule_id": str(sched["_id"]) if sched else None,
            }))
    except WebSocketDisconnect:
        logger.info("WS koptu: %s", websocket.client)
    except Exception as e:
        logger.exception("WS hata: %s", e)
    finally:
        await ScanEventBus.unsubscribe_all(queue)
