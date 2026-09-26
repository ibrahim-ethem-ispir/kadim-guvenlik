# -*- coding: utf-8 -*-
"""
Scan Event Bus - Tarama olaylarini broadcast eden Pub/Sub sistemi

Bu modul tarama sirasinda olusan olaylari (port bulundu, zafiyet tespit edildi,
faz degisti vb.) real-time olarak frontend'e iletir.

Kullanim:
    from scan_events import ScanEventBus, ScanEvent, ScanEventType

    # Olay yayinla
    await ScanEventBus.publish(ScanEvent(
        scan_id="xxx",
        event_type=ScanEventType.PORT_FOUND,
        data={"port": 80, "service": "http"}
    ))

    # Olay dinle
    queue = await ScanEventBus.subscribe("xxx")
    event = await queue.get()
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum
import logging

logger = logging.getLogger("scan-events")


class ScanEventType(str, Enum):
    """Tarama olay tipleri"""

    # Lifecycle events
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    SCAN_STALE = "scan_stale"

    # Progress events
    PHASE_STARTED = "phase_started"
    PHASE_COMPLETED = "phase_completed"
    PROGRESS_UPDATE = "progress_update"

    # Command events
    COMMAND_EXECUTING = "command_executing"
    COMMAND_OUTPUT = "command_output"
    COMMAND_COMPLETED = "command_completed"

    # Discovery events
    PORT_FOUND = "port_found"
    SERVICE_DETECTED = "service_detected"
    OS_DETECTED = "os_detected"
    SUBDOMAIN_FOUND = "subdomain_found"

    # Vulnerability events
    VULNERABILITY_FOUND = "vulnerability_found"
    CRITICAL_FINDING = "critical_finding"

    # Autonomous engine events (otonom saldırı simülasyonu)
    AGENT_THINKING = "agent_thinking"      # "şu an şunu düşünüyorum"
    AGENT_ACTION = "agent_action"          # "şu aracı deniyorum"
    AGENT_OBSERVATION = "agent_observation"  # "şu sonucu buldum"
    AGENT_APPROVAL_NEEDED = "agent_approval_needed"  # tehlikeli aksiyon onayı
    AGENT_PHASE_GATE = "agent_phase_gate"  # iki fazlı onay kapısı (keşif→onay→sömürü)
    AGENT_LLM_EXCHANGE = "agent_llm_exchange"  # LLM istihbarat subayına gönderilen prompt + ham cevap (şeffaflık)

    # System events
    HEARTBEAT = "heartbeat"
    ERROR = "error"
    WARNING = "warning"


@dataclass
class ScanEvent:
    """Tarama olayi"""
    scan_id: str
    event_type: ScanEventType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = "orchestrator"  # Kaynak servis

    def to_dict(self) -> Dict[str, Any]:
        """JSON serializable dict'e donustur"""
        return {
            "scan_id": self.scan_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "source": self.source
        }


class ScanEventBus:
    """
    Pub/Sub Event Bus - Tarama olaylarini broadcast eden sistem

    Thread-safe asyncio.Queue tabanli sistem.
    Her scan_id icin ayri subscriber listesi tutar.
    """

    _subscribers: Dict[str, List[asyncio.Queue]] = {}
    _event_history: Dict[str, List[ScanEvent]] = {}  # Son N olay
    _max_history = 100  # Scan basina maksimum gecmis
    # Wildcard subscriber'lar: TÜM scan_id'lerden gelen olayları dinler. AI agent + WebSocket
    # push için gerekiyor — scan_id bilmeden tüm akışı görmek istiyoruz.
    _wildcard_subscribers: List[asyncio.Queue] = []

    @classmethod
    async def subscribe(cls, scan_id: str) -> asyncio.Queue:
        """
        Bir scan_id icin olay dinlemeye basla

        Returns:
            asyncio.Queue: Olaylarin gelecegi kuyruk
        """
        queue = asyncio.Queue(maxsize=1000)  # Bounded queue - memory leak onleme

        if scan_id not in cls._subscribers:
            cls._subscribers[scan_id] = []

        cls._subscribers[scan_id].append(queue)
        logger.debug(f"New subscriber for scan {scan_id}, total: {len(cls._subscribers[scan_id])}")

        return queue

    @classmethod
    async def subscribe_all(cls) -> asyncio.Queue:
        """
        TÜM scan_id'lerin olaylarını dinle. AI agent ve WebSocket push için.
        Sebep: scan_id önceden bilinmez; agent tüm akışı görüp ilgili kayıtları
        filtrelemelidir. Wildcard subscriber'lar bounded queue kullanır (memory leak
        önleme); dolu ise olay drop edilir (agent geri kalan olayları session üzerinden
        yakalayabilir).
        """
        queue = asyncio.Queue(maxsize=2000)
        cls._wildcard_subscribers.append(queue)
        logger.debug(f"New wildcard subscriber, total: {len(cls._wildcard_subscribers)}")
        return queue

    @classmethod
    async def unsubscribe_all(cls, queue: asyncio.Queue) -> None:
        try:
            cls._wildcard_subscribers.remove(queue)
        except ValueError:
            pass

    @classmethod
    async def unsubscribe(cls, scan_id: str, queue: asyncio.Queue):
        """Olay dinlemeyi birak"""
        if scan_id in cls._subscribers:
            try:
                cls._subscribers[scan_id].remove(queue)
                logger.debug(f"Unsubscribed from scan {scan_id}")

                # Bos liste ise temizle
                if not cls._subscribers[scan_id]:
                    del cls._subscribers[scan_id]
            except ValueError:
                pass  # Zaten yok

    @classmethod
    async def publish(cls, event: ScanEvent):
        """
        Olay yayinla - tum subscriber'lara gonder

        Args:
            event: Yayinlanacak olay
        """
        scan_id = event.scan_id

        # History'ye ekle
        if scan_id not in cls._event_history:
            cls._event_history[scan_id] = []

        cls._event_history[scan_id].append(event)

        # Max history kontrolu
        if len(cls._event_history[scan_id]) > cls._max_history:
            cls._event_history[scan_id] = cls._event_history[scan_id][-cls._max_history:]

        # Subscriber'lara gonder
        if scan_id in cls._subscribers:
            dead_queues = []

            for queue in cls._subscribers[scan_id]:
                try:
                    # Non-blocking put - queue dolu ise skip
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning(f"Queue full for scan {scan_id}, dropping event")
                except Exception as e:
                    logger.error(f"Error publishing event: {e}")
                    dead_queues.append(queue)

            # Olmus queue'lari temizle
            for dq in dead_queues:
                try:
                    cls._subscribers[scan_id].remove(dq)
                except ValueError:
                    pass

        # Wildcard subscriber'lara da gönder (AI agent + WS push). Dolu ise drop — agent
        # bir sonraki olayı bekler, geri kalanı session üzerinden telafi edebilir.
        dead_wildcards = []
        for wq in cls._wildcard_subscribers:
            try:
                wq.put_nowait(event)
            except asyncio.QueueFull:
                logger.debug(f"Wildcard queue full, dropping {event.event_type.value}")
            except Exception:
                dead_wildcards.append(wq)
        for dq in dead_wildcards:
            try:
                cls._wildcard_subscribers.remove(dq)
            except ValueError:
                pass

        logger.debug(f"Published {event.event_type.value} for scan {scan_id}")

    @classmethod
    async def publish_batch(cls, events: List[ScanEvent]):
        """Birden fazla olayi yayinla"""
        for event in events:
            await cls.publish(event)

    @classmethod
    def get_history(cls, scan_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Scan icin olay gecmisini al"""
        if scan_id not in cls._event_history:
            return []

        events = cls._event_history[scan_id][-limit:]
        return [e.to_dict() for e in events]

    @classmethod
    def get_subscriber_count(cls, scan_id: str) -> int:
        """Bir scan icin subscriber sayisi"""
        return len(cls._subscribers.get(scan_id, []))

    @classmethod
    def cleanup_scan(cls, scan_id: str):
        """Scan tamamlaninca temizlik yap"""
        if scan_id in cls._subscribers:
            # Tum subscriber'lara None gonder (baglanti kapanacak)
            for queue in cls._subscribers[scan_id]:
                try:
                    queue.put_nowait(None)
                except:
                    pass
            del cls._subscribers[scan_id]

        # History'yi bir sure daha tut (debug icin)
        # Isterseniz burada da silebilirsiniz


# ============== Yardimci Fonksiyonlar ==============

async def emit_scan_started(scan_id: str, target: str, scan_types: List[str], command_preview: str = None):
    """Tarama basladi olayi yayinla"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.SCAN_STARTED,
        data={
            "target": target,
            "scan_types": scan_types,
            "command_preview": command_preview
        }
    ))


async def emit_command_executing(scan_id: str, service: str, command: str):
    """Komut calistiriliyor olayi"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.COMMAND_EXECUTING,
        source=service,
        data={
            "service": service,
            "command": command
        }
    ))


async def emit_port_found(scan_id: str, port: int, protocol: str, service: str = None, state: str = "open"):
    """Port bulundu olayi"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.PORT_FOUND,
        source="nmap",
        data={
            "port": port,
            "protocol": protocol,
            "service": service,
            "state": state
        }
    ))


async def emit_vulnerability_found(scan_id: str, template_id: str, name: str, severity: str, matched_at: str):
    """Zafiyet bulundu olayi"""
    event_type = ScanEventType.CRITICAL_FINDING if severity in ["critical", "high"] else ScanEventType.VULNERABILITY_FOUND

    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=event_type,
        source="nuclei",
        data={
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "matched_at": matched_at
        }
    ))


async def emit_progress_update(scan_id: str, phase: str, percentage: int, message: str = None):
    """Ilerleme durumu olayi"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.PROGRESS_UPDATE,
        data={
            "phase": phase,
            "percentage": percentage,
            "message": message
        }
    ))


async def emit_scan_completed(scan_id: str, summary: Dict[str, Any]):
    """Tarama tamamlandi olayi"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.SCAN_COMPLETED,
        data=summary
    ))

    # Cleanup
    ScanEventBus.cleanup_scan(scan_id)


async def emit_scan_failed(scan_id: str, error: str, service: str = None):
    """Tarama basarisiz olayi"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.SCAN_FAILED,
        source=service or "orchestrator",
        data={
            "error": error,
            "service": service
        }
    ))

    # Cleanup
    ScanEventBus.cleanup_scan(scan_id)


async def emit_error(scan_id: str, error: str, source: str = "orchestrator"):
    """Hata olayi (tarama devam edebilir)"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.ERROR,
        source=source,
        data={"error": error}
    ))


async def emit_heartbeat(scan_id: str, message: str = None):
    """Heartbeat olayi"""
    await ScanEventBus.publish(ScanEvent(
        scan_id=scan_id,
        event_type=ScanEventType.HEARTBEAT,
        data={"message": message or "Scan is running..."}
    ))
