"""
Türkçe: Otonom tarama sırasında çalışan tüm araçların (nmap, nuclei, ...) ham log
çıktısını tek bir WebSocket üzerinden frontend'e iletir. Her araç kendi servisinde
ayrı WebSocket açar; bu modül onları birleştirir.
"""
import asyncio
import json
import logging
import os
from typing import Optional

import websockets
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("raw-log-proxy")

NMAP_SERVICE_URL = os.getenv("NMAP_SERVICE_URL", "http://nmap-service:8001")
NUCLEI_SERVICE_URL = os.getenv("NUCLEI_SERVICE_URL", "http://nuclei-service:8003")


def _to_ws(url: str) -> str:
    return url.replace("https://", "wss://").replace("http://", "ws://")


async def _pipe_monitor(websocket: WebSocket, service_ws_url: str, scan_id: str, label: str):
    """Tek bir servisin monitor WebSocket'inden gelen mesajları frontend'e aktar.
    Servis ayakta değilse sessizce çık; diğer kaynaklar çalışmaya devam etsin."""
    try:
        async with websockets.connect(
            service_ws_url,
            ping_interval=30,
            ping_timeout=300,
            close_timeout=5,
        ) as svc_ws:
            logger.info(f"🔌 raw-log-proxy: {label} connected for {scan_id}")
            async for message in svc_ws:
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    data = {"type": "log", "data": message}
                # Hangi kaynaktan geldiğini belirt
                await websocket.send_json({
                    "type": data.get("type", "log"),
                    "source": label,
                    "data": data.get("data", data),
                    "timestamp": data.get("timestamp", ""),
                })
    except (websockets.exceptions.InvalidURI,
            websockets.exceptions.WebSocketException,
            OSError,
            asyncio.TimeoutError) as e:
        logger.debug(f"raw-log-proxy {label} bağlantısı kapandı/kurulamadı ({scan_id}): {e}")
    except Exception as e:
        logger.debug(f"raw-log-proxy {label} hata ({scan_id}): {e}")


async def proxy_raw_log_stream(websocket: WebSocket, scan_id: str):
    """Frontend'ten gelen tek bağlantıyı nmap + nuclei monitorlerine bağlar.
    Tarama hangi aşamadaysa ilgili araçtan log gelmeye başlar; diğerleri sessizce
    bekler veya servis ayakta değilse hiç açılmaz."""
    await websocket.accept()
    logger.info(f"🔌 raw-log-proxy: client connected for {scan_id}")

    nmap_ws_url = f"{_to_ws(NMAP_SERVICE_URL)}/scan/monitor/{scan_id}"
    nuclei_ws_url = f"{_to_ws(NUCLEI_SERVICE_URL)}/ws/monitor/{scan_id}"

    tasks = [
        asyncio.create_task(_pipe_monitor(websocket, nmap_ws_url, scan_id, "nmap")),
        asyncio.create_task(_pipe_monitor(websocket, nuclei_ws_url, scan_id, "nuclei")),
    ]

    try:
        await asyncio.gather(*tasks)
    except WebSocketDisconnect:
        logger.info(f"raw-log-proxy: frontend disconnected from {scan_id}")
    except Exception as e:
        logger.error(f"raw-log-proxy hata ({scan_id}): {e}")
    finally:
        for t in tasks:
            t.cancel()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass
