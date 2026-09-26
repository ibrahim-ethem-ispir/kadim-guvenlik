"""
Türkçe: Nuclei servisine WebSocket proxy - Frontend'den gelen real-time stream isteklerini yönlendirir
"""
from fastapi import WebSocket, WebSocketDisconnect
import websockets
import json
import logging
import os

logger = logging.getLogger("nuclei-proxy")

NUCLEI_SERVICE_URL = os.getenv("NUCLEI_SERVICE_URL", "http://nuclei-service:8003")
# Replace http with ws, handling both http:// and https://
if NUCLEI_SERVICE_URL.startswith("https://"):
    NUCLEI_WS_URL = NUCLEI_SERVICE_URL.replace("https://", "wss://")
else:
    NUCLEI_WS_URL = NUCLEI_SERVICE_URL.replace("http://", "ws://")

async def proxy_nuclei_monitor(websocket: WebSocket, scan_id: str):
    """Türkçe: Frontend WebSocket'i nuclei-service Monitor WebSocket'ine bağlar (İzleme)"""
    await websocket.accept()
    
    try:
        # Türkçe: Nuclei servisine WebSocket bağlantısı aç
        async with websockets.connect(f"{NUCLEI_WS_URL}/ws/monitor/{scan_id}") as nuclei_ws:
            # Türkçe: Nuclei'den gelen her mesajı frontend'e ilet
            async for message in nuclei_ws:
                try:
                    data = json.loads(message)
                    await websocket.send_json(data)
                except json.JSONDecodeError:
                    logger.warning(f"Malformed JSON received from Nuclei: {message}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
    except WebSocketDisconnect:
        logger.info(f"Frontend disconnected from monitor {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket monitor proxy error: {str(e)}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass
