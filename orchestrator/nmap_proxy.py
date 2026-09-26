"""
Türkçe: Nmap servisine WebSocket proxy - Frontend'den gelen real-time stream isteklerini yönlendirir
"""
from fastapi import WebSocket, WebSocketDisconnect
import websockets
import json
import logging
import os
import asyncio

logger = logging.getLogger("nmap-proxy")

NMAP_SERVICE_URL = os.getenv("NMAP_SERVICE_URL", "http://nmap-service:8001")
# http:// ve https:// ikisini de güvenli şekilde ws/wss'ye çevir
NMAP_WS_URL = NMAP_SERVICE_URL.replace("https://", "wss://").replace("http://", "ws://")

async def proxy_nmap_stream(websocket: WebSocket, scan_id: str, target: str, options: dict):
    """Türkçe: Frontend WebSocket'i nmap-service WebSocket'ine bağlar (Yeni Tarama)
    Uzun süreli taramalar için heartbeat ve keepalive desteği"""
    # WebSocket is already accepted in main.py
    
    logger.info(f"🔌 proxy_nmap_stream: Starting stream for {scan_id}, target: {target}")
    
    try:
        # Türkçe: Nmap servisine WebSocket bağlantısı aç (timeout yok, sonsuz bekleyebilir)
        async with websockets.connect(
            f"{NMAP_WS_URL}/scan/stream/{scan_id}",
            ping_interval=30,  # Her 30 saniyede ping gönder
            ping_timeout=300,  # Pong için 5 dakika bekle
            close_timeout=10
        ) as nmap_ws:
            logger.info(f"✅ proxy_nmap_stream: Connected to nmap-service for {scan_id}")
            
            # Türkçe: İlk mesajda scan parametrelerini gönder
            await nmap_ws.send(json.dumps({
                "target": target,
                "options": options
            }))
            
            # Türkçe: Frontend'e başlangıç mesajı
            await websocket.send_json({
                "type": "status",
                "data": "WebSocket bağlantısı kuruldu, tarama başlatılıyor...",
                "timestamp": ""
            })
            
            # Türkçe: Nmap'ten gelen her mesajı frontend'e ilet
            async for message in nmap_ws:
                try:
                    data = json.loads(message)
                    logger.debug(f"📨 Nmap→Frontend: {data.get('type')} - {data.get('data', '')[:50]}...")
                    await websocket.send_json(data)
                    
                    # Türkçe: Tarama tamamlandıysa bağlantıyı kapat
                    if data.get("type") == "complete":
                        logger.info(f"✅ proxy_nmap_stream: Scan completed for {scan_id}")
                        break
                except Exception as send_error:
                    logger.error(f"❌ Error sending to frontend: {send_error}")
                    break
                    
    except WebSocketDisconnect:
        logger.info(f"Frontend disconnected from scan {scan_id}")
    except asyncio.TimeoutError:
        logger.error(f"WebSocket timeout for scan {scan_id}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": "WebSocket bağlantısı zaman aşımına uğradı. Tarama arka planda devam ediyor, sonuçları tarama geçmişinden kontrol edebilirsiniz."
            })
        except:
            pass
    except Exception as e:
        logger.error(f"WebSocket proxy error: {str(e)}")
        try:
            # Hassas bilgileri temizle
            safe_error = "Tarama bağlantısında bir hata oluştu. Tarama arka planda devam ediyor olabilir."
            await websocket.send_json({"type": "error", "message": safe_error})
        except:
            pass

async def proxy_nmap_monitor(websocket: WebSocket, scan_id: str):
    """Türkçe: Frontend WebSocket'i nmap-service Monitor WebSocket'ine bağlar (İzleme)"""
    # WebSocket already accepted in main.py
    logger.info(f"🔌 proxy_nmap_monitor: Connecting to nmap-service for {scan_id}")
    
    try:
        # Türkçe: Nmap servisine WebSocket bağlantısı aç (timeout yok, sonsuz bekleyebilir)
        async with websockets.connect(
            f"{NMAP_WS_URL}/scan/monitor/{scan_id}",
            ping_interval=30,  # Her 30 saniyede ping gönder
            ping_timeout=300,  # Pong için 5 dakika bekle
            close_timeout=10
        ) as nmap_ws:
            logger.info(f"✅ proxy_nmap_monitor: Connected to nmap-service for {scan_id}")
            
            # Türkçe: Nmap'ten gelen her mesajı frontend'e ilet
            async for message in nmap_ws:
                data = json.loads(message)
                logger.debug(f"📨 Nmap→Frontend: {data.get('type')} - {data.get('data', '')[:50]}...")
                await websocket.send_json(data)
                
                # Türkçe: Complete mesajı geldiyse çık
                if data.get("type") == "complete":
                    logger.info(f"✅ proxy_nmap_monitor: Scan completed for {scan_id}")
                    break
                # Türkçe: Error mesajı geldiyse çık
                if data.get("type") == "error":
                    logger.warning(f"⚠️ proxy_nmap_monitor: Error for {scan_id}: {data.get('message')}")
                    break
                    
    except WebSocketDisconnect:
        logger.info(f"Frontend disconnected from monitor {scan_id}")
    except asyncio.TimeoutError:
        logger.error(f"WebSocket monitor timeout for scan {scan_id}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": "WebSocket bağlantısı zaman aşımına uğradı. Log dosyası oluşmamış olabilir veya tarama henüz başlamamış."
            })
        except:
            pass
    except Exception as e:
        logger.error(f"WebSocket monitor proxy error: {str(e)}")
        try:
            # Hassas bilgileri temizle
            safe_error = "İzleme bağlantısında bir hata oluştu. Log dosyasını kontrol edebilirsiniz."
            await websocket.send_json({"type": "error", "message": safe_error})
        except:
            pass
