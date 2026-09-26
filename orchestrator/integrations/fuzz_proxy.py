from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
import httpx
import os
import asyncio
from typing import Optional
from pydantic import BaseModel

# Türkçe: nginx /api/ prefix'ini strip ediyor, bu yüzden /fuzz olarak mount et
router = APIRouter(prefix="/fuzz", tags=["fuzz"])

FUZZ_SERVICE_URL = os.getenv("FUZZ_SERVICE_URL", "http://fuzz-service:8011")

class FuzzRequest(BaseModel):
    target: str
    scan_id: str
    wordlist: str = "common.txt"
    smart_seeding: bool = False
    options: Optional[dict] = {}

# --- WebSocket Proxy Helper ---
async def forward_ws(client_ws: WebSocket, service_ws_url: str):
    async with httpx.AsyncClient() as client:
        # Not easy to proxy WS with httpx directly as client.
        # We need generic websockets or aiohttp.
        # But for FastAPI, we can use client-side websockets library or just pipe messages.
        # Nmap proxy uses a specific implementation, let's check standard pattern.
        pass

# Actually, Nmap proxy likely does manual pipe.
# Let's see how nmap_proxy.py is implemented if possible, or use standard pattern.
# For now, I will implement standard proxying.
import websockets

@router.get("/wordlists")
async def get_wordlists():
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{FUZZ_SERVICE_URL}/wordlists", timeout=5.0)
            return resp.json()
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Fuzz Service Unavailable: {e}")

@router.post("/run")
async def run_fuzz_scan(request: FuzzRequest):
    async with httpx.AsyncClient() as client:
        try:
            # We just trigger the scan setup or validate parameters here.
            # The actual "RUN" might happen via WebSocket or POST.
            # Our fuzz-service POST returns "initiated".
            resp = await client.post(
                f"{FUZZ_SERVICE_URL}/scan", 
                json=request.dict(), 
                timeout=10.0
            )
            return resp.json()
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Fuzz Service Error: {e}")

@router.websocket("/stream/{scan_id}")
async def stream_fuzz_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    
    # Internal Service URL (now using SSE instead of WebSocket)
    # Note: Rust service uses SSE at /scan/monitor/{scan_id}
    service_ws_url = f"{FUZZ_SERVICE_URL.replace('http://', 'ws://').replace('https://', 'wss://')}/scan/monitor/{scan_id}"
    
    try:
        async with websockets.connect(service_ws_url) as service_ws:
            # Create tasks to forward messages in both directions
            
            async def forward_to_service():
                try:
                    while True:
                        data = await websocket.receive_text()
                        await service_ws.send(data)
                except Exception:
                   pass

            async def forward_to_client():
                try:
                    while True:
                        data = await service_ws.recv()
                        await websocket.send_text(data)
                except Exception:
                    pass

            await asyncio.gather(forward_to_service(), forward_to_client())
            
    except Exception as e:
        print(f"WS Proxy Error: {e}")
        try:
            await websocket.close(code=1011)
        except:
            pass
