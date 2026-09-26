"""
Türkçe: Nuclei proxy route'ları - /nuclei/* endpoint'leri.

main.py'den ayrıldı. Servis URL'i registry'den alınır. WebSocket monitor
proxy'si nuclei_proxy.py'den import edilir. Davranış birebir aynı.
"""
import httpx
from fastapi import APIRouter, HTTPException, WebSocket

from plugins import registry as _registry
from nuclei_proxy import proxy_nuclei_monitor

router = APIRouter(tags=["nuclei"])

NUCLEI_SERVICE_URL = _registry.url("nuclei")


@router.get("/nuclei/config")
async def get_nuclei_config():
    """Türkçe: Nuclei konfigürasyonunu frontend'e döner"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{NUCLEI_SERVICE_URL}/config", timeout=10.0)
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch nuclei config: {str(e)}")


@router.get("/nuclei/tags")
async def get_nuclei_tags():
    """Türkçe: Nuclei tag listesini frontend'e döner"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{NUCLEI_SERVICE_URL}/tags", timeout=30.0)
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch nuclei tags: {str(e)}")


@router.get("/nuclei/templates")
async def get_nuclei_templates():
    """Türkçe: Nuclei template listesini frontend'e döner"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{NUCLEI_SERVICE_URL}/templates", timeout=30.0)
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch nuclei templates: {str(e)}")


@router.get("/nuclei/logs/{scan_id}")
async def download_nuclei_log(scan_id: str):
    """Türkçe: Nuclei log dosyasını indir"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{NUCLEI_SERVICE_URL}/logs/{scan_id}", timeout=30.0)

            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Log file not found")

            return response.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download log: {str(e)}")


@router.get("/nuclei/active-scans")
async def get_nuclei_active_scans():
    """Türkçe: Aktif Nuclei taramalarını döner"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{NUCLEI_SERVICE_URL}/active-scans", timeout=10.0)
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch active scans: {str(e)}")


@router.delete("/nuclei/scan/{scan_id}")
async def stop_nuclei_scan(scan_id: str):
    """Türkçe: Aktif Nuclei taramasını durdurur"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.delete(f"{NUCLEI_SERVICE_URL}/scan/{scan_id}", timeout=10.0)
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop scan: {str(e)}")


@router.websocket("/nuclei/monitor/{scan_id}")
async def monitor_nuclei_scan(websocket: WebSocket, scan_id: str):
    """Türkçe: Devam eden bir Nuclei taramasını izler"""
    await proxy_nuclei_monitor(websocket, scan_id)
