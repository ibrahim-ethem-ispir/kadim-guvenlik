"""
Türkçe: Nmap proxy route'ları - /nmap/* endpoint'leri.

main.py'den ayrıldı. Servis URL'i doğrudan registry'den alınır; global'e
bağımlı değildir. Davranış birebir aynı.
"""
import httpx
from fastapi import APIRouter, HTTPException

from plugins import registry as _registry

router = APIRouter(tags=["nmap"])

NMAP_SERVICE_URL = _registry.url("nmap")


@router.get("/nmap/config")
async def get_nmap_config():
    """Türkçe: Nmap konfigürasyonunu frontend'e döner"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{NMAP_SERVICE_URL}/config", timeout=10.0)
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch nmap config: {str(e)}")


@router.post("/nmap/validate")
async def validate_nmap_options(request: dict):
    """Türkçe: Nmap parametrelerini validate eder"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{NMAP_SERVICE_URL}/validate",
                json=request,
                timeout=5.0
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@router.post("/nmap/preview")
async def preview_nmap_command(request: dict):
    """Türkçe: Nmap komutunu önizle"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{NMAP_SERVICE_URL}/preview",
                json=request,
                timeout=5.0
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Preview failed: {str(e)}")


@router.get("/nmap/logs/{scan_id}")
async def download_nmap_log(scan_id: str):
    """Türkçe: Nmap log dosyasını indir"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{NMAP_SERVICE_URL}/logs/{scan_id}", timeout=30.0)

            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Log file not found")

            return response.content
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download log: {str(e)}")
