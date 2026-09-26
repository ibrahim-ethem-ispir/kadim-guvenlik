"""
Türkçe: CF Analyzer servisi için proxy endpoint'leri
Bu modül CF Analyzer servisine yapılan istekleri yönetir.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import httpx
import os

# Router tanımı - main.py'da include edilecek
router = APIRouter(prefix="/cf-analyzer", tags=["CF Analyzer"])

# CF Analyzer servis URL'i (Recon Service'e forward etme - backward compatibility için)
# CF Analyzer artık Recon Intelligence servisi tarafından yönetiliyor
CF_ANALYZER_SERVICE_URL = os.getenv("RECON_SERVICE_URL", "http://recon-service:8004")

# Request/Response modelleri
class CFAnalyzerRequest(BaseModel):
    """Türkçe: CF Analyzer için analiz isteği modeli"""
    domain: str
    wordlist: Optional[str] = "files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt"
    concurrency: Optional[int] = 50
    delay_ms: Optional[int] = 0
    timeout_minutes: Optional[int] = 10


@router.post("/analyze")
async def analyze_cloudflare(request: CFAnalyzerRequest):
    """
    Türkçe: Cloudflare analizi başlatır (Async)
    Domain için DNS, HTTP ve subdomain analizi yapar
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{CF_ANALYZER_SERVICE_URL}/analyze",
                json=request.dict(),
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code, 
                    detail=f"CF Analyzer service error: {response.text}"
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="CF Analyzer service timeout")
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="CF Analyzer service unavailable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start analysis: {str(e)}")


@router.get("/analyze/{scan_id}")
async def get_cf_scan_status(scan_id: str):
    """
    Türkçe: Cloudflare analiz durumunu sorgular
    Tarama ilerlemesi, loglar ve sonuçları döndürür
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{CF_ANALYZER_SERVICE_URL}/analyze/{scan_id}",
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                # Eğer sonuç null ise 404 döndür
                if result is None:
                    raise HTTPException(status_code=404, detail="Scan not found")
                return result
            else:
                raise HTTPException(
                    status_code=response.status_code, 
                    detail=f"CF Analyzer service error: {response.text}"
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="CF Analyzer service timeout")
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="CF Analyzer service unavailable")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")


@router.post("/analyze/{scan_id}/cancel")
async def cancel_cf_scan(scan_id: str):
    """
    Türkçe: Cloudflare analizini iptal eder
    Durdur butonu için kullanılır
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{CF_ANALYZER_SERVICE_URL}/analyze/{scan_id}/cancel",
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code, 
                    detail=f"CF Analyzer service error: {response.text}"
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="CF Analyzer service timeout")
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="CF Analyzer service unavailable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel scan: {str(e)}")


@router.get("/wordlists")
async def list_wordlists():
    """
    Türkçe: Kullanılabilir wordlist'leri listeler
    SecLists'ten DNS wordlist'lerini döndürür
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{CF_ANALYZER_SERVICE_URL}/wordlists",
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code, 
                    detail=f"CF Analyzer service error: {response.text}"
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="CF Analyzer service timeout")
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="CF Analyzer service unavailable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list wordlists: {str(e)}")
