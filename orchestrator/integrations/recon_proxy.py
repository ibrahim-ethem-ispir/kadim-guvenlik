"""
Türkçe: Recon Intelligence servisi için proxy endpoint'leri
Bu modül gelişmiş varlık keşfi ve teknoloji istihbarat servisine yapılan istekleri yönetir.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import httpx
import os

from plugins import registry as _registry

# Router tanımı - main.py'da include edilecek
router = APIRouter(prefix="/recon", tags=["Recon Intelligence"])

# Recon Service URL'i (eski cf-analyzer'ın yeni hali)
RECON_SERVICE_URL = os.getenv("RECON_SERVICE_URL", "http://recon-service:8004")
# OSINT servisinin SSL/TLS lookup endpoint'ini kullanmak için
OSINT_SERVICE_URL = _registry.url("osint")

# Request/Response modelleri
class ReconAnalysisRequest(BaseModel):
    """Türkçe: Recon Intelligence analiz isteği modeli"""
    domain: str
    wordlist: Optional[str] = "files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt"
    concurrency: Optional[int] = 50
    delay_ms: Optional[int] = 0
    timeout_minutes: Optional[int] = 10


class TechnologyInfo(BaseModel):
    """Tespit edilen teknoloji bilgisi"""
    name: str
    version: Optional[str] = None
    category: str
    confidence: int  # 0-100 arası güven skoru


class InfrastructureInfo(BaseModel):
    """Altyapı bilgisi"""
    provider: Optional[str] = None
    is_cloud: bool = False
    is_private_ip: bool = False
    is_waf_protected: bool = False


class SubdomainAsset(BaseModel):
    """Bulunan subdomain bilgisi"""
    subdomain: str
    ip: Optional[str] = None
    is_cf: bool = False
    is_live: bool = False
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    infrastructure: InfrastructureInfo
    technologies: List[TechnologyInfo] = []
    page_title: Optional[str] = None


class ScanSummary(BaseModel):
    """Tarama özeti"""
    total_subdomains_found: int
    total_live_assets: int
    total_technologies: int
    cloud_hosted_count: int
    direct_ip_count: int


class ReconAnalysisResponse(BaseModel):
    """Türkçe: Recon Intelligence analiz sonucu"""
    domain: str
    dns: dict
    http: dict
    subdomains: List[SubdomainAsset]
    summary: ScanSummary


@router.post("/analyze")
async def analyze_target(request: ReconAnalysisRequest):
    """
    Türkçe: Recon Intelligence analizi başlatır (Async)
    - Subdomain keşfi
    - Canlılık kontrolü
    - Teknoloji parmak izi tespiti
    - IP/WAF analizi
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{RECON_SERVICE_URL}/analyze",
                json=request.dict(),
                timeout=15.0  # İlk response için timeout (scan arka planda devam eder)
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code, 
                    detail=f"Recon service error: {response.text}"
                )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504, 
            detail="Recon service başlatma timeout (tarama arka planda devam ediyor)"
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Recon service bağlantı hatası: {str(e)}"
        )


@router.get("/analyze/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    Türkçe: Tarama durumunu ve sonuçlarını getirir
    Frontend real-time progress tracking için kullanır
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{RECON_SERVICE_URL}/analyze/{scan_id}",
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                raise HTTPException(status_code=404, detail="Tarama bulunamadı")
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Recon service error: {response.text}"
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Recon service timeout")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Recon service bağlantı hatası: {str(e)}")


@router.post("/analyze/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """
    Türkçe: Devam eden taramayı iptal eder
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{RECON_SERVICE_URL}/analyze/{scan_id}/cancel",
                timeout=5.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Tarama iptal edilemedi: {response.text}"
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Cancel isteği timeout")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Recon service bağlantı hatası: {str(e)}")


@router.get("/analyze/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """
    Türkçe: Çalışan taramayı iptal eder
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{RECON_SERVICE_URL}/analyze/{scan_id}/cancel",
                timeout=10.0
            )
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Recon service timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/history")
async def get_scan_history():
    """
    Türkçe: Tüm tarama geçmişini getirir (MongoDB)
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{RECON_SERVICE_URL}/history",
                timeout=10.0
            )
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Recon service timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/history/{scan_id}")
async def get_scan_detail(scan_id: str):
    """
    Türkçe: Belirli bir taramanın detaylarını getirir (MongoDB)
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{RECON_SERVICE_URL}/history/{scan_id}",
                timeout=10.0
            )
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Recon service timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/history/domain/{domain}")
async def get_domain_history(domain: str):
    """
    Türkçe: Belirli domain için tarama geçmişini getirir
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{RECON_SERVICE_URL}/history/domain/{domain}",
                timeout=10.0
            )
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Recon service timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/stats")
async def get_global_stats():
    """
    Türkçe: Global istatistikleri getirir (Dashboard için)
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{RECON_SERVICE_URL}/stats",
                timeout=10.0
            )
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Recon service timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/wordlists")
async def list_available_wordlists():
    """
    Türkçe: Kullanılabilir wordlist'leri listeler
    Frontend'de kullanıcıya seçenek sunmak için
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{RECON_SERVICE_URL}/wordlists",
                timeout=5.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Wordlist listesi alınamadı"
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Wordlist listesi timeout")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Recon service bağlantı hatası: {str(e)}")


@router.post("/tls")
async def tls_lookup(request: ReconAnalysisRequest):
    """
    Türkçe: Hedefin TLS/SSL sertifika bilgilerini OSINT servisinden çeker.
    Sertifika süresi dolma, zayıf imza algoritması, self-signed, yanlış konfigürasyon
    gibi temel TLS postürü bulgularını dış tarama sonuçlarına katabilmek için
    kullanılır (henüz otonom pipeline'a dahil değildir — öneri dokümanda).
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OSINT_SERVICE_URL}/lookup/ssl",
                json={"target": request.domain},
                timeout=15.0,
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"OSINT SSL lookup error: {response.text}",
                )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="OSINT SSL lookup timeout")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"OSINT service bağlantı hatası: {str(e)}")
