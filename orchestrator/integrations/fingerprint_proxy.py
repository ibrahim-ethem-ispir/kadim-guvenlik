"""
Türkçe: Parmak İzi (wappalyzergo) servisi için proxy endpoint'i.
Manuel tarama sayfasının "hızlı teknoloji tespiti" alanı bunu kullanır: bir domain/IP verilince
diğer taramaları çalıştırmadan hedefteki teknolojileri (isim/sürüm/kategori/CPE) döndürür.
auto-scan bunu OTOMATİK yapar; burası operatörün elle, hızlı kontrolü içindir.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import httpx
import os

router = APIRouter(prefix="/fingerprint", tags=["Fingerprint"])

FINGERPRINT_SERVICE_URL = os.getenv("FINGERPRINT_SERVICE_URL", "http://fingerprint-service:8013")


class FingerprintRequest(BaseModel):
    """Hızlı parmak-izi isteği. url ya da bare host/IP kabul edilir; servis şema (https→http)
    denemesini kendi yapar. html verilirse (opsiyonel) o gövde üstünde tespit yapılır."""
    target: str
    html: Optional[str] = None


@router.post("/analyze")
async def analyze_fingerprint(request: FingerprintRequest):
    """Hedefteki teknolojileri wappalyzergo ile tespit eder (tahribatsız, tek GET).
    Degrade-safe: servis kapalıysa 503 döner — UI operatöre net mesaj gösterir."""
    target = (request.target or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Hedef (domain/IP) boş olamaz.")

    payload = {"url": target}
    if request.html:
        payload["html"] = request.html[:2_000_000]

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=6.0)) as client:
            resp = await client.post(f"{FINGERPRINT_SERVICE_URL}/fingerprint", json=payload)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code,
                                detail=f"Fingerprint service hatası: {resp.text[:200]}")
        result = resp.json()
        # TLS/IP İSTİHBARATI: sertifika SAN'ı + sunucu grubu (IP'ler) + ana IP + CDN.
        # Teknoloji tespitiyle aynı yanıtta döner → UI tek panelde gösterir. Degrade-safe.
        try:
            from pipeline.tls_intel import grab_tls_intel
            result["server_intel"] = await grab_tls_intel(target)
        except Exception:
            pass
        return result
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Parmak izi tespiti zaman aşımına uğradı.")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503,
                            detail=f"Fingerprint service bağlantı hatası: {str(e)}")
