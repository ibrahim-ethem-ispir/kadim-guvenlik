# Hash Cracker Proxy - Orchestrator ile hash-cracker servisi arasında köprü
from fastapi import APIRouter, HTTPException
import httpx
import os

router = APIRouter(prefix="/hash", tags=["hash-cracker"])

HASH_CRACKER_SERVICE_URL = os.getenv("HASH_CRACKER_SERVICE_URL", "http://hash-cracker:8006")

@router.post("/crack")
async def create_hash_crack_job(request: dict):
    """Türkçe: Hash kırma işi oluştur"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{HASH_CRACKER_SERVICE_URL}/crack",
                json=request
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash cracker error: {str(e)}")

@router.get("/crack/{job_id}")
async def get_hash_crack_status(job_id: str):
    """Türkçe: Hash kırma işinin durumunu getir"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{HASH_CRACKER_SERVICE_URL}/crack/{job_id}"
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash cracker error: {str(e)}")

@router.post("/crack/{job_id}/cancel")
async def cancel_hash_crack_job(job_id: str):
    """Türkçe: Hash kırma işini iptal et"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{HASH_CRACKER_SERVICE_URL}/crack/{job_id}/cancel"
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash cracker error: {str(e)}")

@router.get("/detect")
async def detect_hash_type(hash: str):
    """Türkçe: Hash tipini otomatik tespit et"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{HASH_CRACKER_SERVICE_URL}/detect",
                params={"hash": hash}
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash cracker error: {str(e)}")

@router.get("/algorithms")
async def get_hash_algorithms():
    """Türkçe: Desteklenen hash algoritmalarını listele"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{HASH_CRACKER_SERVICE_URL}/algorithms"
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash cracker error: {str(e)}")

@router.get("/wordlists")
async def get_hash_wordlists():
    """Türkçe: Mevcut wordlist'leri listele"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{HASH_CRACKER_SERVICE_URL}/wordlists"
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash cracker error: {str(e)}")

@router.get("/health")
async def hash_cracker_health():
    """Türkçe: Hash cracker servis sağlık kontrolü"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{HASH_CRACKER_SERVICE_URL}/health"
            )
            return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hash cracker unhealthy: {str(e)}")
