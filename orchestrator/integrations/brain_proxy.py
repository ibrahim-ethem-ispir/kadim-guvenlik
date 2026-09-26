"""
AI Brain Proxy - Orchestrator to AI Brain communication
Türkçe: AI Brain servisine proxy

Otomatik Tetikleme Durumları:
1. Tarama tamamlandığında → Brain'e öğrenme sinyali
2. Critical bulgu tespit edildiğinde → Attack chain önerisi
3. Nuclei critical bulgu → Zero-day hunter benzeri patternler iste
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
import httpx
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

router = APIRouter(prefix="/ai/brain", tags=["AI Brain"])

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8009")

# ============== Helper ==============

async def brain_request(method: str, path: str, data: dict = None, timeout: float = 120.0) -> dict:
    """AI Brain'e request gönder"""
    async with httpx.AsyncClient(timeout=timeout) as client:
        url = f"{AI_SERVICE_URL}/brain{path}"
        
        if method == "GET":
            response = await client.get(url)
        elif method == "POST":
            response = await client.post(url, json=data or {})
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        
        return response.json()


# ============== Endpoints ==============

@router.get("/status")
async def get_brain_status():
    """Brain durumunu al"""
    try:
        return await brain_request("GET", "/status")
    except Exception as e:
        return {"status": "unavailable", "error": str(e)}


@router.post("/analyze")
async def smart_analyze(request: dict):
    """Akıllı analiz - otomatik model seçimi"""
    return await brain_request("POST", "/analyze", request)


@router.post("/strategy")
async def get_strategy(request: dict):
    """Hedef için strateji al"""
    return await brain_request("POST", "/strategy", request)


@router.post("/tools/generate")
async def generate_tool(request: dict):
    """AI ile araç üret"""
    return await brain_request("POST", "/tools/generate", request, timeout=180.0)


@router.get("/tools/list")
async def list_tools(tool_type: Optional[str] = None):
    """Üretilen araçları listele"""
    path = f"/tools/list?tool_type={tool_type}" if tool_type else "/tools/list"
    return await brain_request("GET", path)


@router.post("/hunt/zeroday")
async def hunt_zero_day(request: dict):
    """Zero-day avı başlat"""
    return await brain_request("POST", "/hunt/zeroday", request, timeout=300.0)


@router.get("/hunt/zeroday/{finding_id}/poc")
async def get_zeroday_poc(finding_id: str):
    """Zero-day PoC al"""
    return await brain_request("GET", f"/hunt/zeroday/{finding_id}/poc")


@router.post("/chain/build")
async def build_attack_chain(request: dict):
    """Attack chain oluştur"""
    return await brain_request("POST", "/chain/build", request, timeout=180.0)


@router.post("/learn")
async def learn_from_scan(request: dict):
    """Taramadan öğren"""
    return await brain_request("POST", "/learn", request)


@router.get("/memory/stats")
async def get_memory_stats():
    """Memory istatistikleri"""
    return await brain_request("GET", "/memory/stats")


@router.post("/memory/search")
async def search_memory(query: str, pattern_type: Optional[str] = None, limit: int = 10):
    """Memory'de pattern ara"""
    path = f"/memory/search?query={query}&limit={limit}"
    if pattern_type:
        path += f"&pattern_type={pattern_type}"
    return await brain_request("POST", path)


# ============== PHANTOM Endpoints ==============

@router.post("/phantom/start")
async def start_phantom(request: dict):
    """PHANTOM session başlat"""
    return await brain_request("POST", "/phantom/start", request, timeout=300.0)


@router.post("/phantom/autonomous/start")
async def start_phantom_autonomous(request: dict):
    """PHANTOM autonomous full-cycle hunt başlat"""
    return await brain_request("POST", "/phantom/autonomous/start", request, timeout=300.0)


@router.get("/phantom/autonomous/stream")
async def stream_phantom_autonomous(
    request: Request,
    target: str,
    risk_tolerance: float = 0.3,
    depth: str = "normal",
    skip_wait: bool = False,
    preferred_model: Optional[str] = None
):
    """PHANTOM autonomous hunt - real-time SSE stream"""
    # Frontend'den gelen Authorization header'ını al
    auth_header = request.headers.get("Authorization")

    # SSE stream için AI service'e direkt bağlan
    async def event_stream():
        url = f"{AI_SERVICE_URL}/brain/phantom/autonomous/stream"
        params = {
            "target": target,
            "risk_tolerance": risk_tolerance,
            "depth": depth,
            "skip_wait": skip_wait
        }
        if preferred_model:
            params["preferred_model"] = preferred_model

        # Authorization header'ı ilet (internal service-to-service için)
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header

        async with httpx.AsyncClient(timeout=3600.0) as client:
            async with client.stream("GET", url, params=params, headers=headers) as response:
                if response.status_code != 200:
                    error_text = await response.aread()
                    yield f"data: {{'type': 'error', 'message': 'HTTP {response.status_code}: {error_text.decode()}'}}\n\n"
                    return

                async for chunk in response.aiter_bytes():
                    yield chunk.decode()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.get("/phantom/sessions")
async def list_phantom_sessions():
    """Aktif PHANTOM session'larını listele"""
    return await brain_request("GET", "/phantom/sessions")


@router.get("/phantom/{session_id}")
async def get_phantom_session(session_id: str):
    """PHANTOM session detayı"""
    return await brain_request("GET", f"/phantom/{session_id}")


@router.get("/phantom/{session_id}/progress")
async def get_phantom_progress(session_id: str):
    """PHANTOM session progress"""
    return await brain_request("GET", f"/phantom/{session_id}/progress")


@router.get("/phantom/{session_id}/timeline")
async def get_phantom_timeline(session_id: str):
    """PHANTOM session timeline"""
    return await brain_request("GET", f"/phantom/{session_id}/timeline")


@router.get("/phantom/{session_id}/report")
async def get_phantom_report(session_id: str):
    """PHANTOM session report"""
    return await brain_request("GET", f"/phantom/{session_id}/report")


@router.post("/phantom/{session_id}/stop")
async def stop_phantom_session(session_id: str, reason: str = "User stopped"):
    """PHANTOM session durdur"""
    return await brain_request("POST", f"/phantom/{session_id}/stop?reason={reason}", {})


@router.get("/phantom/scheduler/info")
async def get_phantom_scheduler_info(detection_risk: float = 0.3, timezone: str = "Europe/Istanbul"):
    """PHANTOM scheduler bilgisi"""
    return await brain_request("GET", f"/phantom/scheduler/info?detection_risk={detection_risk}&timezone={timezone}")


@router.post("/phantom/confidence/calculate")
async def calculate_phantom_confidence(request: dict):
    """PHANTOM confidence hesapla"""
    return await brain_request("POST", "/phantom/confidence/calculate", request)


# ============== Auto-Trigger Functions ==============

async def trigger_brain_learning(scan_id: str, target: str, scan_data: dict):
    """
    Tarama tamamlandığında AI Brain'e öğrenme sinyali gönder.

    Orchestrator'ın complete_scan_in_db() fonksiyonundan çağrılır.

    ⚠️ NOT: ai-service'te `/brain/learn` route'u HENÜZ YOK — çağrı 404 döner ve aşağıdaki
    except tarafından yutulur (tarama akışı bozulmaz). Bu yüzden çağıran taraf varsayılan
    olarak KAPALIDIR (BRAIN_LEARN_ENABLED). Ürünün GERÇEK öğrenmesi bu yolda değil, auto-scan
    hattındaki exploit_memory/identity_memory'dedir (doğrulanmış ders → scan_memories → prompt).
    """
    try:
        # Kullanılan teknikleri belirle
        techniques_used = list(scan_data.get("results", {}).keys())
        
        # Findings'leri topla
        findings = []
        
        # Nuclei findings
        nuclei_result = scan_data.get("results", {}).get("nuclei", {})
        nuclei_findings = nuclei_result.get("findings_summary", [])
        for f in nuclei_findings[:20]:  # Max 20
            findings.append({
                "id": f.get("template-id", "unknown"),
                "name": f.get("info", {}).get("name", "Unknown"),
                "type": "vulnerability",
                "severity": f.get("info", {}).get("severity", "info"),
                "technique": "nuclei"
            })
        
        # Target profile oluştur (basit)
        target_profile = {
            "domain": target,
            "scan_types": techniques_used
        }
        
        # Nmap'ten teknoloji tahmin et
        nmap_result = scan_data.get("results", {}).get("nmap", {})
        if isinstance(nmap_result, dict):
            raw = str(nmap_result)
            if "apache" in raw.lower():
                target_profile["webserver"] = "apache"
            elif "nginx" in raw.lower():
                target_profile["webserver"] = "nginx"
            if "wordpress" in raw.lower():
                target_profile["cms"] = "wordpress"
        
        # Success level belirle
        critical_count = nuclei_result.get("severity_counts", {}).get("critical", 0)
        high_count = nuclei_result.get("severity_counts", {}).get("high", 0)
        
        if critical_count > 0 or high_count > 0:
            success_level = "full"
        elif len(findings) > 0:
            success_level = "partial"
        else:
            success_level = "none"
        
        # Brain'e gönder
        learn_request = {
            "scan_id": scan_id,
            "target": target,
            "target_profile": target_profile,
            "techniques_used": techniques_used,
            "findings": findings,
            "success_level": success_level,
            "duration_seconds": int(nuclei_result.get("duration_seconds", 0))
        }
        
        await brain_request("POST", "/learn", learn_request)
        print(f"🧠 Brain learned from scan: {scan_id}")
        
    except Exception as e:
        # Öğrenme başarısız olsa da tarama akışını bozma
        print(f"⚠️ Brain learning failed (non-critical): {e}")


async def trigger_attack_chain_suggestion(scan_id: str, target: str, findings: list):
    """
    Critical bulgu tespit edildiğinde attack chain önerisi iste.
    
    Severity critical veya high olan 3+ bulgu varsa tetiklenir.
    """
    try:
        # Sadece yüksek severity bulgular
        critical_findings = [
            f for f in findings 
            if f.get("info", {}).get("severity") in ["critical", "high"]
        ]
        
        if len(critical_findings) < 3:
            return None
        
        # Findings'leri chain builder formatına dönüştür
        chain_findings = []
        for f in critical_findings[:10]:  # Max 10
            chain_findings.append({
                "id": f.get("template-id", "unknown"),
                "name": f.get("info", {}).get("name", "Unknown"),
                "type": "vulnerability",
                "severity": f.get("info", {}).get("severity", "high"),
                "host": target,
                "cvss": 8.0 if f.get("info", {}).get("severity") == "critical" else 6.5
            })
        
        # Chain oluştur
        result = await brain_request("POST", "/chain/build", {
            "findings": chain_findings,
            "target_goal": "admin"
        }, timeout=120.0)
        
        print(f"🔗 Attack chain suggested for {scan_id}: {result.get('paths_found', 0)} paths")
        return result
        
    except Exception as e:
        print(f"⚠️ Attack chain suggestion failed: {e}")
        return None
