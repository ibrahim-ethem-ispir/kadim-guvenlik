"""
AI Proxy Router - Orchestrator
Türkçe: Frontend'den gelen AI analiz isteklerini AI service'e yönlendirir

v2.0 Güncellemeler:
- Chat history persistence (MongoDB)
- Konuşma geçmişi endpoint'leri
- Enhanced response model
"""

from fastapi import APIRouter, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
import httpx
import os
from typing import Literal, Optional, List, Dict, Any
from datetime import datetime

router = APIRouter(prefix="/ai", tags=["AI Analysis"])

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8009")
NUCLEI_SERVICE_URL = os.getenv("NUCLEI_SERVICE_URL", "http://nuclei-service:8003")


def _find_scan(scan_id: str, projection: Optional[dict] = None):
    """Scan'i önce v1 `scans`, bulamazsa v2 `v2_scan_sessions`'ta ara.

    NEDEN: Otonom (Kuşatma Doktrini v2) taramaların TEK kaydı v2_scan_sessions'tır
    (eski `scans` aynası kaldırıldı). Yalnız `scans`'a bakmak otonom scan_id'lerini
    'Tarama bulunamadı' (404) diye reddediyor, AI analiz/rapor/chat'i bu taramalarda
    tümüyle çökertiyordu (bkz. main.py'deki WS ve iptal yollarındaki aynı fallback).

    Döner: (collection, doc) — bulunduğu koleksiyon ve belge. İkisinde de yoksa (None, None).
    DB tümüyle erişilemezse (her iki getter None) HTTPException(500) fırlatır.
    """
    from main import get_scans_collection, get_sessions_collection

    scans_col = get_scans_collection()
    sessions_col = get_sessions_collection()
    if scans_col is None and sessions_col is None:
        raise HTTPException(status_code=500, detail="Database bağlantısı yok")

    for col in (scans_col, sessions_col):
        if col is not None:
            doc = col.find_one({"scan_id": scan_id}, projection)
            if doc is not None:
                return col, doc
    return None, None


def _is_v2(col) -> bool:
    """Belge v2_scan_sessions'tan mı geldi? (koleksiyon adına göre)."""
    return col is not None and getattr(col, "name", None) == "v2_scan_sessions"


def _analysis_key(col) -> str:
    """Manuel panel analizinin yazılacağı alan adı.

    v2 session'ın `ai_analysis` alanı OTONOM motorun zengin yapısıdır (agent_timeline,
    llm_status, recon_map, report_status) — AutonomousTimeline bunu okur. Manuel "AI ile
    Değerlendir" sonucunu oraya `$set` etmek bu yapıyı EZER. Bu yüzden v2'de ayrı anahtar
    (`manual_ai_analysis`) kullanılır; v1 `scans` için eski davranış (`ai_analysis`) korunur.
    """
    return "manual_ai_analysis" if _is_v2(col) else "ai_analysis"


class AIAnalysisRequest(BaseModel):
    scan_id: Optional[str] = None
    scan_data: Optional[dict] = None  # Doğrudan veri gönderilirse
    provider: Literal["ollama", "deepseek", "claude", "gemini"] = "ollama"
    model: str = "mistral:7b"
    analysis_type: str = "security"  # security, hash, osint, vuln
    use_default: bool = False  # True ise Settings'ten default provider/model kullanır


class AIAnalysisResponse(BaseModel):
    provider: str
    model: str
    analysis: str
    risk_score: Optional[int] = None
    recommendations: list = []
    critical_findings: list = []
    technical_details: list = []  # v2.0: Teknik detaylar eklendi
    next_steps: list = []
    conversation_id: Optional[str] = None  # v2.0: Chat history için
    message_count: Optional[int] = None  # v2.0: Mesaj sayısı


class AIChatRequest(BaseModel):
    scan_id: str
    current_analysis: dict
    user_message: str
    provider: Literal["ollama", "deepseek", "claude", "gemini"] = "ollama"
    model: str = "mistral:7b"
    analysis_type: str = "security"
    use_default: bool = False  # True ise Settings'ten default provider/model kullanır


@router.post("/analyze", response_model=AIAnalysisResponse)
async def analyze_scan_with_ai(request: AIAnalysisRequest):
    """
    Türkçe: Tarama sonuçlarını AI ile analiz et
    
    İki mod:
    1. scan_id ile: MongoDB'den veriyi çeker
    2. scan_data ile: Doğrudan gönderilen veriyi kullanır
    """
    
    scan_data = request.scan_data
    # Analizin yazılacağı koleksiyon (scan hangisindeyse) — persistence bunu kullanır.
    persist_col = None

    # scan_id varsa MongoDB'den çek (önce v1 `scans`, sonra v2 `v2_scan_sessions`)
    if request.scan_id and not scan_data:
        persist_col, scan = _find_scan(request.scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Tarama bulunamadı")

        # MongoDB ObjectId serialize edilemez, kaldır
        if "_id" in scan:
            del scan["_id"]
        
        # Türkçe: Eğer Nuclei taraması varsa, ham logları da nuclei-service'den çek
        # Bu loglar AI analizi için kritik detaylar içerir (-v ile artırıldı)
        if "results" in scan and "nuclei" in scan["results"]:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    log_res = await client.get(f"{NUCLEI_SERVICE_URL}/logs/{request.scan_id}")
                    if log_res.status_code == 200:
                        log_data = log_res.json()
                        # Ham log içeriğini scan_data'ya ekle
                        scan["results"]["nuclei"]["full_raw_logs"] = log_data.get("raw_log_content", "")
                        print(f"✅ AI Analizi için ham Nuclei logları eklendi: {request.scan_id}")
            except Exception as e:
                print(f"⚠️ AI Analizi için Nuclei logları çekilemedi: {e}")

        scan_data = scan
    
    if not scan_data:
        raise HTTPException(
            status_code=400, 
            detail="scan_id veya scan_data gerekli"
        )
    
    # AI service'e gönder
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            response = await client.post(
                f"{AI_SERVICE_URL}/analyze",
                json=jsonable_encoder({
                    "scan_data": scan_data,
                    "provider": request.provider,
                    "model": request.model,
                    "analysis_type": request.analysis_type,
                    # use_default'ı ilet: True ise ai-service provider/model'i .env
                    # (AI_SERVICE_LLM_*) varsayılanından çözer. Eskiden iletilmiyordu →
                    # .env varsayılanı bu ana yolda sessizce yok sayılıyordu.
                    "use_default": request.use_default
                })
            )
            
            if response.status_code != 200:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("detail", error_detail)
                except:
                    pass
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"AI service error: {error_detail}"
                )
            
            result = response.json()
            
            # Persistence: Analiz sonucunu MongoDB'ye kaydet
            if request.scan_id:
                try:
                    # scan_data doğrudan geldiyse persist_col henüz çözülmedi → şimdi bul.
                    if persist_col is None:
                        persist_col, _ = _find_scan(request.scan_id, {"_id": 1})
                    if persist_col is not None:
                        key = _analysis_key(persist_col)  # v2'de manual_ai_analysis, v1'de ai_analysis
                        persist_col.update_one(
                            {"scan_id": request.scan_id},
                            {
                                "$set": {
                                    key: result,
                                    f"{key}_updated_at": datetime.utcnow()
                                }
                            }
                        )
                except Exception as e:
                    print(f"MongoDB persistence warning (Analyze): {e}")

            return result
            
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504, 
                detail="AI analizi zaman aşımına uğradı (5 dk). Daha küçük veri veya daha hızlı model deneyin."
            )
        except httpx.ConnectError:
            raise HTTPException(
                status_code=503, 
                detail="AI service'e bağlanılamadı. Servis çalışıyor mu?"
            )


class AIReportRequest(BaseModel):
    """Türkçe: AI Security Report isteği - Nessus'tan 10x daha güçlü"""
    scan_id: str
    scan_data: Optional[dict] = None
    sector: str = "technology"


@router.post("/report")
async def generate_ai_report(request: AIReportRequest):
    """
    Türkçe: Devrimci AI güvenlik raporu oluştur
    
    Bu endpoint NESSUS'UN 10 KATI değer sağlar:
    1. Attack Chain Analysis - Saldırı zincirleri
    2. Business Impact Calculator - Finansal risk hesabı
    3. Automated Remediation - Hazır düzeltme komutları
    4. Compliance Mapping - KVKK, PCI-DSS, ISO27001
    """
    
    scan_data = request.scan_data
    persist_col = None  # raporun yazılacağı koleksiyon (scan hangisindeyse)

    # scan_id varsa MongoDB'den çek (önce v1 `scans`, sonra v2 `v2_scan_sessions`)
    if request.scan_id and not scan_data:
        persist_col, scan = _find_scan(request.scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Tarama bulunamadı")

        if "_id" in scan:
            del scan["_id"]

        scan_data = scan

    if not scan_data:
        raise HTTPException(
            status_code=400,
            detail="scan_id veya scan_data gerekli"
        )

    # AI Report Service'e gönder
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            response = await client.post(
                f"{AI_SERVICE_URL}/report",
                json=jsonable_encoder({
                    "scan_id": request.scan_id,
                    "scan_data": scan_data,
                    "sector": request.sector
                })
            )
            
            if response.status_code != 200:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("detail", error_detail)
                except:
                    pass
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"AI Report Engine error: {error_detail}"
                )
            
            result = response.json()
            
            # Persistence: Raporu MongoDB'ye kaydet (doğru koleksiyona — v1 scans veya v2 session).
            # ai_security_report ayrı bir anahtar; v2'nin yapısal ai_analysis'ini etkilemez.
            try:
                if persist_col is None:
                    persist_col, _ = _find_scan(request.scan_id, {"_id": 1})
                if persist_col is not None:
                    persist_col.update_one(
                        {"scan_id": request.scan_id},
                        {
                            "$set": {
                                "ai_security_report": result,
                                "ai_report_generated_at": datetime.utcnow()
                            }
                        }
                    )
                    print(f"✅ AI Security Report kaydedildi: {request.scan_id}")
            except Exception as e:
                print(f"MongoDB persistence warning (Report): {e}")
            
            return result
            
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504, 
                detail="AI Report oluşturma zaman aşımına uğradı."
            )
        except httpx.ConnectError:
            raise HTTPException(
                status_code=503, 
                detail="AI service'e bağlanılamadı. Servis çalışıyor mu?"
            )


@router.post("/chat", response_model=AIAnalysisResponse)
async def chat_with_ai_proxy(request: AIChatRequest):
    """
    Türkçe: AI ile sohbet et ve raporu güncelle (Persistence ile)
    
    v2.0 Güncellemeler:
    - Chat history MongoDB'ye kaydedilir
    - Konuşma geçmişi korunur
    """
    
    # 1. Scan verisini MongoDB'den al (önce v1 `scans`, sonra v2 `v2_scan_sessions`)
    scans_col, scan = _find_scan(request.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı")

    if "_id" in scan:
        del scan["_id"]

    # 2. Mevcut konuşma geçmişini al (varsa)
    existing_history = scan.get("chat_history", {}).get("messages", [])
    
    # 3. AI Service'e Chat isteği gönder
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            response = await client.post(
                f"{AI_SERVICE_URL}/chat",
                json=jsonable_encoder({
                    "scan_data": scan,
                    "current_analysis": request.current_analysis,
                    "user_message": request.user_message,
                    "provider": request.provider,
                    "model": request.model,
                    "analysis_type": request.analysis_type,
                    "conversation_history": existing_history,  # v2.0: Geçmiş gönder
                    # use_default'ı ilet (analyze ile aynı gerekçe: .env varsayılanı bu yolda çalışsın).
                    "use_default": request.use_default
                })
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"AI service chat error: {response.text}"
                )
            
            result = response.json()
            
            # 4. Persistence: Yeni rapor ve chat history'yi MongoDB'ye kaydet
            try:
                # Yeni mesajları geçmişe ekle
                new_messages = existing_history + [
                    {"role": "user", "content": request.user_message, "timestamp": datetime.utcnow().isoformat()},
                    {"role": "assistant", "content": result.get("analysis", ""), "timestamp": datetime.utcnow().isoformat()}
                ]
                
                # v2 session'da ai_analysis yapısaldır (agent_timeline vb.) → manual_ai_analysis
                # anahtarına yaz, ezme. chat_history ayrı top-level alan; her iki koleksiyonda güvenli.
                key = _analysis_key(scans_col)
                scans_col.update_one(
                    {"scan_id": request.scan_id},
                    {
                        "$set": {
                            key: result,
                            f"{key}_updated_at": datetime.utcnow(),
                            "chat_history": {
                                "messages": new_messages[-40:],  # Son 40 mesajı tut (sliding window)
                                "message_count": len(new_messages),
                                "last_updated": datetime.utcnow()
                            }
                        }
                    }
                )
                print(f"✅ Chat history kaydedildi: {request.scan_id} ({len(new_messages)} mesaj)")
            except Exception as e:
                print(f"MongoDB persistence warning (Chat): {e}")
            
            return result
            
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="AI chat timeout - yanıt çok uzun sürdü.")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="AI service'e bağlanılamadı.")


@router.get("/models")
async def get_available_models():
    """Türkçe: Kullanılabilir AI modellerini listele (Ollama, Claude, Gemini)"""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"{AI_SERVICE_URL}/models")
            if response.status_code == 200:
                return response.json()
            return {"ollama": [], "claude": [], "gemini": []}
        except:
            return {"ollama": [], "claude": [], "gemini": [], "error": "AI service'e bağlanılamadı"}


# ============== Chat History Endpoints ==============

@router.get("/conversation/{scan_id}")
async def get_chat_history(scan_id: str):
    """
    Türkçe: Belirli bir tarama için konuşma geçmişini getir
    
    Frontend sayfa yenilendiğinde konuşma geçmişini
    geri yüklemek için kullanılır.
    """
    from main import get_scans_collection, get_sessions_collection

    # Panel açılışında çağrılır → DB yoksa 500 yerine nazikçe boş dön (frontend sessiz karşılar).
    # Önce v1 `scans`, sonra v2 `v2_scan_sessions` (otonom taramalar yalnız burada).
    proj = {"chat_history": 1, "ai_analysis": 1, "manual_ai_analysis": 1, "target": 1}
    scan = None
    for col in (get_scans_collection(), get_sessions_collection()):
        if col is not None:
            scan = col.find_one({"scan_id": scan_id}, proj)
            if scan is not None:
                break

    if not scan:
        return {"exists": False, "scan_id": scan_id, "messages": []}

    chat_history = scan.get("chat_history", {})
    # v2'de manuel analiz manual_ai_analysis'te; yoksa (v1) ai_analysis'e düş.
    ai_analysis = scan.get("manual_ai_analysis") or scan.get("ai_analysis") or {}
    
    return {
        "exists": True,
        "scan_id": scan_id,
        "target": scan.get("target"),
        "messages": chat_history.get("messages", []),
        "message_count": chat_history.get("message_count", 0),
        "current_risk_score": ai_analysis.get("risk_score"),
        "last_analysis": ai_analysis.get("analysis", "")[:500],  # Özet
        "last_updated": chat_history.get("last_updated")
    }


@router.delete("/conversation/{scan_id}")
async def clear_chat_history(scan_id: str):
    """
    Türkçe: Konuşma geçmişini temizle (yeni analiz için)
    
    Kullanıcı "Yeniden Analiz" butonuna bastığında çağrılır.
    """
    # Scan'in bulunduğu koleksiyonu çöz (v1 scans / v2 session). DB yoksa _find_scan 500 verir.
    scans_col, scan = _find_scan(scan_id, {"_id": 1})
    if scan is None:
        # Kayıt yoksa temizlenecek bir şey de yok — idempotent başarı.
        return {"success": True, "scan_id": scan_id, "message": "Temizlenecek konuşma bulunamadı"}

    try:
        # v2'de OTONOM ai_analysis'i (agent_timeline vb.) EZMEDEN yalnız manuel analizi temizle.
        key = _analysis_key(scans_col)
        result = scans_col.update_one(
            {"scan_id": scan_id},
            {
                "$unset": {"chat_history": "", key: ""},
                "$set": {"ai_analysis_cleared_at": datetime.utcnow()}
            }
        )
        
        # AI Service'deki cache'i de temizle
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                await client.delete(f"{AI_SERVICE_URL}/conversation/{scan_id}")
            except:
                pass  # AI service cache temizleme opsiyonel
        
        return {
            "success": True,
            "scan_id": scan_id,
            "message": "Konuşma geçmişi temizlendi"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Temizleme hatası: {str(e)}")


@router.get("/conversation/{scan_id}/export")
async def export_chat_history(scan_id: str):
    """
    Türkçe: Konuşma geçmişini export et (PDF/rapor için)
    
    Kullanıcı konuşma geçmişini rapor olarak indirmek
    istediğinde kullanılır.
    """
    # Önce v1 `scans`, sonra v2 `v2_scan_sessions` (otonom taramalar yalnız burada).
    scans_col, scan = _find_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadı")

    if "_id" in scan:
        del scan["_id"]

    chat_history = scan.get("chat_history", {})
    # v2'de manuel analiz manual_ai_analysis'te; yoksa (v1) ai_analysis'e düş.
    ai_analysis = scan.get("manual_ai_analysis") or scan.get("ai_analysis") or {}
    
    return {
        "scan_id": scan_id,
        "target": scan.get("target"),
        "created_at": scan.get("created_at"),
        "analysis": {
            "risk_score": ai_analysis.get("risk_score"),
            "critical_findings": ai_analysis.get("critical_findings", []),
            "recommendations": ai_analysis.get("recommendations", []),
            "next_steps": ai_analysis.get("next_steps", []),
            "full_analysis": ai_analysis.get("analysis", "")
        },
        "conversation": {
            "messages": chat_history.get("messages", []),
            "message_count": chat_history.get("message_count", 0)
        },
        "export_date": datetime.utcnow().isoformat()
    }


@router.get("/health")
async def ai_health_check():
    """Türkçe: AI service health check"""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"{AI_SERVICE_URL}/health")
            if response.status_code == 200:
                return response.json()
            return {"status": "unhealthy", "detail": response.text}
        except httpx.ConnectError:
            return {"status": "offline", "detail": "AI service'e bağlanılamadı"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}
