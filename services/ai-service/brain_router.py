"""
AI Security Brain - Main Service
Türkçe: Tüm AI bileşenlerini birleştiren ana servis

v2 Güncellemesi:
- Phantom/Adaptive modülleri kaldırıldı
- Multi-AI Orchestra korundu
- Model healthcheck korundu
- Smart Analysis korundu
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional, Literal
from datetime import datetime
import json
import asyncio
import os
import re
import logging

import httpx

logger = logging.getLogger("brain-router")

# Brain modules
from ai_orchestra import (
    AIOrchestra, get_orchestra, get_strategy_router, get_exploit_router, get_analysis_router,
    SecurityTask, AICapability, TaskPriority, AIResponse
)

# Scan Analyzer (v2 pipeline analizi)
from scan_analyzer import analyze_scan_results

# Model healthcheck
from ai_config import (
    check_model_health, check_ollama_health, check_gemini_health, check_claude_health,
    get_ollama_models, ModelHealthStatus,
    VALID_GEMINI_MODELS, VALID_CLAUDE_MODELS, get_all_models
)


# ============== Request/Response Models ==============

class BrainStatusResponse(BaseModel):
    """Brain durum yanıtı"""
    status: str
    components: Dict[str, Any]
    capabilities: List[str]
    model_stats: Dict[str, Any]


class SmartAnalysisRequest(BaseModel):
    """Akıllı analiz isteği - otomatik model seçimi"""
    scan_data: Dict[str, Any]
    analysis_type: Literal["security", "vulnerability", "osint", "hash", "comprehensive"] = "comprehensive"
    require_privacy: bool = False
    require_offensive: bool = False
    preferred_model: Optional[str] = None


class SmartAnalysisResponse(BaseModel):
    """Akıllı analiz yanıtı"""
    model_used: str
    provider: str
    analysis: str
    risk_score: Optional[int] = None
    recommendations: List[str] = []
    critical_findings: List[str] = []
    tokens_used: int
    cost_estimate: float
    latency_ms: float


# ============== Model Healthcheck Models ==============

class ModelHealthRequest(BaseModel):
    """Model healthcheck isteği"""
    model: str = Field(..., description="Kontrol edilecek model adı")


class ModelHealthResponse(BaseModel):
    """Model healthcheck yanıtı"""
    available: bool
    model: str
    provider: str
    error: Optional[str] = None
    latency_ms: Optional[float] = None


class ModelInfo(BaseModel):
    """Model bilgisi"""
    id: str
    name: str


class AllModelsResponse(BaseModel):
    """Tüm mevcut modellerin listesi"""
    gemini: List[ModelInfo]
    claude: List[ModelInfo]
    ollama: List[ModelInfo]
    ollama_status: str


router = APIRouter(prefix="/brain", tags=["AI Brain"])


# ============== Brain Status ==============

@router.get("/status", response_model=BrainStatusResponse)
async def get_brain_status():
    """Brain durumunu kontrol et."""
    orchestra = get_orchestra()
    stats = orchestra.get_stats()
    api_status = stats.get("api_status", {})

    has_cloud_api = api_status.get("gemini_configured") or api_status.get("claude_configured")
    overall_status = "operational" if has_cloud_api else "limited"

    return BrainStatusResponse(
        status=overall_status,
        components={
            "orchestra": "active",
            "smart_analysis": "active",
            "model_healthcheck": "active",
        },
        capabilities=[
            "multi_model_routing",
            "smart_analysis",
            "model_healthcheck",
        ],
        model_stats=stats,
    )


# ============== Model Healthcheck Endpoints ==============

@router.post("/healthcheck/model", response_model=ModelHealthResponse)
async def check_model(request: ModelHealthRequest):
    """Model Healthcheck - Seçilen modelin erişilebilirliğini kontrol et."""
    status = await check_model_health(request.model)
    return ModelHealthResponse(
        available=status.available,
        model=status.model,
        provider=status.provider,
        error=status.error,
        latency_ms=status.latency_ms
    )


@router.get("/healthcheck/ollama")
async def check_ollama():
    """Ollama Healthcheck"""
    status = await check_ollama_health()
    models = await get_ollama_models() if status.available else []
    return {
        "available": status.available,
        "error": status.error,
        "latency_ms": status.latency_ms,
        "models": models
    }


@router.get("/healthcheck/claude")
async def check_claude():
    """Claude Healthcheck"""
    status = await check_claude_health()
    return {
        "available": status.available,
        "error": status.error,
        "latency_ms": status.latency_ms,
        "models": VALID_CLAUDE_MODELS if status.available else []
    }


@router.get("/healthcheck/gemini")
async def check_gemini():
    """Gemini Healthcheck"""
    status = await check_gemini_health()
    return {
        "available": status.available,
        "error": status.error,
        "latency_ms": status.latency_ms,
        "models": VALID_GEMINI_MODELS if status.available else []
    }


@router.get("/models/available", response_model=AllModelsResponse)
async def get_available_models():
    """Tüm mevcut AI modellerinin listesini döndür."""
    ollama_models = await get_ollama_models()
    ollama_status = "online" if ollama_models else "offline"

    gemini_display = {
        "gemini-3-pro-preview": "Gemini 3 Pro",
        "gemini-3-flash-preview": "Gemini 3 Flash",
        "gemini-2.5-pro": "Gemini 2.5 Pro",
        "gemini-2.5-flash": "Gemini 2.5 Flash",
        "gemini-2.5-flash-lite": "Gemini 2.5 Flash Lite",
        "gemini-2.0-flash": "Gemini 2.0 Flash",
        "gemini-2.0-flash-lite": "Gemini 2.0 Flash Lite",
        "gemini-2.0-flash-exp": "Gemini 2.0 Flash Exp",
        "gemini-1.5-pro": "Gemini 1.5 Pro",
        "gemini-1.5-flash": "Gemini 1.5 Flash",
        "gemini-pro": "Gemini Pro (Legacy)",
    }

    claude_display = {
        "claude-sonnet-4-20250514": "Claude Sonnet 4",
        "claude-opus-4-20250514": "Claude Opus 4",
        "claude-3-7-sonnet-20250219": "Claude 3.7 Sonnet",
        "claude-3-5-sonnet-latest": "Claude 3.5 Sonnet",
        "claude-3-5-haiku-latest": "Claude 3.5 Haiku",
    }

    return AllModelsResponse(
        gemini=[
            ModelInfo(id=m, name=gemini_display.get(m, m))
            for m in VALID_GEMINI_MODELS
        ],
        claude=[
            ModelInfo(id=m, name=claude_display.get(m, m))
            for m in VALID_CLAUDE_MODELS
        ],
        ollama=[
            ModelInfo(id=m, name=m.split(":")[0].title())
            for m in ollama_models
        ],
        ollama_status=ollama_status
    )


# ============== Analysis Endpoint ==============

@router.post("/analyze", response_model=SmartAnalysisResponse)
async def smart_analyze(request: SmartAnalysisRequest):
    """Akıllı Analiz - Otomatik optimal model seçimi ile analiz."""
    orchestra = get_orchestra()

    capabilities = [AICapability.STRATEGY]
    if request.analysis_type == "vulnerability":
        capabilities.append(AICapability.REASONING)
    elif request.analysis_type == "comprehensive":
        capabilities.extend([AICapability.REASONING, AICapability.LARGE_CONTEXT])

    context_estimate = len(json.dumps(request.scan_data)) // 4

    task = SecurityTask(
        task_id=f"analyze_{datetime.now().timestamp()}",
        task_type=f"{request.analysis_type}_analysis",
        content=request.scan_data,
        requires_privacy=request.require_privacy,
        is_offensive=request.require_offensive,
        context_tokens=context_estimate,
        capabilities_needed=capabilities,
        priority=TaskPriority.HIGH,
        preferred_model=request.preferred_model
    )

    response = await orchestra.route_task(task)
    parsed = _parse_analysis_response(response.content)

    return SmartAnalysisResponse(
        model_used=response.model,
        provider=response.provider,
        analysis=response.content,
        risk_score=parsed.get("risk_score"),
        recommendations=parsed.get("recommendations", []),
        critical_findings=parsed.get("critical_findings", []),
        tokens_used=response.tokens_used,
        cost_estimate=response.cost_estimate,
        latency_ms=response.latency_ms
    )


# ============== v2 Pipeline Analysis Endpoint ==============

class V2AnalysisRequest(BaseModel):
    """v2 Pipeline analiz isteği (orchestrator'dan gelir)"""
    scan_id: str
    target: str
    scan_data: Dict[str, Any]
    preferred_model: Optional[str] = None


@router.post("/analyze/v2")
async def analyze_v2_scan(request: V2AnalysisRequest):
    """
    v2 Pipeline Analizi - Orchestrator pipeline tamamlandığında çağırır.
    APT perspektifinde kapsamlı analiz üretir.
    """
    result = await analyze_scan_results(
        scan_id=request.scan_id,
        target=request.target,
        scan_data=request.scan_data,
        preferred_model=request.preferred_model,
    )
    return result


# ============== False-Positive Hakem (P3) ==============
# NEDEN: deterministik doğrulayıcısı OLMAYAN bulgular (RCE/SSRF/misconfig CVE) için
# "istihbarat subayı"na ikincil görüş sorulur: gerçek mi false-positive mi? Bu ASLA kademe
# belirlemez (deterministik katman kraldır) — yalnız operatör/rapor önceliklendirmesine
# danışma sinyali. LLM erişilemezse endpoint 200 + boş results döner (tarama düşmez).

_ADJUDICATE_SYSTEM_PROMPT = (
    "Sen kıdemli bir penetrasyon test uzmanısın (false-positive triyaj hakemi). Görevin: "
    "otomatik tarayıcının ürettiği DOĞRULANMAMIŞ bulguların gerçek bir zafiyet mi yoksa "
    "false-positive mi olduğunu SADECE verilen kanıta (proof/response) dayanarak değerlendirmek. "
    "Sürüm/banner'dan çıkarılmış CVE'ler, WAF/giriş/hata sayfasına eşleşen bulgular ve genel "
    "tespitler çoğunlukla false-positive'dir. Emin değilsen 'uncertain' de. ABARTMA. "
    "ÇIKTIYI YALNIZCA şu JSON şemasında ver, başka metin yazma: "
    '{"results":[{"index":<int>,"verdict":"real|false_positive|uncertain",'
    '"confidence":<0.0-1.0>,"reason":"<kısa gerekçe>"}]}'
)


def _extract_json_obj(text: str) -> Optional[Dict[str, Any]]:
    """LLM cevabından ilk geçerli JSON nesnesini çıkar (```json bloğu veya ham). Yoksa None."""
    if not text:
        return None
    m = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL) or re.search(r'```\s*(.*?)\s*```', text, re.DOTALL)
    candidate = m.group(1) if m else text
    try:
        return json.loads(candidate)
    except Exception:
        pass
    # Ham metinde ilk { ... } bloğunu dene (prose sarmalı durumları)
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(candidate[start:end + 1])
        except Exception:
            return None
    return None


async def _llm_complete_text(system: str, user: str, *, provider: str, model: str,
                             max_tokens: int = 1024) -> Optional[str]:
    """Aktif sağlayıcıya TEK completion çağrısı — kendi system+user prompt'umuzu kontrol eder,
    ham metni döndürür (chat geçmişini KİRLETMEZ, analiz şablonuna sarmaz). Hata → None.

    Provider routing burada tekrar tanımlanır çünkü main.py'daki process_chat_* fonksiyonları
    chat-history/analiz-şablonuna bağlıdır; hakem saf JSON completion ister."""
    from llm_env_config import (OLLAMA_URL, CLAUDE_API_KEY, GEMINI_API_KEY,
                                DEEPSEEK_BASE_URL, DEEPSEEK_API_KEY)
    try:
        if provider == "deepseek":
            if not DEEPSEEK_API_KEY:
                return None
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    f"{DEEPSEEK_BASE_URL}/chat/completions",
                    headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                             "Content-Type": "application/json"},
                    json={"model": model,
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user}],
                          "stream": False, "temperature": 0.1, "max_tokens": max_tokens,
                          "response_format": {"type": "json_object"},
                          "thinking": {"type": "disabled"}},  # v4: CoT kapalı (bkz. CLAUDE.md)
                )
            if resp.status_code != 200:
                return None
            choices = resp.json().get("choices", []) or []
            msg = choices[0].get("message", {}) if choices else {}
            return (msg.get("content") or "").strip() or (msg.get("reasoning_content") or "").strip()

        if provider == "ollama":
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{OLLAMA_URL}/api/generate",
                    json={"model": model, "system": system, "prompt": user, "stream": False,
                          "format": "json", "options": {"temperature": 0.1, "num_predict": max_tokens}},
                )
            if resp.status_code != 200:
                return None
            return resp.json().get("response", "")

        if provider == "claude":
            if not CLAUDE_API_KEY:
                return None
            from anthropic import Anthropic
            client = Anthropic(api_key=CLAUDE_API_KEY)
            message = client.messages.create(
                model=model, max_tokens=max_tokens, temperature=0.1, system=system,
                messages=[{"role": "user", "content": user}])
            return message.content[0].text if message.content else None

        if provider == "gemini":
            if not GEMINI_API_KEY:
                return None
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            gm = genai.GenerativeModel(
                model_name=model,
                system_instruction=system,
                generation_config=genai.GenerationConfig(temperature=0.1, max_output_tokens=max_tokens))
            r = gm.generate_content(user)
            return r.text if getattr(r, "text", None) else None
    except Exception as e:
        logger.info(f"FP-hakem LLM çağrısı başarısız ({provider}): {e}")
        return None
    return None


class AdjudicateFPRequest(BaseModel):
    """FP-hakem isteği (orchestrator'dan). findings: [{index,title,severity,target,cve,proof,response}]"""
    scan_id: str
    target: str
    findings: List[Dict[str, Any]]
    provider: Optional[str] = None
    model: Optional[str] = None


@router.post("/adjudicate-fp")
async def adjudicate_false_positives(request: AdjudicateFPRequest):
    """FALSE-POSITIVE hakem (P3): doğrulanmamış bulguları LLM ile triyaj et (ikincil görüş).

    Sözleşme: {results:[{index,verdict,confidence,reason}]}. LLM erişilemez/parse edilemezse
    200 + boş results döner (orchestrator best-effort; tarama ASLA düşmez). Doktrin: bu görüş
    deterministik kademeyi DEĞİŞTİRMEZ — orchestrator yalnız anotasyon olarak saklar."""
    from llm_env_config import resolve_ai_service_default
    if not request.findings:
        return {"results": []}
    # Provider/model: istek override'ı yoksa aktif varsayılan (DB > .env).
    default = resolve_ai_service_default()
    provider = (request.provider or default.get("provider") or "ollama").lower()
    model = request.model or default.get("model") or ""
    if not model:
        from llm_env_config import provider_default_model
        model = provider_default_model(provider)

    # Bulguları kompakt, kanıt-odaklı biçimde sun (index KORUNUR — eşleştirme için).
    lines = []
    for f in request.findings[:12]:
        lines.append(json.dumps({
            "index": f.get("index"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "cve": f.get("cve"),
            "target": f.get("target"),
            "proof": (f.get("proof") or "")[:800],
            "response_excerpt": (f.get("response") or "")[:800] if f.get("response") else None,
        }, ensure_ascii=False))
    user_prompt = (
        f"Hedef: {request.target}\n"
        f"Aşağıda otomatik tarayıcının ürettiği DOĞRULANMAMIŞ bulgular var. Her biri için "
        f"gerçek mi false-positive mi karar ver. Yalnız kanıta dayan.\n\nBULGULAR:\n"
        + "\n".join(lines)
        + "\n\nSADECE belirtilen JSON şemasını döndür."
    )
    raw = await _llm_complete_text(_ADJUDICATE_SYSTEM_PROMPT, user_prompt,
                                   provider=provider, model=model, max_tokens=1200)
    if not raw:
        return {"results": [], "note": "llm_unavailable"}
    parsed = _extract_json_obj(raw)
    if not isinstance(parsed, dict):
        return {"results": [], "note": "parse_failed"}
    results = parsed.get("results")
    if not isinstance(results, list):
        return {"results": [], "note": "no_results"}
    # Sözleşmeyi normalize et (bozuk/eksik alanları güvenli değere çek).
    clean = []
    for r in results:
        if not isinstance(r, dict):
            continue
        verdict = str(r.get("verdict") or "uncertain").lower()
        if verdict not in ("real", "false_positive", "uncertain"):
            verdict = "uncertain"
        conf = r.get("confidence")
        try:
            conf = round(float(conf), 2) if conf is not None else None
        except (TypeError, ValueError):
            conf = None
        clean.append({"index": r.get("index"), "verdict": verdict,
                      "confidence": conf, "reason": str(r.get("reason") or "")[:300]})
    return {"results": clean, "provider": provider, "model": model}


# ============== Helper Functions ==============

def _parse_analysis_response(content: str) -> Dict:
    """AI yanıtından yapılandırılmış veri çıkar"""
    import re
    result = {
        "risk_score": None,
        "recommendations": [],
        "critical_findings": []
    }

    lines = content.split('\n')
    current_section = None

    for line in lines:
        line_lower = line.lower()

        if 'risk' in line_lower and ('score' in line_lower or ':' in line):
            numbers = re.findall(r'\d+', line)
            if numbers:
                result["risk_score"] = int(numbers[0])

        if 'recommendation' in line_lower or 'öneri' in line_lower:
            current_section = 'recommendations'
        elif 'critical' in line_lower or 'kritik' in line_lower:
            current_section = 'critical_findings'
        elif line.startswith('-') or line.startswith('*'):
            if current_section:
                result[current_section].append(line.strip('-*• '))

    return result
