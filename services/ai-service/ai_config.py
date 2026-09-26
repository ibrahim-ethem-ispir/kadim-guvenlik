"""
AI Config - Merkezi Model ve Ayar Yönetimi
Türkçe: Tüm AI model listelerini ve mapping'lerini tek noktadan yönetir.

Kullanım:
    from ai_config import (
        VALID_GEMINI_MODELS, GEMINI_MODEL_MAPPING, DEFAULT_GEMINI_MODEL,
        VALID_CLAUDE_MODELS, CLAUDE_MODEL_MAPPING, DEFAULT_CLAUDE_MODEL,
        get_valid_model, get_all_models
    )
"""

import os
import httpx
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

# ==============================================================================
# GEMINI MODELS - Google AI
# ==============================================================================

# Geçerli Gemini modelleri (2026 Güncel - Google API'den doğrulanmış liste)
VALID_GEMINI_MODELS: List[str] = [
    # Gemini 3 Series (EN YENİ!)
    "gemini-3-pro-preview",            # 🚀 En güçlü
    "gemini-3-flash-preview",          # ⚡ En hızlı
    # Gemini 2.5 Series
    "gemini-2.5-pro",                  # Reasoning
    "gemini-2.5-flash",                # Hızlı
    "gemini-2.5-flash-lite",           # Hafif
    # Gemini 2.0 Series (GA - Stabil)
    "gemini-2.0-flash",                # Varsayılan
    "gemini-2.0-flash-lite",           # Ucuz
    "gemini-2.0-flash-exp",            # Experimental
    # Legacy
    "gemini-1.5-pro",
    "gemini-1.5-flash",
    "gemini-pro",
]

# Eski/hatalı model adlarını doğru olanlara yönlendir
GEMINI_MODEL_MAPPING: Dict[str, str] = {
    # Eski preview adları
    "gemini-2.5-pro-preview-05-06": "gemini-2.5-pro",
    "gemini-2.5-flash-preview-04-17": "gemini-2.5-flash",
    # Deprecated
    "gemini-2.0-flash-thinking-exp": "gemini-2.0-flash",
}

# Varsayılan model
DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"

# Frontend için gösterilecek tüm modeller (artık kullanılmayan dahil, mapping var)
GEMINI_DISPLAY_MODELS: List[str] = VALID_GEMINI_MODELS.copy()


# ==============================================================================
# CLAUDE MODELS - Anthropic
# ==============================================================================

# Geçerli Claude modelleri (2026 Güncel)
VALID_CLAUDE_MODELS: List[str] = [
    "claude-sonnet-4-20250514",      # En yeni Sonnet 4
    "claude-opus-4-20250514",         # En güçlü model
    "claude-3-7-sonnet-20250219",     # Claude 3.7 Sonnet (hybrid)
    "claude-3-5-sonnet-latest",       # 3.5 Sonnet alias (güncel)
    "claude-3-5-haiku-latest",        # 3.5 Haiku alias (hızlı)
]

# Eski model adlarını yönlendir
CLAUDE_MODEL_MAPPING: Dict[str, str] = {
    "claude-3-5-sonnet-20241022": "claude-3-5-sonnet-latest",
    "claude-3-5-haiku-20241022": "claude-3-5-haiku-latest",
    "claude-3-sonnet": "claude-3-5-sonnet-latest",
    "claude-3-opus": "claude-opus-4-20250514",
    "claude-3-haiku": "claude-3-5-haiku-latest",
}

# Varsayılan model
DEFAULT_CLAUDE_MODEL = "claude-3-5-sonnet-latest"


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def validate_gemini_model(model: str) -> Tuple[str, bool]:
    """
    Gemini model adını validate et ve gerekirse düzelt.
    
    Returns:
        Tuple[str, bool]: (düzeltilmiş_model, değişti_mi)
    """
    if model in VALID_GEMINI_MODELS:
        return model, False
    
    if model in GEMINI_MODEL_MAPPING:
        return GEMINI_MODEL_MAPPING[model], True
    
    return DEFAULT_GEMINI_MODEL, True


def validate_claude_model(model: str) -> Tuple[str, bool]:
    """
    Claude model adını validate et ve gerekirse düzelt.
    
    Returns:
        Tuple[str, bool]: (düzeltilmiş_model, değişti_mi)
    """
    if model in VALID_CLAUDE_MODELS:
        return model, False
    
    if model in CLAUDE_MODEL_MAPPING:
        return CLAUDE_MODEL_MAPPING[model], True
    
    return DEFAULT_CLAUDE_MODEL, True


# DeepSeek (OpenAI-uyumlu bulut) modelleri — .env DEEPSEEK_MODEL ile seçilir.
VALID_DEEPSEEK_MODELS: List[str] = [
    "deepseek-v4-flash",   # ucuz/hızlı (önerilen danışman/analiz görevleri için)
    "deepseek-v4-pro",     # daha güçlü, pahalı
    "deepseek-chat",       # legacy alias
    "deepseek-reasoner",   # reasoning
]


def get_all_models() -> Dict[str, List[str]]:
    """
    Tüm provider'lar için model listelerini döndür.
    Frontend API'si için kullanılır.
    """
    return {
        "ollama": [],  # Dinamik olarak çekilecek
        "deepseek": VALID_DEEPSEEK_MODELS,
        "claude": VALID_CLAUDE_MODELS,
        "gemini": VALID_GEMINI_MODELS,
    }


# Frontend için model açıklamaları
GEMINI_MODEL_DESCRIPTIONS: Dict[str, str] = {
    "gemini-2.5-pro-preview-05-06": "👑 2.5 Pro (En Güçlü Reasoning)",
    "gemini-2.5-flash-preview-04-17": "⚡ 2.5 Flash (Hızlı & Güçlü)",
    "gemini-2.0-flash": "✅ 2.0 Flash (Stabil Varsayılan)",
    "gemini-2.0-flash-lite": "💨 2.0 Flash Lite (Ucuz)",
    "gemini-1.5-pro": "💎 1.5 Pro (2M context)",
    "gemini-1.5-pro-latest": "💎 1.5 Pro Latest",
    "gemini-1.5-flash": "⚡ 1.5 Flash",
    "gemini-1.5-flash-latest": "⚡ 1.5 Flash Latest",
    "gemini-pro": "📦 Gemini Pro (Legacy)",
}

CLAUDE_MODEL_DESCRIPTIONS: Dict[str, str] = {
    "claude-sonnet-4-20250514": "⭐ Sonnet 4 (En Yeni)",
    "claude-opus-4-20250514": "💎 Opus 4 (En Güçlü)",
    "claude-3-7-sonnet-20250219": "🧠 3.7 Sonnet (Hybrid)",
    "claude-3-5-sonnet-latest": "✅ 3.5 Sonnet (Stabil)",
    "claude-3-5-haiku-latest": "⚡ 3.5 Haiku (Hızlı)",
}




# curl -s "https://generativelanguage.googleapis.com/v1beta/models?key=" | grep -o '"name": "[^"]*"' | head -20


# ==============================================================================
# OLLAMA MODELS - Local
# ==============================================================================

# Bilinen Ollama modelleri (healthcheck'te kullanılır)
KNOWN_OLLAMA_MODELS: List[str] = [
    "mistral",
    "qwen2.5-coder",
    "codestral",
    "llama3.2",
    "deepseek-coder-v2",
    "dolphin-mixtral",
]

DEFAULT_OLLAMA_MODEL = "mistral"


# ==============================================================================
# HEALTHCHECK - Model Erişilebilirlik Kontrolü
# ==============================================================================

@dataclass
class ModelHealthStatus:
    """Model sağlık durumu"""
    available: bool
    model: str
    provider: str
    error: Optional[str] = None
    latency_ms: Optional[float] = None


async def check_ollama_health(model: Optional[str] = None) -> ModelHealthStatus:
    """
    Ollama servisinin çalışıp çalışmadığını ve modelin mevcut olduğunu kontrol et.

    Args:
        model: Kontrol edilecek model adı (None ise sadece servis kontrolü)

    Returns:
        ModelHealthStatus: Erişilebilirlik durumu
    """
    import time
    start = time.time()
    ollama_url = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Önce servis kontrolü
            response = await client.get(f"{ollama_url}/api/tags")

            if response.status_code != 200:
                return ModelHealthStatus(
                    available=False,
                    model=model or "ollama",
                    provider="ollama",
                    error=f"Ollama servisi yanıt vermiyor (HTTP {response.status_code})"
                )

            data = response.json()
            available_models = [m.get("name", "").split(":")[0] for m in data.get("models", [])]

            latency = (time.time() - start) * 1000

            # Model belirtilmişse, mevcut mu kontrol et
            if model:
                model_base = model.split(":")[0]
                if model_base not in available_models and model not in [m.get("name", "") for m in data.get("models", [])]:
                    return ModelHealthStatus(
                        available=False,
                        model=model,
                        provider="ollama",
                        error=f"Model '{model}' Ollama'da yüklü değil. Mevcut modeller: {', '.join(available_models[:5])}",
                        latency_ms=latency
                    )

            return ModelHealthStatus(
                available=True,
                model=model or "ollama",
                provider="ollama",
                latency_ms=latency
            )

    except httpx.ConnectError:
        return ModelHealthStatus(
            available=False,
            model=model or "ollama",
            provider="ollama",
            error="Ollama servisi çalışmıyor. 'ollama serve' komutunu çalıştırın."
        )
    except Exception as e:
        return ModelHealthStatus(
            available=False,
            model=model or "ollama",
            provider="ollama",
            error=f"Ollama bağlantı hatası: {str(e)}"
        )


async def check_claude_health(model: Optional[str] = None) -> ModelHealthStatus:
    """
    Claude API key'in geçerli olup olmadığını kontrol et.
    """
    import time
    start = time.time()
    api_key = os.getenv("CLAUDE_API_KEY", "")

    if not api_key:
        return ModelHealthStatus(
            available=False,
            model=model or "claude",
            provider="claude",
            error="CLAUDE_API_KEY tanımlı değil"
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Basit bir test isteği
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": model or "claude-3-5-haiku-latest",
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "test"}]
                }
            )

            latency = (time.time() - start) * 1000

            if response.status_code == 200:
                return ModelHealthStatus(
                    available=True,
                    model=model or "claude",
                    provider="claude",
                    latency_ms=latency
                )
            elif response.status_code == 401:
                return ModelHealthStatus(
                    available=False,
                    model=model or "claude",
                    provider="claude",
                    error="Claude API key geçersiz"
                )
            elif response.status_code == 429:
                return ModelHealthStatus(
                    available=False,
                    model=model or "claude",
                    provider="claude",
                    error="Claude rate limit aşıldı veya kredi yok"
                )
            else:
                return ModelHealthStatus(
                    available=False,
                    model=model or "claude",
                    provider="claude",
                    error=f"Claude API hatası: HTTP {response.status_code}"
                )

    except Exception as e:
        return ModelHealthStatus(
            available=False,
            model=model or "claude",
            provider="claude",
            error=f"Claude bağlantı hatası: {str(e)}"
        )


async def check_gemini_health(model: Optional[str] = None) -> ModelHealthStatus:
    """
    Gemini API key'in geçerli olup olmadığını kontrol et.
    """
    import time
    start = time.time()
    api_key = os.getenv("GEMINI_API_KEY", "")

    if not api_key:
        return ModelHealthStatus(
            available=False,
            model=model or "gemini",
            provider="gemini",
            error="GEMINI_API_KEY tanımlı değil"
        )

    model_to_test = model or "gemini-2.0-flash"
    validated, _ = validate_gemini_model(model_to_test)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{validated}:generateContent?key={api_key}",
                json={
                    "contents": [{"parts": [{"text": "test"}]}],
                    "generationConfig": {"maxOutputTokens": 1}
                }
            )

            latency = (time.time() - start) * 1000

            if response.status_code == 200:
                return ModelHealthStatus(
                    available=True,
                    model=model or "gemini",
                    provider="gemini",
                    latency_ms=latency
                )
            elif response.status_code == 400:
                error_data = response.json()
                error_msg = error_data.get("error", {}).get("message", "Bilinmeyen hata")
                return ModelHealthStatus(
                    available=False,
                    model=model or "gemini",
                    provider="gemini",
                    error=f"Gemini model hatası: {error_msg}"
                )
            elif response.status_code == 429:
                return ModelHealthStatus(
                    available=False,
                    model=model or "gemini",
                    provider="gemini",
                    error="Gemini quota aşıldı veya rate limit"
                )
            else:
                return ModelHealthStatus(
                    available=False,
                    model=model or "gemini",
                    provider="gemini",
                    error=f"Gemini API hatası: HTTP {response.status_code}"
                )

    except Exception as e:
        return ModelHealthStatus(
            available=False,
            model=model or "gemini",
            provider="gemini",
            error=f"Gemini bağlantı hatası: {str(e)}"
        )


async def check_deepseek_health(model: Optional[str] = None) -> ModelHealthStatus:
    """
    DeepSeek (OpenAI-uyumlu bulut) API anahtarının geçerli olup olmadığını kontrol et.
    """
    import time
    start = time.time()
    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")

    if not api_key:
        return ModelHealthStatus(available=False, model=model or "deepseek",
                                 provider="deepseek", error="DEEPSEEK_API_KEY tanımlı değil")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{base_url}/models",
                                    headers={"Authorization": f"Bearer {api_key}"})
        latency = (time.time() - start) * 1000
        if resp.status_code == 200:
            return ModelHealthStatus(available=True, model=model or "deepseek",
                                     provider="deepseek", latency_ms=latency)
        if resp.status_code in (401, 403):
            return ModelHealthStatus(available=False, model=model or "deepseek",
                                     provider="deepseek", error="DeepSeek API key geçersiz")
        return ModelHealthStatus(available=False, model=model or "deepseek", provider="deepseek",
                                 error=f"DeepSeek API hatası: HTTP {resp.status_code}", latency_ms=latency)
    except Exception as e:
        return ModelHealthStatus(available=False, model=model or "deepseek",
                                 provider="deepseek", error=f"DeepSeek bağlantı hatası: {str(e)}")


async def check_model_health(model: str) -> ModelHealthStatus:
    """
    Herhangi bir modelin erişilebilirliğini kontrol et.
    Model adından provider'ı otomatik tespit eder.
    """
    model_lower = model.lower()

    if "gemini" in model_lower:
        return await check_gemini_health(model)
    elif "claude" in model_lower:
        return await check_claude_health(model)
    elif "deepseek" in model_lower:
        return await check_deepseek_health(model)
    else:
        # Varsayılan olarak Ollama (local model)
        return await check_ollama_health(model)


async def get_ollama_models() -> List[str]:
    """
    Ollama'da yüklü modellerin listesini döndür.
    """
    ollama_url = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{ollama_url}/api/tags")

            if response.status_code == 200:
                data = response.json()
                return [m.get("name", "") for m in data.get("models", [])]
    except:
        pass

    return []