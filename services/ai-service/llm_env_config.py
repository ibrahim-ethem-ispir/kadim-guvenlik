"""
Merkezi LLM Env Yapılandırması — Tek Doğruluk Kaynağı (.env)  [ai-service kopyası]
=================================================================================
Türkçe: Bu dosya `orchestrator/integrations/llm_env_config.py` ile BİREBİR aynı
mantığı taşır. İki container ayrı imaj olduğundan paylaşımlı paket import edilemez;
bu yüzden bilinçli, bağımlılıksız bir kopyadır. Değiştirirken İKİSİNİ de güncelle.

Fark: Claude/Gemini varsayılan model adları, ai-service'in mevcut `ai_config.py`
kaynaklarından (DEFAULT_CLAUDE_MODEL / DEFAULT_GEMINI_MODEL) türetilir — böylece
model listeleriyle uyumlu kalır.
"""

import os
import time
from typing import Any, Dict, List, Optional

try:
    from ai_config import DEFAULT_CLAUDE_MODEL, DEFAULT_GEMINI_MODEL
except Exception:  # pragma: no cover - defensive, ai_config her zaman mevcut
    DEFAULT_CLAUDE_MODEL = "claude-3-5-sonnet-latest"
    DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"

# ============================================================
# Ham env okuma (tek nokta)
# ============================================================

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")

DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")

CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
CLAUDE_DEFAULT_MODEL = os.getenv("CLAUDE_MODEL", DEFAULT_CLAUDE_MODEL)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_DEFAULT_MODEL = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)

# NOT: Aktif varsayılan artık DB'de tutulur (get_autonomous_provider). Bu env yalnızca DB boşken seed/fallback.
AUTONOMOUS_LLM_PROVIDER = os.getenv("AUTONOMOUS_LLM_PROVIDER", "ollama").lower()
AUTONOMOUS_MODEL = os.getenv("AUTONOMOUS_MODEL", "hf.co/empero-ai/Qwythos-9B-v2-GGUF:Q4_K_M")

# İstek açıkça provider/model verirse o override eder; vermezse DB varsayılanı (yoksa bu env).
AI_SERVICE_LLM_PROVIDER = os.getenv("AI_SERVICE_LLM_PROVIDER", "ollama").lower()
AI_SERVICE_LLM_MODEL = os.getenv("AI_SERVICE_LLM_MODEL", "").strip()

# DB'deki varsayılan seçim anahtarları (Settings koleksiyonu). Değer = provider adı (str).
DB_KEY_AUTONOMOUS_PROVIDER = "autonomous_llm_provider"
DB_KEY_AI_SERVICE_PROVIDER = "ai_service_llm_provider"
DB_KEY_AI_SERVICE_MODEL = "ai_service_llm_model"


# ============================================================
# Sağlayıcı meta verisi
# ============================================================

VALID_PROVIDERS = ("ollama", "deepseek", "claude", "gemini")

_DATA_LEAVES_NETWORK = {"ollama": False, "deepseek": True, "claude": True, "gemini": True}
_REQUIRES_KEY = {"ollama": False, "deepseek": True, "claude": True, "gemini": True}


def mask_api_key(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    if len(key) <= 8:
        return "****"
    return key[:4] + "..." + key[-4:]


# ============================================================
# DB varsayılan katmanı (MongoDB `Settings`) — "hangi sağlayıcı varsayılan?"
# ============================================================
# Yalnızca provider ADI (ve opsiyonel ai-service model'i) DB'de tutulur — API anahtarı ASLA.
# Kısa in-process cache ile her istekte Mongo'ya gitme spam'i önlenir (varsayılan değişimi
# hızla yansısın diye TTL kısa). Mongo erişilemezse boş → çağıranlar `.env` fallback'ine düşer.

_DB_CACHE_TTL = 3.0  # saniye
_db_cache: Dict[str, Any] = {"ts": 0.0, "values": {}}


_mongo_client = None  # tek-sefer oluşturulan, yeniden kullanılan MongoClient (pymongo'nun önerdiği desen)


def _get_db():
    """MongoClient BİR KEZ oluşturulur ve yeniden kullanılır — her çağrıda yeni client açmak
    bağlantı havuzu + monitör thread'leri sızdırır (analiz hot-path'inde çağrılır). Tembel
    bağlanır ki Mongo yokken import kırılmasın."""
    global _mongo_client
    if _mongo_client is None:
        from pymongo import MongoClient
        uri = os.getenv("MONGODB_URI", "mongodb://kadim:kadim_secure_2024@mongodb:27017")
        _mongo_client = MongoClient(uri, serverSelectionTimeoutMS=2000)
    dbname = os.getenv("MONGODB_DATABASE", "kadim_security")
    return _mongo_client[dbname]


def _read_db_defaults() -> Dict[str, Any]:
    now = time.monotonic()
    if now - _db_cache["ts"] < _DB_CACHE_TTL:
        return _db_cache["values"]
    values: Dict[str, Any] = {}
    try:
        db = _get_db()
        for key in (DB_KEY_AUTONOMOUS_PROVIDER, DB_KEY_AI_SERVICE_PROVIDER, DB_KEY_AI_SERVICE_MODEL):
            doc = db["Settings"].find_one({"key": key}, {"_id": 0, "value": 1})
            if doc and doc.get("value") is not None:
                values[key] = doc["value"]
    except Exception:
        values = {}
    _db_cache.update({"ts": now, "values": values})
    return values


def _set_db_default(key: str, value: Any) -> None:
    from datetime import datetime
    db = _get_db()
    db["Settings"].update_one(
        {"key": key},
        {"$set": {"key": key, "value": value, "category": "ai",
                  "description": "LLM varsayılan sağlayıcı seçimi (UI'dan yönetilir)",
                  "updated_at": datetime.utcnow()}},
        upsert=True,
    )
    _db_cache["ts"] = 0.0


def get_autonomous_provider() -> str:
    val = _read_db_defaults().get(DB_KEY_AUTONOMOUS_PROVIDER) or AUTONOMOUS_LLM_PROVIDER
    p = str(val).lower()
    return p if p in VALID_PROVIDERS else "ollama"


def get_ai_service_provider() -> str:
    val = _read_db_defaults().get(DB_KEY_AI_SERVICE_PROVIDER) or AI_SERVICE_LLM_PROVIDER
    p = str(val).lower()
    return p if p in VALID_PROVIDERS else "ollama"


def set_autonomous_provider(provider: str) -> str:
    p = (provider or "").lower()
    if p not in VALID_PROVIDERS:
        raise ValueError(f"Geçersiz provider: {provider}")
    _set_db_default(DB_KEY_AUTONOMOUS_PROVIDER, p)
    return p


def set_ai_service_provider(provider: str, model: Optional[str] = None) -> Dict[str, str]:
    p = (provider or "").lower()
    if p not in VALID_PROVIDERS:
        raise ValueError(f"Geçersiz provider: {provider}")
    _set_db_default(DB_KEY_AI_SERVICE_PROVIDER, p)
    if model is not None:
        _set_db_default(DB_KEY_AI_SERVICE_MODEL, model.strip())
    return resolve_ai_service_default()


def provider_default_model(provider: str) -> str:
    p = (provider or "").lower()
    if p == "deepseek":
        return DEEPSEEK_MODEL
    if p == "claude":
        return CLAUDE_DEFAULT_MODEL
    if p == "gemini":
        return GEMINI_DEFAULT_MODEL
    return AUTONOMOUS_MODEL


def provider_api_key(provider: str) -> str:
    p = (provider or "").lower()
    if p == "deepseek":
        return DEEPSEEK_API_KEY
    if p == "claude":
        return CLAUDE_API_KEY
    if p == "gemini":
        return GEMINI_API_KEY
    return ""


def provider_url(provider: str) -> Optional[str]:
    p = (provider or "").lower()
    if p == "ollama":
        return OLLAMA_URL
    if p == "deepseek":
        return DEEPSEEK_BASE_URL
    if p == "claude":
        return "https://api.anthropic.com"
    if p == "gemini":
        return "https://generativelanguage.googleapis.com"
    return None


def provider_configured(provider: str) -> bool:
    p = (provider or "").lower()
    if p not in VALID_PROVIDERS:
        return False
    if _REQUIRES_KEY.get(p):
        return bool(provider_api_key(p))
    return True


def resolve_autonomous_default() -> Dict[str, str]:
    """Otonom motor için AKTİF varsayılan provider+model. Provider: DB > .env."""
    provider = get_autonomous_provider()
    return {"provider": provider, "model": provider_default_model(provider)}


def resolve_ai_service_default() -> Dict[str, str]:
    """AI-service için AKTİF varsayılan provider+model.
    Provider: DB > .env. Model: DB > .env > sağlayıcı varsayılanı."""
    provider = get_ai_service_provider()
    db_model = str(_read_db_defaults().get(DB_KEY_AI_SERVICE_MODEL, "") or "").strip()
    model = db_model or AI_SERVICE_LLM_MODEL or provider_default_model(provider)
    return {"provider": provider, "model": model}


def get_provider_summaries() -> List[Dict[str, Any]]:
    # Aktif varsayılanları döngü DIŞINDA bir kez çöz (her sağlayıcı için tekrar okuma olmasın).
    autonomous_default = get_autonomous_provider()
    ai_service_default = get_ai_service_provider()
    summaries: List[Dict[str, Any]] = []
    for p in VALID_PROVIDERS:
        raw_key = provider_api_key(p)
        summaries.append({
            "provider": p,
            "configured": provider_configured(p),
            "requires_key": _REQUIRES_KEY[p],
            "api_key_set": bool(raw_key),
            "api_key_masked": mask_api_key(raw_key),
            "url": provider_url(p),
            "default_model": provider_default_model(p),
            "data_leaves_network": _DATA_LEAVES_NETWORK[p],
            "is_autonomous_default": (p == autonomous_default),
            "is_ai_service_default": (p == ai_service_default),
        })
    return summaries
