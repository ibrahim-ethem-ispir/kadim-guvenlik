"""
Settings Router - Platform geneli yapılandırma yönetimi
Türkçe: Dinamik ayarlar için REST API
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, Optional, List
from datetime import datetime
import asyncio
import os
from pymongo import MongoClient
import logging

router = APIRouter(prefix="/settings", tags=["settings"])

logger = logging.getLogger("orchestrator.settings")

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://kadim:kadim_secure_2024@mongodb:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")

_mongo_client = None  # tek-sefer oluşturulan, yeniden kullanılan client (llm_env_config deseni)

def get_db():
    # Her çağrıda yeni MongoClient açmak bağlantı havuzu + monitör thread'i sızdırır;
    # pymongo client'ı thread-safe ve tembel bağlanır → bir kez kur, süreç boyunca kullan.
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = MongoClient(MONGODB_URI)
    return _mongo_client[MONGODB_DATABASE]

# --- Models ---
class SettingItem(BaseModel):
    key: str
    value: Any
    description: Optional[str] = None
    category: str = "general"

class WordlistSource(BaseModel):
    name: str
    url: str
    type: str  # "url_list", "api", "github"
    enabled: bool = True
    api_key_required: bool = False
    description: Optional[str] = None

# --- Default Settings ---
DEFAULT_FUZZ_SOURCES = [
    {
        "name": "VirusTotal URLs",
        "url": "https://www.virustotal.com/api/v3/domains/{domain}/urls",
        "type": "api",
        "enabled": True,
        "api_key_required": True,
        "description": "VirusTotal'dan domain URL history çeker"
    },
    {
        "name": "SecLists Common",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "type": "github",
        "enabled": True,
        "api_key_required": False,
        "description": "SecLists yaygın dizin/dosya isimleri"
    },
    {
        "name": "SecLists Directory-List-2.3",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "type": "github", 
        "enabled": False,
        "api_key_required": False,
        "description": "Orta boyutlu dizin listesi (~220k satır)"
    },
    {
        "name": "Dirsearch Default",
        "url": "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt",
        "type": "github",
        "enabled": False,
        "api_key_required": False,
        "description": "Dirsearch varsayılan wordlist"
    }
]

@router.get("/")
async def get_all_settings():
    """Tüm ayarları listele"""
    try:
        db = get_db()
        settings = list(db["Settings"].find({}, {"_id": 0}))
        return {"settings": settings, "count": len(settings)}
    except Exception as e:
        logger.error(f"Settings fetch error: {e}")
        return {"settings": [], "count": 0}

@router.get("/{key}")
async def get_setting(key: str):
    """Belirli bir ayarı getir"""
    try:
        db = get_db()
        setting = db["Settings"].find_one({"key": key}, {"_id": 0})
        if not setting:
            raise HTTPException(status_code=404, detail=f"Ayar bulunamadı: {key}")
        return setting
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{key}")
async def update_setting(key: str, item: SettingItem):
    """Ayarı güncelle veya oluştur"""
    try:
        db = get_db()
        db["Settings"].update_one(
            {"key": key},
            {"$set": {
                "key": key,
                "value": item.value,
                "description": item.description,
                "category": item.category,
                "updated_at": datetime.utcnow()
            }},
            upsert=True
        )
        return {"status": "updated", "key": key}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{key}")
async def delete_setting(key: str):
    """Ayarı sil"""
    try:
        db = get_db()
        result = db["Settings"].delete_one({"key": key})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail=f"Ayar bulunamadı: {key}")
        return {"status": "deleted", "key": key}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Fuzz Specific Endpoints ---
@router.get("/fuzz/sources")
async def get_fuzz_sources():
    """
    Fuzz wordlist kaynaklarını getir
    Türkçe: Dinamik wordlist kaynak yönetimi
    """
    try:
        db = get_db()
        setting = db["Settings"].find_one({"key": "fuzz_wordlist_sources"})
        
        if not setting:
            # İlk kez çağrılıyorsa varsayılanları kaydet
            db["Settings"].insert_one({
                "key": "fuzz_wordlist_sources",
                "value": DEFAULT_FUZZ_SOURCES,
                "category": "fuzz",
                "description": "Dinamik wordlist kaynakları (VirusTotal, GitHub, vb.)",
                "created_at": datetime.utcnow()
            })
            logger.info("Varsayılan fuzz kaynakları oluşturuldu")
            return {"sources": DEFAULT_FUZZ_SOURCES}
        
        return {"sources": setting.get("value", [])}
    except Exception as e:
        logger.error(f"Fuzz sources fetch error: {e}")
        return {"sources": DEFAULT_FUZZ_SOURCES}

@router.post("/fuzz/sources")
async def add_fuzz_source(source: WordlistSource):
    """Yeni wordlist kaynağı ekle"""
    try:
        db = get_db()
        setting = db["Settings"].find_one({"key": "fuzz_wordlist_sources"})
        
        sources = setting.get("value", []) if setting else DEFAULT_FUZZ_SOURCES.copy()
        
        # Aynı isimde kaynak var mı kontrol et
        for s in sources:
            if s.get("name") == source.name:
                raise HTTPException(status_code=400, detail=f"Bu isimde kaynak zaten var: {source.name}")
        
        sources.append(source.dict())
        
        db["Settings"].update_one(
            {"key": "fuzz_wordlist_sources"},
            {"$set": {"value": sources, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        logger.info(f"Yeni fuzz kaynağı eklendi: {source.name}")
        return {"status": "added", "source": source.name, "total": len(sources)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/fuzz/sources/{source_name}")
async def update_fuzz_source(source_name: str, source: WordlistSource):
    """Wordlist kaynağını güncelle"""
    try:
        db = get_db()
        setting = db["Settings"].find_one({"key": "fuzz_wordlist_sources"})
        
        if not setting:
            raise HTTPException(status_code=404, detail="Kaynak listesi bulunamadı")
        
        sources = setting.get("value", [])
        found = False
        for i, s in enumerate(sources):
            if s.get("name") == source_name:
                sources[i] = source.dict()
                found = True
                break
        
        if not found:
            raise HTTPException(status_code=404, detail=f"Kaynak bulunamadı: {source_name}")
        
        db["Settings"].update_one(
            {"key": "fuzz_wordlist_sources"},
            {"$set": {"value": sources, "updated_at": datetime.utcnow()}}
        )
        return {"status": "updated", "source": source_name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/fuzz/sources/{source_name}")
async def delete_fuzz_source(source_name: str):
    """Wordlist kaynağını sil"""
    try:
        db = get_db()
        setting = db["Settings"].find_one({"key": "fuzz_wordlist_sources"})
        
        if not setting:
            raise HTTPException(status_code=404, detail="Kaynak listesi bulunamadı")
        
        sources = setting.get("value", [])
        original_len = len(sources)
        sources = [s for s in sources if s.get("name") != source_name]
        
        if len(sources) == original_len:
            raise HTTPException(status_code=404, detail=f"Kaynak bulunamadı: {source_name}")
        
        db["Settings"].update_one(
            {"key": "fuzz_wordlist_sources"},
            {"$set": {"value": sources, "updated_at": datetime.utcnow()}}
        )
        logger.info(f"Fuzz kaynağı silindi: {source_name}")
        return {"status": "deleted", "source": source_name, "remaining": len(sources)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/fuzz/sources/{source_name}/toggle")
async def toggle_fuzz_source(source_name: str):
    """Wordlist kaynağını aktif/pasif yap"""
    try:
        db = get_db()
        setting = db["Settings"].find_one({"key": "fuzz_wordlist_sources"})
        
        if not setting:
            raise HTTPException(status_code=404, detail="Kaynak listesi bulunamadı")
        
        sources = setting.get("value", [])
        found = False
        new_state = False
        
        for s in sources:
            if s.get("name") == source_name:
                s["enabled"] = not s.get("enabled", True)
                new_state = s["enabled"]
                found = True
                break
        
        if not found:
            raise HTTPException(status_code=404, detail=f"Kaynak bulunamadı: {source_name}")
        
        db["Settings"].update_one(
            {"key": "fuzz_wordlist_sources"},
            {"$set": {"value": sources, "updated_at": datetime.utcnow()}}
        )
        return {"status": "toggled", "source": source_name, "enabled": new_state}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- AI Settings Endpoints ---
# Türkçe: İki katman vardır:
#   1) HASSAS BİLGİ (.env): API anahtarı/URL/model. Bu uçlarda SALT-OKURDUR — env-status maskeli
#      gösterir, env-test canlı bağlantı testi yapar. UI bunları yazmaz (elle .env'den değişir).
#   2) VARSAYILAN SEÇİMİ (DB): "hangi sağlayıcı varsayılan?" — /ai/default/* uçlarıyla DB'ye yazılır
#      ve integrations/llm_env_config resolver'ları (DB > .env) üzerinden okunur. Yalnızca provider
#      ADI DB'ye gider, anahtar ASLA. Eski DB `ai_config` uçları (anahtar da yazan) kaldırılmıştı.

import httpx as _httpx  # modül düzeyinde tek import (fonksiyon içi tekrar import yok)


async def _probe_ollama(model: Optional[str] = None) -> Dict[str, Any]:
    """Ollama /api/tags — servis ayakta mı, (varsa) model yüklü mü?"""
    from integrations.llm_env_config import OLLAMA_URL
    try:
        async with _httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
        if resp.status_code != 200:
            return {"reachable": False, "message": f"Ollama HTTP {resp.status_code}"}
        names = [m.get("name", "") for m in resp.json().get("models", []) if isinstance(m, dict)]
        model_ok = True
        if model:
            base = model.split(":")[0]
            model_ok = any(n == model or n.startswith(base) for n in names)
        return {
            "reachable": True, "model_available": model_ok, "models": names[:5],
            "message": f"Bağlantı başarılı! {len(names)} model mevcut."
                       + ("" if model_ok else f" (uyarı: '{model}' yüklü değil)"),
        }
    except Exception as e:
        return {"reachable": False, "message": f"Ollama erişilemez: {e}"}


async def _probe_deepseek(model: Optional[str] = None) -> Dict[str, Any]:
    """DeepSeek /models — API anahtarı geçerli mi? (OpenAI-uyumlu bulut)"""
    from integrations.llm_env_config import DEEPSEEK_BASE_URL, DEEPSEEK_API_KEY
    if not DEEPSEEK_API_KEY:
        return {"reachable": False, "message": "DEEPSEEK_API_KEY tanımlı değil (.env)"}
    try:
        async with _httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"{DEEPSEEK_BASE_URL}/models",
                headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
            )
        if resp.status_code == 200:
            ids = [m.get("id", "") for m in resp.json().get("data", []) if isinstance(m, dict)]
            model_ok = (model in ids) if (model and ids) else True
            return {"reachable": True, "model_available": model_ok, "models": ids[:5],
                    "message": "API key geçerli!"}
        if resp.status_code in (401, 403):
            return {"reachable": False, "message": "DeepSeek API key geçersiz"}
        return {"reachable": False, "message": f"DeepSeek API hatası: HTTP {resp.status_code}"}
    except Exception as e:
        return {"reachable": False, "message": f"DeepSeek erişilemez: {e}"}


async def _probe_claude(model: Optional[str] = None) -> Dict[str, Any]:
    """Claude /v1/messages ile GERÇEK auth round-trip (yalnız client instantiate DEĞİL)."""
    from integrations.llm_env_config import CLAUDE_API_KEY, CLAUDE_DEFAULT_MODEL
    if not CLAUDE_API_KEY:
        return {"reachable": False, "message": "CLAUDE_API_KEY tanımlı değil (.env)"}
    try:
        async with _httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": CLAUDE_API_KEY,
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": model or CLAUDE_DEFAULT_MODEL, "max_tokens": 1,
                      "messages": [{"role": "user", "content": "test"}]},
            )
        if resp.status_code == 200:
            return {"reachable": True, "model_available": True, "message": "API key geçerli!"}
        if resp.status_code == 401:
            return {"reachable": False, "message": "Claude API key geçersiz"}
        if resp.status_code == 429:
            return {"reachable": False, "message": "Claude rate limit / kredi yok"}
        return {"reachable": False, "message": f"Claude API hatası: HTTP {resp.status_code}"}
    except Exception as e:
        return {"reachable": False, "message": f"Claude erişilemez: {e}"}


async def _probe_gemini(model: Optional[str] = None) -> Dict[str, Any]:
    """Gemini generateContent ile gerçek anahtar doğrulaması."""
    from urllib.parse import quote
    from integrations.llm_env_config import GEMINI_API_KEY, GEMINI_DEFAULT_MODEL
    if not GEMINI_API_KEY:
        return {"reachable": False, "message": "GEMINI_API_KEY tanımlı değil (.env)"}
    # Model adı URL yoluna girer; hatalı/boşluklu GEMINI_MODEL (örn. 'models/...' veya boşluk)
    # URL'yi bozmasın diye bir 'models/' önekini soyup segmenti encode et.
    raw_model = (model or GEMINI_DEFAULT_MODEL).strip()
    if raw_model.startswith("models/"):
        raw_model = raw_model[len("models/"):]
    m = quote(raw_model, safe="")
    try:
        async with _httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={GEMINI_API_KEY}",
                json={"contents": [{"parts": [{"text": "test"}]}],
                      "generationConfig": {"maxOutputTokens": 1}},
            )
        if resp.status_code == 200:
            return {"reachable": True, "model_available": True, "message": "API key geçerli!"}
        if resp.status_code == 429:
            return {"reachable": False, "message": "Gemini quota / rate limit"}
        if resp.status_code == 400:
            msg = resp.json().get("error", {}).get("message", "geçersiz istek")
            return {"reachable": False, "message": f"Gemini hatası: {msg}"}
        return {"reachable": False, "message": f"Gemini API hatası: HTTP {resp.status_code}"}
    except Exception as e:
        return {"reachable": False, "message": f"Gemini erişilemez: {e}"}


_PROBES = {
    "ollama": _probe_ollama,
    "deepseek": _probe_deepseek,
    "claude": _probe_claude,
    "gemini": _probe_gemini,
}


@router.get("/ai/env-status")
async def get_ai_env_status():
    """
    Proje geneli LLM yapılandırmasının (.env) SALT-OKUR durumu.
    Türkçe: 4 sağlayıcı için (ollama/deepseek/claude/gemini) yapılandırma özeti + canlı
    erişilebilirlik. Anahtarlar MASKELİ döner. UI (admin/ai-settings) bunu tüketir.
    """
    from integrations.llm_env_config import (
        get_provider_summaries, resolve_ai_service_default, get_autonomous_provider,
    )
    summaries = get_provider_summaries()

    # Yalnız yapılandırılmış (anahtarı olan) sağlayıcılar için canlı probe yap — gereksiz
    # bulut çağrısı/gecikme olmasın. Probe'lar PARALEL çalışır (asyncio.gather): birden çok
    # bulut sağlayıcı yapılandırılıysa toplam süre tek sağlayıcının gecikmesine iner (seri
    # await'te ~timeout'ların toplamı kadar sürüyordu). Yapılandırılmamış → reachable=False.
    configured = [s for s in summaries if s.get("configured")]
    probe_results = await asyncio.gather(
        *[_PROBES[s["provider"]](s.get("default_model")) for s in configured],
        return_exceptions=True,
    )
    probe_by_provider: Dict[str, Any] = {}
    for s, res in zip(configured, probe_results):
        # Bir probe beklenmedik biçimde patlarsa (gather return_exceptions) erişilemez say.
        probe_by_provider[s["provider"]] = (
            {"reachable": False, "message": f"Probe hatası: {res}"}
            if isinstance(res, Exception) else res
        )
    for s in summaries:
        if s.get("configured"):
            probe = probe_by_provider.get(s["provider"], {})
            s.update({
                "reachable": bool(probe.get("reachable")),
                "model_available": probe.get("model_available"),
                "message": probe.get("message"),
                "models": probe.get("models"),
            })
        else:
            s.update({"reachable": False, "model_available": False,
                      "message": "Yapılandırılmamış (.env'de anahtar yok)", "models": []})

    ai_default = resolve_ai_service_default()
    return {
        "providers": summaries,
        "autonomous_provider": get_autonomous_provider(),   # auto-scan motoru (DB > .env)
        "ai_service_provider": ai_default["provider"],      # rapor/analiz motoru (DB > .env)
        "ai_service_model": ai_default["model"],
    }


@router.post("/ai/env-test/{provider}")
async def test_ai_env_connection(provider: str):
    """
    Belirli bir sağlayıcı için `.env`'deki yapılandırmayla GERÇEK bağlantı testi.
    Türkçe: Anahtarı DB'den değil `.env`'den okur; deepseek dahil 4 sağlayıcıyı destekler.
    """
    from integrations.llm_env_config import VALID_PROVIDERS, provider_default_model, provider_configured
    p = (provider or "").lower()
    if p not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Geçersiz provider: {provider}")
    if not provider_configured(p):
        return {"status": "error", "provider": p,
                "message": f"{p} yapılandırılmamış — .env'de anahtar/URL eksik."}
    probe = await _PROBES[p](provider_default_model(p))
    return {
        "status": "success" if probe.get("reachable") else "error",
        "provider": p,
        "message": probe.get("message", ""),
        "models": probe.get("models", []),
    }


# --- Varsayılan sağlayıcı SEÇİMİ (DB'ye yazılır — hassas anahtar DEĞİL, yalnız provider adı) ---
class DefaultProviderBody(BaseModel):
    provider: str                      # ollama | deepseek | claude | gemini
    model: Optional[str] = None        # yalnız ai-service için opsiyonel


@router.put("/ai/default/autonomous")
async def set_autonomous_default(body: DefaultProviderBody):
    """Otonom motorun (auto-scan) varsayılan LLM sağlayıcısını DB'ye yaz.
    Doğrulama: geçerli provider + `.env`'de anahtar/URL yapılandırılmış olmalı."""
    from integrations.llm_env_config import (
        VALID_PROVIDERS, provider_configured, set_autonomous_provider,
    )
    p = (body.provider or "").lower()
    if p not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Geçersiz provider: {body.provider}")
    if not provider_configured(p):
        raise HTTPException(status_code=400,
                            detail=f"{p} yapılandırılmamış — önce .env'e anahtar/URL ekleyin.")
    set_autonomous_provider(p)
    logger.info(f"Otonom motor varsayılanı DB'ye yazıldı: {p}")
    return {"status": "updated", "scope": "autonomous", "provider": p}


@router.put("/ai/default/ai-service")
async def set_ai_service_default(body: DefaultProviderBody):
    """Rapor/Analiz (ai-service) varsayılan LLM sağlayıcısını (ve opsiyonel model'i) DB'ye yaz."""
    from integrations.llm_env_config import (
        VALID_PROVIDERS, provider_configured, set_ai_service_provider,
    )
    p = (body.provider or "").lower()
    if p not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Geçersiz provider: {body.provider}")
    if not provider_configured(p):
        raise HTTPException(status_code=400,
                            detail=f"{p} yapılandırılmamış — önce .env'e anahtar/URL ekleyin.")
    result = set_ai_service_provider(p, body.model)
    logger.info(f"AI-service varsayılanı DB'ye yazıldı: {result}")
    return {"status": "updated", "scope": "ai-service", **result}


@router.get("/ai/autonomous-status")
async def get_autonomous_llm_status():
    """
    Otonom motorun AKTİF LLM (istihbarat subayı) durumunu tarama BAŞLATMADAN döndürür.
    Türkçe: UI'daki "Aktif LLM" göstergesi/modalı bunu kullanır. Hangi provider (ollama|deepseek)
    ve model seçili, sağlayıcı erişilebilir mi, model hazır mı, motor LLM-destekli mi yoksa
    kural-fallback modunda mı çalışacak — hepsini gösterir.

    Not: Motorun kendi preflight() mantığını yeniden kullanır (tek doğruluk kaynağı). emit=None
    verildiği için yalnızca hafif bir sağlık HTTP kontrolü yapar; tarama/yan etki oluşturmaz.
    """
    from integrations.llm_env_config import provider_configured
    try:
        # Import burada (döngüsel import ve pipeline bağımlılığını router yüklenirken tetiklememek için).
        from pipeline.autonomous_engine import AutonomousEngine
        # Hafif prob instance — aktif varsayılan sağlayıcıyı (DB > .env) kendi __init__'inde çözer.
        probe = AutonomousEngine(scan_id="_llm_status_probe_", target="probe.local", emit=None)
        status = await probe.preflight()
        return {
            "provider": probe.provider,
            "model": probe.model,
            "configured": provider_configured(probe.provider),  # .env'de anahtar/URL var mı
            "reachable": bool(status.get("ollama_reachable")),
            "model_available": bool(status.get("model_available")),
            "mode": status.get("mode", "rules-only"),   # "llm-assisted" | "rules-only"
            "url": status.get("url"),
        }
    except Exception as e:
        logger.error(f"Autonomous LLM status error: {e}")
        # Hata da olsa UI kırılmasın — motor zaten LLM'siz (kural+graf) çalışabildiğinden bunu bildir.
        from integrations.llm_env_config import get_autonomous_provider
        prov = get_autonomous_provider()
        return {
            "provider": prov,
            "model": None,
            "configured": provider_configured(prov),
            "reachable": False,
            "model_available": False,
            "mode": "rules-only",
            "url": None,
            "error": str(e),
        }

@router.get("/ai/models")
async def get_ai_models():
    """
    Tüm provider'lar için kullanılabilir modelleri listele
    """
    import httpx
    
    models = {
        "ollama": [],
        "deepseek": [
            {"id": "deepseek-v4-flash", "name": "DeepSeek V4 Flash", "description": "Hızlı & ekonomik (önerilen)"},
            {"id": "deepseek-v4-pro", "name": "DeepSeek V4 Pro", "description": "En güçlü, pahalı"},
            {"id": "deepseek-chat", "name": "DeepSeek Chat", "description": "Legacy alias (v4-flash non-thinking)"},
            {"id": "deepseek-reasoner", "name": "DeepSeek Reasoner", "description": "Reasoning (thinking modu)"},
        ],
        "claude": [
            {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4", "description": "En yeni, dengeli"},
            {"id": "claude-opus-4-20250514", "name": "Claude Opus 4", "description": "En güçlü"},
            {"id": "claude-3-5-sonnet-latest", "name": "Claude 3.5 Sonnet", "description": "Stabil, hızlı"},
            {"id": "claude-3-5-haiku-latest", "name": "Claude 3.5 Haiku", "description": "En hızlı, ekonomik"},
        ],
        "gemini": [
            {"id": "gemini-3-pro", "name": "Gemini 3 Pro", "description": "👑 En Güçlü (Son Model)"},
            {"id": "gemini-3-flash", "name": "Gemini 3 Flash", "description": "⚡ Çok Hızlı ve Güçlü"},
            {"id": "gemini-3-deep-think", "name": "Gemini 3 Deep Think", "description": "🧠 Reasoning Model"},
            {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash", "description": "Stabil, GA sürüm"},
            {"id": "gemini-2.0-flash-lite", "name": "Gemini 2.0 Flash Lite", "description": "Ekonomik, hızlı"},
            {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro", "description": "1M context, güçlü"},
            {"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash", "description": "Hızlı, ucuz"},
        ]
    }
    
    # Ollama modellerini çek
    try:
        ollama_url = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{ollama_url}/api/tags")
            if resp.status_code == 200:
                for m in resp.json().get("models", []):
                    models["ollama"].append({
                        "id": m["name"],
                        "name": m["name"],
                        "description": f"Local - {m.get('size', 'unknown')} bytes"
                    })
    except:
        pass
    
    return models
