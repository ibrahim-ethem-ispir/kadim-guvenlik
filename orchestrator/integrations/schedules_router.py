"""
Türkçe: Hedef Kayıtları (Scheduled Scans) router'ı.

Tasarım kararları (sebep/sonuç):
- Prefix `/schedules` → frontend'den `/api/schedules/*` (gateway nginx). nginx'e dokunulmaz.
- Mongo bağlantısı `settings_router.py` deseniyle lazy singleton; ana `db`'yi KULLANMIYORUZ
  çünkü bazı kurulumlarda ana client yetmiyor (settings_router bu kalıbı zaten kurmuş).
  Tek process'te iki client sorun değil; farklı TTL/yapılandırma gerekirse bağımsız.
- `/run` endpoint'i yarış koşulunu `findOneAndUpdate` ile atomik çözer: `last_scan.session_id`
  alanı NULL ise claim et, değilse 409 dön. "Önce kontrol et, sonra başlat" yerine
  doğrudan "claim et" → iki eşzamanlı istek aynı anda yapsa bile biri NULL görür, diğeri
  NULL görmez (ikinci 409 alır).
- `last_scan.status` motor task'ı bittiğinde Mongo polling watcher ile güncellenir.
  Callback takmak ideal ama motor `_run_autonomous` task referansını dışarıya açmıyor
  (fire-and-forget); Mongo polling (60sn × 720 = 13 saat) kabul edilen bir trade-off.
- Pydantic v2 uyumlu: `@field_validator` (Pydantic v1 `@validator` deprecate).
- `auth` (login-arkası tarama) alanı v1'de YOK. Sebep: kullanıcı ihtiyacı 'kendi
  domainlerim' — login-arkası authenticated testler manuel senaryo, scheduled için
  ayrı bir ürün gerektirir. v2'de `auth_ref` (Settings'te tutulan bearer/cookie) ile
  eklenebilir.
- Periyot: 4 enum (off|hourly|daily|weekly). Cron string UI validasyonu zor ve
  kullanıcının 'düzenli tertipli' ihtiyacını 4 seçenek karşılıyor.
- `pipeline_v2` referansı: `set_pipeline_ref()` ile main.py'den inject edilir. Bu, modül
  içinde `from main import pipeline_v2` (yarı yüklenmiş modülden circular import) riskini
  KESER. main.py:router include'dan SONRA `schedules_router.set_pipeline_ref(pipeline_v2)`
  çağrılır; endpoint'ler `_get_pipeline()` üzerinden erişir.
- AI entegrasyonu: scheduler akıllı jitter uygular (tüm taramalar aynı saatte değil);
  `/suggest-interval` endpoint'i hedef tipine göre LLM önerisi verir; `/insight` son
  taramadan 1 cümlelik AI özeti çeker (ai-service `/analyze`'a delege).
"""
import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator
from pymongo import ASCENDING, MongoClient

logger = logging.getLogger("orchestrator.schedules")

router = APIRouter(prefix="/schedules", tags=["schedules"])

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://mongodb:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")
AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8009")

# Sebep: settings_router kalıbı — her çağrıda yeni MongoClient = havuz + monitör sızıntısı.
_mongo_client: Optional[MongoClient] = None
_pipeline_v2_ref: Optional[Any] = None  # main.py startup'tan sonra inject edilir


def set_pipeline_ref(pipeline) -> None:
    """Türkçe: main.py bu fonksiyonu router include'undan SONRA çağırır. Bu sayede
    `/run` endpoint'i `pipeline_v2`'ye `from main import pipeline_v2` (circular import)
    riski olmadan erişir. Test ortamında inject edilmediyse endpoint'ler 503 döner."""
    global _pipeline_v2_ref
    _pipeline_v2_ref = pipeline


def _get_pipeline():
    if _pipeline_v2_ref is None:
        raise HTTPException(status_code=503, detail="Pipeline henüz başlatılmadı")
    return _pipeline_v2_ref


def _get_db():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = MongoClient(MONGODB_URI)
    return _mongo_client[MONGODB_DATABASE]


# ---- Modül yüklenirken index garantisi (bir kerelik) ----
_indexes_ready = False


def _ensure_indexes() -> None:
    global _indexes_ready
    if _indexes_ready:
        return
    try:
        db = _get_db()
        col = db["scan_schedules"]
        # Sebep: scheduler sorgusu (enabled + schedule.enabled + next_run_at) için
        # composite index — tek alanlı index'lerden 3-5x hızlı.
        col.create_index(
            [("enabled", ASCENDING), ("schedule.enabled", ASCENDING), ("schedule.next_run_at", ASCENDING)],
            name="ix_due_lookup",
        )
        col.create_index([("target", ASCENDING)], name="ix_target")
        _indexes_ready = True
    except Exception as e:
        logger.warning("Index oluşturulamadı (ilk çağrı): %s", e)


# ---- Pydantic modelleri (Pydantic v2 alanları) ----
ALLOWED_LEVELS = ("recon", "standard", "deep")
ALLOWED_INTERVALS = ("off", "hourly", "daily", "weekly")

# V2ScanRequest ile birebir aynı hedef validator'ı — frontend ayrı doğrulasa bile
# backend bunu son kale olarak tutar.
_IPV4 = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
_DOMAIN = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
_BAD_CHARS = [";", "&", "|", "`", "$", "(", ")", "<", ">"]


class ScheduleIn(BaseModel):
    target: str
    label: Optional[str] = None
    notes: Optional[str] = None
    level: str = "standard"
    stealth: bool = False
    schedule: Dict[str, Any] = Field(default_factory=lambda: {"enabled": False, "interval": "off"})
    # Tier 3: tags (bulk operations + group işlemleri için), auto_tune_enabled
    tags: List[str] = Field(default_factory=list)
    auto_tune_enabled: bool = True

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        v = (v or "").strip()
        if v.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            parsed = urlparse(v)
            v = parsed.netloc or (parsed.path.split("/")[0] if parsed.path else "")
        if not (re.match(_IPV4, v) or re.match(_DOMAIN, v)):
            raise ValueError("Hedef geçersiz: IPv4 veya domain olmalı")
        if any(c in v for c in _BAD_CHARS):
            raise ValueError("Hedef geçersiz karakter içeriyor")
        # KAPSAM KAPISI: zamanlanmış taramalar da yetki-allowlist + SSRF/iç-ağ guard'ından geçer
        # (aksi halde /scan'de kapatılan yetki, scheduler yolundan sızar).
        from pipeline.scope_guard import enforce_target_scope
        enforce_target_scope(v)
        return v

    @field_validator("level")
    @classmethod
    def _validate_level(cls, v: str) -> str:
        if v not in ALLOWED_LEVELS:
            raise ValueError(f"level {ALLOWED_LEVELS} içinden olmalı")
        return v

    @field_validator("schedule")
    @classmethod
    def _validate_schedule(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        interval = v.get("interval", "off")
        if interval not in ALLOWED_INTERVALS:
            raise ValueError(f"interval {ALLOWED_INTERVALS} içinden olmalı")
        enabled = bool(v.get("enabled", False)) and interval != "off"
        return {"enabled": enabled, "interval": interval}

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, v: List[str]) -> List[str]:
        # normalize: küçük harf, boşluk → tire, max 32 karakter
        out = []
        for t in (v or []):
            t = (t or "").strip().lower().replace(" ", "-")[:32]
            if t and t not in out:
                out.append(t)
        return out[:10]


class SchedulePatch(BaseModel):
    label: Optional[str] = None
    notes: Optional[str] = None
    level: Optional[str] = None
    stealth: Optional[bool] = None
    schedule: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None
    tags: Optional[List[str]] = None
    auto_tune_enabled: Optional[bool] = None


class BulkRequest(BaseModel):
    """Toplu işlem isteği — schedule_id listesi + aksiyon."""
    schedule_ids: List[str]
    action: str  # "run" | "delete" | "enable" | "disable" | "pause" | "resume"
    # Opsiyonel: bulk run için seviye/stealth override
    level: Optional[str] = None
    stealth: Optional[bool] = None


# ---- Periyot hesaplayıcı (router'da da lazım, scheduler ile aynı mantık) ----
def _compute_next_run(interval: str, base: Optional[datetime] = None) -> Optional[datetime]:
    from datetime import timedelta
    base = base or datetime.now(timezone.utc)
    if interval == "hourly":
        return base + timedelta(hours=1)
    if interval == "daily":
        return base + timedelta(days=1)
    if interval == "weekly":
        return base + timedelta(weeks=1)
    return None


# ---- REST uçları ----


# ============================================================
# AI-Driven Katman (auto-scan ile aynı LLM provider üzerinden)
# ============================================================
# Sebep: scheduled scans modülünü "akıllı sürekli istihbarat asistanı"na taşımak.
# LLM'in 4 rolü var:
#   1) suggest-interval: yeni kayıt eklerken hedef tipine göre periyot önerisi
#   2) insight: kayıt satırında son taramadan 1 cümlelik özet
#   3) anomalies: başarısızlık artışı / hedef değişikliği tespiti
#   4) scheduled'da akıllı jitter: tüm taramaları aynı saatte patlatma
# LLM erişilemezse kural-fallback'ine düşer (motor felsefesi: LLM opsiyonel, kritik yol değil).

class IntervalSuggestRequest(BaseModel):
    target: str
    target_type: str = "domain"  # "domain" | "ip"
    label: Optional[str] = None
    notes: Optional[str] = None


async def _llm_suggest_interval(target: str, target_type: str, label: Optional[str], notes: Optional[str]) -> Dict[str, Any]:
    """
    Kural-tabanlı hızlı fallback + opsiyonel LLM ince ayar.
    LLM çağrısı 5s timeout ile sınırlı — UI asılırsa kural-fallback döner.
    """
    base = _heuristic_interval(target, target_type)
    prompt_payload = {
        "task": "schedule_suggestion",
        "target": target,
        "target_type": target_type,
        "label": label or "",
        "notes": notes or "",
        "rule_based_suggestion": base,
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{AI_SERVICE_URL}/analyze",
                json={
                    "scan_data": prompt_payload,
                    "analysis_type": "schedule_suggestion",
                    "use_default": True,
                },
            )
            if r.status_code == 200:
                data = r.json()
                # ai-service response'undan interval çıkar; 'interval' | 'reasoning' | 'confidence' beklenir
                suggested = (data.get("analysis") or {}).get("interval") if isinstance(data.get("analysis"), dict) else None
                if not suggested:
                    # string response ise regex ile yakala
                    import re as _re
                    m = _re.search(r"\b(hourly|daily|weekly|off)\b", str(data.get("analysis", "")))
                    suggested = m.group(1) if m else None
                if suggested in ALLOWED_INTERVALS:
                    return {
                        "interval": suggested,
                        "source": "llm",
                        "reasoning": (data.get("analysis") or {}).get("reasoning") or "LLM önerisi",
                        "confidence": (data.get("analysis") or {}).get("confidence"),
                    }
    except Exception as e:
        logger.debug("LLM interval önerisi alınamadı, kural-fallback: %s", e)
    return {"interval": base, "source": "rule", "reasoning": "Hedef tipine göre kural-tabanlı tahmin", "confidence": 0.6}


def _heuristic_interval(target: str, target_type: str) -> str:
    """Kural-tabanlı hızlı tahmin — LLM yoksa bu döner."""
    # E-ticaret göstergeleri
    ecommerce_kw = ("shop", "store", "cart", "pay", "magaza", "alisveris", "tienda", "boutique")
    api_kw = ("api", "gateway", "service", "rest", "graphql", "grpc")
    static_kw = ("blog", "docs", "wiki", "static", "page", "portfolio", "kisisel")
    t = target.lower()
    if any(k in t for k in ecommerce_kw):
        return "daily"  # günlük — ödeme/ürün güncellemeleri sık değişir
    if any(k in t for k in api_kw):
        return "hourly"  # saatlik — API yüzeyleri en kritik
    if any(k in t for k in static_kw):
        return "weekly"  # haftalık — statik içerik az değişir
    if target_type == "ip":
        return "daily"  # doğrudan IP → muhtemelen internal servis
    return "daily"  # default: günlük


@router.post("/suggest-interval")
async def suggest_interval(payload: IntervalSuggestRequest) -> Dict[str, Any]:
    """Yeni kayıt eklenirken hedef tipine göre periyot önerisi. LLM + kural-fallback."""
    target_type = payload.target_type
    if payload.target_type not in ("ip", "domain"):
        if re.match(_IPV4, payload.target):
            target_type = "ip"
        else:
            target_type = "domain"
    return await _llm_suggest_interval(payload.target, target_type, payload.label, payload.notes)


@router.get("/{schedule_id}/insight")
async def get_insight(schedule_id: str) -> Dict[str, Any]:
    """
    Son taramadan 1 cümlelik AI özeti. Kayıt satırında gösterilir.
    LLM yoksa scan_session.ai_analysis'tan direkt kısa özet döner.
    """
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")
    rec = _get_db()["scan_schedules"].find_one({"_id": oid})
    if not rec:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")
    last_scan = (rec.get("last_scan") or {})
    scan_id = last_scan.get("scan_id")
    if not scan_id:
        return {"insight": "Henüz tarama yapılmadı.", "source": "rule", "confidence": 1.0}
    sess = _get_db()["v2_scan_sessions"].find_one({"scan_id": scan_id})
    if not sess:
        return {"insight": "Tarama kaydı bulunamadı.", "source": "rule", "confidence": 0.5}
    ai = sess.get("ai_analysis") or {}
    summary = ai.get("summary") or sess.get("summary")
    risk = ai.get("risk_score")
    findings = ai.get("critical_findings") or sess.get("critical_findings") or []
    # 1 cümlelik fallback
    if not summary:
        if risk is not None:
            summary = f"Risk skoru {risk}/100. {len(findings)} kritik bulgu."
        else:
            summary = f"Tarama {sess.get('status','bilinmiyor')} durumda tamamlandı."
    # LLM ince özet (varsa)
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post(
                f"{AI_SERVICE_URL}/analyze",
                json={
                    "scan_data": {
                        "task": "scan_insight",
                        "target": rec.get("target"),
                        "status": sess.get("status"),
                        "summary": summary,
                        "risk_score": risk,
                        "critical_findings_count": len(findings),
                    },
                    "analysis_type": "scan_insight",
                    "use_default": True,
                },
            )
            if r.status_code == 200:
                data = r.json()
                insight = (data.get("analysis") or {}).get("insight") or data.get("analysis")
                if insight and isinstance(insight, str) and 5 < len(insight) < 300:
                    return {"insight": insight, "source": "llm", "risk_score": risk, "confidence": 0.9}
    except Exception as e:
        logger.debug("LLM insight alınamadı, kural-fallback: %s", e)
    return {"insight": summary, "source": "rule", "risk_score": risk, "confidence": 0.7}


@router.get("/anomalies")
async def detect_anomalies() -> Dict[str, Any]:
    """
    Tüm kayıtlarda anomali tespiti:
    - 7+ ardışık başarısız tarama
    - 30+ gündür taranmamış aktif kayıt
    - Son taramada risk_score >= 70 (kritik eşik)
    - Hedef artık yanıt vermiyor (tüm son 3 tarama failed)
    LLM ile özetleme opsiyonel (5s timeout).
    """
    db = _get_db()
    anomalies: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for rec in db["scan_schedules"].find({"enabled": True}):
        target = rec.get("target")
        schedule_id = str(rec["_id"])
        last_scan = rec.get("last_scan") or {}
        # Son 3 tarama sürekli failed
        history = list(db["v2_scan_sessions"].find(
            {"target": target, "status": "failed"},
            {"created_at": 1, "status": 1}
        ).sort("created_at", -1).limit(3))
        if len(history) >= 3:
            anomalies.append({
                "type": "consecutive_failures",
                "severity": "warning",
                "target": target,
                "schedule_id": schedule_id,
                "message": f"Son {len(history)} tarama başarısız. Hedef erişilemiyor veya WAF aktif olabilir.",
            })
        # 30+ gün taranmamış
        last_run = rec.get("schedule", {}).get("last_run_at")
        if last_run:
            try:
                days = (now - last_run).days
                if days > 30:
                    anomalies.append({
                        "type": "stale_schedule",
                        "severity": "info",
                        "target": target,
                        "schedule_id": schedule_id,
                        "message": f"{days} gündür taranmadı. Zamanlama devre dışı olabilir.",
                    })
            except Exception:
                pass
        # Son taramada yüksek risk
        if last_scan.get("scan_id"):
            sess = db["v2_scan_sessions"].find_one({"scan_id": last_scan["scan_id"]})
            if sess:
                risk = (sess.get("ai_analysis") or {}).get("risk_score")
                if risk is not None and risk >= 70:
                    anomalies.append({
                        "type": "high_risk",
                        "severity": "critical",
                        "target": target,
                        "schedule_id": schedule_id,
                        "message": f"Son taramada risk skoru {risk}/100 — acil inceleme gerekli.",
                        "scan_id": last_scan["scan_id"],
                    })
    return {"anomalies": anomalies, "count": len(anomalies)}


def _to_dict(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Mongo dokümanını API'ye dönerken normalize et."""
    out = dict(doc)
    out["schedule_id"] = str(out.pop("_id"))
    for ts in ("created_at", "updated_at"):
        if ts in out and isinstance(out[ts], datetime):
            out[ts] = out[ts].isoformat()
    sched = out.get("schedule") or {}
    for ts in ("next_run_at", "last_run_at"):
        if ts in sched and isinstance(sched[ts], datetime):
            sched[ts] = sched[ts].isoformat()
    ls = out.get("last_scan") or {}
    for ts in ("started_at", "finished_at", "failed_at"):
        if ts in ls and isinstance(ls[ts], datetime):
            ls[ts] = ls[ts].isoformat()
    return out


@router.get("")
@router.get("/", include_in_schema=False)
async def list_schedules(q: Optional[str] = None, enabled: Optional[bool] = None) -> Dict[str, Any]:
    """Tüm kayıtları listele. ?q= araması target/label üzerinde case-insensitive yapar."""
    _ensure_indexes()
    query: Dict[str, Any] = {}
    if enabled is not None:
        query["enabled"] = enabled
    if q:
        rx = re.compile(re.escape(q), re.IGNORECASE)
        query["$or"] = [{"target": rx}, {"label": rx}]
    col = _get_db()["scan_schedules"]
    items = [(_to_dict(d)) for d in col.find(query).sort("created_at", -1).limit(500)]
    return {"items": items, "count": len(items)}


@router.post("")
@router.post("/", include_in_schema=False)
async def create_schedule(payload: ScheduleIn) -> Dict[str, Any]:
    _ensure_indexes()
    now = datetime.now(timezone.utc)
    sched = payload.schedule
    next_at = _compute_next_run(sched["interval"], now) if sched["enabled"] else None
    doc = {
        "target": payload.target,
        "target_type": "ip" if re.match(_IPV4, payload.target) else "domain",
        "label": payload.label or "",
        "notes": payload.notes or "",
        "level": payload.level,
        "stealth": payload.stealth,
        "schedule": {
            "enabled": sched["enabled"],
            "interval": sched["interval"],
            "next_run_at": next_at,
            "last_run_at": None,
            "jittered": False,  # scheduler ilk turda jitter uygulayacak
        },
        "last_scan": None,
        "tags": payload.tags,
        "auto_tune_enabled": payload.auto_tune_enabled,
        "tune_history": [],
        "pending_subdomains": [],
        "enabled": True,
        "created_by": "system",  # v1: AuthMiddleware JWT'den user çekilmiyor; ileride eklenir
        "created_at": now,
        "updated_at": now,
    }
    res = _get_db()["scan_schedules"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return {"schedule": _to_dict(doc)}


@router.get("/{schedule_id}")
async def get_schedule(schedule_id: str) -> Dict[str, Any]:
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")
    doc = _get_db()["scan_schedules"].find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")
    return _to_dict(doc)


@router.put("/{schedule_id}")
async def update_schedule(schedule_id: str, payload: SchedulePatch) -> Dict[str, Any]:
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")
    update: Dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if payload.label is not None:
        update["label"] = payload.label
    if payload.notes is not None:
        update["notes"] = payload.notes
    if payload.level is not None:
        if payload.level not in ALLOWED_LEVELS:
            raise HTTPException(status_code=400, detail=f"level {ALLOWED_LEVELS} içinden olmalı")
        update["level"] = payload.level
    if payload.stealth is not None:
        update["stealth"] = payload.stealth
    if payload.enabled is not None:
        update["enabled"] = payload.enabled
    if payload.tags is not None:
        update["tags"] = payload.tags
    if payload.auto_tune_enabled is not None:
        update["auto_tune_enabled"] = payload.auto_tune_enabled
    if payload.schedule is not None:
        sched = payload.schedule
        interval = sched.get("interval", "off")
        if interval not in ALLOWED_INTERVALS:
            raise HTTPException(status_code=400, detail=f"interval {ALLOWED_INTERVALS} içinden olmalı")
        enabled = bool(sched.get("enabled", False)) and interval != "off"
        update["schedule"] = {
            "enabled": enabled,
            "interval": interval,
            "next_run_at": _compute_next_run(interval) if enabled else None,
        }
    if len(update) == 1:
        raise HTTPException(status_code=400, detail="Güncellenecek alan yok")
    res = _get_db()["scan_schedules"].update_one({"_id": oid}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")
    return _to_dict(_get_db()["scan_schedules"].find_one({"_id": oid}))


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str) -> None:
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")
    res = _get_db()["scan_schedules"].delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")


# ---- Manuel çalıştırma (atomik claim + motor task callback) ----
@router.post("/{schedule_id}/run")
async def run_schedule(schedule_id: str) -> Dict[str, Any]:
    """
    Sebep (atomik claim): İki eşzamanlı istek aynı kaydı 'claim' etmeye çalışırsa
    yalnızca BİRİ `last_scan.session_id IS NULL` koşulunu yakalar (Mongo
    findOneAndUpdate atomik). Diğeri `no document matched` alır → 409. Bu olmadan
    scheduler ve frontend aynı anda tıklasa iki paralel tarama açılırdı.
    """
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")

    # 1) Hedef aktif tarama kontrolü (memory içi) — ekrana hızlı geri bildirim için
    # claim'den önce yapılır. Asıl koruma claim atomikliğindedir.
    pipeline_v2 = _get_pipeline()
    existing = _get_db()["scan_schedules"].find_one({"_id": oid})
    if not existing:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")
    target = existing["target"]
    for sess in getattr(pipeline_v2, "_active_pipelines", {}).values():
        if getattr(sess, "target", None) == target and getattr(sess, "status", "") in ("running", "awaiting_approval", "paused"):
            raise HTTPException(
                status_code=409,
                detail=f"Bu hedef zaten taranıyor (session={getattr(sess, 'session_id', '?')})",
            )

    # 2) Atomik claim: koşullu update ile aynı kaydı iki kez claim edemeyiz.
    # Koşul: enabled=True ve (last_scan yok VEYA last_scan.status in terminal-states).
    # Bug 4 düzeltmesi: `paused` da terminal değil — paused taramayı yeniden başlatmak
    # anlamsız, kullanıcı önce resume etmeli. Claim koşulu sadece gerçek terminal
    # durumlarını kabul eder; paused/awaiting_approval/running zaten memory check'inde yakalanır.
    # `stale`: reconcile task (main.py) 6 saat aşan orphan taramayı 'stale' işaretler;
    # bu da terminal sayılmalı yoksa kullanıcı stale kaydı ASLA yeniden çalıştıramaz.
    now = datetime.now(timezone.utc)
    res = _get_db()["scan_schedules"].update_one(
        {
            "_id": oid,
            "enabled": True,
            "$or": [
                {"last_scan": None},
                {"last_scan.session_id": None},
                {"last_scan.status": {"$in": ["completed", "failed", "cancelled", "stale", "timeout"]}},
            ],
        },
        {"$set": {
            "last_scan": {"status": "starting", "started_at": now},
            "updated_at": now,
        }},
    )
    if res.matched_count == 0:
        latest = _get_db()["scan_schedules"].find_one({"_id": oid})
        ls = (latest or {}).get("last_scan") or {}
        raise HTTPException(
            status_code=409,
            detail=f"Bu kayıt zaten bir taramaya bağlı (last_scan.status={ls.get('status')})",
        )

    # 3) start_pipeline → sonuç → last_scan doldur.
    try:
        result = await pipeline_v2.start_pipeline(
            target=target,
            profile_name="autonomous",
            level=existing.get("level", "standard"),
            stealth=bool(existing.get("stealth", False)),
        )
    except Exception as e:
        # Hata olursa claim'i geri al, kullanıcı tekrar deneyebilsin.
        _get_db()["scan_schedules"].update_one(
            {"_id": oid},
            {"$set": {
                "last_scan": {"status": "failed", "error": str(e), "failed_at": datetime.now(timezone.utc)},
                "updated_at": datetime.now(timezone.utc),
            }},
        )
        raise HTTPException(status_code=500, detail=f"Tarama başlatılamadı: {e}")

    session_id = result.get("session_id")
    scan_id = result.get("scan_id")
    # Claim'i gerçek sonuçlarla doldur.
    _get_db()["scan_schedules"].update_one(
        {"_id": oid},
        {"$set": {
            "last_scan": {
                "session_id": session_id,
                "scan_id": scan_id,
                "status": "running",
                "started_at": datetime.now(timezone.utc),
            },
            "updated_at": datetime.now(timezone.utc),
        }},
    )

    # 4) Motor task'ına callback tak: tamamlanınca last_scan.status güncellenecek.
    # start_pipeline `asyncio.create_task` ile fire-and-forget başlatıyor; referansını
    # almak için pipeline iç task listesinden çekmek yerine, kendi izleme task'ımızı
    # başlatıp Mongo'dan status takip ediyoruz (daha sağlam, motor iç yapısına
    # bağımlılık azalır).
    asyncio.create_task(_watch_and_update_status(oid, scan_id))

    return {
        "session_id": session_id,
        "scan_id": scan_id,
        "target": target,
        "schedule_id": str(oid),
    }


@router.post("/{schedule_id}/stop")
async def stop_schedule(schedule_id: str) -> Dict[str, Any]:
    """
    Türkçe: 'running'/'starting' takılı kalmış bir zamanlanmış taramayı zorla sonlandırır.

    Sebep: `_watch_and_update_status` (bkz. `/run`) orchestrator process'i içinde yaşayan
    bir `asyncio.create_task` — restart/crash sonrası bu task kaybolur ve `last_scan.status`
    hiçbir zaman terminal duruma çekilmez (motor session'ı arka planda 'cancelled'/'completed'
    yazmış olsa bile scan_schedules bundan haberdar olmaz). Bu endpoint iki katmanlı düzeltir:
      1) Motor hâlâ aktifse gerçekten iptal eder (pipeline_v2.cancel_pipeline_by_scan_id).
      2) v2_scan_sessions'taki GERÇEK durumu okuyup last_scan'e yansıtır; session da yoksa/
         hâlâ running görünüyorsa (motor sessizce öldüyse) last_scan.status'ü 'cancelled'
         olarak zorlar — kullanıcının "zorla durdur" isteğinin karşılığı budur.
    """
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")

    db = _get_db()
    existing = db["scan_schedules"].find_one({"_id": oid})
    if not existing:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")

    last_scan = existing.get("last_scan") or {}
    scan_id = last_scan.get("scan_id")
    if last_scan.get("status") not in ("starting", "running"):
        raise HTTPException(
            status_code=409,
            detail=f"Bu kayıt zaten çalışmıyor (last_scan.status={last_scan.get('status')})",
        )

    engine_cancelled = False
    if scan_id:
        try:
            pipeline_v2 = _get_pipeline()
            engine_cancelled = await pipeline_v2.cancel_pipeline_by_scan_id(scan_id)
        except HTTPException:
            pass  # pipeline henüz inject edilmemiş — yalnız DB düzeltmesiyle devam
        except Exception as e:
            logger.warning("Motor iptali başarısız (%s): %s", scan_id, e)

    # Session'ın nihai/gerçek durumunu oku (motor kendi güncellemiş olabilir) —
    # zaten terminal ise onu koru, değilse zorla 'cancelled' yaz.
    final_status = "cancelled"
    if scan_id:
        sess = db["v2_scan_sessions"].find_one({"scan_id": scan_id}, {"status": 1})
        if sess and sess.get("status") in ("completed", "failed", "cancelled", "stale", "timeout"):
            final_status = sess["status"]
        elif sess is not None:
            db["v2_scan_sessions"].update_one(
                {"scan_id": scan_id, "status": {"$in": ["running", "pending", "awaiting_approval", "paused"]}},
                {"$set": {"status": "cancelled", "completed_at": datetime.now(timezone.utc).isoformat(),
                          "cancel_reason": "Kullanıcı tarafından zorla durduruldu (scheduled scan)"}},
            )

    now = datetime.now(timezone.utc)
    db["scan_schedules"].update_one(
        {"_id": oid},
        {"$set": {
            "last_scan.status": final_status,
            "last_scan.finished_at": now,
            "updated_at": now,
        }},
    )
    logger.info("⛔ Zamanlanmış tarama zorla durduruldu: %s (schedule=%s, motor_iptal=%s)",
                scan_id, schedule_id, engine_cancelled)
    return {"status": final_status, "schedule_id": str(oid), "scan_id": scan_id,
            "engine_cancelled": engine_cancelled}


async def _watch_and_update_status(schedule_oid: Any, scan_id: Optional[str]) -> None:
    """
    Sebep: pipeline_v2 motor task referansını dışarıya açmıyor (fire-and-forget).
    start_pipeline sonrası task'ı almak için monkey-patch yerine Mongo'dan status
    yoklayarak bitmesini bekleriz. Adaptif aralık: ilk 5 dakika 30s, sonra 2dk, son
    olarak 5dk — çoğu tarama < 30dk; agresif tarama başlangıcı + uzun kuyruk bekleme
    dengelemesi. 13 saat (motor MAX_DURATION_SECONDS) sonra 'timeout' yaz.

    v2'de motor `_run_autonomous` task'ına callback takılabilir; o zaman bu watcher
    tamamen kaldırılabilir (motor iç yapısına minimal değişiklik gerekir).
    """
    if not scan_id:
        return
    db = _get_db()
    sessions = db["v2_scan_sessions"]
    TERMINAL = {"completed", "failed", "cancelled", "stale", "timeout"}
    # (interval_seconds, total_attempts) — adaptif: erken agresif, sonra seyrek.
    phases = [(30, 10), (120, 30), (300, 100)]  # ~5dk + 1sa + ~5sa = 6.5sa
    total = 0
    for interval, attempts in phases:
        for _ in range(attempts):
            await asyncio.sleep(interval)
            total += 1
            try:
                sess = sessions.find_one(
                    {"scan_id": scan_id},
                    {"status": 1, "finished_at": 1},
                )
            except Exception:
                continue
            if not sess:
                continue
            status = sess.get("status")
            if status in TERMINAL:
                # AI 5: Kritik bulgu varsa ilerleme olayı yayınla — frontend WS bunu
                # yakalayıp toast gösterebilir (broadcast mekanizması auto-scan ile aynı).
                risk = (sess.get("ai_analysis") or {}).get("risk_score")
                critical = (sess.get("ai_analysis") or {}).get("critical_findings") or []
                notification: Optional[Dict[str, Any]] = None
                if risk is not None and risk >= 70:
                    notification = {
                        "severity": "critical",
                        "message": f"Risk skoru {risk}/100 — {len(critical)} kritik bulgu",
                        "scan_id": scan_id,
                    }
                elif critical:
                    notification = {
                        "severity": "warning",
                        "message": f"{len(critical)} kritik bulgu tespit edildi",
                        "scan_id": scan_id,
                    }
                update_doc: Dict[str, Any] = {
                    "last_scan.status": status,
                    "last_scan.finished_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                }
                if notification:
                    update_doc["last_scan.notification"] = notification
                db["scan_schedules"].update_one(
                    {"_id": schedule_oid},
                    {"$set": update_doc},
                )
                if notification:
                    try:
                        from .scan_events import emit_progress_update
                        await emit_progress_update(
                            scan_id or "scheduler",
                            f"[SCHEDULED] {notification['message']}",
                            {"source": "scheduled_scan_alert", "severity": notification["severity"]},
                        )
                    except Exception:
                        pass
                return
    # 13 saat aşıldı → UI'ın 'running' takılmasın diye 'timeout' yaz.
    db["scan_schedules"].update_one(
        {"_id": schedule_oid},
        {"$set": {
            "last_scan.status": "timeout",
            "last_scan.finished_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }},
    )


# ============================================================
# Tier 3: Scan Diff Engine — son 2 tarama karşılaştırması
# ============================================================
# Sebep: scheduled scans'in en değerli çıktısı "ne değişti?" sorusudur. Kullanıcı
# "dün ne oldu, bugün ne farklı?" sorusunu LLM özetli cevapla görmek ister. Kural-tabanlı
# karşılaştırma findings listelerini set olarak karşılaştırır; LLM 4s timeout ile
# 1-paragraf özet üretir (kural-fallback her zaman hazır).


def _fingerprint_finding(f: Any) -> str:
    """Bir finding için stabil parmak izi: severity + name/template-id + url/path."""
    info = f.get("info") if isinstance(f, dict) else None
    if isinstance(info, dict):
        sev = info.get("severity", "?")
        name = info.get("name") or f.get("template-id", "?")
    else:
        sev = f.get("severity", "?") if isinstance(f, dict) else "?"
        name = f.get("name") or f.get("path") or f.get("url") or "?"
    loc = ""
    if isinstance(f, dict):
        loc = f.get("url") or f.get("matched-at") or f.get("path") or ""
    return f"{sev}|{name}|{loc}"


async def _diff_sessions(sess_a: Dict[str, Any], sess_b: Dict[str, Any]) -> Dict[str, Any]:
    """
    İki session arasındaki farkı hesapla: yeni/çözülmüş/değişen bulgular.
    LLM 4s timeout ile özet üretir.
    """
    a_findings = (sess_a.get("findings") or sess_a.get("summary", {}).get("findings") or [])
    b_findings = (sess_b.get("findings") or sess_b.get("summary", {}).get("findings") or [])
    a_sev = sess_a.get("severity_counts") or sess_a.get("summary", {}).get("severity_counts") or {}
    b_sev = sess_b.get("severity_counts") or sess_b.get("summary", {}).get("severity_counts") or {}
    a_set = {_fingerprint_finding(f) for f in a_findings if isinstance(f, (dict, str))}
    b_set = {_fingerprint_finding(f) for f in b_findings if isinstance(f, (dict, str))}
    new_set = b_set - a_set
    resolved_set = a_set - b_set
    delta = {
        sev: b_sev.get(sev, 0) - a_sev.get(sev, 0)
        for sev in ("critical", "high", "medium", "low", "info")
    }
    result: Dict[str, Any] = {
        "previous_scan_id": sess_a.get("scan_id"),
        "current_scan_id": sess_b.get("scan_id"),
        "previous_at": sess_a.get("created_at"),
        "current_at": sess_b.get("created_at"),
        "new_findings": list(new_set),
        "resolved_findings": list(resolved_set),
        "new_count": len(new_set),
        "resolved_count": len(resolved_set),
        "severity_delta": delta,
        "previous_severity_counts": a_sev,
        "current_severity_counts": b_sev,
        "summary": None,
        "summary_source": "rule",
    }

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post(
                f"{AI_SERVICE_URL}/analyze",
                json={
                    "scan_data": {
                        "task": "scan_diff",
                        "target": sess_b.get("target"),
                        "new_count": result["new_count"],
                        "resolved_count": result["resolved_count"],
                        "severity_delta": delta,
                        "new_samples": list(new_set)[:5],
                        "resolved_samples": list(resolved_set)[:5],
                    },
                    "analysis_type": "scan_diff",
                    "use_default": True,
                },
            )
            if r.status_code == 200:
                data = r.json()
                analysis = data.get("analysis")
                if isinstance(analysis, dict):
                    insight = analysis.get("summary") or analysis.get("insight")
                    if insight:
                        result["summary"] = insight
                        result["summary_source"] = "llm"
                elif isinstance(analysis, str) and 5 < len(analysis) < 600:
                    result["summary"] = analysis
                    result["summary_source"] = "llm"
    except Exception as e:
        logger.debug("Diff LLM özet alınamadı (kural-fallback): %s", e)

    if not result["summary"]:
        parts: List[str] = []
        if result["new_count"]:
            parts.append(f"{result['new_count']} yeni bulgu")
        if result["resolved_count"]:
            parts.append(f"{result['resolved_count']} çözüldü")
        crit_delta = delta.get("critical", 0)
        high_delta = delta.get("high", 0)
        if crit_delta > 0:
            parts.append(f"+{crit_delta} kritik")
        elif crit_delta < 0:
            parts.append(f"{crit_delta} kritik (azaldı)")
        if high_delta != 0:
            parts.append(f"high {'+' if high_delta > 0 else ''}{high_delta}")
        result["summary"] = " · ".join(parts) if parts else "Değişiklik yok"
    return result


@router.get("/{schedule_id}/diff")
async def get_diff(schedule_id: str) -> Dict[str, Any]:
    """Son iki tamamlanmış tarama arasındaki fark + LLM özet."""
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")
    rec = _get_db()["scan_schedules"].find_one({"_id": oid})
    if not rec:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")
    target = rec["target"]
    sessions_col = _get_db()["v2_scan_sessions"]
    recent = list(sessions_col.find(
        {"target": target, "status": {"$in": ["completed", "failed", "cancelled", "stale"]}}
    ).sort("created_at", -1).limit(2))
    if len(recent) < 2:
        return {
            "available": False,
            "reason": "Karşılaştırma için en az 2 tamamlanmış tarama gerekli",
            "current_count": len(recent),
        }
    current, previous = recent[0], recent[1]
    diff = await _diff_sessions(previous, current)
    diff["available"] = True
    return diff


# ============================================================
# Tier 3: Bulk operations — çoklu kayıt üzerinde aksiyon
# ============================================================
# Sebep: kullanıcının 20+ domain'i olabilir; tek tek ▶ tıklamak yerine gruplayıp
# toplu işlem yapabilmeli. "Tüm prod hedeflerimi şimdi tara" gibi operasyonlar.


@router.post("/bulk")
async def bulk_action(payload: BulkRequest) -> Dict[str, Any]:
    """Toplu aksiyon: run | delete | enable | disable | pause | resume."""
    from bson import ObjectId
    from bson.errors import InvalidId
    if payload.action not in ("run", "delete", "enable", "disable", "pause", "resume"):
        raise HTTPException(status_code=400, detail=f"Geçersiz action: {payload.action}")
    oids: List[Any] = []
    invalid: List[str] = []
    for sid in payload.schedule_ids:
        try:
            oids.append(ObjectId(sid))
        except InvalidId:
            invalid.append(sid)
    if not oids:
        raise HTTPException(status_code=400, detail="Geçerli schedule_id yok")
    col = _get_db()["scan_schedules"]
    results: Dict[str, Any] = {"requested": len(payload.schedule_ids), "invalid_ids": invalid}

    if payload.action == "delete":
        res = col.delete_many({"_id": {"$in": oids}})
        results["deleted"] = res.deleted_count
        return results

    if payload.action in ("enable", "disable"):
        new_val = payload.action == "enable"
        res = col.update_many({"_id": {"$in": oids}}, {"$set": {"enabled": new_val, "updated_at": datetime.now(timezone.utc)}})
        results["updated"] = res.modified_count
        return results

    if payload.action in ("pause", "resume"):
        if payload.action == "pause":
            res = col.update_many({"_id": {"$in": oids}}, {"$set": {"schedule.enabled": False, "updated_at": datetime.now(timezone.utc)}})
        else:
            res = col.update_many(
                {"_id": {"$in": oids}, "schedule.interval": {"$ne": "off"}},
                {"$set": {
                    "schedule.enabled": True,
                    "paused_by_agent": False,
                    "agent_pause_reason": None,
                    "updated_at": datetime.now(timezone.utc),
                }},
            )
        results["updated"] = res.modified_count
        return results

    # run
    pipeline = _get_pipeline()
    queued: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for oid in oids:
        rec = col.find_one({"_id": oid})
        if not rec:
            skipped.append({"schedule_id": str(oid), "reason": "not_found"})
            continue
        target = rec["target"]
        busy = any(
            getattr(s, "target", None) == target
            and getattr(s, "status", "") in ("running", "awaiting_approval", "paused")
            for s in getattr(pipeline, "_active_pipelines", {}).values()
        )
        if busy:
            skipped.append({"schedule_id": str(oid), "reason": "target_active"})
            continue
        now = datetime.now(timezone.utc)
        claim = col.update_one(
            {"_id": oid, "enabled": True,
             "$or": [
                 {"last_scan": None},
                 {"last_scan.session_id": None},
                 {"last_scan.status": {"$in": ["completed", "failed", "cancelled", "stale", "timeout"]}},
             ]},
            {"$set": {"last_scan": {"status": "starting", "started_at": now}, "updated_at": now}},
        )
        if claim.matched_count == 0:
            skipped.append({"schedule_id": str(oid), "reason": "claim_failed"})
            continue
        try:
            r = await pipeline.start_pipeline(
                target=target,
                profile_name="autonomous",
                level=payload.level or rec.get("level", "standard"),
                stealth=payload.stealth if payload.stealth is not None else bool(rec.get("stealth", False)),
            )
            col.update_one(
                {"_id": oid},
                {"$set": {
                    "last_scan": {
                        "session_id": r.get("session_id"),
                        "scan_id": r.get("scan_id"),
                        "status": "running",
                        "started_at": datetime.now(timezone.utc),
                    },
                    "updated_at": datetime.now(timezone.utc),
                }},
            )
            asyncio.create_task(_watch_and_update_status(oid, r.get("scan_id")))
            queued.append({
                "schedule_id": str(oid),
                "session_id": r.get("session_id"),
                "scan_id": r.get("scan_id"),
                "target": target,
            })
        except Exception as e:
            col.update_one(
                {"_id": oid},
                {"$set": {"last_scan": {"status": "failed", "error": str(e)}, "updated_at": datetime.now(timezone.utc)}},
            )
            skipped.append({"schedule_id": str(oid), "reason": f"start_failed: {e}"})
    results["queued"] = queued
    results["skipped"] = skipped
    results["queued_count"] = len(queued)
    return results


# ============================================================
# Tier 3: Pending subdomain accept/dismiss
# ============================================================
@router.post("/{schedule_id}/accept-subdomain")
async def accept_subdomain(schedule_id: str, subdomain: str) -> Dict[str, Any]:
    """Agent'ın önerdiği subdomain'i listeden çıkar, yeni scan_schedules oluştur."""
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")
    col = _get_db()["scan_schedules"]
    rec = col.find_one({"_id": oid})
    if not rec:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")
    pending = rec.get("pending_subdomains") or []
    entry = next((p for p in pending if p.get("subdomain") == subdomain), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Pending subdomain bulunamadı")
    if col.find_one({"target": subdomain}):
        col.update_one(
            {"_id": oid},
            {"$pull": {"pending_subdomains": {"subdomain": subdomain}}},
        )
        return {"created": False, "reason": "already_exists"}
    now = datetime.now(timezone.utc)
    new_doc = {
        "target": subdomain,
        "target_type": "domain",
        "label": f"{subdomain} (auto-discovered from {rec['target']})",
        "notes": f"AI Agent tarafından {entry.get('discovered_at')} tarihinde keşfedildi",
        "level": rec.get("level", "standard"),
        "stealth": rec.get("stealth", False),
        "schedule": {"enabled": False, "interval": "off", "next_run_at": None, "last_run_at": None, "jittered": False},
        "last_scan": None,
        "tags": rec.get("tags", []),
        "auto_tune_enabled": rec.get("auto_tune_enabled", True),
        "tune_history": [],
        "pending_subdomains": [],
        "enabled": True,
        "created_by": "ai_agent",
        "parent_schedule_id": str(oid),
        "created_at": now,
        "updated_at": now,
    }
    res = col.insert_one(new_doc)
    col.update_one(
        {"_id": oid},
        {"$pull": {"pending_subdomains": {"subdomain": subdomain}}},
    )
    return {"created": True, "schedule_id": str(res.inserted_id), "target": subdomain}


@router.post("/{schedule_id}/dismiss-subdomain")
async def dismiss_subdomain(schedule_id: str, subdomain: str) -> Dict[str, Any]:
    """Pending subdomain'i reddet — listeden çıkar."""
    from bson import ObjectId
    from bson.errors import InvalidId
    try:
        oid = ObjectId(schedule_id)
    except InvalidId:
        raise HTTPException(status_code=400, detail="Geçersiz schedule_id")
    res = _get_db()["scan_schedules"].update_one(
        {"_id": oid},
        {"$pull": {"pending_subdomains": {"subdomain": subdomain}}},
    )
    return {"removed": res.modified_count > 0}
