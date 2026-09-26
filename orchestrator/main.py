from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Request, Depends
from pydantic import BaseModel, validator
import httpx
import os
import re
import uuid
import json
import logging

import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime
from nmap_proxy import proxy_nmap_stream, proxy_nmap_monitor
from integrations.raw_log_proxy import proxy_raw_log_stream
from integrations.recon_proxy import router as recon_router  # Recon Intelligence (Varlık Keşfi)
from integrations.fingerprint_proxy import router as fingerprint_router  # Parmak İzi (wappalyzergo hızlı tespit)
from integrations.cf_analyzer_proxy import router as cf_analyzer_router  # CF Analyzer (Eski servis - backward compat)
from integrations.hash_cracker_proxy import router as hash_cracker_router
from integrations.ai_proxy import router as ai_router  # AI Analysis (Ollama + Claude)
from subfinder_proxy import dispatch_subfinder as _dispatch_subfinder_raw
from pipeline.scan_pipeline_v2 import ScanPipelineV2
from pipeline.scan_profiles import list_profiles as list_scan_profiles
from pipeline.scan_events import (
    ScanEventBus, ScanEvent, ScanEventType,
    emit_scan_started, emit_command_executing, emit_port_found,
    emit_vulnerability_found, emit_progress_update, emit_scan_completed,
    emit_scan_failed, emit_error, emit_heartbeat
)


# ============== Error Sanitization ==============
# Türkçe: Hata temizleme/çeviri mantığı core/errors.py'ye taşındı.
from core.errors import (
    sanitize_error_message,
    get_user_friendly_error,
    ERROR_MESSAGES,
)
from integrations.fuzz_proxy import router as fuzz_router
from integrations.redteam_proxy import router as redteam_router  # Red Team (hassas-yol probu + AI saldırgan analizi)
from integrations.settings_router import router as settings_router  # Settings API (Dinamik ayarlar)
from integrations.schedules_router import router as schedules_router  # Hedef Kayıtları (scheduled scans)
from core.auth_middleware import AuthMiddleware

# Modül seviyesi logger: event-stream/WS disconnect handler'ında (main.py:1518,1520)
# çıplak `logger` kullanılıyordu ama hiç tanımlı değildi → istemci bağlantıyı kesince
# `NameError: name 'logger' is not defined` fırlatıp devasa traceback üretiyordu.
logger = logging.getLogger("orchestrator")

# 🧠 AI Brain Modülü
try:
    from integrations.brain_proxy import router as brain_router, trigger_brain_learning, trigger_attack_chain_suggestion
    BRAIN_AVAILABLE = True
    print("✅ AI Brain Proxy yüklendi")
except ImportError as e:
    BRAIN_AVAILABLE = False
    trigger_brain_learning = None
    trigger_attack_chain_suggestion = None
    print(f"⚠️ AI Brain Proxy yüklenemedi: {e}")

app = FastAPI(title="Kadim Guvenlik Orchestrator")

# Add Auth Middleware
app.add_middleware(AuthMiddleware)


def require_admin(request: Request) -> Dict[str, Any]:
    """
    Türkçe: Yalnızca admin rolündeki kullanıcıya izin veren FastAPI dependency.
    AuthMiddleware geçerli JWT'yi doğrulayıp payload'ı request.state.user'a koyar ama
    ROL BAKMAZ; admin-özel endpoint'ler (ör. LLM logları — hedef istihbaratı + iç karar
    mantığını açar) bu bağımlılıkla korunur. Rol claim'i esnek okunur ("role" | "is_admin").
    """
    user = getattr(request.state, "user", None)
    if not user:
        # Normalde middleware bu noktaya token'sız istek bırakmaz; savunma amaçlı.
        raise HTTPException(status_code=401, detail="Kimlik doğrulanamadı")
    role = str(user.get("role", "")).lower()
    is_admin = user.get("is_admin") is True or role == "admin"
    if not is_admin:
        raise HTTPException(status_code=403, detail="Bu kaynağa yalnızca admin erişebilir")
    return user

# Router'ları ekle
app.include_router(recon_router)  # Recon Intelligence modülü (/api/recon/*)
app.include_router(fingerprint_router)  # Parmak İzi modülü (/api/fingerprint/*) — manuel hızlı tespit
app.include_router(cf_analyzer_router)  # CF Analyzer modülü (/api/cf-analyzer/*) - backward compatibility
app.include_router(hash_cracker_router)
app.include_router(ai_router)  # AI Analysis modülü (/ai/*)
app.include_router(fuzz_router) # Fuzzing Service (/api/fuzz/*)
app.include_router(redteam_router) # Red Team modülü (/api/redteam/*)
app.include_router(settings_router) # Settings API (/api/settings/*)
app.include_router(schedules_router) # Scheduled Scans (/api/schedules/*)
from integrations.schedules_ws import router as schedules_ws_router  # WebSocket push (/api/schedules/ws/*)
app.include_router(schedules_ws_router)

# NOT: `schedules_router.set_pipeline_ref(...)` çağrısı aşağıda (satır ~240),
# `pipeline_v2` tanımından SONRA yapılır. Burada çağırırsak NameError alırız —
# orchestrator ayağa kalkmaz → nginx Bad Gateway döner. `set_pipeline_ref` modül
# fonksiyonu olduğu için router import'unun yanına modülü de import ediyoruz
# (aşağıda set_pipeline_ref satırında `import integrations.schedules_router as
# schedules_module` yapılır).

# Türkçe: Servis proxy route'ları (main.py'den ayrıldı — routers/)
from routers.nmap import router as nmap_router
app.include_router(nmap_router)  # /nmap/*
from routers.nuclei import router as nuclei_router
app.include_router(nuclei_router)  # /nuclei/*
from routers.reports import router as reports_router
app.include_router(reports_router)  # /osint/*, /scans, /vulnerabilities

# 🧠 AI Brain Router
if BRAIN_AVAILABLE:
    app.include_router(brain_router)
    print("✅ AI Brain endpoints aktif: /api/ai/brain/*")

# Configuration
# Türkçe: Altyapı ayarları core/config.py'ye taşındı (env okuma tek noktada).
from core.config import REDIS_URL, MONGODB_URI, MONGODB_DATABASE
# Türkçe: Servis URL'leri artık tek noktadan (plugins/registry.py) besleniyor.
# Yeni servis eklemek için registry.py'deki PLUGINS listesine tek satır ekle.
# Değişken isimleri geriye dönük uyumluluk için korundu; davranış birebir aynı.
from plugins import registry as _plugin_registry

NMAP_SERVICE_URL = _plugin_registry.url("nmap")
SUBFINDER_SERVICE_URL = _plugin_registry.url("subfinder")
RUSTSCAN_SERVICE_URL = _plugin_registry.url("rustscan")
NUCLEI_SERVICE_URL = _plugin_registry.url("nuclei")
OSINT_SERVICE_URL = _plugin_registry.url("osint")
HASH_CRACKER_SERVICE_URL = _plugin_registry.url("hash_cracker")
RECON_SERVICE_URL = _plugin_registry.url("recon")  # Yeni recon service
AI_SERVICE_URL = _plugin_registry.url("ai")  # AI Analysis service
FUZZ_SERVICE_URL = _plugin_registry.url("fuzz")

# Redis Connection Removed
# r = redis.from_url(REDIS_URL)

# MongoDB Connection (for persistent storage)
# Türkçe: Bağlantı ve koleksiyon erişimi core/db.py'ye taşındı.
# db bağlantı kurulamazsa None olur (eski davranışla birebir aynı).
from core.db import (
    mongo_client,
    db,
    get_scans_collection,
    get_sessions_collection,
    get_activities_collection,
    get_vulnerabilities_collection,
    get_scan_schedules_collection,
)

# ============== Stale Scan Cleanup Background Task ==============

# Türkçe: Servis bazlı dinamik stale threshold'lar
STALE_THRESHOLDS = {
    "nmap": 600,      # 10 dakika - nmap için yeterli
    "nuclei": 1800,   # 30 dakika - nuclei daha uzun sürebilir
    "subfinder": 300, # 5 dakika - hızlı olmalı
    "rustscan": 300,  # 5 dakika
    "fuzz": 600,      # 10 dakika
    "default": 900    # 15 dakika (varsayılan)
}

async def stale_scan_cleanup_task():
    """
    Türkçe: Her 1 dakikada bir çalışan arka plan görevi
    Servis bazlı dinamik threshold ile stale taramaları tespit eder
    """
    CLEANUP_INTERVAL = 60  # 1 dakika (5'ten düşürüldü - daha hızlı tespit)
    
    print("🧹 Stale scan cleanup task başlatıldı")
    
    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL)
            
            scans_col = get_scans_collection()
            activities_col = get_activities_collection()
            
            if scans_col is None:
                continue
            
            # Türkçe: Dinamik threshold ile stale taramaları tespit et
            threshold_time = datetime.utcnow()
            stale_count = 0

            # Running durumundaki taramaları kontrol et
            running_scans = scans_col.find({"status": "running"})

            for scan in running_scans:
                created_at = scan.get("created_at")
                if created_at is None:
                    continue

                elapsed = (threshold_time - created_at).total_seconds()
                scan_types = scan.get("scan_types", [])

                # Türkçe: Servis bazlı en yüksek threshold'u al
                max_threshold = max(
                    STALE_THRESHOLDS.get(st, STALE_THRESHOLDS["default"])
                    for st in scan_types
                ) if scan_types else STALE_THRESHOLDS["default"]

                if elapsed > max_threshold:
                    scan_id = scan.get("scan_id")
                    target = scan.get("target", "unknown")
                    
                    # Türkçe: Stale olarak işaretle
                    scans_col.update_one(
                        {"scan_id": scan_id},
                        {
                            "$set": {
                                "status": "stale",
                                "stale_reason": f"Tarama {elapsed/60:.0f} dakikadır yanıt vermiyor",
                                "marked_stale_at": datetime.utcnow()
                            }
                        }
                    )
                    
                    # Türkçe: Aktivite logla
                    if activities_col is not None:
                        activities_col.insert_one({
                            "type": "scan_stale",
                            "scan_id": scan_id,
                            "target": target,
                            "message": f"Tarama stale olarak işaretlendi ({elapsed/60:.0f} dakika)",
                            "severity": "warning",
                            "timestamp": datetime.utcnow()
                        })
                    
                    stale_count += 1
                    print(f"⚠️ Stale scan işaretlendi: {scan_id} ({target})")
            
            if stale_count > 0:
                print(f"🧹 Cleanup tamamlandı: {stale_count} stale tarama işaretlendi")
                
        except Exception as e:
            print(f"❌ Stale cleanup hatası: {e}")


# Türkçe: Zamanlanmış tarama takılma eşiği. `_watch_and_update_status` (schedules_router.py)
# in-memory bir asyncio.create_task — orchestrator restart/crash olursa bu task kaybolur ve
# `scan_schedules.last_scan.status` sonsuza dek 'running'/'starting' takılı kalır (gerçek
# v2_scan_sessions durumu 'cancelled'/'completed' olsa bile kimse geri yazmaz). Bu görev her
# turda hem senkron kopukluğunu (session zaten bitmiş) hem de gerçek orphan'ı (session da
# bulunamıyor/donmuş) düzeltir.
SCHEDULE_STALE_THRESHOLD_SECONDS = 6 * 3600  # motor MAX_DURATION'ından kısa — watcher'ın
# 13 saatlik üst sınırını beklemeden operatöre "takıldı" sinyali verir.


async def scheduled_scan_reconcile_task():
    """
    Türkçe: Her 1 dakikada bir `scan_schedules` içindeki running/starting kayıtları
    `v2_scan_sessions`'daki GERÇEK durumla senkronize eder. İki senaryoyu kapsar:
      1) Session zaten terminal (motor bitirmiş, watcher restart'ta kaybolmuş) → senkronize et.
      2) Session yok VEYA hâlâ running ama eşik aşılmış (motor sessizce öldü) → 'stale' yaz.
    """
    CLEANUP_INTERVAL = 60
    print("🧹 Zamanlanmış tarama reconcile task'ı başlatıldı")

    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL)
            schedules_col = get_scan_schedules_collection()
            sessions_col = get_sessions_collection()
            if schedules_col is None or sessions_col is None:
                continue

            now = datetime.utcnow()
            stuck = schedules_col.find({"last_scan.status": {"$in": ["starting", "running"]}})

            for sched in stuck:
                last_scan = sched.get("last_scan") or {}
                scan_id = last_scan.get("scan_id")
                started_at = last_scan.get("started_at")

                if not scan_id:
                    # 'starting' claim edildi ama start_pipeline hiç dönmedi (ör. o anda
                    # process restart oldu) — started_at eşiği aştıysa serbest bırak.
                    if started_at and (now - started_at).total_seconds() > SCHEDULE_STALE_THRESHOLD_SECONDS:
                        schedules_col.update_one(
                            {"_id": sched["_id"]},
                            {"$set": {"last_scan.status": "failed",
                                      "last_scan.error": "Tarama başlatma yarım kaldı (orchestrator yeniden başladı)",
                                      "last_scan.finished_at": now, "updated_at": now}},
                        )
                    continue

                sess = sessions_col.find_one({"scan_id": scan_id}, {"status": 1})
                if sess and sess.get("status") in ("completed", "failed", "cancelled", "stale", "timeout"):
                    # Motor bitirmiş ama watcher (restart'ta kaybolan in-memory task) geri
                    # yazamamış — gerçek durumu senkronize et.
                    schedules_col.update_one(
                        {"_id": sched["_id"]},
                        {"$set": {"last_scan.status": sess["status"], "last_scan.finished_at": now,
                                  "updated_at": now}},
                    )
                    print(f"🔄 Zamanlanmış tarama senkronize edildi: {sched.get('target')} → {sess['status']}")
                    continue

                # Session yok ya da hâlâ 'running' görünüyor — yalnızca eşik aşıldıysa dokun
                # (aktif taramaları erken kesme riski yok, watcher zaten canlıyken bu yola hiç
                # düşmez çünkü status daha erken terminal olur).
                if started_at and (now - started_at).total_seconds() > SCHEDULE_STALE_THRESHOLD_SECONDS:
                    if sess is None:
                        reason = "Tarama kaydı bulunamadı (orchestrator yeniden başladı, motor durumu kayboldu)"
                    else:
                        reason = f"Tarama {SCHEDULE_STALE_THRESHOLD_SECONDS//3600} saatten uzun süredir yanıt vermiyor"
                    schedules_col.update_one(
                        {"_id": sched["_id"]},
                        {"$set": {"last_scan.status": "stale", "last_scan.error": reason,
                                  "last_scan.finished_at": now, "updated_at": now}},
                    )
                    print(f"⚠️ Zamanlanmış tarama stale işaretlendi: {sched.get('target')} ({reason})")

        except Exception as e:
            print(f"❌ Zamanlanmış tarama reconcile hatası: {e}")


# ============== v2 Pipeline Instance ==============
pipeline_v2 = ScanPipelineV2(db)

# Türkçe: Scheduled scans router'ı `/run` endpoint'inde `pipeline_v2`'ye erişmek için
# referans inject edilir. Bunu `pipeline_v2` tanımından SONRA yapmak zorunlu — önce
# yaparsak NameError → container ayağa kalkmaz → Bad Gateway (B5 düzeltmesi).
# `schedules_router` burada APIRouter objesi; modülün kendisini `as` ile alıyoruz ki
# modül-level `set_pipeline_ref` fonksiyonuna erişelim.
import integrations.schedules_router as schedules_module
schedules_module.set_pipeline_ref(pipeline_v2)


@app.on_event("startup")
async def startup_event():
    """Türkçe: Uygulama başlangıcında arka plan görevlerini çalıştır"""
    # Stale scan cleanup task'ı başlat
    asyncio.create_task(stale_scan_cleanup_task())

    # Türkçe: Zamanlanmış tarama (scan_schedules) reconcile task'ı — restart'ta kaybolan
    # in-memory watcher'ın bıraktığı 'running' takılı kayıtları düzeltir (bkz. fonksiyon
    # docstring'i). stale_scan_cleanup_task'tan bağımsız çünkü farklı koleksiyon/şema.
    asyncio.create_task(scheduled_scan_reconcile_task())

    # Türkçe: Zamanlanmış tarama zamanlayıcısı. pipeline_v2 referansı parametre olarak
    # geçirilir → scheduler.py main.py import etmez, döngüsel import riski yok.
    from pipeline.scheduler import schedule_runner_task
    asyncio.create_task(schedule_runner_task(pipeline_v2))

    # Tier 3: Kalıcı AI Ajanı — 7/24 çalışan, tüm scan event'lerini dinleyen, karar alan
    # ve aksiyon uygulayan persistent task. auto-tune, anomali tespiti, subdomain önerisi
    # gibi işleri yapar. LLM 5s timeout ile; kural-fallback her zaman hazır.
    from pipeline.ai_agent import ai_agent_loop
    asyncio.create_task(ai_agent_loop())

    # KAPSAM KAPISI görünürlüğü: allowlist boşsa operatör tüm hedeflere izin veriyor demektir
    # (dış-kutu konuşlanmasında yetkisiz-tarama riski). Bir kez, açıkça uyar.
    try:
        from pipeline.scope_guard import authorized_hosts_configured
        if not authorized_hosts_configured():
            logger.warning(
                "⚠️ KAPSAM KAPISI AÇIK DEĞİL: AUTHORIZED_TARGETS boş — her yetkili kullanıcı "
                "HERHANGİ bir hedefi tarayabilir. Bankacılık/engagement için allowlist doldurun."
            )
            print("⚠️ AUTHORIZED_TARGETS boş — kapsam allowlist'i zorlanmıyor (yetkisiz-tarama riski)")
        else:
            print("🛡️ Kapsam kapısı aktif (AUTHORIZED_TARGETS zorlanıyor)")
    except Exception:
        pass

    print("🚀 Orchestrator başlatıldı, background tasklar aktif")
    print("🚀 v2 Pipeline Engine aktif")
    print("📅 Scheduled scans runner aktif")
    print("🤖 AI Agent loop aktif")


# ============== MongoDB Helper Functions ==============


def save_scan_to_db(scan_id: str, target: str, scan_types: List[str]):
    """Türkçe: Yeni taramayı MongoDB'ye kaydet"""
    collection = get_scans_collection()
    if collection is not None:
        try:
            collection.insert_one({
                "scan_id": scan_id,
                "target": target,
                "scan_types": scan_types,
                "status": "running",
                "created_at": datetime.utcnow(),
                "completed_at": None,
                "results": {}
            })
            log_activity("scan_started", scan_id, target, f"{', '.join(scan_types)} taraması başlatıldı")
        except Exception as e:
            print(f"MongoDB kayıt hatası: {e}")

def update_scan_result(scan_id: str, service: str, result: dict):
    """
    Türkçe: Servis sonucunu MongoDB'de atomik olarak güncelle

    Özellikler:
    - findOneAndUpdate ile atomik güncelleme
    - update_version ile optimistic locking
    - Büyük dökümanlar için fallback
    """
    collection = get_scans_collection()
    if collection is not None:
        try:
            # Atomik güncelleme - race condition önleme
            updated_doc = collection.find_one_and_update(
                {"scan_id": scan_id},
                {
                    "$set": {
                        f"results.{service}": result,
                        "updated_at": datetime.utcnow()
                    },
                    "$inc": {
                        "update_version": 1  # Optimistic locking counter
                    }
                },
                return_document=True  # Güncellenmiş dökümanı döndür
            )

            if updated_doc is None:
                print(f"⚠️ Scan bulunamadı: {scan_id}")

        except Exception as e:
            error_str = str(e).lower()
            # Türkçe: Document too large hatası için fallback
            if "too large" in error_str or "16793600" in error_str:
                print(f"⚠️ MongoDB döküman boyutu aşıldı, minimal kayıt yapılıyor...")
                try:
                    minimal_result = {
                        "status": result.get("status", "completed"),
                        "findings_count": result.get("findings_count", 0),
                        "severity_counts": result.get("severity_counts", {}),
                        "duration_seconds": result.get("duration_seconds", 0),
                        "note": "Bulgular ayrı koleksiyonda - döküman boyutu limiti aşıldı"
                    }
                    collection.find_one_and_update(
                        {"scan_id": scan_id},
                        {
                            "$set": {
                                f"results.{service}": minimal_result,
                                "updated_at": datetime.utcnow()
                            },
                            "$inc": {"update_version": 1}
                        }
                    )
                    print(f"✅ Minimal kayıt başarılı: {scan_id}")
                except Exception as fallback_err:
                    print(f"❌ Fallback kayıt da başarısız: {fallback_err}")
            else:
                print(f"MongoDB güncelleme hatası: {e}")

def complete_scan_in_db(scan_id: str, status: str = "completed"):
    """Türkçe: Taramayı tamamlandı olarak işaretle ve AI Brain'e öğrenme sinyali gönder"""
    collection = get_scans_collection()
    if collection is not None:
        try:
            scan = collection.find_one({"scan_id": scan_id})
            target = scan.get("target", "unknown") if scan else "unknown"
            
            collection.update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        "status": status,
                        "completed_at": datetime.utcnow()
                    }
                }
            )
            log_activity("scan_completed", scan_id, target, f"Tarama {status} olarak tamamlandı")
            
            # 🧠 AI Brain Öğrenme Tetikleme — DİKKAT: ai-service'te /brain/learn ROUTE'U YOK.
            # Bu tetikleme her tamamlanan tarama başına 404 üretip sessizce yutuluyordu (ölü
            # stub → yanlış "kendini öğrenen brain" izlenimi). GERÇEK öğrenme auto-scan hattında
            # zaten çalışır: exploit_memory / identity_memory doğrulanmış dersleri scan_memories'e
            # yazıp sonraki taramaların prompt'una geri besler. Yanıltıcı iddia üretmemek için bu
            # yol, /brain/learn implemente edilip BRAIN_LEARN_ENABLED=true yapılana dek KAPALIDIR.
            if (os.getenv("BRAIN_LEARN_ENABLED", "false").lower() == "true"
                    and BRAIN_AVAILABLE and trigger_brain_learning
                    and status == "completed" and scan):
                try:
                    asyncio.create_task(trigger_brain_learning(scan_id, target, scan))
                except Exception as brain_err:
                    print(f"⚠️ AI Brain tetikleme hatası (non-critical): {brain_err}")
                    
        except Exception as e:
            print(f"MongoDB tamamlama hatası: {e}")

def log_activity(activity_type: str, scan_id: str, target: str, message: str, severity: str = "info"):
    """Türkçe: Aktivite logunu MongoDB'ye kaydet"""
    collection = get_activities_collection()
    if collection is not None:
        try:
            collection.insert_one({
                "type": activity_type,
                "scan_id": scan_id,
                "target": target,
                "message": message,
                "severity": severity,
                "timestamp": datetime.utcnow()
            })
        except Exception as e:
            print(f"Aktivite log hatası: {e}")

def save_vulnerabilities(scan_id: str, target: str, findings: list):
    """Türkçe: Nuclei zafiyetlerini MongoDB'ye kaydet"""
    collection = get_vulnerabilities_collection()
    if collection is not None and findings:
        try:
            for finding in findings:
                vuln_doc = {
                    "scan_id": scan_id,
                    "target": target,
                    "template_id": finding.get("template-id", "unknown"),
                    "name": finding.get("info", {}).get("name", "Unknown"),
                    "severity": finding.get("info", {}).get("severity", "unknown"),
                    "matched_at": finding.get("matched-at", ""),
                    "description": finding.get("info", {}).get("description", ""),
                    "raw_data": finding,
                    "discovered_at": datetime.utcnow()
                }
                collection.insert_one(vuln_doc)
            
            # Zafiyet bulunduğunda aktivite logla
            critical_count = sum(1 for f in findings if f.get("info", {}).get("severity") == "critical")
            high_count = sum(1 for f in findings if f.get("info", {}).get("severity") == "high")
            
            if critical_count > 0:
                log_activity("vulnerability_found", scan_id, target, 
                           f"{critical_count} kritik zafiyet bulundu!", "critical")
            elif high_count > 0:
                log_activity("vulnerability_found", scan_id, target,
                           f"{high_count} yüksek seviye zafiyet bulundu", "high")
                           
        except Exception as e:
            print(f"Zafiyet kayıt hatası: {e}")

# ============== Request Models ==============

class ScanRequest(BaseModel):
    target: str
    scan_types: List[str]  # ['nmap', 'subfinder', 'rustscan', 'nuclei']
    nmap_options: Optional[dict] = {}
    rustscan_options: Optional[dict] = {}
    nuclei_options: Optional[dict] = {}
    subfinder_options: Optional[dict] = {}
    fuzz_options: Optional[dict] = {}

    @validator('target')
    def validate_target(cls, v):
        # Allow URLs with http/https
        v = v.strip()
        if v.startswith('http://') or v.startswith('https://'):
            # Extract domain from URL for validation
            from urllib.parse import urlparse
            parsed = urlparse(v)
            v_check = parsed.netloc or parsed.path.split('/')[0]
        else:
            v_check = v

        ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

        if not (re.match(ipv4_pattern, v_check) or re.match(domain_pattern, v_check)):
            raise ValueError('Invalid target format. Must be IPv4, Domain, or URL.')

        if any(char in v for char in [';', '&', '|', '`', '$', '(', ')', '<', '>']):
            raise ValueError('Illegal characters detected.')
        # KAPSAM KAPISI: format geçerli olması hedefin YETKİLİ olduğu anlamına gelmez.
        # Dış-kutudan saldırgan-gibi tarayan bu üründe yetki/SSRF kontrolü tarama başlamadan
        # burada zorlanır (yetkisiz erişim + iç-ağ/metadata SSRF engeli).
        from pipeline.scope_guard import enforce_target_scope
        enforce_target_scope(v_check)
        # Şemayı soy: nmap/rustscan/nuclei dispatcher'ları ve profil sweep'i çıplak host ister.
        return v_check

# ============== Scan Dispatch Functions ==============

# ============== Scan Dispatch Functions ==============

SCAN_PRESETS = {
    "stealth": {
        "scan_type": ["-sS"],
        "timing": "-T2",
        "-f": True,
        "--randomize-hosts": True,
        "--data-length": 25,
        "--spoof-mac": "0",
        "--source-port": 53,
        "--max-retries": 2,
        "--host-timeout": "30m",
        "-D": "RND:10"
    },
    "aggressive": {
        "scan_type": ["-sS", "-sV"],
        "timing": "-T4",
        "-A": True,
        "-O": True,
        "--script": "default,vuln,auth",
        "-p-": True,  # Tüm portlar
        "-v": True
    },
    "default": {
        "scan_type": ["-sS", "-sV"],
        "timing": "-T3",
        "--top-ports": 1000,  # 100'den 1000'e çıkarıldı
        "-O": True,           # OS detection eklendi
        "--script": "default,safe",  # Script eklendi
        "-v": True
    },
    # YENİ: PHANTOM için kapsamlı tarama preset'i
    "phantom_comprehensive": {
        "scan_type": ["-sS", "-sV"],
        "timing": "-T3",
        "-O": True,
        "-A": True,
        "--top-ports": 3000,
        "--script": "default,vuln,auth,discovery",
        "--min-rate": 100,
        "--max-rate": 500,
        "-v": True,
        "--reason": True,
        "--version-intensity": 5
    },
    # YENİ: Servis detay preset'i
    "service_detail": {
        "scan_type": ["-sV"],
        "timing": "-T3",
        "--version-intensity": 9,  # Maximum versiyon tespiti
        "--script": "banner,http-headers,ssl-cert",
        "-v": True
    },
    # YENİ: Web uygulaması preset'i
    "web_application": {
        "scan_type": ["-sS", "-sV"],
        "timing": "-T3",
        "-p": "80,443,8080,8443,8000,3000,5000,9000,9443",
        "--script": "http-title,http-headers,http-methods,http-enum,ssl-enum-ciphers",
        "-v": True
    },
    # YENİ: Hızlı ama kapsamlı tarama
    "quick_comprehensive": {
        "scan_type": ["-sS", "-sV"],
        "timing": "-T4",
        "--top-ports": 500,
        "-O": True,
        "--script": "default",
        "-v": True
    }
}

def build_nmap_command_preview(target: str, options: dict) -> str:
    """
    Türkçe: Nmap komut önizlemesi oluşturur (frontend için)
    Gerçek komut nmap-service'de oluşturulur, bu sadece preview
    """
    preset_name = options.get("preset", "default")
    preset = SCAN_PRESETS.get(preset_name, SCAN_PRESETS["default"]).copy()

    # Override with specific options
    for k, v in options.items():
        if k != "preset":
            preset[k] = v

    cmd_parts = ["nmap"]

    # Scan types
    scan_types = preset.get("scan_type", [])
    cmd_parts.extend(scan_types)

    # Common flags
    if preset.get("-sV"):
        cmd_parts.append("-sV")
    if preset.get("-O"):
        cmd_parts.append("-O")
    if preset.get("-A"):
        cmd_parts.append("-A")

    # Timing
    timing = preset.get("timing", "-T3")
    cmd_parts.append(timing)

    # Ports
    if preset.get("-p"):
        cmd_parts.extend(["-p", str(preset["-p"])])
    elif preset.get("-F"):
        cmd_parts.append("-F")
    elif preset.get("--top-ports"):
        cmd_parts.extend(["--top-ports", str(preset["--top-ports"])])

    # Scripts
    if preset.get("--script"):
        cmd_parts.extend(["--script", preset["--script"]])

    cmd_parts.append(target)
    return " ".join(cmd_parts)


def estimate_scan_duration(scan_types: list, options: dict) -> dict:
    """
    Türkçe: Tahmini tarama süresini hesaplar
    """
    estimates = {
        "nmap": {"min": 30, "max": 300, "unit": "seconds"},
        "nuclei": {"min": 60, "max": 600, "unit": "seconds"},
        "subfinder": {"min": 10, "max": 60, "unit": "seconds"},
        "rustscan": {"min": 10, "max": 120, "unit": "seconds"},
        "fuzz": {"min": 60, "max": 300, "unit": "seconds"}
    }

    total_min = 0
    total_max = 0

    for st in scan_types:
        est = estimates.get(st, {"min": 30, "max": 180})
        total_min += est["min"]
        total_max += est["max"]

    # Preset'e göre ayarla
    preset = options.get("preset", "default") if options else "default"
    if preset == "aggressive":
        total_max *= 2
    elif preset == "phantom_comprehensive":
        total_max *= 1.5
    elif preset == "stealth":
        total_max *= 3  # Stealth daha yavaş

    return {
        "min_seconds": int(total_min),
        "max_seconds": int(total_max),
        "formatted": f"{int(total_min/60)}-{int(total_max/60)} dakika"
    }


def check_scan_completion(scan_id: str):
    """Türkçe: Taramanın tamamen bitip bitmediğini kontrol eder (MongoDB)"""
    collection = get_scans_collection()
    if collection is None:
        return

    try:
        scan = collection.find_one({"scan_id": scan_id})
        if not scan:
            return

        scan_types = scan.get("scan_types", [])
        results = scan.get("results", {})
        
        all_completed = True
        for scan_type in scan_types:
            # Check if result exists and status is strictly completed or failed
            # If not present or running/pending, then not completed
            scan_result = results.get(scan_type, {})
            status = scan_result.get("status", "pending")
            
            if status not in ["completed", "failed"]:
                all_completed = False
                break
        
        if all_completed and scan.get("status") == "running":
            # MongoDB'de de güncelle
            complete_scan_in_db(scan_id, "completed")

    except Exception as e:
        print(f"Completion check error: {e}")


async def dispatch_subfinder(scan_id: str, target: str, options: dict = {}):
    """
    Türkçe: Subfinder dispatch wrapper - completion check dahil
    subfinder_proxy.py'dan import edilen fonksiyonu sararak
    tarama tamamlandığında check_scan_completion çağrısı yapar.
    """
    try:
        await _dispatch_subfinder_raw(scan_id, target, options)
    finally:
        check_scan_completion(scan_id)

async def dispatch_nmap(scan_id: str, target: str, options: dict = {}):
    """Türkçe: Nmap servisine tarama isteği gönderir"""
    try:
        # Merge preset options
        preset_name = options.get("preset", "default")
        final_options = SCAN_PRESETS.get(preset_name, SCAN_PRESETS["default"]).copy()

        # Override with specific options if any (excluding 'preset' key)
        for k, v in options.items():
            if k != "preset":
                final_options[k] = v

        # Komut preview oluştur ve event emit et
        command_preview = build_nmap_command_preview(target, final_options)
        await emit_command_executing(scan_id, "nmap", command_preview)

        # Update status to running in MongoDB
        update_scan_result(scan_id, "nmap", {"status": "running", "command": command_preview})
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{NMAP_SERVICE_URL}/scan",
                json={"target": target, "scan_id": scan_id, "options": final_options},
                timeout=1800.0
            )
            result = response.json()

            # MongoDB'ye kaydet
            update_scan_result(scan_id, "nmap", result)
    except Exception as e:
        error_result = {"error": str(e), "status": "failed"}

        update_scan_result(scan_id, "nmap", error_result)
    finally:
        check_scan_completion(scan_id)


async def dispatch_rustscan(scan_id: str, target: str, options: dict = {}):
    """Türkçe: RustScan servisine tarama isteği gönderir ve sonuçları polleyerek takip eder"""
    try:
        # Update status to running in MongoDB
        update_scan_result(scan_id, "rustscan", {"status": "running", "started_at": datetime.utcnow().isoformat()})

        async with httpx.AsyncClient() as client:
            # Türkçe: Taramayı başlat
            response = await client.post(
                f"{RUSTSCAN_SERVICE_URL}/scan",
                json={"target": target, "scan_id": scan_id, "options": options},
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise Exception(f"RustScan başlatılamadı: {response.text}")
            
            start_result = response.json()
            print(f"✅ RustScan başlatıldı: {scan_id} -> {target}")
            
            # Türkçe: MongoDB'den RustScanActiveScans koleksiyonunu polleyerek sonuçları takip et
            db_scans = db["RustScanActiveScans"] if db is not None else None
            if db_scans is None:
                # Fallback: Sadece başlatma sonucunu kaydet
                update_scan_result(scan_id, "rustscan", start_result)
                return
            
            # Türkçe: Polling döngüsü (maksimum 10 dakika)
            MAX_WAIT_SECONDS = 600
            POLL_INTERVAL = 3
            start_time = datetime.utcnow()
            
            while True:
                await asyncio.sleep(POLL_INTERVAL)
                
                # Türkçe: Timeout kontrolü
                elapsed = (datetime.utcnow() - start_time).total_seconds()
                if elapsed > MAX_WAIT_SECONDS:
                    print(f"⏰ RustScan timeout: {scan_id}")
                    update_scan_result(scan_id, "rustscan", {
                        "status": "timeout",
                        "message": f"Tarama {MAX_WAIT_SECONDS // 60} dakika sonra timeout oldu"
                    })
                    break
                
                # Türkçe: RustScanActiveScans koleksiyonunu kontrol et
                rustscan_doc = db_scans.find_one({"scan_id": scan_id})
                if not rustscan_doc:
                    continue
                
                status = rustscan_doc.get("status")
                
                if status == "completed":
                    # Türkçe: Tarama tamamlandı, sonuçları al
                    result = {
                        "status": "completed",
                        "open_ports": rustscan_doc.get("open_ports", []),
                        "open_ports_count": rustscan_doc.get("open_ports_count", 0),
                        "services": rustscan_doc.get("services", []),
                        "raw_output": rustscan_doc.get("raw_output", "")[:5000],  # İlk 5000 karakter
                        "completed_at": datetime.utcnow().isoformat()
                    }
                    update_scan_result(scan_id, "rustscan", result)
                    
                    ports = result.get("open_ports", [])
                    log_activity("scan_completed", scan_id, target, 
                               f"RustScan tamamlandı - {len(ports)} açık port: {', '.join(map(str, ports[:10]))}")
                    print(f"✅ RustScan tamamlandı: {scan_id} - {len(ports)} port")
                    break
                    
                elif status == "failed":
                    error_msg = rustscan_doc.get("error", "Bilinmeyen hata")
                    update_scan_result(scan_id, "rustscan", {"status": "failed", "error": error_msg})
                    log_activity("scan_failed", scan_id, target, f"RustScan hata: {error_msg}", "error")
                    print(f"❌ RustScan hata: {scan_id} - {error_msg}")
                    break
                    
                elif status == "stopped":
                    update_scan_result(scan_id, "rustscan", {"status": "stopped", "message": "Tarama durduruldu"})
                    break
                    
                # Türkçe: Hala çalışıyor, heartbeat gönder
                if int(elapsed) % 30 == 0:
                    update_scan_result(scan_id, "rustscan", {
                        "status": "running",
                        "heartbeat": datetime.utcnow().isoformat()
                    })
                    
    except Exception as e:
        print(f"❌ RustScan dispatch hatası: {e}")
        error_result = {"error": str(e), "status": "failed"}
        update_scan_result(scan_id, "rustscan", error_result)
    finally:
        check_scan_completion(scan_id)

async def dispatch_fuzz(scan_id: str, target: str, options: dict = {}):
    """Türkçe: Fuzzing servisine tarama isteği gönderir ve durumu takip eder"""
    try:
        # Update status to running in MongoDB
        update_scan_result(scan_id, "fuzz", {"status": "running", "started_at": datetime.utcnow().isoformat()})
        
        async with httpx.AsyncClient() as client:
            # Start Scan
            response = await client.post(
                f"{FUZZ_SERVICE_URL}/scan",
                json={
                    "target": target,
                    "scan_id": scan_id,
                    "wordlist": options.get("wordlist", "common.txt"),
                    "smart_seeding": options.get("smart_seeding", False),
                    "options": options
                },
                timeout=10.0
            )
            
            if response.status_code != 200:
                 raise Exception(f"Fuzz Service Error: {response.text}")
            
            # Poll for completion
            # Fuzz service updates FuzzActiveScans collection. 
            # We can poll FuzzActiveScans via pymongo since we have DB access here!
            # Much more efficient than HTTP polling.
            
            db_scans = db["FuzzActiveScans"] if db is not None else None
            if not db_scans:
                 return # Should not happen

            while True:
                await asyncio.sleep(5)
                fuzz_scan = db_scans.find_one({"scan_id": scan_id})
                if not fuzz_scan:
                    # Maybe didn't start yet or deleted?
                    # Check timeout
                    continue
                
                status = fuzz_scan.get("status")
                if status == "completed":
                    timestamp = datetime.utcnow()
                    # Calculate stats from FuzzLogs
                    log_count = db["FuzzLogs"].count_documents({"scan_id": scan_id, "type": "finding"})
                    
                    result = {
                        "status": "completed",
                        "findings_count": log_count,
                        "completed_at": timestamp.isoformat()
                    }
                    update_scan_result(scan_id, "fuzz", result)
                    log_activity("scan_completed", scan_id, target, f"Fuzzing tamamlandı: {log_count} bulgu")
                    break
                elif status == "failed":
                    error_msg = fuzz_scan.get("error", "Unknown error")
                    update_scan_result(scan_id, "fuzz", {"status": "failed", "error": error_msg})
                    log_activity("scan_failed", scan_id, target, f"Fuzzing hata: {error_msg}", "error")
                    break
                
                # Update heartbeat just to show it's alive
                update_scan_result(scan_id, "fuzz", {"status": "running", "last_check": datetime.utcnow().isoformat()})

    except Exception as e:
        error_result = {"error": str(e), "status": "failed"}
        update_scan_result(scan_id, "fuzz", error_result)
        print(f"Fuzz Dispatch Error: {e}")
    finally:
        check_scan_completion(scan_id)

async def dispatch_nuclei(scan_id: str, target: str, options: dict = {}):
    """
    Türkçe: Nuclei servisine zafiyet tarama isteği gönderir
    
    Özellikler:
    - Akıllı timeout (varsayılan 2 saat, progress geldikçe reset)
    - Heartbeat mekanizması (MongoDB'ye düzenli güncelleme)
    - Graceful cleanup (timeout olursa taramayı durdur)
    """
    # Türkçe: Timeout konfigürasyonu (saniye cinsinden)
    MAX_TIMEOUT_SECONDS = options.get("max_timeout", 7200)  # Varsayılan: 2 saat
    POLL_INTERVAL = 2  # Saniye
    HEARTBEAT_INTERVAL = 50  # Her 50 iterasyonda bir heartbeat
    NO_PROGRESS_TIMEOUT = 300  # 5 dakika progress gelmezse endişelen
    
    try:
        # Nuclei konfigürasyonu
        nuclei_config = {
            "target": target,
            "scan_id": scan_id,
            "severity": options.get("severity", ["critical", "high"]),
            "tags": options.get("tags", []),
            "templates": options.get("templates", []),
            "rate_limit": options.get("rate_limit", 300), 
            "timeout": options.get("timeout", 3), 
            "retries": options.get("retries", 1),
            "bulk_size": 25,
            "concurrency": 25,
            "exclude_tags": options.get("exclude_tags", ["dos", "fuzz"]),
            "profile": options.get("profile", "balanced")
        }

        # Türkçe: MongoDB'de status='running' olarak güncelle
        update_scan_result(scan_id, "nuclei", {"status": "running", "started_at": datetime.utcnow().isoformat()})
        
        async with httpx.AsyncClient() as client:
            # Türkçe: Taramayı başlat
            response = await client.post(
                f"{NUCLEI_SERVICE_URL}/scan",
                json=nuclei_config,
                timeout=30.0
            )
            start_result = response.json()
            
            if response.status_code != 200:
                raise Exception(f"Nuclei scan başlatılamadı: {start_result}")
            
            print(f"✅ Nuclei scan başlatıldı: {scan_id}")
            
            # Türkçe: Polling değişkenleri
            start_time = datetime.utcnow()
            last_progress_time = datetime.utcnow()
            iteration_count = 0
            last_matched_count = 0
            
            # Türkçe: Polling döngüsü (akıllı timeout ile)
            while True:
                await asyncio.sleep(POLL_INTERVAL)
                iteration_count += 1
                
                # Türkçe: Toplam süre kontrolü
                elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
                
                if elapsed_seconds > MAX_TIMEOUT_SECONDS:
                    print(f"⏰ Nuclei scan timeout ({MAX_TIMEOUT_SECONDS}s): {scan_id}")
                    
                    # Türkçe: Taramayı durdur
                    try:
                        await client.delete(f"{NUCLEI_SERVICE_URL}/scan/{scan_id}", timeout=10.0)
                    except Exception as stop_err:
                        print(f"⚠️ Scan durdurma hatası: {stop_err}")
                    
                    # Türkçe: MongoDB'ye timeout olarak kaydet
                    update_scan_result(scan_id, "nuclei", {
                        "status": "timeout",
                        "message": f"Tarama {MAX_TIMEOUT_SECONDS // 60} dakika sonra timeout oldu",
                        "elapsed_seconds": elapsed_seconds
                    })
                    log_activity("scan_timeout", scan_id, target, 
                               f"Nuclei tarama timeout - {elapsed_seconds:.0f} saniye", "warning")
                    break
                
                # Türkçe: Heartbeat - Her 50 iterasyonda MongoDB'yi güncelle
                if iteration_count % HEARTBEAT_INTERVAL == 0:
                    update_scan_result(scan_id, "nuclei", {
                        "status": "running",
                        "heartbeat": datetime.utcnow().isoformat(),
                        "elapsed_seconds": elapsed_seconds
                    })
                
                try:
                    status_res = await client.get(f"{NUCLEI_SERVICE_URL}/status/{scan_id}", timeout=10.0)
                    status_data = status_res.json()
                    current_status = status_data.get("status")
                    
                    # Türkçe: Progress geliyorsa timeout sayacını resetle
                    # (Nuclei aktif çalışıyor demektir)
                    if current_status == "running":
                        last_progress_time = datetime.utcnow()
                    
                    if current_status == "completed":
                        # Türkçe: Tarama tamamlandı, sonuçları al
                        print(f"✅ Nuclei scan tamamlandı: {scan_id} ({elapsed_seconds:.0f}s)")
                        
                        log_res = await client.get(f"{NUCLEI_SERVICE_URL}/logs/{scan_id}", timeout=120.0)
                        if log_res.status_code == 200:
                            log_data = log_res.json()
                            
                            # Türkçe: nuclei-service artık FP filtrelemesi yapıyor, direkt kullan
                            findings = log_data.get("findings", [])
                            severity_counts = log_data.get("severity_counts", {})
                            raw_count = log_data.get("raw_findings_count", len(findings))
                            filtered_count = log_data.get("filtered_count", 0)
                            
                            print(f"📊 Nuclei sonuçları: {len(findings)} bulgu (Filtrelenen: {filtered_count})")
                            
                            # Türkçe: MongoDB 16MB limit için sadece özet kaydet
                            MAX_FINDINGS_IN_DOC = 50
                            
                            # Severity'ye göre sırala (critical > high > medium > low > info)
                            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                            findings.sort(key=lambda x: severity_order.get(x.get("info", {}).get("severity", "info"), 5))
                            
                            final_result = {
                                "scan_id": scan_id,
                                "status": "completed",
                                "findings_summary": findings[:MAX_FINDINGS_IN_DOC],  # Sadece en önemli 50
                                "findings_count": len(findings),
                                "raw_findings_count": raw_count,
                                "filtered_fp_count": filtered_count,
                                "severity_counts": severity_counts,
                                "duration_seconds": elapsed_seconds
                            }
                            update_scan_result(scan_id, "nuclei", final_result)
                            
                            # Türkçe: Tüm zafiyetleri ayrı collection'a kaydet
                            if findings:
                                save_vulnerabilities(scan_id, target, findings)
                                
                                # Severity'ye göre log mesajı
                                crit = severity_counts.get("critical", 0)
                                high = severity_counts.get("high", 0)
                                if crit > 0:
                                    log_activity("scan_completed", scan_id, target,
                                               f"Nuclei tarama tamamlandı - {crit} kritik, {high} yüksek seviye bulgu!", "critical")
                                elif high > 0:
                                    log_activity("scan_completed", scan_id, target,
                                               f"Nuclei tarama tamamlandı - {high} yüksek seviye bulgu", "high")
                                else:
                                    log_activity("scan_completed", scan_id, target,
                                               f"Nuclei tarama tamamlandı - {len(findings)} bulgu", "info")
                        else:
                            update_scan_result(scan_id, "nuclei", {
                                "status": "completed", 
                                "message": "Log dosyası bulunamadı",
                                "duration_seconds": elapsed_seconds
                            })
                        break
                        
                    elif current_status == "failed":
                        error_msg = status_data.get("error", "Bilinmeyen hata")
                        print(f"❌ Nuclei scan hata: {scan_id} - {error_msg}")
                        
                        update_scan_result(scan_id, "nuclei", {
                            "status": "failed",
                            "error": error_msg,
                            "duration_seconds": elapsed_seconds
                        })
                        log_activity("scan_failed", scan_id, target, f"Nuclei hata: {error_msg}", "error")
                        break

                    elif current_status == "not_found":
                        # Türkçe: Process kaybolmuş
                        update_scan_result(scan_id, "nuclei", {
                            "status": "failed", 
                            "message": "Tarama process'i bulunamadı"
                        })
                        break
                        
                except httpx.TimeoutException:
                    # Türkçe: Status isteği timeout, devam et
                    print(f"⚠️ Status isteği timeout, devam ediliyor: {scan_id}")
                    continue
                    
                except Exception as poll_err:
                    print(f"⚠️ Polling hatası: {poll_err}")
                    # Türkçe: Birkaç hata tolere et, çok fazla olursa çık
                    if iteration_count > 10 and (datetime.utcnow() - last_progress_time).total_seconds() > NO_PROGRESS_TIMEOUT:
                        print(f"❌ Uzun süre progress gelmedi, tarama durduruluyor: {scan_id}")
                        update_scan_result(scan_id, "nuclei", {
                            "status": "failed",
                            "error": "Taramadan yanıt alınamadı"
                        })
                        break
                    await asyncio.sleep(3)
                    continue
                    
    except Exception as e:
        print(f"❌ Nuclei dispatch hatası: {e}")
        error_result = {"error": str(e), "status": "failed"}
        update_scan_result(scan_id, "nuclei", error_result)
        log_activity("scan_error", scan_id, target, f"Dispatch hatası: {str(e)}", "error")
    finally:
        check_scan_completion(scan_id)


# ============== Tarama Yönetim Endpoint'leri (Force Delete/Cancel) ==============

@app.delete("/scan/{scan_id}")
async def force_delete_scan(scan_id: str):
    """
    Türkçe: Taramayı zorla sil. Çalışıyorsa önce motoru durdurur, sonra session +
    türev verileri (artifacts/llm-logs/vulnerabilities) tek kaynaktan temizler.
    """
    # ÖNCE otonom v2: çalışıyorsa motoru durdurur, session + türev veriyi temizler.
    target = "unknown"
    v2_scan = pipeline_v2.get_scan_v1(scan_id)
    if v2_scan:
        target = v2_scan.get("target", "unknown")
    deleted = await pipeline_v2.delete_scan(scan_id)

    # Manuel v1 tarama: eski `scans` koleksiyonundan sil (+ ilişkili zafiyetler).
    scans_col = get_scans_collection()
    if scans_col is not None:
        doc = scans_col.find_one({"scan_id": scan_id}, {"_id": 0, "target": 1})
        if doc:
            target = doc.get("target", target)
            scans_col.delete_one({"scan_id": scan_id})
            vulns_col = get_vulnerabilities_collection()
            if vulns_col is not None:
                vulns_col.delete_many({"scan_id": scan_id})
            deleted = True

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")

    # Türkçe: Aktivite logla
    activities_col = get_activities_collection()
    if activities_col is not None:
        activities_col.insert_one({
            "type": "scan_deleted",
            "scan_id": scan_id,
            "target": target,
            "message": "Tarama zorla silindi",
            "severity": "warning",
            "timestamp": datetime.utcnow()
        })

    print(f"🗑️ Tarama silindi: {scan_id} ({target})")
    return {"status": "deleted", "scan_id": scan_id, "target": target}


@app.post("/scan/{scan_id}/cancel")
async def force_cancel_scan(scan_id: str):
    """
    Türkçe: Çalışan taramayı iptal et (silmeden). MOTORU gerçekten durdurur ve
    session durumunu 'cancelled' yapar (TEK kaynak v2_scan_sessions).
    """
    scan = pipeline_v2.get_scan_v1(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")
    target = scan.get("target", "unknown")

    cancelled_services = []
    # Çalışan otonom motoru durdur (cancel bayrağı + stage servisleri). Bu, session'ı da
    # 'cancelled' yazar. Motor zaten bitmişse (aktif değil) yalnız kaydı işaretleriz.
    engine_cancelled = await pipeline_v2.cancel_pipeline_by_scan_id(scan_id)
    if engine_cancelled:
        cancelled_services.append("autonomous")
    else:
        # Aktif motor yoktu (ör. process restart sonrası): session'ı yine de 'cancelled'a çek
        # ama TERMINAL durumları (completed/failed/cancelled) EZME.
        sessions_col = db["v2_scan_sessions"] if db is not None else None
        if sessions_col is not None:
            sessions_col.update_one(
                {"scan_id": scan_id, "status": {"$in": ["running", "pending", "awaiting_approval"]}},
                {"$set": {"status": "cancelled", "completed_at": datetime.utcnow().isoformat(),
                          "cancel_reason": "Kullanıcı tarafından iptal edildi"}},
            )

    # Türkçe: Aktivite logla
    activities_col = get_activities_collection()
    if activities_col is not None:
        activities_col.insert_one({
            "type": "scan_cancelled",
            "scan_id": scan_id,
            "target": target,
            "message": f"Tarama kullanıcı tarafından iptal edildi",
            "severity": "info",
            "timestamp": datetime.utcnow()
        })
    
    print(f"⛔ Tarama iptal edildi: {scan_id} ({target})")
    
    return {
        "status": "cancelled",
        "scan_id": scan_id,
        "target": target,
        "cancelled_services": cancelled_services
    }


@app.post("/scans/cleanup-stale")
async def cleanup_stale_scans():
    """
    Türkçe: Takılı (30 dk+ 'running'/'pending') taramaları 'stale' işaretle.

    İKİ kaynağı da tarar (tek tutarlı davranış):
      • Otonom v2: v2_scan_sessions — motor süreci çöktüyse session 'running' takılı kalabilir.
      • Manuel v1: eski `scans` — servis takılırsa aynı şekilde asılı kalır.
    Artık ayna YOK, dolayısıyla eski 'uzlaştırma' adımı da yok — split-brain kalktı.
    """
    STALE_AFTER = 1800  # 30 dakika
    now = datetime.utcnow()

    def _elapsed_seconds(created) -> Optional[float]:
        """created_at datetime (scans) ya da isoformat string (sessions) olabilir."""
        if not created:
            return None
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created)
            except ValueError:
                return None
        try:
            return (now - created).total_seconds()
        except TypeError:
            return None

    cleaned_count = 0
    cleaned_scans = []

    for col, id_field in (
        (get_scans_collection(), "scan_id"),
        (get_sessions_collection(), "scan_id"),
    ):
        if col is None:
            continue
        for scan in col.find({"status": {"$in": ["running", "pending"]}}):
            elapsed = _elapsed_seconds(scan.get("created_at"))
            if elapsed is None or elapsed <= STALE_AFTER:
                continue
            sid = scan.get(id_field)
            col.update_one(
                {id_field: sid},
                {"$set": {
                    "status": "stale",
                    "stale_reason": f"Cleanup ile temizlendi ({elapsed/60:.0f} dk)",
                    "marked_stale_at": now,
                }},
            )
            cleaned_count += 1
            cleaned_scans.append({"scan_id": sid, "target": scan.get("target", "unknown")})

    print(f"🧹 Manuel cleanup: {cleaned_count} takılı tarama 'stale' işaretlendi")
    return {
        "status": "completed",
        "cleaned_count": cleaned_count,
        "cleaned_scans": cleaned_scans,
    }


# ============== API Endpoints ==============


@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())

    # Önce taramayı MongoDB'ye kaydet (KRITIK: Bu olmadan scan bulunamaz!)
    save_scan_to_db(scan_id, request.target, request.scan_types)

    # Initialize component statuses as pending in MongoDB
    for scan_type in request.scan_types:
         update_scan_result(scan_id, scan_type, {"status": "pending"})

    # YENİ: Tarama başladı olayını yayınla
    nmap_preview = build_nmap_command_preview(request.target, request.nmap_options or {}) if "nmap" in request.scan_types else None
    asyncio.create_task(emit_scan_started(scan_id, request.target, request.scan_types, nmap_preview))

    # Dispatch Background Tasks
    if "nmap" in request.scan_types:
        background_tasks.add_task(dispatch_nmap, scan_id, request.target, request.nmap_options)
        
    if "subfinder" in request.scan_types:
        background_tasks.add_task(dispatch_subfinder, scan_id, request.target, request.subfinder_options)

    if "rustscan" in request.scan_types:
        background_tasks.add_task(dispatch_rustscan, scan_id, request.target, request.rustscan_options)

    if "nuclei" in request.scan_types:
        background_tasks.add_task(dispatch_nuclei, scan_id, request.target, request.nuclei_options)

    if "fuzz" in request.scan_types:
        background_tasks.add_task(dispatch_fuzz, scan_id, request.target, request.fuzz_options)

    # Türkçe: Zenginleştirilmiş response - komut ve config bilgisi ile
    response = {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan queued in background",
        "scan_config": {
            "target": request.target,
            "scan_types": request.scan_types,
            "estimated_duration": estimate_scan_duration(request.scan_types, request.nmap_options)
        }
    }

    # Nmap varsa komut preview ekle
    if "nmap" in request.scan_types:
        response["scan_config"]["nmap_command_preview"] = build_nmap_command_preview(
            request.target,
            request.nmap_options or {}
        )
        response["scan_config"]["nmap_preset"] = request.nmap_options.get("preset", "default") if request.nmap_options else "default"

    # Nuclei varsa severity bilgisi ekle
    if "nuclei" in request.scan_types:
        nuclei_opts = request.nuclei_options or {}
        response["scan_config"]["nuclei_severity"] = nuclei_opts.get("severity", ["critical", "high"])
        response["scan_config"]["nuclei_profile"] = nuclei_opts.get("profile", "balanced")

    return response

@app.get("/stats")
async def get_stats():
    """Türkçe: Dashboard istatistiklerini döner (MongoDB + Redis)"""
    stats = {
        "total_scans": 0,
        "active_scans": 0,
        "completed_scans": 0,
        "failed_scans": 0,
        "vulnerabilities_found": 0,
        "recent_activities": [],
        "services_health": {},
        "daily_stats": []
    }
    
    # MongoDB'den toplam istatistikler
    scans_col = get_scans_collection()
    vulns_col = get_vulnerabilities_collection()
    activities_col = get_activities_collection()
    
    if scans_col is not None:
        try:
            stats["total_scans"] = scans_col.count_documents({})
            stats["completed_scans"] = scans_col.count_documents({"status": "completed"})
            stats["failed_scans"] = scans_col.count_documents({"status": "failed"})
        except Exception as e:
            print(f"MongoDB stats hatası: {e}")
    
    # MongoDB'den aktif taramalar
    if scans_col is not None:
        try:
            stats["active_scans"] = scans_col.count_documents({"status": "running"})
        except Exception as e:
            print(f"Active scan count error: {e}")
    
    # MongoDB'den zafiyet sayısı
    if vulns_col is not None:
        try:
            stats["vulnerabilities_found"] = vulns_col.count_documents({})
        except Exception as e:
            print(f"Vuln count hatası: {e}")
    
    # Son aktiviteler
    if activities_col is not None:
        try:
            recent = activities_col.find().sort("timestamp", -1).limit(10)
            for act in recent:
                stats["recent_activities"].append({
                    "type": act.get("type"),
                    "target": act.get("target"),
                    "message": act.get("message"),
                    "severity": act.get("severity", "info"),
                    "timestamp": act.get("timestamp").isoformat() if act.get("timestamp") else None
                })
        except Exception as e:
            print(f"Activities hatası: {e}")
    
    # Servis sağlık kontrolleri
    services = [
        ("nmap", NMAP_SERVICE_URL),
        ("subfinder", SUBFINDER_SERVICE_URL),
        ("rustscan", RUSTSCAN_SERVICE_URL),
        ("nuclei", NUCLEI_SERVICE_URL),
        ("osint", OSINT_SERVICE_URL),
        ("hash_cracker", HASH_CRACKER_SERVICE_URL)
    ]
    
    async with httpx.AsyncClient(timeout=2.0) as client:
        for name, url in services:
            try:
                start = datetime.now()
                # Basit bir health check
                if name in ["nmap", "nuclei"]:
                    endpoint = f"{url}/config"
                elif name == "hash_cracker":
                    endpoint = f"{url}/health"
                else:
                    endpoint = url
                await client.get(endpoint, timeout=2.0)
                latency = (datetime.now() - start).total_seconds() * 1000
                stats["services_health"][name] = {
                    "status": "healthy",
                    "latency_ms": round(latency, 2)
                }
            except Exception as e:
                stats["services_health"][name] = {
                    "status": "unhealthy",
                    "error": str(e)[:50]
                }
    
    # OSINT ve diğer servisler
    stats["services_health"]["mongodb"] = {
        "status": "healthy" if db is not None else "unhealthy"
    }
    
    return stats

@app.get("/scan/{scan_id}")
async def get_scan_results(scan_id: str):
    """Türkçe: Tek tarama detayı. ÖNCE otonom v2 session, yoksa manuel v1 `scans` kaydı.
    Böylece hem Kuşatma otonom hem Manuel Tarama sonuçları aynı endpoint'ten okunur."""
    scan = pipeline_v2.get_scan_v1(scan_id)
    if scan:
        return scan

    # Manuel v1 tarama (scan.tsx → /api/scan): eski `scans` koleksiyonundan oku.
    scans_col = get_scans_collection()
    if scans_col is not None:
        doc = scans_col.find_one({"scan_id": scan_id}, {"_id": 0})
        if doc:
            return {
                "scan_id": scan_id,
                "target": doc.get("target"),
                "status": doc.get("status"),
                "created_at": doc.get("created_at").isoformat() if hasattr(doc.get("created_at"), "isoformat") else doc.get("created_at"),
                "completed_at": doc.get("completed_at").isoformat() if hasattr(doc.get("completed_at"), "isoformat") else doc.get("completed_at"),
                "results": doc.get("results", {}),
            }

    raise HTTPException(status_code=404, detail="Scan not found")

@app.websocket("/scan/stream/{scan_id}")
async def stream_scan(websocket: WebSocket, scan_id: str):
    """Türkçe: Real-time nmap tarama çıktısını stream eder"""
    await websocket.accept()
    data = await websocket.receive_json()
    
    target = data.get("target")
    options = data.get("options", {})
    
    await proxy_nmap_stream(websocket, scan_id, target, options)

@app.websocket("/scan/monitor/{scan_id}")
async def monitor_scan(websocket: WebSocket, scan_id: str):
    """Türkçe: Devam eden bir taramayı izler"""
    await websocket.accept()
    await proxy_nmap_monitor(websocket, scan_id)

@app.websocket("/scan/raw/{scan_id}")
async def raw_log_stream(websocket: WebSocket, scan_id: str):
    """Türkçe: Çalışan tüm araçların (nmap + nuclei) ham loglarını tek WebSocket'te birleştirir.
    Otonom tarama sonuçları sayfasındaki 'Canlı Ham Log' görünümü bunu kullanır."""
    await proxy_raw_log_stream(websocket, scan_id)

@app.get("/active-scans")
async def get_all_active_scans():
    """Türkçe: Aktif (çalışan/onay bekleyen) taramaları döner.

    İKİ KAYNAK birleştirilir, tek tutarlı liste olur:
      • Otonom (Kuşatma v2): v2_scan_sessions — TEK gerçek, artık ayna yok.
      • Manuel tarama: eski `scans` koleksiyonu (scan.tsx hâlâ buraya yazar).
    scan_id'ye göre dedup edilir ve v2 session'ı önceliklidir (eski otonom taramalar
    bir zamanlar `scans`'a da yazıldığından çift görünmesini önler)."""
    v2 = pipeline_v2.active_scans_v1().get("active_scans", [])
    merged = {s["scan_id"]: s for s in v2 if s.get("scan_id")}

    # Manuel v1 taramalar (yalnız v2'de OLMAYAN scan_id'ler eklenir → v2 önceliği korunur)
    scans_col = get_scans_collection()
    if scans_col is not None:
        try:
            for scan in scans_col.find({"status": "running"}):
                sid = scan.get("scan_id")
                if not sid or sid in merged:
                    continue
                created = scan.get("created_at")
                merged[sid] = {
                    "scan_id": sid,
                    "target": scan.get("target", "unknown"),
                    "scan_types": scan.get("scan_types", []),
                    "status": "running",
                    "created_at": created.isoformat() if hasattr(created, "isoformat") else created,
                }
        except Exception as e:
            print(f"MongoDB active scan (manuel) error: {e}")

    active = sorted(merged.values(), key=lambda s: s.get("created_at") or "", reverse=True)
    return {"active_scans": active, "count": len(active)}

# ============== YENİ: Event Stream WebSocket ==============

@app.websocket("/scan/events/{scan_id}")
async def scan_event_stream(websocket: WebSocket, scan_id: str):
    """
    Türkçe: Real-time tarama olayları stream'i

    Tüm tarama olaylarını (port bulundu, zafiyet tespit edildi, faz değişti vb.)
    anlık olarak frontend'e iletir.

    Kullanım (Frontend):
        const ws = new WebSocket(`ws://host/scan/events/${scanId}`);
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log(data.event_type, data.data);
        };
    """
    await websocket.accept()

    # Scan'in var olduğunu kontrol et — önce v1 `scans`, bulamazsa v2 `v2_scan_sessions`.
    # NEDEN v2 fallback: Otonom (Kuşatma Doktrini) taramaların TEK kaydı v2_scan_sessions'tır
    # (eski `scans` aynası kaldırıldı). Burada yalnız v1'e bakmak otonom scan_id'lerini
    # "Scan not found" diye reddedip WS'i anında kapatıyordu → frontend "bağlanılamadı"
    # deyip hiç olay alamıyordu, motor arka planda sağlıklı çalıştığı halde.
    scans_col = get_scans_collection()
    sessions_col = get_sessions_collection()
    scan = scans_col.find_one({"scan_id": scan_id}) if scans_col is not None else None
    is_v2_session = False
    if not scan and sessions_col is not None:
        scan = sessions_col.find_one({"scan_id": scan_id})
        is_v2_session = scan is not None
    # DB erişimi varken iki koleksiyonda da yoksa gerçekten bulunamadı demektir
    if not scan and (scans_col is not None or sessions_col is not None):
        await websocket.send_json({
            "type": "error",
            "message": f"Scan not found: {scan_id}"
        })
        await websocket.close()
        return

    # Event bus'a subscribe ol
    queue = await ScanEventBus.subscribe(scan_id)

    try:
        # İlk olarak mevcut durumu gönder (v1 doc veya v2 session — alan adları ortak)
        if scan:
            created_at = scan.get("created_at")
            await websocket.send_json({
                "type": "initial_state",
                "scan_id": scan_id,
                "target": scan.get("target"),
                "status": scan.get("status"),
                # v2 session'da scan_types alanı yoktur; stage araçlarından türetilir
                "scan_types": scan.get("scan_types") or (
                    list(dict.fromkeys(
                        st["tool"] for st in (scan.get("stages") or {}).values()
                        if isinstance(st, dict) and st.get("tool")
                    )) or ["autonomous"]
                ) if is_v2_session else scan.get("scan_types", []),
                "results": scan.get("results", {}),
                # v1 datetime objesi saklar, v2 session isoformat string — ikisi de desteklenir
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else created_at
            })

        # Geçmiş olayları gönder (varsa)
        history = ScanEventBus.get_history(scan_id, limit=20)
        if history:
            await websocket.send_json({
                "type": "event_history",
                "events": history
            })
            # DÜRÜST-BİTİŞ: history'de terminal olay (completed/failed) varsa tarama çoktan
            # bitmiş demektir — cleanup_scan bağlanmadan ÖNCE çağrıldığı için canlı kuyruğa
            # stream_ended sentinel'i ASLA gelmez → eski kod bu bağlantıyı sonsuza dek
            # heartbeat'le açık tutuyordu (sunucu tarafı sızıntı + client'ta sahte CANLI
            # rozeti). Terminal durumu replay ile işlettikten sonra kibarca kapat.
            terminal_seen = any(
                e.get("event_type") in ("scan_completed", "scan_failed") for e in history
            )
            if terminal_seen:
                await websocket.send_json({
                    "type": "stream_ended",
                    "message": "Scan already finished (history replay)"
                })
                await websocket.close()
                return

        # Canlı olayları dinle
        heartbeat_interval = 15  # saniye
        last_heartbeat = datetime.utcnow()
        # DÜRÜST-BİTİŞ (DB): history penceresi yalnız son 20 olay — uzun taramada terminal
        # olay pencerenin dışında kalabilir. Event-bus sessiz + tarama bitmiş durumda
        # bağlantı heartbeat'le sonsuza dek açık kalırdı. Her 4. heartbeat'te (~60sn)
        # DB'den gerçek duruma bak; terminal ise kibarca bitir. Mongo okuma ~1ms —
        # 15sn'de bir değil, dakikada bir kez olduğundan ihmal edilebilir.
        heartbeat_count = 0

        while True:
            try:
                # Timeout ile event bekle
                event = await asyncio.wait_for(queue.get(), timeout=heartbeat_interval)

                if event is None:
                    # Scan tamamlandı sinyali
                    await websocket.send_json({
                        "type": "stream_ended",
                        "message": "Scan completed or cancelled"
                    })
                    break

                # Event'i gönder
                await websocket.send_json({
                    "type": "event",
                    **event.to_dict()
                })

                # Tamamlanma kontrolü
                if event.event_type in [ScanEventType.SCAN_COMPLETED, ScanEventType.SCAN_FAILED]:
                    break

            except asyncio.TimeoutError:
                # Heartbeat gönder
                now = datetime.utcnow()
                if (now - last_heartbeat).seconds >= heartbeat_interval:
                    await websocket.send_json({
                        "type": "heartbeat",
                        "timestamp": now.isoformat(),
                        "message": "Connection alive"
                    })
                    last_heartbeat = now
                    heartbeat_count += 1
                    # Periyodik DB dürüst-bitiş kontrolü (bkz. yukarıdaki not)
                    if heartbeat_count % 4 == 0 and sessions_col is not None:
                        try:
                            doc = sessions_col.find_one(
                                {"scan_id": scan_id}, {"status": 1, "_id": 0}
                            )
                            if doc and doc.get("status") in (
                                "completed", "failed", "cancelled"
                            ):
                                await websocket.send_json({
                                    "type": "stream_ended",
                                    "message": f"Scan already {doc.get('status')} (db check)"
                                })
                                break
                        except Exception:
                            pass  # DB kısa süreli erişilemezse heartbeat akışı sürsün

    except WebSocketDisconnect:
        logger.info(f"Event stream disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"Event stream error for scan {scan_id}: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": "Internal error occurred"
            })
        except:
            pass
    finally:
        await ScanEventBus.unsubscribe(scan_id, queue)


@app.get("/scan/events/history/{scan_id}")
async def get_scan_event_history(scan_id: str, limit: int = 50):
    """Türkçe: Scan için olay geçmişini döner"""
    history = ScanEventBus.get_history(scan_id, limit=limit)
    return {
        "scan_id": scan_id,
        "event_count": len(history),
        "events": history
    }


# Hash Cracker ve CF Analyzer endpoint'leri proxy modüllerinden geliyor


# ============== v2 Pipeline Endpoints ==============

class V2ScanRequest(BaseModel):
    target: str
    profile: str = "normal"  # quick, normal, full, stealth, web, infra (legacy)
    level: Optional[str] = None  # otonom seviye: recon | standard | deep (profile'ı geçersiz kılar)
    stealth: bool = False  # seviyeden bağımsız kip: nmap -T2, düşük gürültü
    # Türkçe: Kimlik doğrulamalı tarama (opsiyonel). Login ARKASINDAKİ yüzeyi (IDOR/yetki)
    # test edebilmek için. Örn: {"bearer": "eyJ..."} | {"cookie": "session=abc"} |
    # {"headers": {"Authorization": "Bearer x", "X-Api-Key": "y"}}
    auth: Optional[Dict[str, Any]] = None
    # Türkçe: İKİNCİ hesap kimliği (opsiyonel — IDOR/BOLA iki-hesap diferansiyeli için).
    # Verilirse motor "B, A'nın nesnesine erişebiliyor mu?" testiyle IDOR'u KANITLAR
    # (confirmed). Aynı biçim sözleşmesi: {"bearer":...} | {"cookie":...} | {"headers":...}
    auth_b: Optional[Dict[str, Any]] = None
    # Türkçe: Operatör "bu hedef ne?" ipucu (opsiyonel): auto | api | web | server.
    # Otomatik parmak-izi ıskalarsa operatör tipi damgalar. "api" dersen motor uygulama
    # tipini API çerçeveler → kitlesel BOLA/broken-auth önceliklenir. auto/None = saf otomatik.
    target_kind: Optional[str] = None
    # Türkçe: Dayanıklılık & maruz-kalma probu (availability + exposure ekseni). VARSAYILAN
    # KAPALI — operatör UI'dan bilinçli açar. Açıkken motor TAHRİBATSIZ olarak L7 DoS
    # dayanıklılığını (CDN cache duruşu + rate-limit), origin-CDN-bypass ifşasını ve SSH
    # parola-auth maruz-kalmasını yoklar. Gerçek DDoS/brute-force ATILMAZ.
    resilience: bool = False

    @validator('target_kind')
    def validate_target_kind(cls, v):
        if v is None:
            return v
        v = str(v).strip().lower()
        if v in ("", "auto"):
            return None
        if v not in ("api", "web", "server"):
            raise ValueError("target_kind: auto | api | web | server olmalı")
        return v

    @validator('target')
    def validate_target(cls, v):
        v = v.strip()
        if v.startswith('http://') or v.startswith('https://'):
            from urllib.parse import urlparse
            parsed = urlparse(v)
            v_check = parsed.netloc or parsed.path.split('/')[0]
        else:
            v_check = v

        ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

        if not (re.match(ipv4_pattern, v_check) or re.match(domain_pattern, v_check)):
            raise ValueError('Invalid target format. Must be IPv4, Domain, or URL.')

        if any(char in v for char in [';', '&', '|', '`', '$', '(', ')', '<', '>']):
            raise ValueError('Illegal characters detected.')
        # KAPSAM KAPISI (bkz. ScanRequest.validate_target): yetki-allowlist + SSRF/iç-ağ guard.
        from pipeline.scope_guard import enforce_target_scope
        enforce_target_scope(v_check)
        # KRİTİK: şemayı SOYUP çıplak host döndür. Frontend zaten strip eder; API'ye doğrudan
        # URL gelirse 'https://host' aşağı katmana iner, K8s port sweep'i (open_connection)
        # ve profil sinyali çekimi sessizce patlar → hedef "sinyal yok" diye genel taramaya
        # düşer (RKE2/Rancher'ın tanınamaması bug'ının köklerinden biri).
        return v_check


@app.post("/v2/scan")
async def start_v2_scan(request: V2ScanRequest):
    """
    Türkçe: v2 Pipeline ile tarama başlat.
    Profil bazlı otomatik aşama yönetimi.
    """
    result = await pipeline_v2.start_pipeline(
        target=request.target,
        profile_name=request.profile,
        level=request.level,
        stealth=request.stealth,
        auth=request.auth,
        auth_b=request.auth_b,
        target_kind=request.target_kind,
        resilience=request.resilience,
    )
    return result


@app.get("/v2/scan/{session_id}")
async def get_v2_scan_status(session_id: str):
    """Türkçe: v2 Pipeline session durumunu döndür"""
    status = pipeline_v2.get_session_status(session_id)
    if not status:
        # scan_id olarak da dene
        status = pipeline_v2.get_session_by_scan_id(session_id)
    if not status:
        raise HTTPException(status_code=404, detail="Session bulunamadı")
    return status


@app.post("/v2/scan/{session_id}/cancel")
async def cancel_v2_scan(session_id: str):
    """Türkçe: v2 Pipeline'ı iptal et"""
    cancelled = await pipeline_v2.cancel_pipeline(session_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail="Aktif pipeline bulunamadı")
    return {"status": "cancelled", "session_id": session_id}


@app.post("/v2/scan/{session_id}/pause")
async def pause_v2_scan(session_id: str):
    """Türkçe: Otonom taramayı DURAKLAT (§2.5) — geri dönüşlü; resume ile sürer.
    Çalışan stage'i kesmez, sıradaki hamleyi bekletir."""
    ok = pipeline_v2.pause_pipeline(session_id)
    if ok is None:
        raise HTTPException(status_code=404, detail="Aktif otonom motor bulunamadı")
    return {"status": "paused", "session_id": session_id}


@app.post("/v2/scan/{session_id}/resume")
async def resume_v2_scan(session_id: str):
    """Türkçe: Duraklatılmış otonom taramayı SÜRDÜR (§2.5)."""
    ok = pipeline_v2.resume_pipeline(session_id)
    if ok is None:
        raise HTTPException(status_code=404, detail="Aktif otonom motor bulunamadı")
    return {"status": "running", "session_id": session_id}


@app.post("/v2/scan/{session_id}/approve")
async def approve_v2_exploit_phase(session_id: str):
    """
    Türkçe: İki fazlı onay kapısı — keşif fazı tamamlandıktan sonra
    sömürü fazına geçişi onayla (Kuşatma Doktrini).
    """
    ok = pipeline_v2.approve_exploit_phase(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Onay bekleyen session bulunamadı")
    return {"status": "approved", "session_id": session_id, "phase": "exploit"}


@app.get("/v2/scan/{session_id}/cohosted")
async def get_v2_cohosted_candidates(session_id: str):
    """
    Türkçe: Scope kapısı — reverse-IP ile bulunan co-hosted (yabancı) domain'lerin listesi.
    strict scope'ta bunlar OTOMATİK taranmaz; UI bu listeyi bir onay modeli olarak gösterir,
    kullanıcı işaretlediklerini /cohosted/approve ile taramaya açar.
    """
    candidates = pipeline_v2.get_cohosted_candidates(session_id)
    if candidates is None:
        raise HTTPException(status_code=404, detail="Aktif otonom tarama bulunamadı")
    return {"session_id": session_id, "candidates": candidates, "count": len(candidates)}


class CohostedApproveRequest(BaseModel):
    node_ids: List[str] = []  # 'host:reverse:foo.com' ya da sade 'foo.com' kabul edilir


@app.post("/v2/scan/{session_id}/cohosted/approve")
async def approve_v2_cohosted_targets(session_id: str, request: CohostedApproveRequest):
    """
    Türkçe: Kullanıcının UI'da işaretlediği co-hosted domain'leri tarama iznine ekler.
    Onaylananlar bir sonraki karar turundan itibaren motor tarafından (per-host) taranır.
    """
    added = pipeline_v2.approve_cohosted(session_id, request.node_ids)
    if added is None:
        raise HTTPException(status_code=404, detail="Aktif otonom tarama bulunamadı")
    return {"status": "approved", "session_id": session_id, "approved_count": added}


@app.post("/v2/scan/{session_id}/llm/retry")
async def retry_v2_appraisal(session_id: str):
    """
    Türkçe: LLM (istihbarat subayı) cevabı parse edilemediğinde kullanıcı-tetiklemeli
    yeniden danışma. UI, parse başarısızlığı olayını (can_retry_appraisal) görünce bir
    düğme gösterir; operatör tıklayınca motor bir sonraki karar turunda force_retry ile
    (ekstra 'repair' denemesiyle) tekrar danışır. Motor zaten kural+graf ile çalışmaya
    devam eder — bu yalnız LLM sezgi katmanını geri kazanma girişimidir.
    """
    ok = pipeline_v2.retry_appraisal(session_id)
    if ok is None:
        raise HTTPException(status_code=404, detail="Aktif otonom tarama bulunamadı")
    if not ok:
        return {"status": "rejected", "session_id": session_id,
                "reason": "Motor durdurulmuş — yeniden danışma uygulanamaz."}
    return {"status": "retry_scheduled", "session_id": session_id,
            "message": "Bir sonraki karar turunda LLM'e yeniden danışılacak."}


@app.post("/v2/scan/{session_id}/report/retry")
async def retry_v2_autonomous_report(session_id: str):
    """
    Türkçe: AI raporu üretilemediğinde (report_status='failed') kullanıcı-tetiklemeli
    yeniden üretim (§2.1). Motor artık çalışmadığından kanıt+özet Mongo'dan yeniden kurulur
    ve rapor arka planda tekrar gönderilir. UI, session.ai_analysis.report_status='failed'
    görünce bir 'Raporu yeniden dene' düğmesi gösterir; operatör tıklayınca bu tetiklenir.
    """
    ok = await pipeline_v2.retry_autonomous_report(session_id)
    if ok is None:
        raise HTTPException(status_code=404, detail="Session bulunamadı")
    return {"status": "retry_scheduled", "session_id": session_id,
            "message": "AI raporu arka planda yeniden üretiliyor."}


@app.get("/v2/scan/{scan_id}/artifacts")
async def get_v2_scan_artifacts(scan_id: str):
    """
    Türkçe: Otonom taramanın her adımının sonucunu döndür (özet + ham veri).
    "Recon taradı — ne çıktı?" — frontend modalı bunu okur.
    """
    artifacts = pipeline_v2.get_scan_artifacts(scan_id)
    return {"scan_id": scan_id, "artifacts": artifacts, "count": len(artifacts)}


@app.get("/v2/scan/{scan_id}/artifact/{step}/{tool}")
async def get_v2_scan_artifact(scan_id: str, step: int, tool: str):
    """Türkçe: Tek bir adımın tam sonucunu (ham dahil) döndür."""
    artifact_id = f"{scan_id}:{step}:{tool}"
    artifact = pipeline_v2.get_scan_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact bulunamadı")
    return artifact


@app.get("/v2/scan/{scan_id}/llm-logs")
async def get_v2_scan_llm_logs(scan_id: str, _admin: Dict[str, Any] = Depends(require_admin)):
    """
    Türkçe: Otonom taramanın her turunda LLM istihbarat subayına SORULAN prompt + gelen
    HAM cevabı döndür (şeffaflık paneli). "LLM'e ne sordu, ne cevap geldi?" — admin
    log paneli bunu okur. YALNIZCA ADMIN (require_admin): bu veri hedef istihbaratını ve
    motorun iç karar mantığını açar; rol kontrolü sunucu tarafında zorunludur.
    """
    logs = pipeline_v2.get_scan_llm_logs(scan_id)
    return {"scan_id": scan_id, "logs": logs, "count": len(logs)}


class JsSecretRevealRequest(BaseModel):
    """TEMA 3.1 — yetkili operatör için JS-sır unmask (canlı yeniden-getirme)."""
    asset_url: str          # sırrın bulunduğu JS varlığı (bulgudaki asset_url)
    value_masked: str       # bulgunun maske kimliği (ör. "Supe***123!")
    validator: Optional[str] = None    # varsa daralt (password/aws_secret/...)
    secret_type: Optional[str] = None  # varsa daralt ("Hardcoded Password")


@app.post("/v2/js-secret/reveal")
async def reveal_js_secret(request: JsSecretRevealRequest,
                           _admin: Dict[str, Any] = Depends(require_admin)):
    """
    Türkçe: Bir JS-sır bulgusunu CANLI hedeften yeniden indirip HAM değerini çöz.

    NEDEN: Sır rapora/DB'ye MASKELİ gider (doğru — kalıcı depoda ham parola tutulmaz).
    Ama kendi yetkili hedefini doğrulayan operatör değeri geri alamıyordu. Bu uç,
    path_probe `reveal=True` emsalini aynalar: motor varlığı YENİDEN indirir, maskeyle
    eşleşen ham değeri döner; hiçbir kalıcı depoya ham sır yazılmaz (yalnız canlı türetme).

    YALNIZCA ADMIN (require_admin). Her çağrı denetim izine yazılır (js_secret_reveals):
    kim, hangi hedef, ne zaman, sonuç — ama HAM DEĞER denetim izine de GİRMEZ.
    """
    # Yalnız http(s) JS varlığı — SSRF yüzeyini şema ile sınırla.
    if not re.match(r"^https?://", request.asset_url or "", re.I):
        raise HTTPException(status_code=422, detail="Geçersiz asset_url (http/https bekleniyor)")

    from pipeline.js_secrets import reveal_secret
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            result = await reveal_secret(
                client, request.asset_url, request.value_masked,
                validator=request.validator, secret_type=request.secret_type,
            )
    except Exception as e:
        logger.error(f"JS-sır unmask hatası ({request.asset_url}): {e}")
        raise HTTPException(status_code=502, detail=f"Canlı yeniden-getirme başarısız: {e}")

    # DENETİM İZİ: ham değer HARİÇ her şey. (best-effort — yazamama unmask'ı düşürmez)
    try:
        if db is not None:
            db["js_secret_reveals"].insert_one({
                "_id": str(uuid.uuid4()),
                "admin": _admin.get("username") or _admin.get("sub") or _admin.get("id"),
                "asset_url": request.asset_url,
                "value_masked": request.value_masked,
                "validator": request.validator,
                "secret_type": request.secret_type,
                "status": result.get("status"),
                "created_at": datetime.utcnow(),
            })
    except Exception as _ae:
        logger.warning(f"Unmask denetim izi yazılamadı: {_ae}")

    if result.get("status") != "revealed":
        # 404/409 semantiği: neden çözülemediği anlaşılır olsun (drift/rotasyon/belirsizlik).
        code = 409 if result.get("status") == "ambiguous" else 404
        raise HTTPException(status_code=code, detail=result.get("detail") or result.get("status"))
    return result


@app.get("/v2/osint/integrations")
async def get_osint_integrations():
    """
    Türkçe: OSINT API key durumlarını döndür (shodan/virustotal/abuseipdb/securitytrails).
    Frontend "hangi kaynak aktif?" rozetleri için OSINT servisinin /health'ini proxy'ler.
    """
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{OSINT_SERVICE_URL}/health")
            if resp.status_code == 200:
                body = resp.json()
                return {
                    "reachable": True,
                    "integrations": body.get("integrations", []),
                }
            # 200-dışı: servis ayakta ama sağlıksız — sebebi görünür kıl (UI boş hata göstermesin)
            err = f"OSINT /health HTTP {resp.status_code}"
            logging.getLogger("orchestrator").warning(f"OSINT integrations proxy: {err}")
            return {"reachable": False, "integrations": [], "error": err}
    except Exception as e:
        err = str(e)[:120]
        logging.getLogger("orchestrator").warning(f"OSINT integrations proxy erişilemedi: {err}")
        return {"reachable": False, "integrations": [], "error": err}


@app.get("/v2/pipelines/active")
async def get_active_v2_pipelines():
    """Türkçe: Aktif v2 pipeline'ları listele"""
    pipelines = pipeline_v2.get_active_pipelines()
    return {"pipelines": pipelines, "count": len(pipelines)}


@app.get("/v2/profiles")
async def get_v2_profiles():
    """Türkçe: Kullanılabilir tarama SEVİYELERİNİ listele (Tek Doktrin geçişi).

    Statik profiller donduruldu (bkz docs/TEK-DOKTRIN-GECIS-TASARIMI.md). Artık her
    tarama otonom motordan geçer; kullanıcı yalnız derinlik seviyesini seçer.
    Legacy 64 profili görmek için: LEGACY_PROFILES_ENABLED=true + ?legacy=1.
    """
    return {
        "profiles": [
            {"id": "recon", "name": "Keşif", "level": "recon",
             "description": "Pasif harita — pahalı araç çalışmaz. Saldırı yüzeyini çıkarır.",
             "estimated_minutes": None, "stages_count": 0,
             "tools": ["recon", "subfinder", "osint", "origin_discovery"]},
            {"id": "standard", "name": "Standart", "level": "standard",
             "description": "Keşif + en zayıf noktalara HEDEFLİ zafiyet taraması. Kör tarama yok.",
             "estimated_minutes": None, "stages_count": 0,
             "tools": ["nmap", "nuclei"]},
            {"id": "deep", "name": "Derin", "level": "deep",
             "description": "Tam derinlik: fuzz + pivot + gizli portlar. En kapsamlı kuşatma.",
             "estimated_minutes": None, "stages_count": 0,
             "tools": ["nmap", "nuclei", "fuzz"]},
        ],
        "note": "Statik profiller donduruldu — her tarama otonom motordan (Kuşatma Doktrini) geçer.",
    }


@app.get("/v2/profiles/legacy")
async def get_v2_profiles_legacy():
    """Türkçe: DONDURULMUŞ statik profiller (geri-alma/denetim için). Varsayılan yolda kullanılmaz."""
    return {"profiles": list_scan_profiles(), "frozen": True}


@app.get("/v2/sessions")
async def get_v2_sessions(limit: int = 20, status: Optional[str] = None):
    """Türkçe: v2 Pipeline session geçmişini listele"""
    col = pipeline_v2._get_sessions_collection()
    if col is None:
        return {"sessions": [], "total": 0}

    try:
        query = {}
        if status:
            query["status"] = status

        cursor = col.find(query, {"_id": 0}).sort("created_at", -1).limit(limit)
        sessions = list(cursor)
        total = col.count_documents(query)
        return {"sessions": sessions, "total": total}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
