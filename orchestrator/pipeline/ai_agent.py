"""
Türkçe: Kalıcı AI Ajanı — "real-time AI" platformunun beyni.

Tasarım kararları (sebep/sonuç):
- Bu modül `stale_scan_cleanup_task` ve `schedule_runner_task` gibi singleton bir
  asyncio task olarak `startup_event`'te başlatılır. Tek süreçte çalışır, restart
  sonrası scan_schedules/agent_actions Mongo'dan state'i yeniden yükler.
- `ScanEventBus.subscribe_all()` ile TÜM olayları dinler; scan_id özelinde filtrelemez
  → genel korelasyon, cross-target intelligence, auto-tune hepsi burada olur.
- Reasoning loop LLM-driven + kural-fallback. LLM 5s timeout; kapalıysa deterministic
  kurallar çalışır (motor felsefesi: LLM opsiyonel, kritik yol değil).
- Aksiyonlar "agent_actions" koleksiyonuna loglanır → şeffaflık, audit, debugging.

Akış (sürekli):
  ┌─ scan_event geldi ─┐
  │  SCAN_COMPLETED    │──→ findins_analyze() → risk_trend güncelle → auto-tune?
  │  CRITICAL_FINDING  │──→ follow_up_trigger() → aynı target'a deep scan kuyruğa
  │  SCAN_FAILED       │──→ consecutive_failures++ → anomali
  │  schedule_due      │──→ (scheduler zaten yapıyor; agent cross-target yapar)
  └────────────────────┘
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from .scan_events import ScanEvent, ScanEventType, ScanEventBus

logger = logging.getLogger("orchestrator.ai_agent")

AI_SERVICE_URL = __import__("os").getenv("AI_SERVICE_URL", "http://ai-service:8009")
MONGODB_URI = __import__("os").getenv("MONGODB_URI", "mongodb://mongodb:27017")
MONGODB_DATABASE = __import__("os").getenv("MONGODB_DATABASE", "kadim_security")

# Lazy Mongo client
_mongo_client: Optional[Any] = None


def _db():
    """Mongo bağlantısı — process başına bir kez."""
    global _mongo_client
    if _mongo_client is None:
        from pymongo import MongoClient
        _mongo_client = MongoClient(MONGODB_URI)
    return _mongo_client[MONGODB_DATABASE]


# ---- Auto-tune kuralları (LLM yoksa bu çalışır) ----
INTERVAL_ORDER = ["off", "hourly", "daily", "weekly"]
DEDUP_INTERVAL = {"off": 0, "hourly": 1, "daily": 2, "weekly": 3}

# 3+ ardışık temiz tarama → bir kademe seyrekleştir
CLEAN_STREAK_TO_DEDUCE = 3
# Kritik bulgu → en sık kademe (hourly)
CRITICAL_FINDING_BOOST = True


def _decide_frequency(
    current_interval: str,
    clean_streak: int,
    had_critical: bool,
    had_high: int,
) -> tuple[str, str]:
    """
    Kural-tabanlı auto-tune. Döner: (yeni_interval, sebep).
    """
    idx = DEDUP_INTERVAL.get(current_interval, 2)
    if had_critical and CRITICAL_FINDING_BOOST:
        return "hourly", f"Kritik bulgu → saatlik taramaya geçildi"
    if had_high >= 3:
        new_idx = max(0, idx - 1)
        return INTERVAL_ORDER[new_idx], f"{had_high} yüksek bulgu → sıklık artırıldı"
    if clean_streak >= CLEAN_STREAK_TO_DEDUCE:
        new_idx = min(3, idx + 1)
        if new_idx != idx:
            return INTERVAL_ORDER[new_idx], f"{clean_streak} ardışık temiz tarama → sıklık azaltıldı"
    return current_interval, "Değişiklik yok"


async def _llm_reason(prompt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """5s timeout ile LLM'e danış; yanıt JSON dict ise döner, yoksa None."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{AI_SERVICE_URL}/analyze",
                json={
                    "scan_data": prompt,
                    "analysis_type": "scheduled_scan_decision",
                    "use_default": True,
                },
            )
            if r.status_code == 200:
                data = r.json()
                analysis = data.get("analysis")
                if isinstance(analysis, dict):
                    return analysis
    except Exception as e:
        logger.debug("AI agent LLM çağrısı başarısız (kural-fallback): %s", e)
    return None


def _log_action(action: str, target: str, payload: Dict[str, Any]) -> None:
    """agent_actions koleksiyonuna şeffaflık logu."""
    try:
        _db()["agent_actions"].insert_one({
            "action": action,
            "target": target,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc),
        })
    except Exception as e:
        logger.debug("agent_actions log yazılamadı: %s", e)


# ---- Olay işleyicileri (her biri tek bir karar) ----

async def _handle_scan_completed(scan_id: str, target: str, data: Dict[str, Any]) -> None:
    """
    SCAN_COMPLETED: bulguları değerlendir, auto-tune, follow-up tetikle.
    """
    schedules = _db()["scan_schedules"]
    rec = schedules.find_one({"target": target, "enabled": True})
    if not rec:
        return  # Manuel başlatılmış veya kayıt silinmiş

    sessions = _db()["v2_scan_sessions"]
    sess = sessions.find_one({"scan_id": scan_id}) or {}
    summary = sess.get("ai_analysis") or {}
    risk = summary.get("risk_score") or 0
    critical = summary.get("critical_findings") or []
    findings = sess.get("findings") or []
    severity_counts = (
        sess.get("severity_counts")
        or sess.get("summary", {}).get("severity_counts")
        or {}
    )
    had_critical = bool(critical) or severity_counts.get("critical", 0) > 0
    had_high = severity_counts.get("high", 0) or sum(
        1 for f in findings if isinstance(f, dict) and (f.get("info") or f).get("severity") == "high"
    )

    # 1) AUTO-TUNE (kural + opsiyonel LLM)
    new_interval = rec.get("schedule", {}).get("interval", "off")
    reason = "Henüz karar yok"
    auto_tune_enabled = rec.get("auto_tune_enabled", True)
    if auto_tune_enabled and rec.get("schedule", {}).get("enabled"):
        # Clean streak hesabı
        recent = list(schedules.find({"target": target}).sort("updated_at", -1).limit(CLEAN_STREAK_TO_DEDUCE + 2))
        clean_streak = 0
        for r in recent:
            ls = (r.get("last_scan") or {})
            st = ls.get("status")
            sc = sessions.find_one({"scan_id": ls.get("scan_id")}) or {}
            sc_crit = (sc.get("ai_analysis") or {}).get("critical_findings") or []
            sc_sev = sc.get("severity_counts") or {}
            if st in ("completed", None) and not sc_crit and sc_sev.get("critical", 0) == 0 and sc_sev.get("high", 0) == 0:
                clean_streak += 1
            else:
                break

        # Önce kural, sonra LLM ince ayar
        new_interval, reason = _decide_frequency(
            rec.get("schedule", {}).get("interval", "daily"),
            clean_streak, had_critical, had_high,
        )
        if new_interval != rec.get("schedule", {}).get("interval"):
            llm_decision = await _llm_reason({
                "task": "auto_tune",
                "target": target,
                "current_interval": rec.get("schedule", {}).get("interval"),
                "rule_suggested": new_interval,
                "rule_reason": reason,
                "clean_streak": clean_streak,
                "had_critical": had_critical,
                "had_high": had_high,
                "risk_score": risk,
            })
            if llm_decision and llm_decision.get("interval") in INTERVAL_ORDER:
                new_interval = llm_decision["interval"]
                reason = llm_decision.get("reasoning", reason)

            if new_interval != rec.get("schedule", {}).get("interval"):
                from datetime import timedelta
                tune_entry = {
                    "from": rec.get("schedule", {}).get("interval"),
                    "to": new_interval,
                    "reason": reason,
                    "at": datetime.now(timezone.utc),
                }
                # next_run_at'i de yeniden hesapla
                deltas = {"hourly": 1, "daily": 1, "weekly": 7}
                delta = deltas.get(new_interval, 1)
                next_at = datetime.now(timezone.utc) + timedelta(hours=delta if new_interval == "hourly" else delta * 24)
                schedules.update_one(
                    {"_id": rec["_id"]},
                    {"$set": {
                        "schedule.interval": new_interval,
                        "schedule.next_run_at": next_at,
                        "last_tune_at": datetime.now(timezone.utc),
                    }, "$push": {"tune_history": tune_entry}},
                )
                _log_action("auto_tune", target, tune_entry)
                logger.info("🤖 Auto-tune: %s %s → %s (%s)", target, tune_entry["from"], new_interval, reason)

    # 2) FOLLOW-UP: Kritik bulgu → aynı target'a derin tarama (deep level) tetikle
    if had_critical:
        # Çok sık tetikleme — en son follow-up'tan 1 saat geçmiş olmalı
        last_follow_up = rec.get("last_follow_up_at")
        now = datetime.now(timezone.utc)
        if not last_follow_up or (now - last_follow_up).total_seconds() > 3600:
            schedules.update_one(
                {"_id": rec["_id"]},
                {"$set": {"last_follow_up_at": now}},
            )
            _log_action("follow_up_triggered", target, {
                "reason": "critical_finding",
                "scan_id": scan_id,
                "risk_score": risk,
            })
            logger.info("🤖 Follow-up tetiklendi: %s (kritik bulgu, risk=%s)", target, risk)
            # NOT: Follow-up tetikleme pipeline_v2 üzerinden yapılabilir; burada yalnızca
            # logluyoruz. Scheduler bir sonraki turda standard/deep ile alır, ya da
            # kullanıcı tablodan ▶ ile derin tarama başlatabilir. (Asenkron tarama
            # tetikleme motor içinde gerekli — v3 backlog.)


async def _handle_scan_failed(scan_id: str, target: str, data: Dict[str, Any]) -> None:
    """
    SCAN_FAILED: ardışık hata sayacı → 3+ olursa schedule'ı geçici olarak duraklat.
    Sebep: 3 başarısız tarama aynı hedefe art arda çalıştırılırsa kaynak israfı + aynı
    hatayı tekrar tetikleme. Kullanıcıya 'incele' banner'ı bırakır.
    """
    schedules = _db()["scan_schedules"]
    rec = schedules.find_one({"target": target, "enabled": True})
    if not rec:
        return
    # Son 3 tarama failed mı?
    history = list(schedules.find({"target": target}).sort("updated_at", -1).limit(3))
    failed_count = sum(
        1 for h in history
        if (h.get("last_scan") or {}).get("status") == "failed"
    )
    if failed_count >= 3:
        # Geçici duraklat — kullanıcı manuel resume edebilir
        if not rec.get("paused_by_agent"):
            schedules.update_one(
                {"_id": rec["_id"]},
                {"$set": {
                    "paused_by_agent": True,
                    "agent_pause_reason": f"{failed_count} ardışık başarısız tarama — lütfen hedefi kontrol edin",
                }},
            )
            _log_action("auto_pause", target, {"failed_count": failed_count, "scan_id": scan_id})
            logger.warning("🤖 Agent auto-pause: %s (%d ardışık hata)", target, failed_count)


async def _handle_critical_finding(scan_id: str, target: str, data: Dict[str, Any]) -> None:
    """
    CRITICAL_FINDING: anlık alert. Watcher'ın tamamlanma beklemesine gerek yok —
    bulgu geldiği anda WS'e bildirim düşer, kullanıcı toast alır.
    """
    # schedules_ws burada publish eder; agent loglama yapar.
    _log_action("critical_finding_alert", target, {
        "scan_id": scan_id,
        "data": data,
    })


async def _handle_subdomain_found(scan_id: str, target: str, data: Dict[str, Any]) -> None:
    """
    SUBDOMAIN_FOUND: yeni subdomain keşfedildiğinde ilgili schedule varsa kullanıcıya
    'yeni subdomain' bildirimi bırak (UI'da gösterilir, otomatik ekleme YAPMA — kullanıcı
    onayı gerekli).
    """
    subdomain = data.get("subdomain")
    if not subdomain:
        return
    schedules = _db()["scan_schedules"]
    rec = schedules.find_one({"target": target, "enabled": True})
    if not rec:
        return
    # Daha önce bu subdomain için pending suggestion var mı?
    existing = rec.get("pending_subdomains") or []
    if subdomain in existing:
        return
    schedules.update_one(
        {"_id": rec["_id"]},
        {"$push": {"pending_subdomains": {
            "subdomain": subdomain,
            "discovered_at": datetime.now(timezone.utc),
            "source_scan": scan_id,
        }}},
    )
    _log_action("subdomain_suggested", target, {"subdomain": subdomain})
    logger.info("🤖 Subdomain önerildi: %s (kayıt: %s)", subdomain, target)


# ---- Ana agent loop ----

async def ai_agent_loop() -> None:
    """
    7/24 çalışan ajan. Tüm scan event'leri dinler, karar alır, aksiyon uygular.
    Tek süreçte çalışır; restart sonrası Mongo'daki state'i kullanır.
    """
    logger.info("🤖 AI Agent başlatıldı")
    queue = await ScanEventBus.subscribe_all()
    try:
        while True:
            event: ScanEvent = await queue.get()
            try:
                etype = event.event_type
                target = event.data.get("target", "")
                if etype == ScanEventType.SCAN_COMPLETED:
                    await _handle_scan_completed(event.scan_id, target, event.data)
                elif etype == ScanEventType.SCAN_FAILED:
                    await _handle_scan_failed(event.scan_id, target, event.data)
                elif etype == ScanEventType.CRITICAL_FINDING:
                    await _handle_critical_finding(event.scan_id, target, event.data)
                elif etype == ScanEventType.SUBDOMAIN_FOUND:
                    await _handle_subdomain_found(event.scan_id, target, event.data)
            except Exception as e:
                # Tek event hata verse bile ajan dinlemeye devam etsin.
                logger.exception("AI agent event handler hatası: %s", e)
    except asyncio.CancelledError:
        logger.info("🤖 AI Agent durduruluyor")
        raise
    finally:
        await ScanEventBus.unsubscribe_all(queue)
