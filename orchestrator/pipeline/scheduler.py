"""
Türkçe: Zamanlanmış tarama zamanlayıcısı (scheduler runner).

Tasarım kararları (sebep/sonuç):
- `pipeline_v2` dışarıdan parametre olarak alınır → bu modül main.py import etmez, döngüsel
  import riski yok. Startup'ta `create_task(schedule_runner_task(pipeline_v2))` ile başlatılır.
- `stale_scan_cleanup_task` deseninin birebir kopyası: `while True + asyncio.sleep` + try/except
  ile kendini koruyan sonsuz döngü. Yeni bağımlılık (APScheduler/cron) eklemeden 30sn poll.
- Yalnızca `_active_pipelines` içinde aynı `target` için `running|awaiting_approval` yoksa
  tetikler → hedef-dedup (yarış koşulu bertarafı). Global semaphore eklemedik çünkü
  kullanıcı isteği 'düzenli tertipli tarama', burst traffic beklemiyoruz.
- `last_scan.status` güncellemesi `_run_pipeline`/`_run_autonomous` task'ına
  `add_done_callback` ile takılır (router tarafında). Buradaki runner yalnızca yeni
  taramayı başlatır ve `next_run_at`'i ileri atar.
- `REQUIRE_RECON_APPROVAL` env'i AÇIKSA, scheduled taramalar `recon` seviyesinde
  sömürü onayında takılır → bu modül `level in {standard, deep}` zorunlu kılar (router
  seviyesinde, v1'de seçenek yalnızca recon/standard/deep ama scheduler yalnızca
  standard/deep kabul eder). Kullanıcı bilinçli olarak `recon` seçse bile scheduled
  çalıştırma sırasında bir uyarı düşer; sömürü fazı otomatik onaylanmaz — scheduled
  taramalar bu yüzden standard/deep ile sınırlı.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from .scan_events import emit_progress_update

logger = logging.getLogger("orchestrator.scheduler")

POLL_INTERVAL_SECONDS = 30


# Türkçe: Periyot enum'undan bir sonraki çalıştırma zamanını hesapla.
# `next_run_at` her zaman UTC tutulur → sunucu saatinden bağımsız, dağıtık tutarlı.
def compute_next_run(interval: str, base: Optional[datetime] = None) -> Optional[datetime]:
    base = base or datetime.now(timezone.utc)
    if interval == "hourly":
        return base + timedelta(hours=1)
    if interval == "daily":
        return base + timedelta(days=1)
    if interval == "weekly":
        return base + timedelta(weeks=1)
    return None  # off / bilinmeyen


# Türkçe: Verilen `target` için hâlâ aktif bir pipeline var mı? (pipeline_v2 memory'sinden)
def _target_is_active(pipeline, target: str) -> bool:
    # `_active_pipelines` dict'i (session_id -> PipelineSession) aynı event loop'ta
    # paylaşılıyor; pratikte yarış yok, dict tek-thread async.
    for session in getattr(pipeline, "_active_pipelines", {}).values():
        if getattr(session, "target", None) == target:
            status = getattr(session, "status", "")
            if status in ("running", "awaiting_approval", "paused"):
                return True
    return False


async def schedule_runner_task(pipeline) -> None:
    """
    Türkçe: 30 saniyede bir `scan_schedules` koleksiyonunu yoklar, süresi gelmiş ve
    hedefi başka taramada olmayan kayıtlar için `pipeline_v2.start_pipeline` çağırır.
    Döngü kendi hatalarını yutar; scheduler çökerse stale_scan_cleanup_task gibi bir
    başka process izleme mekanizması zaten var.
    """
    # Lazy import: döngüsel importtan kaçınmak için getter'ı burada çağırıyoruz.
    from core.db import get_scan_schedules_collection

    logger.info("📅 Zamanlanmış tarama zamanlayıcısı başlatıldı (poll=%ds)", POLL_INTERVAL_SECONDS)

    while True:
        try:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            col = get_scan_schedules_collection()
            if col is None:
                continue
            now = datetime.now(timezone.utc)
            # Composite index `(enabled, schedule.enabled, next_run_at)` ile hızlı tarama.
            due = col.find({
                "enabled": True,
                "schedule.enabled": True,
                "schedule.next_run_at": {"$lte": now},
            })
            for doc in due:
                target = doc.get("target", "")
                level = doc.get("level", "standard")
                # Sebep: recon seviyesi REQUIRE_RECON_APPROVAL açıksa takılır; scheduled
                # taramalar için standard/deep zorunlu. Kullanıcı formda da bu kısıt
                # net biçimde gösterilir.
                if level not in ("standard", "deep"):
                    logger.warning("⏭️  Zamanlama atlandı: %s (seviye=%s recon olamaz)", target, level)
                    col.update_one(
                        {"_id": doc["_id"]},
                        {"$set": {"schedule.next_run_at": compute_next_run(doc["schedule"].get("interval", "daily"), now)}},
                    )
                    continue
                if _target_is_active(pipeline, target):
                    # Hedef zaten taranıyor → bu turu atla, sonraki tura erteleme.
                    continue
                # AI 2 — akıllı jitter: tüm scheduled taramalar aynı saatte başlarsa
                # Mongo + nmap + nuclei kaynak spike olur, hedef WAF'ları da tetikler.
                # `next_run_at`'in fractional dakikası (MM) hedef hash'ine göre
                # pseudo-rastgele dağıtılır → 60dk pencere içinde 0-59 arasına yayılır.
                # Bu deterministik (aynı target her zaman aynı dakikada) + dağıtık.
                try:
                    scheduled = doc.get("schedule", {})
                    if not scheduled.get("jittered"):
                        next_at_base = compute_next_run(scheduled.get("interval", "daily"), now)
                        if next_at_base:
                            # Hedef adının stable hash'i → aynı hedef her zaman aynı dakikada
                            import hashlib
                            h = int(hashlib.md5(target.encode()).hexdigest()[:8], 16)
                            minute_offset = h % 60
                            from datetime import timedelta as _td
                            jittered = next_at_base.replace(minute=minute_offset, second=0, microsecond=0)
                            # Jitter uygulanmış ve bugünden sonraysa kaydet, sonraki turda atla
                            col.update_one(
                                {"_id": doc["_id"]},
                                {"$set": {"schedule.next_run_at": jittered, "schedule.jittered": True}},
                            )
                            continue
                except Exception as e:
                    logger.debug("Jitter hesaplanamadı (%s), normal akış: %s", target, e)
                try:
                    result = await pipeline.start_pipeline(
                        target=target,
                        profile_name="autonomous",
                        level=level,
                        stealth=bool(doc.get("stealth", False)),
                    )
                except Exception as e:
                    logger.exception("Zamanlanmış tarama başlatılamadı: %s — %s", target, e)
                    col.update_one(
                        {"_id": doc["_id"]},
                        {"$set": {
                            "last_scan": {
                                "status": "failed",
                                "error": str(e),
                                "failed_at": datetime.now(timezone.utc),
                            },
                            "updated_at": datetime.now(timezone.utc),
                        }},
                    )
                    continue
                session_id = result.get("session_id")
                scan_id = result.get("scan_id")
                next_at = compute_next_run(doc["schedule"].get("interval", "daily"), now)
                col.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {
                        "schedule.last_run_at": now,
                        "schedule.next_run_at": next_at,
                        "last_scan": {
                            "session_id": session_id,
                            "scan_id": scan_id,
                            "status": "running",
                            "started_at": now,
                        },
                        "updated_at": now,
                    }},
                )
                # Kullanıcıya ilerleme olayı: scan-history / dashboard'da görünür.
                try:
                    await emit_progress_update(
                        scan_id or "scheduler",
                        f"Zamanlanmış tarama başlatıldı: {target} (level={level})",
                        {"source": "scheduler", "schedule_id": str(doc["_id"])},
                    )
                except Exception:
                    pass
                # Bug 1 düzeltmesi: scheduler tarafından başlatılan taramalar da
                # watcher ile izlenmeli — yoksa last_scan.status sonsuza kadar
                # 'running' kalır, tabloda hiç tamamlanma göstermez. Watcher motor
                # terminal-state'e geçince günceller.
                from integrations.schedules_router import _watch_and_update_status
                asyncio.create_task(_watch_and_update_status(doc["_id"], scan_id))
                logger.info("📅 Zamanlanmış tarama başlatıldı: %s session=%s", target, session_id)
        except Exception as e:
            # Döngü kırılmasın: bir turdaki beklenmeyen hata loglanır, sonraki turda devam.
            logger.exception("Scheduler turu hata verdi: %s", e)
