"""
Nuclei Mikroservisi - Zafiyet Tarama Motoru
ProjectDiscovery Nuclei entegrasyonu ile CVE, misconfig ve teknoloji tespiti
Türkçe: Bu servis Nuclei tarama motorunu yönetir ve real-time sonuç akışı sağlar
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from pydantic import BaseModel, validator
import subprocess
import json
import os
import re
from datetime import datetime
from typing import List, Optional, Dict
import logging
import asyncio

# Türkçe: False Positive Analyzer modülü
from fp_analyzer import get_fp_analyzer, analyze_and_enrich_finding, FPAnalyzer
from template_analyzer import TemplateAnalyzer

# Türkçe: MongoDB bağlantısı
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Türkçe: Gelişmiş loglama yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("nuclei-service")

app = FastAPI(title="Nuclei Service", version="3.0.0")  # MongoDB migration

# ============== MongoDB Configuration ==============
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://mongodb:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")

# Türkçe: MongoDB bağlantısını başlat
mongo_client = None
db = None

try:
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    mongo_client.admin.command('ping')
    db = mongo_client[MONGODB_DATABASE]
    logger.info("✅ MongoDB bağlantısı başarılı")
except ConnectionFailure as e:
    logger.error(f"⚠️ MongoDB bağlantı hatası: {e}")
    db = None


def get_nuclei_logs_collection():
    """Türkçe: NucleiLogs koleksiyonunu döner"""
    if db is None:
        return None
    return db["NucleiLogs"]


def get_active_scans_collection():
    """Türkçe: NucleiActiveScans koleksiyonunu döner"""
    if db is None:
        return None
    return db["NucleiActiveScans"]


def add_log_sync(scan_id: str, level: str, message: str, data: Optional[Dict] = None):
    """
    Türkçe: MongoDB'ye senkron log kaydı ekler
    Levels: INFO, WARNING, ERROR, FINDING, PROGRESS, SCAN_START, SCAN_END
    """
    collection = get_nuclei_logs_collection()
    if collection is None:
        logger.warning(f"MongoDB unavailable, log skipped: {message[:100]}")
        return None
    
    try:
        doc = {
            "scan_id": scan_id,
            "timestamp": datetime.utcnow(),
            "level": level,
            "message": message,
            "data": data or {}
        }
        result = collection.insert_one(doc)
        return result.inserted_id
    except Exception as e:
        logger.error(f"Log insert error: {e}")
        return None


async def add_log(scan_id: str, level: str, message: str, data: Optional[Dict] = None):
    """Türkçe: MongoDB'ye asenkron log kaydı ekler (wrapper)"""
    # Not: pymongo senkron, async için motor kullanılabilir ama basitlik için sync
    return add_log_sync(scan_id, level, message, data)


# Türkçe: Eski log dizini (backward compat için tutulabilir)
os.makedirs("/app/logs", exist_ok=True)

# Türkçe: Template dizini - Nuclei template'lerinin bulunduğu konum
TEMPLATES_DIR = "/root/nuclei-templates"
TEMPLATES_STATS_FILE = f"{TEMPLATES_DIR}/TEMPLATES-STATS.json"


class NucleiScanRequest(BaseModel):
    """Türkçe: Nuclei tarama isteği modeli - Validation ile güvenlik sağlanır"""
    target: str
    scan_id: str
    templates: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    rate_limit: int = 150
    timeout: int = 5
    retries: int = 1
    exclude_tags: List[str] = []
    profile: str = "balanced"  # fast, balanced, stealth
    # Türkçe: Paralellik ayarları. ÖNCEDEN üst katman bunları gönderiyordu ama model/komut
    # bunları HİÇ kullanmıyordu → geniş taramalar (cve_sweep ~4158 template) nuclei varsayılan
    # düşük paralellikle çok yavaş çalışıp timeout'a giriyordu. Artık komuta geçirilir.
    concurrency: int = 25       # -c: eşzamanlı template sayısı
    bulk_size: int = 25         # -bs: host başına paralel istek
    # Türkçe: KANIT modu — bulguyu tetikleyen HAM HTTP istek/yanıtını çıktıya dahil et (-irr).
    # Kurumsal rapor "nuclei bir template eşledi" demez; tetikleyici request/response'u kanıt sunar.
    include_rr: bool = False
    # Türkçe: DAST/aktif fuzzing modu (-dast). Parametre tabanlı enjeksiyon sınıflarını
    # (xss/sqli/ssrf/lfi...) canlı tetikleyerek dener. Agresiftir → yalnız derin/onaylı senaryo.
    dast: bool = False
    # Türkçe: Kimlik doğrulamalı tarama başlıkları. Örn ["Authorization: Bearer xxx",
    # "Cookie: session=abc"]. Login arkasındaki yüzeyi (IDOR, yetki) test edebilmek için.
    custom_headers: List[str] = []
    # Türkçe: URL CORPUS'u (Faz 1: endpoint keşfi). Verilirse nuclei `-u` flag'leri TEK TEK
    # bu URL'ler için üretilir; değerlendirilmesi `target` yerine URL'ler üstünde yapılır.
    # Crawler'ın (orchestrator-yerli endpoint_discovery) bulduğu parametreli endpoint'ler
    # için DAST/sqli/xss/ssrf testi buradan beslenir. Boş ise eski davranış (`target`).
    urls: Optional[List[str]] = None

    @validator('target')
    def validate_target(cls, v):
        """Türkçe: Hedef validasyonu - Command injection önleme için kritik"""
        url_pattern = r'^https?://[a-zA-Z0-9\-\.]+(:[0-9]+)?(/.*)?$'
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$'
        
        if not (re.match(url_pattern, v) or re.match(ip_pattern, v) or re.match(domain_pattern, v)):
            raise ValueError('Geçersiz hedef formatı')
        
        # Türkçe: Shell injection karakterlerini engelle
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>']
        if any(char in v for char in dangerous_chars):
            raise ValueError('Hedefte geçersiz karakterler')
        return v


# Türkçe: Aktif tarama process'lerini takip etmek için global dictionary
scan_processes: Dict[str, subprocess.Popen] = {}
ACTIVE_SCANS_FILE = "/app/logs/active_scans.json"

# Global Cache
TEMPLATES_CACHE = {
    "data": None,
    "last_updated": None,
    "count": 0
}

# Global Template Analyzer
template_analyzer = None

# Periyodik template tazeleme durumu — /health bunu raporlar (bayat kütüphane görünür olsun)
TEMPLATE_UPDATE_HOURS = float(os.getenv("NUCLEI_TEMPLATE_UPDATE_HOURS", "24"))
LAST_TEMPLATE_UPDATE: Optional[datetime] = None
LAST_TEMPLATE_UPDATE_OK: Optional[bool] = None


def _run_template_update() -> bool:
    """Senkron template güncellemesi (thread'de çağrılır). Başarısızlık False döner —
    servis eski kütüphaneyle çalışmaya devam eder, tarama hiç durmaz."""
    try:
        subprocess.run(["nuclei", "-update-templates"], check=True, timeout=600,
                       capture_output=True)
        return True
    except Exception as e:
        logger.warning(f"Template güncellemesi başarısız (eski kütüphane ile devam): {e}")
        return False


async def _template_update_loop():
    """Arka plan döngüsü: başlangıçtan kısa süre sonra ilk güncelleme, sonra her N saatte bir.
    İlk çalıştırma geciktirilir ki servis açılışı template indirmesiyle bloklanmasın.
    İSTİSNA (dürüst-tarama): açılışta kütüphane BOŞ/eksik ise 120sn BEKLEME — kör
    servis zaten işe yaramaz; ilk güncellemeyi hemen başlat (bloklama yok: bu zaten
    arka-plan task'i, açılışı geciktirmez; erken taramalar kapıyı /health'te görür)."""
    global LAST_TEMPLATE_UPDATE, LAST_TEMPLATE_UPDATE_OK
    startup_count = _count_templates()
    if startup_count > 100:
        await asyncio.sleep(120)  # kütüphane dolu — servis önce ayağa kalksın
    else:
        logger.warning(
            f"Kütüphane eksik ({startup_count} template) — ilk güncelleme beklemeden başlıyor."
        )
    while True:
        logger.info("🔄 Periyodik nuclei template güncellemesi başlıyor...")
        ok = await asyncio.to_thread(_run_template_update)
        LAST_TEMPLATE_UPDATE = datetime.utcnow()
        LAST_TEMPLATE_UPDATE_OK = ok
        if ok:
            logger.info(f"✅ Template kütüphanesi tazelendi ({_count_templates()} template).")
            # Template cache'i sıfırla ki /templates yeni kütüphaneyi göstersin
            TEMPLATES_CACHE["data"] = None
            TEMPLATES_CACHE["last_updated"] = None
        await asyncio.sleep(TEMPLATE_UPDATE_HOURS * 3600)

def get_template_analyzer():
    global template_analyzer
    if not template_analyzer:
        template_analyzer = TemplateAnalyzer(TEMPLATES_DIR)
    return template_analyzer

def save_active_scan(scan_id: str, target: str, pid: int, command: List[str] = None, profile: str = "balanced"):
    """Türkçe: Aktif taramayı MongoDB'ye kaydeder (Recovery için)"""
    collection = get_active_scans_collection()
    if collection is None:
        logger.warning(f"MongoDB unavailable, active scan not saved: {scan_id}")
        return
    
    try:
        doc = {
            "scan_id": scan_id,
            "target": target,
            "pid": pid,
            "status": "running",
            "started_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "command": command or [],
            "profile": profile
        }
        # Upsert: varsa güncelle, yoksa ekle
        collection.update_one(
            {"scan_id": scan_id},
            {"$set": doc},
            upsert=True
        )
        logger.info(f"Active scan saved to MongoDB: {scan_id}")
    except Exception as e:
        logger.error(f"Active scan save failed: {e}")


def remove_active_scan(scan_id: str, status: str = "completed"):
    """Türkçe: Aktif taramayı MongoDB'de tamamlandı olarak işaretler"""
    collection = get_active_scans_collection()
    if collection is None:
        return
    
    try:
        collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "status": status,
                "updated_at": datetime.utcnow()
            }}
        )
        logger.info(f"Active scan marked as {status}: {scan_id}")
    except Exception as e:
        logger.error(f"Active scan remove failed: {e}")

@app.on_event("startup")
async def startup_event():
    """Türkçe: Servis başlangıç kontrolleri ve recovery"""
    logger.info("Nuclei Service başlatılıyor...")

    # 1. Template Kontrolü
    if not os.path.exists(TEMPLATES_DIR) or not os.listdir(TEMPLATES_DIR) or not os.path.exists(TEMPLATES_STATS_FILE):
        logger.info("Template'ler bulunamadı veya eksik, indiriliyor...")
        try:
            subprocess.run(["nuclei", "-update-templates"], check=True, timeout=300)
            logger.info("Template download tamamlandı.")
        except Exception as e:
            logger.error(f"Template download failed: {e}")

    # 1c. PERİYODİK TEMPLATE TAZELEME — template'ler yalnız image build'inde güncelleniyordu;
    # arada yayınlanan "güncel CVE" template'leri (ör. yeni WordPress açıkları) servis
    # yeniden build edilene kadar HİÇ yakalanamıyordu. Arka planda her N saatte bir
    # günceller; başarısızlık taramayı etkilemez (eski kütüphane ile devam).
    asyncio.create_task(_template_update_loop())
            
    # 1b. Template SELF-CHECK (K7) — kaç template yüklü? 0 ise servis fiilen KÖR.
    tmpl_count = _count_templates()
    if tmpl_count > 100:
        logger.info(f"✅ Template self-check: {tmpl_count} template yüklü — tarama aktif.")
    else:
        logger.error(
            f"🔴 Template self-check BAŞARISIZ: yalnız {tmpl_count} template bulundu! "
            f"Hedefli CVE taramaları HİÇ eşleşmeyecek — '-update-templates' gerekli. "
            f"Dizin: {TEMPLATES_DIR}"
        )

    # Analyzer'ı başlat (background task olarak)
    try:
        analyzer = get_template_analyzer()
        logger.info("Template Analyzer başlatıldı")
    except Exception as e:
        logger.error(f"Template Analyzer init error: {e}")

    # 2. MongoDB Recovery Mechanism
    collection = get_active_scans_collection()
    if collection is not None:
        logger.info("Önceki oturumdan kalan taramalar kontrol ediliyor (MongoDB)...")
        try:
            # Running durumundaki taramaları bul
            running_scans = list(collection.find({"status": "running"}))
            
            for scan_doc in running_scans:
                scan_id = scan_doc.get("scan_id")
                target = scan_doc.get("target")
                
                logger.warning(f"Kurtarılamayan işlem tespit edildi: {scan_id} (Target: {target})")
                
                # MongoDB'ye error log ekle
                add_log_sync(
                    scan_id=scan_id,
                    level="SCAN_ERROR",
                    message="Servis yeniden başlatıldığı için tarama yarıda kesildi.",
                    data={"reason": "service_restart", "original_target": target}
                )
                
                # Taramayı interrupted olarak işaretle
                collection.update_one(
                    {"scan_id": scan_id},
                    {"$set": {"status": "interrupted", "updated_at": datetime.utcnow()}}
                )
            
            if running_scans:
                logger.info(f"Recovery tamamlandı, {len(running_scans)} tarama interrupted olarak işaretlendi.")
            else:
                logger.info("Kurtarılacak tarama bulunamadı.")
                
        except Exception as e:
            logger.error(f"MongoDB Recovery failed: {e}")
    
    # 3. NucleiLogs için TTL index oluştur (7 gün sonra otomatik sil)
    logs_collection = get_nuclei_logs_collection()
    if logs_collection is not None:
        try:
            logs_collection.create_index("timestamp", expireAfterSeconds=7*24*60*60)
            logs_collection.create_index("scan_id")
            logger.info("NucleiLogs indexleri oluşturuldu (TTL: 7 gün)")
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")


# Türkçe: -irr ile gelen ham request/response gövdeleri çok büyük olabilir (örn. dizin
# listeleyen veya dosya döndüren endpoint). Tek bir FINDING dokümanı MongoDB 16MB BSON
# sınırını aşarsa insert komple başarısız olur ve bulgu sessizce kaybolur. Bu yüzden
# kanıt niteliğini koruyacak ama dokümanı güvende tutacak bir tavan uygulanır.
MAX_PROOF_FIELD_BYTES = int(os.getenv("NUCLEI_MAX_PROOF_BYTES", str(64 * 1024)))  # alan başına 64KB


def _clip_finding_proof(data: Dict) -> Dict:
    """Türkçe: Bir nuclei bulgusundaki büyük kanıt alanlarını (request/response/…) kırpar.
    Orijinali mutasyona uğratmamak için sığ kopya döner; yalnız aşırı büyük alanlar kısalır."""
    if not isinstance(data, dict):
        return data
    clipped = dict(data)
    for field_name in ("request", "response", "interaction", "extracted-results"):
        val = clipped.get(field_name)
        if isinstance(val, str) and len(val) > MAX_PROOF_FIELD_BYTES:
            clipped[field_name] = val[:MAX_PROOF_FIELD_BYTES] + "\n...[truncated]"
    return clipped


def _probe_scheme(target: str, timeout: float = 4.0) -> Optional[str]:
    """Şemasız hedefte hangi şema (https/http) AYAKTA — hızlı tek istekle tespit.

    Amaç: nuclei'yi iki şemayla da taratmaktan kaçınmak (bu SÜREYİ 2'ye katlar → büyük
    hedefte timeout). https öncelikli (kurumsal); yanıt veren ilk şema seçilir. İkisi de
    yanıt vermezse None → çağıran eski 'ikisini de dene' davranışına düşer (güvenli).
    Yalnız bağlantı/HTTP yanıtı yeterli (2xx/3xx/4xx hepsi 'ayakta' sayılır — 401/403 de web'dir).
    """
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "Kadim-Security-Scanner/1.0"})
            urllib.request.urlopen(req, timeout=timeout, context=ctx)
            return scheme
        except urllib.error.HTTPError:
            return scheme  # HTTP hata kodu bile web'in AYAKTA olduğunu gösterir
        except Exception:
            continue
    return None


def _target_urls(target: str) -> List[str]:
    """
    Türkçe: Nuclei hedefine ŞEMA normalize eder — EN KRİTİK DÜZELTME.

    Çıplak `nuclei -u example.com` (şemasız) HTTP template'lerinin ÇOĞUNU çalıştırmaz;
    `https://` varyantını HİÇ denemez. Bu, "motor doğru servisi bulup doğru tag'le nuclei
    çağırıyor ama HİÇBİR bulgu çıkmıyor" durumunun asıl nedeniydi.

    Kural:
      - Hedefte zaten şema varsa → aynen kullan (kullanıcı iradesi).
      - Şemasız → önce hızlı probe ile AYAKTA olan şemayı tespit et, YALNIZ onu tara.
        Bu, taramayı iki şemayla çalıştırmaktan kaçınır (süreyi 2'ye katlıyordu → timeout).
        Probe başarısızsa (ikisi de yanıtsız) güvenli tarafta kalıp ikisini de dener.
    """
    t = target.strip()
    if t.startswith("http://") or t.startswith("https://"):
        return [t]
    live = _probe_scheme(t)
    if live:
        return [f"{live}://{t}"]  # yalnız ayakta olan şema → yarı yarıya süre
    return [f"https://{t}", f"http://{t}"]  # probe belirsiz → güvenli fallback


def build_nuclei_command(request: NucleiScanRequest) -> List[str]:
    """
    Türkçe: Nuclei komutunu oluşturur
    -jsonl: JSONL formatında çıktı (Nuclei v3+)
    -stats: İstatistik bilgisi
    -stats-json: Stats'ı JSON formatında yaz (parse için)
    -duc: Güncel olmayan template uyarısını kapat
    """
    cmd = ["nuclei"]
    # Türkçe: URL CORPUS'u (Faz 1) verildiyse onlar hedef olur (`-u` her biri için tekrar).
    # Verilmezse eski davranış: `target` üzerinden şema-normalize URL'ler. Crawler keşfinden
    # gelen URL'ler zaten tam mutlak (http(s)://), kapsam-by-design host filtresi crawl aşamasında
    # atıldı; güvenlik için burada tekrar same-host zorlamıyoruz ama boş/gecersiz URL'i eliyoruz.
    url_corpus = [u for u in (request.urls or []) if isinstance(u, str) and u.strip()]
    if url_corpus:
        # Türkçe: Çok URL varken tüm template'leri her URL üstünde denemek pahalı; ama bu
        # dışarıdan yetki verilerek çağrıldı (deep/DAST). Nuclei `-u` tekrarlı kabul eder.
        for _u in url_corpus[:500]:
            cmd.extend(["-u", _u.strip()])
    else:
        # ŞEMA NORMALİZASYONU (K1): şemasız hedefe https:// + http:// olarak, şemalıysa aynen.
        for _u in _target_urls(request.target):
            cmd.extend(["-u", _u])
    cmd += [
        "-jsonl",  # JSONL output for parsing (Nuclei v3+)
        "-rate-limit", str(request.rate_limit),
        "-c", str(max(1, min(request.concurrency, 200))),   # eşzamanlı template (sınırlı)
        "-bulk-size", str(max(1, min(request.bulk_size, 200))),  # host başına paralel istek
        "-timeout", str(request.timeout),
        "-retries", str(request.retries),
        "-stats",
        "-stats-json",  # Stats'ı JSON formatında yaz
        "-v",           # Verbose output for AI analysis
        "-no-color",
        "-duc",  # Disable update check
        "-si", "2",  # Stats interval 2 saniye (daha hızlı feedback)
        # Türkçe: Gerçekten GÜRÜLTÜ üreten klasörleri hariç tut (K3 düzeltmesi).
        # ÖNCEDEN 'http/miscellaneous/', 'http/technologies/', 'http/exposed-panels/detect-'
        # ve 'ssl/' TOPTAN dışlanıyordu → açık panel/exposure/misconfig bulguları da eziliyordu.
        # Artık yalnız gerçek FP kaynağı olan global-matchers + waf-detect dışlanır; exposed-panels
        # ve exposures açık kalır (bankada en sık gerçek bulgu sınıfı).
        "-exclude-templates", "http/global-matchers/",
        "-exclude-templates", "http/miscellaneous/waf-detect.yaml",
        "-exclude-templates", "http/miscellaneous/global-waf-detect.yaml",
        # Türkçe: Gürültü tag'leri (waf/fingerprint/tech-detect/cdn-detect) hariç.
        # ÖNCEDEN 'panel','generic','wordpress','joomla','drupal' de dışlanıyordu → açık admin
        # panelleri ve exposure template'lerini kör ediyordu. Bunlar KALDIRILDI: panel/generic
        # gerçek bulgu üretir; CMS tag'leri (wordpress/joomla/drupal) hedefli tarama için gerekli.
        "-exclude-tags", "waf,fingerprint,tech-detect,cdn-detect",
    ]

    # Türkçe: KANIT modu — tetikleyen HAM istek/yanıtı JSONL çıktısına dahil et.
    # Bu sayede _collect_evidence gerçek HTTP kanıtı (request/response/curl) toplayabilir.
    # NOT (nuclei 3.11.1): -irr deprecated oldu ve request/response artık JSONL bulgularında
    # VARSAYILAN olarak dahil (eski 3.3.5'te varsayılan kapalıydı). Eski davranışı birebir
    # korumak için kanıt istenmediyse -omit-raw ile açıkça kapatıyoruz — aksi halde her bulgu
    # ham gövde taşır, MongoDB dokümanları şişer ve tarama çıktısı ağırlaşır.
    if request.include_rr:
        cmd.append("-irr")  # -include-rr: her bulguya request+response ekle (3.11.1'de hâlâ geçerli alias)
    else:
        cmd.append("-omit-raw")  # 3.11.1'in yeni varsayılanını eski davranışa çevir

    # Türkçe: DAST/aktif fuzzing modu — parametre tabanlı enjeksiyon (xss/sqli/ssrf/lfi...).
    # Yalnız üst katmandan bilinçli açıldığında (derin/onaylı) devreye girer.
    if request.dast:
        cmd.append("-dast")

    # Profile Specific Settings
    if request.profile == "stealth":
        # Stealth modu: Yaygın browser UA kullan, delay ekle
        cmd.extend([
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "-H", "Accept-Language: en-US,en;q=0.5",
            "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ])
    else:
        # Default user agent for non-stealth
        cmd.extend(["-H", "User-Agent: Kadim-Security-Scanner/1.0"])
    
    # Türkçe: Severity filtreleme - virgülle ayrılmış tek parametre
    if request.severity:
        valid_severities = [s for s in request.severity if s in ['critical', 'high', 'medium', 'low', 'info']]
        if valid_severities:
            cmd.extend(["-severity", ",".join(valid_severities)])
    
    # Türkçe: Özel template seçimi
    if request.templates:
        for template in request.templates:
            # Güvenlik: Template path'i sanitize et
            if '..' not in template and not template.startswith('/'):
                cmd.extend(["-t", template])
    
    # Türkçe: Tag filtreleme
    if request.tags:
        for tag in request.tags:
            if re.match(r'^[a-zA-Z0-9\-_]+$', tag):
                cmd.extend(["-tags", tag])

    # Türkçe: Çağrandan gelen ek exclude-tags'i UYGULA. Sabit exclude listesine ek olarak
    # nuclei birden çok -exclude-tags kabul eder. Böylece üst katmanın kararı (örn. DAST'ta
    # 'fuzz' HARİÇ TUTULMASIN, normal taramada tutulsun) gerçekten etki eder — sessizce yutulmaz.
    valid_exclude = [t for t in (request.exclude_tags or []) if re.match(r'^[a-zA-Z0-9\-_]+$', t)]
    if valid_exclude:
        cmd.extend(["-exclude-tags", ",".join(valid_exclude)])

    # Türkçe: Kimlik doğrulamalı tarama başlıkları (-H). Her başlık "Ad: değer" biçiminde.
    # Shell'e değil, argv listesine eklenir (subprocess list exec) → enjeksiyon yüzeyi yok.
    # Yine de kontrol/satır sonu karakterlerini ve ':' eksikliğini eleyerek savun.
    # ÇAKIŞMA: komut zaten varsayılan bir User-Agent -H içeriyor; aynı adlı başlığı ikinci
    # kez eklemeyiz (mevcut kazanır) — aksi halde iki User-Agent flag'i belirsizlik yaratır.
    existing_header_names = {
        cmd[i + 1].split(":", 1)[0].strip().lower()
        for i in range(len(cmd) - 1)
        if cmd[i] == "-H" and ":" in cmd[i + 1]
    }
    for header in (request.custom_headers or []):
        if not isinstance(header, str) or ":" not in header:
            continue
        if any(ch in header for ch in ("\n", "\r", "\x00")):
            continue
        name = header.split(":", 1)[0].strip().lower()
        if not name or name in existing_header_names:
            continue
        existing_header_names.add(name)
        cmd.extend(["-H", header])

    return cmd


def _count_templates() -> int:
    """Türkçe: Template dizinindeki .yaml sayısını döner (self-check, K7).
    0 dönerse hedefli -t CVE taramaları sessizce eşleşmez → bunu görünür yaparız."""
    try:
        n = 0
        for _root, _dirs, _files in os.walk(TEMPLATES_DIR):
            n += sum(1 for f in _files if f.endswith(".yaml"))
        return n
    except Exception:
        return -1


@app.get("/health")
async def health_check():
    """Türkçe: Servis sağlık kontrolü + template self-check (K7).

    Template sayısı 0 ise servis "healthy" ama fiilen KÖR demektir (hedefli CVE
    taramaları hiç eşleşmez). Bunu health çıktısında `templates_ok` ile açıkça bildiririz;
    böylece "tarama çalışıyor ama hiç bulmuyor" durumu sessiz kalmaz."""
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        version = result.stdout.strip() or result.stderr.strip()
        tmpl_count = _count_templates()
        return {
            "status": "healthy",
            "service": "nuclei-service",
            "nuclei_version": version,
            "templates_dir": TEMPLATES_DIR,
            "templates_count": tmpl_count,
            # Kurumsal görünürlük: template yoksa/az ise tarama fiilen kör.
            "templates_ok": tmpl_count > 100,
            # Tazelik görünürlüğü: "güncel CVE template'i var mı?" sorusunun cevabı.
            "templates_last_update": LAST_TEMPLATE_UPDATE.isoformat() if LAST_TEMPLATE_UPDATE else None,
            "templates_last_update_ok": LAST_TEMPLATE_UPDATE_OK,
            "template_update_interval_hours": TEMPLATE_UPDATE_HOURS,
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")


@app.get("/config")
async def get_nuclei_config():
    """Türkçe: Nuclei yapılandırma bilgilerini döner - Frontend için"""
    try:
        # TEMPLATES-STATS.json dosyasından gerçek istatistikleri al
        stats = {}
        if os.path.exists(TEMPLATES_STATS_FILE):
            with open(TEMPLATES_STATS_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
                # JSON dosyasının başındaki gereksiz karakterleri temizle
                start = content.find('{')
                if start != -1:
                    stats = json.loads(content[start:])
        
        # Türkçe: Severity bazlı istatistikler
        severity_stats = {item['name']: item['count'] for item in stats.get('severity', [])}
        
        return {
            "categories": [
                {
                    "id": "cve",
                    "name": "CVE Zafiyetleri",
                    "description": "Bilinen CVE zafiyetlerini tara",
                    "template_count": severity_stats.get('critical', 0) + severity_stats.get('high', 0)
                },
                {
                    "id": "misconfiguration",
                    "name": "Yanlış Yapılandırmalar",
                    "description": "Güvenlik yapılandırma hatalarını tespit et",
                    "template_count": 500
                },
                {
                    "id": "exposed-panels",
                    "name": "Açık Paneller",
                    "description": "Admin panelleri ve login sayfaları",
                    "template_count": 300
                },
                {
                    "id": "technologies",
                    "name": "Teknoloji Tespiti",
                    "description": "Kullanılan teknolojileri belirle",
                    "template_count": 400
                },
                {
                    "id": "vulnerabilities",
                    "name": "Genel Zafiyetler",
                    "description": "XSS, SQLi, LFI gibi zafiyetleri tara",
                    "template_count": 1000
                },
                {
                    "id": "exposures",
                    "name": "Veri Sızıntıları",
                    "description": "Açık dosyalar ve hassas bilgiler",
                    "template_count": 200
                }
            ],
            "severities": [
                {"id": "critical", "name": "Critical", "count": severity_stats.get('critical', 0)},
                {"id": "high", "name": "High", "count": severity_stats.get('high', 0)},
                {"id": "medium", "name": "Medium", "count": severity_stats.get('medium', 0)},
                {"id": "low", "name": "Low", "count": severity_stats.get('low', 0)},
                {"id": "info", "name": "Info", "count": severity_stats.get('info', 0)}
            ],
            "total_templates": sum(severity_stats.values()),
            "templates_dir": TEMPLATES_DIR
        }
    except Exception as e:
        logger.error(f"Config error: {e}")
        # Fallback config
        return {
            "categories": [
                {"id": "cve", "name": "CVE Zafiyetleri", "description": "Bilinen CVE zafiyetlerini tara", "template_count": 2000},
                {"id": "misconfiguration", "name": "Yanlış Yapılandırmalar", "description": "Güvenlik yapılandırma hatalarını tespit et", "template_count": 500},
            ],
            "severities": [
                {"id": "critical", "name": "Critical", "count": 1500},
                {"id": "high", "name": "High", "count": 2500},
                {"id": "medium", "name": "Medium", "count": 2500},
                {"id": "low", "name": "Low", "count": 350},
                {"id": "info", "name": "Info", "count": 4400}
            ],
            "total_templates": 11000
        }


@app.get("/tags")
async def list_tags():
    """
    Türkçe: Nuclei template tag listesini döner
    nuclei -tgl komutu ile gerçek tag listesini alır
    """
    try:
        logger.info("Tag listesi yükleniyor...")
        
        # Türkçe: nuclei komutu ile tag listesini al
        cmd = ["nuclei", "-tgl", "-silent"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        tags = []
        
        if result.returncode == 0 and result.stdout:
            # Her satır bir tag içerir
            raw_tags = result.stdout.strip().splitlines()
            # Temizle ve unique yap
            tags = sorted(list(set([t.strip() for t in raw_tags if t.strip() and len(t.strip()) > 1])))
            logger.info(f"Toplam {len(tags)} tag bulundu")
        else:
            # Fallback tags
            logger.warning("Tag listesi alınamadı, fallback kullanılıyor")
            tags = [
                "cve", "cve2023", "cve2024", "rce", "lfi", "xss", "sqli", 
                "ssrf", "idor", "auth-bypass", "panel", "login", "exposure",
                "misconfig", "default-login", "tech", "wordpress", "joomla",
                "apache", "nginx", "iis", "tomcat", "jenkins", "gitlab",
                "kubernetes", "docker", "aws", "azure", "gcloud", "api",
                "graphql", "jwt", "oauth", "saml", "upload", "deserialization",
                "xxe", "ssti", "crlf", "open-redirect", "cors", "takeover"
            ]
        
        return {
            "count": len(tags),
            "tags": tags
        }
        
    except subprocess.TimeoutExpired:
        logger.error("Tag listesi timeout")
        return {"count": 0, "tags": [], "error": "timeout"}
    except Exception as e:
        logger.error(f"Tag list error: {str(e)}")
        return {"count": 0, "tags": [], "error": str(e)}

@app.get("/templates")
async def list_templates(refresh: bool = False):
    """
    Türkçe: Template listesini döner
    nuclei -tl komutu ile gerçek template listesini alır
    Cache mekanizması eklendi.
    """
    global TEMPLATES_CACHE
    
    # Cache geçerli mi?
    if not refresh and TEMPLATES_CACHE["data"] and TEMPLATES_CACHE["count"] > 0:
        logger.info("Template listesi cache'den dönülüyor")
        return {
            "count": TEMPLATES_CACHE["count"],
            "templates": TEMPLATES_CACHE["data"]
        }

    try:
        logger.info("Template listesi yükleniyor (Source: Disk)...")
        
        # Türkçe: nuclei -tl komutu ile template yollarını al
        cmd = ["nuclei", "-tl", "-silent"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        templates = []
        
        if result.returncode == 0 and result.stdout:
            template_paths = result.stdout.strip().splitlines()
            logger.info(f"Toplam {len(template_paths)} template path bulundu")
            
            # Türkçe: Her template için metadata çıkar
            for path in template_paths:
                if not path.strip():
                    continue
                    
                # Path'den template bilgilerini çıkar
                # Örnek: http/cves/2023/CVE-2023-26035.yaml
                parts = path.strip().split('/')
                
                # Severity tahmini yap (path'e göre)
                severity = "info"
                if "cves" in path.lower() or "vulnerabilities" in path.lower():
                    severity = "high"
                elif "critical" in path.lower():
                    severity = "critical"
                elif "misconfig" in path.lower():
                    severity = "medium"
                elif "exposure" in path.lower():
                    severity = "medium"
                elif "panel" in path.lower() or "detect" in path.lower():
                    severity = "info"
                
                # Template ID'yi dosya adından çıkar
                filename = parts[-1].replace('.yaml', '') if parts else path
                
                # Kategori çıkar
                category = parts[0] if len(parts) > 0 else "other"
                
                # Tags oluştur
                tags = [p for p in parts[:-1] if p and len(p) < 30]
                
                templates.append({
                    "id": filename,
                    "name": filename.replace('-', ' ').replace('_', ' ').title(),
                    "description": f"Template: {path}",
                    "severity": severity,
                    "tags": tags,
                    "path": path,
                    "category": category
                })
        
        logger.info(f"Toplam {len(templates)} template döndürülüyor")
        
        # Türkçe: Severity'ye göre sırala (critical > high > medium > low > info)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        templates.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
        
        # Cache'i güncelle
        TEMPLATES_CACHE = {
            "data": templates,
            "last_updated": datetime.now().isoformat(),
            "count": len(templates)
        }
        
        return {
            "count": len(templates),
            "templates": templates
        }
        
    except subprocess.TimeoutExpired:
        logger.error("Template listesi timeout")
        raise HTTPException(status_code=504, detail="Template listesi zaman aşımına uğradı")
    except Exception as e:
        logger.error(f"Template list error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Template listesi alınamadı: {str(e)}")
@app.post("/templates/update")
async def update_templates():
    """
    Türkçe: Manuel template güncelleme ve cache yenileme
    """
    try:
        logger.info("Template güncelleme başlatıldı...")
        
        # 1. Update komutunu çalıştır
        process = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if process.returncode != 0:
            raise Exception(f"Update failed: {process.stderr}")
            
        logger.info("Nuclei templates updated successfully")
        
        # 2. Cache'i yenile (Force refresh)
        # Background task olarak değil, senkron yapalım ki sonucu görelim (veya background yapılabilir ama user bekliyor)
        # Sadece cache'i invalid edelim, bir sonraki istekte dolsun
        global TEMPLATES_CACHE
        TEMPLATES_CACHE = {"data": None, "last_updated": None, "count": 0}
        
        # Veya hemen dolduralım:
        await list_templates(refresh=True)
        
        return {
            "status": "success", 
            "message": "Templates updated and cache refreshed",
            "output": process.stdout
        }
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Template update timed out")
    except Exception as e:
        logger.error(f"Template update error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/templates/analysis")
async def get_template_analysis(template_id: Optional[str] = None):
    """
    Türkçe: Template analiz raporu döner
    Eğer template_id verilirse sadece o template'in analizini döner
    """
    analyzer = get_template_analyzer()
    if template_id:
        # Cache'den veya direkt analiz et
        # Not: TemplateAnalyzer.get_analysis şimdilik sadece cache'ten dönüyor
        # TODO: Analyzer'a get_or_analyze metodu ekle
        res = analyzer.get_analysis(template_id)
        if not res:
            # Bulunamadıysa path bulup analiz etmeyi dene (karmaşık olabilir)
            # Şimdilik analyze_all çağrılmadıysa boş dönebilir
            pass
        return res or {"error": "Analysis not found"}
    
    # Tüm analizleri dön (Cache'den)
    return analyzer.cache

@app.post("/templates/analyze")
async def trigger_analysis_task(background_tasks: BackgroundTasks = None):
    """
    Türkçe: Tüm template'lerin analizini tetikler (Background)
    """
    analyzer = get_template_analyzer()
    
    # Background task yerine şimdilik senkron çalıştıralım veya Thread
    # Basitlik için burada senkron (dikkat: uzun sürebilir)
    # Production için background task şart.
    
    # Hızlıca cache dönelim, arka planda update edelim
    import threading
    def run_analysis():
        logger.info("Template analizi başlatılıyor...")
        results = analyzer.analyze_all()
        logger.info(f"Template analizi tamamlandı. {len(results)} template tarandı.")
        
    threading.Thread(target=run_analysis).start()
    
    return {"status": "started", "message": "Analysis started in background"}

@app.post("/scan")
async def start_nuclei_scan(request: NucleiScanRequest):
    """
    Türkçe: Nuclei taramasını başlatır
    Tarama arka planda çalışır ve MongoDB'ye log yazar
    """
    try:
        logger.info(f"Nuclei scan başlatılıyor: {request.scan_id} -> {request.target}")
        
        cmd = []
        
        try:
            # Türkçe: Rate limit minimum kontrolü
            if request.rate_limit < 10:
                request.rate_limit = 150
                
            cmd = build_nuclei_command(request)
            logger.info(f"Komut: {' '.join(cmd)}")
            
            # Template Reliability ve Risk Kontrolü
            analyzer = get_template_analyzer()
            warnings = []
            if request.templates:
                for t in request.templates:
                     tid = os.path.basename(t).replace('.yaml', '')
                     analysis = analyzer.get_analysis(tid)
                     
                     if not analysis:
                         full_path = ""
                         if t.startswith("/"): full_path = t
                         else: full_path = os.path.join(TEMPLATES_DIR, t)
                         
                         if os.path.exists(full_path):
                             analysis = analyzer.analyze_template(full_path)
                     
                     if analysis:
                         score = analysis.get('reliability_score', 50)
                         risk = analysis.get('fp_risk_score', 50)
                         
                         if score < 40:
                             warnings.append(f"WARNING: Template '{tid}' has LOW reliability (Score: {score})")
                         if risk > 80:
                             warnings.append(f"WARNING: Template '{tid}' has HIGH FP risk (Score: {risk})")

            # Türkçe: MongoDB'ye SCAN_START logları yaz
            add_log_sync(request.scan_id, "SCAN_START", f"Tarama başlatıldı: {request.target}", {
                "target": request.target,
                "command": ' '.join(cmd),
                "severity": request.severity or ["all"],
                "tags": request.tags or ["all"],
                "profile": request.profile
            })
            
            for warn in warnings:
                add_log_sync(request.scan_id, "WARNING", warn)
            
            # Türkçe: Arka planda çalıştır - PIPE ile çıktıyı yakala
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                # KRİTİK (nuclei-boş/timeout): text=True varsayılanı 'strict' decode eder.
                # Nuclei çıktısı, taranan hedefin banner/HTTP yanıt/sertifika alanlarından
                # gelen UTF-8 OLMAYAN byte'lar içerebilir (ör. 0xd7 — Latin-1/CP1254). Bu
                # durumda proc.stdout.readline() UnicodeDecodeError fırlatıp stream thread'ini
                # çökertiyordu → tarama 'failed', HİÇ bulgu toplanmadan; orchestrator poll'u da
                # completed/failed göremeyip 600s timeout'a düşüyordu (UI'da "boş/timeout").
                # errors='replace' ile geçersiz byte'lar '�' olur, JSONL akışı kesintisiz sürer.
                errors="replace",
                bufsize=1  # Line buffered
            )
            
            # Türkçe: Process'i kaydet
            scan_processes[request.scan_id] = process
            
            logger.info(f"Scan başlatıldı: {request.scan_id}, PID: {process.pid}")
            
            # Recovery için MongoDB'ye kaydet
            save_active_scan(request.scan_id, request.target, process.pid, cmd, request.profile)
            
            # Türkçe: Background thread ile çıktıyı MongoDB'ye aktar
            import threading
            def stream_output_to_mongodb(proc, scan_id):
                try:
                    for line in iter(proc.stdout.readline, ''):
                        if not line:
                            break
                        raw_line = line.strip()
                        if not raw_line:
                            continue
                        
                        # Türkçe: Ham satırı her zaman sakla (AI analizi için)
                        # JSON finding tespit et
                        if raw_line.startswith('{'):
                            try:
                                data = json.loads(raw_line)
                                if 'matched-at' in data:
                                    # Türkçe: TÜM bulguları kaydet - FP filtresi KALDIRILDI
                                    # AI analizi için ham veri gerekli. -irr kanıt gövdeleri
                                    # 16MB doküman sınırını aşmasın diye alan başına kırpılır.
                                    safe_data = _clip_finding_proof(data)
                                    add_log_sync(scan_id, "FINDING", safe_data.get("info", {}).get("name", safe_data.get("template-id", "unknown")), {
                                        "template_id": safe_data.get("template-id"),
                                        "severity": safe_data.get("info", {}).get("severity", "info"),
                                        "matched_at": safe_data.get("matched-at"),
                                        "host": safe_data.get("host"),
                                        "raw": safe_data,  # Tam JSON verisi (büyük kanıt alanları kırpılmış)
                                        "raw_line": raw_line[:MAX_PROOF_FIELD_BYTES]  # Ham satır (tavanlı)
                                    })
                                elif 'requests' in data and 'total' in data:
                                    # Progress stats
                                    add_log_sync(scan_id, "PROGRESS", "Tarama ilerliyor", {
                                        "requests_done": data.get("requests", 0),
                                        "requests_total": data.get("total", 0),
                                        "matched": data.get("matched", 0),
                                        "errors": data.get("errors", 0),
                                        "rps": data.get("rps", 0),
                                        "raw_line": raw_line
                                    })
                                else:
                                    # Diğer JSON çıktıları
                                    add_log_sync(scan_id, "JSON", raw_line, {"raw": data, "raw_line": raw_line})
                            except json.JSONDecodeError:
                                add_log_sync(scan_id, "LOG", raw_line, {"raw_line": raw_line})
                        elif raw_line.startswith('['):
                            add_log_sync(scan_id, "INFO", raw_line, {"raw_line": raw_line})
                        else:
                            add_log_sync(scan_id, "LOG", raw_line, {"raw_line": raw_line})
                    
                    # Process tamamlandı
                    exit_code = proc.wait()
                    add_log_sync(scan_id, "SCAN_END", f"Tarama tamamlandı (exit: {exit_code})", {
                        "exit_code": exit_code
                    })
                    remove_active_scan(scan_id, "completed" if exit_code == 0 else "failed")
                    
                except Exception as e:
                    logger.error(f"Stream error for {scan_id}: {e}")
                    add_log_sync(scan_id, "ERROR", f"Stream error: {str(e)}")
                    remove_active_scan(scan_id, "failed")
            
            threading.Thread(target=stream_output_to_mongodb, args=(process, request.scan_id), daemon=True).start()
            
            return {
                "scan_id": request.scan_id,
                "status": "started",
                "message": "Tarama arka planda başlatıldı (MongoDB logging)",
                "pid": process.pid
            }

        except Exception as inner_e:
            error_msg = f"Startup Error: {str(inner_e)}"
            logger.error(error_msg)
            add_log_sync(request.scan_id, "ERROR", error_msg)
            add_log_sync(request.scan_id, "SCAN_END", "Tarama başlatılamadı", {"error": str(inner_e)})
            raise inner_e

    except Exception as e:
        logger.error(f"Scan start error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status/{scan_id}")
async def check_scan_status(scan_id: str):
    """Türkçe: Tarama durumunu kontrol eder (MongoDB)"""
    
    # 1. Memory'deki process'i kontrol et
    process = scan_processes.get(scan_id)
    
    if process:
        poll = process.poll()
        if poll is None:
            return {"status": "running", "pid": process.pid}
        else:
            # Türkçe: Tamamlandı, memory'den temizle
            del scan_processes[scan_id]
            # Not: remove_active_scan zaten stream_output_to_mongodb tarafından çağrılıyor
            return {"status": "completed", "exit_code": poll}
    
    # 2. MongoDB'den kontrol et
    collection = get_active_scans_collection()
    if collection is not None:
        try:
            scan_doc = collection.find_one({"scan_id": scan_id})
            if scan_doc:
                status = scan_doc.get("status", "unknown")
                return {
                    "status": status,
                    "target": scan_doc.get("target"),
                    "started_at": scan_doc.get("started_at").isoformat() if scan_doc.get("started_at") else None
                }
        except Exception as e:
            logger.error(f"MongoDB status check error: {e}")
    
    # 3. Logs collection'da var mı kontrol et
    logs_collection = get_nuclei_logs_collection()
    if logs_collection is not None:
        try:
            scan_end = logs_collection.find_one({"scan_id": scan_id, "level": "SCAN_END"})
            if scan_end:
                return {"status": "completed"}
            
            scan_start = logs_collection.find_one({"scan_id": scan_id, "level": "SCAN_START"})
            if scan_start:
                return {"status": "unknown", "message": "Scan started but no end record found"}
        except Exception as e:
            logger.error(f"MongoDB logs check error: {e}")
        
    return {"status": "not_found"}


@app.get("/logs/{scan_id}")
async def get_scan_log(scan_id: str):
    """Türkçe: MongoDB'den tarama loglarını döner - FP filtreleme ile"""
    
    collection = get_nuclei_logs_collection()
    if collection is None:
        raise HTTPException(status_code=503, detail="MongoDB bağlantısı yok")
    
    try:
        # Türkçe: scan_id'ye ait tüm logları çek
        logs_cursor = collection.find(
            {"scan_id": scan_id}
        ).sort("timestamp", 1)
        
        raw_logs = list(logs_cursor)
        
        if not raw_logs:
            raise HTTPException(status_code=404, detail="Log bulunamadı")
        
        # Türkçe: Log içeriğini backward compat için string olarak da oluştur
        log_lines = []
        findings = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        serialized_logs = []
        
        for log in raw_logs:
            level = log.get("level", "LOG")
            message = log.get("message", "")
            data = log.get("data", {})
            timestamp = log.get("timestamp")
            ts_str = timestamp.isoformat() if timestamp else ""
            
            # Log satırı oluştur
            log_lines.append(f"[{level}] {ts_str} - {message}")
            
            # FINDING ise findings listesine ekle
            if level == "FINDING":
                raw = data.get("raw", {})
                if raw:
                    findings.append(raw)
                    sev = data.get("severity", "info")
                    if sev in severity_counts:
                        severity_counts[sev] += 1
            
            # Türkçe: Serialize edilebilir log objesi oluştur
            serialized_logs.append({
                "id": str(log.get("_id", "")),
                "scan_id": log.get("scan_id", ""),
                "level": level,
                "message": message,
                "timestamp": ts_str,
                "data": data,
                "raw_line": data.get("raw_line", message)  # Ham Nuclei çıktısı
            })
            
            # Ham satırları topla (AI analizi için)
            raw_line = data.get("raw_line", message)
            if raw_line:
                log_lines.append(raw_line)
        
        # Türkçe: Ham log content (Nuclei çıktısı olduğu gibi)
        raw_log_content = "\n".join([
            log.get("data", {}).get("raw_line", log.get("message", ""))
            for log in raw_logs
            if log.get("data", {}).get("raw_line") or log.get("message")
        ])
        
        return {
            "scan_id": scan_id,
            "log_content": raw_log_content,  # Ham Nuclei çıktısı (AI için)
            "file_size": len(raw_log_content),
            "findings": findings,
            "findings_count": len(findings),
            "raw_findings_count": len(findings),
            "filtered_count": 0,
            "severity_counts": severity_counts,
            "logs": serialized_logs,
            "total_logs": len(serialized_logs),
            "raw_log_content": raw_log_content  # Açık alan adı
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MongoDB log read error: {e}")
        raise HTTPException(status_code=500, detail=f"Log okunamadı: {str(e)}")


@app.get("/active-scans")
async def get_active_scans():
    """Türkçe: Aktif taramaların listesini döner (MongoDB + Memory)"""
    active = []
    
    # 1. Memory'deki process'leri kontrol et
    for scan_id, process in list(scan_processes.items()):
        if process.poll() is None:
            # MongoDB'den hedef bilgisini al
            collection = get_active_scans_collection()
            target = "unknown"
            if collection:
                try:
                    doc = collection.find_one({"scan_id": scan_id})
                    if doc:
                        target = doc.get("target", "unknown")
                except:
                    pass
            
            active.append({
                "scan_id": scan_id,
                "target": target,
                "pid": process.pid,
                "status": "running"
            })
        else:
            # Türkçe: Biten process'leri temizle
            del scan_processes[scan_id]
    
    return {"active_scans": active, "count": len(active)}


@app.delete("/scan/{scan_id}")
async def stop_scan(scan_id: str):
    """Türkçe: Çalışan taramayı durdurur"""
    process = scan_processes.get(scan_id)
    
    if process and process.poll() is None:
        process.terminate()
        
        # Türkçe: Nazik kapatma için bekle
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        
        # MongoDB'ye kaydet
        add_log_sync(scan_id, "SCAN_STOPPED", "Kullanıcı tarafından durduruldu")
        
        del scan_processes[scan_id]
        remove_active_scan(scan_id, "stopped")
        logger.info(f"Scan durduruldu: {scan_id}")
        
        return {"status": "stopped", "scan_id": scan_id}
    
    raise HTTPException(status_code=404, detail="Aktif tarama bulunamadı")


@app.websocket("/ws/monitor/{scan_id}")
async def websocket_monitor(websocket: WebSocket, scan_id: str):
    """
    Türkçe: WebSocket ile tarama izleme
    MongoDB NucleiLogs koleksiyonundan real-time polling ile frontend'e gönderir
    """
    await websocket.accept()
    logger.info(f"WebSocket bağlantısı kabul edildi: {scan_id}")
    
    try:
        collection = get_nuclei_logs_collection()
        if collection is None:
            await websocket.send_json({
                "type": "error",
                "message": "MongoDB bağlantısı yok"
            })
            return
        
        # Türkçe: İlk log kaydının gelmesini bekle (max 10 saniye)
        wait_count = 0
        while True:
            first_log = collection.find_one({"scan_id": scan_id})
            if first_log:
                break
            if wait_count > 100:  # 10 saniye
                await websocket.send_json({
                    "type": "error",
                    "message": "Tarama logu bulunamadı - tarama başlatılmamış olabilir"
                })
                return
            await asyncio.sleep(0.1)
            wait_count += 1
        
        # Türkçe: Bağlantı başarılı mesajı
        await websocket.send_json({
            "type": "status",
            "message": "Bağlantı kuruldu, tarama izleniyor..."
        })
        
        # Türkçe: MongoDB polling - son işlenen log _id'sini tut (ObjectId sıralı)
        last_id = None
        no_data_count = 0
        
        while True:
            try:
                # Yeni logları çek - _id bazlı (ObjectId zaman damgası içerir)
                query = {"scan_id": scan_id}
                if last_id:
                    query["_id"] = {"$gt": last_id}
                
                new_logs = list(collection.find(query).sort("_id", 1).limit(50))
                
                if new_logs:
                    no_data_count = 0
                    
                    for log in new_logs:
                        last_id = log.get("_id")  # ObjectId - sıralı
                        level = log.get("level", "LOG")
                        message = log.get("message", "")
                        data = log.get("data", {})
                        timestamp = log.get("timestamp")
                        
                        if level == "FINDING":
                            raw = data.get("raw", {})
                            finding = {
                                "type": "finding",
                                "template_id": data.get("template_id", "unknown"),
                                "name": message,
                                "severity": data.get("severity", "info"),
                                "matched_at": data.get("matched_at", ""),
                                "host": data.get("host", ""),
                                "timestamp": timestamp.isoformat() if timestamp else "",
                                "raw": raw
                            }
                            await websocket.send_json(finding)
                            
                        elif level == "PROGRESS":
                            # Türkçe: Tip güvenliği - MongoDB'den gelen değerler string olabilir
                            req_done = int(data.get("requests_done", 0) or 0)
                            req_total = int(data.get("requests_total", 0) or 0)
                            progress_pct = round((req_done / max(req_total, 1)) * 100, 2) if req_total > 0 else 0
                            progress_data = {
                                "type": "progress",
                                "requests_done": req_done,
                                "requests_total": req_total,
                                "matched": int(data.get("matched", 0) or 0),
                                "errors": int(data.get("errors", 0) or 0),
                                "rps": int(data.get("rps", 0) or 0),
                                "progress_percent": progress_pct
                            }
                            await websocket.send_json(progress_data)
                            
                        elif level == "SCAN_END":
                            await websocket.send_json({
                                "type": "completed",
                                "message": message,
                                "exit_code": data.get("exit_code", 0)
                            })
                            return
                            
                        elif level == "SCAN_STOPPED":
                            await websocket.send_json({
                                "type": "stopped",
                                "message": message
                            })
                            return
                            
                        elif level == "ERROR":
                            await websocket.send_json({
                                "type": "error",
                                "message": message
                            })
                            
                        elif level == "SCAN_START":
                            await websocket.send_json({
                                "type": "info",
                                "message": f"[SCAN_START] {message}",
                                "data": data
                            })
                            
                        else:
                            # LOG, INFO, WARNING
                            await websocket.send_json({
                                "type": "log" if level == "LOG" else "info",
                                "message": message
                            })
                else:
                    no_data_count += 1
                    
                    # Türkçe: Process durumunu kontrol et
                    process = scan_processes.get(scan_id)
                    if process and process.poll() is not None:
                        # Process bitti - son SCAN_END var mı kontrol et
                        scan_end = collection.find_one({"scan_id": scan_id, "level": "SCAN_END"})
                        if scan_end:
                            await websocket.send_json({
                                "type": "completed",
                                "message": "Tarama tamamlandı",
                                "exit_code": scan_end.get("data", {}).get("exit_code", 0)
                            })
                        else:
                            await websocket.send_json({
                                "type": "completed",
                                "message": "Tarama tamamlandı",
                                "exit_code": process.poll()
                            })
                        return
                    
                    # Türkçe: Çok uzun süre veri gelmezse timeout
                    if no_data_count > 600:  # 60 saniye
                        active_collection = get_active_scans_collection()
                        if active_collection:
                            scan_doc = active_collection.find_one({"scan_id": scan_id})
                            if scan_doc and scan_doc.get("status") != "running":
                                await websocket.send_json({
                                    "type": "completed",
                                    "message": f"Tarama {scan_doc.get('status')}"
                                })
                                return
                
                await asyncio.sleep(0.2)  # 200ms polling interval
                
            except Exception as read_error:
                import traceback
                logger.error(f"MongoDB polling hatası: {read_error}\n{traceback.format_exc()}")
                await asyncio.sleep(0.5)
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket bağlantısı kesildi: {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket hatası: {str(e)}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": str(e)
            })
        except:
            pass


def parse_nuclei_stats(line: str) -> Optional[Dict]:
    """
    Türkçe: Nuclei stats satırını parse eder
    Örnek girdi: "[INF] Templates: 100/11287 (0.89%) | Hosts: 1 | RPS: 150 | Matched: 3 | Errors: 0 | Requests: 450/10000"
    """
    try:
        stats = {}
        
        # Templates: 100/11287 (0.89%)
        templates_match = re.search(r'Templates:\s*(\d+)/(\d+)\s*\(([\d.]+)%\)', line)
        if templates_match:
            stats['templates_done'] = int(templates_match.group(1))
            stats['templates_total'] = int(templates_match.group(2))
            stats['progress_percent'] = float(templates_match.group(3))
        
        # RPS (Requests Per Second)
        rps_match = re.search(r'RPS:\s*(\d+)', line)
        if rps_match:
            stats['rps'] = int(rps_match.group(1))
        
        # Matched (findings count)
        matched_match = re.search(r'Matched:\s*(\d+)', line)
        if matched_match:
            stats['matched'] = int(matched_match.group(1))
        
        # Errors
        errors_match = re.search(r'Errors:\s*(\d+)', line)
        if errors_match:
            stats['errors'] = int(errors_match.group(1))
        
        # Requests: 450/10000
        requests_match = re.search(r'Requests:\s*(\d+)/(\d+)', line)
        if requests_match:
            stats['requests_done'] = int(requests_match.group(1))
            stats['requests_total'] = int(requests_match.group(2))
        
        # Hosts
        hosts_match = re.search(r'Hosts:\s*(\d+)', line)
        if hosts_match:
            stats['hosts'] = int(hosts_match.group(1))
        
        # Duration / ETA parsing - "Duration: 00:01:30 | ETA: 00:05:00"
        duration_match = re.search(r'Duration:\s*([\d:]+)', line)
        if duration_match:
            stats['duration'] = duration_match.group(1)
        
        eta_match = re.search(r'ETA:\s*([\d:]+)', line)
        if eta_match:
            stats['eta'] = eta_match.group(1)
        
        return stats if stats else None
    except Exception as e:
        logger.error(f"Stats parse error: {e}")
        return None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)


# ============== FALSE POSITIVE MANAGEMENT ENDPOINTS ==============

class FPMarkRequest(BaseModel):
    """Türkçe: FP/TP işaretleme isteği"""
    template_id: str
    scan_id: Optional[str] = None
    notes: Optional[str] = None


@app.post("/mark-fp")
async def mark_false_positive(request: FPMarkRequest):
    """
    Türkçe: Bir bulguyu false positive olarak işaretle
    Bu bilgi gelecek taramalarda FP skorunu etkiler
    """
    try:
        analyzer = get_fp_analyzer()
        success = await analyzer.mark_as_false_positive(request.template_id)
        
        if success:
            logger.info(f"✅ FP işaretlendi: {request.template_id}")
            return {
                "status": "success",
                "message": f"Template '{request.template_id}' false positive olarak işaretlendi",
                "template_id": request.template_id
            }
        else:
            return {
                "status": "warning",
                "message": "MongoDB bağlantısı yok, işaretleme kaydedilemedi"
            }
    except Exception as e:
        logger.error(f"FP işaretleme hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/mark-tp")
async def mark_true_positive(request: FPMarkRequest):
    """
    Türkçe: Bir bulguyu true positive (gerçek zafiyet) olarak işaretle
    """
    try:
        analyzer = get_fp_analyzer()
        success = await analyzer.mark_as_true_positive(request.template_id)
        
        if success:
            logger.info(f"✅ TP işaretlendi: {request.template_id}")
            return {
                "status": "success",
                "message": f"Template '{request.template_id}' true positive olarak işaretlendi",
                "template_id": request.template_id
            }
        else:
            return {
                "status": "warning",
                "message": "MongoDB bağlantısı yok, işaretleme kaydedilemedi"
            }
    except Exception as e:
        logger.error(f"TP işaretleme hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/fp-stats/{template_id}")
async def get_fp_statistics(template_id: str):
    """
    Türkçe: Template için FP/TP istatistiklerini getir
    """
    try:
        analyzer = get_fp_analyzer()
        stats = await analyzer.get_template_stats(template_id)
        
        if stats:
            return stats
        else:
            return {
                "template_id": template_id,
                "fp_count": 0,
                "tp_count": 0,
                "total": 0,
                "fp_rate": 0,
                "message": "Bu template için henüz istatistik yok"
            }
    except Exception as e:
        logger.error(f"FP stats hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/fp-stats")
async def get_all_fp_statistics():
    """
    Türkçe: Tüm template'ler için FP istatistiklerini getir
    En yüksek FP oranına göre sıralı
    """
    try:
        analyzer = get_fp_analyzer()
        if not analyzer.fp_stats_collection:
            return {"stats": [], "message": "MongoDB bağlantısı yok"}
        
        cursor = analyzer.fp_stats_collection.find({}).sort("fp_count", -1).limit(100)
        stats_list = []
        
        for doc in cursor:
            total = doc.get("fp_count", 0) + doc.get("tp_count", 0)
            stats_list.append({
                "template_id": doc.get("template_id"),
                "fp_count": doc.get("fp_count", 0),
                "tp_count": doc.get("tp_count", 0),
                "total": total,
                "fp_rate": doc.get("fp_count", 0) / total if total > 0 else 0,
                "last_updated": doc.get("last_updated").isoformat() if doc.get("last_updated") else None
            })
        
        return {"stats": stats_list, "count": len(stats_list)}
    except Exception as e:
        logger.error(f"FP stats list hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))

