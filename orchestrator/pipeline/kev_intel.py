"""
Kadim Güvenlik - Aktif Sömürü İstihbaratı (CISA KEV + EPSS)
============================================================
Türkçe: "Bu CVE vahşi doğada GERÇEKTEN sömürülüyor mu?" sorusunun otoriter
yanıtı. İki kaynak:

1) CISA KEV (Known Exploited Vulnerabilities) — ABD siber güvenlik ajansının
   "aktif sömürüldüğü KANITLANMIŞ" CVE listesi. Teorik değil: listeye girmek
   için gerçek saldırı gözlemi şart. Tek JSON, günde bir çekilir.
2) EPSS (FIRST.org) — bir CVE'nin 30 gün içinde sömürülme OLASILIĞI (0-1).
   KEV "sömürüldü" der, EPSS "sömürülecek" der; ikisi birlikte öncelik verir.

NEDEN
-----
cve_intel (NVD) "bu sürümün hangi CVE'leri var" sorusunu yanıtlar ama 400.000+
CVE içinde HANGİSİNİN acil olduğunu söylemez — CVSS teorik şiddettir, sahada
kimse %9.8'lik her CVE'yi sömürmez. KEV/EPSS olmadan motor "teorik CVE denizi"
üretir; kurumsal müşterinin asıl ihtiyacı ise "şu an SALDIRGANLARIN kullandığı"
açıkların önce kapatılmasıdır. Bu modül o önceliği verir: KEV üyesi CVE grafta
yükseltilir, hedefli nuclei kenarı daha yüksek urgency ile seed edilir.

DAYANIKLILIK (doktrin §6 — cve_intel ile aynı felsefe)
------------------------------------------------------
KEV/EPSS erişilemez / yavaş / bozuksa modül SESSİZCE boş döner. Son başarılı
yüklenen liste bellekte kalır (stale-while-error); hiç liste yoksa KEV sinyali
üretilmez — motor NVD + statik haritayla eskisi gibi çalışır. Regresyon yok.

Bu modül SAF ve BAĞIMSIZDIR (yalnız httpx). ai-service'e HTTP atlaması yoktur;
mantık orchestrator-yerlidir. LLM yoktur, deterministiktir.
"""

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import httpx

logger = logging.getLogger("kev-intel")

# ============================================================
# Konfigürasyon
# ============================================================

# CISA KEV resmi beslemesi (~1-2 MB JSON, günde birkaç kez güncellenir).
KEV_FEED_URL = os.getenv(
    "KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
# FIRST.org EPSS API — CVE başına sömürü olasılığı. Virgülle toplu sorgulanır.
EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")

# Tamamen kapatılabilir (offline/hava-boşluğu kurulum). Kapalıysa motor eskisi
# gibi yalnız NVD + statik haritayla çalışır — davranış birebir korunur.
KEV_INTEL_ENABLED = os.getenv("KEV_INTEL_ENABLED", "true").lower() == "true"
EPSS_INTEL_ENABLED = os.getenv("EPSS_INTEL_ENABLED", "true").lower() == "true"

_KEV_TIMEOUT = float(os.getenv("KEV_INTEL_TIMEOUT", "25"))     # feed büyük, cömert
_KEV_CACHE_TTL = float(os.getenv("KEV_INTEL_CACHE_TTL", "86400"))  # 24 saat
_EPSS_TIMEOUT = float(os.getenv("EPSS_INTEL_TIMEOUT", "8"))
_EPSS_CACHE_TTL = float(os.getenv("EPSS_INTEL_CACHE_TTL", "86400"))
_EPSS_BATCH = 30        # FIRST API virgüllü sorguda pratik limit

# ============================================================
# Durum (süreç-ömrü önbellek + stale-while-error)
# ============================================================
# NEDEN tek global durum: KEV feed'i tüm taramalar için AYNIDIR — tarama başına
# yeniden indirmek hem CISA'ya yük hem tarama başına 1-2 sn kayıp demekti.
# Stale-while-error: refresh başarısız olursa eski liste hizmet vermeye devam
# eder (24 saatlik liste, "hiç liste"den kat kat iyidir).

_STATE: Dict[str, Any] = {
    "loaded_at": 0.0,            # monotonic timestamp — 0 = hiç yüklenmedi
    "by_cve": {},                # "CVE-2024-1234" -> KEVEntry
    "by_product": {},            # normalize ürün anahtarı -> [cve_id, ...]
    "title": "",                 # feed'in catalogVersion/title bilgisi (log için)
}
_fetch_lock = asyncio.Lock()

# EPSS önbelleği: {"CVE-...": (timestamp, score)} — KEV'den bağımsız TTL.
_EPSS_CACHE: Dict[str, tuple] = {}


@dataclass
class KEVEntry:
    """KEV listesindeki tek kayıt — motorun öncelik kararı için gereken alanlar."""
    cve_id: str
    vendor: str = ""
    product: str = ""
    name: str = ""               # zafiyet adı (örn. "FortiOS Path Traversal")
    date_added: str = ""         # KEV'e giriş tarihi (sömürü kanıtı tarihi)
    due_date: str = ""           # CISA'nın federal kurumlara verdiği yama süresi
    ransomware: bool = False     # fidye yazılımı kampanyasında kullanıldığı biliniyor
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id, "vendor": self.vendor, "product": self.product,
            "name": self.name, "date_added": self.date_added,
            "due_date": self.due_date, "ransomware": self.ransomware,
            "notes": self.notes[:300],
        }


# ============================================================
# Ürün adı normalizasyonu + alias tablosu
# ============================================================
# NEDEN alias: KEV kayıtları "Palo Alto Networks PAN-OS", banner/recon ise
# "panos" der. İki tarafı da alfasayısal-sade anahtara indirip tam eşleşme
# ararız; yetmeyince bu tablo devreye girer. Tablo ALTYAPIDIR — yeni ürün
# 1 satır; CVE/ürün-özel mantık içermez (cve_intel._CPE_PRODUCT_ALIASES felsefesi).

def _normalize_key(name: str) -> str:
    """'Palo Alto Networks PAN-OS' -> 'panos'; 'Exchange Server' -> 'exchangeserver'.
    Boşluksuz/noktasız alfasayısal anahtar — tire/alt çizgi farkları yok sayılır."""
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# Bizim fingerprint/banner adı -> KEV'deki muhtemel normalize ürün anahtarları.
# product-only anahtarla çakışmayan (veya hiç eşleşmeyen) yaygın sapmalar.
_KEV_PRODUCT_ALIASES: Dict[str, Set[str]] = {
    "apache": {"httpserver"},
    "exchange": {"exchangeserver"},
    "sharepoint": {"sharepointserver"},
    "netscaler": {"adc", "gateway"},                    # Citrix ADC / Gateway
    "citrix": {"adc", "gateway", "virtualappsanddesktops"},
    "confluence": {"confluenceserveranddatacenter", "confluencedatacenterandserver",
                    "confluence"},
    "jira": {"jira", "jirasoftware", "jiraserveranddatacenter"},
    "openssh": {"openssh"},
    "fortios": {"fortios"},
    "fortiweb": {"fortiweb"},
    "fortinet": {"fortios", "fortiweb", "fortisandbox", "fortiproxy", "fortimanager"},
    "panos": {"panos"},
    "paloalto": {"panos", "globalprotectapp", "expedition"},
    "ivanti": {"endpointmanagermobileepmm", "connectsecure", "policysecure",
                "sentry", "epm", "cloudservicesappliancecsa"},
    "epmm": {"endpointmanagermobileepmm"},
    "teamcity": {"teamcity"},
    "metabase": {"metabase"},
    "coldfusion": {"coldfusion"},
    "n8n": {"n8n"},
    "langflow": {"langflow"},
    "wordpress": {"wordpress"},
    "drupal": {"drupalcore", "drupal"},
    "joomla": {"joomla"},
    "magento": {"magento", "adobecommerce", "magentoopensource"},
    "php": {"php"},
    "nginx": {"nginx"},
    "tomcat": {"tomcat"},
    "windows": {"windows"},
    "kubernetes": {"kubernetes"},
    "oracle": {"ebusinesssuite", "peoplesoftenterprisepptools", "weblogicserver",
                "agileproductlifecyclemanagementplm"},
    "peoplesoft": {"peoplesoftenterprisepptools"},
    "weblogic": {"weblogicserver"},
    "cpanel": {"cpanel"},
    "sonicwall": {"sonicos", "sma1000series", "sma100series"},
    "qnap": {"qts", "quTShero"},
    "zyxel": {"zywall", "usgfex", "atp", "vpn", "nas326", "nas542"},
    "dlink": {"dir-815", "dir-820l", "dir-859"},
    "progress": {"loadmaster", "moveittransfer", "ws_ftp"},
    "loadmaster": {"loadmaster"},
    # 2026 cephesi — base normalize çoğunu yakalar; KEV adı sapan/çok-varyantlılar burada.
    "simplehelp": {"simplehelp"},
    "jupyter": {"jupyter", "jupyterhub", "jupyternotebook", "jupyterlab"},
    "gitlab": {"gitlab", "gitlabcommunityedition", "gitlabenterpriseedition"},
    "flowise": {"flowise"},
    "jenkins": {"jenkins"},
    "grafana": {"grafana"},
}


def _product_keys(product: str) -> Set[str]:
    """Bir ürün adının KEV indeksinde denenecek tüm anahtarları (kendisi + aliaslar)."""
    base = _normalize_key(product)
    keys = {base} if base else set()
    keys |= _KEV_PRODUCT_ALIASES.get(base, set())
    # "FortiOS 7.4" gibi banner artığı gelirse ilk kelimeyi de dene
    first = _normalize_key((product or "").split(" ")[0] if product else "")
    if first and first != base:
        keys.add(first)
        keys |= _KEV_PRODUCT_ALIASES.get(first, set())
    return {k for k in keys if k}


# ============================================================
# Feed yükleme / parse (saf, testlerde sahte payload ile beslenebilir)
# ============================================================

def _ingest(payload: Dict[str, Any]) -> int:
    """KEV JSON payload'unu indekslere çevir. Döner: kayıt sayısı.
    SAF: ağ yok; testler sahte payload ile doğrudan çağırır."""
    vulns = payload.get("vulnerabilities", []) or []
    by_cve: Dict[str, KEVEntry] = {}
    by_product: Dict[str, List[str]] = {}
    for v in vulns:
        cve_id = str(v.get("cveID", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        entry = KEVEntry(
            cve_id=cve_id,
            vendor=str(v.get("vendorProject", "") or "").strip(),
            product=str(v.get("product", "") or "").strip(),
            name=str(v.get("vulnerabilityName", "") or "").strip(),
            date_added=str(v.get("dateAdded", "") or "").strip(),
            due_date=str(v.get("dueDate", "") or "").strip(),
            ransomware=str(v.get("knownRansomwareCampaignUse", "") or "").strip().lower() == "known",
            notes=str(v.get("notes", "") or "").strip(),
        )
        by_cve[cve_id] = entry
        # İki düzey indeks: ürün tek başına + vendor+ürün birleşik. İkinci düzey,
        # "Manager"/"Server" gibi JENERİK ürün adlarının yanlış eşleşmesini önler
        # (ürün tek başına anlamsızsa vendor ile aranabilir). Alias tablosu ürün
        # düzeyinde çalışır; vendor düzeyi ek güvenlik ağıdır.
        pk = _normalize_key(entry.product)
        vk = _normalize_key(f"{entry.vendor}{entry.product}")
        for key in (pk, vk):
            if key:
                by_product.setdefault(key, []).append(cve_id)
    _STATE["by_cve"] = by_cve
    _STATE["by_product"] = by_product
    _STATE["title"] = str(payload.get("catalogVersion", "") or payload.get("title", ""))
    return len(by_cve)


async def ensure_loaded(force: bool = False) -> bool:
    """KEV feed'i bayatsa (veya hiç yoksa) indir ve indeksle. Döner: liste hazır mı.

    Stale-while-error: indirme başarısızsa VAR OLAN liste korunur ve True döner;
    hiç liste yoksa False (çağıran KEV sinyalini atlar — degrade-safe).
    """
    if not KEV_INTEL_ENABLED:
        return False
    if not force and _STATE["by_cve"] and \
            (time.monotonic() - _STATE["loaded_at"]) < _KEV_CACHE_TTL:
        return True
    async with _fetch_lock:
        # Çift kontrol: kilidi beklerken başka tarama tazelemiş olabilir.
        if not force and _STATE["by_cve"] and \
                (time.monotonic() - _STATE["loaded_at"]) < _KEV_CACHE_TTL:
            return True
        try:
            async with httpx.AsyncClient(timeout=_KEV_TIMEOUT) as client:
                resp = await client.get(KEV_FEED_URL)
                if resp.status_code != 200:
                    logger.info(f"KEV feed HTTP {resp.status_code} — mevcut liste korunuyor.")
                    return bool(_STATE["by_cve"])
                count = _ingest(resp.json())
                _STATE["loaded_at"] = time.monotonic()
                logger.info(f"🛰️  CISA KEV: {count} aktif-sömürü CVE'si yüklendi "
                            f"(katalog {_STATE['title'] or 'bilinmiyor'}).")
                return True
        except Exception as e:
            logger.info(f"KEV feed erişilemedi ({e}) — mevcut liste korunuyor.")
            return bool(_STATE["by_cve"])


# ============================================================
# Sorgu API'si (senkron okuyucular — ensure_loaded sonrası çağrılır)
# ============================================================

def is_kev(cve_id: str) -> Optional[KEVEntry]:
    """Bu CVE, CISA'nın 'aktif sömürülüyor' listesinde mi? Liste boşsa None."""
    if not cve_id:
        return None
    return _STATE["by_cve"].get(str(cve_id).strip().upper())


def lookup_product(product: str) -> List[KEVEntry]:
    """Ürün adına göre KEV kayıtları (alias-aware tam eşleşme; gürültüsüz).

    NEDEN tam eşleşme: substring arama 'manager' gibi jenerik adlarda onlarca
    yanlış ürün getirir (FP seli = rapor güvenilirliği kaybı). Eksik kalan
    eşleşmeler alias tablosuna 1 satırla eklenir — kontrollü genişleme.
    """
    keys = _product_keys(product)
    seen: Set[str] = set()
    out: List[KEVEntry] = []
    for key in keys:
        for cve_id in _STATE["by_product"].get(key, []):
            if cve_id in seen:
                continue
            seen.add(cve_id)
            entry = _STATE["by_cve"].get(cve_id)
            if entry:
                out.append(entry)
    # Taze eklenen önce — operatörün "bu hafta ne düştü" sorusuna yanıt verir.
    out.sort(key=lambda e: e.date_added, reverse=True)
    return out


def stats() -> Dict[str, Any]:
    """Sağlık/durum bilgisi (log ve debug endpoint'leri için)."""
    return {
        "enabled": KEV_INTEL_ENABLED,
        "loaded": bool(_STATE["by_cve"]),
        "cve_count": len(_STATE["by_cve"]),
        "product_count": len(_STATE["by_product"]),
        "age_seconds": round(time.monotonic() - _STATE["loaded_at"], 1)
        if _STATE["loaded_at"] else None,
        "catalog": _STATE["title"],
    }


# ============================================================
# EPSS — sömürü OLASILIĞI (KEV'in "kanıtlanmış"ına tamamlayıcı)
# ============================================================
# NEDEN EPSS: KEV'e girmemiş ama sömürülme olasılığı yüksek (örn. %70+) CVE,
# CVSS 9.8 ama kimsenin umursamadığı CVE'den DAHA ACİLDİR. Skorlamada EPSS,
# teorik severity gürültüsünü sahaya indirger. Yalnız motora GİREN CVE'ler için
# toplu sorgulanır (tarama başına birkaç düzine — API dostu).

async def epss_scores(cve_ids: List[str]) -> Dict[str, float]:
    """Verilen CVE'ler için EPSS skorları {cve_id: 0..1}. Hata/limitte eksik
    döner (sessiz) — EPSS yoksa skorlama CVSS'e düşer, regresyon yok."""
    if not EPSS_INTEL_ENABLED or not cve_ids:
        return {}
    now = time.monotonic()
    out: Dict[str, float] = {}
    todo: List[str] = []
    for cid in cve_ids:
        cid = str(cid).strip().upper()
        if not cid.startswith("CVE-"):
            continue
        cached = _EPSS_CACHE.get(cid)
        if cached and (now - cached[0]) < _EPSS_CACHE_TTL:
            out[cid] = cached[1]
        else:
            todo.append(cid)
    try:
        async with httpx.AsyncClient(timeout=_EPSS_TIMEOUT) as client:
            for i in range(0, len(todo), _EPSS_BATCH):
                batch = todo[i:i + _EPSS_BATCH]
                resp = await client.get(EPSS_API_URL, params={"cve": ",".join(batch)})
                if resp.status_code != 200:
                    logger.info(f"EPSS HTTP {resp.status_code} — bu parti atlandı.")
                    continue
                for row in resp.json().get("data", []) or []:
                    cid = str(row.get("cve", "")).strip().upper()
                    try:
                        score = float(row.get("epss", 0.0) or 0.0)
                    except (TypeError, ValueError):
                        continue
                    if cid:
                        out[cid] = score
                        _EPSS_CACHE[cid] = (now, score)
    except Exception as e:
        logger.info(f"EPSS erişilemedi ({e}) — skorlama CVSS ile sürer.")
    return out
