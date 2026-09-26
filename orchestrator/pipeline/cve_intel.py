"""
Kadim Güvenlik - Dinamik CVE İstihbaratı (NVD)
==============================================
Türkçe: Servis+sürüm (örn. "OpenSSH 9.7") -> bilinen CVE eşleştirmesini NVD'nin
(NIST resmi zafiyet veritabanı) üzerinden CANLI yapar.

NEDEN
-----
Otonom motor şimdiye kadar YALNIZ elle gömülü statik bir haritaya (adaptive_scanner.
SERVICE_VULNERABILITY_MAP — ~17 servis) bakıyordu. Listede olmayan her servis/sürüm
CVE'siz kalıyordu; rakip analist raporu "OpenSSH 9.7 -> CVE-..." derken bizim motor
sadece "port açık" diyordu. Bu modül o boşluğu kapatır: statik harita HIZLI ÖNBELLEK
olarak kalır, listede yoksa NVD'ye sorulur.

DAYANIKLILIK (doktrin §6 — Ollama/nuclei ile aynı felsefe)
----------------------------------------------------------
NVD erişilemez / rate-limit / yavaşsa modül SESSİZCE boş döner. Motor bu durumda
statik haritayla ilerler — regresyon yok, tarama durmaz. NVD "kral değil, danışman".

Bu modül SAF ve BAĞIMSIZDIR (yalnız httpx). ai-service'e HTTP atlaması yapmaz;
mantık orchestrator-yerlidir — ağ hopu / servis bağımlılığı yoktur.
"""

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("cve-intel")

# ============================================================
# Konfigürasyon
# ============================================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

# Dinamik CVE lookup tamamen kapatılabilir (offline/hava-boşluğu kurulum). Kapalıysa
# motor eskisi gibi yalnız statik haritayla çalışır — davranış birebir korunur.
CVE_INTEL_ENABLED = os.getenv("CVE_INTEL_ENABLED", "true").lower() == "true"

# NVD anonim: 5 istek / 30 sn. API key ile: 50 / 30 sn. Motoru bekletmemek için
# tek bir sorguya kısa timeout; aşılırsa sessizce boş dön (statik haritaya düşülür).
_NVD_TIMEOUT = float(os.getenv("CVE_INTEL_TIMEOUT", "12"))
_MIN_INTERVAL = 6.0 if not NVD_API_KEY else 0.6   # istekler arası minimum boşluk (sn)
_MAX_RESULTS = int(os.getenv("CVE_INTEL_MAX_RESULTS", "8"))

# CVSS tabanı: APT servis-istihbaratında medium CVE'ler de değerli (sürüm ifşası + aday).
# 4.0 = medium+; bu bulgular confidence-tier 'unconfirmed' olarak GÖRÜNÜR ama manşeti
# şişirmez. Dar (yalnız high/critical) davranış için CVE_INTEL_MIN_CVSS=7.0.
_MIN_CVSS = float(os.getenv("CVE_INTEL_MIN_CVSS", "4.0"))

# Süreç-ömrü önbellek: aynı ürün+sürüm tekrar sorulmasın (rate-limit dostu).
# {("openssh","9.7"): (timestamp, [CVEHit, ...])}
_CACHE: Dict[Tuple[str, str], Tuple[float, List["CVEHit"]]] = {}
_CACHE_TTL = float(os.getenv("CVE_INTEL_CACHE_TTL", "86400"))  # 24 saat

# Rate-limit için global kilit + son istek zamanı (paralel taramalar NVD'yi bombalamasın).
_rate_lock = asyncio.Lock()
_last_request_ts: float = 0.0


@dataclass
class CVEHit:
    """NVD'den dönen tek bir CVE — motorun kanıt/aksiyon için ihtiyaç duyduğu alanlar."""
    cve_id: str
    severity: str = "unknown"          # critical | high | medium | low
    cvss_score: float = 0.0
    cvss_version: str = ""
    description: str = ""
    references: List[str] = field(default_factory=list)
    published: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id, "severity": self.severity,
            "cvss_score": self.cvss_score, "cvss_version": self.cvss_version,
            "description": self.description[:400], "references": self.references[:3],
            "published": self.published,
        }


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _parse_cvss(cve_data: Dict[str, Any]) -> Tuple[float, str, str]:
    """NVD metrics bloğundan (CVSS 3.1 > 3.0 > 2.0 önceliğiyle) skor/severity çıkar."""
    metrics = cve_data.get("metrics", {}) or {}
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        block = metrics.get(key)
        if block:
            data = (block[0] or {}).get("cvssData", {}) or {}
            score = float(data.get("baseScore", 0.0) or 0.0)
            sev = (data.get("baseSeverity") or "").lower() or _severity_from_cvss(score)
            return score, ver, sev
    return 0.0, "", "unknown"


async def _throttle():
    """NVD'yi rate-limit'e sokmadan istekleri seyrelt (global, paralel-tarama güvenli)."""
    global _last_request_ts
    async with _rate_lock:
        wait = _MIN_INTERVAL - (time.monotonic() - _last_request_ts)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request_ts = time.monotonic()


def _normalize_version(version: str) -> str:
    """'2.4.49' / 'OpenSSH_9.7p1' gibi banner artığını sade sürüm anahtarına indir."""
    v = (version or "").strip().lower()
    # yaygın banner önekleri ve p-suffix'lerini at
    for junk in ("openssh_", "v", "release", "ubuntu", "debian"):
        v = v.replace(junk, "")
    return v.strip()


# ============================================================
# CPE sürüm-aralığı filtreleme — "YAMALI sürüme CVE adayı üretme"
# ============================================================
# NEDEN: keywordSearch 'wordpress 7.0.2' diye sorduğunda NVD, açıklamasında bu metin
# geçen CVE'leri döner — ama wp2shell vakasında görüldüğü gibi açıklama '7.0.2 ÖNCESİ
# etkilidir' der, yani tespit edilen sürüm YAMALIDIR. Adayı nuclei'ye göndermek israf,
# rapora 'kritik CVE adayı' yazmaksa yanlış alarmdır (rakip 'acil kapat' raporunun
# güvenilirliği tam bu ayırt etmede yatar). NVD 2.0 yanıtı yapısal CPE aralıkları
# (versionStartIncluding/versionEndExcluding) taşır — regex'e gerek yok.

def _version_tuple(v: str) -> Tuple[int, ...]:
    """'7.0.2' → (7,0,2); '8.1.27rc1' → (8,1,27). Sayısal olmayan kuyruk atılır."""
    parts: List[int] = []
    for p in re.split(r"[.\-+~]", v or ""):
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        if num:
            parts.append(int(num))
    return tuple(parts)


def _cmp_versions(a: str, b: str) -> int:
    """-1: a<b, 0: eşit, 1: a>b. Eksik bileşenler 0 sayılır (7.0 == 7.0.0)."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    n = max(len(ta), len(tb), 1)
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


# Yaygın ürün adı → CPE product segmenti eşlemesi. NVD'de 'apache' http_server,
# 'powerdns' authoritative_server olarak kayıtlıdır; banner/teknoloji adıyla CPE adı
# birebir tutmaz. Alias olmadan iki hata doğar: (a) powerdns gibi ürünler KÖR kalır,
# (b) 'apache' sorgusu Apache Foundation'ın TÜM projelerini (OpenNLP/OFBiz/CXF) getirir.
# Tablo altyapıdır — yeni ürün = 1 satır; CVE/ürün-özel mantık içermez.
_CPE_PRODUCT_ALIASES: Dict[str, set] = {
    "apache": {"http_server"},
    "powerdns": {"authoritative_server", "recursor", "dnsdist"},
    "wordpress": {"wordpress"},
    "nginx": {"nginx"},
    "php": {"php"},
    "mysql": {"mysql"},
    "mariadb": {"mariadb"},
    "postgresql": {"postgresql"},
    "openssh": {"openssh"},
    "proftpd": {"proftpd"},
    "vsftpd": {"vsftpd"},
    "tomcat": {"tomcat"},
    "laravel": {"laravel"},
    "joomla": {"joomla\\!", "joomla"},
    "drupal": {"drupal"},
    # ---- 2026 cephesi: AI/agentic yığın (NVD CPE ürün segmentiyle birebir) ----
    "langflow": {"langflow"},
    "n8n": {"n8n"},
    "flowise": {"flowise"},
    "comfyui": {"comfyui"},
    "marimo": {"marimo"},
    "ollama": {"ollama"},
    "sglang": {"sglang"},
    "jupyter": {"jupyter", "notebook", "jupyterhub", "jupyterlab"},
    # ---- 2026 cephesi: niş kurumsal / yönetim düzlemi ----
    "metabase": {"metabase"},
    "teamcity": {"teamcity"},
    "coldfusion": {"coldfusion"},
    "gitlab": {"gitlab"},
    "grafana": {"grafana"},
    "jenkins": {"jenkins"},
    "kibana": {"kibana"},
    "sharepoint": {"sharepoint_server", "sharepoint_enterprise_server",
                   "sharepoint_foundation", "sharepoint"},
    "loadmaster": {"loadmaster"},
    "simplehelp": {"simplehelp"},
    # ---- Edge/appliance aileleri (fingerprint tek ad döner; NVD çok ürün) ----
    "fortinet": {"fortios", "fortiweb", "fortiproxy", "fortisandbox", "fortimanager"},
    "panos": {"pan-os", "pan_os"},
    "ivanti": {"connect_secure", "policy_secure", "endpoint_manager_mobile", "sentry"},
    "citrix_netscaler": {"netscaler_application_delivery_controller",
                         "netscaler_gateway", "application_delivery_controller"},
}


def _cpe_product_variants(product: str) -> set:
    p = (product or "").lower().strip()
    variants = {p, p.replace("-", "_"), p.replace("_", "-"), p.replace(" ", "_")}
    return {v for v in variants if v} | _CPE_PRODUCT_ALIASES.get(p, set())


def _is_version_affected(cve_data: Dict[str, Any], product: str, version: str) -> Optional[bool]:
    """Tespit edilen sürüm bu CVE'den etkileniyor mu?
    True  → CPE aralığı içinde (kesin aday)
    False → (a) aralıklar biliniyor ve sürüm HEPSİNİN dışında (yamalı), veya
            (b) CVE'nin CPE kayıtları TAMAMEN başka ürüne ait (apache→OpenNLP gürültüsü)
    None  → karar verilemedi (CPE kaydı yok/henüz atanmamış) → muhafazakar: aday kalır,
            kanıt katmanı (nuclei template) son sözü söyler."""
    if not version:
        return None
    variants = _cpe_product_variants(product)
    saw_our_unbounded = False
    saw_our_bounded = False
    saw_other_product = False
    for conf in cve_data.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                crit = str(m.get("criteria", "")).lower()
                # CPE product segmenti: cpe:2.3:a:<vendor>:<product>:<version>:...
                parts = crit.split(":")
                cpe_product = parts[4] if len(parts) > 5 else ""
                if cpe_product and cpe_product not in variants:
                    saw_other_product = True
                    continue
                vsi = m.get("versionStartIncluding")
                vse = m.get("versionEndExcluding")
                vei = m.get("versionEndIncluding")
                if not any([vsi, vse, vei]):
                    saw_our_unbounded = True  # 'tüm sürümler' kaydı → karar verilemez
                    continue
                saw_our_bounded = True
                if vsi and _cmp_versions(version, str(vsi)) < 0:
                    continue
                if vse and _cmp_versions(version, str(vse)) >= 0:
                    continue
                if vei and _cmp_versions(version, str(vei)) > 0:
                    continue
                return True
    if saw_our_bounded:
        return False           # ürünümüzün aralıkları biliniyor, sürüm dışarıda = yamalı
    if saw_our_unbounded:
        return None            # ürünümüz ama aralık yok → kararsız, aday kalsın
    if saw_other_product:
        return False           # kayıtlar tamamen başka ürünün → bu bizim CVE'miz değil
    return None


async def lookup(product: str, version: str = "") -> List[CVEHit]:
    """
    Tek bir ürün+sürüm için NVD'den CVE listesi (yüksek-öncelikli, sıralı).
    Erişilemez/rate-limit/kapalı ise BOŞ liste döner — çağıran statik haritaya düşer.

    ÇİFT SORGULU strateji:
    1) keywordSearch 'ürün sürüm' — sürüm metnini açıklamasında taşıyan CVE'ler.
    2) keywordSearch 'ürün' + son N gün filtresi — TAZE CVE'ler. (1)'in kör noktası:
       '7.0.x before 7.0.2' yazan açıklama '7.0.1' metnini İÇERMEZ → keyword eşleşmez
       ve savunmasız sürümde bile CVE kaçardı (wp2shell vakasında kanıtlandı).
       Taze CVE'ler CPE sürüm-aralığı filtresinden geçirilir → sürüm eşleşmesi
       metne değil, yapısal aralığa dayanır (kesin).
    """
    if not CVE_INTEL_ENABLED:
        return []
    product = (product or "").strip().lower()
    if not product:
        return []
    ver = _normalize_version(version)

    cache_key = (product, ver)
    cached = _CACHE.get(cache_key)
    if cached and (time.monotonic() - cached[0]) < _CACHE_TTL:
        return cached[1]

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    vulns: List[Dict[str, Any]] = []
    seen_ids: set = set()
    main_ids: set = set()      # 1. sorgudan (keyword ürün+sürüm) gelenler
    recent_only_ids: set = set()  # yalnız taze-sorgudan gelenler (CPE teyidi şart)

    queries: List[Dict[str, Any]] = [
        {"keywordSearch": f"{product} {ver}".strip(),
         "resultsPerPage": min(_MAX_RESULTS, 20)},
    ]
    if ver:
        from datetime import datetime, timedelta, timezone
        since = datetime.now(timezone.utc) - timedelta(
            days=int(os.getenv("CVE_INTEL_RECENT_DAYS", "90")))
        queries.append({
            "keywordSearch": product,
            # Taze-CVE sorgusu sayfalamaya kurban gitmesin: 90 günde yüzlerce kayıt
            # dönebilir, ilk 20'de kalmak = wp2shell gibi 10 günlük CVE'yi kaçırmak
            # demekti (kanıtlandı). API 2000'e kadar izin verir; filtre bizde (CVSS+CPE).
            "resultsPerPage": int(os.getenv("CVE_INTEL_RECENT_MAX", "2000")),
            "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        })

    try:
        async with httpx.AsyncClient(timeout=_NVD_TIMEOUT) as client:
            for qi, params in enumerate(queries):
                await _throttle()
                resp = await client.get(NVD_API_URL, params=params, headers=headers)
                if resp.status_code != 200:
                    logger.info(f"NVD HTTP {resp.status_code} — bu sorgu atlandı.")
                    continue
                for v in resp.json().get("vulnerabilities", []) or []:
                    cid = (v.get("cve", {}) or {}).get("id", "")
                    if not cid:
                        continue
                    if qi == 0:
                        main_ids.add(cid)
                    elif cid not in main_ids:
                        recent_only_ids.add(cid)
                    if cid not in seen_ids:
                        seen_ids.add(cid)
                        vulns.append(v)
    except Exception as e:
        logger.info(f"NVD erişilemedi ({e}) — statik haritaya düşülüyor.")
        return []

    hits: List[CVEHit] = []
    for vuln in vulns:
        cve_data = vuln.get("cve", {}) if isinstance(vuln, dict) else {}
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue
        score, cvss_ver, sev = _parse_cvss(cve_data)
        if score < _MIN_CVSS:
            continue  # yalnız gerçekten önemli olan motora girsin (gürültü değil)
        # YAMALI-SÜRÜM ELEMEsi: tespit edilen sürüm CPE aralıklarının tamamının
        # dışındaysa bu CVE bu hedef için aday DEĞİL (wp2shell: 7.0.2 yamalıydı).
        # None (kararsız) durumunda aday korunur — son söz kanıt katmanınındır.
        affected = _is_version_affected(cve_data, product, ver) if ver else None
        if affected is False:
            logger.debug(f"NVD: {cve_id} elendi — {product} {ver} yamalı aralıkta.")
            continue
        # TAZE-SORGU SIKIŞTIRMASI: yalnız 'son 90 gün' sorgusundan gelen bir CVE,
        # CPE kaydı ürünümüzü hiç içermiyorsa (affected=None) büyük olasılıkla metinde
        # 'wordpress' geçen BAŞKA bir ürünün (eklenti/tema) CVE'sidir → gürültü seli
        # (kanıt: tek üründen 500 aday). Bunlar yalnız CPE ile TESPIT EDİLEN SÜRÜM
        # ARALIĞINDA doğrulanırsa (affected=True) tutulur. Ana keyword sorgusundan
        # gelenler için muhafazakar davranılır (None → tut, kanıt katmanı karar verir).
        if affected is None and cve_id in recent_only_ids:
            continue
        desc = ""
        for d in cve_data.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = d.get("value", "")[:500]
                break
        refs = [r.get("url", "") for r in (cve_data.get("references", []) or [])[:3] if r.get("url")]
        hits.append(CVEHit(
            cve_id=cve_id, severity=sev, cvss_score=score, cvss_version=cvss_ver,
            description=desc, references=refs, published=cve_data.get("published"),
        ))

    hits.sort(key=lambda h: (_SEVERITY_ORDER.get(h.severity, 5), -h.cvss_score))
    _CACHE[cache_key] = (time.monotonic(), hits)
    if hits:
        logger.info(f"🛰️  NVD: {product} {ver} -> {len(hits)} yüksek-öncelikli CVE "
                    f"({', '.join(h.cve_id for h in hits[:3])})")
    return hits


def cve_ids_to_nuclei_templates(cve_ids: List[str]) -> List[str]:
    """CVE id'lerini nuclei template-id konvansiyonuna çevir ('CVE-2021-41773' -> 'cve-2021-41773').
    Motor bunları HEDEFLİ nuclei taramasında kullanır (kör tarama yerine bu CVE'yi KANITLA)."""
    out: List[str] = []
    for c in cve_ids:
        t = str(c).strip().lower()
        if t and t not in out:
            out.append(t if t.startswith("cve-") else f"cve-{t.replace('cve-', '')}")
    return out
