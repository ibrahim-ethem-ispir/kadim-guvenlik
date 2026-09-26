"""
Kadim Güvenlik - v2 Scan Pipeline
Türkçe: Orchestrator içinde çalışan akıllı tarama pipeline'ı.

Pipeline orchestrator'da çalışır, AI service'e sadece analiz sonuçlarını gönderir.
Bu sayede phantom'daki HTTP zinciri sorunu (AI->Orchestrator->Service) ortadan kalkar.

Özellikler:
- Profil bazlı aşama yönetimi (quick/normal/full/stealth/web/infra)
- Paralel grup desteği (aynı gruptaki aşamalar eşzamanlı çalışır)
- Exponential backoff polling (2->4->8->16->30s)
- SSE event emission (gerçek zamanlı frontend güncellemesi)
- Stage-level ve pipeline-level hard timeout
- AI analiz tetikleme (pipeline tamamlanınca)
- v2_scan_sessions MongoDB collection ile izleme
"""

import asyncio
import httpx
import ipaddress
import json
import logging
import os
import re
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field, asdict
from urllib.parse import parse_qsl

from .scan_profiles import (
    ScanProfile, StageDefinition, get_profile, list_profiles, ScanProfileType,
    LEGACY_PROFILES_ENABLED, profile_to_level,
)
from .scan_events import (
    ScanEventBus, ScanEvent, ScanEventType,
    emit_scan_started, emit_progress_update,
    emit_scan_completed, emit_scan_failed, emit_error,
    emit_heartbeat, emit_vulnerability_found,
)
from .adaptive_scanner import AdaptiveScanner
from .autonomous_engine import (AutonomousEngine, DecisionAction, Evidence,
                                REQUIRE_RECON_APPROVAL, LLM_TASK_TIMEOUT)
from .autonomous_report import build_autonomous_scan_results
from .stage_health import is_degraded, build_degraded_record, summarize_degraded
from .verification import verify_hypothesis, evidence_meta_for, classify_evidence_class
from .attack_graph import Edge, DEFAULT_SEVERITY as _DEFAULT_SEVERITY
from .origin_discovery import OriginDiscovery

logger = logging.getLogger("pipeline-v2")

# ============== Servis URL'leri ==============
NMAP_SERVICE_URL = os.getenv("NMAP_SERVICE_URL", "http://nmap-service:8001")
NUCLEI_SERVICE_URL = os.getenv("NUCLEI_SERVICE_URL", "http://nuclei-service:8003")
SUBFINDER_SERVICE_URL = os.getenv("SUBFINDER_SERVICE_URL", "http://subfinder-service:8010")
RUSTSCAN_SERVICE_URL = os.getenv("RUSTSCAN_SERVICE_URL", "http://rustscan-service:8002")
FUZZ_SERVICE_URL = os.getenv("FUZZ_SERVICE_URL", "http://fuzz-service:8011")
# T1-A: Headless (JS-render) crawler. Boş/erişilemezse httpx crawler tek başına çalışır.
CRAWLER_SERVICE_URL = os.getenv("CRAWLER_SERVICE_URL", "http://crawler-service:8012")
# Parmak izi (wappalyzergo) — teknoloji KİMLİĞİ motoru. Degrade-safe: erişilemezse mevcut
# header/Rust sezgisi kural-fallback olarak kalır (doktrin §6: yeni servis kral değil).
FINGERPRINT_SERVICE_URL = os.getenv("FINGERPRINT_SERVICE_URL", "http://fingerprint-service:8013")
RECON_SERVICE_URL = os.getenv("RECON_SERVICE_URL", "http://recon-service:8004")
OSINT_SERVICE_URL = os.getenv("OSINT_SERVICE_URL", "http://osint-service:8005")
AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8009")

# D2 — ölü-hizmet erken vazgeçme eşiği: poll_with_backoff kaç ARDIŞIK yoklama hatasından
# sonra max_timeout tavanını beklemeden vazgeçsin. 0 = kapalı (eski davranış: hep tavana kadar).
# 5 ardışık hata backoff ile ~60s'te yakalanır → ölü hizmet 600s yerine ~1dk'da kesilir.
POLL_MAX_CONSECUTIVE_ERRORS = int(os.getenv("POLL_MAX_CONSECUTIVE_ERRORS", "5"))

# Nmap presets (main.py'daki ile aynı)
NMAP_PRESETS = {
    "stealth": {
        "scan_type": ["-sS"],
        "timing": "-T2",
        "-f": True,
        "--randomize-hosts": True,
        "--max-retries": 2,
    },
    "aggressive": {
        "scan_type": ["-sS", "-sV"],
        "timing": "-T4",
        "-A": True,
    },
    # Türkçe: default artık NSE katmanını da taşır (T1 — kalite yol haritası Madde 1).
    # NEDEN: -sV yalnız "ne çalışıyor" der; vuln/auth NSE "açık mı" der. nmap-service bu
    # anahtarları ayrı ayrı alıp `--script default,vuln,auth` olarak birleştirir
    # (nmap-service/main.py NSE Scriptler bölümü). vuln = versiyon-tabanlı zaafiyet NSE'leri
    # (ssl-heartbleed, ftp-anon vb.), auth = anon-FTP/open-relay kimlik yoklamaları.
    # Stealth preset'e BİLİNÇLİ olarak eklenmedi: -T2 doktrini düşük-iz gerektirir.
    # Aggressive'e de gerek yok: -A zaten -sC (default script) + -O içerir.
    "default": {
        "scan_type": ["-sS", "-sV"],
        "timing": "-T3",
        "--script=default": True,
        "--script=vuln": True,
        "--script=auth": True,
    },
}


# ============== Standardize Result Schemas ==============

@dataclass
class StageResult:
    """Bir aşamanın standart sonuç formatı"""
    stage_name: str
    tool: str
    status: str  # completed, failed, timeout, skipped
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class PipelineSession:
    """v2 Pipeline oturum bilgisi"""
    session_id: str
    scan_id: str
    target: str
    profile_name: str
    level: Optional[str] = None  # otonom seviye: recon | standard | deep
    stealth: bool = False  # nmap -T2, düşük gürültü kipi (seviyeden bağımsız)
    auth: Optional[Dict[str, Any]] = None  # kimlik doğrulamalı tarama (headers/bearer/cookie)
    # T2-A: IDOR/BOLA iki-hesap diferansiyeli için İKİNCİ kimlik (opsiyonel). Verilirse
    # "altın kip": B, A'nın nesnesini alabiliyorsa → confirmed IDOR. Yoksa tek-hesap
    # enumerasyon (probable) çalışır.
    auth_b: Optional[Dict[str, Any]] = None
    # Operatör "bu hedef ne?" ipucu (opsiyonel): auto | api | web | server. Otomatik parmak-izi
    # ıskalarsa operatör tipi damgalar → profile app_type/kind buna göre çerçevelenir (API dersen
    # kitlesel BOLA/broken-auth önceliklenir). auto/None = yalnız otomatik tespit.
    target_kind: Optional[str] = None
    # Dayanıklılık & maruz-kalma probu (availability + exposure ekseni). VARSAYILAN KAPALI —
    # operatör tarama başlatırken UI'dan bilinçli açar. Açıkken _probe_resilience çalışır:
    # L7 DoS dayanıklılığı (CDN cache duruşu + rate-limit) + origin-CDN-bypass ifşası + SSH
    # parola-auth maruz-kalması. Hepsi TAHRİBATSIZ (gerçek DDoS/brute-force YOK).
    resilience: bool = False
    status: str = "pending"  # pending, running, completed, failed, cancelled
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    stages: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    ai_analysis: Optional[Dict[str, Any]] = None
    total_duration_seconds: float = 0
    error: Optional[str] = None


# ============== Exponential Backoff Polling ==============

async def poll_with_backoff(
    check_fn: Callable,
    max_timeout: int = 600,
    initial_interval: float = 2.0,
    max_interval: float = 30.0,
    backoff_factor: float = 2.0,
    max_consecutive_errors: int = POLL_MAX_CONSECUTIVE_ERRORS,
) -> Dict[str, Any]:
    """
    Türkçe: Exponential backoff ile polling.
    check_fn: async fonksiyon, {"done": bool, "result": dict} döner.

    D2 (yol haritası §7-#7) — ÖLÜ HİZMET ERKEN VAZGEÇME: check_fn ARDIŞIK
    max_consecutive_errors kez patlıyorsa (ConnectError vb.) hizmet ulaşılamaz demektir;
    600s tavanını BOŞA yakmadan vazgeç. Geriye-uyum: dönüş yine status='timeout' (her çağıran
    'timeout' dalını zaten işliyor — kısmi kurtarma/degrade); ek 'unreachable' bayrağı yalnız
    bilgilendirme (yok sayılabilir). Sayaç yalnız ARDIŞIK hataları sayar — başarılı bir yoklama
    onu sıfırlar → geçici/aralıklı hıçkırık cezalandırılmaz, yalnız kalıcı yokluk erken keser.
    """
    interval = initial_interval
    elapsed = 0.0
    consecutive_errors = 0

    while elapsed < max_timeout:
        await asyncio.sleep(interval)
        elapsed += interval

        try:
            check_result = await check_fn()
            consecutive_errors = 0  # başarılı yoklama → ardışık hata sayacı sıfırlanır
            if check_result.get("done"):
                return check_result.get("result", {})
        except Exception as e:
            consecutive_errors += 1
            logger.warning(
                f"Polling error (elapsed={elapsed:.0f}s, ardışık={consecutive_errors}"
                f"/{max_consecutive_errors}): {e}")
            if max_consecutive_errors > 0 and consecutive_errors >= max_consecutive_errors:
                logger.warning(
                    f"⛔ Hizmet {consecutive_errors} ardışık yoklamada ulaşılamadı "
                    f"(elapsed={elapsed:.0f}s) — ölü hizmet, {max_timeout}s tavanı yakılmadan "
                    f"erken vazgeçildi.")
                return {
                    "status": "timeout", "unreachable": True,
                    "message": (f"Hizmet {consecutive_errors} ardışık yoklamada ulaşılamadı "
                                f"(elapsed={elapsed:.0f}s) — ölü hizmet, erken vazgeçildi."),
                    "error": str(e)[:200],
                }

        # Backoff: 2 -> 4 -> 8 -> 16 -> 30
        interval = min(interval * backoff_factor, max_interval)

    return {"status": "timeout", "message": f"Timeout after {max_timeout}s"}


# ============== Sonuç Özetleyici (UI görünürlüğü) ==============

def _clip_list(v: Any, n: int) -> Any:
    """Bir listeyi n elemana kırpar; liste değilse olduğu gibi döndürür."""
    return v[:n] if isinstance(v, list) else v


def _static_finding_contract(finding: Dict[str, Any], info: Dict[str, Any]) -> Dict[str, Any]:
    """Türkçe: Statik nuclei bulgusunu okuyucunun (reports.py) beklediği FALSE-POSITIVE
    sözleşmesine köprüler — tier + proof + cve + tool.

    NEDEN: Otonom yol Evidence.to_dict() ile bu alanları tam yazıyor; statik yol yazmıyordu.
    Sonuç: statik taramadan gelen HER bulgu 'unconfirmed + kanıtsız' görünüp "hiçbirini teyit
    edemiyorum" hissini üretiyordu. Nuclei'nin KENDİ kanıtını (matched-at, matcher, extracted)
    proof'a serer, CVE'yi çıkarır ve tier'ı ölçülü bir kuralla atarız.

    TIER KURALI (ölçülü, aşırı-iddia YOK):
      - nuclei somut veri ÇIKARDIYSA (extracted-results) → match veri döndürmüş, 'probable'.
      - aksi halde → 'unconfirmed' (nuclei-tek eşleşme bağımsız teyit sayılmaz; doktrin).
    'confirmed' ASLA statik-tek imzayla verilmez — o yalnız aktif doğrulayıcıdan (verify_*) gelir.
    """
    extracted = finding.get("extracted-results") or finding.get("extracted_results") or []
    matcher = finding.get("matcher-name") or finding.get("matcher_name") or ""
    matched_at = finding.get("matched-at") or finding.get("matched_at") or ""

    # CVE: nuclei classification.cve-id ya da template info'dan.
    classification = info.get("classification") or {}
    cve_val = classification.get("cve-id") or classification.get("cve_id") or info.get("cve")
    if isinstance(cve_val, list):
        cve_val = cve_val[0] if cve_val else None

    # Kanıt metni: operatörün elle doğrulayabileceği somut izler (kör "?" yerine).
    proof_parts = []
    if matched_at:
        proof_parts.append(f"matched-at: {matched_at}")
    if matcher:
        proof_parts.append(f"matcher: {matcher}")
    if extracted:
        snip = ", ".join(str(x) for x in extracted[:3])
        proof_parts.append(f"extracted: {snip}")
    proof = " | ".join(proof_parts) or None

    tier = "probable" if extracted else "unconfirmed"

    return {
        "confidence_tier": tier,
        "proof": proof,
        "cve": cve_val,
        "tool": "nuclei",
        # Nuclei-tek imza aktif PoC değil; verified=None (verify_* dolduruyor). Sözleşme için açık.
        "verified": None,
        "verification_confidence": None,
    }


def _summarize_osint_lookup(lookup: str, res: Dict[str, Any]) -> Dict[str, Any]:
    """
    Türkçe: Tek bir OSINT lookup yanıtını UI özetine indirger. Ham yanıt (res) devasa
    olabildiği için (Shodan host JSON'u yüzlerce servis/banner) özete yalnız anahtar
    alanlar alınır. Tam ham veri scan_artifacts.raw_data'da kalır.
    """
    if not isinstance(res, dict):
        return {"value": str(res)[:200]}
    if lookup == "shodan":
        return {
            "ports": _clip_list(res.get("ports"), 50),
            "hostnames": _clip_list(res.get("hostnames"), 20),
            "org": res.get("org"), "isp": res.get("isp"),
            "os": res.get("os"), "country": res.get("country_name") or res.get("country"),
            "vulns": _clip_list(res.get("vulns"), 50),
        }
    if lookup == "internetdb":
        return {
            "ip": res.get("ip"),
            "ports": _clip_list(res.get("ports"), 50),
            "vulns": _clip_list(res.get("vulns"), 50),
            "cpes": _clip_list(res.get("cpes"), 30),
            "hostnames": _clip_list(res.get("hostnames"), 20),
            "tags": _clip_list(res.get("tags"), 20),
            "source": res.get("source"),
        }
    if lookup == "virustotal":
        return {
            "malicious": res.get("malicious"), "suspicious": res.get("suspicious"),
            "harmless": res.get("harmless"), "reputation": res.get("reputation"),
        }
    if lookup == "abuseipdb":
        return {
            "confidence_score": res.get("confidence_score"),
            "total_reports": res.get("total_reports"),
            "country_code": res.get("country_code"), "isp": res.get("isp"),
        }
    # Bilinmeyen lookup: skaler alanları + kısa listeleri al, dev nesneleri at.
    out: Dict[str, Any] = {}
    for k, v in res.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, list):
            out[k] = _clip_list(v, 30)
    return out


def summarize_stage_result(tool: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Türkçe: Bir tool'un ham result.data'sını UI'da modal içinde gösterilebilir,
    kısa ve okunur bir özete indirger. "Recon taradı — E NE ÇIKTI?" sorusunun cevabı.

    Döner:
        {
          "highlights": ["3 subdomain", "gerçek IP: 1.2.3.4", ...],  # kısa maddeler
          "table": {...},   # anahtar → değer, modalda tablo olarak gösterilir
          "counts": {...},  # sayısal metrikler (badge)
        }
    Ham veri (data) ayrıca artifact olarak saklanır; bu sadece görünür özettir.
    """
    data = data or {}
    highlights: List[str] = []
    table: Dict[str, Any] = {}
    counts: Dict[str, int] = {}

    if tool == "recon":
        real_ips = data.get("real_ips") or []
        techs = data.get("technologies") or []
        subs = data.get("subdomains") or []
        is_cf = data.get("is_cloudflare")
        if is_cf:
            highlights.append("🛡️ Hedef CDN/Cloudflare arkasında")
        if real_ips:
            highlights.append(f"🎯 Gerçek IP bulundu: {', '.join(str(i) for i in real_ips[:3])}")
            table["Gerçek IP'ler"] = real_ips
        if techs:
            highlights.append(f"🧩 {len(techs)} teknoloji tespit edildi")
            table["Teknolojiler"] = techs
        if subs:
            highlights.append(f"🌐 {len(subs)} subdomain")
            table["Subdomainler"] = [s.get("name", s) if isinstance(s, dict) else s for s in subs[:50]]
        if data.get("page_title"):
            table["Sayfa başlığı"] = data["page_title"]
        counts = {"subdomains": len(subs), "real_ips": len(real_ips), "technologies": len(techs)}

    elif tool == "nmap":
        services = data.get("services") or []
        ports = data.get("open_ports") or []
        for s in services[:50]:
            if isinstance(s, dict):
                label = f"{s.get('port')}/{s.get('service', '?')}"
                prod = " ".join(filter(None, [s.get("product", ""), s.get("version", "")])).strip()
                highlights.append(f"🔌 {label}" + (f" — {prod}" if prod else ""))
        table["Servisler"] = [
            {"port": s.get("port"), "service": s.get("service"),
             "product": s.get("product"), "version": s.get("version")}
            for s in services[:50] if isinstance(s, dict)
        ]
        if data.get("os_detection"):
            table["İşletim sistemi"] = data["os_detection"]
        counts = {"open_ports": len(ports)}

    elif tool == "rustscan":
        ports = data.get("open_ports") or []
        highlights.append(f"⚡ {len(ports)} açık port: {', '.join(str(p) for p in ports[:20])}")
        table["Açık portlar"] = ports
        counts = {"open_ports": len(ports)}

    elif tool == "nuclei":
        findings = data.get("findings") or []
        sev = data.get("severity_counts") or {}
        for f in findings[:50]:
            info = f.get("info", {}) if isinstance(f, dict) else {}
            highlights.append(
                f"[{info.get('severity', '?')}] {info.get('name', f.get('template-id', '?'))}"
            )
        table["Bulgular"] = [
            {"severity": f.get("info", {}).get("severity"),
             "name": f.get("info", {}).get("name"),
             "matched_at": f.get("matched-at"),
             "template": f.get("template-id")}
            for f in findings[:50] if isinstance(f, dict)
        ]
        if sev:
            table["Önem dağılımı"] = sev
        counts = {"findings": data.get("findings_count", len(findings)),
                  "critical": sev.get("critical", 0), "high": sev.get("high", 0)}

    elif tool == "subfinder":
        subs = data.get("subdomains") or []
        highlights.append(f"🌐 {data.get('subdomains_count', len(subs))} subdomain bulundu")
        table["Subdomainler"] = subs[:100]
        counts = {"subdomains": data.get("subdomains_count", len(subs))}

    elif tool == "fuzz":
        dirs = data.get("directories") or []
        files = data.get("files") or []
        highlights.append(f"📁 {len(dirs)} dizin, {len(files)} dosya keşfedildi")
        table["Dizinler"] = dirs[:100]
        table["Dosyalar"] = files[:100]
        counts = {"directories": len(dirs), "files": len(files)}

    elif tool == "osint":
        # data = {lookup_type: {...} | {"error": ...}}
        for lookup, res in data.items():
            if not isinstance(res, dict):
                continue
            if res.get("error"):
                highlights.append(f"⚠️ {lookup}: {res['error']}")
                table[lookup] = {"error": res["error"]}
            else:
                if lookup == "shodan":
                    sp = res.get("ports") or []
                    highlights.append(f"🔦 Shodan: {len(sp)} port" + (f" ({', '.join(str(p) for p in sp[:10])})" if sp else ""))
                elif lookup == "internetdb":
                    sp = res.get("ports") or []
                    cves = res.get("vulns") or []
                    highlights.append(
                        f"🆓 InternetDB (keysiz): {len(sp)} port" +
                        (f" ({', '.join(str(p) for p in sp[:10])})" if sp else "") +
                        (f", {len(cves)} CVE" if cves else "")
                    )
                elif lookup == "virustotal":
                    mal = res.get("malicious", 0)
                    highlights.append(f"🦠 VirusTotal: {mal} motor kötü niyetli işaretledi")
                elif lookup == "abuseipdb":
                    highlights.append(f"🚨 AbuseIPDB güven skoru: %{res.get('confidence_score', 0)}")
                else:
                    highlights.append(f"✅ {lookup}: veri alındı")
                # Ham lookup yanıtı (res) çok büyük olabilir (Shodan host JSON'u yüzlerce
                # banner içerir). Özet ağır olmasın diye anahtar alanlara indirgenir;
                # tam ham veriye scan_artifacts.raw_data'dan ulaşılır.
                table[lookup] = _summarize_osint_lookup(lookup, res)
        counts = {"lookups": len([1 for r in data.values() if isinstance(r, dict) and not r.get("error")])}

    elif tool in ("origin_discovery",):
        cands = data.get("candidates") or []
        best = data.get("best_candidate") or {}
        if best:
            highlights.append(f"🎯 En iyi origin: {best.get('ip')} (%{best.get('confidence')})")
        highlights.append(f"🔍 {len(cands)} aday IP değerlendirildi")
        table["Adaylar"] = cands[:30]
        counts = {"candidates": len(cands)}

    elif tool == "reverse_ip":
        doms = data.get("co_hosted_domains") or []
        highlights.append(f"🏘️ Aynı IP'de {len(doms)} co-hosted domain")
        table["Co-hosted domainler"] = doms[:100]
        counts = {"co_hosted_domains": len(doms)}

    elif tool == "pathprobe":
        findings = data.get("findings") or []
        sev = data.get("severity_counts") or {}
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for f in findings[:50]:
            if isinstance(f, dict):
                highlights.append(
                    f"{sev_icon.get(f.get('severity'), '⚪')} {f.get('url')} "
                    f"[{f.get('severity')}] — {f.get('category')} (HTTP {f.get('status')})"
                )
        if not findings:
            if data.get("note"):
                highlights.append(f"ℹ️ {data['note']}")
            else:
                highlights.append(f"✅ {data.get('probed', 0)} hassas yol tarandı — ifşa yok")
        # Bulgular URL listesi olarak gösterilir; kanıt (snippet/curl) artifact'tedir.
        table["İfşa bulguları"] = [
            f"[{f.get('severity')}] {f.get('url')} (HTTP {f.get('status')}, {f.get('content_length', 0)}B)"
            for f in findings[:60] if isinstance(f, dict)
        ]
        if data.get("base_url"):
            table["Taranan kök"] = data["base_url"]
        counts = {"findings": len(findings), "probed_paths": data.get("probed", 0),
                  "critical": sev.get("critical", 0), "high": sev.get("high", 0)}

    elif tool == "crawl":
        # Türkçe: Faz 1 — endpoint keşfi özeti. Operatöre "kaç URL, kaç parametreli, kaç form"
        # göster; parametreli olanlar SQLi/XSS/SSRF DAST hedefi olduğunu açıkla. "Boş tarama"
        # hissini önler — bu adım ALTERNATİF bulgu üretmez, ama nuclei'nin bulgu üretebilmesi
        # için gerekli KEŞİF adımıdır; UI bunu net söylemeli.
        param_eps = data.get("parameterized_endpoints") or []
        forms = data.get("forms") or []
        urls = data.get("discovered_urls") or []
        js_assets = data.get("js_assets") or []
        # Highlights: ilk ~25 URL + ilk ~10 parametreli + ilk ~5 form.
        for u in urls[:25]:
            highlights.append(f"🔗 {u}")
        for ep in param_eps[:10]:
            if isinstance(ep, dict):
                ps = ",".join(ep.get("params") or [])
                highlights.append(f"🧪 {ep.get('url')}  ?({ps}) — DAST hedefi")
        for fm in forms[:5]:
            if isinstance(fm, dict):
                highlights.append(
                    f"📝 form [{fm.get('method','?').upper()}] {fm.get('action')} "
                    f"— inputs: {', '.join(fm.get('inputs') or []) or 'yok'}"
                )
        if not highlights:
            if data.get("note"):
                highlights.append(f"ℹ️ {data['note']}")
            else:
                highlights.append("ℹ️ Keşfedilen URL yok — site robots/sitemap sunmuyor olabilir")
        table["Keşfedilen URL'ler"] = urls[:60]
        table["Parametreli endpoint'ler"] = [ep.get("url") for ep in param_eps[:60] if isinstance(ep, dict)]
        table["Form'lar"] = [
            f"[{fm.get('method','?')}] {fm.get('action')} ({', '.join(fm.get('inputs') or []) or 'yok'})"
            for fm in forms[:30] if isinstance(fm, dict)
        ]
        if data.get("base_url"):
            table["Taranan kök"] = data["base_url"]
        if js_assets:
            table["JS varlıkları"] = list(js_assets)[:30]
        counts = {
            "urls": data.get("discovered_count", len(urls)),
            "parameterized": data.get("parameterized_count", len(param_eps)),
            "forms": data.get("forms_count", len(forms)),
            "js_assets": data.get("js_assets_count", len(js_assets)),
        }

    else:
        # Bilinmeyen tool — ham anahtarları göster
        for k, v in list(data.items())[:10]:
            if isinstance(v, (str, int, float, bool)):
                table[k] = v
            elif isinstance(v, list):
                table[k] = v[:20]
                counts[k] = len(v)

    return {"highlights": highlights[:60], "table": table, "counts": counts}


# ============== Auth (kimlik doğrulamalı tarama) yardımcıları ==============

def _normalize_auth_headers(auth: Dict[str, Any]) -> List[str]:
    """
    Türkçe: Esnek `auth` sözlüğünü araçların anladığı "Ad: değer" başlık listesine çevirir.

    Kabul edilen biçimler (hepsi opsiyonel, birlikte kullanılabilir):
        {"headers": {"Authorization": "Bearer x", "X-Api-Key": "y"}}
        {"headers": ["Authorization: Bearer x", ...]}   # zaten hazır satırlar
        {"bearer": "x"}                                   # -> Authorization: Bearer x
        {"cookie": "session=abc; token=xyz"}             # -> Cookie: ...
        {"basic": "dXNlcjpwYXNz"}                         # -> Authorization: Basic ...

    Güvenlik: kontrol/satır sonu karakterleri ve ':' içermeyen girdiler elenir
    (araçlara argv listesiyle geçtiği için başlık enjeksiyonu yüzeyi yoktur; yine de savunulur).
    """
    out: List[str] = []
    # Tek bir başlık adı iki kez gelmesin (özellikle Authorization). Adları
    # büyük/küçük harf duyarsız izleriz; İLK gelen kazanır, sonraki aynı-adlı atlanır.
    # Öncelik sırası: açık `headers` > `bearer` > `basic` (aşağıdaki ekleme sırası bunu belirler).
    seen_names: set = set()

    def _add(line: str):
        if not isinstance(line, str) or ":" not in line:
            return
        if any(c in line for c in ("\n", "\r", "\x00")):
            return
        line = line.strip()
        name = line.split(":", 1)[0].strip().lower()
        if not name or name in seen_names:
            return
        seen_names.add(name)
        out.append(line)

    if not isinstance(auth, dict):
        return out

    headers = auth.get("headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            _add(f"{k}: {v}")
    elif isinstance(headers, list):
        for line in headers:
            _add(line)

    if auth.get("bearer"):
        _add(f"Authorization: Bearer {auth['bearer']}")
    if auth.get("basic"):
        _add(f"Authorization: Basic {auth['basic']}")
    if auth.get("cookie"):
        _add(f"Cookie: {auth['cookie']}")

    return out


def _parse_auth_dict_to_headers(auth: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """auth sözlüğünü {'Ad':'değer'} başlık HARİTASINA çevir (IDOR probu httpx'e
    headers=dict verir; nuclei/fuzz ise 'Ad: değer' listesi ister). _normalize_auth_headers'ın
    çıktısını yeniden kullanır → tek doğruluk kaynağı (aynı dedup/sanitizasyon)."""
    out: Dict[str, str] = {}
    for line in _normalize_auth_headers(auth or {}):
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k and v:
            out[k] = v
    return out


# ============== Tool Dispatch Functions (v2) ==============

class ToolDispatcher:
    """
    Türkçe: Mevcut servislere HTTP çağrı yapan dispatcher.
    main.py'daki dispatch fonksiyonlarından farklı olarak:
    - Standart StageResult döner
    - Exponential backoff kullanır
    - MongoDB'ye doğrudan yazmaz (pipeline yönetir)
    - SSE event emit eder
    """

    def __init__(self, scan_id: str, target: str, auth: Optional[Dict[str, Any]] = None):
        self.scan_id = scan_id
        self.target = target
        # Adaptive pipeline: stage'ler arası veri paylaşımı
        # Örn: recon bulduğu gerçek IP'yi nmap'e iletir
        self.discovered_data: Dict[str, Any] = {}
        # Türkçe: Kimlik doğrulamalı tarama başlıkları (madde 2). Bir kez normalize edilir,
        # nuclei (-H) ve fuzz (config.headers) araçlarına aynen taşınır. Bankaların asıl
        # risk yüzeyi login ARKASINDADIR (IDOR/yetki); araçların oraya erişmesini sağlar.
        self.auth = auth or {}
        self.auth_headers: List[str] = _normalize_auth_headers(self.auth)
        if self.auth_headers:
            logger.info(f"🔐 [{scan_id[:8]}] Authenticated tarama: {len(self.auth_headers)} başlık aktif")
        # IPB: hedef profilinden türetilen nuclei -exclude-tags (PHP-on-node gürültüsünü keser).
        # _ensure_target_profile doldurur; _dispatch_nuclei mevcut exclude'lara EKLER (kapsam
        # daraltmaz). Boşsa (profil yok/belirsiz) davranış eskisi gibi — sıfır regresyon.
        self.profile_exclude_tags: List[str] = []

        # IP hedef tespiti: domain mi yoksa IP mi?
        self.target_is_ip = self._is_ip_address(target)
        if self.target_is_ip:
            # IP hedef ise gerçek IP'yi doğrudan kaydet
            self.discovered_data["primary_real_ip"] = target
            self.discovered_data["is_behind_cf"] = False
            logger.info(f"🎯 Hedef bir IP adresi: {target} (recon/subfinder atlanacak)")

    @staticmethod
    def _is_ip_address(target: str) -> bool:
        """Hedefin IP adresi olup olmadığını kontrol et"""
        try:
            ipaddress.ip_address(target.strip())
            return True
        except ValueError:
            return False

    async def dispatch(self, stage: StageDefinition) -> StageResult:
        """Stage'e göre doğru tool'u çağır"""

        # PER-HOST HEDEFLEME: graf, keşfettiği her host/subdomain/origin-IP için kenarına
        # `scan_target` koyar. Tüm handler'lar self.target'ı okuduğundan, bu dispatch süresince
        # self.target'ı o host'a GEÇİCİ swap ederiz (mevcut _dispatch_nmap_real_ip deseni).
        # Böylece "her suru tek tek yokla" gerçekten uygulanır — aksi halde bulunan subdomain/
        # origin IP hiç taranmaz, motor hep kök hedefi yeniden tarardı. finally ile eski hâle döner.
        # NOT: swap DOMAIN_ONLY kontrolünden ÖNCE yapılır ki skip kararı doğru hedefe göre verilsin.
        override_target = stage.options.pop("scan_target", None)
        restore_target = None
        restore_is_ip = None
        if override_target and isinstance(override_target, str) and override_target != self.target:
            restore_target = self.target
            restore_is_ip = self.target_is_ip
            self.target = override_target
            self.target_is_ip = self._is_ip_address(override_target)
            logger.info(f"🎯 [{self.scan_id[:8]}] Per-host hedef: {override_target} ({stage.tool})")

        try:
            return await self._dispatch_inner(stage, started_at=datetime.utcnow())
        finally:
            # Per-host swap'ı geri al — dispatcher yeniden kullanılabilir kalsın (sıralı akış).
            if restore_target is not None:
                self.target = restore_target
                self.target_is_ip = restore_is_ip

    async def _dispatch_inner(self, stage: StageDefinition, started_at: datetime) -> StageResult:
        """dispatch()'in iç gövdesi — self.target zaten (gerekiyorsa) per-host hedefe swap edilmiş."""
        # IP hedefte domain-only tool'ları otomatik atla
        DOMAIN_ONLY_TOOLS = {"recon", "subfinder", "origin_discovery"}
        if self.target_is_ip and stage.tool in DOMAIN_ONLY_TOOLS:
            logger.info(
                f"⏭ [{self.scan_id[:8]}] {stage.tool.upper()} atlanıyor | "
                f"Hedef bir IP adresi, bu tool sadece domain için çalışır"
            )
            return StageResult(
                stage_name=stage.name,
                tool=stage.tool,
                status="skipped",
                error=f"Hedef IP adresi - {stage.tool} sadece domain hedefler için çalışır",
            )

        dispatch_map = {
            "nmap": self._dispatch_nmap,
            "nuclei": self._dispatch_nuclei,
            "subfinder": self._dispatch_subfinder,
            "rustscan": self._dispatch_rustscan,
            "fuzz": self._dispatch_fuzz,
            "recon": self._dispatch_recon,
            "osint": self._dispatch_osint,
            "nmap_real_ip": self._dispatch_nmap_real_ip,
            "origin_discovery": self._dispatch_origin_discovery,
            "reverse_ip": self._dispatch_reverse_ip,
            "pathprobe": self._dispatch_pathprobe,
            # Türkçe: Faz 1 — endpoint keşfi (crawler). path_probe gibi ORCHESTRATOR-YERLİ,
            # yeni servis gerektirmez. attack_graph.keşfedilen URL'leri ENDPOINT node'larına
            # çevirir ve parametreli olanlar için nuclei DAST kenarı seed eder.
            "crawl": self._dispatch_crawl,
        }

        handler = dispatch_map.get(stage.tool)
        if not handler:
            logger.error(f"❌ Bilinmeyen tool: {stage.tool} (stage: {stage.name})")
            return StageResult(
                stage_name=stage.name,
                tool=stage.tool,
                status="failed",
                error=f"Bilinmeyen tool: {stage.tool}",
            )

        logger.info(
            f"▶ [{self.scan_id[:8]}] {stage.tool.upper()} başlıyor | "
            f"stage={stage.name} | target={self.target} | "
            f"timeout={stage.timeout_seconds}s | required={stage.required}"
        )

        # Stage-level SSE event
        await ScanEventBus.publish(ScanEvent(
            scan_id=self.scan_id,
            event_type=ScanEventType.PHASE_STARTED,
            data={
                "stage": stage.name,
                "tool": stage.tool,
                "target": self.target,
                "timeout": stage.timeout_seconds,
            },
        ))

        try:
            result = await asyncio.wait_for(
                handler(stage),
                timeout=stage.timeout_seconds,
            )
            result.started_at = started_at.isoformat()
            result.completed_at = datetime.utcnow().isoformat()
            result.duration_seconds = (datetime.utcnow() - started_at).total_seconds()

            logger.info(
                f"✅ [{self.scan_id[:8]}] {stage.tool.upper()} tamamlandı | "
                f"stage={stage.name} | status={result.status} | "
                f"süre={result.duration_seconds:.1f}s"
            )
            # DAYANIKLILIK (K5): recon completed olsa da teknoloji bulamadıysa fallback dene.
            return await self._maybe_recon_fallback(stage, result, started_at)

        except asyncio.TimeoutError:
            logger.warning(
                f"⏰ [{self.scan_id[:8]}] {stage.tool.upper()} TIMEOUT | "
                f"stage={stage.name} | limit={stage.timeout_seconds}s"
            )
            # NUCLEI KISMİ KURTARMA: taramayı ÖLDÜRMEDEN ÖNCE o ana kadar CANLI yazılmış
            # bulguları çek. Stage-level hard timeout (asyncio.wait_for) poll_with_backoff'un
            # kendi kurtarmasından önce tetiklenebilir; bu yüzden burada da kurtarırız —
            # aksi halde büyük hedefte 10dk tarayıp bulduğu her şeyi kaybediyordu.
            if stage.tool == "nuclei":
                async with httpx.AsyncClient() as _c:
                    partial = await self._fetch_nuclei_partial(_c)
                await self._try_stop_scan(stage.tool)
                if partial.get("findings"):
                    logger.info(
                        f"🛟 [{self.scan_id[:8]}] Nuclei stage-timeout ama "
                        f"{len(partial['findings'])} KISMİ bulgu kurtarıldı."
                    )
                    partial["partial"] = True
                    return StageResult(
                        stage_name=stage.name, tool="nuclei", status="completed",
                        started_at=started_at.isoformat(),
                        completed_at=datetime.utcnow().isoformat(),
                        duration_seconds=stage.timeout_seconds,
                        data=partial,
                        error="Nuclei timeout — kısmi sonuçlar kurtarıldı.",
                    )
            # NMAP KISMİ KURTARMA: nmap-service her açık portu CANLI MongoDB'ye (NmapLogs)
            # + XML'e yazar. Yüksek kapasiteli (tüm-port/agresif) taramada timeout vurunca
            # eskiden 0 port dönüyordu; artık o ana kadar bulunan portları kurtarırız.
            # Önce kurtar, SONRA durdur (durdurma XML'i budayabilir).
            if stage.tool == "nmap":
                async with httpx.AsyncClient() as _c:
                    partial = await self._fetch_nmap_partial(_c)
                await self._try_stop_scan(stage.tool)
                if partial.get("open_ports"):
                    logger.info(
                        f"🛟 [{self.scan_id[:8]}] Nmap stage-timeout ama "
                        f"{len(partial['open_ports'])} KISMİ port kurtarıldı."
                    )
                    partial["partial"] = True
                    return StageResult(
                        stage_name=stage.name, tool="nmap", status="completed",
                        started_at=started_at.isoformat(),
                        completed_at=datetime.utcnow().isoformat(),
                        duration_seconds=stage.timeout_seconds,
                        data=partial,
                        error="Nmap timeout — kısmi portlar kurtarıldı (tarama tamamlanmadı).",
                    )
            # Cleanup: serviste çalışan taramayı durdur (nuclei dışı veya bulgu yoksa)
            await self._try_stop_scan(stage.tool)
            timeout_result = StageResult(
                stage_name=stage.name,
                tool=stage.tool,
                status="timeout",
                started_at=started_at.isoformat(),
                completed_at=datetime.utcnow().isoformat(),
                duration_seconds=stage.timeout_seconds,
                error=f"Timeout: {stage.timeout_seconds}s",
            )
            # KRİTİK: recon timeout'unda burada fallback probe devreye girer — aksi halde
            # recon her takıldığında tüm zincir kopup tarama BOŞ dönüyordu (K5).
            return await self._maybe_recon_fallback(stage, timeout_result, started_at)

        except Exception as e:
            logger.error(
                f"❌ [{self.scan_id[:8]}] {stage.tool.upper()} HATA | "
                f"stage={stage.name} | error={e}"
            )
            failed_result = StageResult(
                stage_name=stage.name,
                tool=stage.tool,
                status="failed",
                started_at=started_at.isoformat(),
                completed_at=datetime.utcnow().isoformat(),
                duration_seconds=(datetime.utcnow() - started_at).total_seconds(),
                error=str(e),
            )
            return await self._maybe_recon_fallback(stage, failed_result, started_at)

        finally:
            await ScanEventBus.publish(ScanEvent(
                scan_id=self.scan_id,
                event_type=ScanEventType.PHASE_COMPLETED,
                data={"stage": stage.name, "tool": stage.tool},
            ))

    # ---- Nmap ----
    async def _dispatch_nmap(self, stage: StageDefinition) -> StageResult:
        """Nmap servisine tarama gönder ve sonucu bekle (senkron HTTP)"""
        options = dict(stage.options)

        # Preset merge
        preset_name = options.pop("preset", "default")
        final_options = NMAP_PRESETS.get(preset_name, NMAP_PRESETS["default"]).copy()
        for k, v in options.items():
            final_options[k] = v

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{NMAP_SERVICE_URL}/scan",
                json={
                    "target": self.target,
                    "scan_id": self.scan_id,
                    "options": final_options,
                },
                # HTTP timeout'u stage limitinin BİRAZ ÜSTÜNDE tut. Aksi halde httpx read
                # timeout'u ile _dispatch_inner'daki asyncio.wait_for(stage.timeout_seconds)
                # AYNI anda yarışıyordu: httpx önce vurursa istisna → status="failed"
                # (kısmi kurtarma YOK); asyncio önce vurursa status="timeout" (kurtarma VAR).
                # Buffer ile daima asyncio kazanır → deterministik timeout + kısmi port kurtarma.
                timeout=float(stage.timeout_seconds) + 30.0,
            )

            if response.status_code != 200:
                return StageResult(
                    stage_name=stage.name,
                    tool="nmap",
                    status="failed",
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )

            raw = response.json()

            # Standardize nmap result
            # findings_summary nmap servisinden liste olarak gelir:
            # [{"port": 80, "protocol": "tcp", "service": "http", ...}, ...]
            findings = raw.get("findings_summary", [])
            if not isinstance(findings, list):
                findings = []

            # open_ports: port numaralarını çıkar
            open_ports = []
            services = []
            for f in findings:
                if isinstance(f, dict):
                    port_num = f.get("port")
                    if port_num is not None:
                        open_ports.append(port_num)
                    services.append({
                        "port": f.get("port"),
                        "protocol": f.get("protocol", "tcp"),
                        "service": f.get("service", "unknown"),
                        "product": f.get("product", ""),
                        "version": f.get("version", ""),
                        # Madde 4: Debian-revision banner'ı ("Ubuntu 4ubuntu0.4") buradadır
                        # — distro-patch-level matrisinin deterministik karar girdisi.
                        "extrainfo": f.get("extrainfo", ""),
                        "state": f.get("state", "open"),
                        # NSE script çıktıları (anon-FTP, ssl-heartbleed, vb.) — nmap-service
                        # port başına taşır ama orchestrator budayıyordu. Madde 6'nın
                        # (NSE→Evidence köprüsü) veri kaynağı burası; şimdilik yalnız akışı aç.
                        "scripts": f.get("scripts", []),
                    })

            scan_stats = raw.get("scan_stats")
            os_detection = None
            if isinstance(scan_stats, dict):
                os_detection = scan_stats.get("os")
            # OS tespitini kimlik omurgasına taşı (nmap -O) — target_profile 'os' boyutu +
            # 'çıplak sunucu' çerçevesi bunu kullanır (eskiden yalnız ekran tablosuna gidiyordu).
            if os_detection:
                self.discovered_data["os_detection"] = os_detection

            # HOST DURUMU: nmap servisi XML runstats'tan türetir; eski servis sürümü
            # alanı hiç göndermiyorsa 'up' varsay (geriye-uyumlu).
            host_status = str(raw.get("host_status") or "up").strip().lower()

            data = {
                "open_ports": open_ports,
                "services": services,
                "os_detection": os_detection,
                "raw_output": (raw.get("output", "") or "")[:10000],
                "host_status": host_status,
                "findings_detail": findings[:50],  # Detaylı port bilgisi (ilk 50)
            }

            # Port sayısı
            port_count = len(open_ports)

            # DÜRÜST-TARAMA (ölü hedef ayrımı): KÖK hedefin nmap'i 'down' döndürdüyse
            # taramayı sürdürmek BOŞ rapor + "temiz göründü" yalanı üretir. Motor bu
            # bayrağı görünür kılan WARNING ile döngüyü erkenden keser. Yalnız kök
            # hedef taramasında (scan_target yok — keşfedilen alt hostlar değil):
            # bir subdomain/origin IP down olabilir, bu TÜM taramayı öldürmemeli.
            if host_status == "down" and not options.get("scan_target"):
                data["host_unreachable"] = True
                data["note"] = "hedef_down: nmap runstats 'up=0' — host yanıt vermiyor"

            return StageResult(
                stage_name=stage.name,
                tool="nmap",
                status="completed",
                data=data,
            )

    # ---- Nuclei ----
    async def _check_nuclei_templates(self) -> Dict[str, Any]:
        """Nuclei template kütüphanesinin FIilen dolu olduğunu doğrula (dürüst-tarama).

        /health yanıtı `templates_count` + `templates_ok` taşır (K7 self-check).
        Döner: {"blind": bool, "templates_count": int, "reason": str}.
        Servis erişilemez/yanıt bozuksa {"blind": False} — kapı yok sayılır
        (servis-down durumu preflight'te ayrıca uyarılır; burada ekstra ceza yok).
        Eşik: NUCLEI_TEMPLATE_MIN (varsayılan 100) — nuclei-service kendi self-check'i
        ile AYNI eşik → iki taraf tek sözleşme."""
        min_templates = int(os.getenv("NUCLEI_TEMPLATE_MIN", "100"))
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=3.0)) as hc:
                resp = await hc.get(f"{NUCLEI_SERVICE_URL}/health")
                if resp.status_code != 200:
                    return {"blind": False, "reason": f"health HTTP {resp.status_code}"}
                payload = resp.json()
            count = int(payload.get("templates_count") or 0)
            ok = bool(payload.get("templates_ok"))
            return {
                "blind": (not ok) or (count < min_templates),
                "templates_count": count,
                "reason": "" if ok and count >= min_templates else "templates_ok=False veya eşik altı",
            }
        except Exception as e:
            return {"blind": False, "reason": f"health erişilemedi: {e}"}

    async def _dispatch_nuclei(self, stage: StageDefinition) -> StageResult:
        """Nuclei servisine tarama gönder ve polling ile sonucu bekle"""
        options = dict(stage.options)

        # Türkçe: DAST/aktif fuzzing kipi — graf, web-app düğümü için bu kenarı
        # options["dast"]=True ile doğurur. DAST açıkken parametre enjeksiyonu (xss/sqli...)
        # canlı denenir; bu yüzden "fuzz" hariç tutulmaz.
        is_dast = bool(options.get("dast"))
        exclude_tags = options.get("exclude_tags", ["dos"] if is_dast else ["dos", "fuzz"])
        # IPB tag-scope: hedef profilinden gelen ilgisiz-yığın etiketlerini EKLE (ör. hedef
        # kesinlikle Node ise php/wordpress/... elenir). Yalnız EKLEME → kapsam daralmaz,
        # generic/cve/misconfig/exposure template'leri aynen çalışır. Bilinçli+gerekli tarama.
        if self.profile_exclude_tags:
            exclude_tags = list(dict.fromkeys(list(exclude_tags) + list(self.profile_exclude_tags)))

        # GENİŞ TARAMA HIZLANDIRMA: cve_sweep (tag kısıtsız, ~4158 template) ve geniş tag
        # taramaları tek tek çalışınca 10dk'yı aşıp timeout'a giriyordu. Bu taramalarda
        # rate-limit ve concurrency'i yükseltip aynı kapsamı ~3-4x hızlı bitiririz (stealth'ten
        # ödün: yalnız geniş taramada, hedefli/DAST taramada eski düşük değerler korunur).
        is_broad = bool(options.get("cve_sweep")) or len(options.get("tags", []) or []) >= 5
        if is_broad and not is_dast:
            default_rate, default_conc, default_bulk = 500, 50, 40
        else:
            default_rate, default_conc, default_bulk = 300, 25, 25

        nuclei_config = {
            "target": self.target,
            "scan_id": self.scan_id,
            # K2: severity tabanı 'medium' (kurumsal görünürlük). options'ta açıkça gelirse o
            # kullanılır (hedefli CVE taramaları critical,high geçirir). Gelmezse graf'ın
            # merkezi tabanı (AUTONOMOUS_SEVERITY_FLOOR, vars. medium) devreye girer.
            "severity": options.get("severity") or list(_DEFAULT_SEVERITY),
            "tags": options.get("tags", []),
            "templates": options.get("templates", []),
            "rate_limit": options.get("rate_limit", default_rate),
            # Per-template timeout: 3sn yavaş hedeflerde template'leri SESSİZCE zaman aşımına
            # uğratıp eşleşmeyi kaçırıyordu ("bulgu yok" sanılıyordu). 8sn güvenilir denge;
            # NUCLEI_TEMPLATE_TIMEOUT ile ayarlanabilir.
            "timeout": options.get("timeout", int(os.getenv("NUCLEI_TEMPLATE_TIMEOUT", "8"))),
            "retries": options.get("retries", 1),
            "bulk_size": default_bulk,
            "concurrency": default_conc,
            "exclude_tags": exclude_tags,
            # Türkçe: KANIT modu — bulguyu tetikleyen ham istek/yanıtı çıktıya dahil et.
            # Otonom taramada kanıt kalitesi için varsayılan AÇIK.
            "include_rr": options.get("include_rr", True),
            # Türkçe: aktif web/API zafiyet testi (madde 3)
            "dast": is_dast,
            # Türkçe: kimlik doğrulamalı tarama başlıkları (madde 2) — login arkası yüzey.
            "custom_headers": self.auth_headers,
            # Türkçe: Faz 1 — endpoint keşfinden gelen URL corpus'u (DAST için). Verilirse
            # nuclei `target` yerine bu URL'leri `-u` ile tek tek tarar. Crawler keşfinden
            # gelen parametreli endpoint'ler buradan beslenir; nuclei `-dast` ile bunları
            # enjeksiyon için canlı test eder.
            "urls": options.get("urls"),
        }

        # DÜRÜST-TARAMA (template körü kapısı): nuclei servisi AYAKTA ama template
        # kütüphanesi boş/eksik olabilir (offline build, başarısız indirme) → her tarama
        # 0 bulgu döner → kullanıcı "temiz" sanır. Bu, sessiz boş taramanın en yaygın
        # kaynağıdır. Scan başına BİR kez /health bakılır (önbellekli); templates_ok
        # False ise aşamayı FAILED işaretle → §2.6 degraded görünürlüğü + WARNING
        # devreye girer, motor diğer araçlarla sürer. Servis zaten erişilemiyorsa
        # kapı ATLANIR (servis-down uyarısı preflight'te ayrıca var; çifte ceza yok).
        try:
            _tpl_state = getattr(self, "_nuclei_template_state", None)
            if _tpl_state is None:
                _tpl_state = await self._check_nuclei_templates()
                self._nuclei_template_state = _tpl_state
            if _tpl_state.get("blind"):
                _tc = _tpl_state.get("templates_count")
                return StageResult(
                    stage_name=stage.name,
                    tool="nuclei",
                    status="failed",
                    error=(
                        f"Nuclei template kütüphanesi yetersiz ({_tc} template) — "
                        f"tarama KÖR çalışırdı (0 bulgu ≠ temiz). Template'leri "
                        f"güncelleyin (nuclei -update-templates) veya NUCLEI_TEMPLATE_MIN "
                        f"eşikini gözden geçirin."
                    ),
                )
        except Exception as _ntpl_e:
            logger.debug(f"Nuclei template health gate atlandı: {_ntpl_e}")

        async with httpx.AsyncClient() as client:
            # Taramayı başlat
            response = await client.post(
                f"{NUCLEI_SERVICE_URL}/scan",
                json=nuclei_config,
                timeout=30.0,
            )

            if response.status_code != 200:
                return StageResult(
                    stage_name=stage.name,
                    tool="nuclei",
                    status="failed",
                    error=f"Nuclei başlatılamadı: HTTP {response.status_code}",
                )

            logger.info(f"Nuclei scan başlatıldı: {self.scan_id}")

            # Exponential backoff polling
            async def check_nuclei():
                status_res = await client.get(
                    f"{NUCLEI_SERVICE_URL}/status/{self.scan_id}",
                    timeout=10.0,
                )
                status_data = status_res.json()
                current_status = status_data.get("status")

                if current_status == "completed":
                    # Sonuçları al
                    log_res = await client.get(
                        f"{NUCLEI_SERVICE_URL}/logs/{self.scan_id}",
                        timeout=120.0,
                    )
                    if log_res.status_code == 200:
                        log_data = log_res.json()
                        findings = log_data.get("findings", [])
                        severity_counts = log_data.get("severity_counts", {})

                        # Severity'ye göre sırala
                        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                        findings.sort(key=lambda x: severity_order.get(
                            x.get("info", {}).get("severity", "info"), 5
                        ))

                        return {
                            "done": True,
                            "result": {
                                "status": "completed",
                                "data": {
                                    "findings": findings[:100],
                                    "findings_count": len(findings),
                                    "raw_findings_count": log_data.get("raw_findings_count", len(findings)),
                                    "filtered_fp_count": log_data.get("filtered_count", 0),
                                    "severity_counts": severity_counts,
                                },
                            },
                        }
                    return {"done": True, "result": {"status": "completed", "data": {}}}

                elif current_status == "failed":
                    return {
                        "done": True,
                        "result": {
                            "status": "failed",
                            "error": status_data.get("error", "Bilinmeyen hata"),
                        },
                    }

                elif current_status in ("not_found", "unknown"):
                    # Process kaybolmuş olabilir - MongoDB'den kontrol et
                    try:
                        logs_res = await client.get(
                            f"{NUCLEI_SERVICE_URL}/logs/{self.scan_id}",
                            timeout=30.0,
                        )
                        if logs_res.status_code == 200:
                            logs_data = logs_res.json()
                            if logs_data.get("findings") is not None:
                                return {
                                    "done": True,
                                    "result": {
                                        "status": "completed",
                                        "data": {
                                            "findings": logs_data.get("findings", [])[:100],
                                            "findings_count": len(logs_data.get("findings", [])),
                                            "severity_counts": logs_data.get("severity_counts", {}),
                                        },
                                    },
                                }
                    except Exception:
                        pass

                return {"done": False}

            poll_result = await poll_with_backoff(
                check_fn=check_nuclei,
                max_timeout=stage.timeout_seconds,
                initial_interval=3.0,
                max_interval=30.0,
            )

            # KISMİ SONUÇ KURTARMA: nuclei servisi bulguları CANLI (her satırda) MongoDB'ye
            # yazar. Poll max_timeout'a takılırsa (büyük hedef/çok template → 10dk+) eskiden
            # status='timeout' + boş data dönüyordu → o ana kadar bulunan TÜM kanıt ÇÖPE
            # gidiyordu (ekranda "kanıt 0" ama tarama 4158 template denemişti). Artık timeout'ta
            # /logs'tan o ana kadarki bulguları çekip 'partial' olarak döndürürüz.
            if poll_result.get("status") == "timeout":
                partial = await self._fetch_nuclei_partial(client)
                # Arkada zombi nuclei süreci kalmasın — kaynakları tüketmesin, sonraki
                # aşamalarla scan_id çakışmasın. (Ignore 404: zaten bitmiş olabilir.)
                try:
                    await client.delete(
                        f"{NUCLEI_SERVICE_URL}/scan/{self.scan_id}", timeout=10.0,
                    )
                except Exception:
                    pass
                if partial.get("findings"):
                    logger.info(
                        f"🛟 [{self.scan_id[:8]}] Nuclei timeout ama {len(partial['findings'])} "
                        f"KISMİ bulgu kurtarıldı (tarama bitmedi, bulunanlar korunuyor)."
                    )
                    partial["partial"] = True  # rapor 'tarama yarıda kesildi' notu düşebilir
                    return StageResult(
                        stage_name=stage.name, tool="nuclei",
                        status="completed",  # kısmi de olsa bulgu var → motor işlesin
                        data=partial,
                        error="Nuclei timeout — kısmi sonuçlar kurtarıldı (tarama tamamlanmadı).",
                    )

            return StageResult(
                stage_name=stage.name,
                tool="nuclei",
                status=poll_result.get("status", "failed"),
                data=poll_result.get("data", {}),
                error=poll_result.get("error"),
            )

    async def _fetch_nuclei_partial(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Nuclei /logs'tan o ana kadar CANLI yazılmış bulguları çek (timeout kurtarma).
        Nuclei süreci öldürülmeden önce yazdığı FINDING'ler MongoDB'de durur; bunları
        toplarız. Hata/veri yoksa boş findings döner (sessiz — regresyon yok)."""
        try:
            log_res = await client.get(
                f"{NUCLEI_SERVICE_URL}/logs/{self.scan_id}", timeout=60.0,
            )
            if log_res.status_code == 200:
                log_data = log_res.json()
                findings = log_data.get("findings", []) or []
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                findings.sort(key=lambda x: severity_order.get(
                    x.get("info", {}).get("severity", "info"), 5))
                return {
                    "findings": findings[:100],
                    "findings_count": len(findings),
                    "severity_counts": log_data.get("severity_counts", {}),
                }
        except Exception as e:
            logger.debug(f"Nuclei kısmi bulgu çekme hatası: {e}")
        return {"findings": []}

    async def _fetch_nmap_partial(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Nmap /partial'dan o ana kadar bulunan portları çek (timeout kurtarma).
        Nmap-service açık portları CANLI (kısmi XML + NmapLogs) yazar; süreç öldürülmeden
        önce yazdıkları kalır. Dönen şekil _dispatch_nmap'in data sözleşmesiyle aynıdır
        (open_ports/services/findings_detail) — motor/graf ayrım gözetmeden işler.
        Hata/veri yoksa boş open_ports döner (sessiz — regresyon yok)."""
        try:
            res = await client.get(
                f"{NMAP_SERVICE_URL}/partial/{self.scan_id}", timeout=60.0,
            )
            if res.status_code == 200:
                raw = res.json()
                findings = raw.get("findings_summary", []) or []
                if not isinstance(findings, list):
                    findings = []
                open_ports, services = [], []
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    port_num = f.get("port")
                    if port_num is not None:
                        open_ports.append(port_num)
                    services.append({
                        "port": f.get("port"),
                        "protocol": f.get("protocol", "tcp"),
                        "service": f.get("service", "unknown"),
                        "product": f.get("product", ""),
                        "version": f.get("version", ""),
                        "extrainfo": f.get("extrainfo", ""),
                        "state": f.get("state", "open"),
                        # NSE script çıktıları — real-IP yolunda da aynı akış (Madde 6 kaynağı).
                        "scripts": f.get("scripts", []),
                    })
                return {
                    "open_ports": open_ports,
                    "services": services,
                    "os_detection": None,
                    "raw_output": "",
                    "host_status": "up",
                    "findings_detail": findings[:50],
                }
        except Exception as e:
            logger.debug(f"Nmap kısmi port çekme hatası: {e}")
        return {"open_ports": []}

    # ---- Subfinder ----
    async def _dispatch_subfinder(self, stage: StageDefinition) -> StageResult:
        """Subfinder servisine subdomain keşif isteği gönder"""
        options = dict(stage.options)

        subfinder_config = {
            "target": self.target,
            "scan_id": self.scan_id,
            "recursive": options.get("recursive", False),
            "timeout": options.get("timeout", 30),
            "rate_limit": options.get("rate_limit", 0),
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{SUBFINDER_SERVICE_URL}/scan",
                json=subfinder_config,
                timeout=30.0,
            )

            if response.status_code != 200:
                return StageResult(
                    stage_name=stage.name,
                    tool="subfinder",
                    status="failed",
                    error=f"Subfinder başlatılamadı: HTTP {response.status_code}",
                )

            logger.info(f"Subfinder scan başlatıldı: {self.scan_id}")

            async def check_subfinder():
                status_res = await client.get(
                    f"{SUBFINDER_SERVICE_URL}/status/{self.scan_id}",
                    timeout=10.0,
                )
                status_data = status_res.json()
                current_status = status_data.get("status")

                if current_status in ("unknown", "not_found"):
                    # MongoDB'den kontrol
                    try:
                        logs_res = await client.get(
                            f"{SUBFINDER_SERVICE_URL}/logs/{self.scan_id}",
                            timeout=30.0,
                        )
                        if logs_res.status_code == 200:
                            logs_data = logs_res.json()
                            for log in logs_data.get("logs", []):
                                if log.get("level") == "SCAN_END":
                                    current_status = "completed"
                                    break
                    except Exception:
                        pass

                if current_status == "completed":
                    log_res = await client.get(
                        f"{SUBFINDER_SERVICE_URL}/logs/{self.scan_id}",
                        timeout=60.0,
                    )
                    if log_res.status_code == 200:
                        log_data = log_res.json()
                        return {
                            "done": True,
                            "result": {
                                "status": "completed",
                                "data": {
                                    "subdomains": log_data.get("subdomains", []),
                                    "subdomains_count": log_data.get("subdomains_count", 0),
                                    "source_counts": log_data.get("source_counts", {}),
                                },
                            },
                        }
                    return {"done": True, "result": {"status": "completed", "data": {}}}

                elif current_status == "failed":
                    return {
                        "done": True,
                        "result": {
                            "status": "failed",
                            "error": status_data.get("error", "Bilinmeyen hata"),
                        },
                    }

                return {"done": False}

            poll_result = await poll_with_backoff(
                check_fn=check_subfinder,
                max_timeout=stage.timeout_seconds,
                initial_interval=3.0,
                max_interval=15.0,
            )

            return StageResult(
                stage_name=stage.name,
                tool="subfinder",
                status=poll_result.get("status", "failed"),
                data=poll_result.get("data", {}),
                error=poll_result.get("error"),
            )

    # ---- RustScan ----
    async def _dispatch_rustscan(self, stage: StageDefinition) -> StageResult:
        """RustScan servisine port tarama isteği gönder"""
        options = dict(stage.options)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{RUSTSCAN_SERVICE_URL}/scan",
                json={
                    "target": self.target,
                    "scan_id": self.scan_id,
                    "options": options,
                },
                timeout=30.0,
            )

            if response.status_code != 200:
                return StageResult(
                    stage_name=stage.name,
                    tool="rustscan",
                    status="failed",
                    error=f"RustScan başlatılamadı: HTTP {response.status_code}",
                )

            # RustScan için de polling (MongoDB tabanlı)
            async def check_rustscan():
                status_res = await client.get(
                    f"{RUSTSCAN_SERVICE_URL}/status/{self.scan_id}",
                    timeout=10.0,
                )
                status_data = status_res.json()
                current_status = status_data.get("status")

                if current_status == "completed":
                    return {
                        "done": True,
                        "result": {
                            "status": "completed",
                            "data": {
                                "open_ports": status_data.get("open_ports", []),
                                "open_ports_count": status_data.get("open_ports_count", 0),
                                "services": status_data.get("services", []),
                            },
                        },
                    }
                elif current_status in ("failed", "stopped"):
                    return {
                        "done": True,
                        "result": {
                            "status": "failed",
                            "error": status_data.get("error", "RustScan failed"),
                        },
                    }
                return {"done": False}

            poll_result = await poll_with_backoff(
                check_fn=check_rustscan,
                max_timeout=stage.timeout_seconds,
                initial_interval=2.0,
                max_interval=15.0,
            )

            return StageResult(
                stage_name=stage.name,
                tool="rustscan",
                status=poll_result.get("status", "failed"),
                data=poll_result.get("data", {}),
                error=poll_result.get("error"),
            )

    # ---- Fuzz ----
    async def _dispatch_fuzz(self, stage: StageDefinition) -> StageResult:
        """Fuzz servisine dizin keşif isteği gönder"""
        options = dict(stage.options)

        # Türkçe: Kimlik doğrulamalı fuzzing (madde 2) — feroxbuster başlıkları config.headers
        # altında bekler (fuzz-service ScanConfig). Auth varsa login arkası dizinler de keşfedilir.
        fuzz_config: Dict[str, Any] = dict(options.get("config", {}))
        if self.auth_headers:
            fuzz_config["headers"] = list(dict.fromkeys(
                list(fuzz_config.get("headers", [])) + self.auth_headers
            ))

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{FUZZ_SERVICE_URL}/scan",
                json={
                    "target": self.target,
                    "scan_id": self.scan_id,
                    "wordlist": options.get("wordlist", "common.txt"),
                    "config": fuzz_config,
                    "options": options,
                },
                timeout=30.0,
            )

            if response.status_code != 200:
                return StageResult(
                    stage_name=stage.name,
                    tool="fuzz",
                    status="failed",
                    error=f"Fuzz başlatılamadı: HTTP {response.status_code}",
                )

            async def _collect_fuzz_logs():
                """/logs'tan bulguları çek, SOFT-404 gürültüsünü ELE, dizin/dosya ayrıştır.

                SOFT-404 SORUNU: bazı hostlar olmayan yola da 200 + neredeyse-aynı içerik döner
                (wildcard). feroxbuster o zaman tüm wordlist'i "bulgu" sanar (gözlemlenen: tek
                hostta 5000 sahte kayıt). Eleme mantığı: aynı (status, content_length) çifti
                ANORMAL çok tekrar ediyorsa (bir imza N'den fazla URL'de) bu bir soft-404
                şablonudur → o kümeyi at. Gerçek bulgular (az sayıda, farklı boyut) kalır."""
                raw_items: List[Dict[str, Any]] = []
                try:
                    logs_res = await client.get(
                        f"{FUZZ_SERVICE_URL}/logs/{self.scan_id}", timeout=15.0,
                    )
                    if logs_res.status_code == 200:
                        raw_items = [it for it in (logs_res.json() or []) if isinstance(it, dict) and it.get("url")]
                except Exception as fetch_err:
                    logger.debug(f"Fuzz logs çekilemedi: {fetch_err}")
                    return [], []

                # Soft-404 imza sayımı: (status, content_length) → kaç URL. Bir imza toplam
                # bulgunun büyük kısmını kaplıyorsa (ve mutlak sayı yüksekse) wildcard'dır.
                from collections import Counter
                sig_counter: Counter = Counter()
                for it in raw_items:
                    sig_counter[(it.get("status"), it.get("content_length"))] += 1
                total = len(raw_items)
                # Bir imza, ya toplamın %40'ından fazlasını ya da mutlak 25'ten fazlasını
                # kaplıyorsa soft-404 şablonu say. (İki koşul da: küçük taramada oran, büyük
                # taramada mutlak sayı yakalar.)
                soft404_sigs = {
                    sig for sig, n in sig_counter.items()
                    if n >= max(25, int(total * 0.4))
                }
                if soft404_sigs:
                    logger.info(f"Fuzz soft-404 elemesi: {sum(sig_counter[s] for s in soft404_sigs)}/"
                                f"{total} kayıt wildcard şablonu — atlandı. scan={self.scan_id[:8]}")

                directories: List[str] = []
                files: List[str] = []
                for it in raw_items:
                    sig = (it.get("status"), it.get("content_length"))
                    if sig in soft404_sigs:
                        continue  # soft-404 gürültüsü
                    url = it["url"]
                    path_part = url.split("://", 1)[-1].split("/", 1)[-1].rstrip("/")
                    last_seg = path_part.rsplit("/", 1)[-1] if path_part else ""
                    if "." in last_seg:
                        files.append(url)
                    else:
                        directories.append(url)
                return directories, files

            # DAYANIKLILIK: status endpoint'i (Rust /api/v2/scans/{id}/status) tarihsel olarak
            # BSON-datetime serde bug'ıyla HTTP 500 dönebiliyordu → fuzz hiç "completed"
            # görünmüyor, her tarama timeout'a düşüyordu. Artık status'a GÜVENMİYORUZ: durumu
            # logs'un DURAĞANLIĞINDAN çıkarıyoruz. Status çalışırsa erken bitiş sinyali olarak
            # kullanılır (bonus); çalışmazsa logs-tabanlı algı devreye girer (garanti).
            _stable = {"last_count": -1, "stable_polls": 0}

            async def check_fuzz():
                # 1) Status'u DENE (varsa erken/temiz bitiş sinyali). 500/404 → yok say.
                try:
                    status_res = await client.get(
                        f"{FUZZ_SERVICE_URL}/api/v2/scans/{self.scan_id}/status",
                        timeout=10.0,
                    )
                    if status_res.status_code == 200:
                        status_data = status_res.json() or {}
                        cs = str(status_data.get("status", "")).lower()
                        if cs == "completed":
                            directories, files = await _collect_fuzz_logs()
                            return {"done": True, "result": {"status": "completed", "data": {
                                "findings_count": status_data.get("findings_count", len(directories) + len(files)),
                                "directories": directories, "files": files}}}
                        if cs in ("failed", "cancelled"):
                            return {"done": True, "result": {"status": "failed",
                                    "error": status_data.get("error") or f"Fuzz {cs}"}}
                except Exception as e:
                    logger.debug(f"Fuzz status okunamadı (logs-fallback devrede): {e}")

                # 2) LOGS-TABANLI ALGI (status'a bağımlı değil): bulgu sayısı ARDIŞIK
                # birkaç poll'da SABİT kaldıysa feroxbuster bitmiş demektir → topla ve bitir.
                directories, files = await _collect_fuzz_logs()
                count = len(directories) + len(files)
                if count == _stable["last_count"]:
                    _stable["stable_polls"] += 1
                else:
                    _stable["last_count"] = count
                    _stable["stable_polls"] = 0
                # 3 ardışık sabit poll (~ initial_interval*3) + en az bir bulgu VEYA hiç bulgu
                # yokken daha uzun sabitlik → tamamlandı say. (Soft-404 host'larda bile durur.)
                stable_needed = 3 if count > 0 else 5
                if _stable["stable_polls"] >= stable_needed:
                    logger.info(f"Fuzz logs-tabanlı tamamlandı: {count} bulgu "
                                f"({_stable['stable_polls']} sabit poll). scan={self.scan_id[:8]}")
                    return {"done": True, "result": {"status": "completed", "data": {
                        "findings_count": count, "directories": directories, "files": files}}}
                return {"done": False}

            poll_result = await poll_with_backoff(
                check_fn=check_fuzz,
                max_timeout=stage.timeout_seconds,
                initial_interval=3.0,
                max_interval=20.0,
            )

            return StageResult(
                stage_name=stage.name,
                tool="fuzz",
                status=poll_result.get("status", "failed"),
                data=poll_result.get("data", {}),
                error=poll_result.get("error"),
            )

    # ---- Recon (Cloudflare bypass, real IP, tech fingerprint) ----
    async def _dispatch_recon(self, stage: StageDefinition) -> StageResult:
        """
        Recon servisine analiz isteği gönder.
        Cloudflare arkasındaki gerçek IP'yi bulur, teknoloji parmak izi çıkarır.
        Bulunan gerçek IP'yi discovered_data'ya kaydeder -> sonraki stage'ler kullanır.
        """
        options = dict(stage.options)

        # Alt-domain kontrolü: hedef portal.example-corp.com gibi zaten alt-domain ise
        # 5000'lik devasa liste gereksizdir ve DNS tarpit/drop riskini artırır.
        target_domain = self.target.strip().lower()
        parts = [p for p in target_domain.split(".") if p]
        is_subdomain = len(parts) > 2 and not (len(parts) == 3 and parts[-2] in ("com", "org", "net", "edu", "gov", "co", "me", "io"))

        # Bounded timeout: recon takılıp tüm taramayı 10 dakika rehin almasın (subdomain: 90s, apex: 180s)
        max_recon_secs = options.get("timeout_seconds", 90 if is_subdomain else 180)
        actual_timeout_secs = min(stage.timeout_seconds, max_recon_secs)

        recon_config = {
            "domain": self.target,
            "wordlist": options.get(
                "wordlist",
                "files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt",
            ),
            "concurrency": options.get("concurrency", 30 if is_subdomain else 50),
            "delay_ms": options.get("delay_ms", 0),
            "timeout_minutes": max(1, (actual_timeout_secs - 15) // 60),
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{RECON_SERVICE_URL}/analyze",
                json=recon_config,
                timeout=15.0,
            )

            if response.status_code != 200:
                return StageResult(
                    stage_name=stage.name,
                    tool="recon",
                    status="failed",
                    error=f"Recon başlatılamadı: HTTP {response.status_code}",
                )

            scan_data = response.json()
            recon_scan_id = scan_data.get("id") or scan_data.get("scan_id", "")

            logger.info(f"Recon scan başlatıldı: {recon_scan_id}")

            async def check_recon():
                status_res = await client.get(
                    f"{RECON_SERVICE_URL}/analyze/{recon_scan_id}",
                    timeout=10.0,
                )
                # SERT-DURUŞ (recon-bitmeme kök nedeni): recon-service
                # `GET /analyze/:id` yanıtı `Json<Option<..>>` — scan id bellekteki
                # haritada YOKSA (servis yeniden başladı / kayıt düşürüldü) 200 + gövde
                # `null` döner. Eskiden `status_data.get(...)` None üstünde patlıyor,
                # poll_with_backoff bunu yutup terminal state göremiyor → tüm bütçe
                # (600sn) BOŞA dönüyordu. Artık kalıcı-yokluk (null/non-200) TERMİNAL
                # sayılır → hızlı 'failed' → `_maybe_recon_fallback` kısmi kurtarmayı
                # HEMEN devralır. Sağlıklı tarama (dict gövde) yolu değişmez.
                if status_res.status_code != 200:
                    return {"done": True, "result": {
                        "status": "failed",
                        "error": f"Recon durum sorgusu HTTP {status_res.status_code}",
                    }}
                try:
                    status_data = status_res.json()
                except Exception:
                    status_data = None
                if not isinstance(status_data, dict):
                    return {"done": True, "result": {
                        "status": "failed",
                        "error": "Recon durumu bulunamadı (servis yeniden başlamış olabilir)",
                    }}
                current_state = status_data.get("state", status_data.get("status", ""))

                # İptal/durdurma da terminal — aksi halde iptalde de 600sn dönerdi.
                if current_state in ("Cancelled", "cancelled", "Stopped", "stopped"):
                    return {"done": True, "result": {
                        "status": "failed",
                        "error": status_data.get("error", "Recon iptal edildi"),
                    }}

                if current_state in ("Completed", "completed"):
                    result_data = status_data.get("result", status_data)

                    # DNS bilgilerini çıkar
                    dns_info = result_data.get("dns", {})
                    is_cf = dns_info.get("is_cf", False)
                    ips = dns_info.get("ips", [])

                    # HTTP bilgilerini çıkar
                    http_info = result_data.get("http", {})
                    found_cf = http_info.get("found_cf", False)
                    technologies = http_info.get("technologies", [])

                    # Subdomain bilgilerini çıkar
                    sub_info = result_data.get("subdomains", {})
                    found_subs = sub_info.get("found", [])

                    # Gerçek IP'leri tespit et (CF olmayan subdomain IP'leri)
                    real_ips = []
                    cf_ips = []
                    for sub in found_subs:
                        sub_ips = sub.get("ips", []) if isinstance(sub, dict) else []
                        sub_is_cf = sub.get("is_cf", True) if isinstance(sub, dict) else True
                        if not sub_is_cf and sub_ips:
                            real_ips.extend(sub_ips)
                        elif sub_is_cf and sub_ips:
                            cf_ips.extend(sub_ips)

                    # Ana domain IP'leri de ekle (CF değilse)
                    if not is_cf and ips:
                        real_ips.extend(ips)

                    real_ips = list(set(real_ips))
                    cf_ips = list(set(cf_ips))

                    # ADAPTIVE: Gerçek IP'leri sonraki stage'ler için kaydet
                    if real_ips:
                        self.discovered_data["real_ips"] = real_ips
                        self.discovered_data["primary_real_ip"] = real_ips[0]
                        logger.info(
                            f"ADAPTIVE: Gerçek IP bulundu: {real_ips} "
                            f"(CF bypass başarılı)"
                        )

                    self.discovered_data["is_behind_cf"] = is_cf or found_cf
                    self.discovered_data["technologies"] = technologies
                    self.discovered_data["subdomains_from_recon"] = [
                        s.get("subdomain", s) if isinstance(s, dict) else s
                        for s in found_subs
                    ]

                    # SSE event: gerçek IP bulundu
                    if real_ips:
                        await ScanEventBus.publish(ScanEvent(
                            scan_id=self.scan_id,
                            event_type=ScanEventType.CRITICAL_FINDING,
                            data={
                                "type": "real_ip_discovered",
                                "real_ips": real_ips,
                                "is_cf_bypass": is_cf or found_cf,
                                "message": f"Cloudflare bypass: {len(real_ips)} gerçek IP bulundu",
                            },
                        ))

                    return {
                        "done": True,
                        "result": {
                            "status": "completed",
                            "data": {
                                "is_cloudflare": is_cf or found_cf,
                                "domain_ips": ips,
                                "real_ips": real_ips,
                                "cf_ips": cf_ips,
                                "technologies": technologies,
                                "subdomains": [
                                    {
                                        "name": s.get("subdomain", "") if isinstance(s, dict) else str(s),
                                        "ips": s.get("ips", []) if isinstance(s, dict) else [],
                                        "is_cf": s.get("is_cf", True) if isinstance(s, dict) else True,
                                    }
                                    for s in found_subs[:100]
                                ],
                                "subdomains_count": len(found_subs),
                                "http_headers": http_info.get("headers", {}),
                                "page_title": http_info.get("page_title", ""),
                            },
                        },
                    }

                elif current_state in ("Failed", "failed"):
                    return {
                        "done": True,
                        "result": {
                            "status": "failed",
                            "error": status_data.get("error", "Recon failed"),
                        },
                    }

                return {"done": False}

            poll_result = await poll_with_backoff(
                check_fn=check_recon,
                max_timeout=actual_timeout_secs,
                initial_interval=3.0,
                max_interval=15.0,
            )

            return StageResult(
                stage_name=stage.name,
                tool="recon",
                status=poll_result.get("status", "failed"),
                data=poll_result.get("data", {}),
                error=poll_result.get("error"),
            )

    async def _maybe_recon_fallback(
        self, stage: StageDefinition, result: StageResult, started_at: datetime
    ) -> StageResult:
        """DAYANIKLILIK (K5): recon başarısız/timeout olduysa VEYA hiç teknoloji bulamadıysa,
        hedefe DOĞRUDAN hafif HTTP/HTTPS probe at. Böylece recon servisi (subdomain
        brute-force/DNS) yavaş/başarısız olsa bile motor en azından 'web var mı + sunucu
        banner' bilgisini alır → nuclei web-surface taraması yine tetiklenir. Aksi halde
        recon her takıldığında tüm zincir kopup tarama BOŞ dönüyordu.

        Yalnız recon stage'i için çalışır; diğer araçlarda sonucu aynen geçirir."""
        if stage.tool != "recon":
            return result
        data = result.data or {}
        if result.status == "completed" and data.get("technologies"):
            return result  # recon zaten teknoloji buldu — fallback gereksiz
        probe = await self._http_probe(self.target)
        if not probe.get("alive"):
            return result  # web canlı değil — recon sonucunu (fail/timeout) aynen bırak
        merged = dict(data)
        if not merged.get("technologies"):
            merged["technologies"] = probe.get("technologies", [])
        merged.setdefault("is_cloudflare", probe.get("is_cloudflare", False))
        merged.setdefault("page_title", probe.get("page_title", ""))
        merged.setdefault("http_headers", probe.get("headers", {}))
        merged["_recon_fallback"] = True  # şeffaflık: bu veri doğrudan probe'dan geldi
        self.discovered_data["technologies"] = merged.get("technologies", [])
        logger.info(
            f"🛟 [{self.scan_id[:8]}] Recon fallback HTTP probe: web CANLI "
            f"({probe.get('scheme')}) tech={probe.get('technologies')} — "
            f"orijinal recon={result.status}, motor web katmanını işleyebilir."
        )
        return StageResult(
            stage_name=stage.name, tool="recon",
            status="completed", data=merged,  # probe web'i doğruladı → motor işlesin
            started_at=result.started_at,
            completed_at=datetime.utcnow().isoformat(),
            duration_seconds=(datetime.utcnow() - started_at).total_seconds(),
            error=None if result.status == "completed" else f"recon-fallback ({result.status})",
        )

    async def _http_probe(self, target: str) -> Dict[str, Any]:
        """Hafif HTTP/HTTPS canlılık + banner probe'u (recon fallback, K5).

        Recon servisine gitmeden hedefe doğrudan tek bir istek atar: web ayakta mı, hangi
        sunucu/teknoloji, CF arkasında mı, sayfa başlığı ne? Amaç TAM fingerprint değil —
        nuclei web-surface taramasını tetikleyecek asgari sinyali güvence altına almak.
        https:// öncelikli (kurumsal), olmazsa http://. Hata durumunda alive=False döner."""
        target = (target or "").strip()
        if target.startswith(("http://", "https://")):
            candidates = [target]
        else:
            candidates = [f"https://{target}", f"http://{target}"]
        for url in candidates:
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                             timeout=httpx.Timeout(8.0, connect=5.0)) as client:
                    resp = await client.get(url, headers={"User-Agent": "Kadim-Security-Scanner/1.0"})
                headers = {k.lower(): v for k, v in resp.headers.items()}
                techs: List[str] = []
                server = headers.get("server", "")
                if server:
                    techs.append(server.split("/")[0])  # "nginx/1.18" -> "nginx"
                powered = headers.get("x-powered-by", "")
                if powered:
                    techs.append(powered.split("/")[0])
                is_cf = "cloudflare" in server.lower() or "cf-ray" in headers
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", resp.text or "", re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:200]
                return {
                    "alive": True, "scheme": url.split("://")[0],
                    "technologies": list(dict.fromkeys([t for t in techs if t])),
                    "is_cloudflare": is_cf, "page_title": title,
                    "headers": {k: headers.get(k, "") for k in ("server", "x-powered-by", "content-type")},
                    "status_code": resp.status_code,
                }
            except Exception:
                continue
        return {"alive": False}

    # ---- OSINT (Shodan, VirusTotal, AbuseIPDB, WHOIS, SSL) ----
    async def _dispatch_osint(self, stage: StageDefinition) -> StageResult:
        """
        OSINT servisine istihbarat toplama isteği gönder.
        Shodan, VirusTotal, AbuseIPDB, WHOIS, SSL analizi yapar.
        Retry mekanizması ve detaylı loglama içerir.
        """
        options = dict(stage.options)
        lookups = options.get("lookups", ["dns", "whois", "ssl", "shodan", "virustotal"])

        logger.info(
            f"🔍 [{self.scan_id[:8]}] OSINT başlıyor | "
            f"lookups={lookups} | target={self.target}"
        )

        # SSE: Hangi OSINT lookup'ları çalışacağını bildir
        await ScanEventBus.publish(ScanEvent(
            scan_id=self.scan_id,
            event_type=ScanEventType.PROGRESS_UPDATE,
            data={
                "type": "osint_started",
                "lookups": lookups,
                "target": self.target,
                "message": f"OSINT istihbarat toplama: {', '.join(lookups)}",
            },
        ))

        all_data: Dict[str, Any] = {}

        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            # Önce OSINT servisinin erişilebilir olup olmadığını kontrol et
            osint_available = await self._check_osint_health(client)
            if not osint_available:
                logger.warning(
                    f"⚠️ [{self.scan_id[:8]}] OSINT servisi erişilemez! "
                    f"URL={OSINT_SERVICE_URL} | Tüm lookup'lar atlanıyor"
                )
                return StageResult(
                    stage_name=stage.name,
                    tool="osint",
                    status="failed",
                    data={lt: {"error": "OSINT servisi erişilemez"} for lt in lookups},
                    error="OSINT servisi erişilemez - servisin çalıştığından emin olun",
                )

            # Her lookup türü için paralel istek
            tasks = []
            for lookup_type in lookups:
                target = self.target
                # Eğer recon gerçek IP bulduysa, Shodan'a gerçek IP ile sor
                if lookup_type == "shodan" and self.discovered_data.get("primary_real_ip"):
                    target = self.discovered_data["primary_real_ip"]
                    logger.info(f"  ↪ Shodan için gerçek IP kullanılıyor: {target}")

                tasks.append(self._osint_lookup(client, lookup_type, target))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = 0
            fail_count = 0
            for lookup_type, result in zip(lookups, results):
                if isinstance(result, Exception):
                    all_data[lookup_type] = {"error": str(result)}
                    fail_count += 1
                    logger.warning(f"  ❌ OSINT {lookup_type}: {result}")
                elif isinstance(result, dict) and result.get("error"):
                    all_data[lookup_type] = result
                    fail_count += 1
                    logger.warning(f"  ❌ OSINT {lookup_type}: {result['error']}")
                else:
                    all_data[lookup_type] = result
                    success_count += 1
                    logger.info(f"  ✅ OSINT {lookup_type}: veri alındı")

        logger.info(
            f"📊 [{self.scan_id[:8]}] OSINT tamamlandı | "
            f"başarılı={success_count}/{len(lookups)} | başarısız={fail_count}"
        )

        # Shodan'dan bulunan ekstra portları kaydet
        shodan_data = all_data.get("shodan", {})
        shodan_ports = []
        if isinstance(shodan_data, dict) and not shodan_data.get("error"):
            shodan_ports = shodan_data.get("ports", [])

        # ---- ÜCRETSİZ FALLBACK: Shodan InternetDB (API KEY GEREKTİRMEZ) ----
        # "Shodan key almadım" durumunda bile açık port/CVE istihbaratı sağlar.
        # Shodan portu gelmediyse VE elimizde bir IP varsa, key'siz internetdb.shodan.io'dan
        # port/CVE/CPE çekilir. lookups'ta "shodan" olmasa da çalışır (ücretsiz istihbarat
        # yaygın konfigürasyonlarda da devrede kalsın). Haftalık güncellenir, ücretsiz.
        ip_for_idb = self.discovered_data.get("primary_real_ip")
        if not ip_for_idb and self._is_ip_address(self.target):
            ip_for_idb = self.target
        if not shodan_ports and ip_for_idb:
            idb = await self._internetdb_lookup(ip_for_idb)
            if idb and not idb.get("error"):
                all_data["internetdb"] = idb
                shodan_ports = idb.get("ports", [])
                logger.info(f"🆓 InternetDB (keysiz): {len(shodan_ports)} port, "
                            f"{len(idb.get('vulns', []))} CVE bulundu ({ip_for_idb})")

        if shodan_ports:
            self.discovered_data["shodan_ports"] = shodan_ports
            logger.info(f"🔓 ADAPTIVE: {len(shodan_ports)} port buldu: {shodan_ports[:10]}")

        # CPE KİMLİK OMURGASI: Shodan/InternetDB CPE'leri (cpe:2.3:o:canonical:ubuntu_linux…)
        # — OTORİTER kimlik + NVD/KEV JOIN anahtarı. Elle imza yazmadan hedef kimliğinin ana
        # kaynağı budur; target_profile (cpe_intel ile) bunu tüketir. Vulns da saklanır (CVE).
        _cpes: List[str] = []
        _idb_vulns: List[str] = []
        for _src in ("shodan", "internetdb"):
            _d = all_data.get(_src)
            if isinstance(_d, dict):
                _cpes.extend([c for c in (_d.get("cpes") or []) if isinstance(c, str)])
                _idb_vulns.extend([v for v in (_d.get("vulns") or []) if isinstance(v, str)])
        if _cpes:
            self.discovered_data["cpes"] = list(dict.fromkeys(
                (self.discovered_data.get("cpes") or []) + _cpes))
            logger.info(f"🧬 CPE kimlik: {len(self.discovered_data['cpes'])} CPE "
                        f"(Shodan/InternetDB) → hedef kimliği + CVE join")
        if _idb_vulns:
            self.discovered_data["osint_cve_ids"] = list(dict.fromkeys(
                (self.discovered_data.get("osint_cve_ids") or []) + _idb_vulns))

        # VirusTotal'dan kötü niyetli tespitler
        vt_data = all_data.get("virustotal", {})
        if isinstance(vt_data, dict) and not vt_data.get("error"):
            self.discovered_data["vt_reputation"] = vt_data
            malicious = vt_data.get("malicious", 0)
            if malicious > 0:
                logger.warning(f"🚨 VirusTotal: {malicious} motordan kötü niyetli tespit!")

        # AbuseIPDB tespitler
        abuseipdb_data = all_data.get("abuseipdb", {})
        if isinstance(abuseipdb_data, dict) and not abuseipdb_data.get("error"):
            abuse_score = abuseipdb_data.get("confidence_score", 0)
            if abuse_score > 50:
                logger.warning(f"🚨 AbuseIPDB: Güven skoru {abuse_score}% - kötü niyetli aktivite!")

        is_success = any(
            not isinstance(v, dict) or not v.get("error")
            for v in all_data.values()
        )

        return StageResult(
            stage_name=stage.name,
            tool="osint",
            status="completed" if is_success else "failed",
            data=all_data,
        )

    async def _check_osint_health(self, client: httpx.AsyncClient) -> bool:
        """OSINT servisinin erişilebilir olup olmadığını kontrol et (3 deneme)"""
        for attempt in range(3):
            try:
                response = await client.get(
                    f"{OSINT_SERVICE_URL}/health",
                    timeout=5.0,
                )
                if response.status_code == 200:
                    return True
                logger.warning(
                    f"  ⚠️ OSINT health check HTTP {response.status_code} "
                    f"(deneme {attempt + 1}/3)"
                )
            except Exception as e:
                logger.warning(
                    f"  ⚠️ OSINT health check başarısız: {e} "
                    f"(deneme {attempt + 1}/3)"
                )
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)  # 1s, 2s backoff
        return False

    async def _osint_lookup(
        self, client: httpx.AsyncClient, lookup_type: str, target: str
    ) -> Dict[str, Any]:
        """Tek bir OSINT lookup isteği (retry mekanizmalı)"""
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                response = await client.post(
                    f"{OSINT_SERVICE_URL}/lookup/{lookup_type}",
                    json={"target": target, "domain": target},
                    timeout=60.0,
                )
                if response.status_code == 200:
                    return response.json()
                error_msg = f"HTTP {response.status_code}"
                if attempt < max_retries:
                    logger.debug(f"  🔄 OSINT {lookup_type} retry ({attempt + 1}): {error_msg}")
                    await asyncio.sleep(1.5 ** attempt)
                    continue
                return {"error": error_msg}
            except httpx.ConnectError as e:
                if attempt < max_retries:
                    logger.debug(f"  🔄 OSINT {lookup_type} bağlantı hatası, retry ({attempt + 1})")
                    await asyncio.sleep(1.5 ** attempt)
                    continue
                return {"error": f"Bağlantı hatası: {e}"}
            except httpx.TimeoutException:
                if attempt < max_retries:
                    logger.debug(f"  🔄 OSINT {lookup_type} timeout, retry ({attempt + 1})")
                    await asyncio.sleep(1.5 ** attempt)
                    continue
                return {"error": f"Timeout (60s)"}
            except Exception as e:
                return {"error": str(e)}
        return {"error": "Tüm denemeler başarısız"}

    async def _internetdb_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Türkçe: Shodan InternetDB — API KEY GEREKTİRMEYEN ücretsiz IP istihbaratı.
        Bir IPv4 için açık portları, CVE'leri (vulns), CPE'leri, hostname ve tag'leri döndürür.
        Shodan üyeliği olmayan kurulumlarda "keşif" için ücretsiz port/CVE kaynağıdır.
        Veri haftalık güncellenir. Ticari kullanımda Shodan enterprise lisansı gerekir.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://internetdb.shodan.io/{ip}",
                    headers={"User-Agent": "KadimGuvenlik/1.0", "Accept": "application/json"},
                )
                if resp.status_code == 404:
                    # 404 = bu IP hakkında InternetDB'de kayıt yok (hata değil)
                    return {"ports": [], "vulns": [], "cpes": [], "hostnames": [],
                            "tags": [], "source": "internetdb", "note": "kayıt yok"}
                if resp.status_code != 200:
                    return {"error": f"InternetDB HTTP {resp.status_code}"}
                body = resp.json()
                return {
                    "ip": body.get("ip", ip),
                    "ports": body.get("ports", []),
                    "vulns": body.get("vulns", []),
                    "cpes": body.get("cpes", []),
                    "hostnames": body.get("hostnames", []),
                    "tags": body.get("tags", []),
                    "source": "internetdb (keysiz/ücretsiz)",
                }
        except Exception as e:
            return {"error": f"InternetDB: {e}"}

    # ---- Adaptive Nmap (gerçek IP ile tarama) ----
    async def _dispatch_nmap_real_ip(self, stage: StageDefinition) -> StageResult:
        """
        Recon'dan bulunan gerçek IP üzerinde direkt port taraması.
        Cloudflare arkasındaki sunucuyu doğrudan tarar.
        """
        real_ip = self.discovered_data.get("primary_real_ip")
        if not real_ip:
            logger.info("Gerçek IP bulunamadı, standart nmap'e düşülüyor")
            return await self._dispatch_nmap(stage)

        logger.info(f"ADAPTIVE: Gerçek IP {real_ip} üzerinde direkt tarama başlıyor")

        # SSE event
        await ScanEventBus.publish(ScanEvent(
            scan_id=self.scan_id,
            event_type=ScanEventType.CRITICAL_FINDING,
            data={
                "type": "direct_ip_scan",
                "real_ip": real_ip,
                "message": f"Gerçek IP ({real_ip}) üzerinde direkt port taraması başladı",
            },
        ))

        # Orijinal target'ı geçici olarak değiştir
        original_target = self.target
        self.target = real_ip
        result = await self._dispatch_nmap(stage)
        self.target = original_target

        # Sonucu zenginleştir
        if result.status == "completed":
            result.data["scan_target"] = real_ip
            result.data["original_domain"] = original_target
            result.data["is_direct_ip_scan"] = True

        return result

    # ---- Origin Discovery (Gelişmiş CF/WAF bypass) ----
    async def _dispatch_origin_discovery(self, stage: StageDefinition) -> StageResult:
        """
        Çoklu vektör origin IP keşfi.
        8 farklı teknikle CDN arkasındaki gerçek IP'yi bulmaya çalışır.
        Sonuçlar discovered_data'ya kaydedilir -> sonraki stage'ler kullanır.
        """
        try:
            discovery = OriginDiscovery(self.target, timeout=10)
            result = await discovery.run()
            result_dict = discovery.to_dict(result)

            # Gerçek IP bulunduysa discovered_data'ya kaydet
            if result.best_candidate:
                self.discovered_data["origin_discovery"] = result_dict
                if result.best_candidate.verified or result.best_candidate.confidence >= 60:
                    self.discovered_data["real_ips"] = [
                        c.ip for c in result.candidates if c.confidence >= 50
                    ]
                    self.discovered_data["primary_real_ip"] = result.best_candidate.ip
                    logger.info(
                        f"ORIGIN DISCOVERY: Gerçek IP bulundu: {result.best_candidate.ip} "
                        f"(güven: %{result.best_candidate.confidence}, "
                        f"teknik: {result.best_candidate.source})"
                    )

                    # SSE: Gerçek IP bulundu
                    await ScanEventBus.publish(ScanEvent(
                        scan_id=self.scan_id,
                        event_type=ScanEventType.CRITICAL_FINDING,
                        data={
                            "type": "origin_ip_discovered",
                            "ip": result.best_candidate.ip,
                            "confidence": result.best_candidate.confidence,
                            "source": result.best_candidate.source,
                            "verified": result.best_candidate.verified,
                            "total_candidates": len(result.candidates),
                            "message": result.risk_assessment,
                        },
                    ))

            self.discovered_data["is_behind_cf"] = result.is_behind_cdn

            return StageResult(
                stage_name=stage.name,
                tool="origin_discovery",
                status="completed",
                data=result_dict,
            )

        except Exception as e:
            logger.error(f"Origin discovery error: {e}")
            return StageResult(
                stage_name=stage.name,
                tool="origin_discovery",
                status="failed",
                error=str(e),
            )

    # ---- Reverse-IP Discovery (Kuşatma Doktrini: IP'de barınan domain'leri keşfet) ----
    async def _dispatch_reverse_ip(self, stage: StageDefinition) -> StageResult:
        """
        Bir IP adresinde barınan TÜM domain'leri keşfeder.
        Free API'ler: HackerTarget, RapidDNS, crt.sh certificate transparency.
        Kuşatma Doktrini: "Surdaki gizli kapı" — ana domain temiz, yan domain savunmasız.
        """
        target_ip = self.discovered_data.get("primary_real_ip") or self.target
        if not self._is_ip_address(target_ip):
            logger.info(f"Reverse-IP: {self.target} IP değil, önce DNS çözümleniyor")
            try:
                import socket
                target_ip = socket.gethostbyname(self.target)
            except Exception:
                return StageResult(
                    stage_name=stage.name, tool="reverse_ip", status="failed",
                    error=f"Hedef domain DNS çözümlemesi başarısız: {self.target}",
                )

        logger.info(f"🔍 Reverse-IP başlıyor: {target_ip}")
        await ScanEventBus.publish(ScanEvent(
            scan_id=self.scan_id,
            event_type=ScanEventType.PROGRESS_UPDATE,
            data={"type": "reverse_ip_started", "ip": target_ip,
                  "message": f"IP'de barınan domain'ler keşfediliyor: {target_ip}"},
        ))

        domains = set()
        sources = {}

        async def try_hackertarget(client: httpx.AsyncClient) -> List[str]:
            try:
                resp = await client.get(
                    f"https://api.hackertarget.com/reverseiplookup/?q={target_ip}",
                    timeout=20.0, headers={"User-Agent": "KadimGuvenlik/1.0"},
                )
                if resp.status_code == 200:
                    text = resp.text.strip()
                    if text and "error" not in text.lower() and "invalid" not in text.lower():
                        return [d.strip() for d in text.split("\n") if d.strip()]
                return []
            except Exception:
                return []

        async def try_rapiddns(client: httpx.AsyncClient) -> List[str]:
            try:
                resp = await client.get(
                    f"https://rapiddns.io/sameip/{target_ip}?full=1",
                    timeout=20.0, headers={"User-Agent": "KadimGuvenlik/1.0"},
                )
                if resp.status_code == 200:
                    import re as _re
                    return _re.findall(r'<td>([a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})</td>', resp.text)
                return []
            except Exception:
                return []

        # NOT: crt.sh-by-IP kaynağı KALDIRILDI — crt.sh sertifika-şeffaflığı domain indeksler,
        # IP→domain EŞLEMEZ; `q=%.{IP}` sorgusu semantik olarak hatalıydı ve alakasız isim
        # döndürüyordu. Gerçek reverse-IP servisleri (HackerTarget/RapidDNS) + aşağıdaki DNS
        # doğrulaması co-hosting sinyalini otoriter kılar.
        async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(30.0)) as client:
            results = await asyncio.gather(
                try_hackertarget(client), try_rapiddns(client),
                return_exceptions=True,
            )
            for i, result in enumerate(results):
                source_label = ["hackertarget", "rapiddns"][i]
                if isinstance(result, Exception):
                    logger.debug(f"Reverse-IP {source_label}: {result}")
                    continue
                for d in result:
                    if d not in domains:
                        domains.add(d)
                        sources[d] = source_label

        raw_list = sorted(domains)

        # --- CO-HOSTED DNS DOĞRULAMA (kritik scope/yetki kapısı — Hata 1 düzeltmesi) ---
        # NEDEN: Reverse-IP kaynakları (HackerTarget/RapidDNS) BAYAT/HATALI passive-DNS
        # döndürür — Cloudflare-fronted domainler (gerçek IP GİZLİ) ve komşu-IP/tarihsel
        # kayıtlar "bu IP'de barınıyor" diye sızar. Doğrulanmadan kabul edilince motor
        # ÜÇÜNCÜ-PARTİ sistemlere aktif prob atardı (yetki ihlali). DOKTRIN: bir domain'i
        # co-hosted saymadan ÖNCE GÜNCEL A kaydının gerçekten target_ip'ye çözüldüğünü
        # doğrula. Farklı-IP/çözülemeyen TARAMA kapsamına GİRMEZ; yalnız şeffaflık için
        # ayrı 'unverified' listesinde raporlanır. Flag: REVERSE_IP_VERIFY=0 kapatır.
        unverified: List[Dict[str, str]] = []
        if os.getenv("REVERSE_IP_VERIFY", "1") == "1" and raw_list:
            import socket as _sock
            _loop = asyncio.get_event_loop()
            _cap = int(os.getenv("REVERSE_IP_VERIFY_MAX", "60"))

            async def _resolve_ips(dom: str):
                try:
                    infos = await _loop.run_in_executor(
                        None, _sock.getaddrinfo, dom, None, _sock.AF_INET)
                    return dom, sorted({i[4][0] for i in infos})
                except Exception:
                    return dom, []

            _checks = await asyncio.gather(
                *[_resolve_ips(d) for d in raw_list[:_cap]], return_exceptions=True)
            _resolved: Dict[str, List[str]] = {}
            for _r in _checks:
                if isinstance(_r, Exception):
                    continue
                _dom, _ips = _r
                _resolved[_dom] = _ips
            # SAF partition (I/O yukarıda; ayırma test edilebilir). Cap üstü domainler
            # _resolved'da yok → otomatik 'unverified' (güvenli taraf: doğrulanmadan taranmaz).
            domain_list, unverified = partition_cohosted_by_ip(raw_list, target_ip, _resolved)
            for _u in unverified:  # kaynak etiketini ekle (helper SAF, source bilmez)
                _u["source"] = sources.get(_u["name"], "unknown")
            if unverified:
                logger.info(
                    f"🚫 [{self.scan_id[:8]}] Reverse-IP doğrulama: {len(unverified)} domain "
                    f"FARKLI IP'ye çözüldü/çözülemedi → kapsam DIŞI (üçüncü-parti koruması); "
                    f"{len(domain_list)} domain {target_ip}'de DOĞRULANDI")
                self.discovered_data["co_hosted_unverified"] = unverified
        else:
            domain_list = raw_list

        if domain_list:
            logger.info(f"✅ Reverse-IP: {len(domain_list)} DOĞRULANMIŞ co-hosted domain "
                        f"({', '.join(sorted(set(sources.get(d, '?') for d in domain_list)))})")
            _drop_note = (f" · {len(unverified)} domain farklı-IP olduğu için elendi"
                          if unverified else "")
            await ScanEventBus.publish(ScanEvent(
                scan_id=self.scan_id,
                event_type=ScanEventType.CRITICAL_FINDING,
                data={
                    "type": "reverse_ip_discovery",
                    "ip": target_ip,
                    "domain_count": len(domain_list),
                    "domains": domain_list[:30],
                    "unverified_count": len(unverified),
                    "message": f"{target_ip} IP'sinde {len(domain_list)} DOĞRULANMIŞ co-hosted "
                               f"domain{_drop_note}.",
                },
            ))
            self.discovered_data["co_hosted_domains"] = domain_list
        else:
            _drop_note = (f" ({len(unverified)} aday farklı-IP/çözülemez olduğu için elendi)"
                          if unverified else "")
            logger.info(f"ℹ️ Reverse-IP: {target_ip} üzerinde DOĞRULANMIŞ co-hosted domain "
                        f"yok{_drop_note}")

        return StageResult(
            stage_name=stage.name, tool="reverse_ip", status="completed",
            data={
                "co_hosted_domains": domain_list,
                "domain_count": len(domain_list),
                "domains": [{"name": d, "source": sources.get(d, "unknown")} for d in domain_list],
                # Şeffaflık: elenen adaylar (farklı IP/çözülemez) — TARANMAZ, sadece raporlanır.
                "co_hosted_unverified": unverified,
                "unverified_count": len(unverified),
                "source": ", ".join(set(sources.values())) if sources else "none",
                "target_ip": target_ip,
            },
        )

    # ---- Hassas Yol / İfşa Prober (orchestrator-içi, servis gerektirmez) ----
    async def _dispatch_pathprobe(self, stage: StageDefinition) -> StageResult:
        """
        "domain/.env" sınıfı basit ama ölümcül açıkların DETERMİNİSTİK taraması.
        Nuclei template'ine muhtaç değildir: küratörlü hassas yol listesini doğrudan
        GET ile proplar, yanıtı İÇERİK validator'larıyla doğrular (soft-404 elemesi).
        Kuşatma Doktrini: en zayıf sur çoğu zaman unutulmuş bir yan domain'deki açık
        .env'dir — template motorunun kör noktasını kapatan güvenlik ağı.
        """
        from .path_probe import probe_sensitive_paths

        host = self.target
        # env pivot'undan gelen alt-uygulama tabanı (ör. '/app') — .env kökte değil orada
        # olabilir; prober aynı yolları bu tabanda da dener. Yoksa None (yalnız kök).
        path_base = stage.options.get("path_base")
        # recon'un tespit ettiği teknolojiler → framework-özel yol seti (laravel.log,
        # actuator/env, wp-config.bak...). Yoksa yalnız statik katalog problanır.
        tech_hints = stage.options.get("tech_hints")

        # K2/K3 — EKLEMELİ zekâ (flag arkasında; kapalıyken bu blok DB'ye HİÇ dokunmaz →
        # ToolDispatcher'ın "Mongo'yu pipeline yönetir / db tutmaz" sözleşmesi varsayılanda korunur).
        # Öğrenilmiş hafıza + LLM önerisi kataloğa `extra_paths` ile enjekte edilir; prober bunları
        # normal yolmuş gibi (aynı deterministik validator ile) işler. Hata → boş enjeksiyon (fallback).
        def _mem_col():
            """scan_memories koleksiyonu — core.db singleton'ından LAZILY (yalnız flag açıkken).
            ToolDispatcher db'yi doğrudan tutmaz; erişilemezse None (motor bozulmaz)."""
            try:
                from core.db import db as _mdb
                return _mdb["scan_memories"] if _mdb is not None else None
            except Exception:
                return None

        extra_paths: list = []
        if os.getenv("PATHPROBE_MEMORY", "0") == "1":
            try:
                col = _mem_col()
                if col is not None:
                    from .path_memory import load_learned_paths
                    learned = load_learned_paths(col, tech_hints)
                    extra_paths += learned
                    if learned:
                        logger.info(f"🧠 [{self.scan_id[:8]}] PathProbe hafıza: {len(learned)} öğrenilmiş yol enjekte.")
            except Exception as e:
                logger.warning(f"PathProbe hafıza yüklenemedi (yok sayılıyor): {e}")
        if os.getenv("PATHPROBE_LLM_INTEL", "0") == "1":
            try:
                from .path_intel import suggest_paths_llm
                fingerprint = {"target": host, "tech_hints": tech_hints or []}
                llm_rows = await suggest_paths_llm(fingerprint)
                extra_paths += llm_rows
                if llm_rows:
                    logger.info(f"🧭 [{self.scan_id[:8]}] PathProbe LLM: {len(llm_rows)} yol önerisi enjekte.")
            except Exception as e:
                logger.warning(f"PathProbe LLM önerisi alınamadı (yok sayılıyor): {e}")

        logger.info(f"🧭 [{self.scan_id[:8]}] PathProbe başlıyor: {host}"
                    + (f" (alt-taban {path_base})" if path_base else ""))
        await ScanEventBus.publish(ScanEvent(
            scan_id=self.scan_id,
            event_type=ScanEventType.PROGRESS_UPDATE,
            data={"type": "pathprobe_started", "target": host,
                  "message": f"Hassas yol taraması (.env/.git/yedek/config): {host}"},
        ))

        try:
            result = await probe_sensitive_paths(host, path_base=path_base, tech_hints=tech_hints,
                                                 extra_paths=extra_paths or None)
        except Exception as e:
            return StageResult(
                stage_name=stage.name, tool="pathprobe", status="failed",
                error=f"PathProbe hatası: {e}",
            )

        findings = result.get("findings") or []
        sev_counts = result.get("severity_counts") or {}

        # K3 — ÖĞRENME: doğrulanan bulguları kalıcı hafızaya yaz (best-effort; kirlenme
        # korkulukları path_memory içinde — kör 200 yazılmaz). "Bir kez gör, hep ara."
        if os.getenv("PATHPROBE_MEMORY", "0") == "1" and findings:
            try:
                col = _mem_col()
                if col is not None:
                    from .path_memory import record_findings
                    record_findings(col, findings, host, techs=tech_hints)
            except Exception as e:
                logger.warning(f"PathProbe hafızaya yazılamadı (yok sayılıyor): {e}")

        # Kritik/yüksek bulgular anında event ile duyurulur — operatör beklemeden görsün.
        for f in findings:
            if f.get("severity") in ("critical", "high"):
                await ScanEventBus.publish(ScanEvent(
                    scan_id=self.scan_id,
                    event_type=ScanEventType.VULNERABILITY_FOUND,
                    data={
                        "type": "sensitive_path_exposure",
                        "severity": f["severity"],
                        "url": f["url"],
                        "category": f["category"],
                        "message": f"🔓 Hassas dosya ifşası [{f['severity']}]: {f['url']}",
                    },
                ))

        if findings:
            self.discovered_data.setdefault("sensitive_path_findings", []).extend(findings)
            logger.info(
                f"🔓 [{self.scan_id[:8]}] PathProbe: {len(findings)} ifşa bulundu "
                f"({', '.join(f'{k}:{v}' for k, v in sev_counts.items())}) — {host}"
            )
        else:
            logger.info(f"✅ [{self.scan_id[:8]}] PathProbe temiz: {host} ({result.get('probed', 0)} yol)")

        # Sürümlü teknoloji parmak izi (wordpress 6.x, apache 2.4.x...) — grafa
        # MUTLAKA taşınmalı: NVD → hedefli nuclei zincirinin tek veri kaynağı.
        detected_tech = result.get("detected_technologies") or []
        if detected_tech:
            logger.info(
                f"🧬 [{self.scan_id[:8]}] Teknoloji parmak izi: "
                + ", ".join(f"{t.get('product')} {t.get('version') or '?'} ({t.get('source')})"
                            for t in detected_tech[:6])
            )

        return StageResult(
            stage_name=stage.name, tool="pathprobe", status="completed",
            data={
                "target": result.get("target"),
                "base_url": result.get("base_url"),
                "probed": result.get("probed", 0),
                "findings": findings,
                "findings_count": len(findings),
                "severity_counts": sev_counts,
                "note": result.get("note"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "detected_technologies": detected_tech,
            },
        )

    async def _headless_crawl(self, host: str, depth: Any) -> Optional[Dict[str, Any]]:
        """T1-A: crawler-service'i (headless Chromium/Playwright) çağır — JS-render yüzey keşfi.
        Auth başlıkları geçirilir (login-arkası SPA). Erişilemez/hata → None (degrade-safe:
        çağıran httpx crawler sonucuyla devam eder). Doktrin: yeni servis kral değil, augment."""
        payload = {
            "target": host,
            "depth": int(depth) if isinstance(depth, int) else 2,
            "auth_headers": self.auth_headers,
            "max_pages": int(os.getenv("CRAWLER_MAX_PAGES", "25")),
        }
        try:
            async with httpx.AsyncClient(timeout=150.0) as client:
                r = await client.post(f"{CRAWLER_SERVICE_URL}/crawl", json=payload)
                if r.status_code == 200:
                    return r.json()
                logger.debug(f"Headless crawler HTTP {r.status_code}")
        except Exception as e:
            logger.debug(f"Headless crawler erişilemedi: {e}")
        return None

    async def _dispatch_crawl(self, stage: StageDefinition) -> StageResult:
        """Türkçe: Faz 1 — endpoint keşfi / crawler. path_probe gibi ORCHESTRATOR-YERLİ; yeni
        servis gerektirmez. Crawler hedefi BFS tarayıp parametreli endpoint'leri/form'ları/JS
        varlıklarını toplar. attack_graph bunları ENDPOINT node'larına çevirir + parametreli
        olanlar için nuclei DAST kenarı seed eder. Bu KAPI olmadan nuclei `target` yalnız
        KÖK URL'i görür ve SQLi/XSS/SSRF template'leri hiçbir URL bulamazdı (doktrin §3.1).

        BUG BOUNTY GENİŞLETMESİ (P0-A/P0-B/P1): crawl artık TEK başına değil, pasif
        kaynaklarla birleşik bir YÜZEY KEŞİF hattıdır:
          1) Wayback CDX (pasif — hedefe istek gitmez): tarihî, artık linklenmeyen ama
             canlı olabilen endpoint'ler (WAYBACK_DISCOVERY=0 kapatır)
          2) Swagger/OpenAPI keşfi: doküman açıksa endpoint×method×parametre matrisi
             bedavaya gelir (OPENAPI_DISCOVERY=0 kapatır)
          3) Endpoint sürüm-diff: snapshot scan_memories'e yazılır, öncekiyle diff'lenir;
             YENİ yüzey kural-tohumuna ÖNCELİKLİ beslenir (ENDPOINT_DIFF=0 kapatır)
          4) HTTP method matrisi: seçilmiş API/admin yollarında GET/POST/PUT/DELETE →
             method-swap erişim boşluğu tespiti (METHOD_PROBE=0 kapatır)
        Her ek katman best-effort'tur: düşerse crawl'un kendi çıktısı yine döner."""
        from .endpoint_discovery import discover_endpoints

        host = self.target
        depth = stage.options.get("depth")
        logger.info(f"🕸 [{self.scan_id[:8]}] Endpoint keşfi (crawl) başlıyor: {host}")
        await ScanEventBus.publish(ScanEvent(
            scan_id=self.scan_id,
            event_type=ScanEventType.PROGRESS_UPDATE,
            data={"type": "crawl_started", "target": host,
                  "message": f"Endpoint keşfi (URL/form/JS crawl): {host}"},
        ))

        try:
            # T1-B: auth başlıkları crawl'a geçer → login-ARKASI yüzey keşfi.
            result = await discover_endpoints(host, depth=depth, auth_headers=self.auth_headers)
        except Exception as e:
            return StageResult(
                stage_name=stage.name, tool="crawl", status="failed",
                error=f"Crawl hatası: {e}",
            )

        discovered = list(result.get("discovered_urls") or [])
        param_eps = list(result.get("parameterized_endpoints") or [])
        forms = list(result.get("forms") or [])
        js_assets = result.get("js_assets") or []
        base_url = result.get("base_url")

        # ---- T1-A: HEADLESS (JS-render) CRAWL — SPA yüzeyini gerçek tarayıcıyla augment et.
        # httpx crawler JS çalıştırmaz → SPA'da neredeyse boş döner. Headless servis render edip
        # DOM linkleri + form + YAKALANAN XHR/fetch (gerçek API) döndürür. MERGE edilir; servis
        # kapalı/erişilemezse sessizce httpx sonucuyla devam (degrade-safe, doktrin §6).
        if os.getenv("HEADLESS_CRAWL", "1") == "1":
            try:
                hb = await self._headless_crawl(host, depth)
                if hb:
                    seen_u = set(discovered)
                    seen_p = {e.get("url") for e in param_eps}
                    for u in hb.get("discovered_urls") or []:
                        if u not in seen_u:
                            seen_u.add(u); discovered.append(u)
                    for e in hb.get("parameterized_endpoints") or []:
                        if isinstance(e, dict) and e.get("url") and e["url"] not in seen_p:
                            seen_p.add(e["url"]); param_eps.append(e)
                    seen_f = {(f.get("url"), tuple(f.get("inputs") or [])) for f in forms}
                    for f in hb.get("forms") or []:
                        key = (f.get("url"), tuple(f.get("inputs") or []))
                        if key not in seen_f:
                            seen_f.add(key); forms.append(f)
                    js_assets = list(dict.fromkeys(list(js_assets) + (hb.get("js_assets") or [])))
                    if not base_url:
                        base_url = hb.get("base_url")
                    logger.info(
                        f"🎭 [{self.scan_id[:8]}] Headless crawl merge: "
                        f"+{len(hb.get('discovered_urls') or [])} URL, "
                        f"{hb.get('captured_api_count', 0)} XHR/fetch API yakalandı")
            except Exception as e:
                logger.info(f"Headless crawl atlandı (best-effort): {e}")

        # ---- 1) WAYBACK (pasif tarihî yüzey) — hedefe istek gitmez ----
        wayback_info: Dict[str, Any] = {"total": 0, "note": "disabled"}
        if os.getenv("WAYBACK_DISCOVERY", "1") == "1":
            try:
                from .passive_sources import fetch_wayback_endpoints
                wb = await fetch_wayback_endpoints(host)
                wayback_info = {"total": wb.get("total", 0), "note": wb.get("note")}
                seen_urls = set(discovered)
                seen_param = {e.get("url") for e in param_eps}
                added = 0
                for u in wb.get("parameterized") or []:
                    if u not in seen_urls and u not in seen_param:
                        seen_param.add(u)
                        param_eps.append({"url": u, "params": [
                            k for k, _v in parse_qsl(
                                u.split("?", 1)[1] if "?" in u else "",
                                keep_blank_values=True)],
                            "source": "wayback"})
                        added += 1
                for u in wb.get("plain") or []:
                    if u not in seen_urls:
                        seen_urls.add(u)
                        discovered.append(u)
                        added += 1
                if added:
                    logger.info(f"🕰 [{self.scan_id[:8]}] Wayback: {added} tarihî endpoint "
                                f"keşif havuzuna eklendi — {host}")
            except Exception as e:
                wayback_info = {"total": 0, "note": f"error: {type(e).__name__}"}
                logger.debug(f"Wayback keşfi atlandı: {e}")

        # ---- 2) OPENAPI (swagger) keşfi — doküman açıksa matris bedava ----
        openapi_info: Dict[str, Any] = {"found": False, "endpoint_count": 0}
        openapi_endpoints: List[Dict[str, Any]] = []
        if os.getenv("OPENAPI_DISCOVERY", "1") == "1" and base_url:
            try:
                from .openapi_discovery import discover_openapi
                oa = await discover_openapi(base_url)
                openapi_info = {"found": oa.get("found", False),
                                "doc_url": oa.get("doc_url"),
                                "title": oa.get("title"),
                                "endpoint_count": oa.get("endpoint_count", 0),
                                "note": oa.get("note")}
                openapi_endpoints = oa.get("endpoints") or []
                if openapi_endpoints:
                    # GET + parametreli OpenAPI endpoint'leri DAST havuzuna; gövde
                    # metotları kural-tohumuna (api_endpoints) gitmek üzere data'da kalır.
                    seen_param = {e.get("url") for e in param_eps}
                    for ep in openapi_endpoints:
                        if ep.get("method") == "get" and ep.get("params") and ep.get("url"):
                            if ep["url"] not in seen_param:
                                seen_param.add(ep["url"])
                                param_eps.append({"url": ep["url"], "params": ep["params"],
                                                  "source": "openapi"})
                    await ScanEventBus.publish(ScanEvent(
                        scan_id=self.scan_id,
                        event_type=ScanEventType.PROGRESS_UPDATE,
                        data={"type": "openapi_discovered", "target": host,
                              "doc_url": oa.get("doc_url"),
                              "count": oa.get("endpoint_count", 0),
                              "message": f"📜 API dokümanı bulundu: {oa.get('endpoint_count')} "
                                         f"endpoint × method × parametre test matrisine alındı"},
                    ))
            except Exception as e:
                openapi_info = {"found": False, "note": f"error: {type(e).__name__}"}
                logger.debug(f"OpenAPI keşfi atlandı: {e}")

        # ---- 2b) GRAPHQL introspection keşfi (T2-C) — tek uçtan TÜM operasyon matrisi ----
        # OpenAPI'nin GraphQL kardeşi. Modern API'ler tek `/graphql`ten konuşur; REST crawl
        # buna kördür. Introspection AÇIK ise tüm operasyon+argüman matrisi tek istekle gelir
        # ve "introspection prod'da açık" başlı başına bir bulgudur (CWE-200). Auth başlıkları
        # geçer → login-arkası GraphQL. Best-effort; düşerse crawl çıktısı yine döner.
        graphql_info: Dict[str, Any] = {"found": False}
        graphql_operations: List[Dict[str, Any]] = []
        if os.getenv("GRAPHQL_DISCOVERY", "1") == "1" and base_url:
            try:
                from .graphql_intel import discover_graphql
                gq = await discover_graphql(base_url, auth_headers=self.auth_headers)
                graphql_info = {
                    "found": gq.get("found", False),
                    "endpoint_url": gq.get("endpoint_url"),
                    "introspection_enabled": gq.get("introspection_enabled", False),
                    "operation_count": gq.get("operation_count", 0),
                    "mutation_count": gq.get("mutation_count", 0),
                    "note": gq.get("note"),
                }
                graphql_operations = gq.get("operations") or []
                if gq.get("found") and gq.get("introspection_enabled"):
                    await ScanEventBus.publish(ScanEvent(
                        scan_id=self.scan_id,
                        event_type=ScanEventType.VULNERABILITY_FOUND,
                        data={"type": "graphql_introspection_exposed",
                              "severity": "medium",
                              "url": gq.get("endpoint_url"),
                              "operation_count": gq.get("operation_count", 0),
                              "mutation_count": gq.get("mutation_count", 0),
                              "message": f"🔮 GraphQL introspection AÇIK: "
                                         f"{gq.get('operation_count')} operasyon "
                                         f"({gq.get('mutation_count')} mutation) ifşa — "
                                         f"{gq.get('endpoint_url')}"},
                    ))
                elif gq.get("found"):
                    await ScanEventBus.publish(ScanEvent(
                        scan_id=self.scan_id,
                        event_type=ScanEventType.PROGRESS_UPDATE,
                        data={"type": "graphql_endpoint_found",
                              "url": gq.get("endpoint_url"),
                              "message": f"🔮 GraphQL ucu bulundu (introspection kapalı): "
                                         f"{gq.get('endpoint_url')}"},
                    ))
            except Exception as e:
                graphql_info = {"found": False, "note": f"error: {type(e).__name__}"}
                logger.debug(f"GraphQL keşfi atlandı: {e}")

        # ---- 3) ENDPOINT SÜRÜM-DIFF (P0-A) — 'yeni bir şey var mı' monitörü ----
        diff_info: Dict[str, Any] = {}
        if os.getenv("ENDPOINT_DIFF", "1") == "1":
            try:
                from core.db import db as _mdb
                if _mdb is not None:
                    from .endpoint_diff import (build_snapshot, diff_snapshots,
                                                diff_has_news, diff_headline,
                                                load_latest_snapshot, save_snapshot,
                                                new_surface_urls)
                    col = _mdb["scan_memories"]
                    snapshot = build_snapshot(discovered, param_eps, forms)
                    prev_doc = load_latest_snapshot(col, host)
                    prev_snap = (prev_doc or {}).get("snapshot")
                    diff = diff_snapshots(prev_snap, snapshot)
                    save_snapshot(col, host=host, snapshot=snapshot,
                                  scan_id=self.scan_id, diff=diff)
                    diff_info = {
                        "is_first": diff.get("is_first", True),
                        "headline": diff_headline(diff),
                        "new_urls": diff.get("new_urls", [])[:20],
                        "new_params": diff.get("new_params", [])[:20],
                        "new_forms": diff.get("new_forms", [])[:10],
                        "no_diff_streak": (prev_doc or {}).get("no_diff_streak", 0),
                    }
                    if diff_has_news(diff):
                        # YENİ YÜZEY: kural-tohumu hattına ÖNCELİKLİ girmesi için yeni
                        # yüzey URL'leri discovered listesinin BAŞINA alınır (graph.integrate
                        # sırayla meta'ya ekler; seed bütçesi önce bunları görür).
                        fresh = new_surface_urls(diff)
                        if fresh:
                            fresh_set = set(fresh)
                            discovered = fresh + [u for u in discovered if u not in fresh_set]
                        await ScanEventBus.publish(ScanEvent(
                            scan_id=self.scan_id,
                            event_type=ScanEventType.PROGRESS_UPDATE,
                            data={"type": "endpoint_diff_news", "target": host,
                                  "diff": diff_info,
                                  "message": diff_headline(diff)},
                        ))
                    logger.info(f"🔭 [{self.scan_id[:8]}] Endpoint diff: {diff_headline(diff)}")
            except Exception as e:
                logger.debug(f"Endpoint diff atlandı: {e}")

        # ---- 4) METHOD MATRİSİ (P0-B keşif) — method-swap erişim boşluğu ----
        # Bütçe: en fazla 6 aday URL × 4 metot = 24 istek. Adaylar: parametresiz,
        # API/admin çağrışımlı yollar (erişim kontrolü buralarda yoğunlaşır).

        # ---- 5) JS SIR TARAMASI (P2-C secret hunting) — bundle.js'ten sızmış API key/JWT ----
        js_findings: List[Dict[str, Any]] = []
        if os.getenv("JS_SECRET_SCAN", "1") == "1" and js_assets and base_url:
            try:
                from .js_secrets import scan_js_asset
                scan_cap = min(len(js_assets or []), 15)
                async with httpx.AsyncClient(verify=False, timeout=12.0) as sclient:
                    for asset_url in (js_assets or [])[:scan_cap]:
                        secrets = await scan_js_asset(sclient, asset_url)
                        if secrets:
                            js_findings.extend(secrets)
                if js_findings:
                    for jf in js_findings:
                        # Canlı kart title/proof/tier/tool bekler (usePipelineStream EvidenceCard).
                        # Kardeş username varsa "Hardcoded Credential: user / mask" diye net sun.
                        _uname = jf.get("username")
                        # BAŞLIK evidence yolundakiyle (attack_graph.integrate) BİREBİR aynı
                        # olmalı — aksi halde aynı sır İKİ kart olur: bu canlı kart ("… mask")
                        # + observe'un ürettiği evidence kartı ("… mask in url"). Frontend
                        # dedup'ı `title|target` anahtarıyla eler; başlık ayrışınca ikisi de
                        # geçer (ekranda çift Hardcoded Credential). Aynı format → tek kart.
                        _title = (f"Hardcoded Credential: {_uname} / {jf['value_masked']} in {jf['asset_url']}"
                                  if _uname else f"JS Secret Exposure: {jf['secret_type']} in {jf['asset_url']}")
                        _proof = (f"Kullanıcı: {_uname} · Parola (maskeli): {jf['value_masked']}. "
                                  f"Bağlam: {jf.get('line_text', '')[:220]}"
                                  if _uname else
                                  f"{jf['secret_type']} bulundu (maskeli: {jf['value_masked']}). "
                                  f"Bağlam: {jf.get('line_text', '')[:220]}")
                        await ScanEventBus.publish(ScanEvent(
                            scan_id=self.scan_id,
                            event_type=ScanEventType.VULNERABILITY_FOUND,
                            data={"type": "js_secret_exposure",
                                  "title": _title,
                                  "severity": jf["severity"],
                                  "secret_type": jf["secret_type"],
                                  "target": jf["asset_url"],
                                  "asset_url": jf["asset_url"],
                                  "value_masked": jf["value_masked"],
                                  "username": _uname,
                                  "proof": _proof,
                                  "confidence_tier": jf.get("confidence_tier") or "unconfirmed",
                                  "tool": "js_secret_scan",
                                  "message": f"🔑 JS sır ifşası [{jf['severity']}]: "
                                             f"{_title} — {jf['asset_url']}"},
                        ))
                    logger.info(f"🔑 [{self.scan_id[:8]}] JS secret: {len(js_findings)} bulgu — {host}")
            except Exception as e:
                logger.debug(f"JS secret taraması atlandı: {e}")
        matrix_findings: List[Dict[str, Any]] = []
        if os.getenv("METHOD_PROBE", "1") == "1" and base_url:
            try:
                from .method_probe import probe_method_matrix
                _hints = ("api", "admin", "account", "auth", "user", "login",
                          "upload", "config", "internal", "panel", "manage")
                candidates = [u for u in discovered
                              if "?" not in u and any(h in u.lower() for h in _hints)][:6]
                if candidates:
                    async with httpx.AsyncClient(verify=False, follow_redirects=False) as mclient:
                        rows = await probe_method_matrix(mclient, candidates)
                    for row in rows:
                        if row.get("interpretation"):
                            matrix_findings.append(row)
                    if matrix_findings:
                        for mf in matrix_findings:
                            interp = mf["interpretation"]
                            if interp.get("kind") == "access_gap":
                                await ScanEventBus.publish(ScanEvent(
                                    scan_id=self.scan_id,
                                    event_type=ScanEventType.VULNERABILITY_FOUND,
                                    data={"type": "method_swap_access_gap",
                                          "severity": "medium", "url": mf["url"],
                                          "method": interp["method"],
                                          "message": f"🔓 Method-swap erişim boşluğu: GET "
                                                     f"{interp['blocked_get']} iken "
                                                     f"{interp['method']} {interp['status']} — "
                                                     f"{mf['url']}"},
                                ))
            except Exception as e:
                logger.debug(f"Method matrisi atlandı: {e}")

        total = len(discovered)
        param_total = len(param_eps)

        # Operatör görünürlüğü: keşif sonucu özet (kaç URL, kaç parametreli — bunlar
        # SQLi/XSS hedefi; nuclei'da DAST ile beslenir).
        logger.info(
            f"🕸 [{self.scan_id[:8]}] Crawl bitti: {total} URL, {param_total} parametreli "
            f"endpoint, {len(forms)} form, {len(js_assets)} JS, "
            f"wayback={wayback_info.get('total', 0)}, "
            f"openapi={openapi_info.get('endpoint_count', 0)}, "
            f"graphql={graphql_info.get('operation_count', 0)}"
            f"{'(introspection AÇIK)' if graphql_info.get('introspection_enabled') else ''}, "
            f"method_gap={len(matrix_findings)} — {host}"
        )

        # Parametreli endpoint'leri operatöre olay olarak yayınla — "şaşırtmaca bulgu"
        # değil, "DAST hedefi bulundu" sinyali: SQLi/XSS testine aday URL'ler keşfettik.
        # Pratikte kullanıcının "boş tarama" şikayetinin kök sebebi bu boşluğun görünürlüksüz
        # olmasıydı. Artık "0 bulgu" yerine "5 aday endpoint bulundu (DAST keşfi için)"
        # görür.
        if param_eps:
            await ScanEventBus.publish(ScanEvent(
                scan_id=self.scan_id,
                event_type=ScanEventType.PROGRESS_UPDATE,
                data={
                    "type": "crawl_endpoints_discovered",
                    "target": host,
                    "count": param_total,
                    "samples": [e.get("url") for e in param_eps[:5]],
                    "message": f"🧪 {param_total} parametreli endpoint keşfedildi — DAST hedefi",
                },
            ))

        return StageResult(
            stage_name=stage.name, tool="crawl", status="completed",
            data={
                "target": result.get("target"),
                "base_url": base_url,
                "seed_urls": result.get("seed_urls"),
                "discovered_urls": discovered,
                "discovered_count": total,
                "parameterized_endpoints": param_eps,
                "parameterized_count": param_total,
                "forms": forms,
                "forms_count": result.get("forms_count", len(forms)),
                "js_assets": js_assets,
                "js_assets_count": result.get("js_assets_count", len(js_assets)),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "partial": result.get("partial"),
                "note": result.get("note"),
                # Bug bounty genişletmesi çıktıları (graph.integrate + tohumlayıcı tüketir)
                "wayback": wayback_info,
                "openapi": openapi_info,
                "openapi_endpoints": openapi_endpoints[:120],
                "graphql": graphql_info,
                "graphql_operations": graphql_operations[:200],
                "endpoint_diff": diff_info,
                "method_matrix_findings": matrix_findings,
                "js_secret_findings": js_findings,
            },
        )

    async def _try_stop_scan(self, tool: str):
        """Timeout olan taramayı durdurmaya çalış"""
        url_map = {
            "nmap": f"{NMAP_SERVICE_URL}/scan/{self.scan_id}",
            "nuclei": f"{NUCLEI_SERVICE_URL}/scan/{self.scan_id}",
            "subfinder": f"{SUBFINDER_SERVICE_URL}/scan/{self.scan_id}",
            "rustscan": f"{RUSTSCAN_SERVICE_URL}/scan/{self.scan_id}",
            "fuzz": f"{FUZZ_SERVICE_URL}/scan/{self.scan_id}",
            "recon": f"{RECON_SERVICE_URL}/analyze/{self.scan_id}/cancel",
            "osint": f"{OSINT_SERVICE_URL}/investigate/{self.scan_id}",
        }
        url = url_map.get(tool)
        if not url:
            return

        try:
            async with httpx.AsyncClient() as client:
                await client.delete(url, timeout=5.0)
                logger.info(f"Scan stopped: {tool}/{self.scan_id}")
        except Exception as e:
            logger.warning(f"Could not stop scan {tool}/{self.scan_id}: {e}")


# ============== Pipeline Engine ==============

def _compute_coverage(engine, session) -> Dict[str, Any]:
    """Bug bounty kapsam skoru (checklist'in ağırlıklı tamamlanma yüzdesi).

    BUG-BOUNTY-YETKINLIK-ANALIZI.md §5 "Program Bitti" kapanış kriterlerinden türetildi.
    Her madde: tool çalıştı mı (stages), meta verisi var mı (engine.graph root.meta),
    doğrulama yapıldı mı? Ağırlık → ağırlıklı toplam → 100 üzerinden skor.

    Çıktı: {score, max_score, items: [{name, done, weight, note}]} — frontend çubuk/
    checklist olarak render edebilir."""
    root = engine.graph.nodes[engine.graph.root_id]
    meta = root.meta
    stages = dict(session.stages if hasattr(session, "stages") else {})
    stage_names = set(stages.keys())

    def _any_tool(tool: str) -> bool:
        return any(tool in k for k in stage_names)

    # Sonuç = ağırlıklı 100'lük (items zaten max_score = 100 olacak şekilde ayarlı)
    items: List[Dict[str, Any]] = [
        {"name": "Subdomain keşfi", "done": _any_tool("subfinder"),
         "weight": 8},
        {"name": "Port/servis taraması", "done": _any_tool("nmap") or _any_tool("rustscan"),
         "weight": 8},
        {"name": "Crawl (endpoint + URL + form + JS)", "done": _any_tool("crawl"),
         "weight": 15},
        {"name": "PathProbe (hassas yol ifşası)", "done": _any_tool("pathprobe"),
         "weight": 10},
        {"name": "Wayback pasif yüzey", "done": bool(meta.get("wayback_fetched")),
         "weight": 5},
        {"name": "OpenAPI doküman keşfi", "done": bool(meta.get("openapi_found")),
         "weight": 6},
        {"name": "Endpoint diff monitörü", "done": "endpoint_diff" in meta,
         "weight": 7},
        {"name": "Yüzey durağan (≥2 hafta diff'siz)",
         "done": (meta.get("endpoint_diff") or {}).get("no_diff_streak", 0) >= 2,
         "weight": 7},
        {"name": "WAF parmak izi", "done": getattr(engine, "waf_profile", None) is not None,
         "weight": 5},
        {"name": "PoC doğrulama (≥1 kanıtlı hipotez)",
         "done": any(getattr(e, "verified", None) is True for e in engine.graph.evidence),
         "weight": 14},
        {"name": "Zafiyet bulundu (≥1 kanıt)",
         "done": len(engine.graph.evidence) > 0,
         "weight": 15},
    ]
    score = sum(item["weight"] for item in items if item["done"])
    max_score = sum(item["weight"] for item in items)
    return {
        "score": score,
        "max_score": max_score,
        "percent": round(score / max_score * 100) if max_score else 0,
        "items": items,
    }


def _build_coverage_state(engine, session) -> Dict[str, Any]:
    """Kapsama Sözleşmesi (A1) için tarama-sonu sinyallerini topla — SAF veri, I/O yok.

    coverage_contract.build_coverage'a beslenir. Her erişim korumalı: eksik/bozuk alan bu
    fonksiyonu ya da sözleşmeyi ÇÖKERTMEZ (build_coverage ayrıca degrade-safe). 'Koştu'
    sinyalleri: session.stages (aşamalar), tried_count>0 edge'ler, root.meta prob markerları
    (k8s_probed/idor_probed/wp_probed_hosts...). 'Bulundu' sinyali: Evidence.tool (otoriter)."""
    try:
        root = engine.graph.nodes[engine.graph.root_id]
        meta = dict(root.meta or {})
    except Exception:
        meta = {}
    evidence: List[Dict[str, Any]] = []
    for e in (getattr(engine.graph, "evidence", None) or []):
        try:
            tier = (e.effective_confidence_tier()
                    if hasattr(e, "effective_confidence_tier")
                    else getattr(e, "confidence_tier", None))
        except Exception:
            tier = getattr(e, "confidence_tier", None)
        evidence.append({
            "tool": getattr(e, "tool", ""),
            "severity": getattr(e, "severity", ""),
            "confidence_tier": tier,
            "verified": getattr(e, "verified", None),
        })
    tried_tools: List[str] = []
    try:
        for edge in engine.graph.edges.values():
            if (getattr(edge, "tried_count", 0) or 0) > 0:
                tried_tools.append(getattr(edge, "tool", ""))
    except Exception:
        pass
    try:
        ran_stages = list((session.stages or {}).keys())
    except Exception:
        ran_stages = []
    return {
        "evidence": evidence,
        "tried_tools": tried_tools,
        "ran_stages": ran_stages,
        "meta": meta,
        "profile": meta.get("target_profile") or {},
        "resilience_enabled": bool(getattr(session, "resilience", False)),
        "level": (getattr(session, "level", None)
                  or getattr(getattr(engine, "level", None), "name", "standard")),
    }


def partition_cohosted_by_ip(
    candidates: List[str], target_ip: str, resolved: Dict[str, List[str]]
) -> Tuple[List[str], List[Dict[str, str]]]:
    """SAF: reverse-IP adaylarını GÜNCEL A kaydına göre ikiye ayır (I/O dışarıda çözülür).

    Reverse-IP passive-DNS kaynakları bayat/hatalı olabilir (Cloudflare-fronted → gerçek IP
    gizli; komşu-IP/tarihsel kayıt). Bir domain'i "bu IP'de barınıyor" saymak için güncel A
    kaydı GERÇEKTEN target_ip'ye çözülmeli. Bu fonksiyon o kararı verir; DNS çözümleme
    (`resolved` haritası) çağıran tarafta yapılır → saf ve test edilebilir.

    Args:
      candidates: aday domain listesi.
      target_ip:  co-hosting için doğrulanacak IP.
      resolved:   {domain: [ip,...]} önceden çözülmüş harita (yoksa/boşsa doğrulanamadı sayılır).
    Döner: (verified sıralı liste, unverified [{name, resolved}] — TARANMAZ, sadece raporlanır)."""
    verified: List[str] = []
    unverified: List[Dict[str, str]] = []
    for d in candidates:
        ips = resolved.get(d) or []
        if target_ip in ips:
            verified.append(d)
        else:
            unverified.append({"name": d, "resolved": ",".join(ips) if ips else "çözülemedi"})
    return sorted(verified), unverified


class ScanPipelineV2:
    """
    Türkçe: v2 Pipeline Engine.
    Orchestrator içinde çalışır, profile'a göre stage'leri sırayla veya paralel yürütür.
    """

    def __init__(self, db):
        """
        Args:
            db: MongoDB database instance (orchestrator'dan geçirilen)
        """
        self.db = db
        self._active_pipelines: Dict[str, PipelineSession] = {}
        # İki fazlı onay kapısı: session_id -> asyncio.Event (keşif→onay→sömürü)
        self._approval_events: Dict[str, asyncio.Event] = {}
        # Onay bekleyen session'lar için engine referansı
        self._approval_engines: Dict[str, Any] = {}
        # Çalışan otonom engine'ler (session_id -> engine) — co-hosted onay endpoint'i erişir
        self._running_engines: Dict[str, Any] = {}

    def _get_sessions_collection(self):
        if self.db is not None:
            return self.db["v2_scan_sessions"]
        return None

    def _get_vulnerabilities_collection(self):
        if self.db is not None:
            return self.db["vulnerabilities"]
        return None

    async def start_pipeline(
        self,
        target: str,
        profile_name: str = "normal",
        scan_id: Optional[str] = None,
        level: Optional[str] = None,
        stealth: bool = False,
        auth: Optional[Dict[str, Any]] = None,
        auth_b: Optional[Dict[str, Any]] = None,
        target_kind: Optional[str] = None,
        resilience: bool = False,
    ) -> Dict[str, Any]:
        """
        Türkçe: Pipeline'ı başlat.
        Background task olarak çalışır, hemen session bilgisini döner.
        `level` (recon|standard|deep) otonom modda tarama derinliğini belirler.
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        session_id = str(uuid.uuid4())

        # ---- TEK DOKTRIN: her tarama otonom motordan geçer (Kuşatma Doktrini) ----
        # Explicit otonom istek VEYA legacy statik yol kapalıysa (varsayılan) → otonom motor.
        # Seviye: kullanıcı verdiyse o, yoksa eski profil adından türetilir.
        is_explicit_autonomous = profile_name in ("autonomous", "ai_autonomous")
        route_to_autonomous = is_explicit_autonomous or not LEGACY_PROFILES_ENABLED
        if route_to_autonomous:
            resolved_level = level or (
                None if is_explicit_autonomous else profile_to_level(profile_name)
            )
            session = PipelineSession(
                session_id=session_id,
                scan_id=scan_id,
                target=target,
                profile_name="autonomous",
                level=resolved_level,
                stealth=stealth,
                auth=auth,
                auth_b=auth_b,
                target_kind=(target_kind or None),
                resilience=bool(resilience),
            )
            self._active_pipelines[session_id] = session
            self._save_session(session)
            # Fire-and-forget task'a REFERANS tut + yutulan hatayı GÖRÜNÜR yap. Referanssız
            # create_task, bir 'await' noktasında askıdayken GC tarafından toplanabilir VEYA
            # erken bir exception'ı sessizce yutar — her iki durumda oturum sonsuza dek
            # 'running' kalır (teşhis edilemez, operatör "tarama yapmıyor" yaşar). Done-callback
            # hatayı loglar ve oturumu 'failed' damgalar → sessiz ölüm biter.
            task = asyncio.create_task(self._run_autonomous(session))
            if not hasattr(self, "_bg_tasks"):
                self._bg_tasks = set()
            self._bg_tasks.add(task)

            def _autonomous_done(t: asyncio.Task, _sess=session):
                self._bg_tasks.discard(t)
                if t.cancelled():
                    return
                exc = t.exception()
                if exc is not None:
                    logger.error(
                        f"[{_sess.scan_id[:8]}] Otonom motor beklenmedik hata ile öldü: "
                        f"{type(exc).__name__}: {exc}", exc_info=exc)
                    try:
                        _sess.status = "failed"
                        _sess.error = f"engine crash: {type(exc).__name__}: {exc}"
                        self._update_session(_sess)
                    except Exception:
                        pass

            task.add_done_callback(_autonomous_done)
            return {
                "session_id": session_id,
                "scan_id": scan_id,
                "target": target,
                "profile": "autonomous",
                "level": resolved_level or "standard",
                "profile_description": "Otonom saldırı simülasyonu — dış saldırgan gibi "
                                       "kendi kendine ilerler, gerçek zafiyet arar.",
                "mode": "autonomous",
                "stages": ["dynamic"],
                "estimated_minutes": None,
                "status": "started",
            }

        # ---- LEGACY: sadece LEGACY_PROFILES_ENABLED=true iken statik profil yolu ----
        profile = get_profile(profile_name)

        # Session oluştur
        session = PipelineSession(
            session_id=session_id,
            scan_id=scan_id,
            target=target,
            profile_name=profile_name,
        )

        # Stage bilgilerini ekle
        for stage in profile.stages:
            session.stages[stage.name] = {
                "tool": stage.tool,
                "status": "pending",
                "parallel_group": stage.parallel_group,
            }

        self._active_pipelines[session_id] = session

        # MongoDB'ye kaydet
        self._save_session(session)

        # Background task olarak çalıştır
        asyncio.create_task(self._run_pipeline(session, profile))

        return {
            "session_id": session_id,
            "scan_id": scan_id,
            "target": target,
            "profile": profile_name,
            "profile_description": profile.description,
            "stages": list(session.stages.keys()),
            "estimated_minutes": profile.estimated_duration_minutes,
            "status": "started",
        }

    async def _run_pipeline(self, session: PipelineSession, profile: ScanProfile):
        """Türkçe: Pipeline'ın asıl çalışma mantığı"""
        session.status = "running"
        session.started_at = datetime.utcnow().isoformat()
        self._update_session(session)

        # SSE: Tarama başladı
        tools = [s.tool for s in profile.stages]
        await emit_scan_started(session.scan_id, session.target, tools)

        dispatcher = ToolDispatcher(session.scan_id, session.target)
        adaptive = AdaptiveScanner()  # Adaptif analiz motoru
        pipeline_start = datetime.utcnow()
        all_results: Dict[str, StageResult] = {}
        failed_required = False

        try:
            # Stage'leri grupla: Paralel gruplar ve sıralı stage'ler
            execution_order = self._build_execution_order(profile.stages)

            total_stages = len(profile.stages)
            completed_stages = 0

            for group in execution_order:
                if failed_required:
                    # Önceki required stage başarısız olduysa kalan stage'leri skip et
                    for stage in group:
                        all_results[stage.name] = StageResult(
                            stage_name=stage.name,
                            tool=stage.tool,
                            status="skipped",
                            error="Önceki zorunlu aşama başarısız oldu",
                        )
                        session.stages[stage.name]["status"] = "skipped"
                    continue

                if len(group) == 1:
                    # Tek stage - sıralı çalıştır
                    stage = group[0]
                    session.stages[stage.name]["status"] = "running"
                    self._update_session(session)

                    # Heartbeat: uzun taramalarda frontend'e yaşıyorum sinyali
                    await emit_heartbeat(
                        session.scan_id,
                        f"Stage başlıyor: {stage.name} ({stage.tool}) | "
                        f"{completed_stages}/{total_stages} tamamlandı"
                    )

                    result = await dispatcher.dispatch(stage)
                    all_results[stage.name] = result

                    session.stages[stage.name]["status"] = result.status
                    session.stages[stage.name]["duration"] = result.duration_seconds

                    # ADAPTIVE: Her stage sonrası adaptif analiz
                    if result.status == "completed" and result.data:
                        try:
                            adaptive_result = adaptive.analyze_stage_results(
                                stage_name=stage.name,
                                stage_data=result.data,
                                all_results={k: asdict(v) for k, v in all_results.items()},
                                is_behind_cdn=dispatcher.discovered_data.get("is_behind_cf", False),
                                real_ip_found=bool(dispatcher.discovered_data.get("primary_real_ip")),
                            )
                            # Adaptif sonuçları session'a kaydet
                            session.stages[stage.name]["adaptive"] = adaptive_result

                            if adaptive_result.get("anomalies"):
                                await ScanEventBus.publish(ScanEvent(
                                    scan_id=session.scan_id,
                                    event_type=ScanEventType.CRITICAL_FINDING,
                                    data={
                                        "type": "adaptive_alert",
                                        "anomalies": adaptive_result["anomalies"][:5],
                                        "recommendations": adaptive_result["recommendations"][:3],
                                    },
                                ))
                        except Exception as ae:
                            logger.debug(f"Adaptive analysis error: {ae}")

                    completed_stages += 1
                    pct = int((completed_stages / total_stages) * 100)
                    await emit_progress_update(
                        session.scan_id, stage.name, pct,
                        f"{stage.tool} - {result.status}",
                    )

                    # Required stage başarısız olursa pipeline dursun
                    if result.status in ("failed", "timeout") and stage.required:
                        failed_required = True
                        logger.warning(f"Required stage failed: {stage.name}")

                else:
                    # Paralel grup - eşzamanlı çalıştır
                    for stage in group:
                        session.stages[stage.name]["status"] = "running"
                    self._update_session(session)

                    tasks = [dispatcher.dispatch(stage) for stage in group]
                    results = await asyncio.gather(*tasks, return_exceptions=True)

                    for stage, result in zip(group, results):
                        if isinstance(result, Exception):
                            result = StageResult(
                                stage_name=stage.name,
                                tool=stage.tool,
                                status="failed",
                                error=str(result),
                            )
                        all_results[stage.name] = result
                        session.stages[stage.name]["status"] = result.status
                        session.stages[stage.name]["duration"] = result.duration_seconds

                        completed_stages += 1

                        if result.status in ("failed", "timeout") and stage.required:
                            failed_required = True

                    pct = int((completed_stages / total_stages) * 100)
                    await emit_progress_update(
                        session.scan_id, "parallel_group", pct,
                        f"Paralel grup tamamlandı ({len(group)} aşama)",
                    )

                self._update_session(session)

            # Pipeline tamamlandı
            session.completed_at = datetime.utcnow().isoformat()
            session.total_duration_seconds = (datetime.utcnow() - pipeline_start).total_seconds()
            session.status = "failed" if failed_required else "completed"

            # Zafiyetleri ayrı collection'a kaydet
            self._save_vulnerabilities(session.scan_id, session.target, all_results)

            self._update_session(session)

            # SSE: Tamamlandı
            summary = self._build_summary(session, all_results)
            await emit_scan_completed(session.scan_id, summary)

            # AI Analiz tetikle (background)
            if profile.ai_analysis_enabled:
                asyncio.create_task(self._trigger_ai_analysis(session, all_results))

            logger.info(
                f"Pipeline completed: {session.scan_id} "
                f"({session.total_duration_seconds:.0f}s, status={session.status})"
            )

        except Exception as e:
            logger.error(f"Pipeline error: {session.scan_id} -> {e}")
            session.status = "failed"
            session.error = str(e)
            session.completed_at = datetime.utcnow().isoformat()
            session.total_duration_seconds = (datetime.utcnow() - pipeline_start).total_seconds()
            self._update_session(session)

            await emit_scan_failed(session.scan_id, str(e))

        finally:
            # Active pipelines'dan kaldır
            self._active_pipelines.pop(session.session_id, None)

    # ================================================================
    # OTONOM MOD (Autonomous Attacker Simulation)
    # Dış saldırgan gibi düşünen, kendi kendine ilerleyen tarama.
    # Statik profil YOK — her adımı motor karar verir, canlı gösterir.
    # ================================================================

    # Otonom motorun çağırdığı toollar ↔ ilgili docker-compose servis adları.
    # Preflight'da kapalıysa kullanıcıya "şu servisi başlat" diye gösteririz.
    _COMPOSE_SERVICE_NAMES: Dict[str, str] = {
        "nmap": "nmap-service",
        "nuclei": "nuclei-service",
        "subfinder": "subfinder-service",
        "rustscan": "rustscan-service",
        "fuzz": "fuzz-service",
        "recon": "recon-service",
        "osint": "osint-service",
    }

    _REQUIRED_SERVICE_URLS = {
        "nmap": NMAP_SERVICE_URL,
        "nuclei": NUCLEI_SERVICE_URL,
        "subfinder": SUBFINDER_SERVICE_URL,
        "rustscan": RUSTSCAN_SERVICE_URL,
        "fuzz": FUZZ_SERVICE_URL,
        "recon": RECON_SERVICE_URL,
        "osint": OSINT_SERVICE_URL,
    }

    async def _probe_required_services(self) -> Dict[str, bool]:
        """KRİTİK (K7): Otonom motorun bağımlı olduğu 7 tarayıcı servisinin
        HTTP olarak ulaşılabilir olup olmadığını kısa (3sn) yoklar.

        Döner: {servis_adı: bool}. HTTP yanıtı (<500) 'ayakta' demek, bağlantı
        hatası/timeout veya 5xx 'kapalı' demek. Kesin bir /health endpoint'i
        garantisi olmadığı için kök veya /health'e istek atıp SÜRECİN ayakta
        olup olmadığını yanıtlarız — komutunnerde 404 dahi dönebilse bağlantı
        kurulduğunu (servis process'inin yaşadığını) gösterir."""
        probe_paths = {
            "osint": "/health",   # osint-service /health endpoint'ini uygulamış
            "nmap": "/config",    # nmap-service:8001 /config endpoint'ini sunuyor
            "nuclei": "/config",  # nuclei-service:8003 /config endpoint'ini sunuyor
            # Diğer standart sözleşmeli servislerde /health garantisi yok → kök "/" ile deneyim.
        }
        # shared client: aynı seviyede paralel yoklama.
        client = httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=2.0))

        async def _probe(name: str, base: str) -> bool:
            path = probe_paths.get(name, "/")
            try:
                resp = await client.get(f"{base}{path}")
                return resp.status_code < 500
            except Exception:
                return False

        try:
            names = list(self._REQUIRED_SERVICE_URLS.keys())
            ups = await asyncio.gather(
                *[_probe(n, u) for n, u in self._REQUIRED_SERVICE_URLS.items()],
                return_exceptions=False,
            )
            return {name: bool(up) for name, up in zip(names, ups)}
        except Exception:
            # Herhangi bir beklenmedik hatada tümünü False sayıp devam et.
            return {name: False for name in self._REQUIRED_SERVICE_URLS}
        finally:
            await client.aclose()

    async def _run_autonomous(self, session: PipelineSession):
        """Türkçe: Otonom saldırı simülasyon döngüsü (decide -> act -> observe)."""
        session.status = "running"
        session.started_at = datetime.utcnow().isoformat()
        self._update_session(session)

        await emit_scan_started(session.scan_id, session.target, ["autonomous"])

        dispatcher = ToolDispatcher(session.scan_id, session.target, auth=session.auth)
        run_start = datetime.utcnow()

        def timeline_push(event_type: ScanEventType, message: str, data: Dict[str, Any]):
            """EKSİK-0: session.ai_analysis.agent_timeline içine kalıcı adım kaydı biriktir.
            WS geçmişi 20 event ile sınırlı; reconnect'te frontend'in okuyacağı kalıcı kaynak budur."""
            if session.ai_analysis is None:
                session.ai_analysis = {}
            timeline = session.ai_analysis.setdefault("agent_timeline", [])
            timeline.append({
                "event_type": event_type.value, "message": message,
                "data": data, "timestamp": datetime.utcnow().isoformat(),
            })

        async def narrate(
            event_type: ScanEventType, message: str,
            data: Dict[str, Any] = None,
            persist_data: Optional[Dict[str, Any]] = None,
        ):
            """WS event'i `data` (tam, canlı akış için) ile yayınlanır; kalıcı agent_timeline'a
            ise `persist_data` (verilmişse hafif referans) yazılır. Böylece ağır `result_summary`
            gibi alanlar WS'te bir kez görünür ama her adımda MongoDB'ye yeniden yazılan
            agent_timeline'ı şişirmez — ham veri zaten scan_artifacts'te kalıcıdır."""
            data = data or {}
            # LLM alışverişi (prompt + ham cevap) ADMIN-ÖZEL ve ağır. Canlı WS bus'ına
            # HİÇ YAYINLANMAZ — aksi halde scan stream'ine bağlı her (admin olmayan)
            # abone system_prompt/prompt/raw_response'u görürdü (yetki sızıntısı). Yalnızca
            # ayrı scan_llm_logs koleksiyonuna kalıcı yazılır; admin panel oradan (rol
            # kontrollü REST endpoint ile) okur. agent_timeline'a da girmez.
            if event_type == ScanEventType.AGENT_LLM_EXCHANGE:
                self._save_llm_log(session.scan_id, message, data)
                return
            await ScanEventBus.publish(ScanEvent(
                scan_id=session.scan_id,
                event_type=event_type,
                data={"message": message, **data},
            ))
            timeline_push(event_type, message, persist_data if persist_data is not None else data)

        async def act(message: str):
            """GÖRÜNÜRLÜK (UI akışı): post-observe probe'leri (WAF parmak izi, servis derin-dalış,
            K8s, IDOR...) WS'e SESSİZ koşuyordu → frontend "dondu/bekliyor" hissi, sonra adım
            sıçraması. Her probun başında hafif `engine_activity` olayı yayınla; frontend canlı
            etkinlik bandı bunu gösterir. narrate DEĞİL: agent_timeline'a persist edilmez (yalnız
            WS bus), admin-özel veri içermez."""
            await ScanEventBus.publish(ScanEvent(
                scan_id=session.scan_id,
                event_type=ScanEventType.PROGRESS_UPDATE,
                data={"type": "engine_activity", "message": message,
                      "step": (engine.step or None)},
            ))

        engine = AutonomousEngine(session.scan_id, session.target,
                                   target_is_ip=dispatcher.target_is_ip, emit=narrate,
                                   level=session.level)
        await act("🚀 Motor hazırlanıyor — geçmiş dersler yükleniyor, istihbarat yapılandırılıyor")
        # OAST & APT Stealth Controller başlat
        try:
            from .oast_client import OastClient
            from .stealth_controller import StealthController
            engine.oast_client = OastClient(session_id=session.session_id)
            engine.stealth_controller = StealthController()
        except Exception as _sc_e:
            logger.debug(f"OAST/Stealth başlatılamadı: {_sc_e}")
            engine.oast_client = None
            engine.stealth_controller = None
        # FIELD-JOURNAL (exploit_memory): önceki taramalarda AKTİF doğrulanmış sömürü
        # derslerini scan_memories'den yükle → LLM prompt'una "GEÇMİŞ DERSLER" olarak girer.
        # Böylece istihbarat subayı hedefi/benzer hedefleri tanır; her taramaya sıfırdan
        # başlamaz. Flag: EXPLOIT_MEMORY=0 kapatır. Hata → sessiz fallback (motor bozulmaz).
        if os.getenv("EXPLOIT_MEMORY", "1") == "1":
            try:
                from core.db import db as _mdb
                if _mdb is not None:
                    from .exploit_memory import load_exploit_lessons, load_failed_patterns
                    engine.memory_lessons = load_exploit_lessons(
                        _mdb["scan_memories"], session.target)
                    # Başarısızlık listesi de prompt'a girer: LLM patlamış kalıpları
                    # tekrar önermesin (deterministik filtre ayrıca kuyrukta çalışır).
                    _fk, engine.failed_lessons = load_failed_patterns(
                        _mdb["scan_memories"], session.target)
                    if engine.memory_lessons:
                        logger.info(
                            f"🧠 [{session.scan_id[:8]}] Field-journal: "
                            f"{len(engine.memory_lessons)} doğrulanmış ders yüklendi.")
            except Exception as _fj_e:
                logger.debug(f"Field-journal yüklenemedi (yok sayılıyor): {_fj_e}")
        # VEKTÖR HAFIZA (Qdrant) — field-journal'ı TAMAMLAR: düz-metin eşleşmenin
        # bulamadığı SEMANTİK benzer geçmiş bulguları hedef profilinden recall eder.
        # Flag: VECTOR_MEMORY_ENABLED (varsayılan kapalı). Hata/kapalı → sessiz no-op;
        # doktrin: hafıza lükstür, kritik yol değil — motor hafızasız eksiksiz çalışır.
        try:
            from .memory_store import gecmis_dersleri_hatirla
            _vektor_dersler = gecmis_dersleri_hatirla(session.target, limit=5)
            if _vektor_dersler:
                engine.memory_lessons.extend(_vektor_dersler)
                await narrate(
                    ScanEventType.AGENT_THINKING,
                    f"🧠 Vektör hafıza: geçmiş taramalardan {len(_vektor_dersler)} benzer "
                    f"bulgu/ders hatırlandı — istihbarat subayının bağlamına eklendi.",
                    {"step": 0, "vector_memory_hits": len(_vektor_dersler)},
                )
        except Exception as _vh_e:
            logger.debug(f"Vektör hafıza recall atlandı (yok sayılıyor): {_vh_e}")
        # Çalışan engine'i registry'ye kaydet — co-hosted onay endpoint'i (UI) buna erişir.
        self._running_engines[session.session_id] = engine
        # Recon/origin CF durumunu dispatcher ile paylaş (root node meta üstünden)
        root_meta = engine.graph.nodes[engine.graph.root_id].meta
        root_meta["is_behind_cdn"] = dispatcher.discovered_data.get("is_behind_cf", False)
        root_meta["real_ip"] = dispatcher.discovered_data.get("primary_real_ip")

        # PREFLIGHT (K6): LLM istihbarat subayı gerçekten aktif mi? Kullanıcıya baştan bildir.
        # Motoru engellemez; sadece "AI aktif/kural-fallback" durumunu görünür yapar.
        await act("🔌 Ön kontrol — LLM istihbarat subayı yoklanıyor")
        try:
            llm_status = await engine.preflight()
            if session.ai_analysis is None:
                session.ai_analysis = {}
            session.ai_analysis["llm_status"] = llm_status
            self._update_session(session)
        except Exception as _pf_e:
            logger.debug(f"Preflight atlandı: {_pf_e}")

        # PREFLIGHT (K7 — SERVİS SAĞLIĞI): Otonom motorun çağırdığı 7 tarayıcı
        # mikroservisinin (nmap/nuclei/subfinder/rustscan/recon/osint/fuzz) gerçekten
        # ayakta olup olmadığını BAŞTAN yoklar. Bunlardan biri kapalıysa ilgili tool
        # her çağrıda ConnectError ile sessizce "failed" dönecek, motor boş tarama
        # yapıp "kanıt bulunamadı" diye bitirecektir — kullanıcı bunu "tarama boş
        # dönüyor" belirtisi olarak yaşar. Burada açıkça AGENT_THINKING uyarısı
        # yayınlanır: "nmap-service erişilemez — docker compose ile başlatın" vb.
        # Motoru DURDURMAZ (recon fallback, InternetDB, origin_discovery gibi
        # orchestrator-içi araçlar yine çalışır); yalnızca sessiz hatayı görünür yapar.
        # Tam-felaket kapısı (yukarıda): tüm servisler down ise while'a hiç girilmez —
        # boş 'temiz' tarama üretme (svc_all_down stop_reason'unu taşır).
        await act("🩺 Ön kontrol — 7 tarayıcı servisinin sağlığı yoklanıyor")
        svc_status: Dict[str, bool] = {}
        try:
            svc_status = await self._probe_required_services()
            down = [name for name, up in svc_status.items() if not up]
            if down:
                await narrate(
                    ScanEventType.AGENT_THINKING,
                    f"⚠️ TARAYICI SERVİSLERİ EKSİK — {', '.join(down)} ulaşılamaz. "
                    f"Bu araçlar her adımda sessizce 'failed' dönecek; tarama BOŞ "
                    f"çıkabilir. Başlatın: `docker compose up -d "
                    f"{' '.join(_COMPOSE_SERVICE_NAMES[n] for n in down)}`",
                    {"service_status": svc_status, "missing_services": down},
                    persist_data={"service_status": svc_status,
                                  "missing_services": down},
                )
                logger.warning(
                    f"[{session.scan_id[:8]}] Otonom tarama başladı ama gerekli "
                    f"servisler kapalı: {down}"
                )
        except Exception as _sv_e:
            logger.debug(f"Servis sağlık probu atlandı: {_sv_e}")

        # DÜRÜST-TARAMA (tam-felaket kapısı): HEPSİ kapalıysa motor hiçbir araç
        # çalıştıramaz → her dispatch sessizce 'failed' döner → oturum kanıtsız 'biter'.
        # Bu, kullanıcının "boş tarama" yaşadığı senaryolardan biridir. Aktif döngüye
        # GİRME; stop_reason + kapanış anlatısı durumu açıkça söyler. (Orchestrator-içi
        # pasif araçlar tek başına tarama iddiası taşımaz — dürüstlük > kısmi görüntü.)
        svc_all_down = bool(svc_status) and not any(svc_status.values())
        if svc_all_down:
            stop_reason = "all_services_down"
            session.status = "failed"
            self._update_session(session)
            await narrate(
                ScanEventType.WARNING,
                "⛔ TÜM tarayıcı servisleri (nmap/nuclei/subfinder/rustscan/fuzz/recon/osint) "
                "kapalı — aktif zafiyet taraması YAPILAMADI. Boş 'temiz' raporu üretmemek "
                "için döngü başlatılmadı. Stack'i başlatın: `docker compose up -d`",
                {"service_status": svc_status, "fatal": True},
            )

        # Kapanış anlatısı için: motor NEDEN durdu? (bütçe / karar / araç yok)
        # NOT: yukarıda 'all_services_down' ATANDIYSA ezilmez — döngüye hiç girilmedi,
        # o nihai karardır. (Tanım sırası: fatal kapısı while'dan ÖNCE çalışır.)
        if not svc_all_down:
            stop_reason = "budget"      # döngü while koşuluyla biterse bütçe/süre doldu demektir
        last_reasoning = ""             # son 'düşün' gerekçesi (sıradaki hamle/çıkmaz)
        # §2.6: Sessizce yutulan aşama düşüşlerini GÖRÜNÜR yap — her failed/timeout aşama
        # kaydedilir + WARNING yayınlanır; tarama-sonu özetinde "N aşamadan M'si düştü".
        degraded_stages: List[Dict[str, Any]] = []
        # IPB — taramaya başlamadan hedefi TANI (recon-first). İlk profil web sinyalleriyle
        # kurulur → İLK nuclei bile stack'e göre tag-scope'lanır (PHP-on-node gürültüsü baştan
        # kesilir). Portlar henüz yoksa gözlem döngüsünde nmap sonrası tazelenir.
        await act("🎯 Hedef tanınıyor — recon-first profil çıkarılıyor (web/appliance/host)")
        try:
            await self._ensure_target_profile(session, engine, dispatcher)
        except Exception as _tpe0:
            logger.debug(f"İlk hedef profili atlandı: {_tpe0}")
        try:
            while engine.budget_left() and not svc_all_down:
                # §2.5: Duraklatıldıysa YENİ hamle başlatma — resume gelene kadar bekle.
                # (Çalışan bir stage'i kesmez; yalnız sıradaki kararı bekletir → stealth bozulmaz.)
                if engine.is_paused:
                    session.status = "paused"
                    self._update_session(session)
                    await narrate(ScanEventType.AGENT_THINKING,
                                  "⏸️ Kuşatma duraklatıldı — 'Devam Et' bekleniyor.")
                    await engine.wait_while_paused()
                    if engine.cancelled:
                        stop_reason = "decision"
                        break
                    session.status = "running"
                    self._update_session(session)
                    await narrate(ScanEventType.AGENT_THINKING, "▶️ Kuşatma sürdürülüyor.")

                # 1) DECIDE (expand -> appraise -> siege_score -> guardrail)
                await act("🧠 Hamle hesaplanıyor — sınır genişletiliyor + istihbarat subayına danışılıyor")
                decision, considered = await engine.next_decision()
                last_reasoning = decision.reasoning

                await narrate(
                    ScanEventType.AGENT_THINKING,
                    f"🧠 Adım {engine.step}: {decision.reasoning}",
                    {
                        "step": engine.step, "action": decision.action.value,
                        "tool": decision.tool, "expected": decision.expected,
                        "confidence": decision.confidence, "source": decision.source,
                        "siege_score": considered[0]["score"] if considered else None,
                        "chosen_because": "en yüksek getiri/maliyet oranı",
                        "considered": considered,
                        "target_node": considered[0]["target_node"] if considered else None,
                        "target_value": (
                            engine.graph.nodes[considered[0]["target_node"]].value
                            if considered and considered[0]["target_node"] in engine.graph.nodes
                            else None
                        ),
                    },
                )

                # PLAN B: LLM'in bu turda ürettiği SOMUT saldırı hipotezlerini AKTİF doğrula.
                # DeepSeek "şu param'da SQLi olabilir" der → verifier deterministik kanıtlar →
                # YALNIZ kanıtlanırsa verified Evidence olur (LLM'e körü körüne güvenilmez).
                await act("🧪 İstihbarat subayının saldırı hipotezleri deterministik doğrulanıyor")
                await self._verify_hypotheses(session, engine, narrate)

                # 2) Terminal / özel aksiyonlar
                if decision.action == DecisionAction.STOP:
                    stop_reason = "decision"
                    await narrate(ScanEventType.AGENT_THINKING,
                                  f"✅ Karar: durdur. {decision.reasoning}")
                    break

                if decision.action == DecisionAction.REQUEST_APPROVAL:
                    # Tehlikeli aksiyon: otomatik ÇALIŞTIRMA, onay iste ve atla
                    await narrate(
                        ScanEventType.AGENT_APPROVAL_NEEDED,
                        f"⚠️ '{decision.tool}' tehlikeli bir aksiyon. İnsan onayı gerekiyor, "
                        f"otomatik atlanıyor.",
                        {"tool": decision.tool, "options": decision.options},
                    )
                    skip_edge = Edge(from_id=engine.graph.root_id, to_id=engine.graph.root_id,
                                      tool=decision.tool or "danger", options=decision.options)
                    engine.graph.executed_signatures.add(skip_edge.signature())
                    continue

                if decision.action == DecisionAction.PHASE_GATE:
                    # İki fazlı onay kapısı: keşif fazı bitti, sömürü için onay bekle
                    recon_map = engine.recon_map
                    await narrate(
                        ScanEventType.AGENT_PHASE_GATE,
                        "🛡️ KEŞİF FAZI TAMAMLANDI — Saldırı yüzeyi haritalandı. "
                        "Sömürü fazına geçmek için onay bekleniyor.",
                        {
                            "recon_map": recon_map,
                            "total_hosts": len(recon_map.get("discovered_hosts", [])),
                            "co_hosted_domains": recon_map.get("co_hosted_domains", []),
                            "active_edges_waiting": len(recon_map.get("active_edges_waiting", [])),
                        },
                    )
                    session.status = "awaiting_approval"
                    if session.ai_analysis is None:
                        session.ai_analysis = {}
                    session.ai_analysis["recon_map"] = recon_map
                    self._update_session(session)
                    # Durakla ve onay bekle — loop async beklemeye geçer
                    await self._wait_for_approval(session, engine)
                    # Onay geldi, engine._phase artık "exploit"
                    continue

                if not decision.tool:
                    stop_reason = "no_tool"
                    break

                # 3) ACT
                stage = decision.to_stage()
                # Gizli kip (seviyeden bağımsız): nmap taramalarını stealth preset'e (-T2,
                # -f, randomize) çevir. Graf mantığına dokunmaz — sadece yürütme kipidir.
                if session.stealth and stage.tool == "nmap" and "preset" not in stage.options:
                    stage.options["preset"] = "stealth"
                session.stages[stage.name] = {"tool": stage.tool, "status": "running",
                                              "reasoning": decision.reasoning}
                self._update_session(session)

                await narrate(
                    ScanEventType.AGENT_ACTION,
                    f"▶️ {stage.tool.upper()} çalıştırılıyor — hedef: {decision.expected}",
                    {"step": engine.step, "tool": stage.tool, "options": stage.options,
                     "expected": decision.expected},
                )
                # Canlı etkinlik bandı da aracın çalıştığını göstersin — kalp atışı adım kartını
                # tazeler ama bant bayat kalmasın; ActivityAge saniyeyi kendisi sayar.
                await act(f"🔧 {stage.tool.upper()} çalışıyor — servis yanıtı bekleniyor")

                # ACT'i task olarak başlat; beklerken periyodik "hâlâ çalışıyor (Ns)" sinyali
                # yay ki uzun süren araçlarda (recon/nmap) ekran donuk görünmesin.
                # Bu heartbeat SADECE WS'e gider (persist_data={} ile kalıcı timeline'a yazılmaz).
                # Orchestrator-yerli AKTİF saldırı (probe_api_bola): dış servis yok →
                # heartbeat dispatch makinesini atla, kampanyayı doğrudan koş. Sonuç
                # normal akışa (artifact + observe + post-observe) StageResult olarak girer.
                if stage.tool == "probe_api_bola":
                    result = await self._dispatch_bola_native(session, engine, narrate, stage)
                else:
                    dispatch_task = asyncio.create_task(dispatcher.dispatch(stage))
                    act_started = datetime.utcnow()
                    heartbeat_step = engine.step
                    heartbeat_tool = stage.tool
                    interrupted = False
                    while not dispatch_task.done():
                        try:
                            await asyncio.wait_for(asyncio.shield(dispatch_task), timeout=8.0)
                        except asyncio.TimeoutError:
                            # §2.5: İptal geldiyse çalışan aracın bitmesini BEKLEME — dispatch'i kes +
                            # servisi durdur. İptal artık ≤8sn'de hissedilir (eskiden stage sonuna
                            # kadar sürer, 'kozmetik iptal' olurdu).
                            if engine.cancelled:
                                interrupted = True
                                dispatch_task.cancel()
                                try:
                                    await dispatcher._try_stop_scan(stage.tool)
                                except Exception:
                                    pass
                                break
                            elapsed = int((datetime.utcnow() - act_started).total_seconds())
                            await narrate(
                                ScanEventType.AGENT_ACTION,
                                f"⏳ {heartbeat_tool.upper()} çalışıyor… ({elapsed}sn)",
                                {"step": heartbeat_step, "tool": heartbeat_tool,
                                 "running": True, "elapsed_seconds": elapsed},
                                persist_data={},  # kalıcı timeline'ı şişirme
                            )
                        except Exception:
                            break  # asıl hata aşağıda result üzerinden ele alınır

                    if interrupted:
                        # Kesilen dispatch'in temizlenmesini bekle (CancelledError yut) ve sonucu
                        # İŞLEME — kullanıcı iptali; ana döngüden çık (budget_left zaten False dönerdi).
                        try:
                            await dispatch_task
                        except asyncio.CancelledError:
                            pass
                        except Exception:
                            pass
                        if stage.name in session.stages:
                            session.stages[stage.name]["status"] = "cancelled"
                        stop_reason = "decision"
                        break
                    result = await dispatch_task

                # --- GÖRÜNÜRLÜK: ham sonucu özetle + kalıcı sakla ---
                # "Recon taradı — e ne çıktı?" cevabı burada üretilir ve saklanır.
                result_summary = summarize_stage_result(stage.tool, result.data or {})
                artifact_id = self._save_scan_artifact(
                    session.scan_id, engine.step, stage, result, result_summary
                )

                session.stages[stage.name]["status"] = result.status
                session.stages[stage.name]["duration"] = result.duration_seconds
                session.stages[stage.name]["step"] = engine.step
                session.stages[stage.name]["summary"] = result_summary
                session.stages[stage.name]["artifact_id"] = artifact_id
                if result.error:
                    session.stages[stage.name]["error"] = result.error

                # §2.6: Aşama düştüyse (failed/timeout) SESSİZ GEÇME — kaydet + operatöre
                # WARNING yayınla. Motor doktrin gereği DURMAZ (recon fallback devrede),
                # ama artık "recon düştü, fallback kullanıldı" operatöre görünür.
                if is_degraded(result.status):
                    rec = build_degraded_record(
                        stage_name=stage.name, tool=stage.tool, step=engine.step,
                        status=result.status, error=result.error,
                    )
                    degraded_stages.append(rec)
                    await narrate(
                        ScanEventType.WARNING,
                        f"⚠️ {stage.tool.upper()} aşaması düştü ({result.status})"
                        + (f": {result.error}" if result.error else "")
                        + " — motor kural+graf ile devam ediyor (kısmi sonuç).",
                        rec,
                    )

                # CF/gerçek IP güncellemelerini dispatcher'dan geri al
                root_meta["is_behind_cdn"] = root_meta.get("is_behind_cdn") or dispatcher.discovered_data.get("is_behind_cf", False)
                if dispatcher.discovered_data.get("primary_real_ip"):
                    root_meta["real_ip"] = dispatcher.discovered_data["primary_real_ip"]

                # 4) OBSERVE (grafa işle, kanıt topla, kural motorunu besle, öğren)
                new_ev = engine.observe(decision, result.data or {}, result.status)

                # 4.05) ÖLÜ-HOST DUYURUSU: observe bu adımda bir hostu 'host_unreachable'
                # nedeniyle karantinaya aldıysa operatöre görünür yap — sessiz kalırsa
                # "kapalı domainde ne arıyorsun" tekrar yaşanır (ölü artık taranmaz ama
                # NEDEN taranmadığı da bilinmeli).
                if engine.newly_dead_hosts:
                    for _dh in engine.newly_dead_hosts:
                        await narrate(
                            ScanEventType.WARNING,
                            f"☠️ {_dh} ÖLÜ host olarak karantinaya alındı "
                            f"(80/443 üzerinden HTTP erişimi yok) — bu hosta artık "
                            f"adım harcanmayacak, bütçe canlı yüzeylere akacak.",
                            {"host": _dh, "step": engine.step, "quarantine": "dead_host"},
                        )
                    engine.newly_dead_hosts.clear()

                # 4.1) GÖZLEMİ ANINDA DUYUR — UI'da adım "çalışıyor..." kalmasın!
                # Takip eden 15 zenginleştirme probu (k8s, wp, deserialization vb.) çalışırken
                # frontend bu adımın bittiğini ve özetini hemen görsün.
                obs_msg = f"📊 {stage.tool.upper()} → {result.status}"
                if new_ev > 0:
                    obs_msg = f"🔴 {new_ev} yeni KANITLI zafiyet bulundu! ({stage.tool.upper()})"
                    for ev in engine.graph.evidence[-new_ev:]:
                        await emit_vulnerability_found(
                            session.scan_id, ev.cve or ev.title, ev.title,
                            ev.severity, ev.target,
                        )
                elif result.status == "completed" and result_summary.get("highlights"):
                    obs_msg = f"📊 {stage.tool.upper()}: {result_summary['highlights'][0]}"

                root = engine.graph.nodes[engine.graph.root_id]
                obs_common = {
                    "step": engine.step, "status": result.status,
                    "new_evidence": new_ev,
                    "total_evidence": len(engine.graph.evidence),
                    "known_ports": len(root.meta.get("open_ports", [])),
                    "services": [n.label for n in engine.graph.nodes.values()
                                 if n.type.value == "service"],
                    "leads": engine.graph.notes[-5:],
                    "artifact_id": artifact_id,
                    "error": result.error,
                }
                live_obs = {**obs_common, "result_summary": result_summary}
                persist_obs = {
                    **obs_common,
                    "result_summary": {
                        "highlights": result_summary.get("highlights", [])[:3],
                        "counts": result_summary.get("counts", {}),
                        "table": {},
                    },
                }
                await narrate(
                    ScanEventType.AGENT_OBSERVATION, obs_msg,
                    live_obs, persist_data=persist_obs,
                )
                self._update_session(session)

                # DÜRÜST-TARAMA (ölü hedef): nmap kök hedefi DOWN buldu → döngüyü SÜRDÜRMEK
                # boş rapor üretir ve kullanıcı bunu "tarama tutarlı çalışmıyor" yaşar.
                # Kanıt aramayı kes, NEDENİ büyük-başlıkla söyle, kapanış anlatısına taşı.
                if (result.data or {}).get("host_unreachable"):
                    stop_reason = "target_unreachable"
                    await narrate(
                        ScanEventType.WARNING,
                        "⛔ HEDEF ULAŞILAMAZ — nmap kök hedefi DOWN buldu (host yanıt vermiyor). "
                        "Boş bir 'temiz' raporu üretmemek için tarama erken kesildi. "
                        "Hedefin ayakta/DNS'in çözüldüğünü doğrulayın.",
                        {"step": engine.step, "host_status": result.data.get("host_status"),
                         "note": result.data.get("note"), "tool": "nmap"},
                    )
                    break

                # 4.5) KEŞİF-SONRASI WAF PARMAK İZİ — observe bir web host çıkardıysa (recon/
                # nmap sonrası crawl/DAST kenarları seed edilir) her web origin için duvarı
                # parmak izle. Sömürü yoluna hiç gelinmese bile WAF görünür olur (operatörün
                # "WAF tespit etmiyor" şikayetinin kök çözümü). İç iş: yeni origin yoksa erken döner.
                await act("🛡️ WAF/CDN parmak izi — web origin duvarları tespit ediliyor")
                await self._maybe_fingerprint_waf(session, engine, narrate)

                # 4.6) SESSİZ HATA GÖRÜNÜRLÜĞÜ: OSINT 'completed' ama içeride API-anahtarı
                # hatasıyla boş döndüyse operatörü uyar (eksik key → 'boş tarama' hissi).
                await self._maybe_warn_osint_auth(stage, result, narrate)

                # PoC DOĞRULAMA (Pillar #1): yeni bulgulardaki SQLi adaylarını AKTİF teyit et
                # (zaman-tabanlı blind SQLi) → false-positive elenir, bulgu 'verified' damgalanır.
                # "Tarayıcı"yı "pentester"dan ayıran katman. Best-effort: çökse tarama düşmez.
                # IPB — "önce düşmanı tanı": hedef profilini kur/tazele + playbook'u (bilinçli
                # saldırı kararı) hesapla. Enrichment problarından ÖNCE → gate'ler ve nuclei
                # tag-scope güncel profile göre uygulanır. Best-effort; profil yoksa modüller
                # varsayılan davranır (kör kalma yok).
                await act("🎯 Hedef profili tazeleniyor — yeni keşiflerle playbook yeniden hesaplanıyor")
                try:
                    await self._ensure_target_profile(session, engine, dispatcher)
                except Exception as _tpe:
                    logger.info(f"Hedef profili atlandı (best-effort, scan={session.scan_id}): {_tpe}")
                if new_ev > 0:
                    await act("🔎 Yeni bulgular doğrulanıyor (deterministik + LLM hakemi)")
                    await self._verify_new_evidence(session, engine, new_ev, narrate)
                    # FALSE-POSITIVE (P2): catch-all host tespiti → var-olmayan yola 2xx dönen
                    # sunucuda 'ifşa/varlık' bulguları şüphelidir; deterministik demote + neden.
                    await self._annotate_catchall_findings(session, engine, new_ev, narrate)
                    # FALSE-POSITIVE (P3): deterministik doğrulayıcısı OLMAYAN unconfirmed
                    # bulgular için LLM-hakem ikincil görüş (asla kademe belirlemez — danışma).
                    await self._adjudicate_unconfirmed(session, engine, new_ev, narrate)
                # APT FAZ 3: mail/DNS servisleri keşfedildiyse AKTİF derin-dalış (SMTP STARTTLS/
                # VRFY, DNS AXFR/version). Kanıt olmasa da (new_ev=0) çalışır — nmap servis
                # node'u üretir üretmez. Best-effort; her node bir kez problanır. Doktrin:
                # zenginleştirme ASLA taramayı düşürmez → çağrı da korumalı.
                await act("🛠️ Servis derin-dalışı — SMTP/DNS/uygulama imzaları taranıyor")
                try:
                    await self._probe_discovered_services(session, engine, narrate)
                except Exception as _spe:
                    logger.info(f"Servis derin-dalış atlandı (best-effort, scan={session.scan_id}): {_spe}")
                # Madde 4 (T5): distro-paket zaafiyet matrisi — banner + OS'tan "Ubuntu
                # 20.04'te bu OpenSSH hâlâ Terrapin'in gerisinde" cümlesi. PASİF: hiç ağ
                # isteği yok, yalnız elimizdeki banner'ı USN snapshot'ına eşler.
                try:
                    await self._probe_distro_intel(session, engine, narrate)
                except Exception as _die:
                    logger.info(f"Distro istihbaratı atlandı (best-effort, scan={session.scan_id}): {_die}")
                # IPB payoff: hedef K8s ise (playbook k8s_probe aktif) K8s-farkında ifşa probu.
                # K8s DEĞİLSE hiç çalışmaz (bilinçli saldırı — gereksiz K8s portu yoklaması yok).
                # Madde 5 (T4) — NodePort YÜZEY pası ÖNCE koşar: dashboard/registry/apiserver
                # sızıntısını bulur, profil sinyalini besler → derin prob (aşağıda + sonraki
                # turlar) aynı turda/sonrasında kapsama alınır. Yalnız AÇIK portlara GET.
                await act("☸️ K8s yüzey probu — NodePort dashboard/registry/API keşfi")
                try:
                    await self._probe_kubernetes_surface(session, engine, narrate)
                except Exception as _k8se:
                    logger.info(f"K8s yüzey probu atlandı (best-effort, scan={session.scan_id}): {_k8se}")
                await act("☸️ K8s probu — kontrol düzlemi ifşa taraması")
                try:
                    await self._probe_kubernetes(session, engine, narrate)
                except Exception as _k8e:
                    logger.info(f"K8s probu atlandı (best-effort, scan={session.scan_id}): {_k8e}")
                # Hypervisor/sanallaştırma mgmt ifşası (ESXi/vCenter/Proxmox/Cockpit/oVirt) —
                # yalnız hedefin KENDİSİ, tahribatsız GET. "Ana makine görünür mü"nün dürüst
                # karşılığı: mgmt-plane internete açık mı. Best-effort, korumalı.
                await act("🖥️ Hypervisor yönetim yüzeyi probu (ESXi/vCenter/Proxmox)")
                try:
                    await self._probe_hypervisor(session, engine, narrate)
                except Exception as _hve:
                    logger.info(f"Hypervisor probu atlandı (best-effort, scan={session.scan_id}): {_hve}")
                # IPB payoff: hedef WordPress ise (playbook wp_probe, if_relevant) WP-özel
                # deterministik prob. WP DEĞİLSE hiç çalışmaz. _probe_idor'dan ÖNCE → bulduğu
                # /wp-json/<res>/<id> IDOR adayları aynı turda root.meta['endpoints']'e seed
                # edilir, IDOR diferansiyeli onları devralır. Best-effort, korumalı.
                await act("🎯 WordPress probu — WP ifşa/zaafiyet taraması")
                try:
                    await self._probe_wordpress(session, engine, narrate)
                except Exception as _wpe:
                    logger.info(f"WordPress probu atlandı (best-effort, scan={session.scan_id}): {_wpe}")
                # #4 admin-ajax SQLi ORACLE: WP tespit edildiyse (aynı wp_probe gate) action
                # handler'larında AKTİF time-based SQLi kanıtla. _probe_wordpress'ten SONRA
                # (WP doğrulandıktan sonra). AKTİF enjeksiyon → WP_SQLI_ORACLE + recon-değil kapılı.
                await act("🗄️ WP admin-ajax SQLi oracle — time-based teyit")
                try:
                    await self._probe_wp_sqli(session, engine, narrate)
                except Exception as _wse:
                    logger.info(f"WP SQLi oracle atlandı (best-effort, scan={session.scan_id}): {_wse}")
                # P3: hedef SharePoint/TeamCity/ASP.NET ise (playbook deserialization_probe,
                # if_relevant) tahribatsız kabul-imza probu. Değilse hiç çalışmaz. WP zincirinden
                # BAĞIMSIZ framework gate'i (aynı host havuzunu paylaşır).
                await act("📦 Deserialization kabul-imza probu")
                try:
                    await self._probe_deserialization(session, engine, narrate)
                except Exception as _dse:
                    logger.info(f"Deserialization probu atlandı (best-effort, scan={session.scan_id}): {_dse}")
                # P3: hedef edge/VPN/firewall appliance ise (playbook appliance_probe, if_relevant)
                # tahribatsız auth-bypass/missing-auth probu. Appliance değilse hiç çalışmaz.
                await act("🛡️ Appliance/edge probu — auth-bypass/missing-auth")
                try:
                    await self._probe_appliance(session, engine, narrate)
                except Exception as _ase:
                    logger.info(f"Appliance probu atlandı (best-effort, scan={session.scan_id}): {_ase}")
                # DAYANIKLILIK & MARUZ-KALMA (availability+exposure): L7 DoS dayanıklılığı +
                # origin-CDN-bypass ifşası + SSH parola-auth maruz-kalması. YALNIZ operatör UI
                # toggle'ı açtıysa (session.resilience — VARSAYILAN KAPALI). TAHRİBATSIZ; gerçek
                # DDoS/brute-force yok. Kapalıysa tek satırlık kontrolle hemen döner (sıfır maliyet).
                await act("⚡ Dayanıklılık & CDN-bypass maruz-kalma probu")
                try:
                    await self._probe_resilience(session, engine, narrate)
                except Exception as _rse:
                    logger.info(f"Dayanıklılık probu atlandı (best-effort, scan={session.scan_id}): {_rse}")
                # APT FAZ 4: crawl LLM/chat endpoint'i keşfettiyse ofansif prompt-injection
                # red-team (MITRE ATLAS). Tahribatsız işaret-tabanlı; best-effort, korumalı.
                await act("🧠 LLM endpoint red-team — prompt injection (MITRE ATLAS)")
                try:
                    await self._redteam_llm_endpoints(session, engine, narrate)
                except Exception as _lre:
                    logger.info(f"LLM red-team atlandı (best-effort, scan={session.scan_id}): {_lre}")
                # T2-A: keşfedilen nesne-referanslı URL'lerde IDOR/BOLA diferansiyel probu.
                # A kimliği (auth) şart; auth_b varsa iki-hesap confirmed, yoksa tek-hesap
                # probable. Best-effort; crawl endpoint üretir üretmez çalışır (new_ev'e bağlı
                # DEĞİL — IDOR kanıtı bir 'bulgu' değil aktif diferansiyeldir).
                await act("🔑 IDOR/BOLA diferansiyel probu — nesne referansı taraması")
                try:
                    await self._probe_idor(session, engine, narrate)
                except Exception as _ie:
                    logger.info(f"IDOR probu atlandı (best-effort, scan={session.scan_id}): {_ie}")
                # T2-A2: PATH-bazlı DİKEY yetki yükseltme (FAC matrisi) — IDOR'un nesne
                # diferansiyelini tamamlar: A token'ı ↔ ayrıcalıklı uçlar + yöntem aşınması.
                # A kimliği şart (anon vaka path_probe kapsamı); recon'da çalışmaz.
                await act("🔐 FAC matris probu — dikey yetki sıçraması")
                try:
                    await self._probe_fac_matrix(session, engine, narrate)
                except Exception as _fme:
                    logger.info(f"FAC matris probu atlandı (best-effort, scan={session.scan_id}): {_fme}")
                # T2-B: proaktif CORS + JWT doğrulaması (önceki bulgu gerekmez; JWT offline).
                await act("🌐 CORS/JWT web-misconfig probu")
                try:
                    await self._probe_web_misconfig(session, engine, narrate)
                except Exception as _we:
                    logger.info(f"Web-misconfig probu atlandı (best-effort, scan={session.scan_id}): {_we}")
                # T3-B: exploit ZİNCİRİ icrası (kırılan JWT sırrı → forge → korumalı erişim).
                # _probe_web_misconfig'ten SONRA (artifact'lar oluşsun); best-effort, korumalı.
                await act("⛓️ Exploit zinciri icrası — kırılan doğrulayıcı takibi")
                try:
                    await self._execute_chains(session, engine, narrate)
                except Exception as _ce:
                    logger.info(f"Exploit zinciri atlandı (best-effort, scan={session.scan_id}): {_ce}")
                # APT KOMBİNASYON KENARLARI: tüm prob/zincir taşları masada iken, tek başına
                # düşük CONFIRMED bulguları BİRLEŞTİRİP yüksek-etki kombinasyon türet (user-enum+
                # xmlrpc=brute-force; enum+IDOR=kitlesel sızıntı). Yeni istek YOK — var olan kanıtı
                # ilişkilendirir. En SONDA çalışır (IDOR/misconfig/chain kanıtları da girsin).
                await act("🧩 Bulgu kombinasyon sentezi — zincirleme etki analizi")
                try:
                    await self._synthesize_combinations(session, engine, narrate)
                except Exception as _cbe:
                    logger.info(f"Kombinasyon sentezi atlandı (best-effort, scan={session.scan_id}): {_cbe}")

                # WAPPALYZER PARMAK İZİ (tek-atış): web yüzeyi bilinir bilinmez teknoloji
                # kimliğini üret → root.meta['technologies']'e MERGE olur, SONRAKİ turların
                # appraise + cpe_intel (CPE→KEV/CVE) kararlarını besler. Guard bir kez çalışmasını
                # garanti eder; finalize'daki çağrı yalnız güvenlik ağı (buraya hiç gelinmezse).
                await act("🏷️ Teknoloji parmak izi (Wappalyzer) — ürün kimliği öğreniliyor")
                try:
                    await self._enrich_fingerprint(session, engine, narrate)
                except Exception as _fpe:
                    logger.debug(f"Parmak izi (döngü-içi) atlandı (best-effort, scan={session.scan_id}): {_fpe}")

                # BANKACILIK & FINTECH: Eşzamanlılık / Race Condition (CWE-362) probu
                await act("🏎️ Race-condition probu (CWE-362)")
                try:
                    await self._probe_race_condition(session, engine, narrate)
                except Exception as _rce:
                    logger.info(f"Race condition probu atlandı (best-effort, scan={session.scan_id}): {_rce}")

                # OAST CALLBACK DİNLEYİCİSİ: Asenkron kuyruklardan dönen callback'ler
                try:
                    await self._poll_oast_callbacks(session, engine, narrate)
                except Exception as _oaste:
                    logger.info(f"OAST callback yoklaması atlandı (best-effort, scan={session.scan_id}): {_oaste}")

                # KRİTİK (K8 — SESSİZ HATA GÖRÜNÜRLÜĞÜ): tool failed/timeout olduysa bunu
                # sadece "📊 tool → failed" satırının arkasına gömmek yerine AÇIK bir
                # WARNING olayı yayınla. Tool servisi kapalıysa (K7), her çağrıda burası
                # tetiklenir ve kullanıcı "tarama boş" yerine "nmap-service çalışmıyor"
                # mesajını tekrar tekrar görür → sessiz hatayı gürültüye çevir.
                if result.status in ("failed", "timeout") and result.error:
                    await ScanEventBus.publish(ScanEvent(
                        scan_id=session.scan_id,
                        event_type=ScanEventType.WARNING,
                        source=stage.tool,
                        data={
                            "tool": stage.tool,
                            "status": result.status,
                            "error": result.error,
                            "message": (
                                f"❌ {stage.tool.upper()} {result.status} — {result.error}"
                                + (" (servis kapalı olabilir; docker compose up -d "
                                   f"{self._COMPOSE_SERVICE_NAMES.get(stage.tool, stage.tool)} "
                                   "ile başlatın)." if stage.tool in self._COMPOSE_SERVICE_NAMES else "")
                            ),
                        },
                    ))

            await act("🧾 Kapanış — parmak izi, CVE istihbaratı ve varlık deltası hazırlanıyor")
            # ---- Döngü bitti: özet + kanıt kaydı ----
            # Kapanış güvencesi: döngü bittiğinde stages içinde running kalanları tamamla (UI'da spinner asılı kalmasın)
            for st_name, st_info in session.stages.items():
                if isinstance(st_info, dict) and st_info.get("status") == "running":
                    st_info["status"] = "completed"
            self._update_session(session)
            # FAQ 1.2(c): son-tur sürüm-CVE triage etiketi — tüm nuclei sonuçları masada iken
            # unconfirmed kalan inference CVE'lerine "template ateşlemedi → yamalı olabilir"
            # gerekçesini verification_detail'a yaz (best-effort, I/O yok).
            try:
                await self._annotate_cve_unconfirmed_triage(engine, narrate)
            except Exception as _cve_triage_e:
                logger.debug(f"CVE triage atlandı (best-effort, scan={session.scan_id}): {_cve_triage_e}")
            summary = engine.summary()
            # §2.6: Aşama sağlığı özeti — kaç aşama düştü, hangileri (operatör görünürlüğü).
            summary["stage_health"] = summarize_degraded(degraded_stages, total_stages=len(session.stages))
            # Kapanış anlatısı: motor NEDEN durdu, ne denedi, sırada ne vardı? (şeffaflık)
            summary["closing_narrative"] = self._build_closing_narrative(
                engine, stop_reason, last_reasoning
            )
            # BUG BOUNTY KAPSAM SKORU (P0-A/P1-B kapanış kriterleri):
            # "Bakılacak yer kalmadı" hissini ölçülebilir yüze çevirir. Checklist'in
            # durumunu ağırlıklı puanla hesaplar; 100 = tam kapsam (her kaynak denendi).
            summary["coverage"] = _compute_coverage(engine, session)
            # KAPSAMA SÖZLEŞMESİ (A1): recon süreç-skoru olan 'coverage'dan AYRI — her
            # taban-TESPİT-sınıfı için bulundu/temiz/kontrol-edilemedi+NEDEN üretir. Amaç:
            # whack-a-mole sessiz düşüşünün panzehiri (JS kaçtı/K8s kapısı kapalı/resilience
            # toggle'ı kapalı → artık GÖRÜNÜR). UI (B) ve benchmark (E) bunun üstüne oturur.
            # Best-effort + degrade-safe: hata olsa bile özet üretilir.
            try:
                from .coverage_contract import build_coverage as _build_cov
                summary["coverage_contract"] = _build_cov(_build_coverage_state(engine, session))
            except Exception as _cc_e:
                logger.debug(f"Kapsama sözleşmesi atlandı (best-effort, scan={session.scan_id}): {_cc_e}")
            # WAPPALYZER PARMAK İZİ: web yüzeyini güncel imza setiyle tanımla (kimlik omurgası
            # + UI modalı). asset_diff'ten ÖNCE — teknoloji kimliği snapshot'a da girsin.
            try:
                await self._enrich_fingerprint(session, engine, narrate)
            except Exception as _fp_e:
                logger.debug(f"Parmak izi zenginleştirme atlandı (best-effort, scan={session.scan_id}): {_fp_e}")

            # CVE İSTİHBARATI (vulnx/PDCP): EPSS+KEV+PoC+nuclei-template. Rate-limit görünür.
            try:
                await self._enrich_cve_intel(session, engine, narrate)
            except Exception as _cvi_e:
                logger.debug(f"CVE istihbaratı atlandı (best-effort, scan={session.scan_id}): {_cvi_e}")

            # PORT & SERVİS VARLIK DELTA RADARI: Önceki taramayla diff çıkar ve kaydet
            try:
                await self._record_asset_diff(session, engine, dispatcher, narrate)
            except Exception as _ad_e:
                logger.debug(f"Varlık delta radarı atlandı (best-effort, scan={session.scan_id}): {_ad_e}")

            # Son OAST yoklaması (asenkron geciken callback'ler)
            try:
                await self._poll_oast_callbacks(session, engine, narrate)
            except Exception as _oast_fin_e:
                logger.debug(f"Son OAST yoklaması atlandı: {_oast_fin_e}")

            if hasattr(engine, "oast_client") and engine.oast_client:
                summary["oast"] = engine.oast_client.summary()
            if hasattr(engine, "stealth_controller") and engine.stealth_controller:
                summary["stealth"] = engine.stealth_controller.summary()
            if session.ai_analysis and "asset_diff" in session.ai_analysis:
                summary["asset_diff"] = session.ai_analysis["asset_diff"]
            if session.ai_analysis and "fingerprint" in session.ai_analysis:
                summary["fingerprint"] = session.ai_analysis["fingerprint"]
            if session.ai_analysis and "cve_intel" in session.ai_analysis:
                summary["cve_intel"] = session.ai_analysis["cve_intel"]

            session.completed_at = datetime.utcnow().isoformat()
            session.total_duration_seconds = (datetime.utcnow() - run_start).total_seconds()
            # İptalle çıktıysak durumu 'completed'a EZME — cancel_pipeline zaten 'cancelled'
            # yazdı; kullanıcının iptali korunur. Aynı şekilde tam-servis-felaketinde
            # 'failed' kalır — 'completed' görünümlü boş tarama (dürüstlük açığı) olmaz.
            if not engine.cancelled and not svc_all_down:
                session.status = "completed"
            if session.ai_analysis is None:
                session.ai_analysis = {}
            session.ai_analysis.update(summary)
            self._update_session(session)

            # Kanıtlanmış zafiyetleri vulnerabilities collection'a yaz
            self._save_autonomous_evidence(session.scan_id, session.target, engine.graph.evidence)

            await emit_scan_completed(session.scan_id, summary)
            logger.info(
                f"Autonomous scan done: {session.scan_id} | steps={summary['steps_taken']} "
                f"| vulns={summary['vulnerability_count']} | success={summary['success']}"
            )

            # Nihai AI rapor motorunu tetikle (mevcut sistem)
            asyncio.create_task(self._trigger_autonomous_report(session, engine.graph.evidence, summary))

        except Exception as e:
            logger.error(f"Autonomous scan error: {session.scan_id} -> {e}")
            # İptal sonrası motor bir istisna atarsa 'cancelled'ı 'failed'e EZME.
            if not engine.cancelled:
                session.status = "failed"
                session.error = str(e)
            session.completed_at = datetime.utcnow().isoformat()
            self._update_session(session)
            await emit_scan_failed(session.scan_id, str(e))
        finally:
            self._active_pipelines.pop(session.session_id, None)
            self._running_engines.pop(session.session_id, None)

    # ---------- Co-hosted (scope) onay köprüsü — UI modeli için ----------
    def get_cohosted_candidates(self, session_id: str) -> Optional[List[Dict[str, Any]]]:
        """Çalışan otonom taramanın keşfettiği co-hosted host'ları + onay durumunu döner.
        Engine artık çalışmıyorsa None."""
        engine = self._running_engines.get(session_id)
        if engine is None:
            return None
        return engine.cohosted_candidates()

    def approve_cohosted(self, session_id: str, node_ids: List[str]) -> Optional[int]:
        """Kullanıcının UI'da işaretlediği co-hosted host'ları tarama iznine ekler.
        Döner: yeni onaylanan host sayısı; engine yoksa None."""
        engine = self._running_engines.get(session_id)
        if engine is None:
            return None
        return engine.approve_cohosted_targets(node_ids)

    def retry_appraisal(self, session_id: str) -> Optional[bool]:
        """Kullanıcı-tetiklemeli 'LLM'e yeniden danış'. LLM cevabı parse edilemediğinde UI
        bir düğme gösterir; operatör tıklayınca motor bir sonraki turda force_retry ile
        (ekstra repair denemesiyle) tekrar danışır. Döner: tetik kabul edildi mi; engine
        artık çalışmıyorsa None."""
        engine = self._running_engines.get(session_id)
        if engine is None:
            return None
        return engine.request_reappraisal()

    def _get_artifacts_collection(self):
        if self.db is not None:
            return self.db["scan_artifacts"]
        return None

    def _get_llm_logs_collection(self):
        if self.db is not None:
            return self.db["scan_llm_logs"]
        return None

    # LLM prompt/cevap tek doküman sınırı — panelde okunabilir kalsın, DB'yi şişirmesin.
    _MAX_LLM_LOG_CHARS = 16_000

    def _save_llm_log(self, scan_id: str, message: str, data: Dict[str, Any]) -> Optional[str]:
        """
        Türkçe: Otonom motorun bir kuşatma turunda LLM istihbarat subayına SORDUĞU prompt +
        aldığı HAM cevabı kalıcı yazar (şeffaflık / hata ayıklama). "LLM'e ne sordu, ne
        cevap geldi?" sorusunun kalıcı kaynağı. Admin log paneli buradan okur.
        agent_timeline'a GİRMEZ — ayrı koleksiyon, ağır alanları oradan uzak tutar.
        Döner: log_id veya None (DB yoksa).
        """
        coll = self._get_llm_logs_collection()
        if coll is None:
            return None
        step = data.get("step", 0)
        log_id = f"{scan_id}:{step}"

        def _clip(v: Any) -> Any:
            if isinstance(v, str) and len(v) > self._MAX_LLM_LOG_CHARS:
                return v[: self._MAX_LLM_LOG_CHARS] + "\n…[kırpıldı]"
            return v

        try:
            coll.update_one(
                {"log_id": log_id},
                {"$set": {
                    "log_id": log_id,
                    "scan_id": scan_id,
                    "step": step,
                    "message": message,
                    "provider": data.get("provider"),
                    "model": data.get("model"),
                    "system_prompt": _clip(data.get("system_prompt", "")),
                    "prompt": _clip(data.get("prompt", "")),
                    "raw_response": _clip(data.get("raw_response", "")),
                    "parsed_ok": bool(data.get("parsed_ok", False)),
                    "duration_ms": data.get("duration_ms"),
                    "healthy": data.get("healthy"),
                    "created_at": datetime.utcnow().isoformat(),
                }},
                upsert=True,
            )
            return log_id
        except Exception as e:
            logger.warning(f"LLM log save error ({log_id}): {e}")
            return None

    def get_scan_llm_logs(self, scan_id: str) -> List[Dict[str, Any]]:
        """Türkçe: Bir taramanın tüm LLM alışverişlerini (soru + ham cevap) sıralı döndür.
        Admin log paneli bunu okur."""
        coll = self._get_llm_logs_collection()
        if coll is None:
            return []
        try:
            cursor = coll.find({"scan_id": scan_id}, {"_id": 0}).sort("step", 1)
            return list(cursor)
        except Exception as e:
            logger.warning(f"LLM log fetch error ({scan_id}): {e}")
            return []

    def _save_scan_artifact(
        self, scan_id: str, step: int, stage: StageDefinition,
        result: StageResult, summary: Dict[str, Any],
    ) -> Optional[str]:
        """
        Türkçe: Bir adımın HAM sonucunu + UI özetini scan_artifacts collection'a yazar.
        "Recon taradı — ne çıktı?" sorusunun kalıcı cevabı. Frontend modalı buradan okur.
        Döner: artifact_id (frontend modal fetch için) veya None.
        """
        coll = self._get_artifacts_collection()
        if coll is None:
            return None
        artifact_id = f"{scan_id}:{step}:{stage.tool}"
        try:
            coll.update_one(
                {"artifact_id": artifact_id},
                {"$set": {
                    "artifact_id": artifact_id,
                    "scan_id": scan_id,
                    "step": step,
                    "stage_name": stage.name,
                    "tool": stage.tool,
                    "status": result.status,
                    "options": dict(stage.options),
                    "summary": summary,
                    # Ham veri MongoDB doküman limitine (16MB) takılmasın diye kırpılır.
                    "raw_data": self._truncate_for_mongo(result.data or {}),
                    "error": result.error,
                    "duration_seconds": result.duration_seconds,
                    "created_at": datetime.utcnow().isoformat(),
                }},
                upsert=True,
            )
            return artifact_id
        except Exception as e:
            logger.warning(f"Artifact save error ({artifact_id}): {e}")
            return None

    # BSON hard limit 16MB; güvenli marjla altında kalmak için eşik.
    _MAX_ARTIFACT_BYTES = 8_000_000

    @classmethod
    def _truncate_for_mongo(cls, data: Dict[str, Any], max_list: int = 200) -> Dict[str, Any]:
        """
        Ham tool çıktısını MongoDB 16MB doküman limitine takılmadan saklanabilir hale getirir.
        1) Uzun top-level listeleri max_list'e kırpar (eleman sayısı koruması).
        2) Buna rağmen serileşmiş boyut eşiği aşarsa (tek eleman/iç içe yapı devse) ham veriyi
           tümden düşürüp bir işaret bırakır — böylece update_one BSONObjectTooLarge ile patlayıp
           artifact'i sessizce kaybetmez.
        """
        out: Dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, list) and len(v) > max_list:
                out[k] = v[:max_list]
                out[f"{k}__truncated"] = len(v)
            else:
                out[k] = v

        # Boyut koruması: kırpma sonrası hâlâ çok büyükse ham veriyi düşür.
        try:
            approx_bytes = len(json.dumps(out, default=str, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            approx_bytes = 0  # serileşemiyorsa boyut ölçülemez; aşağıda bırakılır
        if approx_bytes > cls._MAX_ARTIFACT_BYTES:
            return {
                "_dropped": True,
                "_reason": f"raw_data {approx_bytes} bayt > {cls._MAX_ARTIFACT_BYTES} bayt eşiği — "
                           f"MongoDB limiti için düşürüldü. Özet için summary alanına bakın.",
                "_keys": list(data.keys())[:50],
            }
        return out

    def get_scan_artifacts(self, scan_id: str) -> List[Dict[str, Any]]:
        """Türkçe: Bir taramanın tüm adım sonuçlarını (özet + ham) döndür (frontend modal)."""
        coll = self._get_artifacts_collection()
        if coll is None:
            return []
        try:
            cursor = coll.find({"scan_id": scan_id}, {"_id": 0}).sort("step", 1)
            return list(cursor)
        except Exception as e:
            logger.warning(f"Artifact fetch error ({scan_id}): {e}")
            return []

    def get_scan_artifact(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        """Türkçe: Tek bir adımın sonucunu (ham dahil) döndür."""
        coll = self._get_artifacts_collection()
        if coll is None:
            return None
        try:
            return coll.find_one({"artifact_id": artifact_id}, {"_id": 0})
        except Exception as e:
            logger.warning(f"Artifact fetch error ({artifact_id}): {e}")
            return None

    @staticmethod
    def _build_closing_narrative(engine, stop_reason: str, last_reasoning: str) -> Dict[str, Any]:
        """
        Türkçe: Tarama bitince motorun 'kapanış anlatısı'nı üret — NEDEN durdu, NE denedi,
        sırada NE vardı. Kullanıcının 'motor ne düşündü, neye takıldı' sorusuna cevap.
        """
        graph = engine.graph
        # Çalıştırılan araçlar (executed kenarlardan)
        tried_tools: Dict[str, int] = {}
        for e in graph.edges.values():
            if getattr(e, "tried_count", 0) > 0:
                tried_tools[e.tool] = tried_tools.get(e.tool, 0) + 1
        # Değerlendirilmiş ama denenmemiş (açık) kenarlar — 'sıradaki mantıklı hamleler'
        next_moves = []
        try:
            for e in graph.edges.values():
                if e.state == "open" and getattr(e, "tried_count", 0) == 0:
                    next_moves.append({
                        "tool": e.tool, "target": e.to_id,
                        "rationale": getattr(e, "rationale", "") or "",
                    })
        except Exception:
            pass
        next_moves = next_moves[:8]

        reason_text = {
            "budget": "Adım/süre bütçesi doldu — motor daha fazla ilerleyemedi.",
            "decision": "Motor deneyecek mantıklı (eşik üstü) bir hamle kalmadığına karar verdi.",
            "no_tool": "Seçilebilecek geçerli bir araç kalmadı (graf tükendi).",
            "target_unreachable": "Hedef yanıt vermiyor (nmap host DOWN) — tarama erken kesildi; "
                                  "bulgu yokluğu 'temiz' anlamına GELMEZ.",
            "all_services_down": "Tüm tarayıcı mikroservisleri kapalı — aktif tarama yapılamadı; "
                                 "sonuçlar güvenilmez (boş tarama).",
        }.get(stop_reason, "Tarama tamamlandı.")

        return {
            "stop_reason": stop_reason,
            "stop_reason_text": reason_text,
            "last_reasoning": last_reasoning,
            "steps_taken": engine.step,
            "tools_used": tried_tools,
            "evidence_count": len(graph.evidence),
            "next_moves": next_moves,          # denenmemiş, sırada bekleyen hamleler
            "notes_tail": graph.notes[-8:],     # son ipuçları/anomaliler
        }

    def _save_autonomous_evidence(self, scan_id: str, target: str, evidence: List[Any]):
        """Türkçe: Otonom motorun kanıtladığı zafiyetleri DB'ye yaz."""
        try:
            coll = self._get_vulnerabilities_collection()
            if coll is None or not evidence:
                return
            docs = []
            for ev in evidence:
                d = ev.to_dict()
                d.update({"scan_id": scan_id, "target": target,
                          "source": "autonomous", "pipeline_version": "autonomous",
                          "created_at": datetime.utcnow().isoformat(),
                          "discovered_at": datetime.utcnow()})
                docs.append(d)
            if docs:
                coll.insert_many(docs)
                # VEKTÖR HAFIZA: bulguları embedding olarak da sakla → gelecek
                # taramalarda SEMANTİK recall (gecmis_dersleri_hatirla) bunları bulur.
                # Best-effort: flag kapalı/Qdrant yoksa 0 döner, Mongo kaydı etkilenmez.
                try:
                    from .memory_store import bulgulari_hafizaya_yaz
                    _yazilan = bulgulari_hafizaya_yaz(scan_id, target, docs)
                    if _yazilan:
                        logger.info(f"🧠 Vektör hafıza: {_yazilan} bulgu embedding'lendi.")
                except Exception as _vh_e:
                    logger.debug(f"Vektör hafıza yazımı atlandı: {_vh_e}")
        except Exception as e:
            logger.warning(f"Autonomous evidence save error: {e}")

    async def _adaptive_reverify(self, session: PipelineSession, engine, ev, klass: str, client):
        """T3-A: statik/mutasyon doğrulaması başarısız olan enjekte-edilebilir bir bulgu için
        LLM'den hedefe/WAF'a ÖZGÜ payload iste, verify_adaptive ile AYNI deterministik imza
        üstünden yeniden doğrula. Döner: Verdict (verified=True ise kanıt) ya da None.

        DOKTRIN: LLM zanaatlar, çekirdek onaylar. LLM erişilemez/payload üretmezse None →
        çağıran normal FP işaretlemesine düşer (sıfır regresyon). Gate: ADAPTIVE_PAYLOADS=1,
        recon'da değil, sınıf adaptif-destekli, query-param'lı URL, tarama başına
        ADAPTIVE_PAYLOADS_MAX (varsayılan 5) — LLM maliyeti/dokunuş bütçeli."""
        if os.getenv("ADAPTIVE_PAYLOADS", "1") != "1":
            return None
        if klass not in ("sqli", "xss", "lfi", "ssti"):
            return None
        url = getattr(ev, "target", "") or ""
        if "?" not in url or "=" not in url.split("?", 1)[1]:
            return None  # query param yok → query-hattı adaptif işe yaramaz
        if not hasattr(self, "_adaptive_count"):
            self._adaptive_count: Dict[str, int] = {}
        used = self._adaptive_count.get(session.scan_id, 0)
        if used >= int(os.getenv("ADAPTIVE_PAYLOADS_MAX", "5")):
            return None
        try:
            from .adaptive_payloads import build_probe_context, craft_payloads
            from .verification import verify_adaptive, build_injected_urls
        except Exception:
            return None
        try:  # T4-A: offline corpus — örnekler LLM bağlamına, boş üretimde fallback olarak
            from .payload_corpus import examples_for as _corpus_examples
            from .payload_corpus import retry_payloads as _corpus_retry
        except Exception:
            def _corpus_examples(klass, n=5):
                return []

            def _corpus_retry(klass):
                return []

        # CANLI bağlam: baseline + canary (WAF davranışı). Best-effort — snippet'ler LLM'e.
        baseline_txt, blocked_txt, status_b, status_c, framework = "", "", None, None, None
        try:
            rb = await client.get(url)
            baseline_txt = (rb.text or "")[:1500]
            status_b = rb.status_code
            framework = rb.headers.get("server") or rb.headers.get("x-powered-by")
        except Exception:
            pass
        canary = {"sqli": "' OR SLEEP(1)-- -", "xss": "<script>alert(1)</script>",
                  "lfi": "../../../../etc/passwd", "ssti": "{{7*7}}"}.get(klass, "'")
        try:
            cs = build_injected_urls(url, canary)
            if cs:
                rc = await client.get(cs[0])
                blocked_txt = (rc.text or "")[:1500]
                status_c = rc.status_code
        except Exception:
            pass
        waf = None
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is not None:
            wf = root.meta.get("waf")
            waf = wf.get("vendor") if isinstance(wf, dict) else (wf if isinstance(wf, str) else None)

        ctx = build_probe_context(vuln_class=klass, url=url, param=None, method="get",
                                  baseline=baseline_txt, blocked=blocked_txt,
                                  status_baseline=status_b, status_blocked=status_c,
                                  waf=waf, framework=framework,
                                  corpus_examples=_corpus_examples(klass, 5))
        payloads = await craft_payloads(ctx)
        kaynak = "🧠 LLM"
        if not payloads:
            # T4-A: LLM boş/erişilemez → offline PATT corpus'u AYNI deterministik imza
            # hattından dene (verify_adaptive onaylar; LLM zanaatlar/çekirdek onaylar
            # doktrinine yapısal olarak uygun — payload yine yalnız ADAY).
            payloads = _corpus_retry(klass)
            kaynak = "📚 Corpus"
        if not payloads:
            return None
        # Bütçe payload GERÇEKTEN üretilince tüketilir (LLM ya da corpus — ikisi de
        # ek istek maliyeti; boş deneme sayılmaz).
        self._adaptive_count[session.scan_id] = used + 1
        await ScanEventBus.publish(ScanEvent(
            scan_id=session.scan_id,
            event_type=ScanEventType.PROGRESS_UPDATE,
            data={"type": "adaptive_payloads", "vuln_class": klass, "target": url,
                  "count": len(payloads),
                  "message": f"{kaynak} {len(payloads)} {klass} payload'u deniyor "
                             f"— deterministik imzayla test ediliyor: {url}"},
        ))
        try:
            return await verify_adaptive(url, None, klass, payloads, client)
        except Exception as e:
            logger.debug(f"verify_adaptive hatası: {e}")
            return None

    async def _verify_new_evidence(self, session: PipelineSession, engine, new_count: int, narrate):
        """PoC DOĞRULAMA (Pillar #1): yeni bulguları AKTİF teyit eder. Amaç: nuclei "template
        eşleşti" tahminini bağımsız bir yöntemle KANITLAMAK → false-positive elenir, bulgu
        `verified` + `confidence_tier` damgalanır.

        FALSE-POSITIVE (kapsam genişletmesi): eskiden yalnız SQLi adayları teyit ediliyordu;
        artık deterministik doğrulayıcısı OLAN her sınıf (sqli/xss/lfi/ssti/open_redirect)
        classify_evidence_class ile eşlenip verify_hypothesis'ten geçer. Böylece nuclei'nin
        ürettiği bu sınıflardaki 'critical' bulgular ya CONFIRMED'e yükselir ya da
        'unconfirmed' (test edilip teyit edilemedi → olası FP) kalır — manşet kritik sayısını
        şişirmez. Doğrulayıcısı olmayan sınıflar (RCE/SSRF/IDOR) unconfirmed kalır (dokunulmaz).

        Güvenlik/kapılar (doktrin: davetsiz agresiflikten kaçın):
        - `POC_VERIFY_ENABLED=false` → tamamen kapalı.
        - `recon` seviyesinde çalışmaz (saf keşifte aktif enjeksiyon yapma).
        - Tarama başına `POC_VERIFY_MAX` (varsayılan 15) doğrulama ile sınırlı (maliyet/dokunuş).
        Best-effort: doğrulama motoru çökse bile tarama DÜŞMEZ (kural: LLM/araç kral değil)."""
        if os.getenv("POC_VERIFY_ENABLED", "true").lower() != "true":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        cap = int(os.getenv("POC_VERIFY_MAX", "15"))
        attempted = sum(1 for e in engine.graph.evidence if getattr(e, "verified", None) is not None)
        if attempted >= cap:
            return
        recent = engine.graph.evidence[-new_count:]
        # (kanıt, sınıf) — yalnız doğrulayıcısı olan sınıflar; verified henüz yoksa.
        candidates: List[tuple] = []
        for e in recent:
            if getattr(e, "verified", None) is not None:
                continue
            klass = classify_evidence_class(e.to_dict())
            if klass:
                candidates.append((e, klass))
        if not candidates:
            return
        # FAQ 1.4: POC_VERIFY_MAX bütçesini BULGU ÖNCELİĞİNE göre dağıt — kap dolduğunda
        # kritik/high (manşet yalanını öldürür) medium'dan ÖNCE doğrulanmış olsun. Aynı şiddet
        # içinde SQLi önceliklidir (blind-only doğrulayıcı; sessizce kaybolmasın).
        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        candidates.sort(key=lambda c: (
            _sev_rank.get(getattr(c[0], "severity", "").lower(), 9),
            0 if c[1] == "sqli" else 1,
        ))
        from types import SimpleNamespace
        try:
            timeout = float(os.getenv("POC_VERIFY_HTTP_TIMEOUT", "20"))
            # verify=False BİLİNÇLİ: pentest hedefleri sık sık self-signed/expired sertifika
            # kullanır; TLS doğrulaması açık olsa bu hedefler HİÇ test edilemezdi (path_probe/
            # origin_discovery/redteam_proxy ile aynı konvansiyon). Kapatmak istersen:
            # POC_VERIFY_TLS=true.
            verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=verify_tls) as client:
                for ev, klass in candidates:
                    if attempted >= cap:
                        break
                    attempted += 1
                    # Duck-typed hipotez: verify_hypothesis url/vuln_class/param/method/... okur.
                    hyp = SimpleNamespace(url=ev.target, vuln_class=klass, param=None,
                                          method="get", body_params=None, body_kind="form",
                                          rationale="")
                    verdict = await verify_hypothesis(hyp, client)
                    detail = getattr(verdict, "detail", "") or ""
                    # FAQ 1.6: "test EDİLEMEDİ" YAPISAL sinyal — verifier skripped=True verdi
                    # (parametre yok / doğrulayıcı yok). verified'ı False'a çekme (tried-and-
                    # failed değil); None bırak → tier unconfirmed kalır. Substring fallback
                    # eski/manuel verdict'ler için tutulur (verifiğin wording'i değişse de
                    # yapısal alanını OMATIKOL): tried-failed ↔ untestable dönmesin.
                    skipped = bool(getattr(verdict, "skipped", False)) or \
                        ("atlandı" in detail) or ("kurulamadı" in detail)
                    if verdict.verified:
                        ev.verified = True
                        ev.verification_method = verdict.method
                        ev.verification_detail = detail
                        ev.verification_confidence = getattr(verdict, "confidence", None)
                        await narrate(
                            ScanEventType.CRITICAL_FINDING,
                            f"✅ KANITLANDI (PoC): {ev.title} — {detail}",
                            {"title": ev.title, "target": ev.target, "severity": ev.severity,
                             "verified": True, "method": verdict.method, "vuln_class": klass,
                             "confidence": getattr(verdict, "confidence", None),
                             "confidence_tier": "confirmed"},
                        )
                    elif not skipped:
                        # T3-A: deterministik statik/mutasyon başarısız AMA denendi (param var →
                        # enjekte-edilebilir). LLM'den hedefe/WAF'a ÖZGÜ payload iste, AYNI
                        # deterministik imzayla yeniden dene. LLM zanaatlar, çekirdek onaylar;
                        # LLM yoksa/payload üretmezse → None → aşağıda normal FP işaretlemesi.
                        adaptive = await self._adaptive_reverify(session, engine, ev, klass, client)
                        if adaptive is not None and adaptive.verified:
                            ev.verified = True
                            ev.verification_method = adaptive.method
                            ev.verification_detail = adaptive.detail
                            ev.verification_confidence = getattr(adaptive, "confidence", None)
                            await narrate(
                                ScanEventType.CRITICAL_FINDING,
                                f"✅ KANITLANDI (LLM-adaptif PoC): {ev.title} — {adaptive.detail}",
                                {"title": ev.title, "target": ev.target, "severity": ev.severity,
                                 "verified": True, "method": adaptive.method, "vuln_class": klass,
                                 "confidence": getattr(adaptive, "confidence", None),
                                 "confidence_tier": "confirmed"},
                            )
                        else:
                            ev.verified = False  # denendi, teyit edilemedi → olası false-positive
                            ev.verification_method = verdict.method
                            ev.verification_detail = detail
                            ev.verification_confidence = getattr(verdict, "confidence", None)
                            await narrate(
                                ScanEventType.AGENT_OBSERVATION,
                                f"⚠️ Doğrulanamadı (olası false-positive): {ev.title}",
                                {"title": ev.title, "target": ev.target, "verified": False,
                                 "vuln_class": klass, "method": verdict.method,
                                 "confidence_tier": "unconfirmed"},
                                persist_data={},
                            )
                    # skipped → dokunma; kanıt unconfirmed olarak kalır (test edilemedi).
        except Exception as e:
            logger.warning(f"PoC doğrulama atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _annotate_catchall_findings(self, session: PipelineSession, engine,
                                          new_count: int, narrate):
        """FALSE-POSITIVE (P2): host catch-all mı? Var-olmayan rastgele yollara 2xx dönen
        sunucuda 'ifşa/varlık' türü bulgular (bir şey 'bulundu') şüphelidir — o yol her zaman
        200 döner. Böyle host'lardaki ilgili bulgular deterministik olarak 'unconfirmed'a
        çekilir + fp_reason='catchall_host'. Yalnız DEMOTE; aktif PoC ile kanıtlanmışlara
        (verified=True) ve enjeksiyon/CVE bulgularına DOKUNMAZ.

        Best-effort + host-bazlı önbellek (aynı host bir kez problanır). POC_WAF_DETECT gibi
        FP_CATCHALL_DETECT=0 ile kapatılabilir."""
        if os.getenv("FP_CATCHALL_DETECT", "1") != "1":
            return
        recent = engine.graph.evidence[-new_count:]
        from .fp_signals import (is_catchall_from_samples, random_probe_paths,
                                  looks_like_exposure_finding)
        from urllib.parse import urlsplit
        # Aday: aktif kanıtlanmamış (verified is not True) + ifşa/varlık türü bulgular.
        cands = [e for e in recent
                 if getattr(e, "verified", None) is not True
                 and getattr(e, "fp_reason", None) is None
                 and looks_like_exposure_finding(getattr(e, "title", ""), getattr(e, "cve", "") or "")]
        if not cands:
            return
        if not hasattr(self, "_catchall_cache"):
            self._catchall_cache: Dict[str, bool] = {}
        try:
            verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=verify_tls) as client:
                for ev in cands:
                    tgt = getattr(ev, "target", "") or ""
                    raw = tgt if "://" in tgt else f"http://{tgt}"
                    parts = urlsplit(raw)
                    origin = f"{parts.scheme}://{parts.netloc}"
                    host_key = parts.netloc
                    if not host_key:
                        continue
                    if host_key not in self._catchall_cache:
                        statuses: List[int] = []
                        bodies: List[str] = []
                        for p in random_probe_paths(2):
                            try:
                                r = await client.get(origin + p)
                                statuses.append(r.status_code)
                                bodies.append((r.text or "")[:4000])
                            except Exception:
                                statuses.append(-1)  # ulaşılamadı → catch-all değil say
                        self._catchall_cache[host_key] = is_catchall_from_samples(statuses, bodies)
                    if self._catchall_cache.get(host_key):
                        ev.confidence_tier = "unconfirmed"
                        ev.fp_reason = "catchall_host"
                        await narrate(
                            ScanEventType.AGENT_OBSERVATION,
                            f"🌀 Catch-all host (var-olmayan yola 2xx) — '{ev.title}' bulgusu "
                            f"şüpheli, doğrulanması gerek",
                            {"title": ev.title, "target": ev.target,
                             "fp_reason": "catchall_host", "confidence_tier": "unconfirmed"},
                            persist_data={},
                        )
        except Exception as e:
            logger.warning(f"Catch-all tespiti atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _adjudicate_unconfirmed(self, session: PipelineSession, engine,
                                      new_count: int, narrate):
        """FALSE-POSITIVE (P3): deterministik doğrulayıcısı OLMAYAN unconfirmed bulgular için
        LLM-hakem ('istihbarat subayı') ikincil görüş verir: gerçek mi, false-positive mi?

        DOKTRIN: bu ASLA kademe belirlemez — deterministik katman kraldır. LLM yalnız
        `llm_fp_opinion` anotasyonu ekler (operatör/rapor önceliklendirmesi için). LLM
        erişilemezse sessizce atlanır (tarama düşmez). FP_LLM_ADJUDICATION=0 ile kapatılır.

        Yalnız: unconfirmed + aktif doğrulayıcısı olmayan (classify None) + henüz FP sinyali
        (fp_reason) olmayan + bir miktar kanıtı olan bulgular gönderilir (RCE/SSRF/misconfig
        gibi uzun kuyruk). Böylece deterministik katmanın çözemediği bulgular triyaj edilir."""
        if os.getenv("FP_LLM_ADJUDICATION", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        recent = engine.graph.evidence[-new_count:]
        cands = []
        for e in recent:
            d = e.to_dict()
            if d.get("confidence_tier") != "unconfirmed":
                continue
            if getattr(e, "llm_fp_opinion", None) is not None:
                continue
            if classify_evidence_class(d):
                continue  # deterministik doğrulayıcısı var → LLM'e gerek yok
            # Bir miktar kanıt/bağlam olmalı (boş bulguya LLM yorması anlamsız).
            if not (d.get("proof") or d.get("response") or d.get("request")):
                continue
            cands.append(e)
        if not cands:
            return
        cap = int(os.getenv("FP_LLM_ADJUDICATION_MAX", "8"))
        cands = cands[:cap]
        try:
            payload = {
                "scan_id": session.scan_id,
                "target": session.target,
                "findings": [{
                    "index": i,
                    "title": e.title,
                    "severity": e.severity,
                    "target": e.target,
                    "cve": e.cve,
                    "proof": (e.proof or "")[:800],
                    "response": (e.response or "")[:1200] if e.response else None,
                } for i, e in enumerate(cands)],
            }
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(f"{AI_SERVICE_URL}/brain/adjudicate-fp", json=payload)
                if resp.status_code != 200:
                    logger.info(f"FP-hakem atlandı: ai-service HTTP {resp.status_code}")
                    return
                data = resp.json()
            results = data.get("results") or []
            by_idx = {r.get("index"): r for r in results if isinstance(r, dict)}
            fp_flagged = 0
            for i, e in enumerate(cands):
                r = by_idx.get(i)
                if not isinstance(r, dict):
                    continue
                verdict = str(r.get("verdict") or "uncertain").lower()
                e.llm_fp_opinion = {
                    "verdict": verdict,
                    "confidence": r.get("confidence"),
                    "reason": str(r.get("reason") or "")[:300],
                }
                if verdict == "false_positive":
                    fp_flagged += 1
            if fp_flagged:
                await narrate(
                    ScanEventType.AGENT_OBSERVATION,
                    f"🧠 LLM-hakem: {fp_flagged}/{len(cands)} doğrulanmamış bulgu olası "
                    f"false-positive işaretlendi (ikincil görüş — kademe değişmedi)",
                    {"fp_flagged": fp_flagged, "total": len(cands)},
                    persist_data={},
                )
        except Exception as e:
            logger.info(f"FP-hakem atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _annotate_cve_unconfirmed_triage(self, engine, narrate):
        """FAQ 1.2(c) — SÜRÜM-CVE'NİN NİHAİ TRIAGE ETİKETİ.

        Tarama sonunda hâlâ 'unconfirmed' kalan inference CVE kayıtları (cve_intel/kev_intel)
        için doğrulama yolunu çözümleyip neden'in ne olduğunu verification_detail'a yazar:
          - hedefli nuclei template'i VARDI ama ATEŞLEMEDİ → sürüm büyük olasılıkla yamalı/
            backport'lu (en değerli bilgi — operatör 'kriptik unconfirmed' görmesin);
          - nuclei denemesi HİÇ olmadıysa → zaten oluşturma anında etiketlendi (template yok).
        Best-effort; new_ev'e bağlı DEĞİL — döngünün SONUNDA bir kez koşar (tüm nuclei
        sonuçları masadayken). I/O YOK (yalnız graf içi derleme), kapatma gerekmez."""
        seen = 0
        for ev in list(engine.graph.evidence):
            if str(getattr(ev, "tool", "")) not in ("cve_intel", "kev_intel"):
                continue
            if ev.effective_confidence_tier() != "unconfirmed":
                continue  # birleşti/yükseldi (1.5/1.3) — dokunma
            if getattr(ev, "verification_detail", None):
                continue  # oluşturma anında etiketlendi (template yok / KEV yolu)
            node_id = f"vuln:{ev.cve}"
            node = engine.graph.nodes.get(node_id)
            had_template_edge = False
            if node is not None:
                had_template_edge = any(
                    e.to_id == node_id and e.tool == "nuclei"
                    for e in engine.graph.edges.values())
            ev.verification_detail = (
                "Hedefli nuclei template'i çalıştı ama ATEŞLEMEDİ — sürüm yamalı/backport "
                "uygulanmış olabilir; aktif istismar KANITI yok. Manuel triyaj önerilir"
                if had_template_edge else
                "Nuclei template'i ile doğrulanamadı — sürümden çıkarılmış CVE adayı; "
                "manuel inceleyin.")
            seen += 1
        if seen:
            await narrate(
                ScanEventType.AGENT_OBSERVATION,
                f"🏷️ {seen} sürüm-CVE adayı triaj edildi: hedefli nuclei template'i "
                f"ateşlemedi (sürüm yamalı olabilir) — raporda 'incele' listesinde",
                {"cve_unconfirmed_triaged": seen}, persist_data={},
            )

    async def _probe_discovered_services(self, session: PipelineSession, engine, narrate):
        """APT FAZ 3: keşfedilen mail/DNS servislerine DETERMİNİSTİK, TAHRİBATSIZ derin-dalış.

        SMTP (25/587): STARTTLS var mı (cleartext risk), VRFY/EXPN (user-enum), banner sürüm.
        DNS (53): AXFR zone-transfer açık mı (tüm iç kayıtlar sızar), version.bind.
        Hiçbir mail gönderilmez / kayıt değiştirilmez — yalnız yetenek okuması. Bulgular
        confidence_tier ile eklenir (STARTTLS-yok/AXFR-açık = confirmed, deterministik gözlem).

        Best-effort + node-bazlı dedup (meta['probed']). FP_SERVICE_PROBE=0 kapatır;
        recon seviyesinde çalışmaz (saf keşifte aktif servis yoklaması yapma)."""
        if os.getenv("FP_SERVICE_PROBE", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        from .attack_graph import NodeType, _SERVICE_VALUE_CATEGORY, _canon_url  # noqa: F401
        from .autonomous_engine import Evidence
        # Aday: mail/DNS kategorili, henüz problanmamış, portu olan servis düğümleri
        targets = []
        for n in engine.graph.nodes.values():
            if n.type != NodeType.SERVICE or n.meta.get("probed"):
                continue
            matched = n.meta.get("matched_service") or n.label.split("@")[0]
            cat = _SERVICE_VALUE_CATEGORY.get(matched, "")
            port = n.meta.get("port")
            if cat in ("mail-service", "dns-service") and port:
                targets.append((n, cat, matched, int(port) if str(port).isdigit() else None))
        if not targets:
            return
        host = engine.target
        try:
            from . import service_probes
        except Exception as e:
            logger.debug(f"service_probes yüklenemedi: {e}")
            return
        for node, cat, matched, port in targets:
            node.meta["probed"] = True  # tekrar problama (dedup)
            if port is None:
                continue
            try:
                if cat == "mail-service" and port in (25, 587, 2525):
                    res = await service_probes.probe_smtp(host, port)
                elif cat == "dns-service" and port == 53:
                    res = await service_probes.probe_dns(host, host, port=port)
                else:
                    continue  # TLS-only mail portları (465/993/995) düz probda atlanır
            except Exception as e:
                logger.debug(f"Servis probu hatası ({matched}:{port}): {e}")
                continue
            for f in res.get("findings", []):
                sev = str(f.get("severity") or "info").lower()
                tier = f.get("confidence_tier") or "unconfirmed"
                tgt = f"{host}:{port}"
                fp = f"service_probe|{matched}|{f.get('title','')[:40]}|{tgt}"
                ev = Evidence(
                    title=f.get("title") or f"{matched} bulgusu",
                    severity=sev, cve=None, target=tgt, proof=f.get("proof") or "",
                    tool="service_probe", step=engine.step,
                    mitre=f.get("mitre"), cwe=f.get("cwe") or [],
                    verified=True if tier == "confirmed" else None,
                    verification_method="service-probe" if tier == "confirmed" else None,
                    verification_detail=(f.get("proof") or "")[:200] if tier == "confirmed" else None,
                    confidence_tier=tier,
                )
                if engine.graph.add_evidence(ev, fp) and tier == "confirmed" and sev in ("critical", "high", "medium"):
                    await narrate(
                        ScanEventType.CRITICAL_FINDING,
                        f"🛰️ Servis derin-dalış: {f.get('title')}",
                        {"title": f.get("title"), "target": tgt, "severity": sev,
                         "confidence_tier": tier, "tool": "service_probe"},
                    )

    async def _probe_distro_intel(self, session: PipelineSession, engine, narrate):
        """Madde 4 (T5) — distro-paket zaafiyet matrisi (PASİF istihbarat).

        Banner (product/version/extrainfo) + OS tespitini Ubuntu USN snapshot'ına
        eşler: "Ubuntu 20.04 üzerinde OpenSSH 8.2p1-4ubuntu0.4 — 12 yamanabilir
        CVE, Terrapin düzeltmesi 1:8.2p1-4ubuntu0.10 GERİSİNDE". APT gözü: LTS
        backport evreninde fix sürümü Debian-revision'da yaşar; upstream-CVE
        hattı (NVD) bunu GÖREMEZ. Sıfır ağ isteği — elimizdeki veri konuşur.

        Tier: dpkg sürüm karşılaştırması deterministik ama aktif PoC yok →
        'probable' (revision banner'dan okunabildiyse); revision okunamadıysa
        aday 'unconfirmed'. KEV kesişimi bulguyu rapor manşetine taşır.
        Best-effort; node-bazlı dedup (meta['distro_checked']); DISTRO_INTEL_ENABLED=0
        kapatır; snapshot yoksa linux_distro_intel sessiz [] döner (sıfır regresyon)."""
        if os.getenv("DISTRO_INTEL_ENABLED", "1") != "1":
            return
        if not self._cap_allowed(engine, "linux_distro_intel", default=True):
            return
        from .autonomous_engine import Evidence
        from .attack_graph import NodeType
        try:
            from .linux_distro_intel import analyze_services
        except Exception as e:
            logger.debug(f"linux_distro_intel yüklenemedi: {e}")
            return
        services = []
        for n in engine.graph.nodes.values():
            if n.type != NodeType.SERVICE or n.meta.get("distro_checked"):
                continue
            n.meta["distro_checked"] = True  # dedup: her servis node'u bir kez
            if not n.meta.get("version"):
                continue  # sürümsüz banner'dan patch-level kararı çıkmaz
            services.append({
                "product": n.meta.get("product") or n.meta.get("matched_service") or "",
                "version": n.meta.get("version") or "",
                "extrainfo": n.meta.get("extrainfo") or "",
                "port": n.meta.get("port"),
                "host": self._bare_host(engine.target),
            })
        if not services:
            return
        os_detection = self.discovered_data.get("os_detection")
        findings = analyze_services(services, os_detection)
        for f in findings:
            fp = f"distro_intel|{f.get('pkg')}|{f.get('installed')}|{f.get('target')}"
            apt_groups, techniques = [], []
            if f.get("cve"):
                try:
                    from .attack_graph import _threat_intel_for_cve
                    apt_groups, techniques = _threat_intel_for_cve(f["cve"])
                except Exception:
                    pass
            kev_flag = bool(f.get("kev"))
            ev = Evidence(
                title=f["title"], severity=f["severity"], cve=f.get("cve"),
                target=f["target"], proof=f["proof"], tool="distro_intel",
                step=engine.step,
                mitre=(techniques[0] if techniques else "T1190"),
                attack_techniques=techniques or ["T1190"],
                apt_groups=apt_groups,
                cvss_v3=f.get("cvss_v3"),
                confidence_tier=f["confidence_tier"],
            )
            if not engine.graph.add_evidence(ev, fp):
                continue
            if kev_flag or f["severity"] in ("critical", "high"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING,
                    f"🐧 Distro yama-istihbaratı: {f['title']}"
                    + (" ⚡KEV" if kev_flag else ""),
                    {"title": f["title"], "target": f["target"],
                     "severity": f["severity"], "cve": f.get("cve"),
                     "cve_count": f.get("cve_count"), "kev": kev_flag,
                     "confidence_tier": f["confidence_tier"], "tool": "distro_intel"},
                )

    @staticmethod
    def _bare_host(target: str) -> str:
        """Hedefi çıplak host'a indir: şema/yol/port soyulur. API validator URL'yi KABUL
        edip strip ETMEZ → 'https://host' kalırsa open_connection/httpx sessizce patlar ve
        profil SIFIR sinyalle kurulur (RKE2/Rancher hedefinin 'genel tarama'ya düşme bug'ı).
        IPv6 köşeli parantezi korunur (open_connection [::1] kabul eder)."""
        t = (target or "").strip()
        if "://" in t:
            t = t.split("://", 1)[1]
        t = t.split("/", 1)[0]
        # host:port (IPv6 değilse) → port at
        if t and not t.startswith("[") and t.count(":") == 1:
            t = t.split(":", 1)[0]
        return t

    async def _fetch_profile_signals(self, host: str) -> Dict[str, Any]:
        """IPB: hedefin kök sayfasını BİR KEZ çek → header/çerez/gövde sinyalleri (fingerprint
        için). Tek istek (recon-first, ucuz), best-effort. Şema https→http."""
        from .target_profile import parse_set_cookie_names
        headers: Dict[str, str] = {}
        cookies: List[str] = []
        body = ""
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        try:
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=True,
                                         timeout=10.0) as c:
                for scheme in ("https", "http"):
                    try:
                        r = await c.get(f"{scheme}://{host}/")
                    except Exception:
                        continue
                    headers = {k: v for k, v in r.headers.items()}
                    try:
                        sc = r.headers.get_list("set-cookie")
                    except Exception:
                        scv = r.headers.get("set-cookie")
                        sc = [scv] if scv else []
                    cookies = parse_set_cookie_names(sc)
                    body = (r.text or "")[:65536]
                    break
        except Exception as e:
            logger.debug(f"Profil sinyali alınamadı ({host}): {e}")
        return {"headers": headers, "cookies": cookies, "body": body}

    async def _infra_port_sweep(self, host: str) -> List[int]:
        """IPB: K8s kontrol-düzlemi portlarına HEDEFLİ TCP-connect (nmap top-1000 bunları
        kaçırır → K8s asla tespit edilemezdi). ~11 port, eşzamanlı, kısa timeout —
        ucuz recon. Liste k8s_probe.KUBE_PORTS'tan gelir (TEK doğruluk kaynağı: sweep,
        profil ve derin prob hep aynı port kümesini görür; 9345 RKE2/Rancher dahil).
        Açık olanları döndürür. INFRA_PORT_PROBE=0 kapatır."""
        try:
            from .k8s_probe import KUBE_PORTS
            k8s_ports = sorted(KUBE_PORTS.keys())
        except Exception:
            k8s_ports = [6443, 8443, 10250, 10255, 2379, 2380, 10257, 10259, 4194, 9345, 10256, 16443]

        async def _check(p: int):
            try:
                fut = asyncio.open_connection(host, p)
                reader, writer = await asyncio.wait_for(fut, timeout=3.0)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return p
            except Exception:
                return None

        try:
            res = await asyncio.gather(*[_check(p) for p in k8s_ports], return_exceptions=True)
        except Exception:
            return []
        return [p for p in res if isinstance(p, int)]

    async def _k8s_api_sig_probe(self, host: str, open_ports: List[int]) -> List[tuple]:
        """ZATEN AÇIK aday portlarda (443 / k3s 16443 / NodePort 30000-32767) K8s API imzası ara.
        Kontrol-düzlemi (6443/10250...) firewall arkasında olsa bile K8s, NodePort/dashboard/
        ingress üzerinden dışarı sızabilir; TCP-sweep bunu görmez. Burada yalnız AÇIK portlara
        tahribatsız GET /version (+ registry için /v2/_catalog) atılır, SAF classify_* ile
        doğrulanır → FP-güvenli. Port başına en fazla 2 istek, toplam 12 port tavanı.
        [(port, şema, sürüm|None), ...] döndürür; bulgu yoksa []. K8S_API_SIG_PROBE ile kapanır."""
        try:
            from .k8s_probe import (classify_apiserver, classify_rancher, extract_k8s_version)
        except Exception:
            return []
        cand = sorted({p for p in open_ports
                       if p in (443, 16443) or 30000 <= p <= 32767})[:12]
        if not cand:
            return []
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        out: List[tuple] = []
        try:
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False,
                                         timeout=6.0) as client:
                for p in cand:
                    r = None
                    scheme = None
                    for sch in ("https", "http"):   # önce TLS, olmazsa düz HTTP (tek geçiş yeter)
                        try:
                            r = await client.get(f"{sch}://{host}:{p}/version")
                            scheme = sch
                            break
                        except Exception:
                            r = None
                    if r is None:
                        continue
                    body = (r.text or "")[:16384]
                    cls = classify_apiserver(r.status_code, body)
                    if cls:
                        out.append((p, scheme, cls.get("version") or extract_k8s_version(body)))
                        continue
                    if classify_rancher(r.status_code, body):
                        out.append((p, scheme, None))
                        continue
                    low = body.lower()
                    # kubernetes-dashboard / K8s Status (404 /version ama gövde K8s imzalı)
                    if "kubernetes" in low and ("dashboard" in low or '"kind":"status"' in low):
                        out.append((p, scheme, extract_k8s_version(body)))
                        continue
                    # private registry (K8s cluster içinde sık): yalnız anon /v2/_catalog açıksa
                    if r.headers.get("Docker-Distribution-Api-Version"):
                        try:
                            cat = await client.get(f"{scheme}://{host}:{p}/v2/_catalog")
                            if cat.status_code == 200 and '"repositories"' in (cat.text or ""):
                                out.append((p, scheme, None))
                                continue
                        except Exception:
                            pass
        except Exception as e:
            logger.debug(f"K8s API-imza pası hatası: {e}")
        return out

    def _collect_open_ports(self, engine) -> List[int]:
        """Graf'tan açık portları topla (root.meta['open_ports'] + SERVICE düğüm portları)."""
        from .attack_graph import NodeType
        ports: List[Any] = []
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is not None:
            ports.extend(root.meta.get("open_ports") or [])
        for n in engine.graph.nodes.values():
            if getattr(n, "type", None) == NodeType.SERVICE and getattr(n, "meta", None):
                pv = n.meta.get("port")
                if pv is not None:
                    ports.append(pv)
        out = set()
        for p in ports:
            # open_ports kanonik biçimi DICT'tir ({"port":..}); SERVICE düğümleri ise çıplak
            # int verir. İkisini de int port numarasına indir — dict'leri int() ile eleyip
            # sessizce port kaybetme (eski davranış infra dict'lerini düşürüyordu).
            if isinstance(p, dict):
                p = p.get("port")
            try:
                out.add(int(p))
            except (TypeError, ValueError):
                continue
        return sorted(out)

    @staticmethod
    def _identity_weak(profile, cpe_products) -> bool:
        """Deterministik kimlik (Tier 1 tablo + Tier 2 CPE) ZAYIF mı? → LLM son-çare tetiklenir.
        Zayıf = CPE ürünü yok + web yığını sinyali yok + os/framework/language yok. Bu tam olarak
        'yetersiz sinyal' vakasıdır (RKE2/pfSense/niş appliance) — motorun tıkandığı yer."""
        if cpe_products:
            return False
        try:
            if profile.has_web_signal():
                return False
            return not (profile.value("os") or profile.value("framework")
                        or profile.value("language"))
        except Exception:
            return False

    async def _llm_infer_identity(self, engine, session, sig: Dict[str, Any],
                                  ports: List[int]) -> Tuple[List[Tuple[str, str, float, str]], List[str]]:
        """Tier 3 çekirdeği: ham kanıtı derle → LLM'e sor → kimlik sinyalleri + ürün listesi.
        Best-effort (LLM/parse düşerse boş döner). Operatöre 'LLM kimlik tahmini (doğrulanmadı)'
        olayı yayınlar — tahmin olduğunu AÇIKÇA belirtir (kanıt değil, çerçeve ipucu)."""
        from .llm_identity import (IDENTITY_SYSTEM, build_identity_prompt,
                                   parse_identity, identity_to_signals)
        from .attack_graph import NodeType
        body = sig.get("body") or ""
        title = None
        _m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if _m:
            title = _m.group(1).strip()[:200]
        services: List[str] = []
        for n in engine.graph.nodes.values():
            if getattr(n, "type", None) != NodeType.SERVICE:
                continue
            mt = getattr(n, "meta", None) or {}
            svc = mt.get("service") or mt.get("matched_service") or ""
            prod = f"{mt.get('product') or ''} {mt.get('version') or ''}".strip()
            entry = f"{mt.get('port')}/{svc} {prod}".strip()
            if entry:
                services.append(entry)
        evidence = {
            "title": title,
            "headers": sig.get("headers") or {},
            "cookies": sig.get("cookies") or [],
            "services": services,
            "ports": ports,
            "body_snippet": body[:800],
        }
        # SERT TAVAN: llm_complete kendi httpx timeout'unu taşır, ama sağlayıcı yanıtı
        # damla-damla akıtırsa read-timeout resetlenip aşılabilir. wait_for wall-clock tavanı
        # kimlik çıkarımının otonom döngüyü kritik yolda DONDURMAMASINI garanti eder (doktrin:
        # LLM kritik yol değil). Timeout → sağlayıcı yavaş işaretlenir + kural-profil sürer.
        try:
            raw = await asyncio.wait_for(
                engine.llm_complete(IDENTITY_SYSTEM, build_identity_prompt(evidence),
                                    max_tokens=700),
                timeout=LLM_TASK_TIMEOUT + 5,
            )
        except asyncio.TimeoutError:
            engine._llm_healthy = False
            logger.warning(f"[{session.scan_id[:8]}] LLM kimlik çıkarımı sert timeout — "
                           f"atlandı; kural-tabanlı profil sürüyor.")
            return [], []
        if not raw:
            return [], []
        result = parse_identity(raw)
        if result is None:
            return [], []
        extra, products = identity_to_signals(result)
        if extra or products:
            prod_str = ", ".join(products[:6]) or (result.role or "?")
            try:
                await ScanEventBus.publish(ScanEvent(
                    scan_id=session.scan_id,
                    event_type=ScanEventType.PROGRESS_UPDATE,
                    data={"type": "llm_identity", "target": engine.target,
                          "products": products[:10], "os": result.os, "role": result.role,
                          "why": result.why,
                          "message": (f"🧠 LLM kimlik tahmini (doğrulanmadı): {prod_str}"
                                      + (f" · rol: {result.role}" if result.role else ""))}))
            except Exception:
                pass
            logger.info(f"🧠 [{session.scan_id[:8]}] LLM kimlik: {prod_str} "
                        f"(role={result.role}, os={result.os})")
        return extra, products

    def _host_defense_signals(self, engine, session) -> List[Tuple[str, str, float, str]]:
        """SERVICE düğümlerinden (nmap -sV) OS/host ipuçları + hedefin KENDİ origin'inden
        saptanan WAF/savunma cihazını target_profile'a `extra` sinyal olarak türet (SAF-ish).

        NEDEN: kullanıcı şikayeti — motor RKE2/Ubuntu sunucuyu 'web sitesi' sayıp CMS
        modülleri koşuyordu. SSH/OS banner'ı ('OpenSSH ... Ubuntu') en güvenilir 'bu bir
        sunucu' ipucudur; WAF ise 'önünde güvenlik cihazı' çerçevesini kurar. Co-hosted CF
        karışmasın diye WAF YALNIZ session.ai_analysis['waf'] (FIX3: target-origin-only)."""
        from .attack_graph import NodeType
        extra: List[Tuple[str, str, float, str]] = []
        for n in engine.graph.nodes.values():
            if getattr(n, "type", None) != NodeType.SERVICE:
                continue
            m = getattr(n, "meta", None) or {}
            svc = str(m.get("service") or m.get("matched_service") or "").lower()
            banner = f"{m.get('product') or ''} {m.get('version') or ''}".strip().lower()
            port = m.get("port")
            if "ubuntu" in banner:
                extra.append(("os", "ubuntu", 0.85, f"banner:{banner[:40]}"))
            elif "debian" in banner:
                extra.append(("os", "debian", 0.8, f"banner:{banner[:40]}"))
            elif any(x in banner for x in ("centos", "red hat", "rhel", "rocky", "almalinux")):
                extra.append(("os", "rhel", 0.8, f"banner:{banner[:40]}"))
            elif "windows" in banner or svc in ("msrpc", "microsoft-ds", "netbios-ssn"):
                extra.append(("os", "windows", 0.7, f"svc:{svc or banner[:30]}"))
            if svc == "ssh" or port == 22:
                extra.append(("os", "linux", 0.5, "svc:ssh"))
        waf = (getattr(session, "ai_analysis", None) or {}).get("waf") if session else None
        if isinstance(waf, dict) and str(waf.get("vendor") or "unknown") not in ("unknown", ""):
            try:
                conf = float(waf.get("confidence") or 0.6)
            except (TypeError, ValueError):
                conf = 0.6
            extra.append(("waf", str(waf["vendor"]), min(0.95, max(0.5, conf)), "waf_detect"))
        return extra

    async def _ensure_target_profile(self, session: PipelineSession, engine, dispatcher):
        """IPB çekirdeği — 'önce düşmanı tanı'. Hedef profilini kurar/tazeler ve playbook'u
        (bilinçli saldırı kararı) hesaplar. Web sinyalleri BİR KEZ çekilir (cache); portlar
        her çağrıda tazelenir (nmap sonrası K8s tespiti devreye girer). Sonuçlar:
          - engine._target_profile / engine._playbook (gating için)
          - dispatcher.profile_exclude_tags (nuclei tag-scope)
          - root.meta['target_profile'|'playbook'] (rapor/UI görünürlüğü)
        Best-effort: hata halinde profil boş kalır → tüm modüller varsayılan (kör kalma yok)."""
        if os.getenv("TARGET_PROFILING", "1") != "1":
            return
        try:
            from .target_profile import fingerprint
            from .playbook import select_playbook, nuclei_tag_plan
        except Exception:
            return
        if not hasattr(self, "_profile_web_sig"):
            self._profile_web_sig: Dict[str, Any] = {}
            self._last_profile_summary: Dict[str, str] = {}
            self._infra_ports_cache: Dict[str, Any] = {}
            self._llm_identity_done: set = set()   # Tier 3: (scan_id:host) başına EN FAZLA 1 LLM kimlik çağrısı
            self._llm_identity_calls: Dict[str, int] = {}  # scan_id -> toplam LLM kimlik çağrısı (bütçe tavanı)
            self._identity_learned: set = set()    # Tier 4: tarama başına EN FAZLA 1 öğrenme yazımı
            self._k8s_sig_cache: Dict[str, Any] = {}  # scan_id -> {"probed": set, "hits": [(port, şema, sürüm)]} — ARTIMLI API-imza pası (V2: yeni portlar gelmeye devam eder)
        host = self._bare_host(engine.target)
        sig = self._profile_web_sig.get(session.scan_id)
        if sig is None:
            sig = await self._fetch_profile_signals(host)
            self._profile_web_sig[session.scan_id] = sig
        # K8s kontrol-düzlemi portlarını hedefli yokla (nmap kaçırır) → K8s tespiti.
        # BOŞ sonuç hemen cache'lenMEZ: geçici ağ/DNS hatası taramayı boyunca kör etmesin
        # diye en fazla 3 kez yeniden denenir; sonra kesin cache'lenir (her tur 3sn blok yok).
        _sweep_state = self._infra_ports_cache.get(session.scan_id)
        if _sweep_state is None or (not _sweep_state[0] and _sweep_state[1] < 3):
            infra_ports = (await self._infra_port_sweep(host)
                           if os.getenv("INFRA_PORT_PROBE", "1") == "1" else [])
            attempts = (_sweep_state[1] + 1) if _sweep_state else 1
            self._infra_ports_cache[session.scan_id] = (infra_ports, attempts)
            if infra_ports:
                logger.info(f"🎯 [{session.scan_id[:8]}] K8s port sweep: açık {infra_ports}")
        infra_ports = self._infra_ports_cache.get(session.scan_id, ([], 0))[0]
        ports = sorted(set(self._collect_open_ports(engine) + list(infra_ports)))
        # AKILCILIK: hedef bir 'site' mi yoksa çıplak sunucu/appliance mı? SSH/OS banner'ı
        # (nmap -sV) ve hedefin KENDİ origin'inden saptanan WAF/firewall profile taşınır →
        # motor "her hedefi web sitesi" saymaz, çerçeveyi ve gating'i buna göre kurar.
        extra_signals = self._host_defense_signals(engine, session)
        # K8s API-İMZA PASI (NodePort / 443 / k3s-16443 / dashboard / registry): kontrol-düzlemi
        # firewall arkasında olsa bile K8s, NodePort ya da ingress/LB üzerinden dışarı sızabilir.
        # TCP-sweep yalnız KUBE_PORTS'u (6443/10250...) yoklar → bu portlardan SIZAN K8s'i yakalar;
        # bu pas ise ZATEN AÇIK aday portlarda (NodePort 30000-32767, 443, 16443) tahribatsız GET
        # /version ile K8s API imzası arar. Bulursa: profil kubernetes olur (playbook k8s_probe'u
        # açar) + port derin proba taşınır. Yalnız açık portlar, tarama başına 1 kez (cache),
        # SAF classify_* (FP-güvenli). K8S_API_SIG_PROBE=0 kapatır.
        _k8s_api_extra: Dict[int, str] = {}
        if os.getenv("K8S_API_SIG_PROBE", "1") == "1":
            # ARTIMLI pas (V2): eskiden tarama başına TEK sefer koşup cache'leniyordu —
            # profil ilk turda (rustscan tam-port bitMEDEN) koşarsa NodePort keşfi BOŞ
            # döndü ve tarama boyunca asla yeniden denenmedi → "K8s kurulu ama tespit
            # edilmiyor" şikayetinin kökü. Şimdi yalnız YENİ aday portlar yoklanır.
            _sig_state = self._k8s_sig_cache.get(session.scan_id)
            if not isinstance(_sig_state, dict):
                _sig_state = {"probed": set(), "hits": []}
                self._k8s_sig_cache[session.scan_id] = _sig_state
            _sig_cand = sorted(({p for p in ports if p in (443, 16443) or 30000 <= p <= 32767}
                                - set(_sig_state["probed"])))[:12]
            if _sig_cand:
                for _hit in await self._k8s_api_sig_probe(host, _sig_cand):
                    _sig_state["probed"].add(int(_hit[0]))
                    _sig_state["hits"].append(_hit)
            for _p, _sch, _ver in (_sig_state.get("hits") or []):
                _k8s_api_extra[int(_p)] = _sch or "https"
                if int(_p) not in infra_ports:
                    infra_ports = list(infra_ports) + [int(_p)]
            if _k8s_api_extra:
                _vnote = ""
                _hits = _sig_state.get("hits") or []
                _with_ver = [(p, v) for (p, _s, v) in _hits if v]
                if _with_ver:
                    _vnote = " (sürüm " + ", ".join(str(v) for _p, v in _with_ver) + ")"
                extra_signals = extra_signals + [
                    ("infra", "kubernetes", 0.9,
                      "k8s-api-imza @" + ", ".join(f"{p}/{s}" for p, s in _k8s_api_extra.items()) + _vnote)]
                ports = sorted(set(ports) | {int(p) for p in _k8s_api_extra})
                logger.info(f"☸️ [{session.scan_id[:8]}] K8s API-imza pası: "
                            f"{sorted(_k8s_api_extra)} portunda Kubernetes API doğrulandı")
        # Operatör "bu hedef ne?" ipucu — otomatik tespit ıskalasa bile tipi damgala.
        # api/web → güçlü app_type sinyali (has_web_signal → kind=web + downstream gating).
        # server → aşağıda emit'te kind='host' zorlanır. auto/None → hiçbir şey (saf otomatik).
        _op_kind = str(getattr(session, "target_kind", "") or "").lower()
        if _op_kind == "api":
            extra_signals = extra_signals + [("app_type", "api", 0.98, "operatör: API")]
        elif _op_kind == "web":
            extra_signals = extra_signals + [("app_type", "server-rendered", 0.9, "operatör: web uygulaması")]
        # CPE KİMLİK OMURGASI: nmap/Shodan'ın OTORİTER CPE + OS verisini profile bağla —
        # elle imza yazmadan os/ürün/web-sunucu kimliği (10k config problemi için temel katman).
        cpe_products: List[str] = []
        llm_products: List[str] = []
        try:
            from .cpe_intel import cpe_to_signals, os_string_to_signal
            cpe_sig, cpe_products = cpe_to_signals(self.discovered_data.get("cpes") or [])
            extra_signals = extra_signals + cpe_sig
            _os_sig = os_string_to_signal(self.discovered_data.get("os_detection"))
            if _os_sig:
                extra_signals.append(_os_sig)
        except Exception as _e:
            logger.debug(f"CPE kimlik sinyali atlandı: {_e}")
        # Kimlik kanıtı (header/çerez/başlık) — recall + LLM + learn ORTAK kaynağı.
        _identity_evidence = self._identity_evidence(sig)
        # TIER 4 — ÖĞRENME RECALL: daha önce (CPE/LLM ile) tanınan bir ürünü, AYIRT EDİCİ
        # sinyalinden LLM'e SORMADAN geri çağır (hızlı-yol büyür; niş 'Spective' bir kez
        # öğrenilince ücretsiz). Deterministik altında ağırlık → çeliştiğinde canlı veri baskın.
        learned_labels: List[str] = []
        if os.getenv("IDENTITY_MEMORY", "1") == "1":
            try:
                _col = self._identity_mem_col()
                if _col is not None:
                    from .identity_memory import extract_identity_signals, recall as _id_recall
                    _sigs = extract_identity_signals(_identity_evidence)
                    _rc_extra, learned_labels = _id_recall(_col, _sigs)
                    if _rc_extra:
                        extra_signals = extra_signals + _rc_extra
                        logger.info(f"🧠 [{session.scan_id[:8]}] Kimlik hafızası: "
                                    f"{len(learned_labels)} öğrenilmiş kimlik uygulandı.")
            except Exception as _e:
                logger.debug(f"Kimlik recall atlandı: {_e}")
        try:
            profile = fingerprint(headers=sig.get("headers"), cookies=sig.get("cookies"),
                                  body=sig.get("body") or "", ports=ports, extra=extra_signals)
        except Exception as e:
            logger.debug(f"Fingerprint hatası: {e}")
            return
        # TIER 3 — LLM SON-ÇARE KİMLİK: Tier 1 (tablo) + Tier 2 (CPE) hedefi tanıyamadıysa,
        # ham kanıtı LLM'e sorup ürün/CPE HİPOTEZİ al (pfSense/RKE2/niş "Spective" → LLM zaten
        # bilir; elle imza yazma). Düşük güvenle profile işlenir (deterministik baskın kalır),
        # tarama başına 1 kez, best-effort. Doğrulama: kimlik yalnız ÇERÇEVE; tahribat yok.
        # PER-HOST kimlik: cap artık (scan_id:host) bazlı → çok-hostlu profilleme eklenince her
        # tanınmayan host bir kez LLM'e sorulabilir. Tarama başına toplam tavan (env, vars. 3)
        # bulut sağlayıcıda maliyeti sınırlar. Tek-hostlu taramada davranış aynı (1 çağrı).
        _id_key = f"{session.scan_id}:{host}"
        _id_max = int(os.getenv("AUTONOMOUS_LLM_IDENTITY_MAX", "3"))
        if (os.getenv("LLM_IDENTITY", "1") == "1"
                and _id_key not in self._llm_identity_done
                and self._llm_identity_calls.get(session.scan_id, 0) < _id_max
                and getattr(engine, "_llm_healthy", False)
                and self._identity_weak(profile, cpe_products)
                and (sig.get("headers") or sig.get("body") or ports)):
            self._llm_identity_done.add(_id_key)
            self._llm_identity_calls[session.scan_id] = \
                self._llm_identity_calls.get(session.scan_id, 0) + 1
            try:
                _llm_extra, _llm_out = await self._llm_infer_identity(engine, session, sig, ports)
            except Exception as _e:
                logger.debug(f"LLM kimlik atlandı: {_e}")
                _llm_extra, _llm_out = [], []
            if _llm_extra:
                extra_signals = extra_signals + _llm_extra
                llm_products = list(dict.fromkeys(llm_products + _llm_out))
                try:
                    profile = fingerprint(headers=sig.get("headers"), cookies=sig.get("cookies"),
                                          body=sig.get("body") or "", ports=ports, extra=extra_signals)
                except Exception as _e:
                    logger.debug(f"LLM kimlik re-fingerprint hatası: {_e}")
        # Görüntü ürün listesi: CPE (otoriter) + LLM (tahmin) + öğrenilmiş (hafıza) birleşik.
        all_products = list(dict.fromkeys(cpe_products + llm_products + learned_labels))
        engine._target_profile = profile
        engine._playbook = select_playbook(profile)
        try:
            dispatcher.profile_exclude_tags = nuclei_tag_plan(profile).get("exclude_tags", [])
        except Exception:
            dispatcher.profile_exclude_tags = []
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is not None:
            # Hedefli sweep'te bulunan K8s portlarını grafın açık-port kümesine KAT (tek
            # doğruluk kaynağı → _probe_kubernetes ve diğer modüller de görür; nmap kaçırsa bile).
            # KRİTİK: open_ports'un KANONİK biçimi DICT listesidir (attack_graph._absorb_ports
            # {"port":.., "service":..} üretir; appraise prompt'u p.get('port') okur). Çıplak int
            # katmak listeyi dict+int KARIŞIK yapar → _build_appraisal_prompt'ta 'int has no get'
            # → LLM danışması HER TUR çöker, motor sessizce kural-fallback'e düşer. Bu yüzden
            # infra portlarını da DICT olarak, port-numarasına göre tekilleştirerek katıyoruz.
            if infra_ports:
                existing = root.meta.get("open_ports") or []
                known = {p.get("port") for p in existing if isinstance(p, dict)}
                known |= {p for p in existing if isinstance(p, int)}
                for ip in infra_ports:
                    if ip not in known:
                        existing.append({"port": ip, "service": "k8s-infra",
                                         "product": "", "version": ""})
                        known.add(ip)
                root.meta["open_ports"] = existing
            # HTTP-imza pasıyla doğrulanan K8s API portları (KUBE_PORTS dışı: NodePort/443/16443)
            # → _probe_kubernetes bunları apiserver gibi derin yoklasın (extra_ports).
            if _k8s_api_extra:
                merged_api = dict(root.meta.get("k8s_api_ports") or {})
                merged_api.update(_k8s_api_extra)
                root.meta["k8s_api_ports"] = merged_api
            root.meta["target_profile"] = profile.to_dict()
            root.meta["playbook"] = engine._playbook.to_dict()
            if all_products:
                root.meta["cpe_products"] = all_products[:30]
        # Operatör görünürlüğü — özet DEĞİŞİNCE bir kez bildir (her turda spam yok).
        summ = profile.summary()
        if self._last_profile_summary.get(session.scan_id) != summ:
            self._last_profile_summary[session.scan_id] = summ
            await ScanEventBus.publish(ScanEvent(
                scan_id=session.scan_id,
                event_type=ScanEventType.PROGRESS_UPDATE,
                data={"type": "target_profiled", "target": engine.target,
                      "profile": summ, "playbook": engine._playbook.summary(),
                      # Hedef TİPİ — UI 'site' varsaymasın: web | appliance | host | unknown.
                      # Operatör "server" dediyse çıplak host çerçevesi zorlanır (operatör bilir).
                      "kind": ("host" if _op_kind == "server" else profile.kind()),
                      # Ürün kimliği: CPE (otoriter) + LLM (tahmin) + öğrenilmiş (hafıza).
                      "products": all_products[:20],
                      # Yapılandırılmış gerçekler (UI "hangi sistem" kartı için):
                      # {boyut: {value, confidence, evidence}}.
                      "facts": profile.to_dict().get("facts", {}),
                      # K8s/altyapı port-sweep GÖRÜNÜRLÜĞÜ: motorun kontrol-düzlemi portlarını
                      # (6443/9345/10250/etcd...) YOKLADIĞINI ve sonucunu operatör görsün. RKE2/K8s
                      # dışarıdan firewall'luysa "açık: yok" → k8s_probe'un NEDEN atlandığı anlaşılır
                      # (kullanıcı: "K8s kurulu ama göremiyorum"). Boş sonuç = tespit yok, K8s yok değil.
                      "infra_probe": {
                          "attempted": os.getenv("INFRA_PORT_PROBE", "1") == "1",
                          "k8s_ports_open": list(infra_ports),
                      },
                      # Yapılandırılmış playbook kararları (UI okunabilir rozet render'ı için —
                      # ham "aktif: php_modules, ..." string'i yerine): {modül: {run, priority, reason}}.
                      "playbook_decisions": engine._playbook.to_dict(),
                      "message": f"🎯 Hedef tanındı → {summ} | plan: {engine._playbook.summary()}"},
            ))
            logger.info(f"🎯 [{session.scan_id[:8]}] IPB profil: {summ} || {engine._playbook.summary()}")

        # TIER 4 — ÖĞREN: bu taramada CPE/LLM ile tanınan kimliği (saf tablo-hit'i DEĞİL) AYIRT
        # EDİCİ web sinyallerine bağla → sonraki taramalar aynı ürünü LLM'siz tanır (hızlı-yol
        # kendini büyütür). Tarama başına EN FAZLA 1 kez, YALNIZ kimlik oturunca (distill≠None),
        # best-effort (Mongo yoksa/hata → sessiz atla). IDENTITY_MEMORY=0 kapatır.
        if (os.getenv("IDENTITY_MEMORY", "1") == "1"
                and session.scan_id not in self._identity_learned):
            try:
                _col = self._identity_mem_col()
                if _col is not None:
                    from .identity_memory import (distill_identity, extract_identity_signals,
                                                  learn as _id_learn)
                    _ident = distill_identity(profile, cpe_products, llm_products)
                    if _ident:
                        _n = _id_learn(_col, extract_identity_signals(_identity_evidence),
                                       _ident, engine.target)
                        if _n:
                            self._identity_learned.add(session.scan_id)  # yalnız BAŞARIDA işaretle
                            logger.info(f"🧠 [{session.scan_id[:8]}] Kimlik öğrenildi: "
                                        f"'{_ident['label']}' ← {_n} sinyal ({_ident['source']}).")
            except Exception as _e:
                logger.debug(f"Kimlik öğrenme atlandı: {_e}")

    @staticmethod
    def _identity_mem_col():
        """identity_memory koleksiyonu — core.db süreç-singleton'ından (yoksa None; motor bozulmaz)."""
        try:
            from core.db import db as _mdb
            return _mdb["identity_memory"] if _mdb is not None else None
        except Exception:
            return None

    @staticmethod
    def _identity_evidence(sig: Dict[str, Any]) -> Dict[str, Any]:
        """Profil web sinyalinden (header/çerez/gövde) kimlik kanıtı sözlüğü — recall + learn
        ORTAK kaynağı. Başlık gövdeden çıkarılır (ürün-adı sık başlıkta geçer)."""
        body = sig.get("body") or ""
        title = None
        _m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if _m:
            title = _m.group(1).strip()[:200]
        return {"headers": sig.get("headers") or {}, "cookies": sig.get("cookies") or [],
                "title": title}

    def _cap_allowed(self, engine, name: str, default: bool = True) -> bool:
        """Playbook kararına göre bir modül çalışsın mı? Playbook yoksa `default`."""
        pb = getattr(engine, "_playbook", None)
        if pb is None:
            return default
        return pb.allowed(name, default)

    async def _probe_kubernetes_surface(self, session: PipelineSession, engine, narrate):
        """V2 / Madde 5 (T4) — NodePort YÜZEY pası: dashboard / private registry /
        NodePort'tan sızan apiserver. rustscan tam-port 30000-32767 aralığını GÖRÜR ama
        kimse sınıflandırmazdı; kontrol düzlemi (6443) firewall'luyken bile K8s bu
        portlardan dışarı sızar → tespit kördü ("master IP'si var, tespit yok" şikayeti).
        TAHRİBATSIZ: yalnız ZATEN AÇIK portlara GET (gürültü doktrini); port-bazlı dedup
        (her port tarama başına bir kez yoklanır — yeni port gelirse sonraki turda denenir).
        GATE: playbook şartı YOK (bilinçli — _k8s_api_sig_probe deseni): aday kümenin
        kendisi "NodePort aralığında açık port var" verisidir; K8S_PROBE_V2=0 kapatır.
        Best-effort; ASLA raise etmez."""
        if os.getenv("K8S_PROBE_V2", "1") != "1":
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        ports = self._collect_open_ports(engine)
        _done = set(root.meta.get("k8s_surface_probed_ports") or [])
        cand = [p for p in ports if 30000 <= p <= 32767 and p not in _done]
        if not cand:
            return
        try:
            from .autonomous_engine import Evidence
            from .k8s_probe import probe_k8s_surface
        except Exception:
            return
        root.meta["k8s_surface_probed_ports"] = sorted(_done | set(cand))
        try:
            verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False) as client:
                findings, api_hits = await probe_k8s_surface(engine.target, cand, client)
        except Exception as e:
            logger.info(f"K8s yüzey probu atlandı (best-effort, scan={session.scan_id}): {e}")
            return
        # NodePort'tan doğrulanan K8s API portları → tek doğruluk kaynağı havuzları:
        # (a) root.meta['k8s_api_ports'] → _probe_kubernetes extra_ports ile derin yoklar;
        # (b) sig-cache hits → sonraki _ensure_target_profile turu profil sinyali (0.9)
        #     üretir → playbook k8s_probe AÇILIR → derin prob gerçekten koşar.
        if api_hits:
            merged = dict(root.meta.get("k8s_api_ports") or {})
            merged.update(api_hits)
            root.meta["k8s_api_ports"] = merged
            _sig_state = getattr(self, "_k8s_sig_cache", {}).get(session.scan_id)
            if isinstance(_sig_state, dict):
                for _p, _sch in api_hits.items():
                    if _p not in _sig_state.get("probed", set()):
                        _sig_state.setdefault("probed", set()).add(_p)
                        _sig_state.setdefault("hits", []).append((_p, _sch, None))
            # Derin prob bu portu HENÜZ kapsamadıysa (playbook bu turda henüz kubernetes
            # demedi — profil yüzey probundan ÖNCE koştu) görünürlük bulgusu üret; derin
            # prob sonraki turda zengin bulguyu (sürüm/secret) getirir.
            _deep_done = set(root.meta.get("k8s_probed_ports") or [])
            for _p, _sch in api_hits.items():
                if _p in _deep_done:
                    continue
                _base = f"{_sch}://{engine.target}:{_p}"
                ev = Evidence(
                    title=f"Kubernetes API'si NodePort Üzerinden Dışarı Sızıyor @ {_base}",
                    severity="medium", cve=None, target=_base,
                    proof=(f"NodePort {_p} üzerinde Kubernetes API imzası doğrulandı "
                           f"(Status/gitVersion). Kontrol düzlemi (6443/10250) firewall "
                           f"arkasında olsa bile cluster NodePort'tan erişilebilir: sürüm "
                           f"ifşası + anonim RBAC hatası yüzeyi dışarıdan canlı. Derin prob "
                           f"(anon secret/kubelet) bir sonraki turda koşacak."),
                    tool="k8s_probe", step=engine.step,
                    cwe=["CWE-200"], mitre="T1613",
                    verified=True, verification_method="k8s-signature",
                    verification_confidence=0.9, confidence_tier="confirmed")
                if engine.graph.add_evidence(ev, f"k8s|{_base}|nodeport-api"):
                    await narrate(
                        ScanEventType.VULNERABILITY_FOUND,
                        f"☸️ NodePort'tan K8s API sızması: {_base}",
                        {"title": ev.title, "target": _base, "severity": "medium",
                         "confidence_tier": "confirmed", "tool": "k8s_probe"})
            logger.info(f"☸️ [{session.scan_id[:8]}] K8s yüzey pası: NodePort'ta API "
                        f"doğrulandı {sorted(api_hits)} — derin prob sıraya alındı")
        for f in findings:
            tier = f.get("confidence_tier", "confirmed")
            sev = f.get("severity", "high")
            ev = Evidence(
                title=f["title"], severity=sev, cve=None, target=f["target"],
                proof=f["proof"], tool="k8s_probe", step=engine.step,
                cwe=f.get("cwe") or ["CWE-306"], mitre=f.get("mitre") or "T1613",
                verified=True if tier == "confirmed" else None,
                verification_method=f.get("verification_method") if tier == "confirmed" else None,
                verification_detail=(f["proof"][:200]) if tier == "confirmed" else None,
                verification_confidence=f.get("verification_confidence") if tier == "confirmed" else None,
                confidence_tier=tier,
            )
            if engine.graph.add_evidence(ev, f"k8s|{f['target']}|{f['title'][:40]}"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING if sev in ("critical", "high")
                    else ScanEventType.VULNERABILITY_FOUND,
                    f"☸️ Kubernetes yüzeyi: {f['title']}",
                    {"title": f["title"], "target": f["target"], "severity": sev,
                     "confidence_tier": tier, "tool": "k8s_probe"})
        if findings or api_hits:
            logger.info(f"☸️ [{session.scan_id[:8]}] K8s yüzey probu: "
                        f"{len(findings)} bulgu — {engine.target}")

    async def _probe_kubernetes(self, session: PipelineSession, engine, narrate):
        """IPB payoff — K8s-farkında ifşa probu. YALNIZ profil K8s dediğinde (playbook
        k8s_probe, if_relevant) çalışır → bilinçli saldırı: K8s olmayan hedefte K8s portları
        yoklanmaz. Auth'suz apiserver/kubelet/etcd ifşasını deterministik kanıtlar. TAHRİBATSIZ."""
        # k8s_probe if_relevant: playbook YOKSA default False (K8s portlarını körlemesine yoklama).
        if not self._cap_allowed(engine, "k8s_probe", default=False):
            return
        ports = self._collect_open_ports(engine)
        try:
            from .k8s_probe import KUBE_PORTS, probe_kubernetes
        except Exception:
            return
        # Port filtresi KUBE_PORTS'tan (9345 RKE2, 2380 etcd-peer, kube-proxy, cadvisor dahil)
        kube_ports = [p for p in ports if p in KUBE_PORTS]
        root = engine.graph.nodes.get(engine.graph.root_id)
        # HTTP-imza pasıyla doğrulanmış KUBE_PORTS-DIŞI K8s API portları (NodePort/443/16443).
        # Bunlar kontrol-düzlemi firewall arkasındayken bile K8s'i dışarı sızdırır → apiserver gibi
        # derin yoklanır. Yoksa dict boş kalır, davranış eskiyle birebir.
        _api_extra: Dict[int, str] = {}
        if root is not None:
            for _p, _sch in (root.meta.get("k8s_api_ports") or {}).items():
                try:
                    _api_extra[int(_p)] = _sch or "https"
                except (TypeError, ValueError):
                    continue
        if not kube_ports and not _api_extra:
            return
        if root is None:
            return
        # ARTIMLI derin prob (V2 / Madde 5): eskiden tek-sefer "k8s_probed" bayrağı vardı —
        # ilk turda eldeki portlar yoklanıp bayrak atılıyordu; SONRAKI turlarda keşfedilen
        # portlar (NodePort yüzey pası, rustscan geç tam-port) asla derin yoklanamıyordu.
        # Şimdi port-bazlı dedup: yalnız YENİ portlar yoklanır. "k8s_probed" bayrağı
        # coverage sözleşmesi için korunur (koştuğu turlarda True).
        _done_ports = set(root.meta.get("k8s_probed_ports") or [])
        _probe_ports = sorted((set(kube_ports) | set(_api_extra.keys())) - _done_ports)
        if not _probe_ports:
            return
        root.meta["k8s_probed"] = True
        root.meta["k8s_probed_ports"] = sorted(_done_ports | set(_probe_ports))
        try:
            from .autonomous_engine import Evidence
            # Kimlik-etiketi: sürüm ucu auth arkasında olsa bile TLS sertifikasından dağıtım
            # (rke2/k3s/...) yakalanır — identity-first. K8S_CERT_IDENTITY=0 kapatır.
            _cert_res = None
            if os.getenv("K8S_CERT_IDENTITY", "1") == "1":
                try:
                    from .k8s_probe import tls_peer_identity as _cert_res  # noqa: F811
                except Exception:
                    _cert_res = None
            verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False) as client:
                findings = await probe_kubernetes(engine.target, _probe_ports, client,
                                                  cert_identity=_cert_res,
                                                  extra_ports=_api_extra)
        except Exception as e:
            logger.info(f"K8s probu atlandı (best-effort, scan={session.scan_id}): {e}")
            return
        # Sürüm bulunan bileşen → SERVICE düğümü seed: "tespit→CVE/KEV" halkası kurulsun
        # (RKE2 sürüm damgası NVD+KEV'e akmadan bulgu yarım kalırdı — WP envanter deseni).
        try:
            from .attack_graph import (Node, Edge, NodeType as _NT, NodeState as _NS,
                                       DEFAULT_NODE_VALUE as _DNV)
            for f in findings:
                ver = f.get("version")
                if not ver:
                    continue
                prod = f.get("product") or "kubernetes"
                nid = f"svc:k8s:{prod}@{engine.target}:{f.get('port') or ''}"
                if nid in engine.graph.nodes:
                    continue
                engine.graph.add_node(Node(
                    id=nid, type=_NT.SERVICE, label=f"{prod}@{ver}",
                    value=_DNV, breach_prob=0.35, state=_NS.DISCOVERED,
                    meta={"product": prod, "version": ver, "matched_service": prod,
                          "needs_cve_lookup": True, "component": "kubernetes",
                          "host": engine.target, "port": f.get("port")}))
                engine.graph.add_edge(from_id=root.id, to_id=nid, tool="k8s_probe",
                                      cost=1.0, success_prob=1.0,
                                      rationale=f"K8s bileşeni {prod} {ver} → NVD CVE/KEV.",
                                      state="executed")
        except Exception as _kce:
            logger.debug(f"K8s sürüm→CVE seed atlandı: {_kce}")
        for f in findings:
            tier = f.get("confidence_tier", "confirmed")
            sev = f.get("severity", "high")
            ev = Evidence(
                title=f["title"], severity=sev, cve=None, target=f["target"],
                proof=f["proof"], tool="k8s_probe", step=engine.step,
                cwe=f.get("cwe") or ["CWE-306"], mitre=f.get("mitre") or "T1613",
                verified=True if tier == "confirmed" else None,
                verification_method=f.get("verification_method") if tier == "confirmed" else None,
                verification_detail=(f["proof"][:200]) if tier == "confirmed" else None,
                verification_confidence=f.get("verification_confidence") if tier == "confirmed" else None,
                confidence_tier=tier,
            )
            if engine.graph.add_evidence(ev, f"k8s|{f['target']}|{f['title'][:40]}"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING if sev in ("critical", "high")
                    else ScanEventType.VULNERABILITY_FOUND,
                    f"☸️ Kubernetes: {f['title']}",
                    {"title": f["title"], "target": f["target"], "severity": sev,
                     "confidence_tier": tier, "tool": "k8s_probe"})
        # Madde 5 (T4) — sürüm→CVE: resmî K8s CVE danışma matrisi (statik snapshot,
        # deterministik minor/patch kıyası). NVD hattı (SERVICE seed) ayrıca koşar;
        # bu katman ÇEVRİMDIŞI konuşur — dağıtım damgalı sürümlerde (rke2r1/k3s1) de
        # minor/patch otoriter olduğundan eşleşir. Kanıt gücü: probable (aktif PoC yok,
        # sürüm kıyası deterministik — distro-intel doktriniyle aynı kademe).
        try:
            from .attack_graph import _threat_intel_for_cve
            from .k8s_probe import match_k8s_cves
            _cve_added = 0
            for f in findings:
                _ver = f.get("version")
                if not _ver or f.get("product") != "kube-apiserver":
                    continue
                for _cve in match_k8s_cves("kube-apiserver", _ver):
                    _sev = str(_cve.get("severity") or "medium")
                    _win = " (yalnız Windows node'larda sömürülebilir)" if _cve.get("windows_only") else ""
                    apt_groups, techniques = _threat_intel_for_cve(_cve["cve"])
                    ev = Evidence(
                        title=(f"Kubernetes kube-apiserver {_ver} — {_cve['cve']}: "
                               f"{(_cve.get('title') or '')[:90]}{_win}"),
                        severity=_sev, cve=_cve["cve"], target=f["target"],
                        proof=(f"gitVersion={_ver} ↔ resmî K8s CVE danışması: "
                               f"{_cve.get('match_reason', '')}. Etkilenen aralıklar: "
                               f"{'; '.join((_cve.get('affected') or [])[:4])}. "
                               f"Düzeltmeler: {json.dumps(_cve.get('fixed_in'), ensure_ascii=False)}. "
                               f"Kaynak: {_cve.get('url', '')}"),
                        tool="k8s_probe", step=engine.step,
                        cwe=["CWE-1104"], mitre="T1613",
                        cvss_v3=_cve.get("cvss3"),
                        attack_techniques=techniques, apt_groups=apt_groups,
                        confidence_tier="probable",
                        verification_method="version-advisory-match",
                        verification_detail=_cve.get("match_reason"),
                        verification_confidence=0.85)
                    if engine.graph.add_evidence(ev, f"k8scve|{f['target']}|{_cve['cve']}"):
                        _cve_added += 1
                        await narrate(
                            ScanEventType.CRITICAL_FINDING if _sev in ("critical", "high")
                            else ScanEventType.VULNERABILITY_FOUND,
                            f"☸️ Kubernetes sürüm zaafiyeti: {_cve['cve']} @ {f['target']}",
                            {"title": ev.title, "target": f["target"], "severity": _sev,
                             "cve": _cve["cve"], "cvss_v3": _cve.get("cvss3"),
                             "confidence_tier": "probable", "tool": "k8s_probe"})
            if _cve_added:
                logger.info(f"☸️ [{session.scan_id[:8]}] K8s sürüm→CVE: "
                            f"{_cve_added} danışma eşleşmesi — {engine.target}")
        except Exception as _kve:
            logger.debug(f"K8s sürüm→CVE katmanı atlandı (best-effort): {_kve}")
        if findings:
            logger.info(f"☸️ [{session.scan_id[:8]}] K8s probu: {len(findings)} bulgu — {engine.target}")

    async def _probe_hypervisor(self, session: PipelineSession, engine, narrate):
        """Hypervisor/sanallaştırma YÖNETİM arayüzü internete açık mı (TAHRİBATSIZ, yalnız GET).

        Kullanıcının "ana makine (ESXi/Proxmox) görünür mü" isteğinin DÜRÜST karşılığı: VM→fiziksel
        host eşlemesi dışarıdan imkansız; ama hedefin KENDİSİ ESXi/vCenter/Proxmox/Cockpit/oVirt
        mgmt arayüzünü açığa veriyorsa bu tüm host'un saldırı yüzeyidir (ESXi ransomware buradan
        girer) → yüksek bulgu. Yalnız engine.target'e gider (co-hosted sızıntısı yok). Mgmt portları
        (8006/8007/9090) nmap'in kaçırdığı için hedefli yoklanır; imza yoksa bulgu YOK (FP-güvenli).
        Flag: HYPERVISOR_PROBE=0 kapatır. Best-effort; ASLA raise etmez."""
        if os.getenv("HYPERVISOR_PROBE", "1") != "1":
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None or root.meta.get("hypervisor_probed"):
            return
        root.meta["hypervisor_probed"] = True
        try:
            from .hypervisor_probe import probe_hypervisor
            from .autonomous_engine import Evidence
        except Exception:
            return
        ports = self._collect_open_ports(engine)
        try:
            verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=True) as client:
                findings = await probe_hypervisor(engine.target, ports, client)
        except Exception as e:
            logger.info(f"Hypervisor probu atlandı (best-effort, scan={session.scan_id}): {e}")
            return
        for f in findings:
            tier = f.get("confidence_tier", "confirmed")
            sev = f.get("severity", "high")
            ev = Evidence(
                title=f["title"], severity=sev, cve=None, target=f["target"],
                proof=f["proof"], tool="hypervisor_probe", step=engine.step,
                cwe=f.get("cwe") or ["CWE-284"], mitre=f.get("mitre") or "T1133",
                verified=True if tier == "confirmed" else None,
                verification_method="deterministic-observation" if tier == "confirmed" else None,
                verification_detail=(f["proof"][:200]) if tier == "confirmed" else None,
                confidence_tier=tier,
            )
            if engine.graph.add_evidence(ev, f"hypervisor|{f['target']}|{f['product'][:40]}"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING if sev in ("critical", "high")
                    else ScanEventType.VULNERABILITY_FOUND,
                    f"🖥️ Hypervisor mgmt ifşası: {f['title']}",
                    {"title": f["title"], "target": f["target"], "severity": sev,
                     "confidence_tier": tier, "tool": "hypervisor_probe"})
        if findings:
            logger.info(f"🖥️ [{session.scan_id[:8]}] Hypervisor probu: {len(findings)} ifşa "
                        f"— {engine.target}")

    def _wp_candidate_hosts(self, engine) -> List[str]:
        """WP probu için aday host'lar: kök hedef + grafta WEB işareti taşıyan keşfedilen
        origin'ler (subdomain/co-host). Bare hostname'e normalize + dedup. #3 graf simetrisi:
        path_probe/WAF-fingerprint her web hostuna gider; WP probu da öyle olmalı (blog.corp.io
        WP iken kök SPA olabilir). Her host, probe_wordpress'in CANLI re-confirm'iyle kendini
        gate'ler → WP olmayan host'ta yalnız 1 GET (ana sayfa) harcanır, WP taraması ÇALIŞMAZ."""
        from urllib.parse import urlsplit

        def _host(x: str) -> str:
            x = str(x or "").strip()
            return (urlsplit(x).netloc or x) if "://" in x else x

        out: List[str] = []
        seen: set = set()
        for x in [engine.target] + self._web_origins_for_waf(engine):
            h = _host(x)
            if h and h not in seen:
                seen.add(h)
                out.append(h)
        return out

    async def _probe_wordpress(self, session: PipelineSession, engine, narrate):
        """IPB payoff — WordPress-farkında deterministik prob. HER aday host (kök + keşfedilen
        web subdomain) için çalışır; her host probe_wordpress'in CANLI re-confirm'iyle kendini
        gate'ler → WP OLMAYAN host'ta WP taraması yapılmaz (kullanıcı doktrini per-host: 'WP
        değilse kesinlikle çalışmamalı' — 1 GET'lik tespit dışında). Onaylanan host'lar
        root.meta['wp_confirmed_hosts']'a yazılır (SQLi oracle yalnız oradan çalışır).

        Kazanım (host başına): çekirdek sürüm + readme.txt KESİN plugin envanteri → CVE korelasyonu,
        /wp-json route hasadı → IDOR adayları (endpoints'e seed), REST/author user-enum, xmlrpc,
        debug.log. TAHRİBATSIZ (yalnız GET). WP_PROBE=0 kapatır; WP_PROBE_MAX_HOSTS host tavanı.
        Best-effort, host-bazlı dedup (root.meta['wp_probed_hosts'])."""
        if os.getenv("WP_PROBE", "1") != "1":
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        candidates = self._wp_candidate_hosts(engine)
        if not candidates:
            return
        probed: set = root.meta.setdefault("wp_probed_hosts", set())
        confirmed: List[str] = root.meta.setdefault("wp_confirmed_hosts", [])
        cap = int(os.getenv("WP_PROBE_MAX_HOSTS", "5"))
        todo = [h for h in candidates if h not in probed][:cap]
        if not todo:
            return
        try:
            from .wp_probe import probe_wordpress
            from .autonomous_engine import Evidence
            from .attack_graph import Node, Edge, NodeType, NodeState, DEFAULT_NODE_VALUE
        except Exception:
            return
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        try:
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False) as client:
                for host in todo:
                    probed.add(host)
                    try:
                        res = await probe_wordpress(host, client)
                    except Exception as e:
                        logger.debug(f"WP probu hata ({host}): {e}")
                        continue
                    if not res.get("confirmed_wp"):
                        continue  # canlı re-confirm: bu host WP değil → per-host gate, sessiz geç
                    if host not in confirmed:
                        confirmed.append(host)

                    # ENVANTER → CVE KORELASYONU (host başına): çekirdek + KESİN sürümlü plugin'leri
                    # SERVICE düğümü (needs_cve_lookup=True) olarak seed et → enrich_cve_intelligence
                    # NVD'ye sorar (CVE düğümü + hedefli nuclei kenarı + unconfirmed kanıt). wp_probe
                    # SAF kalır (CVE I/O graf enrich'te).
                    try:
                        components: List[Tuple[str, str, str]] = []
                        if res.get("core_version"):
                            components.append(("wordpress", res["core_version"], "wordpress"))
                        for _slug, _ver in (res.get("inventory", {}).get("plugins", {}) or {}).items():
                            if _ver:
                                components.append((_slug, _ver, f"wp-plugin:{_slug}"))
                        for product, version, label in components[:10]:  # NVD sorgu bütçesi
                            nid = f"svc:wpc:{label}@{host}"
                            if nid in engine.graph.nodes:
                                continue
                            engine.graph.add_node(Node(
                                id=nid, type=NodeType.SERVICE, label=f"{label}@{version}",
                                value=DEFAULT_NODE_VALUE, breach_prob=0.3, state=NodeState.DISCOVERED,
                                meta={"product": product, "version": version, "matched_service": label,
                                      "needs_cve_lookup": True, "component": "wordpress",
                                      "host": host, "port": None}))
                            engine.graph.add_edge(Edge(
                                from_id=root.id, to_id=nid, tool="wp_probe", cost=1.0, success_prob=1.0,
                                rationale=f"WordPress bileşeni ({host}): {label} {version} → NVD CVE.",
                                state="executed"))
                    except Exception as _cse:
                        logger.debug(f"WP envanter→CVE seed atlandı ({host}): {_cse}")

                    # /wp-json/<res>/<id> IDOR adaylarını endpoints'e seed → _probe_idor devralır.
                    idor_seeds = res.get("idor_candidates") or []
                    if idor_seeds:
                        eps = root.meta.get("endpoints")
                        if not isinstance(eps, list):
                            eps = []
                        existing = set(eps)
                        for u in idor_seeds:
                            if u not in existing:
                                eps.append(u)
                                existing.add(u)
                        root.meta["endpoints"] = eps

                    findings = res.get("findings") or []
                    for f in findings:
                        tier = f.get("confidence_tier", "confirmed")
                        sev = f.get("severity", "low")
                        ev = Evidence(
                            title=f["title"], severity=sev, cve=None, target=f["target"],
                            proof=f["proof"], tool="wp_probe", step=engine.step,
                            cwe=f.get("cwe") or ["CWE-200"], mitre=f.get("mitre") or "T1592",
                            verified=True if tier == "confirmed" else None,
                            verification_method=f.get("verification_method") if tier == "confirmed" else None,
                            verification_detail=(f["proof"][:200]) if tier == "confirmed" else None,
                            verification_confidence=f.get("verification_confidence") if tier == "confirmed" else None,
                            confidence_tier=tier,
                        )
                        if engine.graph.add_evidence(ev, f"wp|{f['target']}|{f['title'][:40]}"):
                            await narrate(
                                ScanEventType.CRITICAL_FINDING if sev in ("critical", "high")
                                else ScanEventType.VULNERABILITY_FOUND,
                                f"🔵 WordPress: {f['title']}",
                                {"title": f["title"], "target": f["target"], "severity": sev,
                                 "confidence_tier": tier, "tool": "wp_probe"})
                    if findings or idor_seeds:
                        logger.info(
                            f"🔵 [{session.scan_id[:8]}] WP probu ({host}): {len(findings)} bulgu, "
                            f"{len(idor_seeds)} IDOR adayı seed")
        except Exception as e:
            logger.info(f"WordPress probu atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _probe_wp_sqli(self, session: PipelineSession, engine, narrate):
        """#4 admin-ajax SQL Injection ORACLE — WP'yi 'keşif prober'dan 'SQLi oracle'a çıkarır.
        Güncel CVE deseninin manşeti: SQLi'ler admin-ajax action parametrelerinde. Bu modül
        action'ları hasat eder, aday enjeksiyon noktaları üretir ve KANITI motorun MEVCUT
        time-based blind doğrulayıcısına (verification.verify_time_based_sqli) yaptırır →
        deterministik confirmed. Yeni enjeksiyon motoru icat etmez; kanıtlı çekirdeği kullanır.

        AKTİF enjeksiyon (motorun ilk tahribat-sınırı katmanı): SLEEP-tabanlı, SALT-OKUNUR ama
        SQL çalıştırır. ÇOK KAPILI: WP_SQLI_ORACLE=1 (kill-switch), recon'da çalışmaz, YALNIZ
        wp_probe'un CANLI onayladığı host'larda (root.meta['wp_confirmed_hosts']) — WP olmayan
        host'a tek payload gitmez. Host başına tek sefer, sıkı cap/pacing, ilk confirmed'de durur.
        Subdomain kapsama: kök SPA olsa da blog.corp.io WP onaylandıysa orada da çalışır."""
        if os.getenv("WP_SQLI_ORACLE", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        # WP-gated (per-host): YALNIZ wp_probe'un canlı WP onayladığı host'lar. Boşsa _probe_wordpress
        # henüz WP bulmadı → enjekte etme. Bu, 'WP değilse kesinlikle çalışmamalı'yı host bazında sağlar.
        confirmed_hosts = list(root.meta.get("wp_confirmed_hosts") or [])
        if not confirmed_hosts:
            return
        done: set = root.meta.setdefault("wp_sqli_done_hosts", set())
        todo = [h for h in confirmed_hosts if h not in done][:int(os.getenv("WP_SQLI_MAX_HOSTS", "3"))]
        if not todo:
            return
        try:
            from .wp_sqli_oracle import run_wp_sqli_oracle
            from .autonomous_engine import Evidence
        except Exception:
            return
        max_c = int(os.getenv("WP_SQLI_MAX_CANDIDATES", "6"))
        delay = float(os.getenv("WP_SQLI_DELAY", "4"))
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        try:
            # follow_redirects=False: enjeksiyon zamanlaması temiz kalsın (yönlendirme gecikme
            # gürültüsü katar). _resolve kökü ayrıca explicit follow ile çeker.
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False,
                                         timeout=20.0) as client:
                for host in todo:
                    done.add(host)
                    try:
                        findings = await run_wp_sqli_oracle(host, client,
                                                            max_candidates=max_c, delay_seconds=delay)
                    except Exception as e:
                        logger.info(f"WP SQLi oracle atlandı ({host}, scan={session.scan_id}): {e}")
                        continue
                    for f in findings:
                        ev = Evidence(
                            title=f["title"], severity="critical", cve=None, target=f["target"],
                            proof=f["proof"], tool="wp_sqli_oracle", step=engine.step,
                            cwe=f.get("cwe") or ["CWE-89"], mitre=f.get("mitre") or "T1190",
                            verified=True,
                            verification_method=f.get("verification_method") or "time-based-blind-sqli",
                            verification_detail=f["proof"][:200],
                            verification_confidence=f.get("verification_confidence"),
                            confidence_tier="confirmed",
                        )
                        if engine.graph.add_evidence(ev, f"wpsqli|{f['action']}|{f['param']}|{host}"):
                            await narrate(
                                ScanEventType.CRITICAL_FINDING,
                                f"💉 WordPress AJAX SQLi [confirmed/critical]: action={f['action']}, param={f['param']}",
                                {"title": f["title"], "target": f["target"], "severity": "critical",
                                 "confidence_tier": "confirmed", "tool": "wp_sqli_oracle",
                                 "action": f["action"], "param": f["param"]})
                    if findings:
                        logger.info(f"💉 [{session.scan_id[:8]}] WP SQLi oracle ({host}): "
                                    f"{len(findings)} KANITLI SQLi")
        except Exception as e:
            logger.info(f"WP SQLi oracle atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _probe_deserialization(self, session: PipelineSession, engine, narrate):
        """P3 — Deserialization kabul-imza probu (SharePoint ToolShell yol-imzası, ASP.NET
        ViewState MAC-kabul testi, TeamCity sürüm ifşası). YALNIZ playbook deserialization_probe
        if_relevant ise çalışır (framework=sharepoint|teamcity veya language=dotnet) — WP
        zincirinden BAĞIMSIZ bir framework gate'i, aynı host havuzunu paylaşır.

        TAHRİBATSIZ: gerçek gadget-chain/RCE payload'u ÇALIŞTIRILMAZ, yalnız kabul-imzası/
        oracle davranışı gözlenir (bkz. deserialization_probe.py modül başlığı — tahribatsızlık
        gerekçesi orada denetlenebilir şekilde yazılı). DESERIALIZATION_PROBE=0 kapatır;
        DESERIALIZATION_PROBE_MAX_HOSTS host tavanı. Best-effort, host-bazlı dedup."""
        if not self._cap_allowed(engine, "deserialization_probe", default=False):
            return
        if os.getenv("DESERIALIZATION_PROBE", "1") != "1":
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        candidates = self._wp_candidate_hosts(engine)
        if not candidates:
            return
        probed: set = root.meta.setdefault("deser_probed_hosts", set())
        cap = int(os.getenv("DESERIALIZATION_PROBE_MAX_HOSTS", "5"))
        todo = [h for h in candidates if h not in probed][:cap]
        if not todo:
            return
        try:
            from .deserialization_probe import probe_deserialization
            from .autonomous_engine import Evidence
        except Exception:
            return
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        try:
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False) as client:
                for host in todo:
                    probed.add(host)
                    try:
                        res = await probe_deserialization(host, client)
                    except Exception as e:
                        logger.debug(f"Deserialization probu hata ({host}): {e}")
                        continue
                    findings = res.get("findings") or []
                    for f in findings:
                        tier = f.get("confidence_tier", "confirmed")
                        sev = f.get("severity", "medium")
                        ev = Evidence(
                            title=f["title"], severity=sev, cve=None, target=f["target"],
                            proof=f["proof"], tool="deserialization_probe", step=engine.step,
                            cwe=f.get("cwe") or ["CWE-502"], mitre=f.get("mitre") or "T1190",
                            verified=True if tier == "confirmed" else None,
                            verification_method=f.get("verification_method") if tier == "confirmed" else None,
                            verification_detail=(f["proof"][:200]) if tier == "confirmed" else None,
                            verification_confidence=f.get("verification_confidence") if tier == "confirmed" else None,
                            confidence_tier=tier,
                        )
                        if engine.graph.add_evidence(ev, f"deser|{f['target']}|{f['title'][:40]}"):
                            await narrate(
                                ScanEventType.CRITICAL_FINDING if sev in ("critical", "high")
                                else ScanEventType.VULNERABILITY_FOUND,
                                f"🧬 Deserialization: {f['title']}",
                                {"title": f["title"], "target": f["target"], "severity": sev,
                                 "confidence_tier": tier, "tool": "deserialization_probe"})
                    if findings:
                        logger.info(
                            f"🧬 [{session.scan_id[:8]}] Deserialization probu ({host}): "
                            f"{len(findings)} bulgu")
        except Exception as e:
            logger.info(f"Deserialization probu atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _probe_appliance(self, session: PipelineSession, engine, narrate):
        """P3 — Edge/VPN/firewall appliance auth-bypass/missing-auth probu (FortiWeb/PAN-OS/
        Ivanti/NetScaler/N-able/SimpleHelp/LoadMaster). YALNIZ playbook appliance_probe
        if_relevant ise çalışır (framework bir appliance ailesi) — deserialization/WP
        zincirinden BAĞIMSIZ framework gate'i, aynı host havuzunu paylaşır.

        TAHRİBATSIZ: yalnız GET; sürüm ifşası + kimliksiz ayrıcalıklı-erişim diferansiyeli
        gözlenir (bkz. appliance_probe.py modül başlığı — tahribatsızlık gerekçesi orada
        denetlenebilir). Exploit tekniği/komut çalıştırılmaz. APPLIANCE_PROBE=0 kapatır;
        APPLIANCE_PROBE_MAX_HOSTS host tavanı. Best-effort, host-bazlı dedup."""
        if not self._cap_allowed(engine, "appliance_probe", default=False):
            return
        if os.getenv("APPLIANCE_PROBE", "1") != "1":
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        candidates = self._wp_candidate_hosts(engine)
        if not candidates:
            return
        probed: set = root.meta.setdefault("appliance_probed_hosts", set())
        cap = int(os.getenv("APPLIANCE_PROBE_MAX_HOSTS", "5"))
        todo = [h for h in candidates if h not in probed][:cap]
        if not todo:
            return
        try:
            from .appliance_probe import probe_appliance
            from .autonomous_engine import Evidence
        except Exception:
            return
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        try:
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False) as client:
                for host in todo:
                    probed.add(host)
                    try:
                        res = await probe_appliance(host, client)
                    except Exception as e:
                        logger.debug(f"Appliance probu hata ({host}): {e}")
                        continue
                    findings = res.get("findings") or []
                    for f in findings:
                        tier = f.get("confidence_tier", "confirmed")
                        sev = f.get("severity", "high")
                        ev = Evidence(
                            title=f["title"], severity=sev, cve=None, target=f["target"],
                            proof=f["proof"], tool="appliance_probe", step=engine.step,
                            cwe=f.get("cwe") or ["CWE-306"], mitre=f.get("mitre") or "T1190",
                            verified=True if tier == "confirmed" else None,
                            verification_method=f.get("verification_method") if tier == "confirmed" else None,
                            verification_detail=(f["proof"][:200]) if tier == "confirmed" else None,
                            verification_confidence=f.get("verification_confidence") if tier == "confirmed" else None,
                            confidence_tier=tier,
                        )
                        if engine.graph.add_evidence(ev, f"appliance|{f['target']}|{f['title'][:40]}"):
                            await narrate(
                                ScanEventType.CRITICAL_FINDING if sev in ("critical", "high")
                                else ScanEventType.VULNERABILITY_FOUND,
                                f"🛡️ Appliance: {f['title']}",
                                {"title": f["title"], "target": f["target"], "severity": sev,
                                 "confidence_tier": tier, "tool": "appliance_probe"})
                    if findings:
                        logger.info(
                            f"🛡️ [{session.scan_id[:8]}] Appliance probu ({host}, "
                            f"{res.get('family')}): {len(findings)} bulgu")
        except Exception as e:
            logger.info(f"Appliance probu atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _probe_resilience(self, session: PipelineSession, engine, narrate):
        """Dayanıklılık & maruz-kalma probu (availability + exposure ekseni). Motorun bugüne
        dek kör kaldığı sınıf: hedef, tek bir açık bile sömürülmeden L7 flood ile düşer /
        origin ifşasıyla CDN korumasını baypas ettirir / SSH parola-auth ile brute-force'a
        zemin verir (gözlenen 203.0.113.76 olayı). Üç eksen (hepsi TAHRİBATSIZ):

          A) L7 DoS dayanıklılığı: CDN arkasında anasayfa cache'leniyor mu + rate-limit var mı.
          B) Origin ifşası: gerçek origin IP'ye CDN ATLANARAK erişilip aynı uygulama mı (bypass).
          C) SSH maruz-kalması: banner sürümü + parola kimlik doğrulaması AÇIK mı (kimlik DENENMEZ).

        KAPI: YALNIZ operatör UI toggle'ı açıksa çalışır (session.resilience — VARSAYILAN KAPALI;
        kullanıcı tarama başlatırken bilinçli açar). RESILIENCE_PROBE=0 ops kill-switch. Gerçek
        DDoS/brute-force ATILMAZ. Best-effort, per-hedef dedup, ASLA raise etmez."""
        if not getattr(session, "resilience", False):
            return
        if os.getenv("RESILIENCE_PROBE", "1") != "1":
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        try:
            from . import resilience_probe as RP
            from .autonomous_engine import Evidence
            from .attack_graph import NodeType
        except Exception:
            return
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        web_probed: set = root.meta.setdefault("resilience_web_probed", set())
        ssh_probed: set = root.meta.setdefault("resilience_ssh_probed", set())
        posture = root.meta.setdefault("edge_posture", {
            "cdn": None, "origin_exposed": False, "cdn_bypassable": False,
            "homepage_cached": False, "ssh_password_auth": None})
        collected: List[Tuple[str, Dict[str, Any]]] = []

        # ---- A/B) L7 dayanıklılık + origin-CDN-bypass ifşası (web hostları) ----
        web_cap = int(os.getenv("RESILIENCE_MAX_HOSTS", "3"))
        web_hosts = [h for h in self._wp_candidate_hosts(engine) if h not in web_probed][:web_cap]
        # origin IP yalnız hedef CDN arkasındaysa anlamlı (aksi halde real_ip = hedefin kendisi)
        origin_ip = root.meta.get("real_ip") if root.meta.get("is_behind_cdn") else None
        primary_host = None
        if web_hosts:
            try:
                async with httpx.AsyncClient(verify=verify_tls, follow_redirects=True) as client:
                    for host in web_hosts:
                        web_probed.add(host)
                        if primary_host is None:
                            primary_host = host
                        try:
                            l7 = await RP.probe_l7_resilience(host, client)
                        except Exception as e:
                            logger.debug(f"L7 dayanıklılık hata ({host}): {e}")
                            continue
                        for f in l7.get("findings", []):
                            collected.append((host, f))
                        if not posture.get("cdn"):
                            posture["cdn"] = l7.get("cdn")
                        if l7.get("homepage_cached"):
                            posture["homepage_cached"] = True
                        # Origin-bypass yalnız kök host için + origin IP biliniyorsa (tek deneme)
                        if origin_ip and l7.get("cdn") and host == primary_host:
                            try:
                                oe = await RP.probe_origin_exposure(
                                    host, origin_ip, l7.get("cdn"), client,
                                    cdn_body_sig=l7.get("cdn_body_sig"))
                                for f in oe.get("findings", []):
                                    collected.append((f"{host} (origin {origin_ip})", f))
                                if oe.get("cdn_bypassable"):
                                    posture["cdn_bypassable"] = True
                                    posture["origin_exposed"] = True
                            except Exception as e:
                                logger.debug(f"Origin ifşa probu hata ({origin_ip}): {e}")
            except Exception as e:
                logger.debug(f"Dayanıklılık web katmanı atlandı ({session.scan_id}): {e}")

        # ---- C) SSH maruz-kalması (yalnız nmap SSH servisi bulduysa — gürültü yok) ----
        ssh_cap = int(os.getenv("RESILIENCE_SSH_MAX", "3"))
        ssh_targets: List[Tuple[str, int]] = []
        for n in engine.graph.nodes.values():
            if n.type != NodeType.SERVICE:
                continue
            matched = n.meta.get("matched_service") or (
                n.label.split("@")[0] if isinstance(n.label, str) else "")
            port = n.meta.get("port")
            if str(matched).lower() == "ssh" and port:
                p = int(port) if str(port).isdigit() else 22
                ssh_targets.append((engine.target, p))
        for host, port in ssh_targets[:ssh_cap]:
            key = f"{host}:{port}"
            if key in ssh_probed:
                continue
            ssh_probed.add(key)
            try:
                r = await RP.probe_ssh_exposure(host, port, internet_exposed=True)
            except Exception as e:
                logger.debug(f"SSH maruz-kalma probu hata ({key}): {e}")
                continue
            for f in r.get("findings", []):
                collected.append((key, f))
            if r.get("password_auth") is True:
                posture["ssh_password_auth"] = True
            elif r.get("password_auth") is False and posture.get("ssh_password_auth") is None:
                posture["ssh_password_auth"] = False

        # ---- Bulguları grafa işle (confidence_tier korunur) + operatöre yayınla ----
        for tgt, f in collected:
            sev = str(f.get("severity") or "info").lower()
            tier = f.get("confidence_tier") or "unconfirmed"
            ev = Evidence(
                title=f["title"], severity=sev, cve=None, target=tgt,
                proof=f["proof"], tool="resilience_probe", step=engine.step,
                cwe=f.get("cwe") or ["CWE-770"], mitre=f.get("mitre") or "T1499",
                verified=True if tier == "confirmed" else None,
                verification_method="deterministic-observation" if tier == "confirmed" else None,
                verification_detail=(f["proof"][:200]) if tier == "confirmed" else None,
                confidence_tier=tier,
            )
            if engine.graph.add_evidence(ev, f"resilience|{tgt}|{f['title'][:40]}"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING if sev in ("critical", "high")
                    else ScanEventType.VULNERABILITY_FOUND,
                    f"🌊 Dayanıklılık: {f['title']}",
                    {"title": f["title"], "target": tgt, "severity": sev,
                     "confidence_tier": tier, "tool": "resilience_probe",
                     "axis": f.get("axis"), "remediation": f.get("remediation")})
        if collected:
            logger.info(
                f"🌊 [{session.scan_id[:8]}] Dayanıklılık probu: {len(collected)} bulgu "
                f"(cdn={posture.get('cdn')}, bypass={posture.get('cdn_bypassable')}, "
                f"ssh_pw={posture.get('ssh_password_auth')})")

    async def _probe_idor(self, session: PipelineSession, engine, narrate):
        """T2-A: OTOMATİK IDOR/BOLA güvenlik-ağı — her turda post-observe koşar. Planlayıcının
        `probe_api_bola` aktif saldırısıyla AYNI çekirdeği (`_run_bola_campaign`) paylaşır;
        ortak `idor_probed` seti çift-istemi engeller (planlayıcı bir hedefi işlediyse otomatik
        onu tekrar problamaz). Gate: IDOR_PROBE=0 kapatır; recon'da çalışmaz. Kimlik yoksa
        BRONZE kip (kimliksiz nesne ifşası). TAHRİBATSIZ (yalnız GET)."""
        if os.getenv("IDOR_PROBE", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        auth_a = _parse_auth_dict_to_headers(session.auth)
        # Kimlik YOKSA BRONZE kip: kimliksiz nesne ifşası + kitlesel sızıntı (dıştan yetkili
        # testin çoğu unauth'tur; modern API'nin en sık gerçek açığı budur). IDOR_UNAUTH_PROBE=0
        # kapatır (yalnız kimlikli IDOR'a döner).
        if not auth_a and os.getenv("IDOR_UNAUTH_PROBE", "1") != "1":
            return
        await self._run_bola_campaign(session, engine, narrate, candidates=None)

    async def _run_bola_campaign(self, session: PipelineSession, engine, narrate,
                                 *, candidates: Optional[List[str]] = None) -> Dict[str, Any]:
        """API BOLA/broken-auth kampanyası — PAYLAŞILAN ÇEKİRDEK (otomatik prob + planlayıcı
        `probe_api_bola` aksiyonu ikisi de çağırır).

        İnsan pentester'ların en çok kazandığı, tarayıcıların en kör olduğu sınıf. IDOR bir
        imza değil DİFERANSİYEL gözlemdir → aktif olarak kanıtlanır:
          - İki-hesap (auth + auth_b): B, A'nın nesnesini alabiliyorsa → **confirmed**.
          - Tek-hesap / kimliksiz: id-yürüyüşüyle başka nesne + KİTLESEL PII ifşası (TEB).

        `candidates` verilirse o URL kümesi (planlayıcı hedefli seçim); yoksa graftan
        (crawl endpoint'leri) toplanır. Dedup: root.meta['idor_probed']. TAHRİBATSIZ, ASLA
        raise etmez. Döner: {"findings", "confirmed", "candidates"}."""
        auth_a = _parse_auth_dict_to_headers(session.auth)
        auth_b = _parse_auth_dict_to_headers(getattr(session, "auth_b", None))
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return {"findings": 0, "confirmed": 0, "candidates": 0}
        probed: set = root.meta.setdefault("idor_probed", set())
        from .attack_graph import NodeType
        from .idor_probe import (extract_object_refs, probe_idor,
                                 probe_object_exposure, probe_mass_exposure, _MAX_TARGETS)
        # Aday havuzu: açıkça verildiyse onu kullan (planlayıcı _candidates), yoksa graftan
        # topla (root.meta['endpoints'] MUTLAK URL'ler + http(s) ENDPOINT node label'ları).
        if candidates:
            pool: List[str] = list(candidates)
        else:
            pool = list(root.meta.get("endpoints", []) or [])
            for n in engine.graph.nodes.values():
                if n.type == NodeType.ENDPOINT and isinstance(n.label, str) \
                        and n.label.startswith(("http://", "https://")):
                    pool.append(n.label)
        # Henüz problanmamış + nesne-ref taşıyan URL'ler (probe_idor içeride _MAX_TARGETS
        # kapıyor → burada da aynı sayıda alıp SADECE onları işaretle; dilimleme sonraki
        # turlarda kalanı işler, kapsam kaybı yok).
        cand: List[str] = []
        for u in dict.fromkeys(pool):
            if u in probed:
                continue
            if extract_object_refs(u):
                cand.append(u)
            if len(cand) >= _MAX_TARGETS:
                break
        if not cand:
            return {"findings": 0, "confirmed": 0, "candidates": 0}
        for u in cand:
            probed.add(u)

        try:
            if auth_a:
                findings = await probe_idor(cand, auth_a=auth_a, auth_b=auth_b)
            else:
                findings = await probe_object_exposure(cand)
        except Exception as e:
            logger.info(f"IDOR probu atlandı (best-effort, scan={session.scan_id}): {e}")
            findings = []

        # TEB senaryosu — KİTLESEL ifşa: "yürünebilir nesne VAR" yetmez, KAÇ farklı kullanıcının
        # PII'si döndüğünü say. Kimliksiz pass HER ZAMAN (token'sız asıl senaryo); auth varsa
        # o kimlikle kitlesel çekim de. MASS_EXPOSURE_PROBE=0 kapatır. Tahribatsız, kanıtta ham PII yok.
        if os.getenv("MASS_EXPOSURE_PROBE", "1") == "1":
            pacing = 0.15 if getattr(session, "stealth", False) else 0.0
            try:
                mass = await probe_mass_exposure(cand, auth=None, pacing=pacing)
                if auth_a:
                    mass += await probe_mass_exposure(cand, auth=auth_a, pacing=pacing)
                findings = (findings or []) + mass
            except Exception as e:
                logger.info(f"Kitlesel ifşa probu atlandı (best-effort, scan={session.scan_id}): {e}")

        if not findings:
            return {"findings": 0, "confirmed": 0, "candidates": len(cand)}

        from .autonomous_engine import Evidence
        from .attack_graph import _canon_url
        confirmed = 0
        for f in findings:
            tier = f["tier"]
            sev = f["severity"]
            url = f["url"]
            if tier == "confirmed":
                confirmed += 1
            fp = (f"idor|{_canon_url(url)}|{f.get('ref_name') or f.get('ref_kind')}"
                  f"|{f.get('verification_method', '')}")
            ev = Evidence(
                title=f["title"], severity=sev, cve=None, target=url,
                proof=f["proof"], tool="idor_probe", step=engine.step,
                cwe=f.get("cwe") or ["CWE-639"], mitre=f.get("mitre") or "T1190",
                verified=True if tier == "confirmed" else None,
                verification_method=f.get("verification_method") if tier == "confirmed" else None,
                verification_detail=f.get("verification_detail") if tier == "confirmed" else None,
                verification_confidence=f.get("verification_confidence") if tier == "confirmed" else None,
                confidence_tier=tier,
            )
            if engine.graph.add_evidence(ev, fp):
                icon = "🔓" if tier == "confirmed" else "🕵️"
                await narrate(
                    ScanEventType.CRITICAL_FINDING if tier == "confirmed"
                    else ScanEventType.VULNERABILITY_FOUND,
                    f"{icon} IDOR/BOLA [{tier}]: {url}",
                    {"title": f["title"], "target": url, "severity": sev,
                     "confidence_tier": tier, "tool": "idor_probe",
                     "ref_kind": f.get("ref_kind"), "ref_name": f.get("ref_name")},
                )
        _mode = "iki-hesap" if auth_b else ("tek-hesap" if auth_a else "kimliksiz-BRONZE")
        logger.info(
            f"🔓 [{session.scan_id[:8]}] IDOR/BOLA kampanyası: {len(findings)} bulgu "
            f"({confirmed} confirmed) — {_mode} kip")
        return {"findings": len(findings), "confirmed": confirmed, "candidates": len(cand)}

    async def _dispatch_bola_native(self, session: PipelineSession, engine, narrate,
                                    stage) -> StageResult:
        """Planlayıcı `probe_api_bola` aksiyonunu ÇALIŞTIR (orchestrator-yerli, dış servis yok).
        Motorun bilinçli saldırı kararı → mevcut kampanya çekirdeğini hedefli koşar. Kısa +
        kapaklı (heartbeat gerekmez). IDOR_PROBE=0 kill-switch'ine saygı; ASLA raise etmez."""
        started = datetime.utcnow()
        if os.getenv("IDOR_PROBE", "1") != "1":
            return StageResult(stage_name=stage.name, tool="probe_api_bola", status="skipped",
                               error="IDOR_PROBE kapalı (kill-switch)",
                               started_at=started.isoformat(),
                               completed_at=datetime.utcnow().isoformat())
        cands = stage.options.get("_candidates") or None
        await narrate(
            ScanEventType.AGENT_ACTION,
            "🎯 API BOLA saldırısı — nesne-ID'li endpoint'lerde token'sız/çapraz-kimlik "
            "kitlesel erişim deneniyor…",
            {"step": engine.step, "tool": "probe_api_bola",
             "candidates": len(cands) if cands else 0},
        )
        try:
            summary = await self._run_bola_campaign(session, engine, narrate, candidates=cands)
        except Exception as e:
            return StageResult(stage_name=stage.name, tool="probe_api_bola", status="failed",
                               error=f"API BOLA saldırısı hatası: {e}",
                               started_at=started.isoformat(),
                               completed_at=datetime.utcnow().isoformat())
        dur = (datetime.utcnow() - started).total_seconds()
        return StageResult(
            stage_name=stage.name, tool="probe_api_bola", status="completed",
            started_at=started.isoformat(), completed_at=datetime.utcnow().isoformat(),
            duration_seconds=dur,
            data={"bola_findings": summary.get("findings", 0),
                  "bola_confirmed": summary.get("confirmed", 0),
                  "candidates_probed": summary.get("candidates", 0)},
        )

    async def _probe_fac_matrix(self, session: PipelineSession, engine, narrate):
        """T2-A2: Dikey yetki yükseltme / FAC matrisi — idor_probe NESNE bazlı boşluğu
        kanıtlar; bu ROL/İŞLEV bazlı boşluğu kanıtlar (pentest bulgularının bel kemiği,
        tarayıcıların kör noktası). İki kip, tek probda otomatik seçilir:
          1) YÖNTEM AŞINMASI (rol gerekmez): A'ya GET'i 401/403 olan ayrıcalıklı uç,
             X-HTTP-Method-Override / X-Original-URL / X-Rewrite-URL / ?_method / yol
             normalizasyonu ile 2xx+JSON veriyorsa → confirmed bypass (1 kimlikle!).
          2) AYRICALIKLI YOL: anon REDDEDİLMİŞKEN A token'ı dolu veri alıyorsa → A'nın
             JWT'si bariz non-admin ise confirmed dikey privesc, rol okunamazsa probable.
        A kimliği (auth) şart — kimliksiz vaka path_probe/web_misconfig kapsamı.
        TAHRİBATSIZ: yalnız GET + başlık/query/yol hilesi (POST/PUT bilinçli yok).
        FAC_MATRIX_PROBE=0 kapatır; recon'da çalışmaz; playbook fac_matrix gate'ine saygı.
        Best-effort, dedup: root.meta['fac_probed']."""
        if os.getenv("FAC_MATRIX_PROBE", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        if not self._cap_allowed(engine, "fac_matrix", default=True):
            return
        auth_a = _parse_auth_dict_to_headers(session.auth)
        if not auth_a:
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        from .fac_matrix_probe import (select_privileged_urls, probe_fac_matrix,
                                       jwt_nonadmin, _MAX_TARGETS)
        from .attack_graph import NodeType
        probed: set = root.meta.setdefault("fac_probed", set())
        # Aday havuzu: keşfedilen uçlar (root.meta + graf ENDPOINT düğümleri); havuz boşsa
        # kök hedef üzerinden sentetik klasik admin yolları (select_privileged_urls örer).
        pool: List[str] = list(root.meta.get("endpoints", []) or [])
        for n in engine.graph.nodes.values():
            if n.type == NodeType.ENDPOINT and isinstance(n.label, str) \
                    and n.label.startswith(("http://", "https://")):
                pool.append(n.label)
        if not pool:
            pool = [f"https://{engine.target}/"]
        cands = [u for u in select_privileged_urls(pool) if u not in probed][: _MAX_TARGETS]
        if not cands:
            return
        for u in cands:
            probed.add(u)
        # A kimliğinin ROL sinyali — TAMAMEN OFFLINE (kullanıcının kendi JWT'si, imza
        # çözülmez, yalnız payload okunur). Bariz non-admin → KİP-2 confirmed kapısı açılır.
        a_nonadmin: Optional[bool] = None
        try:
            from .verification import decode_jwt, _JWT_RE
            nonadmin_votes: List[bool] = []
            for val in auth_a.values():
                for m in _JWT_RE.finditer(val or ""):
                    dec = decode_jwt(m.group(0))
                    if dec:
                        v = jwt_nonadmin(dec.get("payload") or {})
                        if v is not None:
                            nonadmin_votes.append(v)
            if nonadmin_votes:
                a_nonadmin = all(nonadmin_votes)  # çelişki varsa temkinli: bariz değil
        except Exception:
            pass
        try:
            findings = await probe_fac_matrix(cands, auth_a=auth_a, a_is_nonadmin=a_nonadmin)
        except Exception as e:
            logger.info(f"FAC matris probu atlandı (best-effort, scan={session.scan_id}): {e}")
            return
        if not findings:
            return
        from .autonomous_engine import Evidence
        from .attack_graph import _canon_url
        confirmed = 0
        for f in findings:
            tier = f["tier"]
            if tier == "confirmed":
                confirmed += 1
            ev = Evidence(
                title=f["title"], severity=f["severity"], cve=None, target=f["url"],
                proof=f["proof"], tool="fac_matrix", step=engine.step,
                cwe=f.get("cwe") or ["CWE-284", "CWE-863"], mitre=f.get("mitre") or "T1078",
                verified=True if tier == "confirmed" else None,
                verification_method=f.get("verification_method") if tier == "confirmed" else None,
                verification_detail=f.get("verification_detail") if tier == "confirmed" else None,
                verification_confidence=f.get("verification_confidence") if tier == "confirmed" else None,
                confidence_tier=tier,
            )
            if engine.graph.add_evidence(ev, f"fac|{_canon_url(f['url'])}|{f['kind']}"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING if tier == "confirmed"
                    else ScanEventType.VULNERABILITY_FOUND,
                    f"⬆️ Dikey yetki/FAC [{tier}]: {f['url']}",
                    {"title": f["title"], "target": f["url"], "severity": f["severity"],
                     "confidence_tier": tier, "tool": "fac_matrix", "kind": f["kind"]},
                )
        logger.info(f"⬆️ [{session.scan_id[:8]}] FAC matris: {len(findings)} bulgu "
                    f"({confirmed} confirmed) — rol={'non-admin' if a_nonadmin else 'bilinmiyor/yönetici'}")
        return {"findings": len(findings), "confirmed": confirmed, "candidates": len(cands)}

    async def _probe_web_misconfig(self, session: PipelineSession, engine, narrate):
        """T2-B: PROAKTİF CORS + JWT doğrulaması — önceki bulgu GEREKMEZ (nuclei bunları
        stack'imizde nadiren tohumlar; verifier'lar boşta kalmasın diye burada aktif tetiklenir).

        JWT: kullanıcının verdiği token'lar (auth + auth_b) TAMAMEN OFFLINE analiz edilir —
        HS* zayıf-sır kırılırsa confirmed critical (token forge → auth bypass), alg=none
        confirmed high. Ağ maliyeti sıfır, risk sıfır.
        CORS: base + en değerli endpoint'lere (api/auth/account) keyfi Origin ile tek GET;
        ACAO yansıması confirmed. Auth başlığıyla da denenir (kimlikli veri sızıntısı asıl
        yüksek-etkili senaryo). TAHRİBATSIZ. WEB_MISCONFIG_PROBE=0 kapatır; recon'da çalışmaz."""
        if os.getenv("WEB_MISCONFIG_PROBE", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        import hashlib as _hashlib
        from .verification import verify_cors, verify_jwt, _JWT_RE, crack_jwt_secret, analyze_jwt
        from .autonomous_engine import Evidence
        from .attack_graph import _canon_url
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return

        # ---- JWT (offline) — kullanıcı token'ları (A + B) ----
        jwt_seen: set = root.meta.setdefault("jwt_probed", set())
        tokens: List[str] = []
        for auth in (session.auth, getattr(session, "auth_b", None)):
            for _name, val in _parse_auth_dict_to_headers(auth).items():
                for m in _JWT_RE.finditer(val or ""):
                    tokens.append(m.group(0))
        for tok in dict.fromkeys(tokens):
            thash = _hashlib.sha1(tok.encode("utf-8", "replace")).hexdigest()[:12]
            if thash in jwt_seen:
                continue
            jwt_seen.add(thash)
            try:
                v = verify_jwt(tok)
            except Exception:
                continue
            if not v.verified:
                continue
            sev = v.severity or "high"
            ev = Evidence(
                title=f"JWT Weakness @ {engine.target}", severity=sev, cve=None,
                target=engine.target, proof=v.detail, tool="jwt_verify", step=engine.step,
                cwe=["CWE-347"], mitre="T1550.001",
                verified=True, verification_method=v.method,
                verification_detail=v.detail, verification_confidence=v.confidence,
                confidence_tier="confirmed",
            )
            if engine.graph.add_evidence(ev, f"jwt|{thash}"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING,
                    f"🔑 JWT zayıflığı [confirmed/{sev}]: {v.method}",
                    {"title": "JWT Weakness", "target": engine.target, "severity": sev,
                     "confidence_tier": "confirmed", "tool": "jwt_verify"})
            # T3-B: kırılan sır / alg=none → ZİNCİR ARTIFACT'I (in-process; DB'ye yazılmaz).
            # _execute_chains bunu tüketip token FORGE edip korumalı erişimi kanıtlar.
            try:
                if not hasattr(self, "_chain_artifacts"):
                    self._chain_artifacts: Dict[str, List[Dict[str, Any]]] = {}
                info = analyze_jwt(tok)
                secret = crack_jwt_secret(tok) if info.get("hs") else None
                if secret is not None or info.get("alg_none"):
                    self._chain_artifacts.setdefault(session.scan_id, []).append({
                        "kind": "jwt_secret", "token": tok, "secret": secret,
                        "alg": "none" if info.get("alg_none") else info.get("alg"),
                    })
            except Exception:
                pass

        # ---- CORS (tahribatsız tek GET/endpoint) ----
        cors_seen: set = root.meta.setdefault("cors_probed", set())
        pool = [u for u in (root.meta.get("endpoints") or []) if isinstance(u, str)
                and u.startswith(("http://", "https://"))]
        pool.append(f"https://{engine.target}/")  # kök her zaman aday

        def _cors_score(u: str) -> int:
            return sum(1 for h in ("api", "account", "auth", "user", "admin", "profile", "graphql")
                       if h in u.lower())
        pool = sorted(dict.fromkeys(pool), key=_cors_score, reverse=True)
        cands = [u for u in pool if u not in cors_seen][:5]
        if not cands:
            return
        auth_map = _parse_auth_dict_to_headers(session.auth)
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                         timeout=15.0) as client:
                for u in cands:
                    cors_seen.add(u)
                    try:
                        v = await verify_cors(u, client, headers=auth_map or None)
                    except Exception:
                        continue
                    if not v.verified:
                        continue
                    sev = v.severity or "medium"
                    ev = Evidence(
                        title=f"CORS Misconfiguration @ {u}", severity=sev, cve=None,
                        target=u, proof=v.detail, tool="cors_verify", step=engine.step,
                        cwe=["CWE-942"], mitre="T1190",
                        verified=True, verification_method=v.method,
                        verification_detail=v.detail, verification_confidence=v.confidence,
                        confidence_tier="confirmed",
                    )
                    if engine.graph.add_evidence(ev, f"cors|{_canon_url(u)}"):
                        await narrate(
                            ScanEventType.CRITICAL_FINDING if sev == "high"
                            else ScanEventType.VULNERABILITY_FOUND,
                            f"🌐 CORS misconfig [confirmed/{sev}]: {u}",
                            {"title": "CORS Misconfiguration", "target": u, "severity": sev,
                             "confidence_tier": "confirmed", "tool": "cors_verify"})
        except Exception as e:
            logger.debug(f"CORS probu atlandı: {e}")

    async def _execute_chains(self, session: PipelineSession, engine, narrate):
        """T3-B: exploit ZİNCİRİ icrası (artifact reuse). Ayrık bulguları birbirine bağlar.

        Flagship: JWT Forge → Yetki Yükseltme. _probe_web_misconfig'in kırdığı JWT sırrı/alg=none
        artifact'ını alır, saldırgan iddiaları taşıyan GEÇERLİ token forge eder, anonim erişimin
        REDDEDİLDİĞİ korumalı endpoint'e gider; kabul edilirse KANITLI auth-bypass/priv-esc.
        Bu 'bir zayıflık var'ı 'işte tam etki'ye çevirir (kill-chain'e escalation halkası ekler).

        Deterministik (imzayı biz üretiyoruz, kabulü durum-kodu farkı kanıtlıyor), TAHRİBATSIZ
        (yalnız GET). Gate: CHAIN_EXECUTE=1, recon'da değil. Artifact yoksa erken döner."""
        if os.getenv("CHAIN_EXECUTE", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        arts = getattr(self, "_chain_artifacts", {}).get(session.scan_id) or []
        jwt_arts = [a for a in arts if a.get("kind") == "jwt_secret"]
        if not jwt_arts:
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        from .exploit_chain import run_jwt_forge_chain
        from .autonomous_engine import Evidence
        from .attack_graph import _canon_url

        # Korumalı endpoint adayları: admin/account/api/... çağrışımlı mutlak URL'ler.
        pool = [u for u in (root.meta.get("endpoints") or []) if isinstance(u, str)
                and u.startswith(("http://", "https://"))]
        hints = ("admin", "account", "api", "user", "profile", "settings",
                 "dashboard", "manage", "internal", "me", "billing")
        ranked = sorted(dict.fromkeys(pool),
                        key=lambda u: sum(1 for h in hints if h in u.lower()), reverse=True)
        cands = [u for u in ranked if any(h in u.lower() for h in hints)][:6] or ranked[:4]
        cands.append(f"https://{engine.target}/")  # kök de aday (korumalı olabilir)
        cands = list(dict.fromkeys(cands))
        if not cands:
            return
        done: set = root.meta.setdefault("chain_jwt_done", set())
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        try:
            async with httpx.AsyncClient(verify=verify_tls, follow_redirects=False,
                                         timeout=15.0) as client:
                for art in jwt_arts:
                    akey = (art.get("token") or "")[:24]
                    if not akey or akey in done:
                        continue
                    done.add(akey)
                    try:
                        findings = await run_jwt_forge_chain(
                            cands, token=art["token"], secret=art.get("secret"),
                            alg=art.get("alg"), client=client)
                    except Exception as e:
                        logger.debug(f"Forge zinciri hatası: {e}")
                        continue
                    for f in findings:
                        ev = Evidence(
                            title=f"Privilege Escalation via Forged JWT @ {f['url']}",
                            severity="critical", cve=None, target=f["url"],
                            proof=f["proof"], tool="exploit_chain", step=engine.step,
                            cwe=["CWE-347", "CWE-287"], mitre="T1548",
                            verified=True, verification_method="jwt-forge-chain",
                            verification_detail=f["proof"][:200],
                            verification_confidence=0.95, confidence_tier="confirmed",
                            # Kanıt Sözleşmesi: tekrar-koşulabilir ispat + kararlı kimlik
                            # artık rapora/DB'ye AKAR (eskiden zincirde düşüyordu).
                            proof_bundle=f.get("proof_bundle"),
                            proof_fingerprint=f.get("fingerprint"),
                        )
                        if engine.graph.add_evidence(ev, f"chain_jwt|{_canon_url(f['url'])}"):
                            await narrate(
                                ScanEventType.CRITICAL_FINDING,
                                f"⛓️ ZİNCİR: forge'lu JWT ile yetki yükseltme — {f['url']}",
                                {"title": "Privilege Escalation via Forged JWT",
                                 "target": f["url"], "severity": "critical",
                                 "confidence_tier": "confirmed", "tool": "exploit_chain",
                                 "chain": "jwt_weak_secret→forge→protected_access"})
        except Exception as e:
            logger.debug(f"Exploit zinciri atlandı: {e}")

    async def _synthesize_combinations(self, session: PipelineSession, engine, narrate):
        """APT doktrini — KOMBİNASYON KENARLARI. Tek başına düşük CONFIRMED bulguları birleştirip
        yüksek-etki saldırı yüzeyi türet (combo_chains SAF kural motoru). APT'lerin tarayıcıdan
        farkı budur: user-enum+xmlrpc=pratik brute-force; enum+kanıtlı IDOR=kitlesel sızıntı;
        debug.log+kesin sürüm=hedefli exploit istihbaratı.

        Yeni istek YOK (TAHRİBATSIZ) — yalnız var olan CONFIRMED kanıtı ilişkilendirir. Üretilen
        kombinasyon Evidence olarak grafa yazılır → compose_killchain anlatısına da akar (sentez
        neden→etki kenarı). Her turun sonunda çalışır; add_evidence fingerprint'i tekrarı eler.
        COMBO_CHAINS=0 kapatır. Best-effort."""
        if os.getenv("COMBO_CHAINS", "1") != "1":
            return
        try:
            from .combo_chains import (
                Signal, find_combinations,
                SIG_WP_USER_ENUM, SIG_WP_AUTHOR_SCAN, SIG_WP_XMLRPC, SIG_WP_DEBUG_LOG,
                SIG_WP_CORE_VERSION, SIG_WP_INVENTORY, SIG_IDOR_CONFIRMED,
                SIG_AI_PROMPT_INJECTION, SIG_AI_TOOL_ABUSE, SIG_AI_OUTPUT_SSRF,
                SIG_AI_SYSTEM_LEAK, SIG_AI_JAILBREAK)
            from .autonomous_engine import Evidence
        except Exception:
            return
        # Kanıt → kararlı sinyal etiketi. wp_probe verification_method'u ayırt edici; IDOR tool'dan.
        method_map = {
            "wp-rest-users": SIG_WP_USER_ENUM, "wp-author-scan": SIG_WP_AUTHOR_SCAN,
            "wp-xmlrpc": SIG_WP_XMLRPC, "wp-debug-log": SIG_WP_DEBUG_LOG,
            "wp-generator": SIG_WP_CORE_VERSION, "wp-inventory": SIG_WP_INVENTORY,
            # AI/LLM red-team (verification_method = ai-<class>):
            "ai-prompt_injection": SIG_AI_PROMPT_INJECTION,
            "ai-indirect_prompt_injection": SIG_AI_PROMPT_INJECTION,
            "ai-tool_abuse": SIG_AI_TOOL_ABUSE,
            "ai-output_handling_ssrf": SIG_AI_OUTPUT_SSRF,
            "ai-output_handling": SIG_AI_OUTPUT_SSRF,
            "ai-system_prompt_leak": SIG_AI_SYSTEM_LEAK,
            "ai-multiturn_jailbreak": SIG_AI_JAILBREAK,
        }

        def _ai_kind_from_evidence(ev) -> Optional[str]:
            """llm_redteam bulgusu / OAST callback'ini AI sinyali sınıfına çevir (SAF değil ama
            yalnız başlık/metadata okur). Eşleşme yoksa None."""
            tool = getattr(ev, "tool", "") or ""
            title = (getattr(ev, "title", "") or "").lower()
            if tool == "ai_tool-oast":
                return SIG_AI_TOOL_ABUSE
            if tool == "ai_output-oast":
                return SIG_AI_OUTPUT_SSRF
            if tool != "llm_redteam":
                return None
            if "tool" in title and "abuse" in title:
                return SIG_AI_TOOL_ABUSE
            if "output handling" in title and "ssrf" in title:
                return SIG_AI_OUTPUT_SSRF
            if "indirect" in title or "prompt injection" in title:
                return SIG_AI_PROMPT_INJECTION
            if "jailbreak" in title:
                return SIG_AI_JAILBREAK
            if "system-prompt" in title or "system prompt" in title:
                return SIG_AI_SYSTEM_LEAK
            return None

        signals: List[Any] = []
        for ev in list(getattr(engine.graph, "evidence", []) or []):
            # Yalnız CONFIRMED taşlar zincire girer (doktrin: spekülasyon değil kanıt).
            try:
                if ev.effective_confidence_tier() != "confirmed":
                    continue
            except Exception:
                if getattr(ev, "confidence_tier", None) != "confirmed":
                    continue
            kind = method_map.get(getattr(ev, "verification_method", None) or "")
            if kind is None and getattr(ev, "tool", "") == "idor_probe":
                kind = SIG_IDOR_CONFIRMED
            if kind is None:
                kind = _ai_kind_from_evidence(ev)
            if kind is None:
                continue
            signals.append(Signal(kind=kind, target=getattr(ev, "target", "") or "",
                                  severity=getattr(ev, "severity", "") or "",
                                  title=getattr(ev, "title", "") or ""))
        if len(signals) < 2:
            return
        combos = find_combinations(signals)
        if not combos:
            return
        for c in combos:
            ev = Evidence(
                title=c["title"], severity=c["severity"], cve=None, target=c["target"],
                proof=c["proof"], tool="combo_chains", step=engine.step,
                cwe=c.get("cwe") or [], mitre=c.get("mitre") or "T1110",
                verified=True, verification_method=c["verification_method"],
                verification_detail=c["proof"][:200], verification_confidence=0.85,
                confidence_tier="confirmed",
            )
            if engine.graph.add_evidence(ev, f"combo|{c['combo']}|{c['target']}"):
                await narrate(
                    ScanEventType.CRITICAL_FINDING,
                    f"🔗 Kombinasyon zinciri [{c['severity']}]: {c['title']}",
                    {"title": c["title"], "target": c["target"], "severity": c["severity"],
                     "confidence_tier": "confirmed", "tool": "combo_chains",
                     "combo": c["combo"], "sources": c.get("sources")})
                logger.info(f"🔗 [{session.scan_id[:8]}] Kombinasyon: {c['combo']} — {c['target']}")

    async def _redteam_llm_endpoints(self, session: PipelineSession, engine, narrate):
        """APT FAZ 4 / AI RED-TEAM: hedefte LLM/agent özelliği varsa çok-sınıflı ofansif yoklama.

        Aday endpoint'ler: (a) grindeki ENDPOINT node'ları + root.meta endpoints, (b) AKTİF KEŞİF
        (bilinen OpenAI/ollama/MCP yolları doğrudan yoklanır — crawl'ı beklemez). Her aday
        TAHRİBATSIZ probe'lanır (baseline echo → LLM mi? → direct/indirect prompt injection,
        system-prompt leak, output-handling+XSS/SSRF, tool/function abuse, multi-turn jailbreak).
        Kanıt = benzersiz marker yansıması VEYA OAST callback (deterministik → confirmed). Tier
        doktrini: sezgisel sınıflar (system-prompt leak, çıktı-HTML) 'probable' tavanlı.
        MITRE ATLAS + OWASP LLM Top10 eşlemeli. LLM_REDTEAM=0 kapatır; recon'da çalışmaz;
        scan-başı dedup (`engine._llm_redteam_done`)."""
        if os.getenv("LLM_REDTEAM", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        # PLAYBOOK GATE (ai_redteam, if_relevant): profil AI/agentic ise derin test; profil
        # AI değilse aktif keşif "pozitif istihbarat" sayılır — keşif kapalıysa hiç çalışma.
        _pb = getattr(engine, "_playbook", None)
        _ai_profile = bool(_pb.allowed("ai_redteam", default=False)) if _pb is not None else False
        _discovery = os.getenv("AI_REDTEAM_DISCOVERY", "1") == "1"
        if not _ai_profile and not _discovery:
            return
        try:
            from .llm_redteam import (ai_endpoint_candidates, redteam_endpoint,
                                      discover_ai_endpoints)
            from .attack_graph import NodeType, _canon_url
            from .autonomous_engine import Evidence
        except Exception as e:
            logger.debug(f"llm_redteam yüklenemedi: {e}")
            return
        # Adayları topla: ENDPOINT node label'ları + root.meta endpoints
        root = engine.graph.nodes.get(engine.graph.root_id)
        urls = set()
        for n in engine.graph.nodes.values():
            if n.type == NodeType.ENDPOINT and isinstance(n.label, str) and n.label.startswith("http"):
                urls.add(n.label)
        if root is not None:
            for u in (root.meta.get("endpoints") or []):
                if isinstance(u, str) and u.startswith("http"):
                    urls.add(u)
        candidates = ai_endpoint_candidates(urls, cap=int(os.getenv("LLM_REDTEAM_MAX", "5")))
        # AI/agent yolu (openai/ollama/mcp) aktif keşifte BULUNDU mu? LLM baseline echo ile
        # doğrulanamasa bile bu pozitif istihbarattır → attestation 'not_tested' ile üretilir ki
        # panel kaybolmasın ve "test edilemedi" açıkça görünsün (sessiz boşluk = yanlış güven).
        ai_paths_found = False
        # AKTİF KEŞİF: grafı/crawl'u BEKLEME — bilinen AI/agent yollarını (/v1/chat/completions,
        # /api/chat, /v1/models, MCP) doğrudan yokla. Eski tasarım yalnız crawl'ın yüzeye
        # çıkardığı adaylara bağlıydı → chat endpoint'i linklenmemişse AI red-team hiç koşmazdı.
        # TEK-ATIŞ (engine._ai_discovery_done): bu metod her turda çağrılır; guard olmadan hedefe
        # tur başına ~16 GET giderdi (istek amplifikasyonu + WAF tetikleme). Keşif tarama-başı bir
        # kez. Durum `engine`'de tutulur (per-scan); `self` pipeline singleton'ı DEĞİL — aksi halde
        # ilk taramadan sonra hiçbir tarama keşif yapamazdı.
        if (os.getenv("AI_REDTEAM_DISCOVERY", "1") == "1" and root is not None
                and not getattr(engine, "_ai_discovery_done", False)):
            engine._ai_discovery_done = True
            try:
                _base = (getattr(engine, "target", "") or "").strip()
                if _base and not _base.startswith("http"):
                    _base = f"https://{_base}"
                if _base:
                    _dto = float(os.getenv("AI_REDTEAM_DISCOVERY_TIMEOUT", "8"))
                    async with httpx.AsyncClient(timeout=_dto, follow_redirects=True,
                                                 verify=False) as _dc:
                        _found = await discover_ai_endpoints(_dc, _base, timeout=_dto)
                    for _u in _found:
                        if _u not in urls:
                            urls.add(_u)
                    candidates = ai_endpoint_candidates(
                        urls, cap=int(os.getenv("LLM_REDTEAM_MAX", "5")))
                    if _found:
                        ai_paths_found = True
                        await narrate(
                            ScanEventType.AGENT_OBSERVATION,
                            f" AI endpoint aktif keşfi: {len(_found)} AI/agent yolu bulundu "
                            f"(openai/ollama/mcp uçları)",
                            {"found": _found[:8]}, persist_data={},
                        )
            except Exception as _de:
                logger.debug(f"AI aktif keşif atlandı: {_de}")
        if not candidates:
            return
        if not hasattr(engine, "_llm_redteam_done"):
            engine._llm_redteam_done: set = set()
        candidates = [u for u in candidates if _canon_url(u) not in engine._llm_redteam_done]
        cap = int(os.getenv("LLM_REDTEAM_MAX", "5"))
        candidates = candidates[:cap]
        if not candidates:
            return
        # Attestation birikimi KÜMÜLATİF (engine'de tutulur). NEDEN: bu metod her turda çağrılır
        # ve endpoint'ler turlar arası deduplanır (_llm_redteam_done); local biriktirsek sonraki
        # turun attestation'ı öncekinin güvencesini EZERDİ. engine per-scan → doğru kapsam.
        if not hasattr(engine, "_ai_tested_cum"):
            engine._ai_tested_cum = set()
            engine._ai_findings_cum = []
            engine._ai_sampling_cum = {}
            # HAFIZA (experience replay): geçmiş taramalardan aile kazanma oranlarını yükle →
            # aday önceliğini besle. Best-effort; DB yoksa {} (soğuk başlangıç).
            try:
                from core.db import db as _sdb
                from .sampling_memory import load_family_priors
                engine._ai_family_priors = load_family_priors(_sdb) if _sdb is not None else {}
            except Exception:
                engine._ai_family_priors = {}
        saw_llm = False
        try:
            timeout = float(os.getenv("POC_VERIFY_HTTP_TIMEOUT", "20"))
            verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=verify_tls) as client:
                for url in candidates:
                    engine._llm_redteam_done.add(_canon_url(url))
                    try:
                        res = await redteam_endpoint(
                            client, url,
                            oast_client=getattr(engine, "oast_client", None),
                            deep=True,
                            enable_dow=(os.getenv("AI_REDTEAM_DOW", "0") == "1"),
                            family_priors=getattr(engine, "_ai_family_priors", None),
                        )
                    except Exception as e:
                        logger.debug(f"LLM red-team probe hatası ({url}): {e}")
                        continue
                    engine._ai_tested_cum.update(res.get("tested_kinds") or [])
                    if not res.get("is_llm"):
                        continue
                    saw_llm = True
                    # OAST token'ları engine'de kayıtlı kalır; tur-sonu _poll_oast_callbacks
                    # ai_tool/ai_output marker'larını confirmed kanıt olarak yayınlar.
                    for f in res.get("findings", []):
                        engine._ai_findings_cum.append(f)
                        # HAFIZA (experience replay): generate-and-verify aile istatistiğini
                        # birik. "Hangi strateji işe yarıyor" (builtin/corpus/…) sonraki turların
                        # önceliğini besler — model eğitmeden öğrenme.
                        _smp = f.get("sampling") or {}
                        for _fam, _st in (_smp.get("family_stats") or {}).items():
                            _slot = engine._ai_sampling_cum.setdefault(
                                _fam, {"tried": 0, "wins": 0})
                            _slot["tried"] += int(_st.get("tried", 0))
                            _slot["wins"] += int(_st.get("wins", 0))
                        tier = f.get("confidence_tier") or "unconfirmed"
                        sev = str(f.get("severity") or "info").lower()
                        # KANONİK owasp_llm (2025): bulgunun emit ettiği alan eski numaralandırmada
                        # olabilir (tool_abuse→LLM08); compliance_map 'kind'den düzeltir. Böylece
                        # bulgu olayı ile attestation kartı AYNI sınıfı gösterir. Non-kritik: hata → eski.
                        try:
                            from .compliance_map import map_finding as _map_f
                            _owasp = _map_f(f).get("owasp_llm") or f.get("owasp_llm")
                        except Exception:
                            _owasp = f.get("owasp_llm")
                        fp = f"llm_redteam|{f.get('title','')[:50]}|{_canon_url(url)}"
                        ev = Evidence(
                            title=f.get("title") or "LLM bulgusu", severity=sev, cve=None,
                            target=url, proof=f.get("proof") or "", tool="llm_redteam",
                            step=engine.step, mitre=f.get("mitre") or f.get("atlas"),
                            cwe=f.get("cwe") or [],
                            verified=True if tier == "confirmed" else None,
                            verification_method="llm-injection-marker" if tier == "confirmed" else None,
                            verification_detail=(f.get("proof") or "")[:200] if tier == "confirmed" else None,
                            confidence_tier=tier,
                        )
                        if engine.graph.add_evidence(ev, fp) and tier in ("confirmed", "probable"):
                            await narrate(
                                ScanEventType.CRITICAL_FINDING,
                                f"⚔️ AI red-team: {f.get('title')}",
                                {"title": f.get("title"), "target": url, "severity": sev,
                                 "confidence_tier": tier, "tool": "llm_redteam",
                                 "atlas": f.get("atlas"), "owasp_llm": _owasp},
                            )
        except Exception as e:
            logger.info(f"LLM red-team atlandı (best-effort, scan={session.scan_id}): {e}")

        # HAFIZA YAZIMI (experience replay): bu turda öğrenilen AİLE DELTASINI global
        # istatistiğe ekle (kümülatif snapshot'tan fark — tur birden çok kez çalışsa da çift
        # saymaz). Best-effort; DB yoksa sessiz. Sonraki taramaların prior'ını bu besler.
        try:
            from core.db import db as _sdb2
            from .sampling_memory import record_family_outcomes, family_delta
            _cur = getattr(engine, "_ai_sampling_cum", {}) or {}
            _delta = family_delta(_cur, getattr(engine, "_ai_sampling_recorded", {}) or {})
            if _delta:
                record_family_outcomes(_sdb2, _delta)
                engine._ai_sampling_recorded = {f: dict(s) for f, s in _cur.items()}
        except Exception as _sme:
            logger.debug(f"AI sampling hafıza yazımı atlandı: {_sme}")

        # UYUM & GÜVENCE (attestation): AI yüzeyi test edildiyse OWASP LLM Top-10 (2025) +
        # MITRE ATLAS + NIST AI RMF + EU AI Act durum tablosunu deterministik üret. En kritik
        # kısım TERS-KAPSAMA: "neyi test etmedik"i (not_tested/not_reachable) kanıtıyla raporlar
        # — denetçi/EU AI Act için satılabilir güvence, piyasadaki AI tarayıcıları vermez.
        # KOŞUL: LLM doğrulandı VEYA en az bir AI/agent yolu bulundu. İkincisinde LLM teyit
        # edilememiştir → sınıflar 'not_tested' çıkar (dürüst kapsam boşluğu), panel kaybolmaz.
        if saw_llm or ai_paths_found:
            try:
                from .compliance_map import attest_coverage
                attestation = attest_coverage(
                    engine._ai_findings_cum, engine._ai_tested_cum, ai_surface=True)
                # LLM baseline echo ile doğrulanamadıysa açıkça işaretle (denetçi/operatör görsün).
                attestation["llm_confirmed"] = bool(saw_llm)
                if not saw_llm:
                    attestation["note_llm"] = (
                        "AI/agent yolu bulundu ancak LLM baseline echo ile doğrulanamadı "
                        "(sertleştirilmiş veya LLM değil) — erişilebilir sınıflar test EDİLEMEDİ.")
                root = engine.graph.nodes.get(engine.graph.root_id)
                if root is not None:
                    root.meta["ai_compliance_attestation"] = attestation
                # KALICILAŞTIR: session.ai_analysis → /api/v2/scan/{id} ile frontend'e akar
                # (ComplianceAttestationPanel bunu tüketir). Küçük/deterministik → BSON riski yok.
                if session.ai_analysis is None:
                    session.ai_analysis = {}
                session.ai_analysis["compliance_attestation"] = attestation
                # HAFIZA (experience replay): generate-and-verify aile-kazanma istatistiği →
                # rapor/UI + sonraki turların aday önceliği (model eğitmeden öğrenme).
                _samp = getattr(engine, "_ai_sampling_cum", {}) or {}
                for _s in _samp.values():
                    _s["win_rate"] = round(_s["wins"] / _s["tried"], 3) if _s.get("tried") else 0.0
                if _samp:
                    if root is not None:
                        root.meta["ai_sampling"] = _samp
                    session.ai_analysis["ai_sampling"] = _samp
                    attestation["sampling"] = _samp  # UI paneli aile kazanma oranını gösterir
                self._update_session(session)
                eu = attestation.get("eu_ai_act", {})
                _prefix = "" if saw_llm else "AI yolu bulundu, LLM doğrulanamadı — "
                await narrate(
                    ScanEventType.AGENT_OBSERVATION,
                    (f"🛡️ {_prefix}AI uyum güvencesi (OWASP LLM 2025 / EU AI Act Art.15): duruş="
                     f"{eu.get('posture')} · test-edilmeyen="
                     f"{','.join(eu.get('gaps_not_tested') or []) or '—'}"),
                    {"ai_compliance_attestation": attestation}, persist_data={},
                )
            except Exception as _ce:
                logger.debug(f"AI uyum attestation atlandı: {_ce}")

    async def _probe_race_condition(self, session: PipelineSession, engine, narrate):
        """BANKACILIK & FINTECH: Eşzamanlılık / Race Condition (CWE-362) probu.
        İşbank İşim / İşim Kolay gibi uygulamalarda durum-değiştirici finansal uçlarda
        (transfer, pay, coupon, limit, bakiye vb.) kilit / idempotency kontrolü yoklar.
        Tahribatsız: güvenli parametrelerle çoklu senkron istek atar.
        Gate: RACE_PROBE=1 (varsayılan), recon'da çalışmaz."""
        if os.getenv("RACE_PROBE", "1") != "1":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        from .race_probe import is_financial_target, probe_race_condition
        from .autonomous_engine import Evidence
        from .attack_graph import _canon_url

        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        probed: set = root.meta.setdefault("race_probed_urls", set())
        endpoints = root.meta.get("endpoints") or []
        financial_cands = [
            u for u in endpoints
            if isinstance(u, str) and u.startswith(("http://", "https://"))
            and u not in probed and is_financial_target(u)
        ][:4]  # Bütçe koruması: her turda en fazla 4 uç

        if not financial_cands:
            return

        headers = _parse_auth_dict_to_headers(session.auth)
        timeout = float(os.getenv("RACE_PROBE_TIMEOUT", "12.0"))
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
                for target_url in financial_cands:
                    probed.add(target_url)
                    root.meta["race_probed"] = True
                    verdict = await probe_race_condition(target_url, client, burst_count=8, headers=headers)
                    if verdict.is_vulnerable:
                        sev = "high"
                        ev = Evidence(
                            title=verdict.title,
                            severity=sev,
                            cve=None,
                            target=target_url,
                            proof=verdict.detail,
                            tool="race_probe",
                            step=engine.step,
                            cwe=["CWE-362"],
                            mitre="T1190",
                            verified=True if verdict.confidence_tier == "confirmed" else None,
                            verification_method="concurrency-burst",
                            verification_detail=verdict.detail,
                            confidence_tier=verdict.confidence_tier,
                        )
                        fp = f"race|{_canon_url(target_url)}"
                        if engine.graph.add_evidence(ev, fp):
                            await narrate(
                                ScanEventType.CRITICAL_FINDING if verdict.confidence_tier == "confirmed"
                                else ScanEventType.VULNERABILITY_FOUND,
                                f"⚡ Finansal Yarış Durumu (Race Condition) [{verdict.confidence_tier.upper()}]: {target_url}",
                                {
                                    "title": verdict.title,
                                    "target": target_url,
                                    "severity": sev,
                                    "confidence_tier": verdict.confidence_tier,
                                    "detail": verdict.detail,
                                    "tool": "race_probe"
                                }
                            )
        except Exception as e:
            logger.debug(f"Race condition probu hatası: {e}")

    async def _poll_oast_callbacks(self, session: PipelineSession, engine, narrate):
        """OAST CALLBACK DİNLEYİCİSİ: Arka plandaki asenkron kuyruk / worker servislerinden
        (Kafka, RabbitMQ, IBM MQ) dönen DNS/HTTP etkileşimlerini yoklar ve kanıt kaydeder."""
        if not hasattr(engine, "oast_client") or engine.oast_client is None:
            return
        from .autonomous_engine import Evidence

        try:
            hits = await engine.oast_client.poll_interactions()
            if not hits:
                return

            root = engine.graph.nodes.get(engine.graph.root_id)
            if root:
                root.meta["oast_probed"] = True
                root.meta["oast"] = engine.oast_client.summary()

            seen_callbacks: set = getattr(engine, "_seen_oast_callbacks", set())
            setattr(engine, "_seen_oast_callbacks", seen_callbacks)

            for hit in hits:
                if hit.full_id in seen_callbacks:
                    continue
                seen_callbacks.add(hit.full_id)

                sev = "critical" if hit.marker in ("rce", "xxe") else "high"
                if hit.marker == "ai_tool":
                    title = "AI Red-Team: LLM Tool Abuse → OAST callback"
                    _cwe = ["CWE-1426", "CWE-918"]
                    _atlas = "AML.T0050"
                elif hit.marker == "ai_output":
                    title = "AI Red-Team: LLM Output Handling → SSRF (OAST callback)"
                    _cwe = ["CWE-1426", "CWE-918"]
                    _atlas = "AML.T0040"
                else:
                    title = f"Kör Zafiyet (OAST {hit.protocol.upper()} Callback): {hit.marker.upper()}"
                    _cwe = (["CWE-918"] if hit.marker == "ssrf"
                            else ["CWE-611"] if hit.marker == "xxe" else ["CWE-78"])
                    _atlas = None
                proof = (
                    f"OAST sunucusuna {hit.protocol.upper()} geri araması ulaştı. "
                    f"Kaynak Backend IP: {hit.remote_address}, Token: {hit.full_id}"
                )
                ev = Evidence(
                    title=title,
                    severity=sev,
                    cve=None,
                    target=session.target,
                    proof=proof,
                    tool=f"{hit.marker}-oast",
                    step=engine.step,
                    verified=True,
                    verification_method=f"oast-{hit.protocol}",
                    verification_detail=proof,
                    confidence_tier="confirmed",
                    mitre=_atlas,
                    cwe=_cwe
                )
                fp = f"oast|{hit.marker}|{hit.full_id}"
                if engine.graph.add_evidence(ev, fp):
                    await narrate(
                        ScanEventType.CRITICAL_FINDING,
                        f"🚨 OAST KÖR ZAFİYET TEYİT EDİLDİ [{hit.marker.upper()}]: Kaynak IP: {hit.remote_address}",
                        {
                            "title": title,
                            "severity": sev,
                            "confidence_tier": "confirmed",
                            "remote_address": hit.remote_address,
                            "protocol": hit.protocol,
                            "tool": f"{hit.marker}-oast"
                        }
                    )
        except Exception as e:
            logger.debug(f"OAST poll hatası: {e}")

    async def _enrich_fingerprint(self, session: PipelineSession, engine, narrate):
        """WAPPALYZER PARMAK-İZİ: taranan web yüzeyini ProjectDiscovery wappalyzergo motoruyla
        (binlerce GÜNCEL Wappalyzer imzası; isim/sürüm/kategori/CPE) tanımlar. NEDEN: elle
        bakımı çürüyen 142-imzalık Rust tespiti yerine kiralık motor+veri → kimlik omurgası
        tutarlı ve güncel kalır (bakım = servis imajının `go get -u`'su).

        İki yönlü tüketim:
          1) root.meta['technologies']'e MERGE → cpe_intel/target_profile/appraise besleyici
             (motor KARARINA girer; UI ile aynı tek kaynak → 'tutarlılık').
          2) session.ai_analysis['fingerprint']'e zengin biçim (kategori/sürüm/CPE) → UI
             'Parmak İzi' modalı bunu okur (reconnect-dayanıklı, summary'den de gider).

        Degrade-safe: servis kapalı/erişilemez → sessizce atlar; mevcut header/Rust sezgisi
        kural-fallback olarak kalır (doktrin §6). Bayrak: WAPPALYZER_INTEL (vars. açık).
        SPA sinerjisi: crawler render-DOM'u root.meta['rendered_html']'de varsa gövde olarak
        gönderilir (JS-render isabeti); yoksa servis URL'i kendi çeker."""
        if os.getenv("WAPPALYZER_INTEL", "1") != "1":
            return
        # TEK-ATIŞ: döngüde erken (motor kararını beslesin) VE finalize'da (güvenlik ağı)
        # çağrılır; bu bayrak ikisinin de en fazla bir kez gerçek istek atmasını sağlar —
        # hot-loop'u 18sn'lik çağrıyla her tur meşgul etmez.
        if getattr(engine, "_fingerprint_done", False):
            return
        root = engine.graph.nodes.get(engine.graph.root_id)
        if root is None:
            return
        target = (getattr(session, "target", "") or getattr(engine, "target", "") or "").strip()
        if not target:
            return
        engine._fingerprint_done = True  # gate'leri geçtik → bir kez dene (sonuç ne olursa)

        payload: Dict[str, Any] = {"url": target}
        # SPA sinerjisi (opsiyonel): crawler render ettiyse ham DOM'u besle → saf-HTTP'den iyi.
        rendered = root.meta.get("rendered_html")
        if isinstance(rendered, str) and rendered.strip():
            payload["html"] = rendered[:2_000_000]  # 2MB tavan (istek şişmesin)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(18.0, connect=6.0)) as client:
                r = await client.post(f"{FINGERPRINT_SERVICE_URL}/fingerprint", json=payload)
            if r.status_code != 200:
                logger.debug(f"fingerprint-service HTTP {r.status_code}")
                return
            data = r.json() or {}
        except Exception as e:
            logger.debug(f"fingerprint-service erişilemedi (degrade-safe): {e}")
            return

        techs = data.get("technologies") or []
        if not techs:
            return

        # 1) KİMLİK MERGE — root.meta['technologies'] string listesidir. İsimleri (varsa sürümle)
        # ekle; küçük-harf temel-ada göre tekilleştir (mevcut 'nginx' ile çift olmasın).
        existing = list(root.meta.get("technologies") or [])
        seen = {str(t).split(" ")[0].lower() for t in existing}
        added = 0
        for it in techs:
            if not isinstance(it, dict):
                continue
            name = (it.get("name") or "").strip()
            if not name:
                continue
            ver = (it.get("version") or "").strip()
            label = f"{name} {ver}".strip()
            if name.lower() not in seen:
                existing.append(label)
                seen.add(name.lower())
                added += 1
        root.meta["technologies"] = existing

        # 2) UI/rapor için zengin parmak-izi (kategori/sürüm/CPE korunur).
        fp = {
            "engine": data.get("engine") or "wappalyzergo",
            "count": data.get("count") or len(techs),
            "title": data.get("title") or "",
            "source": data.get("source") or "",
            "technologies": techs,
        }
        # TLS/IP İSTİHBARATI: sertifika SAN (ek yüzey) + sunucu grubu (IP'ler) + ana IP + CDN.
        # Aynı 'fingerprint' nesnesine gömülür → auto-scan rozet-modalı ile manuel kart AYNI
        # paylaşılan paneli kullandığından ikisinde de görünür (tek kaynak). Degrade-safe.
        try:
            from .tls_intel import grab_tls_intel
            fp["server_intel"] = await grab_tls_intel(session.target)
        except Exception as _tls_e:
            logger.debug(f"TLS/IP istihbaratı atlandı (best-effort, scan={session.scan_id}): {_tls_e}")
        if session.ai_analysis is None:
            session.ai_analysis = {}
        session.ai_analysis["fingerprint"] = fp

        await narrate(
            ScanEventType.AGENT_OBSERVATION,
            f"🔎 Parmak izi (wappalyzergo): {len(techs)} teknoloji tanımlandı"
            + (f", {added} yeni kimlik motora eklendi" if added else "")
            + (" [render-DOM]" if payload.get("html") else ""),
            {"fingerprint": fp},
        )

    async def _enrich_cve_intel(self, session: PipelineSession, engine, narrate):
        """vulnx (ProjectDiscovery PDCP) CVE İSTİHBARATI: bulunan CVE'ler için EPSS + KEV +
        **PoC var mı/kaç** + **hazır nuclei-template var mı** çeker → kev_intel'i (KEV+EPSS)
        PoC/template ekseniyle derinleştirir ("açık var" değil "şununla DOĞRULANABİLİR").

        GÖRÜNÜR degrade (doktrin: sessiz yutma yok): dakikalık limit dolarsa ilgili CVE'ler
        'bakılacaktı ama bakılamadı (rate_limit)' olarak UI'a taşınır. Keysiz çalışır (10/dk);
        ücretsiz PDCP_API_KEY limiti kaldırır. Best-effort; motoru DÜŞÜRMEZ."""
        if os.getenv("VULNX_INTEL", "1") != "1":
            return
        from .vulnx_intel import enrich_cves

        cves: List[str] = []
        for ev in (getattr(engine.graph, "evidence", None) or []):
            c = getattr(ev, "cve", None)
            if c:
                cves.append(c)
        for n in engine.graph.nodes.values():
            for c in ((n.meta or {}).get("cves") or []):
                if c:
                    cves.append(c)
        if not cves:
            return

        intel = await enrich_cves(cves, max_lookups=int(os.getenv("VULNX_MAX_LOOKUPS", "12")))
        if not intel.get("results") and not intel.get("skipped"):
            return
        if session.ai_analysis is None:
            session.ai_analysis = {}
        session.ai_analysis["cve_intel"] = intel

        n_ok = len(intel.get("checked", []))
        rl = [s["cve"] for s in intel.get("skipped", []) if s.get("reason") == "rate_limit"]
        msg = (f"🧠 CVE istihbaratı (vulnx): {n_ok} CVE zenginleştirildi "
               f"(EPSS/KEV/PoC/nuclei-template)")
        if rl:
            msg += (f" — ⚠️ RATE LIMIT: {len(rl)} CVE bakılacaktı ama bakılamadı "
                    f"(ücretsiz PDCP anahtarı ile limit kalkar)")
        await narrate(ScanEventType.AGENT_OBSERVATION, msg, {"cve_intel": intel})

    async def _record_asset_diff(self, session: PipelineSession, engine, dispatcher, narrate):
        """PORT & SERVİS VARLIK ENVANTERİ DELTA RADARI: Önceki tarama ile bu tarama arasındaki
        yeni açılan portları, değişen servisleri ve sertifikaları hesaplar ve kaydeder."""
        try:
            from core.db import db as _mdb
            from .asset_diff import (
                build_asset_snapshot, diff_asset_snapshots,
                save_asset_snapshot, load_latest_asset_snapshot
            )

            root = engine.graph.nodes.get(engine.graph.root_id)
            if not root:
                return

            ports_data = []
            open_ports = root.meta.get("open_ports") or []
            for p in open_ports:
                if isinstance(p, dict):
                    ports_data.append(p)
                elif isinstance(p, (int, str)) and str(p).isdigit():
                    ports_data.append({"port": int(p), "protocol": "tcp", "service": "unknown"})

            from .attack_graph import NodeType
            for n in engine.graph.nodes.values():
                if n.type == NodeType.PORT and isinstance(n.meta, dict):
                    port_num = n.meta.get("port")
                    if port_num and int(port_num) not in [x.get("port") for x in ports_data]:
                        ports_data.append({
                            "port": int(port_num),
                            "protocol": n.meta.get("protocol", "tcp"),
                            "service": n.meta.get("service", "unknown"),
                            "product": n.meta.get("product", ""),
                            "version": n.meta.get("version", ""),
                        })

            technologies = list(root.meta.get("technologies") or [])
            curr_snap = build_asset_snapshot(session.target, ports_data, technologies=technologies)

            mem_col = _mdb["scan_memories"] if _mdb is not None else None
            prev_snap = load_latest_asset_snapshot(mem_col, session.target) if mem_col is not None else None
            delta = diff_asset_snapshots(prev_snap, curr_snap)

            if session.ai_analysis is None:
                session.ai_analysis = {}
            session.ai_analysis["asset_diff"] = delta

            if mem_col is not None:
                save_asset_snapshot(mem_col, session.target, curr_snap)

            if delta.get("has_changes"):
                new_p = [f"{p['port']}/{p['protocol']}" for p in delta.get("new_ports", [])]
                msg = "📡 Varlık Radarı Değişimi: "
                if new_p:
                    msg += f"Yeni Açılan Portlar: {', '.join(new_p)} "
                if delta.get("changed_services"):
                    msg += f"| Değişen Servis: {len(delta['changed_services'])} "
                await narrate(
                    ScanEventType.AGENT_OBSERVATION,
                    msg,
                    {"asset_diff": delta}
                )
        except Exception as e:
            logger.debug(f"Asset diff kaydedilemedi: {e}")

    # ============== WAF Parmak İzi (keşif-sonrası, host-bazlı) ==============

    def _web_origins_for_waf(self, engine) -> List[str]:
        """Grafta WEB işareti taşıyan host'ları (bare host/IP) döndür — WAF fingerprint hedefi.

        Sinyal: yalnız 'web uygulaması doğrulandı' dalında seed edilen kenarlar (crawl,
        nuclei-dast, nuclei-cve_sweep). pathprobe iç DB host'larına da raid ettiği için
        onu KAYNAK ALMAYIZ (yanlış "web host" üretmesin). scan_target verilmişse per-host
        origin odur; yoksa kök hedef."""
        origins: List[str] = []
        seen: set = set()
        for e in engine.graph.edges.values():
            web_edge = (e.tool == "crawl") or (
                e.tool == "nuclei" and (e.options.get("dast") or e.options.get("cve_sweep")))
            if not web_edge:
                continue
            # SCOPE KAPISI (Hata 2 düzeltmesi): post-observe web probları (WAF/resilience/WP)
            # skorlu döngüyle AYNI co-hosted kapısına uymalı. Aksi halde strict scope'ta
            # onaysız (üçüncü-parti/paylaşımlı-hosting) co-hosted host'lar bu listeden sızıp
            # aktif problanıyordu — kenar var diye (koşmasa/onaysız olsa bile). IP hedefte
            # _cohosted_blocked zaten False döner (sahiplik) → kendi vhost'ların taranır.
            try:
                if engine._cohosted_blocked(e):
                    continue
            except Exception:
                pass
            tgt = e.options.get("scan_target") or engine.target
            if tgt and tgt not in seen:
                seen.add(tgt)
                origins.append(tgt)
        return origins

    async def _fingerprint_waf_origin(self, session: PipelineSession, engine, narrate,
                                      client, tgt: str, active: bool):
        """Tek bir web origin'i WAF için parmak izle (PAYLAŞILAN çekirdek — hem keşif-sonrası
        adım hem hipotez doğrulama buradan geçer). Sonuç engine.waf_by_origin'de host
        anahtarıyla önbelleklenir (None dahil → aynı host tekrar denenmez). İlk TANINAN
        (unknown olmayan) profil engine.waf_profile'a yazılır; payload_mutator onu kullanır."""
        if os.getenv("POC_WAF_DETECT", "1") != "1":
            return None
        from urllib.parse import urlsplit
        from .waf_detect import detect_waf
        raw = tgt if "://" in tgt else f"http://{tgt}"
        host_key = urlsplit(raw).netloc or tgt
        if host_key in engine.waf_by_origin:
            return engine.waf_by_origin[host_key]
        # https tercih (modern hedef); tanınmazsa http. tgt zaten şemalıysa o şema öncelikli.
        orig_scheme = urlsplit(tgt).scheme if "://" in tgt else ""
        if orig_scheme:
            scheme_order = [orig_scheme, "http" if orig_scheme == "https" else "https"]
        else:
            scheme_order = ["https", "http"]
        prof = None
        used_base = None
        for scheme in scheme_order:
            base = f"{scheme}://{host_key}/"
            used_base = base
            try:
                prof = await detect_waf(base, client, active=active)
            except Exception as _e:
                logger.debug(f"WAF fingerprint hata ({base}): {_e}")
                prof = None
            if prof is not None:
                break
        engine.waf_by_origin[host_key] = prof   # None da işaretlenir → tekrar deneme yok
        if prof is None:
            return None
        # İlk gerçek profil → mutator'ın kullandığı birincil profil.
        if engine.waf_profile is None:
            engine.waf_profile = prof
        # APT Stealth Controller'ı WAF tespitine göre güncelle
        if hasattr(engine, "stealth_controller") and engine.stealth_controller:
            was_active = engine.stealth_controller.is_active
            engine.stealth_controller.update_waf_vendor(prof.vendor, prof.blocked_probe)
            if not was_active and engine.stealth_controller.is_active:
                await narrate(
                    ScanEventType.AGENT_THINKING,
                    f"🛡️ Banka/Kurumsal WAF ({prof.vendor.upper()}) tespit edildi — "
                    f"APT Gizlilik Kipi ve Dinamik Jitter devrede, IP banlanması engelleniyor.",
                    engine.stealth_controller.summary(),
                )
        # Session'a kalıcı yaz — /api/v2/scan/{id} ile UI'a gider (reconnect dayanıklı).
        if session.ai_analysis is None:
            session.ai_analysis = {}
        session.ai_analysis.setdefault("waf_by_host", {})[host_key] = {
            **prof.to_dict(), "origin": used_base}
        # BİRİNCİL özet 'waf' alanı YALNIZ HEDEFİN KENDİ origin'inden gelir. Neden: aynı IP'de
        # barınan CO-HOSTED/komşu domain Cloudflare arkasında olabilir; onun WAF'ını hedefe
        # atfetmek yanıltıcıdır (kullanıcı şikayeti: "IP'de Cloudflare yok ama CF diyor" — kaynak
        # co-hosted domaindi). Komşu WAF'lar yalnız waf_by_host'ta kalır; host bilgisi eklenir ki
        # UI "Cloudflare @ <host>" diye atfetsin. engine.waf_profile (mutator) davranışı korunur.
        _target_host = self._bare_host(engine.target)
        if prof.vendor != "unknown" and host_key == _target_host and not session.ai_analysis.get("waf"):
            session.ai_analysis["waf"] = {**prof.to_dict(), "host": host_key}
        self._update_session(session)
        await narrate(
            ScanEventType.AGENT_OBSERVATION,
            f"🛡️ WAF tespit edildi ({host_key}): {prof.vendor} "
            f"(güven {prof.confidence:.2f})"
            + (" — aktif tetik bloklandı" if prof.blocked_probe else "")
            + (", vendor-profilli mutasyon devrede" if prof.vendor != "unknown" else ""),
            {"waf": prof.to_dict(), "host": host_key, "origin": used_base},
        )
        return prof

    async def _maybe_fingerprint_waf(self, session: PipelineSession, engine, narrate):
        """KEŞİF-SONRASI WAF PARMAK İZİ — grafta web işareti taşıyan HER host için (kök +
        keşfedilen subdomain/origin). Eskiden WAF yalnız hipotez-doğrulama yolunda, tek host
        için bakılırdı → standart taramada o yola nadiren gelinip WAF HİÇ görünmüyordu.
        Artık recon bir web host çıkarır çıkarmaz bağımsız çalışır (döngüde observe sonrası).
        Keşif seviyesinde yalnız PASİF (active=False); Standart+ seviyede zararsız aktif
        tetik. POC_WAF_DETECT=0 kapatır. Hata → sessiz (motor bozulmaz — WAF opsiyonel katman)."""
        if os.getenv("POC_WAF_DETECT", "1") != "1":
            return
        origins = self._web_origins_for_waf(engine)
        todo = [o for o in origins if o not in engine.waf_by_origin]
        if not todo:
            return
        max_hosts = int(os.getenv("POC_WAF_MAX_HOSTS", "6"))
        remaining = max_hosts - len(engine.waf_by_origin)
        if remaining <= 0:
            return
        active = engine.level.name != "recon"
        timeout = float(os.getenv("POC_VERIFY_HTTP_TIMEOUT", "20"))
        verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                         verify=verify_tls) as client:
                for tgt in todo[:remaining]:
                    try:
                        await self._fingerprint_waf_origin(
                            session, engine, narrate, client, tgt, active)
                    except Exception as _e:
                        logger.debug(f"WAF fingerprint atlandı ({tgt}): {_e}")
        except Exception as _e:
            logger.debug(f"WAF fingerprint client hatası: {_e}")

    # OSINT lookup'larında API-anahtarı hatası imzaları (küçük harf karşılaştırılır).
    _OSINT_AUTH_ERROR_MARKERS = (
        "401", "403", "unauthorized", "forbidden", "api key", "apikey", "api_key",
        "invalid key", "authentication", "kimlik doğrulama", "yetkisiz",
    )

    async def _maybe_warn_osint_auth(self, stage, result, narrate):
        """SESSİZ HATA GÖRÜNÜRLÜĞÜ (K7/K8 deseni): OSINT 'completed' görünüp içeride
        lookup'lar API-anahtarı hatası (401/403) ile boş dönüyorsa operatöre AÇIK uyarı ver.
        Aksi halde 'osint tamamlandı' satırının arkasında 'eksik key → boş veri' gizlenir ve
        kullanıcı bunu 'tarama boş' olarak yaşar. Yalnız görünürlük — motoru etkilemez."""
        if stage.tool != "osint" or result.status != "completed":
            return
        data = result.data or {}
        auth_failed, total = [], 0
        for lookup, res in data.items():
            if not isinstance(res, dict):
                continue
            total += 1
            err = str(res.get("error") or "").lower()
            if err and any(m in err for m in self._OSINT_AUTH_ERROR_MARKERS):
                auth_failed.append(lookup)
        if not auth_failed:
            return
        try:
            await narrate(
                ScanEventType.WARNING,
                f"🔑 OSINT: {len(auth_failed)}/{total} kaynak API-anahtarı hatası ile boş "
                f"döndü ({', '.join(auth_failed)}). Bu kaynaklar anahtarsız veri VERMEZ — "
                f"ilgili anahtarları .env'e ekleyin (ör. SHODAN_API_KEY, VIRUSTOTAL_API_KEY). "
                f"Ücretsiz InternetDB (keysiz) yine de denenir.",
                {"osint_auth_failed": auth_failed, "osint_total": total},
                persist_data={"osint_auth_failed": auth_failed, "osint_total": total},
            )
        except Exception as _e:
            logger.debug(f"OSINT auth uyarısı atlandı: {_e}")

    async def _verify_hypotheses(self, session: PipelineSession, engine, narrate):
        """PLAN B: LLM'in SOMUT saldırı hipotezlerini AKTİF doğrula → DeepSeek'i "araç seçici"den
        "saldırı fikri üreticisi"ne çıkarır. Kanıtlanan hipotez YENİ verified Evidence olur;
        kanıtlanamayan sessizce düşer (LLM hipotezi güvenilmez — deterministik kanıt zorunlu,
        halüsinasyon-güvenli hibrit).

        Kapılar (_verify_new_evidence ile AYNI bütçe + davetsiz agresiflik önlemi):
        - POC_VERIFY_ENABLED / recon seviyesi / POC_VERIFY_MAX cap.
        - Onay kapısı AÇIKSA (AUTONOMOUS_REQUIRE_RECON_APPROVAL=true) ve hâlâ recon fazındaysak
          doğrulama YAPILMAZ — hipotezler kuyrukta kalır, sömürü onayından sonra çalışır."""
        if os.getenv("POC_VERIFY_ENABLED", "true").lower() != "true":
            return
        if str(getattr(session, "level", "") or "").lower() == "recon":
            return
        # Onay gerekiyorsa ve daha sömürü fazına geçilmediyse aktif doğrulama yapma (yetki kapısı).
        if REQUIRE_RECON_APPROVAL and getattr(engine, "phase", "exploit") == "recon":
            return
        # KURAL-TOHUMU (doktrin: LLM opsiyonel): keşfedilen endpoint'lerden deterministik
        # hipotez üret — LLM hiç hipotez vermemiş olsa bile doğrulayıcılar beslenir.
        # LLM hipotezleriyle aynı kuyruk + aynı verifier; kanıt zorunluluğu değişmez.
        # P0-B: graffaki formlar (HTML POST) ve OpenAPI matrisi de tohum kaynağıdır.
        try:
            root_meta = engine.graph.nodes[engine.graph.root_id].meta
            endpoints = engine.graph.compact_state().get("endpoints") or []
            p_b_forms = root_meta.get("forms")
            p_b_api = root_meta.get("openapi_endpoints")
            seeded = engine.seed_rule_hypotheses(endpoints, forms=p_b_forms,
                                                  api_endpoints=p_b_api)
            if seeded:
                logger.info(f"🌱 [{session.scan_id[:8]}] Kural-tohumu: {seeded} deterministik hipotez kuyruğa eklendi.")
        except Exception as _seed_e:
            logger.debug(f"Kural-tohumu atlandı: {_seed_e}")
        hyps = engine.consume_hypotheses()
        if not hyps:
            return
        # KAPSAM SON-KAPISI (defense-in-depth): gerçek HTTP isteğinden HEMEN önce, hedef host'u
        # engagement kapsamı dışında kalan her hipotezi ele. parse_hypotheses zaten LLM yolunu
        # süzüyor; bu kapı tohum + adaptif-retry dahil TÜM yolları I/O sınırında garanti eder
        # (dış-kutudan yetkisiz/metadata hedefine istek asla gitmesin).
        try:
            from .attack_hypothesis import _host_in_scope
            _scope = engine._scope_hosts()
            before = len(hyps)
            hyps = [h for h in hyps if _host_in_scope(h.url, _scope)]
            dropped = before - len(hyps)
            if dropped:
                logger.warning(f"🚫 [{session.scan_id[:8]}] Kapsam-dışı {dropped} hipotez elendi (host allowlist).")
                await narrate(
                    ScanEventType.AGENT_OBSERVATION,
                    f"🚫 {dropped} hipotez kapsam dışı host hedeflediği için elendi "
                    f"(yetkisiz/off-target istek engellendi)",
                    {"scope_dropped": dropped}, persist_data={},
                )
        except Exception as _sc_e:
            logger.debug(f"Kapsam son-kapısı atlandı: {_sc_e}")
        if not hyps:
            return
        # BAŞARISIZLIK HAFIZASI: daha önce patlamış kalıpları kuyruktan ele — bütçe
        # tekrar denemelere harcanmasın (TTL'lidir; hedef düzeldiyse kayıt kendiliğinden düşer).
        _fail_keys: set = set()
        _mem = None
        if os.getenv("EXPLOIT_MEMORY", "1") == "1":
            try:
                from core.db import db as _mdb
                _mem = _mdb["scan_memories"] if _mdb is not None else None
                if _mem is not None:
                    from .exploit_memory import load_failed_patterns, failure_key_tuple
                    _fail_keys, _fail_lines = load_failed_patterns(_mem, session.target)
                    if _fail_keys:
                        before = len(hyps)
                        hyps = [h for h in hyps
                                if failure_key_tuple(h.url, h.vuln_class, h.param) not in _fail_keys]
                        skipped = before - len(hyps)
                        if skipped:
                            await narrate(
                                ScanEventType.AGENT_OBSERVATION,
                                f"🔁 {skipped} hipotez başarısızlık hafızasından elendi "
                                f"(daha önce doğrulanamadı — bütçe korundu)",
                                {"skipped": skipped}, persist_data={},
                            )
            except Exception as _fm_e:
                logger.debug(f"Başarısızlık filtresi atlandı: {_fm_e}")
        if not hyps:
            return
        cap = int(os.getenv("POC_VERIFY_MAX", "15"))
        attempted = sum(1 for e in engine.graph.evidence if getattr(e, "verified", None) is not None)
        if attempted >= cap:
            return
        try:
            timeout = float(os.getenv("POC_VERIFY_HTTP_TIMEOUT", "20"))
            verify_tls = os.getenv("POC_VERIFY_TLS", "false").lower() == "true"
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=verify_tls) as client:
                # WAF FINGERPRINT: keşif-sonrası adım (_maybe_fingerprint_waf) çoğu web host'u
                # ZATEN parmak izledi (engine.waf_by_origin önbelleği). Ama hipotezin hedefi
                # farklı bir origin olabilir → o origin de BİR KEZ parmak izlensin ki mutasyon
                # profili doğru duvarı görsün. Aynı paylaşılan helper (host-bazlı dedup) çağrılır;
                # host zaten önbellekteyse anında döner. POC_WAF_DETECT=0 içeride ele alınır.
                if hyps:
                    await self._fingerprint_waf_origin(
                        session, engine, narrate, client, hyps[0].url, active=True)
                for hyp in hyps:
                    if attempted >= cap:
                        break
                    if hasattr(engine, "stealth_controller") and engine.stealth_controller:
                        await engine.stealth_controller.pace()
                    # BÜTÇE KAPAĞI: her BİRİNCİL doğrulama denemesi bütçeden düşer (POC_VERIFY_MAX).
                    # Bu satır olmadan sayaç yalnız WAF-retry dalında artıyordu → cap hiç tetiklenmez,
                    # 200 hipotez 15 yerine 200 kez canlı hedefe gider (istek amplifikasyonu).
                    attempted += 1
                    verdict = await verify_hypothesis(hyp, client, oast_client=getattr(engine, "oast_client", None))
                    if (not verdict.verified and not getattr(verdict, "skipped", False)
                            and engine.waf_profile is not None and attempted < cap):
                        # GENERATE-AND-VERIFY (Best-of-N) — AI-dışı sınıflar: duvar belli.
                        # Tek mutasyon denemesi yerine MUTASYON + CORPUS ailelerini ADAY yap,
                        # deterministik verifier KAZANANI seçsin. Aile kazanma istatistiği
                        # hafızaya yazılır (experience replay) → sonraki taramalarda öncelik.
                        try:
                            from .verifier_sampling import (Candidate, Verdict as _SV,
                                                            run_best_of_n)
                            from .payload_mutator import mutation_plan
                            _learned: list = []
                            if _mem is not None:
                                try:
                                    from .exploit_memory import load_waf_bypass_order
                                    _learned = load_waf_bypass_order(
                                        _mem, engine.waf_profile.vendor, hyp.vuln_class)
                                except Exception:
                                    pass
                            _cands: list = []
                            _plan = mutation_plan(engine.waf_profile.vendor, hyp.vuln_class,
                                                  _learned)
                            if _plan:
                                _cands.append(Candidate("mutation", "mutation", _plan, prior=0.6))
                            try:
                                from .payload_corpus import retry_payloads as _corpus_retry
                                _cp = _corpus_retry(hyp.vuln_class)
                                if _cp:
                                    _cands.append(Candidate("corpus", "corpus", _cp, prior=0.4))
                            except Exception:
                                pass
                            if _cands:
                                async def _v(c):
                                    if c.family == "mutation":
                                        _rv = await verify_hypothesis(hyp, client,
                                                                      mutations=c.payload)
                                    else:
                                        from .verification import verify_adaptive
                                        _rv = await verify_adaptive(hyp.url, hyp.param,
                                                                    hyp.vuln_class, c.payload, client)
                                    return _SV(bool(getattr(_rv, "verified", False)),
                                               float(getattr(_rv, "confidence", 0.0) or 0.0),
                                               getattr(_rv, "detail", "") or "",
                                               finding={"v": _rv})
                                _n = int(os.getenv("VERIFIER_SAMPLING_N", "3"))
                                _sres = await run_best_of_n(_cands, _v, _n, early_exit=True,
                                                            dedup_key=lambda c: c.family)
                                attempted += _sres.tried
                                # HAFIZA: aile kazanma istatistiği (experience replay).
                                try:
                                    from core.db import db as _sdb3
                                    from .sampling_memory import record_family_outcomes
                                    if _sdb3 is not None and _sres.family_stats:
                                        record_family_outcomes(_sdb3, _sres.family_stats)
                                except Exception:
                                    pass
                                if _sres.winner and _sres.winner_verdict:
                                    _wv = _sres.winner_verdict.finding.get("v")
                                    if _wv is not None and getattr(_wv, "verified", False):
                                        verdict = _wv
                                        if (_sres.winner.family == "mutation"
                                                and getattr(_wv, "mutation", None)):
                                            await narrate(
                                                ScanEventType.AGENT_OBSERVATION,
                                                f"🛡️→🔓 WAF AŞILDI: {engine.waf_profile.vendor} "
                                                f"duvarı '{_wv.mutation}' mutasyonuyla geçildi "
                                                f"({hyp.vuln_class} @ {hyp.url})",
                                                {"vendor": engine.waf_profile.vendor,
                                                 "mutation": _wv.mutation,
                                                 "vuln_class": hyp.vuln_class, "url": hyp.url},
                                            )
                        except Exception as _retry_e:
                            logger.debug(f"Verifier-sampling retry atlandı: {_retry_e}")
                    if not verdict.verified:
                        # FAQ 1.6: test EDİLEMEDİ (parametre yok / doğrulayıcı yok) → tried-and-
                        # failed DEĞİL. Başarısızlık hafızasına YAZMA (kalıp 'bu batar' diye
                        # elenmesin) — aksi halde skipped ↔ failed sessizce tur dönerdi.
                        if getattr(verdict, "skipped", False):
                            await narrate(
                                ScanEventType.AGENT_OBSERVATION,
                                f"🧠→⏭️ LLM hipotezi test EDİLEMEDİ (yapısal skip): "
                                f"{hyp.vuln_class.upper()} @ {hyp.url} — {verdict.detail}",
                                {"hypothesis": hyp.url, "vuln_class": hyp.vuln_class,
                                 "skipped": True}, persist_data={},
                            )
                            continue
                        # Başarısızlığı TTL'li hafızaya yaz — bu kalıp bir sonraki
                        # taramada (ve bu taramanın kalan turlarında) tekrar DENENMESİN.
                        if _mem is not None:
                            try:
                                from .exploit_memory import record_failed_hypothesis
                                record_failed_hypothesis(
                                    _mem, target=session.target,
                                    vuln_class=hyp.vuln_class, url=hyp.url,
                                    param=hyp.param, method=verdict.method)
                            except Exception as _rf_e:
                                logger.debug(f"Başarısızlık kaydı atlandı: {_rf_e}")
                        await narrate(
                            ScanEventType.AGENT_OBSERVATION,
                            f"🧠→❌ LLM hipotezi doğrulanamadı: {hyp.vuln_class.upper()} @ {hyp.url}",
                            {"hypothesis": hyp.url, "vuln_class": hyp.vuln_class, "verified": False},
                            persist_data={},  # negatif teyit düşük değerli — timeline'ı şişirme
                        )
                        continue
                    # Başlık/severity/CWE sınıf-bazlı tablodan (§5.0-2) — önceden SQLi'ye
                    # hardcoded'du; yeni sınıf yanlış etiketlenmesin diye metadata haritası.
                    _meta = evidence_meta_for(hyp.vuln_class)
                    _param_lbl = hyp.param or "parametre"
                    _title = (_meta["title"].replace("{param}", _param_lbl)
                              .replace("{url}", hyp.url).replace("{class}", hyp.vuln_class))
                    # AI/LLM sınıfları için KADEME doktrini: kanıt deterministik olsa bile
                    # probable-tavanlı sınıflar (system-prompt leak, çıktı-HTML) confirmed'a
                    # yükselmesin. Diğer sınıfların davranışı değişmez (None → türetilir).
                    _vc = str(getattr(hyp, "vuln_class", "") or "")
                    _ai_tier: Optional[str] = None
                    if _vc in ("prompt_injection", "indirect_prompt_injection", "multiturn_jailbreak"):
                        _ai_tier = "confirmed"
                    elif _vc in ("system_prompt_leak", "output_handling", "denial_of_wallet"):
                        _ai_tier = "probable"
                    elif _vc in ("tool_abuse", "output_handling_ssrf"):
                        _ai_tier = "confirmed" if float(verdict.confidence or 0) >= 0.85 else "probable"
                    ev = Evidence(
                        title=_title,
                        severity=_meta["severity"], cve=None, target=hyp.url,
                        proof=("LLM istihbarat hipotezi → AKTİF PoC ile DOĞRULANDI. "
                               + verdict.detail
                               + (f" | LLM gerekçesi: {hyp.rationale}" if hyp.rationale else "")),
                        tool="poc_verify", step=engine.step, cwe=list(_meta["cwe"]),
                        mitre=_meta.get("mitre"),
                        verified=True, verification_method=verdict.method,
                        verification_detail=verdict.detail, verification_confidence=verdict.confidence,
                        confidence_tier=_ai_tier,
                    )
                    from .attack_graph import _canon_url
                    if not engine.graph.add_evidence(ev, f"poc_verify|{hyp.vuln_class}|{_canon_url(hyp.url)}|{hyp.param or ''}"):
                        continue  # aynı URL+parametre+sınıf zaten kanıtlanmış — mükerrer bulgu üretme
                    # FIELD-JOURNAL: kanıtlanan sömürüyü kalıcı derse çevir — sonraki
                    # taramaların LLM prompt'una geri beslenir (yalnız verified=True;
                    # kanıtlanamayan hipotez hafızayı KİRLETMEZ). Best-effort.
                    if os.getenv("EXPLOIT_MEMORY", "1") == "1":
                        try:
                            from core.db import db as _mdb
                            if _mdb is not None:
                                from .exploit_memory import record_verified_exploit, clear_failed_hypothesis
                                record_verified_exploit(
                                    _mdb["scan_memories"], target=session.target,
                                    vuln_class=hyp.vuln_class, url=hyp.url,
                                    param=hyp.param, method=verdict.method,
                                    confidence=verdict.confidence)
                                # Kalıp daha önce patlayıp şimdi tuttuysa başarısızlık
                                # kaydını kapat (hedef/koşullar değişmiş — iz kalsın).
                                clear_failed_hypothesis(
                                    _mdb["scan_memories"], url=hyp.url,
                                    vuln_class=hyp.vuln_class, param=hyp.param)
                                # WAF-bypass dersi: kanıt bir mutasyonla geldiyse kaydet —
                                # bu vendor'da bu mutasyon bir dahaki sefere ÖNCE denenir.
                                if getattr(verdict, "mutation", None) and engine.waf_profile:
                                    from .exploit_memory import record_waf_bypass
                                    record_waf_bypass(
                                        _mdb["scan_memories"],
                                        vendor=engine.waf_profile.vendor,
                                        vuln_class=hyp.vuln_class,
                                        mutation=verdict.mutation,
                                        target=session.target)
                        except Exception as _me:
                            logger.debug(f"Sömürü dersi kaydı atlandı: {_me}")
                    await narrate(
                        ScanEventType.CRITICAL_FINDING,
                        f"🧠→✅ LLM HİPOTEZİ KANITLANDI: {ev.title} — {verdict.detail}",
                        {"title": ev.title, "target": ev.target, "severity": ev.severity,
                         "verified": True, "method": verdict.method,
                         "confidence": verdict.confidence, "source": "llm_hypothesis"},
                    )
                    await emit_vulnerability_found(
                        session.scan_id, ev.title, ev.title, ev.severity, ev.target,
                    )
        except Exception as e:
            logger.warning(f"Hipotez doğrulama atlandı (best-effort, scan={session.scan_id}): {e}")

    async def _trigger_autonomous_report(self, session: PipelineSession, evidence: List[Any], summary: Dict[str, Any]):
        """Türkçe: Otonom tarama sonucu için AI rapor motorunu tetikler (canlı yol).
        Kanıtları serileştirir ve primitiflerle `_send_autonomous_report`'a devreder — böylece
        retry yolu (Mongo'dan yeniden kur) AYNI gönderim mantığını paylaşır."""
        # Kanıt Evidence objesi ya da (retry'de) dict olabilir — ikisini de tolere et.
        evidence_dicts = [e.to_dict() if hasattr(e, "to_dict") else e for e in evidence]
        # UYUM & GÜVENCE: attestation session'da tutulur; AI raporuna da taşı ki dışa aktarılan
        # raporda (LLM analizi + PDF) OWASP/ATLAS/EU AI Act durumu görünsün (yalnız UI'da kalmasın).
        _att = (getattr(session, "ai_analysis", None) or {}).get("compliance_attestation")
        if _att and isinstance(summary, dict):
            summary["compliance_attestation"] = _att
        await self._send_autonomous_report(
            session_id=session.session_id, scan_id=session.scan_id, target=session.target,
            level=session.level, stealth=session.stealth, profile_name=session.profile_name,
            stages=session.stages, evidence_dicts=evidence_dicts, summary=summary,
        )

    async def _send_autonomous_report(
        self, *, session_id: str, scan_id: str, target: str, level: Any, stealth: Any,
        profile_name: str, stages: Dict[str, Any], evidence_dicts: List[Dict[str, Any]],
        summary: Dict[str, Any],
    ):
        """Türkçe: AI rapor motorunu çağırır ve rapor-durumunu (pending→ok/failed) izler (§2.1).

        DİKKAT — entegrasyon sözleşmesi: AI servisinin `V2AnalysisRequest` şeması
        `scan_data: Dict` ZORUNLU tutar ve `scan_data["results"]`i {tool_name: tool_data}
        ŞEKLİNDE okur (statik pipeline sözleşmesi). Motorun düz kanıt+özetini AYNI şekle
        `build_autonomous_scan_results` ile çeviririz — aksi halde 'results' boş kalıp AI
        raporu motorun bulgularını HİÇ görmezdi (eski 'analizde patlama' hatası)."""
        # §2.1: rapor üretimi başladı — operatör "üretiliyor" görebilsin, sessizce kaybolmasın.
        self._set_report_status(session_id, "pending")
        try:
            scan_data_for_ai = {
                "mode": "autonomous",
                "session_id": session_id,
                "level": level,
                "stealth": stealth,
                "results": build_autonomous_scan_results(evidence_dicts, summary),
                "target": target,
                "profile": profile_name,
                # Üst-seviye alanlar geriye-uyum/gelecekteki tüketiciler için korunur (zararsız).
                "verified_vulnerabilities": summary.get("verified_vulnerabilities", []),
                "vulnerabilities": evidence_dicts,
                "findings": evidence_dicts,
                "open_ports": summary.get("open_ports", 0),
                "services_identified": summary.get("services_identified", []),
                "subdomains_found": summary.get("subdomains_found", 0),
                "attention_items": summary.get("attention_items", []),
                "closing_narrative": summary.get("closing_narrative", {}),
                "stages": stages,
                # AI uyum & güvence (OWASP LLM 2025 / ATLAS / NIST AI RMF / EU AI Act) — rapor
                # motoru + dışa aktarım tüketebilsin; yoksa None (geriye-uyumlu).
                "compliance_attestation": summary.get("compliance_attestation"),
            }
            payload = {"scan_id": scan_id, "target": target, "scan_data": scan_data_for_ai}
            async with httpx.AsyncClient(timeout=300.0) as client:
                resp = await client.post(f"{AI_SERVICE_URL}/brain/analyze/v2", json=payload)
                # Yanıtı GÖRMEZDEN GELME: 422/5xx sessizce yutulursa operatör "analiz gelmedi"
                # der ama neden bilmez. Hata varsa yüzeye çıkar (durum=failed + warning).
                resp.raise_for_status()
            self._set_report_status(session_id, "ok")
        except Exception as e:
            # Rapor motoru KRİTİK YOL DEĞİL (doktrin: tarama düşmez), ama başarısızlığı
            # GÖRÜNÜR olmalı — eski 'logger.debug' prod'da görünmüyordu ("sessiz patlama").
            # Durum 'failed'e yazılır → UI rozet + 'yeniden dene' düğmesi gösterir.
            logger.warning(f"Otonom AI raporu üretilemedi (scan_id={scan_id}): {e}")
            self._set_report_status(session_id, "failed", str(e))

    def _set_report_status(self, session_id: str, status: str, error: Optional[str] = None):
        """Türkçe: AI rapor durumunu (pending|ok|failed) session.ai_analysis'e yaz (§2.1).
        Aktif session bellekteyse oradan, değilse (tarama bitmiş) doğrudan Mongo'dan güncelle.
        UI bunu session status pollingiyle okuyup rozet/retry gösterir."""
        s = self._active_pipelines.get(session_id)
        if s is not None:
            if s.ai_analysis is None:
                s.ai_analysis = {}
            s.ai_analysis["report_status"] = status
            if error:
                s.ai_analysis["report_error"] = str(error)[:500]
            else:
                s.ai_analysis.pop("report_error", None)
            self._update_session(s)
            return
        col = self._get_sessions_collection()
        if col is not None:
            upd: Dict[str, Any] = {"ai_analysis.report_status": status}
            if error:
                upd["ai_analysis.report_error"] = str(error)[:500]
            try:
                col.update_one({"session_id": session_id}, {"$set": upd})
            except Exception as e:
                logger.debug(f"report_status persist atlandı ({session_id}): {e}")

    async def retry_autonomous_report(self, session_id: str) -> Optional[bool]:
        """Türkçe: Kullanıcı-tetiklemeli 'AI raporunu yeniden üret' (§2.1). Motor artık
        çalışmadığından kanıt+özet Mongo'dan yeniden kurulur (vulnerabilities koleksiyonu +
        session.ai_analysis) ve rapor arka planda tekrar gönderilir.
        Döner: True (tetiklendi) | None (session yok)."""
        status = self.get_session_status(session_id)
        if status is None:
            return None
        scan_id = status.get("scan_id") or ""
        target = status.get("target") or ""
        summary = status.get("ai_analysis") or {}
        stages = status.get("stages") or {}
        profile_name = status.get("profile") or ""

        evidence_dicts: List[Dict[str, Any]] = []
        coll = self._get_vulnerabilities_collection()
        if coll is not None and scan_id:
            try:
                evidence_dicts = list(coll.find(
                    {"scan_id": scan_id, "source": "autonomous"}, {"_id": 0}
                ))
            except Exception as e:
                logger.warning(f"Retry: kanıt Mongo'dan okunamadı ({scan_id}): {e}")

        asyncio.create_task(self._send_autonomous_report(
            session_id=session_id, scan_id=scan_id, target=target,
            level=summary.get("level", ""), stealth=summary.get("stealth", False),
            profile_name=profile_name, stages=stages, evidence_dicts=evidence_dicts,
            summary=summary,
        ))
        return True

    async def _wait_for_approval(self, session: PipelineSession, engine):
        """Kullanıcı onayı için asenkron bekleme. approve_exploit_phase() ile tetiklenir."""
        event = asyncio.Event()
        self._approval_events[session.session_id] = event
        self._approval_engines[session.session_id] = engine
        logger.info(f"🛡️ Onay bekleniyor: session={session.session_id} | target={session.target}")

        timeout = int(os.getenv("PHASE_GATE_TIMEOUT_SECONDS", "3600"))  # 1 saat varsayılan
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            logger.info(f"✅ Onay alındı: session={session.session_id} — sömürü fazı başlıyor")
            session.status = "running"
            self._update_session(session)
        except asyncio.TimeoutError:
            # Zaman aşımında motoru TEMİZ sonlandır: önceden yalnız log basılıp döngü
            # 'continue' ediyordu → session 'awaiting_approval'da KALICI takılıyor,
            # UI "onay bekleniyor"da donuyordu (bilinen 'bağlanıyor'da donma' üretim yolu).
            # engine.cancel() → döngü bir sonraki tur başında cancelled'ı görüp çıkar;
            # 'completed'a ezilmesin diye durumu burada 'cancelled' yazıyoruz (döngü sonu
            # engine.cancelled ise status'e dokunmaz — bkz. 2783-2785).
            logger.warning(f"⏰ Onay zaman aşımı: session={session.session_id} — otomatik durduruldu")
            session.status = "cancelled"
            self._update_session(session)
            try:
                await ScanEventBus.publish(ScanEvent(
                    scan_id=session.scan_id,
                    event_type=ScanEventType.WARNING,
                    source="phase_gate",
                    data={"message": ("⏰ Sömürü fazı onayı zaman aşımına uğradı — "
                                      "kuşatma güvenli şekilde sonlandırıldı. "
                                      "Keşif bulguları rapora yansıtıldı."),
                          "reason": "phase_gate_timeout"},
                ))
            except Exception:
                pass
            engine.cancel()
        finally:
            self._approval_events.pop(session.session_id, None)
            self._approval_engines.pop(session.session_id, None)

    def approve_exploit_phase(self, session_id: str) -> bool:
        """
        Kullanıcı sömürü fazını onayladı. PHASE_GATE'te bekleyen döngüyü devam ettirir.
        Döner: başarılı ise True, session bulunamaz/beklemezse False.
        """
        event = self._approval_events.get(session_id)
        engine = self._approval_engines.get(session_id)
        if event is None or engine is None:
            return False
        engine.approve_exploit_phase()
        event.set()
        return True

    def _build_execution_order(self, stages: List[StageDefinition]) -> List[List[StageDefinition]]:
        """
        Türkçe: Stage'leri çalışma sırasına göre grupla.
        Aynı parallel_group'a sahip olanlar birlikte çalışır.
        parallel_group=None olanlar sıralı çalışır.
        """
        groups: List[List[StageDefinition]] = []
        parallel_groups: Dict[str, List[StageDefinition]] = {}

        for stage in stages:
            if stage.parallel_group:
                if stage.parallel_group not in parallel_groups:
                    parallel_groups[stage.parallel_group] = []
                parallel_groups[stage.parallel_group].append(stage)
            else:
                # Önce bekleyen paralel grupları flush et
                # (sıralı stage'den önce paralel gruplar çalışmalı)
                groups.append([stage])

        # Paralel grupları ekle (stage listesindeki ilk görünüme göre sırala)
        # Yeniden yapılandır: stages sırasında paralel grupları doğru yere ekle
        result: List[List[StageDefinition]] = []
        seen_groups = set()

        for stage in stages:
            if stage.parallel_group:
                if stage.parallel_group not in seen_groups:
                    seen_groups.add(stage.parallel_group)
                    result.append(parallel_groups[stage.parallel_group])
            else:
                result.append([stage])

        return result

    def _save_session(self, session: PipelineSession):
        """MongoDB'ye session kaydet"""
        col = self._get_sessions_collection()
        if col is None:
            return
        try:
            doc = {
                "session_id": session.session_id,
                "scan_id": session.scan_id,
                "target": session.target,
                "profile_name": session.profile_name,
                "status": session.status,
                "created_at": session.created_at,
                "started_at": session.started_at,
                "completed_at": session.completed_at,
                "stages": session.stages,
                "ai_analysis": session.ai_analysis,
                "total_duration_seconds": session.total_duration_seconds,
                "error": session.error,
            }
            col.insert_one(doc)
        except Exception as e:
            logger.error(f"Session save error: {e}")

    def _update_session(self, session: PipelineSession):
        """MongoDB'de session güncelle"""
        col = self._get_sessions_collection()
        if col is None:
            return
        try:
            col.update_one(
                {"session_id": session.session_id},
                {"$set": {
                    "status": session.status,
                    "started_at": session.started_at,
                    "completed_at": session.completed_at,
                    "stages": session.stages,
                    "ai_analysis": session.ai_analysis,
                    "total_duration_seconds": session.total_duration_seconds,
                    "error": session.error,
                    "updated_at": datetime.utcnow().isoformat(),
                }},
            )
        except Exception as e:
            logger.error(f"Session update error: {e}")

    def _save_vulnerabilities(self, scan_id: str, target: str, results: Dict[str, StageResult]):
        """Nuclei zafiyetlerini ayrı collection'a kaydet"""
        col = self._get_vulnerabilities_collection()
        if col is None:
            return

        for name, result in results.items():
            if result.tool != "nuclei" or result.status != "completed":
                continue

            findings = result.data.get("findings", [])
            if not findings:
                continue

            try:
                docs = []
                for finding in findings:
                    info = finding.get("info", {}) or {}
                    docs.append({
                        "scan_id": scan_id,
                        "target": target,
                        "template_id": finding.get("template-id", "unknown"),
                        "name": info.get("name", "Unknown"),
                        "severity": info.get("severity", "unknown"),
                        "matched_at": finding.get("matched-at", ""),
                        "description": info.get("description", ""),
                        "raw_data": finding,
                        "discovered_at": datetime.utcnow(),
                        "pipeline_version": "v2",
                        # SÖZLEŞME KÖPRÜSÜ: okuyucu (reports.py) ve otonom yazıcı bu alanları
                        # bekliyor; statik yol bunları DÜŞÜRÜYORDU → her statik bulgu tier'sız
                        # kalıp "unconfirmed + kanıtsız" görünüyordu ("hiçbirini teyit
                        # edemiyorum"). Alanları uçtan uca taşırız.
                        **_static_finding_contract(finding, info),
                    })
                if docs:
                    col.insert_many(docs)
                    logger.info(f"Saved {len(docs)} vulnerabilities for {scan_id}")
            except Exception as e:
                logger.error(f"Vulnerability save error: {e}")

    def _build_summary(self, session: PipelineSession, results: Dict[str, StageResult]) -> Dict[str, Any]:
        """Pipeline özet bilgisi oluştur"""
        summary = {
            "session_id": session.session_id,
            "scan_id": session.scan_id,
            "target": session.target,
            "profile": session.profile_name,
            "status": session.status,
            "duration_seconds": session.total_duration_seconds,
            "stages_summary": {},
        }

        total_ports = 0
        total_vulns = 0
        total_subdomains = 0
        severity_counts = {}

        for name, result in results.items():
            summary["stages_summary"][name] = {
                "tool": result.tool,
                "status": result.status,
                "duration": result.duration_seconds,
            }

            if result.tool == "nmap" and result.status == "completed":
                ports = result.data.get("open_ports", [])
                total_ports = len(ports) if isinstance(ports, list) else 0

            elif result.tool == "nuclei" and result.status == "completed":
                total_vulns = result.data.get("findings_count", 0)
                severity_counts = result.data.get("severity_counts", {})

            elif result.tool == "subfinder" and result.status == "completed":
                total_subdomains = result.data.get("subdomains_count", 0)

        summary["findings"] = {
            "open_ports": total_ports,
            "vulnerabilities": total_vulns,
            "subdomains": total_subdomains,
            "severity_counts": severity_counts,
        }

        return summary

    async def _trigger_ai_analysis(self, session: PipelineSession, results: Dict[str, StageResult]):
        """
        Türkçe: AI Service'e analiz isteği gönder.
        Pipeline tamamlandıktan sonra background'da çalışır.
        """
        try:
            # Analiz için sonuçları hazırla
            analysis_payload = {
                "scan_id": session.scan_id,
                "target": session.target,
                "profile": session.profile_name,
                "results": {},
            }

            for name, result in results.items():
                if result.status == "completed" and result.data:
                    analysis_payload["results"][result.tool] = result.data

            if not analysis_payload["results"]:
                logger.info(f"No results for AI analysis: {session.scan_id}")
                return

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{AI_SERVICE_URL}/brain/analyze/v2",
                    json={
                        "scan_id": session.scan_id,
                        "target": session.target,
                        "scan_data": analysis_payload,
                    },
                    timeout=120.0,
                )

                if response.status_code == 200:
                    ai_result = response.json()
                    session.ai_analysis = ai_result

                    # v2_scan_sessions güncelle (TEK doğruluk kaynağı)
                    col = self._get_sessions_collection()
                    if col is not None:
                        col.update_one(
                            {"session_id": session.session_id},
                            {"$set": {"ai_analysis": ai_result}},
                        )

                    logger.info(f"AI analysis completed: {session.scan_id}")
                else:
                    logger.warning(f"AI analysis failed: HTTP {response.status_code}")

        except Exception as e:
            logger.warning(f"AI analysis trigger error (non-critical): {e}")

    # ============== Pipeline Management ==============

    @staticmethod
    def _normalize_session_doc(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        MongoDB session dokümanını frontend sözleşmesine uydur.
        DB dokümanı `profile_name` ile saklanır ama memory dalı ve frontend `profile`
        alanını bekler; yoksa otonom taramalar (profile=='autonomous' dalı) yanlışlıkla
        eski statik pipeline görünümüne düşer. Burada `profile` normalize edilir.
        Ayrıca frontend `duration_seconds` bekler; DB `total_duration_seconds` tutar.
        """
        if not doc:
            return doc
        if "profile" not in doc and "profile_name" in doc:
            doc["profile"] = doc["profile_name"]
        if "duration_seconds" not in doc and "total_duration_seconds" in doc:
            doc["duration_seconds"] = doc["total_duration_seconds"]
        return doc

    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Session durumunu döndür"""
        # Önce memory'den
        session = self._active_pipelines.get(session_id)
        if session:
            return {
                "session_id": session.session_id,
                "scan_id": session.scan_id,
                "target": session.target,
                "profile": session.profile_name,
                "status": session.status,
                "stages": session.stages,
                "ai_analysis": session.ai_analysis,
                "duration_seconds": session.total_duration_seconds,
            }

        # MongoDB'den
        col = self._get_sessions_collection()
        if col is not None:
            doc = col.find_one({"session_id": session_id}, {"_id": 0})
            return self._normalize_session_doc(doc)

        return None

    def get_session_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """scan_id ile session bul"""
        # Memory'den
        for session in self._active_pipelines.values():
            if session.scan_id == scan_id:
                return self.get_session_status(session.session_id)

        # MongoDB'den
        col = self._get_sessions_collection()
        if col is not None:
            doc = col.find_one({"scan_id": scan_id}, {"_id": 0})
            return self._normalize_session_doc(doc)

        return None

    async def cancel_pipeline(self, session_id: str) -> bool:
        """Çalışan pipeline'ı iptal et — MOTORU gerçekten durdurur (kozmetik değil)."""
        session = self._active_pipelines.get(session_id)
        if not session:
            return False

        # Otonom motora 'dur' işareti koy → next tur başında budget_left() False döner ve
        # _run_autonomous döngüsü çıkar (durum 'completed'a geri dönmez).
        engine = self._running_engines.get(session_id)
        if engine is not None:
            engine.cancel()

        session.status = "cancelled"
        session.completed_at = datetime.utcnow().isoformat()

        # Çalışan stage'lerin servislerini durdur
        dispatcher = ToolDispatcher(session.scan_id, session.target)
        for stage_name, stage_info in session.stages.items():
            if stage_info.get("status") == "running":
                await dispatcher._try_stop_scan(stage_info["tool"])
                session.stages[stage_name]["status"] = "cancelled"

        self._update_session(session)
        # NOT: _active_pipelines'tan BURADA çıkarMIYORUZ — _run_autonomous'un finally'si
        # temizler. Erken pop, iptal bayrağını gören döngünün son session yazımıyla yarışırdı.
        logger.info(f"Pipeline cancelled: {session_id}")
        return True

    async def cancel_pipeline_by_scan_id(self, scan_id: str) -> bool:
        """scan_id'den çalışan v2/otonom pipeline'ı bulup iptal et.

        Aktif Taramalar sayfası v1 /scan/{scan_id}/cancel çağırır ama otonom motor
        session_id ile yönetilir; eşleşme olmazsa eski v1 iptal yalnız DB kaydını
        'cancelled' yapıp MOTORU çalışır bırakıyordu (kayıt-gerçek uyumsuzluğu).
        Bu köprü scan_id → session_id eşleyip cancel_pipeline'a devreder."""
        for sid, session in list(self._active_pipelines.items()):
            if session.scan_id == scan_id:
                return await self.cancel_pipeline(sid)
        return False

    def pause_pipeline(self, session_id: str) -> Optional[bool]:
        """§2.5: Çalışan otonom motoru DURAKLAT (geri dönüşlü). Çalışan stage'i kesmez;
        sıradaki hamle 'resume' gelene kadar bekletilir. Döner: True | None (motor yok)."""
        engine = self._running_engines.get(session_id)
        if engine is None:
            return None
        engine.pause()
        s = self._active_pipelines.get(session_id)
        if s is not None:
            s.status = "paused"
            self._update_session(s)
        return True

    def resume_pipeline(self, session_id: str) -> Optional[bool]:
        """§2.5: Duraklatılmış motoru SÜRDÜR. Döner: True | None (motor yok)."""
        engine = self._running_engines.get(session_id)
        if engine is None:
            return None
        engine.resume()
        s = self._active_pipelines.get(session_id)
        if s is not None:
            s.status = "running"
            self._update_session(s)
        return True

    def get_active_pipelines(self) -> List[Dict[str, Any]]:
        """Aktif pipeline'ları listele"""
        return [
            {
                "session_id": s.session_id,
                "scan_id": s.scan_id,
                "target": s.target,
                "profile": s.profile_name,
                "status": s.status,
                "stages": s.stages,
            }
            for s in self._active_pipelines.values()
        ]

    # ============================================================
    # v1 sözleşmesi köprüsü — TEK doğruluk kaynağı v2_scan_sessions
    # ============================================================
    # Aktif Taramalar / Tarama Geçmişi / AI Raporlar sayfaları tarihsel olarak eski `scans`
    # koleksiyonunu okuyordu (v1). v1 otonom akış kaldırıldı; artık taramanın TEK gerçeği
    # v2_scan_sessions'tır. Bu köprü, o sayfaların beklediği v1 şeklini (scan_id/target/
    # scan_types/status/created_at/completed_at) session dokümanından ÜRETİR — ayrı bir ayna
    # koleksiyonu tutmadan. Böylece split-brain (kayıt-gerçek uyumsuzluğu) tümüyle biter.

    @staticmethod
    def _session_scan_types(doc: Dict[str, Any]) -> List[str]:
        """Session'dan v1 `scan_types` listesini türet: çalıştırılan stage araçları.
        Otonom taramalarda stage adları araç adıdır; hiç yoksa ['autonomous']."""
        stages = doc.get("stages") or {}
        tools = []
        for st in stages.values():
            if isinstance(st, dict) and st.get("tool"):
                tools.append(st["tool"])
        # Sırayı koru ama tekrarı at (dict.fromkeys stable-unique).
        tools = list(dict.fromkeys(tools))
        return tools or ["autonomous"]

    def _session_to_v1(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Session dokümanını Aktif/Geçmiş sayfalarının beklediği v1 şekle çevir."""
        return {
            "scan_id": doc.get("scan_id"),
            "target": doc.get("target"),
            "scan_types": self._session_scan_types(doc),
            "status": doc.get("status"),
            # Session created_at/completed_at zaten isoformat string olarak saklanır.
            "created_at": doc.get("created_at"),
            "completed_at": doc.get("completed_at"),
        }

    def active_scans_v1(self) -> Dict[str, Any]:
        """Aktif Taramalar için: yalnız çalışan/onay bekleyen session'ları v1 şeklinde döndür.
        Kaynak MongoDB (memory değil) — reload sonrası da tutarlı, tek sorgu."""
        col = self._get_sessions_collection()
        if col is None:
            return {"active_scans": [], "count": 0}
        cursor = col.find(
            {"status": {"$in": ["running", "pending", "awaiting_approval"]}},
            {"_id": 0},
        ).sort("created_at", -1)
        scans = [self._session_to_v1(d) for d in cursor]
        return {"active_scans": scans, "count": len(scans)}

    def get_scan_v1(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Tek tarama detayı, v1 şeklinde. Otonom session'ı map eder.

        NOT: results.tsx otonom taramayı AYRICA /api/v2/scan/{id}'den (tam session) render
        eder; bu endpoint'in `results` alanını otonom için KULLANMAZ. Ama ai-reports.tsx
        rapor üretimi için /api/scan/{id}.results'ı okur → otonom özeti (ai_analysis) buraya
        `results.autonomous` altında konur ki rapor girdisi boş kalmasın."""
        doc = self.get_session_by_scan_id(scan_id)
        if not doc:
            return None
        v1 = self._session_to_v1(doc)
        v1["results"] = {"autonomous": doc.get("ai_analysis") or {}}
        v1["ai_analysis"] = doc.get("ai_analysis") or {}
        return v1

    async def delete_scan(self, scan_id: str) -> bool:
        """Taramayı TEK kaynaktan sil: çalışıyorsa önce durdur, sonra session + türev
        koleksiyonları (artifacts/llm-logs/vulnerabilities) temizle. Bulunamazsa False."""
        await self.cancel_pipeline_by_scan_id(scan_id)  # çalışıyorsa motoru durdur
        col = self._get_sessions_collection()
        if col is None:
            return False
        res = col.delete_one({"scan_id": scan_id})
        # Türev veriyi de temizle (yörünge/log/zafiyet) — yetim doküman kalmasın.
        for getter in (self._get_artifacts_collection, self._get_llm_logs_collection,
                       self._get_vulnerabilities_collection):
            c = getter()
            if c is not None:
                try:
                    c.delete_many({"scan_id": scan_id})
                except Exception as e:
                    logger.debug(f"delete_scan türev temizleme atlandı ({scan_id}): {e}")
        return res.deleted_count > 0
