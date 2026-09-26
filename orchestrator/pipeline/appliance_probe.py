"""
Kadim Güvenlik — Appliance Auth-Bypass / Missing-Auth Probu (P3)
================================================================
Türkçe: 2026 KEV'inin en büyük RCE/erişim dilimi "edge appliance" ailesinde — FortiWeb/
FortiSandbox (missing authz), PAN-OS GlobalProtect (auth bypass), Ivanti Sentry/EPMM,
Citrix NetScaler, N-able N-central, SimpleHelp RMM, Progress LoadMaster. Motor bunları
TESPİT ediyordu (fingerprint + nuclei imzası) ama AKTİF KANITLAYAMIYORDU. Bu modül o
boşluğu kapatır — ama SİLAH ÜRETMEZ: gerçek bir exploit zinciri (RCE payload, komut
enjeksiyonu) HİÇBİR ZAMAN çalıştırılmaz.

İki tahribatsız kanal (doktrin: *sömürülebilirliği kanıtla, hedefi düşürme*):
  1) SÜRÜM/YAPI İFŞASI — appliance'a özgü auth'suz erişilebilen endpoint sürüm/config
     sızdırıyorsa (deserialization_probe'un TeamCity kanalı deseni). CONFIRMED CWE-200 +
     sürüm→CVE korelasyonu (hangi auth-bypass CVE'sinin bu sürümü vurduğu istihbaratı).
  2) EKSİK KİMLİK DOĞRULAMA (differential) — normalde KİMLİK GEREKTİREN yönetim/API
     endpoint'i KİMLİKSİZ istekte AYRICALIKLI içerik döndürüyorsa (ürüne özgü başarı
     imzası) → CONFIRMED CWE-306/CWE-287. Salt-okunur GET; veri değiştirilmez, exploit
     zinciri ilerletilmez — yalnız "auth kapısı yok/atlanıyor" davranışı gözlenir. Bu,
     idor_probe'un diferansiyel mantığının appliance yönetim düzlemine taşınmış hâlidir.

KRİTİK DOKTRIN — MODÜLER GATE (wp_probe/k8s_probe/deserialization_probe deseni):
  (1) playbook.appliance_probe (if_relevant) — profil bir appliance ailesi (waf/framework/
      server ya da CPE ürünü) demezse dispatcher bu modülü HİÇ çağırmaz.
  (2) probe_appliance içinde CANLI RE-CONFIRM — kök yanıtta gerçek appliance imzası yoksa
      TEK bulgu üretilmez (defense-in-depth; profil yanılsa bile false-positive'e karşı).

TAHRİBATSIZLIK GEREKÇESİ (denetlenebilir olsun diye açık yazılı):
Tüm istekler GET'tir (yan etkisiz, salt-okunur). Kimlik atlatma testinde EK bir exploit
tekniği (özel header/param ile auth kandırma) DENENMEZ — yalnız endpoint'in kimliksiz
düz GET'ine verdiği yanıt gözlenir. "Ayrıcalıklı içerik döndü" = ürüne özgü, kimlik
sonrası görülmesi beklenen imza (config anahtarı, kullanıcı listesi JSON'ı, sürüm+build).
Login/redirect/401/403 → bulgu YOK (kapı çalışıyor). Hiçbir hesap oluşturulmaz, hiçbir
ayar değiştirilmez, hiçbir komut çalıştırılmaz.

Tasarım: identify_*/classify_* çekirdeği SAF (stdlib + regex) → izole test; probe_appliance
ince I/O. ASLA raise etmez. Best-effort: sağlayıcı/ağ hatası taramayı düşürmez.
"""

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("appliance-probe")

# ============================================================
# SAF çekirdek — appliance ailesi kimliği (I/O yok, izole test)
# ============================================================
# Her aile için kök yanıt canlı-imza belirteçleri. Ayırt edici seçildi (jenerik "login"
# değil) → çift-kapının ikinci kapısı; profil yanılsa bile FP üretmez.
_APPLIANCE_SIGNS: Dict[str, Dict[str, Any]] = {
    "fortinet": {
        "body": re.compile(r"/remote/login|fortigate|fortiweb|fgt_lang|fortinet", re.I),
        "headers": ("server: xxxxxxxx-xxxxx",),  # FortiWeb/FortiGate imza server header'ı
        "label": "Fortinet (FortiOS/FortiWeb/FortiSandbox)",
    },
    "panos": {
        "body": re.compile(r"global-?protect|/global-protect/login|pan_forgot_pass|clientDownload", re.I),
        "headers": (),
        "label": "Palo Alto PAN-OS / GlobalProtect",
    },
    "ivanti": {
        "body": re.compile(r"dana-na/|/mifs/|ivanti|pulse\s*secure|epmm", re.I),
        "headers": (),
        "label": "Ivanti (Connect Secure / EPMM / Sentry)",
    },
    "citrix_netscaler": {
        "body": re.compile(r"/vpn/index\.html|ns_gui|netscaler|citrix\s*gateway|/logon/LogonPoint", re.I),
        "headers": ("via: ns",),
        "label": "Citrix NetScaler / Gateway",
    },
    "nable_ncentral": {
        "body": re.compile(r"n-?central|nable|/dms/|/download/", re.I),
        "headers": (),
        "label": "N-able N-central",
    },
    "simplehelp": {
        "body": re.compile(r"simplehelp|/allih/|/toolbox-", re.I),
        "headers": (),
        "label": "SimpleHelp RMM",
    },
    "loadmaster": {
        "body": re.compile(r"loadmaster|kemp\s*technologies|lm-?report", re.I),
        "headers": (),
        "label": "Progress Kemp LoadMaster",
    },
}


# Her aile için auth'suz yoklanacak endpoint kataloğu. curated/küçük — modül zaten ürün-gated,
# gürültü riski düşük. kind:
#   version   → auth'suz sürüm/build ifşası (CONFIRMED CWE-200 + CVE korelasyonu)
#   unauth_api→ normalde kimlik isteyen API/yönetim; kimliksiz AYRICALIKLI içerik = CWE-306
# success: kind=version için sürüm regex; kind=unauth_api için ayrıcalıklı-içerik imzası.
# fail: her zaman "bulgu YOK" (kapı çalışıyor) — login/redirect/deny imzaları.
_APPLIANCE_ENDPOINTS: Dict[str, List[Dict[str, Any]]] = {
    "fortinet": [
        {"path": "/api/v2/cmdb/system/status", "kind": "unauth_api",
         "success": re.compile(r'"(?:version|build|serial)"\s*:', re.I), "cve": "CVE-2026-26083 (FortiSandbox missing authz sınıfı)"},
        {"path": "/migadmin/", "kind": "unauth_api",
         "success": re.compile(r"fortiweb|admin\s*console|system\s*status", re.I), "cve": "CVE-2025-64446 (FortiWeb auth bypass sınıfı)"},
    ],
    "panos": [
        {"path": "/global-protect/portal/config/index.esp", "kind": "unauth_api",
         "success": re.compile(r"portal-config|gp-portal|<panorama", re.I), "cve": "CVE-2026-0257 (GlobalProtect auth bypass sınıfı)"},
    ],
    "ivanti": [
        {"path": "/mifs/services/", "kind": "unauth_api",
         "success": re.compile(r"wsdl|services\s*list|axis", re.I), "cve": "CVE-2026-1281/1340 (EPMM sınıfı)"},
        {"path": "/api/v1/system/status", "kind": "version",
         "success": re.compile(r'"(?:version|build)"\s*:\s*"([0-9][0-9A-Za-z.\-]{1,20})"', re.I), "cve": "Ivanti sürüm→CVE korelasyonu"},
    ],
    "citrix_netscaler": [
        {"path": "/nitro/v1/config/nsversion", "kind": "version",
         "success": re.compile(r'"nsversion"\s*:\s*"?\s*NetScaler[^"]*?(\d+\.\d+)', re.I), "cve": "NetScaler sürüm→CVE (CitrixBleed sınıfı)"},
    ],
    "nable_ncentral": [
        {"path": "/dms2/services2/ServerEI2", "kind": "unauth_api",
         "success": re.compile(r"serverei|wsdl|definitions", re.I), "cve": "CVE-2026-18577 (N-central auth bypass sınıfı)"},
    ],
    "simplehelp": [
        {"path": "/allih/", "kind": "unauth_api",
         "success": re.compile(r"simplehelp|technician|admin\s*console", re.I), "cve": "CVE-2026-48558 (SimpleHelp auth bypass sınıfı)"},
    ],
    "loadmaster": [
        {"path": "/access/get", "kind": "unauth_api",
         "success": re.compile(r"loadmaster|apikey|<Response", re.I), "cve": "CVE-2026-8037 (LoadMaster command inj. — %99 exploit)"},
    ],
}

# Auth'un ÇALIŞTIĞINI gösteren yanıt imzaları — bunlardan biri varsa bulgu ÜRETME (kapı sağlam).
_AUTH_GATE_MARKERS = re.compile(
    r"login|sign\s*in|authenticat|unauthor|forbidden|access\s*denied|session\s*expired|"
    r"401\s*unauthorized|403\s*forbidden|please\s*log", re.I)


def identify_appliance(body: str = "", headers: Optional[Dict[str, str]] = None
                       ) -> Tuple[Optional[str], List[str]]:
    """Kök yanıttan appliance AİLESİNİ tanı (SAF). Çift-kapının ikinci kapısı. Döner
    (aile-anahtarı|None, kanıt-listesi). Birden çok eşleşirse ilk (en spesifik sıradaki)."""
    hay = ""
    if headers:
        hay = " ".join(f"{k.lower()}: {str(v).lower()}" for k, v in headers.items())
    b = (body or "")[:200000]
    for fam, sig in _APPLIANCE_SIGNS.items():
        ev: List[str] = []
        if sig["body"].search(b):
            ev.append(f"body:{fam}-signature")
        for hn in sig["headers"]:
            if hn in hay:
                ev.append(f"header:{hn.split(':')[0]}")
                break
        if ev:
            return fam, ev
    return None, []


def classify_appliance_response(kind: str, status: int, body: str,
                                success: "re.Pattern") -> Optional[Dict[str, Any]]:
    """Tek endpoint yanıtını sınıflandır (SAF).
    - Auth-gate imzası varsa (login/401/403/deny) → None (kapı çalışıyor, bulgu yok).
    - kind=version: 2xx + sürüm regex → {"kind":"version","version":X}.
    - kind=unauth_api: 2xx + ayrıcalıklı-içerik imzası (auth-gate YOK) → {"kind":"unauth_api"}.
    - Aksi hâli → None (kör 200'e/redirect'e güvenme)."""
    if status not in (200, 203, 206):
        return None
    b = body or ""
    if _AUTH_GATE_MARKERS.search(b[:4000]):
        return None  # yanıt bir kimlik kapısı → erişim YOK
    m = success.search(b)
    if not m:
        return None
    if kind == "version":
        ver = m.group(1) if m.groups() else ""
        return {"kind": "version", "version": ver}
    return {"kind": "unauth_api"}


def _finding(title: str, severity: str, target: str, proof: str, *,
             tier: str = "confirmed", cwe: Optional[List[str]] = None,
             mitre: str = "T1190", method: str = "appliance-probe") -> Dict[str, Any]:
    return {"title": title, "severity": severity, "target": target, "proof": proof,
            "confidence_tier": tier, "cwe": cwe or ["CWE-306"], "mitre": mitre,
            "verification_method": method,
            "verification_confidence": 0.85 if tier == "confirmed" else None}


# ============================================================
# I/O — TAHRİBATSIZ (yalnız GET), best-effort
# ============================================================

async def _get(client, url: str) -> Optional[Tuple[int, str]]:
    """Tek GET → (status, body[:32KB]). Hata → None."""
    try:
        r = await client.get(url, timeout=10.0, follow_redirects=False)
        return (r.status_code, (r.text or "")[:32768])
    except Exception:
        return None


async def _resolve_base(client, host: str) -> Optional[Tuple[str, str, Dict[str, str]]]:
    """host için çalışan kök URL'yi TEK istekle bul → (base, body[:200KB], headers)."""
    def _norm(u: str) -> str:
        return u.rstrip("/")
    urls = ([host] if host.startswith(("http://", "https://"))
            else [f"https://{host}", f"http://{host}"])
    for u in urls:
        try:
            r = await client.get(_norm(u) + "/", timeout=10.0, follow_redirects=True)
        except Exception:
            continue
        headers = {k: v for k, v in r.headers.items()} if hasattr(r, "headers") else {}
        return (_norm(u), (r.text or "")[:200000], headers)
    return None


async def probe_appliance(host: str, client, *, max_endpoints: int = 4) -> Dict[str, Any]:
    """Appliance auth-bypass/missing-auth yüzeyini TAHRİBATSIZ yokla → {family, findings}.
    ASLA raise etmez. Çift-kapının ikinci kapısı: kök yanıtta canlı appliance imzası yoksa
    BOŞ döner (profil yanılsa bile FP üretmez)."""
    result: Dict[str, Any] = {"family": None, "findings": []}
    findings: List[Dict[str, Any]] = result["findings"]

    resolved = await _resolve_base(client, host)
    if not resolved:
        return result
    base, root_body, root_headers = resolved

    fam, fam_ev = identify_appliance(root_body, root_headers)
    if not fam:
        return result
    result["family"] = fam
    label = _APPLIANCE_SIGNS[fam]["label"]

    endpoints = _APPLIANCE_ENDPOINTS.get(fam, [])[:max_endpoints]
    for i, ep in enumerate(endpoints):
        if i:
            await asyncio.sleep(0.15)  # pacing — WAF'lı appliance'ta salvo tetiklemesin
        r = await _get(client, f"{base}{ep['path']}")
        if not r:
            continue
        c = classify_appliance_response(ep["kind"], r[0], r[1], ep["success"])
        if not c:
            continue
        cve_hint = ep.get("cve", "")
        if c["kind"] == "version":
            ver = c.get("version") or "?"
            findings.append(_finding(
                f"{label} Sürüm İfşası ({ver}) @ {base}{ep['path']}", "medium",
                f"{base}{ep['path']}",
                f"Auth'suz GET {ep['path']} → sürüm '{ver}' ifşa ediliyor (kanıt: "
                f"{', '.join(fam_ev)}). Sürüm→CVE korelasyonu: {cve_hint}. Bu tek başına "
                f"RCE değildir; hangi bilinen zafiyetin bu sürümü vurduğu istihbaratıdır.",
                tier="confirmed", cwe=["CWE-200"], mitre="T1592.002", method="appliance-version-disclosure"))
        else:  # unauth_api
            findings.append(_finding(
                f"{label} Eksik Kimlik Doğrulama: {ep['path']} @ {base}", "critical",
                f"{base}{ep['path']}",
                f"Kimliksiz GET {ep['path']} → normalde kimlik gerektiren yönetim/API "
                f"endpoint'i AYRICALIKLI içerik döndürdü (HTTP {r[0]}; login/401/403 kapısı YOK; "
                f"kanıt: {', '.join(fam_ev)}). Bu, eksik kimlik doğrulama / auth-bypass "
                f"davranışının KANITIDIR ({cve_hint}). TAHRİBATSIZ: yalnız düz GET yanıtı "
                f"gözlendi — hiçbir exploit tekniği/komut çalıştırılmadı, veri değiştirilmedi.",
                tier="confirmed", cwe=["CWE-306", "CWE-287"], mitre="T1190",
                method="appliance-missing-auth-differential"))

    # Dedup (aynı başlık+hedef)
    seen = set()
    out = []
    for f in findings:
        key = (f["title"], f["target"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    result["findings"] = out
    return result
