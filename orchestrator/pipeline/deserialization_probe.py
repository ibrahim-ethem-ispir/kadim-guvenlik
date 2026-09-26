"""
Kadim Güvenlik — Deserialization Kabul-İmza Probu (P3)
========================================================
Türkçe: 2026'nın en büyük RCE dilimi deserialization sınıfında (SharePoint ToolShell,
TeamCity gadget yüzeyi, ASP.NET ViewState) — motor bugüne kadar bu sınıf için hiçbir
aktif doğrulayıcı taşımıyordu. Bu modül o boşluğu KAPATIR ama SİLAH ÜRETMEZ: gerçek bir
gadget-chain (ör. ysoserial.net ObjectDataProvider zinciri) hiçbir zaman çalıştırılmaz.
Yalnız "bu yüzey açık ve savunmasız-görünüyor" imzası/oracle-tabanlı tahribatsız kanıt
toplanır — doktrin: *sömürülebilirliği kanıtla, hedefi düşürme*.

Üç kanal:
  1) SharePoint ToolShell yol-imzası — küratörlü path listesi + deterministik GET +
     içerik/header validator (path_probe.py deseni, küçük ölçekte).
  2) ASP.NET ViewState kabul testi — rastgele/geçersiz __VIEWSTATE POST'una sunucunun
     MAC doğrulamasını AÇIK mı KAPALI mı işlediğini gözlemler (aşağıda TAHRİBATSIZLIK
     GEREKÇESİ bölümüne bak).
  3) TeamCity sürüm ifşası — /app/rest/server auth'suz erişilebiliyorsa sürüm sızar
     (CVE korelasyonu için istihbarat; gadget denenmez).

KRİTİK DOKTRIN — MODÜLER GATE: Bu prob YALNIZ hedef gerçekten SharePoint/TeamCity/ASP.NET
ise çalışır. Motorda çift kapı vardır (wp_probe/k8s_probe ile aynı desen):
  (1) playbook.deserialization_probe (if_relevant) — profil framework=sharepoint|teamcity
      ya da language=dotnet demezse dispatcher bu modülü hiç çağırmaz.
  (2) probe_deserialization içinde CANLI RE-CONFIRM — kök sayfada gerçek imza yoksa TEK
      bulgu üretilmez (defense-in-depth; profil yanılsa bile false-positive'e karşı).

TAHRİBATSIZLIK GEREKÇESİ (ViewState testi — denetlenebilir olsun diye burada açık yazılı):
Gönderilen __VIEWSTATE değeri RASTGELE/GEÇERSİZ base64 çöptür — gerçek bir gadget-chain
DEĞİLDİR, hiçbir .NET tipi/nesne grafiği kodlanmaz. POST YALNIZ kökteki formun KENDİ
action'ına gider; action HTML'den çözülemiyorsa test HİÇ yapılmaz (riskli varsayım/yan
etkili rastgele POST yok). Formun diğer input alanları boş/varsayılan gönderilir — login,
kayıt, satın alma gibi bir iş akışı TETİKLENMEZ. Sunucu tarafında iki olası davranış
vardır: (a) MAC doğrulaması BAŞARISIZ olur → ASP.NET bunu bir exception olarak loglar,
kalıcı state değişikliği YOKTUR; (b) MAC KAPALIYSA deserializer çöp veriyi açmaya
çalışır ve tip uyuşmazlığı/format hatasıyla exception/500 döner — gadget chain
olmadığından dosya yazma/komut çalıştırma gibi bir yan etki GERÇEKLEŞMEZ. Gözlenen
TEK şey HTTP yanıtının kendisidir (status + gövde imzası).

Tasarım (wp_probe/k8s_probe deseni): classify_*/is_*_live çekirdeği SAF (stdlib + regex)
→ izole test; probe_deserialization ince I/O. ASLA raise etmez. Best-effort: sağlayıcı/ağ
hatası taramayı düşürmez.
"""

import asyncio
import logging
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger("deserialization-probe")

# ============================================================
# SAF çekirdek — parmak izi & sınıflandırma (I/O yok, izole test)
# ============================================================

# SharePoint canlı-imza belirteçleri (kök HTML/header). Herhangi biri = SharePoint.
_SP_BODY_MARKERS = re.compile(r"/_layouts/15/|/_api/web/|/_vti_bin/", re.I)
_SP_HEADER_NAMES = ("x-sharepointhealthscore", "microsoftsharepointteamservices", "sprequestguid")

# TeamCity canlı-imza belirteçleri.
_TC_BODY_MARKER = re.compile(r"TeamCity\s+\d+\.\d+", re.I)
_TC_HEADER_NAMES = ("x-teamcity-node-id",)

# SharePoint ToolShell yol kataloğu — (path, validator adı). Sınırlı/küratörlü: path_probe.py'nin
# 64-yollu soft-404 mekanizmasına gerek yok, bu prob zaten ürün-gated (yalnız SharePoint tespit
# edildiğinde çalışır) → gürültü riski düşük.
SHAREPOINT_PATHS: List[Tuple[str, str]] = [
    ("/_layouts/15/ToolPane.aspx", "sharepoint_toolpane"),
    ("/_layouts/15/start.aspx", "sharepoint_generic"),
    ("/_layouts/SignOut.aspx", "sharepoint_generic"),
    ("/_vti_bin/client.svc", "sharepoint_vti"),
    ("/_layouts/15/spsdisco.aspx", "sharepoint_generic"),
]

# TeamCity endpoint kataloğu.
TEAMCITY_PATHS: List[Tuple[str, str]] = [
    ("/app/rest/server", "teamcity_server_info"),  # auth'suzsa sürüm XML/JSON sızar
]

# TeamCity /app/rest/server yanıtından sürüm çıkarımı: version="2024.03.2" (XML) ya da
# "version":"2024.03.2" (JSON) — her iki gösterim de destekli.
_TC_VERSION = re.compile(r'version["\']?\s*[:=]\s*["\']([0-9][0-9A-Za-z.\-]{1,20})["\']')

# ViewState MAC hata imzaları (kültürden bağımsız, .NET framework sabit metinleri).
_VS_MAC_FAIL_MARKERS = (
    "validation of viewstate mac failed",
    "the viewstate is invalid",
    "viewstate mac doğrulaması",  # bazı yerelleştirilmiş IIS hata sayfaları
)
# Belirsiz/genel postback hatası — MAC durumu hakkında KARAR VERİLEMEZ (bulgu üretme).
_VS_AMBIGUOUS_MARKERS = (
    "invalid postback or callback argument",
    "unable to validate data",
)


def is_sharepoint_live(body: str = "", headers: Optional[Dict[str, str]] = None) -> Tuple[bool, List[str]]:
    """Hedef CANLI olarak SharePoint mi? (SAF). Çift-kapının ikinci kapısı. Döner
    (sharepoint?, kanıt-listesi)."""
    ev: List[str] = []
    if body and _SP_BODY_MARKERS.search(body[:200000]):
        ev.append("body:_layouts|_api/web|_vti_bin")
    if headers:
        hay = " ".join(f"{k.lower()}:{str(v).lower()}" for k, v in headers.items())
        for name in _SP_HEADER_NAMES:
            if name in hay:
                ev.append(f"header:{name}")
                break
    return (len(ev) > 0, ev)


def is_teamcity_live(body: str = "", headers: Optional[Dict[str, str]] = None) -> Tuple[bool, List[str]]:
    """Hedef CANLI olarak TeamCity mi? (SAF). Döner (teamcity?, kanıt-listesi)."""
    ev: List[str] = []
    if body and _TC_BODY_MARKER.search(body[:200000]):
        ev.append("body:TeamCity-version")
    if headers:
        hay = " ".join(f"{k.lower()}:{str(v).lower()}" for k, v in headers.items())
        for name in _TC_HEADER_NAMES:
            if name in hay:
                ev.append(f"header:{name}")
                break
    return (len(ev) > 0, ev)


def classify_sharepoint_path(path: str, status: int, ctype: str, body: str) -> Optional[Dict[str, Any]]:
    """Tek SharePoint yolunun yanıtını sınıflandır (SAF). 200/302/401 + gövdede SharePoint
    imzası (ya da ToolPane'e özgü ASPX viewstate/form imzası) varsa 'yol açık' der; soft-404/
    generic IIS hata sayfası ya da imzasız 200 → None (kör 200'e güvenme)."""
    if status not in (200, 302, 401):
        return None
    b = body or ""
    if status == 200:
        # 200 dönse bile içerik SharePoint imzası TAŞIMIYORSA (ör. paylaşımlı host soft-404,
        # generic IIS karşılama sayfası) bulgu sayma.
        if not (_SP_BODY_MARKERS.search(b) or "sharepoint" in b.lower() or "__viewstate" in b.lower()):
            return None
    return {"path": path, "status": status, "signature": "sharepoint-response"}


def classify_viewstate_acceptance(status: int, body: str) -> Optional[Dict[str, Any]]:
    """Bozuk __VIEWSTATE POST'una sunucu yanıtını sınıflandır (SAF). Döner
    {"mac_status": "enforced"|"disabled"} ya da None (belirsiz → bulgu üretme).

    - MAC hata imzası (400/500 + 'validation of viewstate mac failed' vb.) → 'enforced'
      (MAC aktif; yine de eski/zayıf machineKey riski not edilir — info/low).
    - 200 + hata imzası YOK (sunucu çöp veriyi normal işleyip sayfayı render etti) →
      'disabled' (KRİTİK: keyfi ViewState kabul ediliyor → gadget-chain RCE yüzeyi VAR;
      gadget'ın kendisi hiç çalıştırılmadı, yalnız kabul davranışı gözlendi).
    - Genel/belirsiz postback hatası → None (MAC durumu hakkında karar verilemez)."""
    b = (body or "").lower()
    for marker in _VS_AMBIGUOUS_MARKERS:
        if marker in b:
            return None
    for marker in _VS_MAC_FAIL_MARKERS:
        if marker in b:
            return {"mac_status": "enforced"}
    if status == 200:
        return {"mac_status": "disabled"}
    return None


def classify_teamcity_version(status: int, ctype: str, body: str) -> Optional[Dict[str, Any]]:
    """TeamCity /app/rest/server yanıtından sürüm çıkar (SAF). Auth'suz 200 + version
    alanı → sürüm ifşası (CVE korelasyon girdisi). 401/403 → None (auth ister, hata değil)."""
    if status != 200:
        return None
    m = _TC_VERSION.search(body or "")
    if not m:
        return None
    return {"version": m.group(1)}


class _FormActionParser(HTMLParser):
    """İlk <form> etiketinin action'ını çıkarır (SAF, stdlib — 3p bağımlılık yok)."""

    def __init__(self) -> None:
        super().__init__()
        self.action: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if self.action is not None or tag.lower() != "form":
            return
        for k, v in attrs:
            if k.lower() == "action" and v:
                self.action = v
                return
        self.action = ""  # form var ama action yok → kendi URL'ine post eder (boş = self)


def extract_form_action(body: str, base: str) -> Optional[str]:
    """Kök body'deki ilk formun action'ını MUTLAK URL'ye çevir (SAF). Form yoksa None
    (ViewState testi bu durumda ATLANIR — riskli varsayım/yan etkili rastgele POST yok).
    action="" (self-post) → base'in kendisi."""
    if "__VIEWSTATE" not in (body or ""):
        return None
    parser = _FormActionParser()
    try:
        parser.feed(body[:200000])
    except Exception:
        return None
    if parser.action is None:
        return None
    if parser.action == "":
        return base
    try:
        absu = urljoin(base + "/", parser.action)
    except Exception:
        return None
    # Aynı host dışına post etmeyelim (SSRF-benzeri yan etki riski) — farklı origin'se atla.
    if urlsplit(absu).netloc and urlsplit(absu).netloc != urlsplit(base).netloc:
        return None
    return absu


def _finding(title: str, severity: str, target: str, proof: str, *,
             tier: str = "confirmed", cwe: Optional[List[str]] = None,
             mitre: str = "T1190", method: str = "deserialization-probe") -> Dict[str, Any]:
    return {"title": title, "severity": severity, "target": target, "proof": proof,
            "confidence_tier": tier, "cwe": cwe or ["CWE-502"], "mitre": mitre,
            "verification_method": method,
            "verification_confidence": 0.85 if tier == "confirmed" else None}


# ============================================================
# I/O — TAHRİBATSIZ (GET + tek zararsız POST), best-effort
# ============================================================

async def _get(client, url: str, *, allow_redirects: bool = False) -> Optional[Tuple[int, str, str]]:
    """Tek GET → (status, content-type, body[:32KB]). Hata → None."""
    try:
        r = await client.get(url, timeout=10.0, follow_redirects=allow_redirects)
        ctype = r.headers.get("content-type", "") if hasattr(r, "headers") else ""
        return (r.status_code, ctype, (r.text or "")[:32768])
    except Exception:
        return None


async def _fetch_root(client, url: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Kök sayfayı BİR KEZ zengin çek → (body[:200KB], headers). Hata → None."""
    try:
        r = await client.get(url, timeout=10.0, follow_redirects=True)
    except Exception:
        return None
    headers = {k: v for k, v in r.headers.items()} if hasattr(r, "headers") else {}
    return ((r.text or "")[:200000], headers)


async def _resolve_base(client, host: str) -> Optional[Tuple[str, str, Dict[str, str]]]:
    """host için çalışan kök URL'yi (https→http) TEK istekle bul. Döner (base, body, headers)."""
    if host.startswith(("http://", "https://")):
        got = await _fetch_root(client, host.rstrip("/") + "/")
        return (host.rstrip("/"), *got) if got else None
    for scheme in ("https", "http"):
        got = await _fetch_root(client, f"{scheme}://{host}/")
        if got is not None:
            return (f"{scheme}://{host}", *got)
    return None


async def _test_viewstate_acceptance(client, action_url: str) -> Optional[Tuple[int, str]]:
    """Rastgele/geçersiz __VIEWSTATE ile TEK POST → (status, body[:32KB]). Bkz. modül başlığı
    TAHRİBATSIZLIK GEREKÇESİ. Hata → None (test yapılamadı, bulgu üretilmez)."""
    try:
        r = await client.post(
            action_url,
            data={"__VIEWSTATE": "/wEPDwULLTE2MTQ5MDU0ODZkZ2FyYmFnZ2FyYmFnZ2FyYmFnZ2FyYmFnZ2Fy==",
                  "__EVENTVALIDATION": "/wEWAQKgarbagegarbagegarbagegarbage=="},
            timeout=10.0, follow_redirects=False,
        )
        return (r.status_code, (r.text or "")[:32768])
    except Exception:
        return None


async def probe_deserialization(host: str, client, *, max_paths: int = 8) -> Dict[str, Any]:
    """Deserialization saldırı yüzeyini TAHRİBATSIZ yokla → {confirmed_sharepoint,
    confirmed_teamcity, viewstate_tested, findings}. ASLA raise etmez. Çift-kapının ikinci
    kapısı burada: kök sayfada canlı imza yoksa BOŞ döner (profil yanılsa bile FP üretmez)."""
    result: Dict[str, Any] = {"confirmed_sharepoint": False, "confirmed_teamcity": False,
                              "viewstate_tested": False, "findings": []}
    findings: List[Dict[str, Any]] = result["findings"]

    resolved = await _resolve_base(client, host)
    if not resolved:
        return result
    base, root_body, root_headers = resolved

    # --- SharePoint canlı re-confirm + ToolShell yol taraması ---
    sp_ok, sp_ev = is_sharepoint_live(root_body, root_headers)
    if sp_ok:
        result["confirmed_sharepoint"] = True
        for i, (path, _validator) in enumerate(SHAREPOINT_PATHS[:max_paths]):
            if i:
                await asyncio.sleep(0.15)  # pacing — WAF'lı SharePoint'te salvo tetiklemesin
            r = await _get(client, f"{base}{path}")
            if not r:
                continue
            c = classify_sharepoint_path(path, r[0], r[1], r[2])
            if c:
                findings.append(_finding(
                    f"SharePoint Yönetim Yüzeyi Açık: {path} @ {base}", "high", f"{base}{path}",
                    f"GET {path} → HTTP {c['status']}, SharePoint imzası (ToolShell zincirinin "
                    f"parçası olan yönetim yüzeyi erişilebilir; kanıt: {', '.join(sp_ev)}). "
                    f"Sürüm/yama durumu doğrulanmalı — bu tek başına RCE değildir, saldırı "
                    f"yüzeyinin AÇIK olduğunun kanıtıdır.",
                    tier="confirmed", cwe=["CWE-502"], mitre="T1190", method="sharepoint-path-signature"))

    # --- TeamCity canlı re-confirm + sürüm ifşası ---
    tc_ok, tc_ev = is_teamcity_live(root_body, root_headers)
    if tc_ok:
        result["confirmed_teamcity"] = True
        for path, validator in TEAMCITY_PATHS:
            r = await _get(client, f"{base}{path}")
            if not r:
                continue
            if validator == "teamcity_server_info":
                v = classify_teamcity_version(r[0], r[1], r[2])
                if v:
                    findings.append(_finding(
                        f"TeamCity Sürüm İfşası ({v['version']}) @ {base}", "medium", f"{base}{path}",
                        f"Auth'suz GET {path} → TeamCity {v['version']} sürümünü ifşa ediyor "
                        f"(kanıt: {', '.join(tc_ev)}). Sürüm→CVE ilişkilendirmesi (deserialization "
                        f"gadget yüzeyi dahil) için istihbarat.",
                        tier="confirmed", cwe=["CWE-200"], mitre="T1592.002", method="teamcity-version"))

    # --- ASP.NET ViewState kabul testi (SharePoint/TeamCity olmasa da dotnet hedefte anlamlı) ---
    action_url = extract_form_action(root_body, base)
    if action_url:
        vs = await _test_viewstate_acceptance(client, action_url)
        if vs:
            result["viewstate_tested"] = True
            c = classify_viewstate_acceptance(vs[0], vs[1])
            if c and c.get("mac_status") == "disabled":
                findings.append(_finding(
                    f"ASP.NET ViewState MAC Doğrulaması KAPALI @ {action_url}", "critical",
                    action_url,
                    f"Rastgele/geçersiz __VIEWSTATE POST edildi (gerçek gadget-chain DEĞİL — "
                    f"yalnız base64 çöp) ve sunucu HATA VERMEDEN normal yanıt döndü (HTTP "
                    f"{vs[0]}). Bu, EnableViewStateMac=false ya da eşdeğeri bir yapılandırma "
                    f"gösterir: sunucu KEYFİ ViewState kabul ediyor → ysoserial.net tarzı "
                    f"gadget-chain ile RCE YÜZEYİ mevcut (gadget ÇALIŞTIRILMADI — yalnız kabul "
                    f"davranışı gözlendi, TAHRİBATSIZ). Sertleştirme: EnableViewStateMac=true + "
                    f"machineKey rotasyonu.",
                    tier="confirmed", cwe=["CWE-502"], mitre="T1190", method="viewstate-mac-oracle"))
            elif c and c.get("mac_status") == "enforced":
                findings.append(_finding(
                    f"ASP.NET ViewState MAC Doğrulaması Aktif @ {action_url}", "info", action_url,
                    f"Rastgele __VIEWSTATE POST'una sunucu MAC doğrulama HATASI döndü (HTTP "
                    f"{vs[0]}) — MAC aktif (iyi durum). Not: eski/statik machineKey paylaşımı "
                    f"hâlâ risk taşıyabilir (bilinen machineKey sızıntısı varsa gadget-chain "
                    f"yine mümkündür); bu bulgu yalnız MAC'in AKTİF olduğunu belgeler.",
                    tier="confirmed", cwe=["CWE-502"], mitre="T1190", method="viewstate-mac-oracle"))

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
