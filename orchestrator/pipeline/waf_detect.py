"""
Kadim Güvenlik — WAF Fingerprinting (waf_detect)
================================================
Türkçe: Hedefin önündeki korumayı (FortiWeb, FortiGate/FortiGuard, Cloudflare, ModSecurity,
Akamai, Imperva, F5 ASM, AWS WAF, Sucuri) TESPİT eder. Amaç: doğrulayıcılar duvara KÖR
çarpmasın — WAF bilinirse payload mutasyonu (payload_mutator) vendor-profilli seçilir ve
"false-negative duvarı" kırılır.

İki kademeli (pathprobe deseni):
1. PASİF — normal GET; cookie/header/gövde imzaları (hedefe saldırı YOK).
   FortiWeb'in `FORTIWAFSID` cookie'si gibi karakteristik izler çoğu zaman yeter.
2. AKTİF TETİK — zararsız ama WAF-dostu pattern (`<script>x</script>`, `../../etc/passwd`)
   TEK keşif isteğiyle; yanıtın blok sayfasına dönüşü (403/406 + imza) vendor'ı ele verir.
   Onay/seviye kapısına tabidir (çağıran karar verir); tahribatsızdır.

Kritik ayrım: FortiWeb (WAF — FORTIWAFSID, .fgd_icon blok sayfası) ile FortiGate/FortiGuard
(ağ firewall/web filter — FortiGuard kategori blok sayfası) FARKLI iz bırakır; ikisi de
'fortinet' ailesinden ama mutasyon profilleri ayrı tutulur. Salt-L3/L4 FortiGate HTTP izi
bırakmaz → tespit edilemez (kabul edilmiş false-negative).

Karar çekirdeği SAF (match_waf / looks_blocked — I/O yok, izole test edilir); yalnız
detect_waf ağ yapar.
"""
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("waf-detect")


def origin_of(url: str) -> Optional[str]:
    """URL'den şema://host kökünü çıkar (fingerprint hedefi). Geçersizse None."""
    s = str(url or "").strip()
    if s and "://" not in s:
        s = "http://" + s
    parts = urlsplit(s)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    try:
        _ = parts.port   # 'javascript:x' gibi sahte şemalı dizgiler port'u çökertir — ele
    except ValueError:
        return None
    return f"{parts.scheme}://{parts.netloc}/"


@dataclass
class WafProfile:
    """Tespit sonucu: vendor kimliği + güven + kanıt izleri."""
    vendor: str                     # "fortiweb" | "fortiguard" | "cloudflare" | ... | "unknown"
    confidence: float               # 0.0-1.0
    evidence: List[str] = field(default_factory=list)   # insan-okunur imza gerekçeleri
    blocked_probe: bool = False     # aktif tetik bloklandı mı (WAF gerçekten devrede)

    def to_dict(self) -> Dict[str, Any]:
        return {"vendor": self.vendor, "confidence": round(self.confidence, 2),
                "evidence": self.evidence, "blocked_probe": self.blocked_probe}


# ============================================================
# İmza veritabanı (küratörlü — SAF)
# ============================================================
# Her kural: (kanal, desen, ağırlık). Kanal: "cookie", "header:<ad>", "body", "status:<kod>".
# Desen küçük-harf karşılaştırılır. Ağırlıklar toplanır; eşik altı 'unknown'.
# Referans: wafw00f + nuclei waf-detect imza setleri (kamusal bilgi).
_WAF_SIGNATURES: List[Tuple[str, str, str, float]] = [
    # --- Fortinet ailesi ---
    ("fortiweb",   "cookie", "fortiwafsid", 0.95),          # FORTIWAFSID=... — neredeyse kesin
    ("fortiweb",   "body", ".fgd_icon", 0.90),              # blok sayfası ikon yolu
    ("fortiweb",   "body", "fortiweb", 0.70),
    ("fortiweb",   "body", "web page blocked", 0.45),       # tek başına zayıf — başka WAF da der
    ("fortiguard", "body", "fortiguard", 0.85),             # FortiGate web-filter blok sayfası
    ("fortiguard", "body", "web filter blocked", 0.65),
    ("fortiguard", "body", "fortinet", 0.40),
    # --- Cloudflare ---
    ("cloudflare", "header:server", "cloudflare", 0.90),
    ("cloudflare", "header:cf-ray", "", 0.95),              # başlığın VARLIĞI yeter
    ("cloudflare", "cookie", "__cf_bm", 0.90),
    ("cloudflare", "cookie", "cf_clearance", 0.85),
    ("cloudflare", "body", "attention required! | cloudflare", 0.85),
    # --- ModSecurity ---
    ("modsecurity", "body", "mod_security", 0.85),
    ("modsecurity", "body", "modsecurity", 0.85),
    ("modsecurity", "body", "not acceptable", 0.35),        # 406 gövdesi — zayıf
    # --- Akamai ---
    ("akamai", "header:server", "akamaighost", 0.90),
    ("akamai", "header:x-akamai-transformed", "", 0.90),
    ("akamai", "body", "akamai", 0.30),
    # --- Imperva / Incapsula ---
    ("imperva", "cookie", "incap_ses", 0.90),
    ("imperva", "cookie", "visid_incap", 0.90),
    ("imperva", "body", "incapsula", 0.85),
    ("imperva", "body", "imperva", 0.80),
    # --- F5 BIG-IP ASM ---
    ("f5_asm", "cookie", "bigipserver", 0.55),              # LB cookie — ASM değil ama F5 var
    ("f5_asm", "body", "the requested url was rejected", 0.85),
    ("f5_asm", "body", "support id", 0.30),
    # --- AWS WAF / CloudFront ---
    ("aws_waf", "body", "request blocked", 0.55),
    ("aws_waf", "header:x-cache", "cloudfront", 0.60),
    ("aws_waf", "header:server", "cloudfront", 0.60),
    # --- Sucuri ---
    ("sucuri", "header:server", "sucuri", 0.85),
    ("sucuri", "header:x-sucuri-id", "", 0.95),
    ("sucuri", "body", "sucuri website firewall", 0.95),
]

# Karar eşiği: toplam ağırlık bunun altındaysa 'unknown' (zayıf tek imza WAF sayılmaz).
_DETECT_THRESHOLD = 0.6

# Genel blok göstergeleri (vendor-bağımsız) — looks_blocked için.
_BLOCK_BODY_MARKERS = (
    "access denied", "request blocked", "web page blocked", "web filter blocked",
    "the requested url was rejected", "not acceptable", "request rejected",
    "blocked by", "attack detected", "forbidden",
)
_BLOCK_STATUSES = frozenset({401, 403, 406, 419, 429, 501})


def match_waf(headers: Dict[str, str], cookies: str, body: str,
              status: int) -> List[Tuple[str, float, str]]:
    """Bir HTTP yanıtının izlerini imza DB'siyle karşılaştır (SAF — I/O yok).

    Döner: [(vendor, toplam_ağırlık, gerekçe), ...] ağırlık azalan sırada; yalnız eşik
    üstü vendor'lar. cookies: birleşik Set-Cookie metni (küçük-harf karşılaştırma)."""
    h_lower = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    ck = (cookies or "").lower()
    bd = (body or "").lower()[:200_000]   # SPA gövdelerinde taşmayı önle
    scores: Dict[str, float] = {}
    reasons: Dict[str, List[str]] = {}
    for vendor, channel, pattern, weight in _WAF_SIGNATURES:
        hit = False
        if channel == "cookie":
            hit = pattern in ck
        elif channel.startswith("header:"):
            name = channel.split(":", 1)[1]
            hit = (name in h_lower) if pattern == "" else (pattern in h_lower.get(name, ""))
        elif channel == "body":
            hit = pattern in bd
        elif channel.startswith("status:"):
            hit = status == int(channel.split(":", 1)[1])
        if hit:
            scores[vendor] = scores.get(vendor, 0.0) + weight
            reasons.setdefault(vendor, []).append(f"{channel}~'{pattern}' (+{weight})")
    out = [(v, min(0.99, s), "; ".join(reasons[v])) for v, s in scores.items()
           if s >= _DETECT_THRESHOLD]
    out.sort(key=lambda t: t[1], reverse=True)
    return out


def looks_blocked(status: int, body: str) -> bool:
    """Yanıt WAF bloğu gibi mi? (SAF) Doğrulayıcılar 'hedef güvenli' ile 'WAF blokladı'
    durumunu ayırsın diye — blok, mutasyonla TEKRAR DENEME sinyalidir."""
    if status in _BLOCK_STATUSES:
        return True
    bd = (body or "").lower()[:64_000]
    return any(m in bd for m in _BLOCK_BODY_MARKERS)


# Aktif tetik payload'ları: WAF'ların HEPSİNİN yakaladığı, hedefe ZARARSIZ klasik pattern'ler.
# Amaç sömürmek değil, duvarı Görmek — tek-iki istekle sınırlı tutulur.
_TRIGGER_PROBES = [
    ("kadimprobe", "%3Cscript%3Ealert(1)%3C/script%3E"),      # XSS tetik (encode'lu)
    ("kadimprobe", "..%2f..%2f..%2fetc%2fpasswd"),            # traversal tetik
]


async def detect_waf(base_url: str, client: httpx.AsyncClient,
                     *, active: bool = True) -> Optional[WafProfile]:
    """Hedefin WAF'ını iki kademeyle parmak izle (I/O — ince katman).

    Pasif her zaman; aktif tetik yalnız active=True iken (çağıran seviye/onay kapısına
    bağlar). Hiç imza yoksa None (WAF yok ya da tanınmıyor — 'unknown' sayılmaz, sessiz)."""
    # 1) PASİF — normal istek
    try:
        r = await client.get(base_url, timeout=15.0)
    except Exception:
        return None
    cookies = "; ".join(r.headers.get_list("set-cookie")) if hasattr(r.headers, "get_list") \
        else r.headers.get("set-cookie", "")
    body = r.text or ""
    hits = match_waf(dict(r.headers), cookies, body, r.status_code)
    blocked = False

    # 2) AKTİF TETİK — blok sayfası imzaları pasifte görünmeyen WAF'ı ele verir
    if active:
        sep = "&" if "?" in base_url else "?"
        for pname, pval in _TRIGGER_PROBES:
            try:
                tr = await client.get(f"{base_url}{sep}{pname}={pval}", timeout=15.0)
            except Exception:
                continue
            tbody = tr.text or ""
            if looks_blocked(tr.status_code, tbody):
                blocked = True
            tcookies = "; ".join(tr.headers.get_list("set-cookie")) if hasattr(tr.headers, "get_list") \
                else tr.headers.get("set-cookie", "")
            hits = match_waf(dict(tr.headers), tcookies, tbody, tr.status_code) or hits
            if hits:
                break   # vendor bulundu — daha fazla tetik yok (dokunuş tasarrufu)

    if not hits:
        if blocked:
            return WafProfile("unknown", 0.5, ["aktif tetik bloklandı ama imza eşleşmedi"],
                              blocked_probe=True)
        return None
    vendor, conf, why = hits[0]
    return WafProfile(vendor, conf, [why], blocked_probe=blocked)
