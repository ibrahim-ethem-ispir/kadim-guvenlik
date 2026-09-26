"""
Kadim Güvenlik — JavaScript Secret Avcısı (Bug Bounty P2-C)
=============================================================
Türkçe: Crawler JS dosyalarını zaten indiriyor ama içindeki SIZMIŞ SIRLARI taramıyor.
Oysa bug bounty'de en hızlı para: bir bundle.js'ten sızan AWS_SECRET_ACCESS_KEY,
Slack webhook, JWT signing key, iç IP+port hardcoded.

Bu modül crawler'ın indirdiği JS gövdelerini KÜRATÖRLÜ regex setiyle tarar;
eşleşen sırları maskeler (ilk 4 + son 4 karakter — rapora sızmaz) ve doğrular
(pathprobe validator deseni: sır gerçek mi — boş/placeholder mı?). Bulgu snippet'i
güvenli maskeli haliyle Evidence olur.

Regex seti: TruffleHog + Gitleaks + Shhgit koleksiyonlarından elenmiş, false-positive
oranı düşük desenler. Yalnızca OKUMA (dosya yazma/istek atma YOK) — tahribatsız.

Tasarım: SAF karar çekirdeği (scan_js_content) + I/O katmanı (scan_js_asset) ayrık.
İzole test edilebilir (test_js_secrets.py).
"""

import logging
import math
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("js-secrets")

# ============================================================
# Küratörlü sır regex'leri — (desen, sır_adı, severity, validator)
# ============================================================
# validator: desenin yanında VARSAGI doğrulama adımı (placeholder/boş eleme).
# 'length': en az N karakter, 'no_placeholder': 'YOUR_KEY'/'xxx'/'test' içermez,
# 'aws_format': AKIA... bazlı IAM key prefix, 'jwt_header': base64 başlık parse'ı.
# 'slack_format': TXXXX... prefix, 'github_format': ghp_/gho_ prefix.

# AWS IAM anahtarları — AKIA... (20 char, büyük harf+rakam)
_AWS_ACCESS_KEY = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
# AWS secret key — 40 alfanümerik, base64 görünümünde. Minify JS'te
# false-positive'i azaltmak için: eşleşme yakınında (80 char) 'secret'/'aws'
# anahtar kelimesi geçme şartı _is_placeholder'da kontrol edilir.
_AWS_SECRET = re.compile(r'\b(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])')
# Generic API key — 'key'/'api'/'token' kelime sınırında, ardından : = ve değer.
# Tırnaklı ("apiKey": "...") VE tırnaksız (apiKey: "...") sözdizimlerini yakalar.
_API_KEY_KV = re.compile(r'''\b(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token|secret[_-]?key|access[_-]?key)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{20,60})["']''', re.I)
# JWT — eyJ... base64url header + payload + signature (3 bölümlü, noktalı)
_JWT = re.compile(r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b')
# GitHub personal access token — ghp_ / gho_ / github_pat_ prefix
_GITHUB_TOKEN = re.compile(r'\b(?:ghp|gho|github[_-]pat)[_\-][A-Za-z0-9_\-]{20,60}\b')
# Slack webhook — TXXXXX/BXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX formatı
_SLACK_WEBHOOK = re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+')
# Google API key — AIza... (39 karakter)
_GOOGLE_API = re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')
# Private key header — "-----BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY-----"
_PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----')
# Generic password/secret in key-value form (tırnaklı/tırnaksız sözdizimi)
_PASSWORD_KV = re.compile(r'''\b(?:password|passwd|pwd|secret|db[_-]?pass|db[_-]?url|connection[_-]?string)\s*[:=]\s*["']([^"'\n]{8,120})["']''', re.I)
# İç IP + port — 10.x / 172.16-31.x / 192.168.x (SSRF yüzeyi)
_INTERNAL_IP_PORT = re.compile(r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b')
# Database connection string yakalayıcı (mongodb://, mysql://, postgres://...)
_DB_URL = re.compile(r'''(?:mongodb|mysql|postgres(?:ql)?|redis|jdbc|sqlserver)://[^\s"'<>]{10,150}''', re.I)

# Sır ailesi → (regex, ad, severity, placeholder_denetleyici)
_SECRET_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
    (_AWS_ACCESS_KEY, "AWS Access Key", "high", "aws_access"),
    (_AWS_SECRET, "AWS Secret Key", "critical", "aws_secret"),
    (_API_KEY_KV, "API Key/Token (KV)", "high", "api_key"),
    (_JWT, "JWT Token", "medium", "jwt"),
    (_GITHUB_TOKEN, "GitHub Personal Access Token", "critical", "github_token"),
    (_SLACK_WEBHOOK, "Slack Webhook URL", "high", "slack_webhook"),
    (_GOOGLE_API, "Google API Key", "high", "google_api"),
    (_PRIVATE_KEY, "Private Key (PEM)", "critical", "private_key"),
    (_PASSWORD_KV, "Password/Secret (KV)", "high", "password"),
    (_INTERNAL_IP_PORT, "Internal IP + Port", "medium", "internal_ip"),
    (_DB_URL, "Database Connection String", "critical", "db_url"),
]


# ============================================================
# Masking — sır rapora ÇIPLAK gitmez
# ============================================================

def mask_secret(value: str) -> str:
    """Sırrı rapor-güvenli maskeye çevir: ilk 4 + son 4 karakter, orta ***.
    8 karakterden kısa sırlar tamamen maskelenir (çok kısa = değersiz)."""
    v = str(value or "").strip()
    if len(v) <= 8:
        return "***"
    return v[:4] + "***" + v[-4:]


# ============================================================
# Placeholder denetleyiciler — "foo: bar" diye her bar sır değildir
# ============================================================

def _is_placeholder(value: str, kind: str) -> bool:
    """Değer gerçek sır mı yoksa placeholder/boş/test değeri mi?"""
    v = str(value or "").strip()
    if not v or len(v) < 8:
        return True
    vl = v.lower()
    generic = ("your_key", "your_secret", "your_token", "your_api",
               "your_password", "your_value", "your_string",
               "placeholder", "changeme", "change_me", "replace_me",
               "xxxxxxxx", "test_key", "test_secret", "test_value",
               "example", "ex@mple", "sample",
               "null", "undefined", "none", "todo", "fixme",
               "<your", "[your", "{your",
               "xxx", "***", "____", "----")
    if any(p in vl for p in generic):
        return True
    if kind in ("aws_access",):
        return len(v) < 16
    if kind in ("aws_secret",):
        # Uzunluk + büyük harf zorunlu (base64'te genelde karışık case olur).
        return len(v) < 30 or not any(c.isupper() for c in v)
    if kind in ("jwt",):
        parts = v.split(".")
        if len(parts) != 3:
            return True
        try:
            import base64
            for p in parts:
                padded = p + "=" * (-len(p) % 4)
                base64.urlsafe_b64decode(padded)
        except Exception:
            return True
        return False
    unique = set(vl)
    if len(unique) <= 2:
        return True
    return False


# ============================================================
# Güç/kademe denetimi — "eşleşti" ≠ "gerçek gizli sır"
# ============================================================
# NEDEN: saf regex eşleşmesi false-positive kaynağıdır. En yaygın tuzak: TASARIMI GEREĞİ
# public olan anahtarlar (Stripe pk_, reCAPTCHA site key, istemci Google API key) "sır" diye
# raporlanır. İkinci tuzak: düşük-entropili KV değerleri (form alanı, örnek, kelime) rastgele
# sır sanılır. Bu katman her bulguya güven kademesi (confidence_tier) verir ve gerekirse
# severity'yi düşürür — böylece js_secrets körü körüne "verified/critical" basmaz.

# Public-by-design önekler: bunlar istemcide bulunması NORMAL olan anahtarlardır (sır değil).
_PUBLIC_KEY_PREFIXES = (
    "pk_live_", "pk_test_", "pk-", "pub_", "public_",   # Stripe publishable vb.
    "6l",                                                # reCAPTCHA site key (6L...)
    "ua-", "g-", "ga-", "gtm-",                          # Google Analytics/Tag ölçüm kimliği
)

# Kardeş kullanıcı-adı anahtarları: bir password'ün hemen yanında somut değerli bir
# username/email/login anahtarı duruyorsa bu HARDCODED CREDENTIAL çiftidir (tipik olarak
# login formunun defaultValues'enjeksiyonu). İnsan şifresi DOĞASI GEREĞİ düşük-entropilidir;
# burada entropi-cezası uygulamak gerçek bulguyu haksızca unconfirmed/medium'a düşürür.
_USERNAME_SIBLING = re.compile(
    r'''\b(?:user[_-]?name(?:[_-]?or[_-]?email)?|e[_-]?mail|login|account(?:[_-]?name)?|user)\s*[:=]\s*["']([^"'\n]{3,60})["']''',
    re.I,
)

# Login/form bağlam işaretleri — hardcoded credential olasılığını güçlendirir.
_CREDENTIAL_CONTEXT_MARKERS = (
    "defaultvalues", "useform", "login", "signin", "sign-in", "auth",
    "superadmin", "usernameor", "credentials",
)

# Kardeş username için hafif placeholder eleme (sır denetleyicisinden daha gevşek —
# 'admin' gibi kısa ama anlamlı değerler geçerli kullanıcı adıdır, elenmemeli).
_USERNAME_PLACEHOLDERS = (
    "your_", "example", "placeholder", "changeme", "change_me", "xxx",
    "dummy", "sample", "null", "undefined", "test@", "user@", "email@",
)


def _shannon_entropy(s: str) -> float:
    """Karakter başına Shannon entropisi (bit/char). Rastgele sır (~4-6) ile kelime/
    placeholder'ı (~2-3.5) ayırır. Boş → 0.0 (SAF)."""
    if not s:
        return 0.0
    n = len(s)
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def secret_strength(value: str, kind: str, *,
                    has_credential_context: bool = False) -> Tuple[str, Optional[str]]:
    """Bir sır adayının (confidence_tier, severity_override|None) gücünü belirle (SAF).

    confidence_tier: confirmed (tek-anlamlı format) / probable (güçlü sinyal, düşük FP) /
    unconfirmed (public-by-design veya düşük entropi — olası false-positive). severity_override
    None ise çağıran mevcut severity'yi korur; değilse onu bu değere DÜŞÜRÜR.

    has_credential_context: yalnız password türü için anlamlı — değer bir login formunun
    defaultValues'unda / yanında username ile duruyorsa gerçek kimlik bilgisidir; entropi
    cezası uygulanmaz (insan şifresi düşük-entropili olur)."""
    v = str(value or "")
    vl = v.lower()
    # 1) Public-by-design → sır değil; kaydet ama düşük severity + unconfirmed.
    if any(vl.startswith(p) for p in _PUBLIC_KEY_PREFIXES):
        return "unconfirmed", "low"
    # 2) Tek-anlamlı formatlar (yanlış-pozitif pratikte imkânsız)
    if kind == "private_key":
        return "confirmed", None            # PEM private key sızıntısı — tartışmasız
    if kind in ("github_token", "slack_webhook", "aws_access", "jwt", "internal_ip"):
        return "probable", None             # format güçlü ama "canlı/geçerli" kanıtlanmadı
    if kind == "aws_secret":
        return ("probable", None) if _shannon_entropy(v) >= 3.2 else ("unconfirmed", "medium")
    if kind == "db_url":
        # Kimlik bilgisi (user:pass@) taşıyorsa gerçek sır; yoksa yalnız bağlantı host'u.
        has_creds = bool(re.search(r"://[^/\s:@]+:[^/\s@]+@", v))
        return ("probable", None) if has_creds else ("unconfirmed", "medium")
    if kind == "google_api":
        # İstemci Google API key genelde HTTP-referer/kısıtlı → "high" basmak klasik FP.
        return "unconfirmed", "low"
    if kind in ("api_key", "password"):
        # HARDCODED CREDENTIAL istisnası: login şifresi yanında username/form bağlamı varsa
        # gerçek kimlik bilgisidir — high severity korunur, entropi-cezası UYGULANMAZ.
        if kind == "password" and has_credential_context:
            return "probable", None
        # Jenerik KV: entropi rastgele sırrı kelime/placeholder'dan ayırır.
        if len(v) >= 16 and _shannon_entropy(v) >= 3.2:
            return "probable", None
        return "unconfirmed", ("medium" if kind == "password" else "low")
    return "unconfirmed", None


def _context_near_keyword(body: str, pos: int, radius: int = 80) -> bool:
    """Eşleşme pozisyonunun radius karakter yakınında 'secret'/'aws'/'api'/'token'/'key'
    anahtar kelimesi geçiyor mu? Minify JS false-positive elemesi."""
    start = max(0, pos - radius)
    end = min(len(body), pos + radius + 40)
    window = body[start:end].lower()
    return any(kw in window for kw in (
        "secret", "aws", "token", "api_key", "apikey", "credential",
        "password", "passwd", "private", "auth",
    ))


def _find_sibling_username(body: str, pos: int, radius: int = 160) -> Optional[str]:
    """Password eşleşmesinin yakınında somut değerli bir username/email/login anahtarı
    var mı? Varsa en yakın olanın değerini döndür (hardcoded credential çifti sinyali).
    Username bir SIR değildir — maskelenmez, bulguyu eyleme-dönüştürülebilir kılar (SAF)."""
    start = max(0, pos - radius)
    end = min(len(body), pos + radius)
    window = body[start:end]
    best: Optional[Tuple[int, str]] = None
    for m in _USERNAME_SIBLING.finditer(window):
        val = (m.group(1) or "").strip()
        vl = val.lower()
        if len(val) < 3 or any(p in vl for p in _USERNAME_PLACEHOLDERS):
            continue
        if len(set(vl)) <= 2:
            continue
        dist = abs((start + m.start()) - pos)
        if best is None or dist < best[0]:
            best = (dist, val)
    return best[1] if best else None


def _is_credential_context(body: str, pos: int, radius: int = 200) -> bool:
    """Eşleşme yakınında login/form/defaultValues bağlam işaretleri geçiyor mu?
    Hardcoded credential olasılığını güçlendiren ikincil sinyal (SAF)."""
    start = max(0, pos - radius)
    end = min(len(body), pos + radius)
    window = body[start:end].lower()
    return any(kw in window for kw in _CREDENTIAL_CONTEXT_MARKERS)


# ============================================================
# SAF çekirdek — JS string'ini tara
# ============================================================

# Tek seferde taranacak maks JS boyutu (SPA bundle'ları devasa olabilir;
# ilk 512KB yeter — sırlar genelde bundle başında/ortasında, derin minify'da
# bile bu kadarı webpack define-plugin enjeksiyonlarını kapsar).
_MAX_SCAN_BYTES = 512 * 1024

# Betik başına maks bulgu — aynı bundle'da 50 aynı kütüphane deseni olabilir,
# sadece ilk 8 tanesini raporla (gürültü/göz korkutma önlemi).
_MAX_FINDINGS_PER_ASSET = 8


def scan_js_content(js: str, asset_url: str = "", *,
                    max_bytes: int = _MAX_SCAN_BYTES,
                    max_findings: int = _MAX_FINDINGS_PER_ASSET,
                    reveal: bool = False) -> List[Dict[str, Any]]:
    """JS gövdesini tüm sır desenleriyle tara, bulguları maskeli döndür (SAF — I/O yok).

    Çıktı: [{"secret_type": "AWS Access Key", "value_masked": "AKIA***ABCD",
            "line_text": "...", "severity": "high", "asset_url": "https://x/app.js",
            "validator": "aws_access"}] — yalnızca placeholder olmayan, gerçek sır
    ihtimali yüksek eşleşmeler. Sıra: severity azalan.

    reveal=True: bulgulara HAM `value` + maskesiz `line_text_raw` da eklenir (kanıtlama).
    Yalnız admin-only canlı yeniden-getirme yolundan (path_probe reveal=True emsali) çağrılır;
    DB'ye/canlı akışa ASLA reveal ile girmez — kalıcı depo maskeli kalır. Varsayılan (False)
    davranışı bit-bit aynıdır (regresyon yok)."""
    if not js:
        return []
    body = js[:max_bytes] if len(js) > max_bytes else js
    findings: List[Dict[str, Any]] = []
    seen_values: set = set()  # aynı sırı tekrar raporlama

    for pattern, name, severity, validator in _SECRET_PATTERNS:
        for match in pattern.finditer(body):
            if len(findings) >= max_findings:
                break
            # KV desenlerinde yakalanan grup 1, düz desenlerde match.group(0)
            value = match.group(1) if pattern is _API_KEY_KV or pattern is _PASSWORD_KV else match.group(0)
            if not value:
                value = match.group(0)
            if value in seen_values:
                continue
            if _is_placeholder(value, validator):
                continue
            # AWS secret: minify JS'te 40-char random string patlamasını önle —
            # yakınında 'secret'/'aws'/'token' anahtar kelimesi şart.
            if validator == "aws_secret" and not _context_near_keyword(body, match.start()):
                continue
            seen_values.add(value)
            # HARDCODED CREDENTIAL tespiti: password yanında somut username veya login/form
            # bağlamı varsa gerçek kimlik bilgisidir → entropi-cezası uygulanmaz, high korunur.
            username_sibling: Optional[str] = None
            cred_context = False
            if validator == "password":
                username_sibling = _find_sibling_username(body, match.start())
                cred_context = bool(username_sibling) or _is_credential_context(body, match.start())
            # GÜÇ/KADEME denetimi: public-by-design anahtar veya düşük-entropili KV değeri
            # false-positive'dir → kademe unconfirmed + severity düşürülür (körü körüne
            # "high/critical" basma). Tek-anlamlı formatlar (PEM/github/slack) güçlü kalır.
            tier, sev_override = secret_strength(value, validator, has_credential_context=cred_context)
            eff_severity = sev_override or severity
            # Eşleşen satırın bağlamını al — kardeş username genelde ÖNCE gelir, bu yüzden
            # öne doğru daha geniş pencere (90) açılır; sırın kendisi maskeli.
            start = max(0, match.start() - 90)
            end = min(len(body), match.end() + 30)
            raw_window = body[start:end].replace("\n", " ").replace("\r", " ").strip()
            line_preview = raw_window.replace(value, mask_secret(value))
            _f = {
                "secret_type": name,
                "value_masked": mask_secret(value),
                # username bir sır değildir; eyleme-dönüştürülebilirlik için maskelenmez.
                "username": username_sibling,
                "line_text": line_preview[:240],
                "severity": eff_severity,
                "asset_url": asset_url,
                "validator": validator,
                "confidence_tier": tier,
            }
            if reveal:
                # HAM değerler yalnız admin unmask yanıtında taşınır (DB'ye asla yazılmaz).
                _f["value"] = value
                _f["line_text_raw"] = raw_window[:240]
            findings.append(_f)
        if len(findings) >= max_findings:
            break
    return findings


# ============================================================
# I/O katmanı — crawler'ın indirdiği JS varlığı üstünde tara
# ============================================================

async def scan_js_asset(client, asset_url: str, *,
                         max_bytes: int = _MAX_SCAN_BYTES,
                         reveal: bool = False) -> List[Dict[str, Any]]:
    """Tek bir JS varlığını indirip tara. Hata → boş liste (best-effort).
    Tam bundle'ı indirmekten kaçınmak için stream + cap (crawler ile aynı desen).
    reveal yalnız admin unmask yolundan geçer (bkz. scan_js_content)."""
    try:
        async with client.stream("GET", asset_url, timeout=12.0) as r:
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) >= max_bytes:
                    break
            js = buf.decode("utf-8", errors="replace")
            return scan_js_content(js, asset_url, reveal=reveal)
    except Exception as e:
        logger.debug(f"JS secret taraması atlandı ({asset_url}): {e}")
        return []


# ============================================================
# UNMASK — yetkili operatör için canlı yeniden-getirme (TEMA 3.1)
# ============================================================

async def reveal_secret(client, asset_url: str, value_masked: str, *,
                        validator: Optional[str] = None,
                        secret_type: Optional[str] = None) -> Dict[str, Any]:
    """Bir JS-sır bulgusunu CANLI hedeften yeniden-getirip HAM değerini çöz.

    path_probe `reveal=True` emsali: sır DB'de/rapordan maskeli kalır; yetkili operatör
    kendi hedefini doğrulamak isterse motor varlığı YENİDEN indirir ve maskeyle eşleşen
    ham değeri döner. Böylece ham parola hiçbir kalıcı depoda tutulmaz — yalnız canlı
    yeniden-türetilir (deterministik, tahribatsız GET).

    Eşleştirme kimliği: value_masked (+ verilmişse validator/secret_type). Aynı maskeye
    birden çok FARKLI ham değer düşerse belirsizlik döner (409 gibi) — operatör daraltmalı.

    Döner: {"status": "revealed|not_found|drifted|ambiguous", "value": <ham|None>, ...}
    """
    findings = await scan_js_asset(client, asset_url, reveal=True)
    if not findings:
        # Varlık artık erişilemez ya da sır gitmiş (rotasyon/yeniden-derleme) → drift.
        return {"status": "drifted", "value": None,
                "detail": "Varlık indirilemedi ya da sır artık yok (rotasyon/rebuild olabilir)."}
    matches = []
    for f in findings:
        if f.get("value_masked") != value_masked:
            continue
        if validator and f.get("validator") != validator:
            continue
        if secret_type and f.get("secret_type") != secret_type:
            continue
        matches.append(f)
    if not matches:
        return {"status": "not_found", "value": None,
                "detail": "Bu maske canlı varlıkta bulunamadı — sır rotasyona uğramış olabilir."}
    distinct = {m.get("value") for m in matches}
    if len(distinct) > 1:
        return {"status": "ambiguous", "value": None, "match_count": len(distinct),
                "detail": "Aynı maskeye birden çok farklı ham değer düşüyor — validator/tip ile daralt."}
    m = matches[0]
    return {
        "status": "revealed",
        "value": m.get("value"),
        "value_masked": value_masked,
        "line_text_raw": m.get("line_text_raw"),
        "username": m.get("username"),
        "secret_type": m.get("secret_type"),
        "validator": m.get("validator"),
        "asset_url": asset_url,
    }
