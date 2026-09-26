"""
Kadim Güvenlik — False-Positive Sinyalleri (P2, deterministik)
===============================================================
Türkçe: Bir bulgunun "kanıtı" aslında GERÇEK içerik mi, yoksa WAF engel sayfası / giriş
duvarı / genel hata / catch-all kabuğu mı? Sektörün klasik false-positive kaynağı: nuclei
bir template'i eşler ama eşleşen şey aslında bir WAF challenge veya login sayfasıdır (içerik
yanıtın kendisi değil). Bu modül SAF sinyaller üretir (I/O yok) — pipeline bunları kullanıp
şüpheli bulguları 'unconfirmed'a çeker ve `fp_reason` ile NEDEN'ini operatöre söyler.

Tasarım (path_probe/verification deseni): karar çekirdeği SAF ve izole test edilebilir
(test_fp_signals.py); host catch-all probu (I/O) pipeline tarafında ince bir katman.
"""

import re
from typing import List, Optional, Sequence

# ---- İmza setleri (küçük harfe indirgenmiş gövdede aranır) ----

# WAF / bot-koruma engel sayfaları — eşleşen bulgu neredeyse kesin FP'dir.
_WAF_BLOCK_SIGNS = (
    "access denied", "request blocked", "you have been blocked",
    "attention required", "cloudflare", "cf-ray", "ray id:",
    "incapsula incident", "request unsuccessful. incapsula",
    "powered by sucuri", "sucuri website firewall", "mod_security", "mod security",
    "web application firewall", "blocked by", "akamai", "the requested url was rejected",
    "your request has been blocked", "security check to access", "please verify you are a human",
    "captcha", "hcaptcha", "recaptcha",
)

# Giriş / kimlik duvarı — "admin paneli buldum" sanılan şey aslında login sayfasıdır.
_AUTH_WALL_SIGNS = (
    "please sign in", "please log in", "sign in to continue", "login required",
    "session has expired", "session expired", "you must be logged in",
    "authentication required", "unauthorized access", "please authenticate",
)

# Genel hata / soft-404 — 200 döner ama içerik "bulunamadı/hata" der.
_ERROR_PAGE_SIGNS = (
    "404 not found", "page not found", "not found", "error 404",
    "an error has occurred", "an error occurred", "internal server error",
    "500 internal server error", "503 service", "something went wrong",
    "oops! that page", "we couldn't find", "sayfa bulunamadı", "bir hata oluştu",
)

_MAINTENANCE_SIGNS = (
    "under maintenance", "temporarily unavailable", "be right back",
    "scheduled maintenance", "site maintenance", "bakım çalışması", "bakımda",
)

# Login formu tespiti: password input + login bağlamı → auth duvarı.
_PASSWORD_INPUT_RE = re.compile(r'type\s*=\s*["\']?password', re.I)


def classify_response_page(text: Optional[str], status: Optional[int] = None) -> Optional[str]:
    """Yanıt gövdesi GERÇEK bir bulgu içeriği mi, yoksa engel/duvar/hata sayfası mı? (SAF)

    Döner: "waf_block" | "auth_wall" | "generic_error" | "maintenance" | "empty" | None.
    None = normal/özgün içerik gibi (bulgu güvenilir). Bir etiket dönerse bulgunun "kanıtı"
    aslında bu sayfadır → çağıran onu 'unconfirmed'a çeker + fp_reason yazar.

    NOT: yalnız DEMOTE amaçlıdır (asla bir bulguyu yükseltmez) — yanlış negatif riski düşük;
    en fazla, gerçekten bu sayfaları içeren nadir bir bulgu 'incelenmeli'ye düşer (zararsız)."""
    body = (text or "")
    if len(body.strip()) < 20:
        return "empty"
    low = body.lower()

    if any(s in low for s in _WAF_BLOCK_SIGNS):
        return "waf_block"
    if any(s in low for s in _MAINTENANCE_SIGNS):
        return "maintenance"
    # Auth duvarı: güçlü metinsel imza VEYA (password input + 401/403).
    if any(s in low for s in _AUTH_WALL_SIGNS):
        return "auth_wall"
    if _PASSWORD_INPUT_RE.search(low) and (status in (401, 403)):
        return "auth_wall"
    # Genel hata / soft-404: metinsel imza, ya da 2xx statüde "not found"/"error" metni.
    if any(s in low for s in _ERROR_PAGE_SIGNS):
        return "generic_error"
    return None


def _norm_len(text: Optional[str]) -> int:
    return len((text or "").strip())


def is_catchall_from_samples(statuses: Sequence[int],
                             bodies: Optional[Sequence[str]] = None,
                             *, min_samples: int = 2) -> bool:
    """Rastgele/var-olmayan yollara verilen yanıtlardan host'un catch-all olup olmadığını
    kararlaştır (SAF). Düzgün sunucu var-olmayan yola 4xx döner; catch-all/SPA ise 2xx
    (uygulama kabuğu) döner → o host'ta 'yol bulundu' türü bulgular şüphelidir.

    Kural: en az `min_samples` örnek VE tümü 2xx/3xx (4xx/5xx YOK). bodies verilirse ek
    tutarlılık: gövde uzunlukları birbirine yakınsa (aynı kabuk) sinyal güçlenir; farklıysa
    catch-all sayma (dinamik içerik olabilir)."""
    codes = [c for c in statuses if isinstance(c, int)]
    if len(codes) < min_samples:
        return False
    # Herhangi biri 4xx/5xx ise sunucu var-olmayanı reddediyor → catch-all DEĞİL.
    if any(c >= 400 for c in codes):
        return False
    if not all(200 <= c < 400 for c in codes):
        return False
    if bodies:
        lens = [_norm_len(b) for b in bodies if b is not None]
        lens = [n for n in lens if n > 0]
        if len(lens) >= 2:
            lo, hi = min(lens), max(lens)
            # Uzunluklar çok farklıysa (>%50 sapma) aynı kabuk değil → catch-all sayma.
            if hi > 0 and (hi - lo) / hi > 0.5:
                return False
    return True


# Rastgele/var-olmayan yol üreteci — catch-all probu için (I/O çağıran tarafta).
def random_probe_paths(n: int = 2) -> List[str]:
    """Var olması pratikte imkânsız rastgele yollar (catch-all probu). SAF — sadece string."""
    import secrets
    return [f"/kadim-fp-probe-{secrets.token_hex(8)}-{i}.html" for i in range(max(1, n))]


# Nuclei "varlık/ifşa" tabanlı bulgu mu? (catch-all demote'u yalnız bunlara uygular —
# aktif enjeksiyon/CVE bulgularına değil.) Kaba sınıflama: template-id/başlık ipuçları.
_EXPOSURE_HINTS = (
    "exposure", "exposed", "detect", "disclosure", "listing", "directory-listing",
    "default-page", "install", "backup", "config", "panel", "login", "dashboard",
)


def looks_like_exposure_finding(title: str = "", template_id: str = "") -> bool:
    """Bulgu 'bir şey var/ifşa' türü mü (varlığı statü/içerik-varlığına dayanır)? (SAF)
    Bu tür bulgular catch-all host'ta şüphelidir; enjeksiyon/CVE bulguları etkilenmez."""
    hay = f"{title} {template_id}".lower()
    return any(h in hay for h in _EXPOSURE_HINTS)
