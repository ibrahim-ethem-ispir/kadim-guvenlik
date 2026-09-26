"""
Kadim Güvenlik — Dikey Yetki Yükseltme / FAC matrisi (Broken Function-Level Access Control)
============================================================================================
IDOR/BOLA (idor_probe) NESNE bazlı boşluğu kanıtlar (A'nın kaydı B'ye açılıyor mu). Bu modül
ROL/İŞLEV bazlı boşluğu kanıtlar: sıradan bir kimliğin yönetici-fonksiyonu uçlarına ulaşması.
İnsan pentester'ların en sık raporladığı kritik sınıf, otomatik tarayıcıların kör noktası —
çünkü imza değil, DİFERANSİYEL gözlem:

  ┌─ KİP 1 — YÖNTEM AŞINMASI (1 kimlik yeterli, rolden BAĞIMSIZ) → confirmed/probable
  │   A'ya kanonik GET REDDEDİLDİ (401/403) ama aynı URL biçim-değiştirmiş hâliyle
  │   (X-HTTP-Method-Override / X-Original-URL / X-Rewrite-URL / ?_method / yol
  │   normalizasyonu) 2xx + dolu veri veriyor → denetim katmanı yalnız kanonik isteği
  │   denetliyor; bypass KANITLI. JSON/API gövde → confirmed; HTML kabuk → probable
  │   (SPA-kabuk FP kalkanı — doktrin: FP'yi confirmed'a yazma).
  │
  └─ KİP 2 — AYRICALIKLI YOL ERİŞİMİ (anon-red + A-2xx diferansiyeli) → confirmed/probable
      Anonim istek REDDEDİLİYORKEN (kaynak korunaklı) A'nın token'ı korumalı yönetici
      ucundan dolu veri alıyorsa: A'nın JWT iddiaları BARİZ non-admin diyorsa → confirmed
      dikey yetki yükseltme; rol okunamıyorsa → probable (A gerçekten yönetici olabilir).

Tasarım (idor_probe ile aynı sözleşme): karar çekirdeği SAF (ağ/DB yok, izole test) →
I/O katmanı ince ve TAHRİBATSIZ (yalnız GET + başlık/query/yol hilesi; POST/PUT GÖNDERİLMEZ
— handler'ı zayıf endpoint'te durum değiştirme riski BİLİNÇLİ alındı), bütçeli, ASLA raise
etmez. Doktrin: LLM yok — tamamen deterministik.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

# idor_probe'un ölçüm primitifleri AYNEN paylaşılır (tek doğruluk kaynağı; exploit_chain
# ve proof_contract da aynı deseni kullanır).
from .idor_probe import (Measured, _get, _is_substantive, _is_denied,
                         _looks_like_data)

logger = logging.getLogger("fac-matrix-probe")

# ---- Bütçeler (IDOR ile aynı büyüklük mertebesi — observe döngüsü başına sınırlı maliyet) ----
_MAX_TARGETS = 8           #kaç ayrıcalıklı URL problanır
_MAX_VARIANTS = 6          # reddedilen URL başına azami aşınma varyantı
_PER_REQUEST_TIMEOUT = 8.0

# ---- İşlev-seviyesi hassas path ipuçları (zincir hint'leri ailesi + appliance panelleri) ----
# Segment sınırlı eşleşme (^|[/_.\-?=&] ... $ benzeri): "admin" kelimesi "readmin" gibi
# alt-dizilerde değil, YALNIZ path segmenti olarak geçince ayrıcalıklı sayılır (FP kısan kalkan).
_PRIV_HINT = re.compile(
    r"(?:^|[/_.\-?=&])(admin|administrator|manage|manager|dashboard|console|debug|"
    r"actuator|settings|internal|billing|backup|config|system|phpmyadmin|adminer|"
    r"grafana|kibana|webadmin|cpanel|super|root|ops)(?:$|[/_.\-?=&])", re.I)

# Kök origin üzerinde sentetik klasik dikey-FAC yolları — "non-admin açısından erişilmesi
# KRİTİK olurdu" minimum seti. Dizin enum/ifşa taraması path_probe'un işi; buranın farkı
# KİMLİK diferansiyeli + aşınma varyantı çalıştırması.
_SYNTH_PATHS = [
    "/admin", "/admin/", "/admin/users", "/administrator",
    "/api/admin", "/api/admin/users", "/api/settings", "/api/internal",
    "/console", "/debug", "/actuator", "/actuator/env",
    "/phpmyadmin/", "/adminer.php", "/manager/html",
]


def select_privileged_urls(pool: List[str], *, max_targets: int = _MAX_TARGETS) -> List[str]:
    """Aday havuzundan ayrıcalıklı uçları seç (SAF). Gerçek keşif URL'leri (hint-eşleşen)
    ÖNCE gelir, sonra kök origin üzerinde sentetik klasik admin yolları. Dedup + kapalı."""
    real = [u for u in dict.fromkeys(pool)
            if isinstance(u, str) and u.startswith(("http://", "https://"))]
    hinted = [u for u in real if _PRIV_HINT.search(urlsplit(u).path or "")]
    origin = ""
    for u in real:
        p = urlsplit(u)
        if p.scheme and p.netloc:
            origin = f"{p.scheme}://{p.netloc}"
            break
    out: List[str] = []
    seen: set = set()
    for u in hinted:
        if u not in seen:
            seen.add(u)
            out.append(u)
    if origin:
        for pth in _SYNTH_PATHS:
            u = origin + pth
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out[:max_targets]


def tamper_variants(url: str) -> List[Tuple[str, str, Dict[str, str]]]:
    """Aşınma varyantları (SAF): (etiket, url, ek-başlıklar). Yalnız başlık/query/yol
    hilesi — WİRE'daki HTTP metodu DEĞİŞMEZ (daima GET). POST/PUT bilinçli YOK: boş
    gövdeli bile olsa yazıcı handler'a istek atmak tahribat riski (doktrin: tahribatsız).
    Denetim filtrelerinin çoğu yalnız 'GET <tam yol>' imzasına bakar; biçim-değişmiş
    aynı istek filreyi aşabilir — kanıt budur."""
    parts = urlsplit(url)
    path = parts.path or "/"
    out: List[Tuple[str, str, Dict[str, str]]] = [
        ("x-method-override:GET", url, {"X-HTTP-Method-Override": "GET"}),
        ("x-method-override:PUT", url, {"X-HTTP-Method-Override": "PUT"}),
        ("x-original-url", url, {"X-Original-URL": path}),
        ("x-rewrite-url", url, {"X-Rewrite-URL": path}),
    ]
    # Sorgu aşınması: ?_method=GET (Laravel/Rails style-override geleneği)
    if "_method" not in (parts.query or ""):
        q = (parts.query + "&" if parts.query else "") + "_method=GET"
        out.append(("query:_method=GET",
                    urlunsplit((parts.scheme, parts.netloc, parts.path, q, parts.fragment)), {}))
    # Yol normalizasyonları: ACL prefix-eşleşme şaşırmaçları (// ve trailing-slash)
    if "//" not in path:
        dbl = "//" + path.lstrip("/")
        out.append(("path:double-slash",
                    urlunsplit((parts.scheme, parts.netloc, dbl, parts.query, parts.fragment)), {}))
    last = path.rsplit("/", 1)[-1]
    if not path.endswith("/") and "." not in last:
        out.append(("path:trailing-slash",
                    urlunsplit((parts.scheme, parts.netloc, path + "/", parts.query, parts.fragment)), {}))
    return out


def jwt_nonadmin(payload: Dict[str, Any]) -> Optional[bool]:
    """JWT iddiaları 'bu kimlik BARİZ non-admin' diyor mu? (SAF, OFFLINE — imza önemi yok,
    kullanıcı kendi token'ını veriyor). Üç değerli:
      True  → bariz non-admin (role=user/staff... veya is_admin=false) → KİP-2 confirmed kapısı
      False → bariz ADMIN (role=admin/superadmin, is_admin=true) → erişim NORMAL, vuln değil
      None  → rol sinyali yok → emin değiliz → tavan probable (FP'yi confirmed'a yazma)"""
    if not isinstance(payload, dict) or not payload:
        return None

    def _s(v: Any) -> str:
        return str(v).strip().lower()

    admin_words = {"admin", "administrator", "superadmin", "super", "root", "owner",
                   "superuser", "sysadmin", "support"}
    neg_words = {"user", "member", "customer", "client", "guest", "staff", "employee",
                 "readonly", "read-only", "viewer", "operator", "buyer"}
    # 1) Doğrudan boolean bayraklar (en güçlü sinyal)
    for k in ("is_admin", "isadmin", "admin", "superadmin", "is_superuser", "issuperuser"):
        if k in payload:
            v = payload[k]
            if v is True or _s(v) in ("1", "true", "yes"):
                return False
            if v is False or _s(v) in ("0", "false", "no"):
                return True
    # 2) Rol/kümе alanları
    for k in ("role", "roles", "rol", "user_role", "userrole", "group", "groups",
              "scope", "scopes", "realm_access", "resource_access"):
        if k not in payload:
            continue
        v = payload[k]
        vals: set
        if isinstance(v, dict) and isinstance(v.get("roles"), list):
            vals = {_s(x) for x in v["roles"]}                       # keycloak realm_access
        elif isinstance(v, (list, tuple, set)):
            vals = {_s(x) for x in v}
        else:
            vals = {_s(v)}
        flat: set = set()
        for item in vals:
            flat.update(item.replace(",", " ").split())
        if flat & admin_words:
            return False
        if flat & neg_words:
            return True
    return None


def adjudicate_method_tamper(baseline: Optional[Measured],
                             variants: List[Tuple[str, Optional[Measured]]]) -> Dict[str, Any]:
    """KİP 1 kararı (SAF). Kanonik GET A'ya reddedilmişken bir biçim-varyantı dolu veri
    döndürüyorsa erişim kontrolü yalnız kanonik biçimi denetler → bypass gözlemi.
    JSON/API gövde → confirmed (gerçek veri sızdı, kabuk değil). HTML/ambigu gövde →
    probable (SPA-kabuk FP kalkanı). RoLDEN bağımsız kanıt — 1 kimlikle çalışır."""
    none = {"is_fac": False, "tier": None, "reason": None}
    if not _is_denied(baseline):
        return {**none, "reason": "baseline_get_reddedilmedi_kip1_degil"}
    html_label: Optional[str] = None
    for label, m in variants:
        if not _is_substantive(m):
            continue
        if _looks_like_data(m):
            return {"is_fac": True, "tier": "confirmed", "variant": label,
                    "reason": (f"Kanonik GET reddedildi (status={getattr(baseline, 'status', '?')}), "
                               f"aynı istek '{label}' biçimiyle 2xx JSON/API verisi döndürdü. "
                               f"Denetim katmanı yalnız kanonik isteği denetliyor — BYPASS KANITLI.")}
        if html_label is None:
            html_label = label
    if html_label is not None:
        return {"is_fac": True, "tier": "probable", "variant": html_label,
                "reason": (f"'{html_label}' varyantı kanonik GET reddedilmişken 2xx gövde "
                           f"döndürdü; içerik JSON/API değil (SPA kabuğu olabilir) — manuel "
                           f"doğrulama ile teyit edilmeli.")}
    return {**none, "reason": "tum_varyantlar_reddedildi_erisim_kontrolu_calisiyor"}


def adjudicate_privileged_access(owner: Optional[Measured], anon: Optional[Measured],
                                 *, a_is_nonadmin: Optional[bool]) -> Dict[str, Any]:
    """KİP 2 kararı (SAF). Anon reddedilmişken (kaynak korunaklı) A token'ı dolu veri
    alıyorsa: A bariz non-admin → confirmed dikey yetki yükseltme; rol okunamadı →
    probable (A yönetici olabilir — FP'yi confirmed'a yazma doktrini); A bariz admin →
    NORMAL erişim, bulgu değil. Anon da alıyorsa uç zaten herkese açık → bu modülün
    konusu değil (path_probe/web_misconfig kapsamı)."""
    none = {"is_fac": False, "tier": None, "reason": None}
    if not _is_substantive(owner):
        return {**none, "reason": "a_baseline_anlamli_degil"}
    if anon is not None and _is_substantive(anon):
        return {**none, "reason": "anon_da_erisebiliyor(uc_korunakli_degil)"}
    if not _is_denied(anon):
        return {**none, "reason": "anon_durumu_belirsiz"}
    if a_is_nonadmin is False:
        return {**none, "reason": "a_kimligi_jwt_yonetici_gosteriyor(normal_erisim)"}
    if a_is_nonadmin is True:
        return {"is_fac": True, "tier": "confirmed",
                "reason": ("Ayricalikli uc korunakli (anonim erisim reddedildi) ve A token'i "
                           "JWT iddialarina gore BARIZ non-admin oldugu halde 2xx dolu veri "
                           "aldi → DIKEY yetki yukseltme KANITLANDI (islev-seviyesi erisim "
                           "kontrolu yok).")}
    return {"is_fac": True, "tier": "probable",
            "reason": ("Anonim erisim reddedilirken A token'i ayrica yetkili bir islev ucunden "
                       "2xx dolu veri aldi. A'nin rolu JWT'den dogrulanamadi — yonetici "
                       "degilse bu kritik acik; operatör A'nin rolunu teyit etmeli.")}


async def probe_fac_matrix(candidates: List[str], *, auth_a: Dict[str, str],
                           a_is_nonadmin: Optional[bool] = None,
                           max_targets: int = _MAX_TARGETS) -> List[Dict[str, Any]]:
    """Aday ayrıcalıklı URL'lerde FAC matris probu (I/O). auth_a zorunlu — kimlik olmadan
    dikey yetki diferansiyeli kurulamaz (anon vaka path_probe/web_misconfig kapsamı).
    Her hedef: anon → A → (A reddedildiyse) aşınma varyantları. TAHRİBATSIZ (yalnız GET),
    bütçeli, ASLA raise etmez. Döner bulgu listesi (idor_probe ile AYNI şema)."""
    import httpx
    findings: List[Dict[str, Any]] = []
    if not auth_a:
        return findings  # kimliksiz dikey yetki kanıtlanamaz → gürültü üretme

    targets = [u for u in dict.fromkeys(candidates)
               if isinstance(u, str) and u.startswith(("http://", "https://"))][:max_targets]
    if not targets:
        return findings

    limits = httpx.Limits(max_connections=6, max_keepalive_connections=6)
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                     timeout=_PER_REQUEST_TIMEOUT, limits=limits) as client:
            for url in targets:
                try:
                    anon = await _get(client, url, {})
                    owner = await _get(client, url, auth_a)
                    if _is_denied(owner):
                        # KİP 1: A'ya kapalı → biçim aşınması denenir (rol gerekmez)
                        vlist: List[Tuple[str, Optional[Measured]]] = []
                        for label, vurl, extra in tamper_variants(url)[:_MAX_VARIANTS]:
                            hdrs = dict(auth_a)
                            hdrs.update(extra)
                            vlist.append((label, await _get(client, vurl, hdrs)))
                        verdict = adjudicate_method_tamper(owner, vlist)
                        method = "fac-method-tamper"
                        kind = "method-tamper"
                    else:
                        # KİP 2: A içeriği aldı → anon-red diferansiyeli + rol sinyali
                        verdict = adjudicate_privileged_access(owner, anon,
                                                               a_is_nonadmin=a_is_nonadmin)
                        method = "fac-anon-denied-differential"
                        kind = "privileged-path"
                except Exception as e:
                    logger.debug(f"FAC matris prob hatası ({url}): {e}")
                    continue

                if not verdict.get("is_fac"):
                    continue
                tier = verdict["tier"]
                sev = "critical" if tier == "confirmed" else "medium"
                findings.append({
                    "url": url,
                    "kind": kind,
                    "variant": verdict.get("variant"),
                    "tier": tier,
                    "severity": sev,
                    "cwe": ["CWE-284", "CWE-863", "CWE-285"],
                    "mitre": "T1078",
                    "title": ("Broken Function-Level Access Control (Vertical Privesc)"
                              f" @ {url}"),
                    "proof": verdict["reason"],
                    "verification_method": method,
                    "verification_detail": verdict["reason"][:200],
                    "verification_confidence": 0.9 if tier == "confirmed" else 0.5,
                })
    except Exception as e:
        logger.debug(f"FAC matris probu genel hata: {e}")
    return findings
