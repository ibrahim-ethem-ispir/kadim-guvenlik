"""
Kadim Güvenlik — Dayanıklılık & Maruz-Kalma Probu (Availability + Exposure ekseni)
==================================================================================
Türkçe: Motor bugüne dek CIA üçlüsünün yalnız C (gizlilik) ve I (bütünlük) eksenini
tarıyordu — "sızma/CVE/enjeksiyon". Ama gerçek bir olayda (203.0.113.76)
hedef, tek bir açık bile sömürülmeden, saf bir **Layer-7 HTTP flood** ile ~11 saat çevrimdışı
kaldı: Cloudflare arkasındaki dinamik anasayfaya (`/`) ~3.000 req/s indi, PHP-FPM işçi havuzu
(max_children=100) doydu, sunucu isteklerin %99'una 502 döndü. Aynı pencerede SSH'a hedefli
bir parola-deneme (brute-force) yürütüldü ve sistemde **root'a parola ile giriş AÇIK**tı.

Bu modül tam o kör noktayı kapatır — hedefi YIKMADAN "dayanıklılık göstergeleri" toplar:

  A) L7 DoS dayanıklılığı: Anasayfa CDN tarafından cache'leniyor mu? Cache'lenmeyen dinamik
     kök = her istek origin'e iner = L7 flood'a birebir açık (bu olayın kök zafiyeti).
     Rate-limit var mı? (küçük, kontrollü bir mikro-patlama; ilk direnç işaretinde durur.)
  B) Origin ifşası (CDN-bypass): Hedef Cloudflare/Akamai/Fastly arkasında mı ve gerçek
     origin IP'sine CDN'i ATLAYARAK doğrudan erişilebiliyor mu? Erişilebiliyorsa saldırgan
     tüm CDN korumasını (WAF/rate-limit/Under-Attack) baypas eder — bu olayın 1 no'lu P0'ı.
  C) SSH maruz-kalması: SSH internete açık mı, banner sürümü ne, ve **parola kimlik
     doğrulaması açık mı**? Parola-auth + internete-açık SSH = brute-force'un birebir
     zeminidir (bu olayda tam buydu).

TAHRİBATSIZ İLKE: Gerçek DDoS ATILMAZ. Yük eğrisi opsiyoneldir, küçük ve sınırlıdır, ilk
degrade işaretinde durur. SSH'a HİÇBİR kimlik denenmez — yalnız "none" metoduyla sunucunun
duyurduğu izinli auth metotları okunur (standart, zararsız keşif). Kimlik/parola gönderilmez.

Tasarım (motor konvansiyonu): SAF analiz çekirdeği (analyze_*/classify_* — I/O yok, izole
test) + ince I/O katmanı (probe_*). Bulgular confidence_tier taşır → FP sistemine oturur.
Modül ASLA raise etmez; best-effort. Master anahtar per-tarama toggle (UI, VARSAYILAN KAPALI);
RESILIENCE_PROBE=0 ops kill-switch.
"""

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("resilience-probe")


# ============================================================
# SAF analiz çekirdeği (I/O yok — TDD)
# ============================================================

# CDN imza tablosu: header adı (lower) → (regex, cdn adı). CF-RAY/Server=cloudflare en güçlü
# sinyal; Akamai/Fastly/CloudFront de tanınır (origin-bypass mantığı hepsinde aynı).
_CDN_HEADER_SIGNATURES: List[Tuple[str, str, str]] = [
    ("server", r"cloudflare", "cloudflare"),
    ("cf-ray", r".+", "cloudflare"),
    ("cf-cache-status", r".+", "cloudflare"),
    ("server", r"akamai|akamaighost", "akamai"),
    ("x-akamai-transformed", r".+", "akamai"),
    ("x-served-by", r".+", "fastly"),
    ("x-fastly-request-id", r".+", "fastly"),
    ("server", r"fastly", "fastly"),
    ("x-amz-cf-id", r".+", "cloudfront"),
    ("via", r"cloudfront", "cloudfront"),
    ("server", r"sucuri", "sucuri"),
]


def detect_cdn(headers: Dict[str, str]) -> Optional[str]:
    """Yanıt header'larından hedefin önünde CDN var mı, hangisi (SAF). Yoksa None.
    Header adları büyük/küçük harf duyarsız karşılaştırılır (HTTP semantiği)."""
    if not headers:
        return None
    low = {str(k).lower(): str(v or "") for k, v in headers.items()}
    for hname, pattern, cdn in _CDN_HEADER_SIGNATURES:
        val = low.get(hname)
        if val is not None and re.search(pattern, val, re.I):
            return cdn
    return None


# CDN'in "bu içeriği cache'lemedim, origin'e ilettim" dediği CF-Cache-Status değerleri.
_UNCACHED_CF_STATUS = {"dynamic", "miss", "bypass", "expired", "none"}
# Origin'in "beni cache'leme" dediği Cache-Control token'ları.
_NO_STORE_RE = re.compile(r"(?i)\b(no-store|no-cache|private|max-age=0)\b")


def analyze_cache_posture(status: int, headers: Dict[str, str], *,
                          cdn: Optional[str], host: str = "") -> List[Dict[str, Any]]:
    """Anasayfa yanıtının cache duruşundan L7-flood maruz-kalmasını türet (SAF).

    Kural (bu olayın kök zafiyeti): Hedef bir CDN arkasındaysa AMA anasayfa cache'lenmiyorsa
    (CF-Cache-Status: DYNAMIC/MISS ya da Cache-Control: no-store/private), her istek origin'e
    iner → CDN, hacimsel L7 GET flood'una karşı hiçbir tampon sağlamaz. Bu, deterministik bir
    header gözlemidir (tahmin değil) → confirmed. Şiddet 'medium': kendi başına RCE değil ama
    erişilebilirlik (availability) doğrudan risk altında."""
    findings: List[Dict[str, Any]] = []
    tgt = host or "hedef"
    low = {str(k).lower(): str(v or "") for k, v in (headers or {}).items()}
    cf_status = low.get("cf-cache-status", "").strip().lower()
    cache_control = low.get("cache-control", "")
    age = low.get("age")

    # Yalnız CDN arkasında anlamlı (CDN yoksa "cache yok" beklenendir, bulgu değil).
    if not cdn:
        return findings

    cached = False
    if cf_status and cf_status in {"hit", "revalidated"}:
        cached = True
    if age and str(age).strip().isdigit() and int(str(age).strip()) > 0 and not cf_status:
        cached = True  # Age>0 + HIT-benzeri → kenar sunucudan servis edildi

    uncached_signal = (
        (cf_status in _UNCACHED_CF_STATUS)
        or bool(_NO_STORE_RE.search(cache_control))
        or (cdn == "cloudflare" and not cf_status and not cached)  # CF'de CF-Cache-Status yoksa çoğu kez proxy-only
    )

    if uncached_signal and not cached:
        reason_bits = []
        if cf_status:
            reason_bits.append(f"CF-Cache-Status: {cf_status.upper()}")
        if _NO_STORE_RE.search(cache_control):
            reason_bits.append(f"Cache-Control: {cache_control[:80]}")
        if not reason_bits:
            reason_bits.append("kenar yanıtında HIT/Age cache kanıtı yok")
        findings.append({
            "axis": "availability",
            "title": f"Anasayfa CDN tarafından cache'lenmiyor — L7 flood origin'e iner @ {tgt}",
            "severity": "medium", "confidence_tier": "confirmed",
            "proof": (
                f"Hedef {cdn} arkasında ama anasayfa (/) dinamik/cache'siz servis ediliyor "
                f"({'; '.join(reason_bits)}). Her istek CDN cache'ini ıskalayıp origin'e "
                f"iletilir → CDN, hacimsel L7 HTTP GET flood'una karşı tampon SAĞLAMAZ. "
                f"Origin dinamik uç (PHP/uygulama) ise az istekle işçi havuzu tükenir "
                f"(gözlenen olay: ~3.000 req/s → PHP-FPM doygunluğu → %99 HTTP 502)."
            ),
            "cwe": ["CWE-770"], "mitre": "T1499.002",
            "remediation": (
                "CDN'de anasayfa için kenar-cache/micro-cache (kısa Edge TTL 30–60sn) veya "
                "'Under Attack'/Managed Challenge + rate-limiting kuralı uygula; origin'i "
                "yalnız CDN IP aralıklarına aç (bypass'ı kes)."
            ),
        })
    return findings


def analyze_ratelimit(host: str, burst_statuses: List[int], *,
                      cdn: Optional[str]) -> List[Dict[str, Any]]:
    """Küçük kontrollü bir istek patlamasının durum kodlarından rate-limit varlığını türet (SAF).

    burst_statuses: art arda atılan (az sayıda) isteğin HTTP durum kodları. İçlerinden herhangi
    biri 429/503/challenge (403 CF-benzeri) döndüyse → bir hız-kısıtlama katmanı VAR (bulgu yok,
    iyi). Hiçbiri dönmediyse ve hepsi 2xx/3xx ise → gözlemlenen aralıkta hız-kısıtlama YOK
    (probable — kısa pencere kesin kanıt değil, ama bu olayın zemini tam buydu)."""
    findings: List[Dict[str, Any]] = []
    if not burst_statuses:
        return findings
    n = len(burst_statuses)
    limited = sum(1 for s in burst_statuses if s in (429, 503) or s == 509)
    challenged = sum(1 for s in burst_statuses if s in (403, 401))
    if limited or challenged:
        return findings  # direnç gözlendi → bulgu üretme
    ok = sum(1 for s in burst_statuses if 200 <= s < 400)
    if ok >= max(1, int(n * 0.9)):
        findings.append({
            "axis": "availability",
            "title": f"Hız-kısıtlama (rate-limit) gözlenmedi — L7 flood'a açık @ {host}",
            "severity": "low", "confidence_tier": "probable",
            "proof": (
                f"{n} art arda (kontrollü, tahribatsız) istekten {ok}'i 2xx/3xx döndü; "
                f"hiçbiri 429/503/challenge değil. Gözlemlenen kısa pencerede bir hız-kısıtlama "
                f"katmanı DEVREYE GİRMEDİ. Botnet ölçeğinde ({'CDN: ' + cdn if cdn else 'origin'}) "
                f"bu, dağıtık GET flood'unun serbestçe origin'e inebileceğini gösterir."
            ),
            "cwe": ["CWE-770"], "mitre": "T1499",
            "remediation": (
                "CDN katmanında per-IP rate-limiting (ör. >20 istek/10sn → blok) ve/veya "
                "origin nginx'te limit_req/limit_conn uygula."
            ),
        })
    return findings


def analyze_origin_exposure(host: str, cdn: Optional[str], origin_ip: Optional[str],
                            *, direct_status: Optional[int], direct_body_sig: Optional[str],
                            cdn_body_sig: Optional[str]) -> List[Dict[str, Any]]:
    """CDN arkasındaki hedefin gerçek origin IP'sine CDN ATLANARAK erişilip erişilemediğini
    türet (SAF).

    direct_*: origin_ip'ye doğrudan (Host: host başlığıyla) bağlanınca alınan yanıt.
    cdn_body_sig / direct_body_sig: gövde imzası (ör. title/uzunluk özeti) — ikisi EŞLEŞİYORSA
    doğrudan erişilen IP gerçekten AYNI uygulamayı servis ediyor demektir → CDN-bypass
    KANITLANDI (confirmed, high): saldırgan WAF/rate-limit/Under-Attack korumasını tümden
    atlar. Bu, gözlenen olayın 1 no'lu P0'ıdır."""
    findings: List[Dict[str, Any]] = []
    if not cdn or not origin_ip:
        return findings
    if direct_status is None:
        return findings
    # Doğrudan bağlantı yanıt verdi mi + aynı uygulama mı?
    reachable = 200 <= int(direct_status) < 500  # 5xx bile "origin ayakta ve bize cevap veriyor"
    same_app = bool(direct_body_sig and cdn_body_sig and direct_body_sig == cdn_body_sig)
    if reachable and same_app:
        findings.append({
            "axis": "exposure",
            "title": f"Origin IP ifşa — CDN ({cdn}) baypas edilebiliyor @ {host}",
            "severity": "high", "confidence_tier": "confirmed",
            "proof": (
                f"Gerçek origin IP ({origin_ip}) CDN atlanarak doğrudan bağlanıldı (HTTP "
                f"{direct_status}) ve AYNI uygulamayı servis etti (gövde imzası eşleşti). "
                f"Saldırgan {cdn}'ı tamamen baypas edip origin'i doğrudan vurabilir — WAF, "
                f"rate-limit, 'Under Attack' ve bot-koruma DEVRE DIŞI kalır. Gözlenen L7 "
                f"flood/SSH brute-force olayının kök kolaylaştırıcısı budur."
            ),
            "cwe": ["CWE-668"], "mitre": "T1590.005",
            "remediation": (
                f"Origin firewall'ında 80/443'ü YALNIZ {cdn} IP aralıklarına aç (diğer herkese "
                f"kapat); Authenticated Origin Pulls (mTLS) etkinleştir; gerekirse origin IP'yi "
                f"rotasyona sok. Origin IP artık ifşa (co-hosted vhost'lar/DNS geçmişi) — "
                f"yalnız IP değişimi yetmez, firewall şart."
            ),
        })
    elif reachable and direct_body_sig and cdn_body_sig and direct_body_sig != cdn_body_sig:
        # Doğrudan IP cevap veriyor ama farklı içerik (paylaşılan hosting/başka vhost) — zayıf sinyal
        findings.append({
            "axis": "exposure",
            "title": f"Origin IP doğrudan erişilebilir (farklı içerik) @ {host}",
            "severity": "low", "confidence_tier": "probable",
            "proof": (
                f"Origin IP ({origin_ip}) 80/443'te doğrudan cevap veriyor (HTTP {direct_status}) "
                f"ama gövde CDN yanıtından farklı — muhtemelen paylaşılan hosting/başka vhost. "
                f"Yine de origin yüzeyi internete açık; doğru Host başlığıyla bypass denenebilir."
            ),
            "cwe": ["CWE-668"], "mitre": "T1590.005",
            "remediation": "Origin 80/443'ü CDN IP aralıklarına kısıtla.",
        })
    return findings


# SSH auth metot sınıflandırması — parola tabanlı metotlar brute-force'un zeminidir.
_PASSWORD_AUTH_METHODS = {"password", "keyboard-interactive"}
_SSH_VERSION_RE = re.compile(r"SSH-2\.0-([^\r\n]+)")
_OPENSSH_VER_RE = re.compile(r"OpenSSH[_/]([0-9]+\.[0-9]+(?:p[0-9]+)?)")


def classify_ssh(banner: str, auth_methods: Optional[List[str]], *,
                 host: str = "", port: int = 22,
                 internet_exposed: bool = True) -> List[Dict[str, Any]]:
    """SSH banner + izin verilen auth metotlarından maruz-kalma/sertleşme bulguları türet (SAF).

    - banner → sürüm ifşası (info) + OpenSSH sürümü (cve_intel devralır).
    - auth_methods 'password'/'keyboard-interactive' İÇERİYORSA → parola kimlik doğrulaması
      AÇIK. Internete açık + parola-auth = brute-force'un birebir zemini (gözlenen olay).
      Metotlar sunucunun 'none' denemesine verdiği YANITTAN okunur (kimlik DENENMEZ) →
      deterministik gözlem → confirmed.
    - Yalnız publickey → sertleşmiş (bulgu üretilmez; pozitif duruş)."""
    findings: List[Dict[str, Any]] = []
    tgt = f"{host}:{port}" if host else f":{port}"
    banner = (banner or "").strip()

    version = None
    m = _SSH_VERSION_RE.search(banner)
    if m:
        version = m.group(1).strip()

    # Sürüm ifşası (aday — cve_intel için OpenSSH sürümü değerli)
    if banner:
        findings.append({
            "axis": "exposure",
            "title": f"SSH sürüm ifşası @ {tgt}",
            "severity": "info", "confidence_tier": "unconfirmed",
            "proof": f"SSH banner: {banner[:160]}"
                     + (f" (OpenSSH {_OPENSSH_VER_RE.search(banner).group(1)})"
                        if _OPENSSH_VER_RE.search(banner) else ""),
            "cwe": ["CWE-200"], "mitre": "T1592",
        })

    if auth_methods:
        methods_low = [str(a).strip().lower() for a in auth_methods]
        has_password = any(a in _PASSWORD_AUTH_METHODS for a in methods_low)
        if has_password:
            sev = "high" if internet_exposed else "medium"
            findings.append({
                "axis": "exposure",
                "title": f"SSH parola kimlik doğrulaması AÇIK — brute-force zemini @ {tgt}",
                "severity": sev, "confidence_tier": "confirmed",
                "proof": (
                    f"SSH sunucusu izin verilen kimlik metotları arasında parola tabanlı "
                    f"doğrulamayı duyuruyor (metotlar: {', '.join(methods_low)}). "
                    + ("Servis internete açık — " if internet_exposed else "")
                    + "parola-auth açık + internete-açık SSH, dağıtık brute-force'un birebir "
                    "zeminidir (gözlenen olayda 16.8K başarısız deneme + hedefli kullanıcı "
                    "adları). Kimlik DENENMEDİ — bu, sunucunun 'none' metoduna verdiği "
                    "yanıttan okunan izinli-metot listesidir."
                ),
                "cwe": ["CWE-307", "CWE-262"], "mitre": "T1110.001",
                "remediation": (
                    "sshd_config: PasswordAuthentication no + PermitRootLogin prohibit-password "
                    "(yalnız anahtar); MaxAuthTries 3; fail2ban bantime uzat + /24 subnet ban + "
                    "recidive; SSH'ı VPN/bastion arkasına al ya da 22'yi yalnız yönetici IP'lerine aç."
                ),
            })
        # Yalnız publickey → sertleşmiş; sessiz pozitif (bulgu üretme, gürültü yok).

    return findings


def summarize_posture(cdn: Optional[str], origin_exposed: bool, cdn_bypassable: bool,
                      homepage_cached: bool, ssh_password_auth: Optional[bool]) -> Dict[str, Any]:
    """Rapor/UI için tek-bakış duruş özeti (SAF). root.meta['edge_posture']'a yazılır."""
    return {
        "cdn": cdn,
        "origin_exposed": bool(origin_exposed),
        "cdn_bypassable": bool(cdn_bypassable),
        "homepage_cached": bool(homepage_cached),
        "ssh_password_auth": ssh_password_auth,  # True/False/None(bilinmiyor)
    }


# ============================================================
# I/O katmanı (ince — httpx / asyncio soket / ssh CLI)
# ============================================================

def _body_signature(status: int, body: str) -> str:
    """Gövdeden hafif, kararlı bir imza üret (title + kaba uzunluk kovası). CDN yanıtı ile
    doğrudan-origin yanıtının 'aynı uygulama' olup olmadığını header-bağımsız karşılaştırmak
    için — byte-byte eşitlik dinamik içerikte tutmaz, bu imza toleranslıdır."""
    body = body or ""
    title = ""
    mt = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    if mt:
        title = re.sub(r"\s+", " ", mt.group(1)).strip().lower()[:120]
    # uzunluk kovası (log2 tabanlı kaba kova → dinamik ufak farklar aynı kovada kalır)
    blen = len(body)
    bucket = 0 if blen == 0 else int(max(0, (blen.bit_length())))
    return f"{title}|{bucket}"


async def probe_l7_resilience(host: str, client, *, burst: int = 12,
                              timeout: float = 8.0) -> Dict[str, Any]:
    """Anasayfaya (/) TAHRİBATSIZ bir bakış: CDN tespiti + cache duruşu + küçük kontrollü
    rate-limit patlaması. burst küçük tutulur (varsayılan 12) ve YIKMA amacı yoktur — yalnız
    'bir direnç katmanı devreye giriyor mu' gözlemi. Döner: findings + posture verisi."""
    url = host if host.startswith(("http://", "https://")) else f"https://{host}"
    findings: List[Dict[str, Any]] = []
    cdn = None
    homepage_cached = False
    cdn_body_sig = None
    first_headers: Dict[str, str] = {}
    try:
        r = await client.get(url, timeout=timeout)
        first_headers = {k: v for k, v in r.headers.items()}
        cdn = detect_cdn(first_headers)
        body = r.text or ""
        cdn_body_sig = _body_signature(r.status_code, body)
        cf_status = first_headers.get("cf-cache-status", "") or first_headers.get("CF-Cache-Status", "")
        homepage_cached = str(cf_status).strip().lower() in {"hit", "revalidated"}
        findings += analyze_cache_posture(r.status_code, first_headers, cdn=cdn, host=host)
    except Exception as e:
        logger.debug(f"L7 resilience ilk GET hata ({host}): {e}")
        return {"findings": findings, "cdn": cdn, "homepage_cached": homepage_cached,
                "cdn_body_sig": cdn_body_sig, "headers": first_headers}

    # Kontrollü mikro-patlama — sıralı, küçük; ilk 429/503/challenge'da erken çık.
    statuses: List[int] = []
    try:
        for _ in range(max(1, burst)):
            rr = await client.get(url, timeout=timeout)
            statuses.append(rr.status_code)
            if rr.status_code in (429, 503, 509):
                break  # direnç gözlendi → daha fazla istek atma (tahribatsızlık)
    except Exception as e:
        logger.debug(f"L7 resilience patlama kısmi ({host}): {e}")
    findings += analyze_ratelimit(host, statuses, cdn=cdn)

    return {"findings": findings, "cdn": cdn, "homepage_cached": homepage_cached,
            "cdn_body_sig": cdn_body_sig, "headers": first_headers, "burst_statuses": statuses}


async def probe_origin_exposure(host: str, origin_ip: str, cdn: Optional[str], client,
                                *, cdn_body_sig: Optional[str], timeout: float = 8.0) -> Dict[str, Any]:
    """Gerçek origin IP'ye CDN'i ATLAYARAK doğrudan bağlan (Host: host başlığıyla) ve aynı
    uygulama mı diye bak. TAHRİBATSIZ: tek GET. origin_ip origin_discovery/passive-DNS'ten gelir.
    Döner findings + cdn_bypassable bool."""
    findings: List[Dict[str, Any]] = []
    bypassable = False
    if not origin_ip or not cdn:
        return {"findings": findings, "cdn_bypassable": bypassable}
    direct_status = None
    direct_sig = None
    for scheme in ("https", "http"):
        try:
            # IP'ye doğrudan istek; Host başlığı gerçek hostname (vhost eşleşsin). verify kapalı
            # (origin sertifikası IP'ye uymayabilir) — yalnız erişilebilirlik/uygulama-eşleşmesi bakılır.
            # KRİTİK: redirect TAKİP EDİLMEZ (follow_redirects=False). Origin, 301→https://host/
            # derse takip edersek tekrar CDN'e döner ve YANLIŞ "bypass onaylandı" üretiriz —
            # doğrudan IP'nin KENDİ verdiği yanıtı (aynı uygulama mı) görmemiz gerekir.
            r = await client.get(f"{scheme}://{origin_ip}/",
                                 headers={"Host": host},
                                 timeout=timeout,
                                 follow_redirects=False)
            direct_status = r.status_code
            direct_sig = _body_signature(r.status_code, r.text or "")
            break
        except Exception as e:
            logger.debug(f"Origin doğrudan {scheme} hata ({origin_ip}): {e}")
            continue
    findings += analyze_origin_exposure(
        host, cdn, origin_ip,
        direct_status=direct_status, direct_body_sig=direct_sig, cdn_body_sig=cdn_body_sig)
    bypassable = any(f.get("confidence_tier") == "confirmed" for f in findings)
    return {"findings": findings, "cdn_bypassable": bypassable, "direct_status": direct_status}


async def _ssh_banner(host: str, port: int, timeout: float = 6.0) -> str:
    """SSH banner'ını (SSH-2.0-...) ham soketle oku. TAHRİBATSIZ: yalnız sunucunun ilk satırı."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=timeout)
            return (data or b"").decode("utf-8", "replace").strip()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"SSH banner hata ({host}:{port}): {e}")
        return ""


_SSH_METHODS_RE = re.compile(r"(?i)Permission denied\s*\(([^)]+)\)")
_SSH_AUTH_LINE_RE = re.compile(r"(?i)Authentications that can continue:\s*([^\r\n]+)")


async def _ssh_auth_methods(host: str, port: int, timeout: float = 8.0) -> Optional[List[str]]:
    """Sunucunun izin verdiği auth metotlarını 'none' metoduyla oku (TAHRİBATSIZ — kimlik/parola
    DENENMEZ). `ssh` CLI ile: PreferredAuthentications=none → sunucu izinli metotları döndürür
    ('Permission denied (publickey,password).'). ssh binary yoksa/çökerse None (banner-only fallback)."""
    args = [
        "ssh",
        "-o", "PreferredAuthentications=none",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={int(timeout)}",
        "-p", str(port),
        f"kadimprobe@{host}",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        logger.debug("ssh binary yok — auth-method tespiti atlandı (banner-only)")
        return None
    except Exception as e:
        logger.debug(f"ssh subprocess başlatılamadı ({host}:{port}): {e}")
        return None
    try:
        _out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout + 4)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        return None
    text = (err or b"").decode("utf-8", "replace")
    m = _SSH_METHODS_RE.search(text) or _SSH_AUTH_LINE_RE.search(text)
    if not m:
        return None
    return [t.strip() for t in re.split(r"[,\s]+", m.group(1)) if t.strip()]


async def probe_ssh_exposure(host: str, port: int = 22, *,
                             internet_exposed: bool = True,
                             timeout: float = 8.0) -> Dict[str, Any]:
    """SSH maruz-kalma probu (TAHRİBATSIZ): banner + izinli auth metotları. Kimlik DENENMEZ.
    Döner findings + password_auth bool/None."""
    banner = await _ssh_banner(host, port, timeout=min(timeout, 6.0))
    methods = None
    if banner:  # port SSH konuşuyor → auth metotlarını dene (yalnız 'none')
        methods = await _ssh_auth_methods(host, port, timeout=timeout)
    findings = classify_ssh(banner, methods, host=host, port=port,
                            internet_exposed=internet_exposed)
    password_auth: Optional[bool] = None
    if methods is not None:
        password_auth = any(str(a).lower() in _PASSWORD_AUTH_METHODS for a in methods)
    return {"findings": findings, "banner": banner, "auth_methods": methods,
            "password_auth": password_auth}
