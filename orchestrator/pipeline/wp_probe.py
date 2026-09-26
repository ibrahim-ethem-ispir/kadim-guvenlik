"""
Kadim Güvenlik — WordPress-Farkında Keşif & İfşa Probu (IPB payoff)
==================================================================
Türkçe: Güncel CVE deseninin ezici çoğunluğu WordPress ekseninde (plugin SQLi, REST
IDOR/BOLA, /wp-json bilgi ifşası, user-enum). Klasik nuclei-tabanlı akış bir template
YAYIMLANANA kadar kördür; oysa WP'nin saldırı yüzeyi DETERMİNİSTİKTİR: parmak izi →
readme.txt ile kesin plugin sürümü → /wp-json route hasadı → REST/author user-enum →
xmlrpc yüzeyi. Bu modül tam bunu yapar (nuclei'yi BEKLEMEZ).

KRİTİK DOKTRIN — MODÜLER GATE: Bu prob YALNIZ hedef gerçekten WordPress ise çalışır.
Motorda çift kapı vardır:
  (1) playbook.wp_probe (if_relevant) — profil `framework=wordpress` demezse dispatcher
      bu modülü hiç çağırmaz (bilinçli saldırı: WP olmayanda WP portu/yolu yoklanmaz).
  (2) probe_wordpress içinde CANLI RE-CONFIRM — profil eski/yanlışsa bile, kök sayfada
      WP imzası yoksa TEK bulgu üretilmez (defense-in-depth; false-positive'e karşı).

KANIT = deterministik yanıtın KENDİSİ: /wp-json/wp/v2/users → JSON kullanıcı listesi;
?author=1 → /author/<kullanıcı>/ yönlendirmesi; plugin readme.txt "Stable tag" satırı.
Template tahmini yok → confirmed. TAHRİBATSIZ: yalnız GET; xmlrpc system.multicall /
pingback ÇALIŞTIRILMAZ (yalnız arayüzün açık olduğu gözlemlenir). Best-effort: ASLA raise
etmez; sağlayıcı/ağ hatası taramayı düşürmez.

Tasarım (path_probe/k8s_probe deseni): classify_*/parse_* çekirdeği SAF (stdlib + regex) →
izole test; probe_wordpress ince I/O. Bulunan /wp-json/<res>/<id> route'ları IDOR ADAYI
olarak döner → pipeline bunları root.meta['endpoints']'e seed eder, mevcut _probe_idor
diferansiyeli (iki-hesap = confirmed) otomatik devralır (tekerleği yeniden icat etme).
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from .target_profile import parse_set_cookie_names

logger = logging.getLogger("wp-probe")

# ============================================================
# SAF çekirdek — parmak izi & sınıflandırma (I/O yok, izole test)
# ============================================================

# WordPress imza belirteçleri (kök HTML). Herhangi biri = WP (güçlü sinyal).
_WP_BODY_MARKERS = re.compile(
    r"/wp-content/|/wp-includes/|/wp-json|"
    r"""name=["']generator["']\s+content=["']WordPress""",
    re.I,
)
# Çekirdek sürüm: <meta name="generator" content="WordPress 6.4.2">
_WP_GENERATOR = re.compile(
    r"""name=["']generator["']\s+content=["']WordPress\s+([0-9][0-9A-Za-z.\-]*)""", re.I)
# wp-includes asset'lerinde çekirdek sürüm sızar: wp-emoji-release.min.js?ver=6.4.2
_WP_INCLUDES_VER = re.compile(r"/wp-includes/[^\"'\s?]+\?ver=([0-9][0-9.]{1,12})", re.I)
# /wp-content/(plugins|themes)/<slug>/...(?ver=X)
_WP_ASSET = re.compile(
    r"/wp-content/(plugins|themes)/([a-zA-Z0-9][a-zA-Z0-9._\-]{0,60})/"
    r"[^\"'\s?>]*(?:\?[^\"'\s>]*?\bver=([0-9][0-9A-Za-z.\-]{0,20}))?",
    re.I,
)
# readme.txt "Stable tag: 1.2.3" (WordPress.org plugin standardı → KESİN kurulu sürüm)
_STABLE_TAG = re.compile(r"^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", re.I | re.M)
# WP route şablonundaki sayısal id capture: (?P<id>[\d]+) / (?P<id>\d+)
_ROUTE_NUM_ID = re.compile(r"\(\?P<[a-zA-Z_]+>\\?\[?\\?d\]?\+?\)")
# Route'ta HALA çözülmemiş (sayısal-olmayan) named-group kaldı mı? → o route atlanır.
_ROUTE_ANY_GROUP = re.compile(r"\(\?P<")


def extract_core_version(body: str) -> Optional[str]:
    """Kök HTML'den WP çekirdek sürümünü çıkar (SAF). Önce generator meta (en güvenilir),
    yoksa wp-includes asset ?ver= sızıntısı. Bulunamazsa None."""
    if not body:
        return None
    m = _WP_GENERATOR.search(body)
    if m:
        return m.group(1)
    m = _WP_INCLUDES_VER.search(body)
    return m.group(1) if m else None


def is_wordpress(body: str = "", cookie_names: Optional[List[str]] = None,
                 headers: Optional[Dict[str, str]] = None) -> Tuple[bool, List[str]]:
    """Hedef CANLI olarak WordPress mi? (SAF). Çift-kapının ikinci kapısı: profil yanılsa
    bile burada imza yoksa prob susar. Döner (wp_mu?, kanıt-listesi)."""
    ev: List[str] = []
    if body and _WP_BODY_MARKERS.search(body[:200000]):
        ev.append("body:wp-content/wp-includes/wp-json/generator")
    for c in (cookie_names or []):
        cl = str(c).lower()
        if cl.startswith("wordpress_") or cl.startswith("wp-settings") or cl == "wp-settings-time":
            ev.append(f"cookie:{cl}")
            break
    if headers:
        link = str(headers.get("Link") or headers.get("link") or "").lower()
        if "wp-json" in link or 'rel="https://api.w.org/"' in link:
            ev.append("header:link-wp-json")
    return (len(ev) > 0, ev)


def parse_assets(html: str) -> Dict[str, Dict[str, Optional[str]]]:
    """Kök HTML'den plugin/tema envanterini çıkar (SAF). slug→sürüm (?ver='den; yoksa None).
    Wappalyzer-tarzı pasif keşif: hiç ek istek yok, sayfada zaten görünen asset'lerden."""
    out: Dict[str, Dict[str, Optional[str]]] = {"plugins": {}, "themes": {}}
    if not html:
        return out
    for kind, slug, ver in _WP_ASSET.findall(html[:200000]):
        bucket = out["plugins"] if kind.lower() == "plugins" else out["themes"]
        slug = slug.strip()
        if not slug or slug.lower() in ("index", ""):
            continue
        # Aynı slug birden çok kez görülür; ilk gördüğümüz sürümü koru, sonra ?ver= gelirse doldur.
        prev = bucket.get(slug, "___missing___")
        if prev == "___missing___":
            bucket[slug] = ver or None
        elif prev is None and ver:
            bucket[slug] = ver
    return out


def parse_readme_stable_tag(text: str) -> Optional[str]:
    """Plugin readme.txt'ten "Stable tag" = KESİN kurulu sürüm (SAF). WordPress.org standardı;
    ?ver= (asset cache-buster) yanıltabilirken bu deterministiktir. 'trunk' → None (dev)."""
    if not text:
        return None
    m = _STABLE_TAG.search(text[:8192])
    if not m:
        return None
    v = m.group(1).strip()
    return None if v.lower() == "trunk" else v


def parse_wp_json(body: str) -> Dict[str, List[str]]:
    """/wp-json/ kök yanıtını ayrıştır (SAF). Döner {"namespaces":[...], "routes":[...]}.
    routes = route şablon anahtarları (IDOR aday üretimi bunları kullanır). Bozuk JSON → boş."""
    try:
        data = json.loads(body or "")
    except Exception:
        return {"namespaces": [], "routes": []}
    if not isinstance(data, dict):
        return {"namespaces": [], "routes": []}
    ns = data.get("namespaces")
    routes = data.get("routes")
    ns_list = [str(x) for x in ns] if isinstance(ns, list) else []
    route_list = list(routes.keys()) if isinstance(routes, dict) else []
    return {"namespaces": ns_list, "routes": route_list}


def _route_to_probe_url(base: str, route: str) -> Optional[str]:
    """WP route şablonunu (`/wp/v2/posts/(?P<id>[\\d]+)`) somut IDOR aday URL'sine çevir (SAF).
    Sayısal id grubunu 1 ile değiştirir; ÇÖZÜLEMEYEN başka named-group kalırsa (slug vb.) None
    (bozuk URL üretme). Kaynak adı (users/posts...) prev-segment olarak korunur → _probe_idor'un
    ad-ipucu süzgecinden geçer."""
    if not route or "(?P<" not in route:
        return None  # değişkensiz route IDOR adayı değil
    path = _ROUTE_NUM_ID.sub("1", route)
    # (?P<id>[\d]+) çeşitlemeleri kaba regex'i kaçırabilir → yaygın kalıbı da düşür:
    path = re.sub(r"\(\?P<[a-zA-Z_]+>\[?\\d\]?\+?\)", "1", path)
    if _ROUTE_ANY_GROUP.search(path):
        return None  # hâlâ regex grubu var (ör. (?P<slug>[\w-]+)) → atla
    path = path.rstrip("$").replace("\\", "")
    return f"{base.rstrip('/')}/wp-json{path}"


def idor_candidates_from_routes(base: str, routes: List[str],
                                namespaces: Optional[List[str]] = None) -> List[str]:
    """Route şablonlarından IDOR/BOLA aday URL'leri üret (SAF). Sayısal-id taşıyan route'lar +
    wp/v2 çekirdek koleksiyonları (users/posts/comments/media). Dedup, sıra korunur.
    Bunlar _probe_idor'a seed edilir (nesne-ref süzgeci + iki-hesap diferansiyeli onda)."""
    out: List[str] = []
    for r in routes or []:
        u = _route_to_probe_url(base, r)
        if u:
            out.append(u)
    # wp/v2 çekirdek koleksiyonları her zaman yüksek-değerli IDOR/enum adayı (route listesi
    # bunları /(?P<id>) formunda zaten içerir ama namespace varsa garanti seed edelim).
    if namespaces and any(n in ("wp/v2",) for n in namespaces):
        for res in ("users", "posts", "comments", "media"):
            out.append(f"{base.rstrip('/')}/wp-json/wp/v2/{res}/1")
    return list(dict.fromkeys(out))


def classify_rest_users(status: int, ctype: str, body: str) -> Optional[Dict[str, Any]]:
    """/wp-json/wp/v2/users auth'suz kullanıcı listesi döndü mü? (SAF). 200 + JSON dizi +
    slug/name alanları → confirmed user-enum (CWE-200). Yönetici kullanıcı adları sızar →
    brute-force/oltalama girdisi. 401/403 → ifşa yok (None)."""
    if status != 200:
        return None
    if "json" not in (ctype or "").lower() and not (body or "").lstrip().startswith("["):
        return None
    try:
        data = json.loads(body or "")
    except Exception:
        return None
    if not isinstance(data, list) or not data:
        return None
    users: List[str] = []
    for item in data[:50]:
        if isinstance(item, dict) and ("slug" in item or "name" in item):
            users.append(str(item.get("slug") or item.get("name")))
    if not users:
        return None
    return {"exposed": True, "count": len(users), "sample": users[:8]}


def classify_author_redirect(status: int, location: str, body: str) -> Optional[str]:
    """?author=1 author-scan → kullanıcı adı sızıntısı (SAF). 30x Location: /author/<ad>/ ya da
    gövdede body class 'author-<ad>'. Döner kullanıcı adı ya da None."""
    loc = location or ""
    m = re.search(r"/author/([^/?#]+)/?", loc)
    if m and status in (301, 302, 307, 308):
        return m.group(1)
    # body class="... author-<ad> author-<id> ..." → <ad> (kullanıcı adı), <id> (sayısal) değil.
    # WP her ikisini de basar; ilk SAYISAL-OLMAYAN token kullanıcı adıdır.
    for tok in re.findall(r"\bauthor-([a-zA-Z0-9._\-]+)", body or ""):
        if not tok.isdigit():
            return tok
    return None


def classify_xmlrpc(status: int, body: str) -> Optional[Dict[str, Any]]:
    """/xmlrpc.php arayüzü açık mı? (SAF). GET'e karşı WP imza yanıtı 'XML-RPC server accepts
    POST requests only'. Yalnız AÇIKLIK gözlenir — pingback/system.multicall ÇALIŞTIRILMAZ
    (tahribatsız). Açıksa: SSRF-pingback + brute-force amplifikasyon yüzeyi."""
    b = (body or "").lower()
    if "xml-rpc server accepts post requests only" in b:
        return {"enabled": True}
    # Bazı sürümler GET'e faultCode'lu XML döndürür ama yine de canlıdır.
    if "<methodresponse>" in b and "xmlrpc" in b:
        return {"enabled": True}
    return None


def validate_debug_log(status: int, ctype: str, body: str) -> bool:
    """/wp-content/debug.log ifşası doğrulayıcı (SAF). PHP hata günlüğü imzaları — sunucu
    yolları, sorgu, bazen sır sızar (CWE-532). soft-404/HTML sayfayı ele."""
    if status != 200:
        return False
    ct = (ctype or "").lower()
    if "html" in ct:
        return False
    b = body or ""
    hits = 0
    for needle in ("PHP Notice", "PHP Warning", "PHP Fatal error", "PHP Deprecated",
                   "Stack trace:", "[error]", " on line ", "PHP Parse error"):
        if needle in b:
            hits += 1
    return hits >= 1


# ============================================================
# I/O — TAHRİBATSIZ (yalnız GET), best-effort
# ============================================================

def _finding(title: str, severity: str, target: str, proof: str, *,
             tier: str = "confirmed", cwe: Optional[List[str]] = None,
             mitre: str = "T1592", method: str = "wp-probe") -> Dict[str, Any]:
    return {"title": title, "severity": severity, "target": target, "proof": proof,
            "confidence_tier": tier, "cwe": cwe or ["CWE-200"], "mitre": mitre,
            "verification_method": method,
            "verification_confidence": 0.9 if tier == "confirmed" else None}


async def _get(client, url: str, *, allow_redirects: bool = False) -> Optional[Tuple[int, str, str, str]]:
    """Tek GET → (status, content-type, location, body[:32KB]). Hata → None."""
    try:
        r = await client.get(url, timeout=10.0, follow_redirects=allow_redirects)
        loc = r.headers.get("location", "") if hasattr(r, "headers") else ""
        ctype = r.headers.get("content-type", "") if hasattr(r, "headers") else ""
        return (r.status_code, ctype, loc, (r.text or "")[:32768])
    except Exception:
        return None


async def _fetch_root(client, url: str) -> Optional[Tuple[str, Dict[str, str], List[str]]]:
    """Kök sayfayı BİR KEZ zengin çek → (body[:200KB], headers, cookie_names). Header ve
    Set-Cookie confirmation'ın Link-header/çerez kanalları için ŞART (body marker'ı maskeleyen
    hardened WP'yi kaçırmamak). Hata → None."""
    try:
        r = await client.get(url, timeout=10.0, follow_redirects=True)
    except Exception:
        return None
    headers = {k: v for k, v in r.headers.items()} if hasattr(r, "headers") else {}
    try:
        sc = r.headers.get_list("set-cookie")           # httpx multidict
    except Exception:
        scv = r.headers.get("set-cookie") if hasattr(r, "headers") else None
        sc = [scv] if scv else []
    cookies = parse_set_cookie_names(sc)
    return ((r.text or "")[:200000], headers, cookies)


async def _resolve_base(client, host: str) -> Optional[Tuple[str, str, Dict[str, str], List[str]]]:
    """host için çalışan kök URL'yi (https→http) TEK istekle bul. Döner
    (base, body, headers, cookie_names) — çift kök-fetch yok (WAF'ta istek tasarrufu)."""
    if host.startswith(("http://", "https://")):
        got = await _fetch_root(client, host.rstrip("/") + "/")
        return (host.rstrip("/"), *got) if got else None
    for scheme in ("https", "http"):
        got = await _fetch_root(client, f"{scheme}://{host}/")
        if got is not None:
            return (f"{scheme}://{host}", *got)
    return None


async def probe_wordpress(host: str, client, *,
                          max_plugins: int = 12) -> Dict[str, Any]:
    """WordPress saldırı yüzeyini TAHRİBATSIZ yokla → {findings, idor_candidates, inventory,
    core_version, confirmed_wp}. ASLA raise etmez. Çift-kapının ikinci kapısı burada: kök
    sayfada canlı WP imzası yoksa BOŞ döner (profil yanılsa bile FP üretmez)."""
    result: Dict[str, Any] = {"confirmed_wp": False, "core_version": None,
                              "inventory": {"plugins": {}, "themes": {}},
                              "findings": [], "idor_candidates": []}
    findings: List[Dict[str, Any]] = result["findings"]

    resolved = await _resolve_base(client, host)
    if not resolved:
        return result
    base, root_body, root_headers, root_cookies = resolved

    # (2) CANLI RE-CONFIRM — üç kanal: gövde marker'ı + Set-Cookie (wordpress_/wp-settings) +
    # Link header (rel=api.w.org). Hardened WP wp-content'i maskeleyebilir ama REST/cookie
    # kanalı genelde sağlar. Hiçbiri yoksa hiç bulgu üretme (çift-kapının ikinci kapısı).
    wp_ok, wp_ev = is_wordpress(body=root_body, cookie_names=root_cookies, headers=root_headers)
    if not wp_ok:
        return result
    result["confirmed_wp"] = True

    # --- Çekirdek sürüm ifşası (intel → cve/nuclei ilişkilendirmesi) ---
    core_ver = extract_core_version(root_body)
    result["core_version"] = core_ver
    if core_ver:
        findings.append(_finding(
            f"WordPress Çekirdek Sürümü İfşa ({core_ver}) @ {base}", "low", base,
            f"Kök sayfa WordPress {core_ver} sürümünü ifşa ediyor (generator meta / wp-includes "
            f"?ver=). Sürüm→CVE ilişkilendirmesi için istihbarat; nuclei 'wordpress' "
            f"template'leri bu sürüme odaklanır.",
            cwe=["CWE-200"], mitre="T1592.002", method="wp-generator"))

    # --- Plugin/tema envanteri (pasif) + readme.txt ile KESİN sürüm ---
    inv = parse_assets(root_body)
    result["inventory"] = inv
    plugin_slugs = list(inv["plugins"].keys())[:max_plugins]
    for i, slug in enumerate(plugin_slugs):
        if i:
            await asyncio.sleep(0.15)  # pacing: WAF'lı WP'de readme salvosu 403 seli tetiklemesin
        rr = await _get(client, f"{base}/wp-content/plugins/{slug}/readme.txt")
        if rr:
            tag = parse_readme_stable_tag(rr[3])
            if tag:
                inv["plugins"][slug] = tag  # ?ver= tahminini KESİN sürümle değiştir
    detected = [f"{s}@{v or '?'}" for s, v in inv["plugins"].items()]
    detected_themes = [f"{s}@{v or '?'}" for s, v in inv["themes"].items()]
    if detected or detected_themes:
        findings.append(_finding(
            f"WordPress Eklenti/Tema Envanteri ({len(detected)} eklenti) @ {base}",
            "info", base,
            "Pasif keşif + readme.txt ile saptanan bileşenler — "
            + (f"eklenti: {', '.join(detected[:20])}. " if detected else "")
            + (f"tema: {', '.join(detected_themes[:8])}. " if detected_themes else "")
            + "Kesin sürüm (readme 'Stable tag') → bilinen-CVE eşlemesi ve plugin-bazlı "
              "nuclei tag hedeflemesi için saldırı yüzeyi haritası.",
            tier="confirmed", cwe=["CWE-200"], mitre="T1592.002", method="wp-inventory"))

    # --- REST API route hasadı + IDOR adayları + user-enum ---
    rj = await _get(client, f"{base}/wp-json/")
    namespaces: List[str] = []
    if rj and rj[0] == 200:
        parsed = parse_wp_json(rj[3])
        namespaces = parsed["namespaces"]
        result["idor_candidates"] = idor_candidates_from_routes(
            base, parsed["routes"], namespaces)

    # REST kullanıcı enümerasyonu (auth'suz /wp-json/wp/v2/users)
    ru = await _get(client, f"{base}/wp-json/wp/v2/users")
    rest_users = None
    if ru:
        rest_users = classify_rest_users(ru[0], ru[1], ru[3])
    if rest_users and rest_users.get("exposed"):
        findings.append(_finding(
            f"WordPress REST API Kullanıcı Enümerasyonu @ {base}",
            "medium", f"{base}/wp-json/wp/v2/users",
            f"Auth'suz GET /wp-json/wp/v2/users → {rest_users['count']} kullanıcı döndü "
            f"(örn: {', '.join(rest_users['sample'])}). Yönetici/yazar kullanıcı ADLARI sızar → "
            f"hedefli brute-force ve oltalama girdisi. Anon JSON yanıtı = deterministik kanıt.",
            tier="confirmed", cwe=["CWE-200"], mitre="T1589.001", method="wp-rest-users"))

    # --- Author-scan user-enum (?author=1) — REST kapalıysa ikinci yol ---
    if not (rest_users and rest_users.get("exposed")):
        ra = await _get(client, f"{base}/?author=1", allow_redirects=False)
        if ra:
            uname = classify_author_redirect(ra[0], ra[2], ra[3])
            if uname:
                findings.append(_finding(
                    f"WordPress Author-Scan Kullanıcı Adı İfşası ({uname}) @ {base}",
                    "low", base,
                    f"GET /?author=1 → /author/{uname}/ yönlendirmesi kullanıcı adını sızdırıyor "
                    f"(id→kullanıcı eşlemesi). Yönetici hesap adı brute-force/oltalama girdisi.",
                    tier="confirmed", cwe=["CWE-200"], mitre="T1589.001", method="wp-author-scan"))

    # --- XML-RPC yüzeyi (tahribatsız — yalnız açıklık) ---
    rx = await _get(client, f"{base}/xmlrpc.php")
    if rx:
        xr = classify_xmlrpc(rx[0], rx[3])
        if xr and xr.get("enabled"):
            findings.append(_finding(
                f"WordPress XML-RPC Arayüzü Açık @ {base}",
                "low", f"{base}/xmlrpc.php",
                "GET /xmlrpc.php → 'accepts POST requests only' WP imzası: XML-RPC açık. "
                "pingback.ping ile SSRF/port-tarama ve system.multicall ile brute-force "
                "amplifikasyonu YÜZEYİ mevcut (ÇALIŞTIRILMADI — yalnız açıklık gözlendi). "
                "Sertleştirme: xmlrpc.php erişimini kapat.",
                tier="confirmed", cwe=["CWE-200"], mitre="T1190", method="wp-xmlrpc"))

    # --- debug.log ifşası (yüksek — yol/sır sızıntısı) ---
    rd = await _get(client, f"{base}/wp-content/debug.log")
    if rd and validate_debug_log(rd[0], rd[1], rd[3]):
        findings.append(_finding(
            f"WordPress debug.log İfşası @ {base}",
            "high", f"{base}/wp-content/debug.log",
            "GET /wp-content/debug.log → PHP hata günlüğü erişilebilir (imza: PHP "
            "Notice/Warning/Fatal/Stack trace). Sunucu mutlak yolları, sorgu ve zaman zaman "
            "sırlar sızar (WP_DEBUG_LOG production'da açık bırakılmış). Deterministik içerik = kanıt.",
            tier="confirmed", cwe=["CWE-532"], mitre="T1552.001", method="wp-debug-log"))

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
