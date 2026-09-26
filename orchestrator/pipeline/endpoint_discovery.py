"""
Kadim Güvenlik — Endpoint Keşfi / Crawler (Kuşatma Doktrini — Faz 1)
==================================================================
Türkçe: Saldırı-yüzeyi keşfinin tek en büyük tavanını kapatır. Mevcut tarama yığını
hedefe yalnız KÖK adresini (örn `https://x.com/`) veriyor — nuclei/fuzz'u o kökte çağırıyor.
Oysa SQLi/XSS/SSRF/IDOR/iş-mantığı zafiyetlerinin ezici çoğunluğu PARAMETRELİ derin
endpoint'lerde yaşar: `/api/v2/accounts/{id}/transfer?amount=`, `/search?q=`, `/report?file=`.

Bu modül hedefi bir örümcek (crawler) gibi tarayıp:
  1) Pasif kaynaklar: robots.txt, sitemap.xml (sitenin kendi beyanı)
  2) Aktif crawl: kökten BFS, aynı-host link'leri toplanır, HTML form/script/iframe çözümlenir
  3) JS varlık analizi: satır-içi/harici JS'ten endpoint + parametre ayrıştırılır
  4) Parametreli endpoint'lerin çıkarımı → bunlar DAST/aktif enjeksiyon HEDEFLERİ olur

Tasarım (path_probe.py deseniyle uyumlu):
- Orchestrator-YERLİ: yeni servis/ konteyner gerektirmez; httpx ile doğrudan hedefe GET.
- Gürültüsüz: yalnız GET, düşük eşzamanlılık, kısa timeout — aynı sınırlarla pathprobe'a paralel.
- Sınır: URL sayısı/bütçe kapağı (sonsuz crawl değil — bankada prod'a dokunma riskine karşı).
- Aynı-host kısıdı: dış host'a çıkma — hedef yetki alanı (scope) dışına taşma riskini sıfırlar.
- Soft-404 ihmal: olmayan yol 200 dönebilir; burada SADECE URL'i topluyoruz, bulgu çıkarmıyoruz.
  Doğrulama nuclei/DAST için bırakılır. Bu yüzden crawl, pathprobe gibi içerik-validator'ı
  kullanmaz — tek görevi endpoint kandidatlarını getirmektir.

ÇIKTI ŞEMASI (attack_graph.integrate `crawl` dalı bunu tüketir):
    {
      "target": host, "base_url": ...,
      "seed_urls":     [...]  # robots/sitemap'ten gelen "site beyanı"
      "discovered_urls": [...]  # crawl+JS+form' lardan çıkan tüm same-host URL'leri
      "parameterized_endpoints": [{"url":..., "params":[...]}]  # enjeksiyon hedefleri
      "forms": [{"action":..., "method":..., "inputs":[...]}]
      "js_assets": ["https://x.com/app.js", ...]
      "elapsed_seconds", "partial", "note"
    }
"""

import asyncio
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode

import httpx

logger = logging.getLogger("endpoint-discovery")

# ============================================================
# Bütçe / sınır — banka prod'una frenzy tarama yapmamak için
# ============================================================
# Türkçe: Crawler sonsuz bir ماشine döngüsü olmasın. Aynı host'ta bile 10bin sayfa
# gereksiz: nuclei'ye 10bin URL yığmak timeout'a düşürür. 500 URL pratikte bir web
# uygulamasının gerçek saldırı yüzeyini kapsar (portal/dashboard + API sürümleri).
MAX_URLS = int(os.getenv("CRAWL_MAX_URLS", "500"))
MAX_DEPTH = int(os.getenv("CRAWL_MAX_DEPTH", "2"))
PER_REQUEST_TIMEOUT = float(os.getenv("CRAWL_TIMEOUT", "8"))
CONCURRENCY = int(os.getenv("CRAWL_CONCURRENCY", "8"))
OVERALL_BUDGET = float(os.getenv("CRAWL_OVERALL_TIMEOUT", "60"))
# MODERN YÜZEY (L1): "enjeksiyon/authz hedefi" yalnız klasik `?param=` değildir. Modern
# kurumsal hedeflerin yüzeyi path-param REST (`/users/123` — IDOR/BOLA), API rotaları
# (`/api/...`, `/graphql` — JSON/GraphQL gövde enjeksiyonu) ve versiyonlu API'lerdir.
# Bunlar `?` taşımadığı için eski çıkarımda "değersiz statik" sayılıp motor tarafından
# HİÇ aktif test edilmiyordu ("standart açık yoksa işe yaramıyor" şikayetinin kökü).
# Bayrak kapatılırsa (=0) tam eski davranış: yalnız query-string endpoint'ler. Degrade-safe.
MODERN_SURFACE = os.getenv("MODERN_SURFACE", "1") == "1"
# Tek yanıt gövdesi sınırı — sayfa HTML/JS'i bu kadarını parse ederiz (dev SPA bundle
# şişirmesin diye).
_READ_CAP = 512 * 1024  # 512KB

# Türkçe: Ortam değişkenleriyle tüm altura'da makul değerler. Kullanıcı istediği takdirde
# bütçeyi artırabilir (CRAWL_MAX_URLS). Sıfır/çok düşük güvenli: ekonomi modu.
MAX_URLS = max(50, min(MAX_URLS, 5000))
MAX_DEPTH = max(1, min(MAX_DEPTH, 5))
CONCURRENCY = max(2, min(CONCURRENCY, 32))
PER_REQUEST_TIMEOUT = max(2.0, min(PER_REQUEST_TIMEOUT, 30.0))
OVERALL_BUDGET = max(15.0, min(OVERALL_BUDGET, 600.0))

# Statik kaynak dosya uzantıları — sayfanın bir parçası ama nuclei endeksinde taramaya
# değmez; çalışma hacmini tırmalamak için URL kümesinden düşürülür.
_STATIC_EXT: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".mov", ".avi", ".mkv", ".webm",
    ".pdf", ".zip", ".rar", ".tar", ".gz", ".7z", ".bz2",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

# Türkçe: HTML'de URL/endpoint çıkarmak için desenler. Href/action/src ayıklarken
# regex yerine link etiketlerini basitleştiriyoruz: HTML tam olarak parse edilemeyebilir
# (bozuk/budaklı), bu yüzden çeşitli formülleri deneriz. Builder: derin crawl yapıp
# ayrıştırıcıya bağımlı kalmamak için.
_HREF_RE = re.compile(r"""(?:href|action|src|data-url|formaction)\s*=\s*["']([^"']+)["']""", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_FORM_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']+)["']""", re.I)
_FORM_METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']+)["']""", re.I)
_INPUT_NAME_RE = re.compile(r"""<input\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.I)
_SITEMAP_URL_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# JS içindeki API/rotalar — `/api/...`, `fetch('...')`, `axios.post('...')`, `'route'` vb.
# Türkçe: SPA uygulamalarında gerçek yüzey budur. Vue/React/Angular client-side
# rotalarını yakalamaya çalışırız; kör regex'tir (parser değil) ama endpoint kandidatları
# için yeterli — nuclei/DAST bunları doğrulayacak.
_JS_ENDPOINT_RE = re.compile(
    r"""(?:["'])((?:/(?:api|v[0-9]+|rest|graphql|gql|admin|user|account|auth|login|search|upload|download|export|report|settings|profile|dashboard)[^\s"'<>{}|\\^`]*))(?:["'])""",
    re.I,
)
_JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.[a-z]+|\$\.ajax|\$\.get|\$\.post)\s*\(\s*["']([^"')]+)["']""",
    re.I,
)

_UA = "Mozilla/5.0 (compatible; KadimGuvenlik/1.0; +security-audit)"


def _canon_host(host: str) -> str:
    """WWW farkını normalize et → 'www.x.com' ile 'x.com' aynı host sayılır (aynı yetki
    alanında crawl out etmeme garantisi)."""
    h = (host or "").strip().lower()
    if h.startswith("www."):
        h = h[4:]
    return h


def _is_static(url: str) -> bool:
    """Statik dosya mı? Crawl'a sokmaya değmez — nuclei template'i de anlamsız."""
    p = urlsplit(url)
    path = p.path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)


def _normalize_url(url: str, base_url: str) -> Optional[str]:
    """Mutlak URL'ye çevir + aynı-host + http(s) kontrolü. Geçersizse None.
    Kök TODO/Açıkça direntinalı href'leri eler (mailto:, tel:, javascript:, #)."""
    if not url:
        return None
    u = url.strip()
    if not u or u.startswith(("mailto:", "tel:", "javascript:", "#")):
        return None
    try:
        full = urljoin(base_url, u)
    except Exception:
        return None
    parts = urlsplit(full)
    if parts.scheme not in ("http", "https"):
        return None
    if not parts.netloc:
        return None
    # Parçayı (fragment) at — aynı yol farklı anchor aynı URL sayılır.
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _same_host(url: str, base_host: str) -> bool:
    """URL'nin host'u kök hedefle (www нормalize) aynı mı? Yetki dışına taşma koruması."""
    try:
        return _canon_host(urlsplit(url).netloc) == _canon_host(base_host)
    except Exception:
        return False


def _has_params(url: str) -> bool:
    """URL parametreli mi? DAST/enjeksiyon hedefi olur."""
    try:
        q = urlsplit(url).query
        return bool(q and "=" in q)
    except Exception:
        return False


def _params_of(url: str) -> List[str]:
    """URL'nin sorgu parametre adlarını döndür (enjeksiyon hedef adları)."""
    try:
        return [k for (k, _) in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []


# ---- MODERN YÜZEY sınıflandırıcı (SAF — I/O yok) --------------------------------
# Bir path segmenti "nesne kimliği" mi? (IDOR/BOLA + enjeksiyon yüzeyi): saf sayısal id,
# UUID veya uzun hex/hash. Versiyon segmentleri (`v1`,`v2`) harfle başladığı için sayısal
# desene TAKILMAZ — yanlış-pozitif değildir.
_PATH_ID_SEG_RE = re.compile(
    r"^(?:"
    r"\d+"                                                      # /users/123
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # UUID
    r"|[0-9a-fA-F]{12,}"                                        # uzun hex/hash: /orders/9f8e7d6c5b4a
    r")$"
)
# Kesin API rotası: gövde/JSON parametresi taşır → enjeksiyon + authz (BOLA/BFLA) hedefi.
_API_ROUTE_RE = re.compile(r"^/(?:api|rest|graphql|gql|v[0-9]+)(?:/|$)", re.I)


def _has_path_id(path: str) -> bool:
    """Path'te nesne-kimliği segmenti var mı? (IDOR/BOLA yüzeyi). Yanlış-pozitifi kısmak
    için kimlik segmenti İLK segment olamaz ve kendinden ÖNCE harf içeren bir 'kaynak'
    segmenti (users/orders/...) gelmelidir — `/2024/rapor` gibi yıl-önekli yolları eler,
    `/users/123`'ü yakalar."""
    segs = [s for s in (path or "").split("/") if s]
    for i in range(1, len(segs)):
        if _PATH_ID_SEG_RE.match(segs[i]) and re.search(r"[A-Za-z]", segs[i - 1] or ""):
            return True
    return False


def _injection_kind(url: str) -> Optional[str]:
    """URL'nin aktif test (DAST/IDOR) yüzeyi sınıfı: 'query' | 'path-param' | 'api-route'
    | None. Öncelik: somut query-param > path-id (IDOR) > API rotası (gövde). Modern hedef
    (SPA/JSON API/GraphQL) `?` taşımaz ama yüzeyi buradadır — motorun eşiğini geçmesi için
    bu sınıflar 'değerli' kabul edilir (bkz attack_graph değerleme)."""
    if _has_params(url):
        return "query"
    try:
        path = urlsplit(url).path or "/"
    except Exception:
        return None
    if _has_path_id(path):
        return "path-param"
    if _API_ROUTE_RE.search(path):
        return "api-route"
    return None


def _extract_links_html(html: str, base_url: str) -> List[str]:
    """HTML içindeki href/action/src/data-url/formaction'leri HTTP mutlak URL'ye çevir.
    Bozuk HTML'e dayanıklı regex; gerçek DOM parser değil ama kandidat toplama için yeter."""
    out: List[str] = []
    seen: Set[str] = set()
    for m in _HREF_RE.finditer(html or ""):
        url = _normalize_url(m.group(1), base_url)
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _extract_forms(html: str, base_url: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """HTML'den <form action/method/inputs> çıkar. CSRF/auth-arkası form keşfinin tohumu."""
    forms: List[Dict[str, Any]] = []
    form_urls: List[str] = []
    seen_action: Set[str] = set()
    for fm in _FORM_RE.finditer(html or ""):
        block = fm.group(1) or ""
        act_m = _FORM_ACTION_RE.search(block)
        method_m = _FORM_METHOD_RE.search(block)
        inputs = list(set(_INPUT_NAME_RE.findall(block)))
        action_url = _normalize_url(act_m.group(1) if act_m else base_url, base_url)
        if not action_url:
            continue
        forms.append({
            "action": action_url,
            "method": (method_m.group(1) if method_m else "get").lower(),
            "inputs": inputs,
        })
        # Method-GET formları URL parametresine çevrilip endpoint havuzuna girebilir.
        method = (method_m.group(1) if method_m else "get").lower()
        if method == "get" and inputs:
            parts = urlsplit(action_url)
            ext = urlsplit(action_url)
            new_q = urlencode([(name, "") for name in inputs])
            q_full = ext.query + ("&" if ext.query else "") + new_q
            get_url = urlunsplit((ext.scheme, ext.netloc, ext.path, q_full, ""))
            if get_url not in seen_action:
                seen_action.add(get_url)
                form_urls.append(get_url)
    return forms, form_urls


def _extract_js_endpoints(js: str, base_url: str) -> List[str]:
    """JS gövdesinden API/rota kandidatlarını çıkar + base'e göre mutlak URL'ye çevir.
    İki deseni deneriz (rota đa deseni + fetch çağrıları)."""
    out: List[str] = []
    seen: Set[str] = set()
    for pat in (_JS_ENDPOINT_RE, _JS_FETCH_RE):
        try:
            for m in pat.finditer(js or ""):
                raw = m.group(1).strip()
                if not raw:
                    continue
                # Göreli yol ise base_url'e göre mutlak yap.
                # Türkçe: regex'ler mutlak URL de yakalayabilir (http://...). Bu durumda
                # urljoin birincil kalır. Aynı-host filtresi daha sonra uygulanır.
                u = _normalize_url(raw if raw.startswith("http") else "/", base_url)
                if not u:
                    continue
                # Hedef path'i sadece rota kısmıyla değiştir → JS /api/users tam yol olsun.
                # raw rooted URL ise (/api/...) → host + raw.
                if raw.startswith("/"):
                    parts = urlsplit(base_url)
                    u = urlunsplit((parts.scheme, parts.netloc, raw, "", ""))
                if u not in seen:
                    seen.add(u)
                    out.append(u)
        except Exception:
            continue
    return out


async def _resolve_base_url(client: httpx.AsyncClient, host: str) -> Optional[str]:
    """80/443 probe → ayakta olan şema. Pathprobe ile AYNI desen (duplicate etmek yerine
    path_probe'tan import etmek döngüsel import riski var; küçük duplikasyon kabul edildi)."""
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}/", timeout=PER_REQUEST_TIMEOUT + 2)
            if r.status_code < 500:
                return f"{scheme}://{host}"
        except Exception:
            continue
    return None


async def _fetch_capped(client: httpx.AsyncClient, url: str) -> Tuple[Optional[httpx.Response], bytes]:
    """İlk _READ_CAP baytı oku, sonra bağlantıyı kapat (dev SPA bundle yüklemekten kaçınma).
    path_probe'taki aynı desen; burada HTML için kullanılır."""
    try:
        async with client.stream("GET", url) as r:
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) >= _READ_CAP:
                    break
            return r, bytes(buf)
    except Exception:
        return None, b""


async def _fetch_robots_sitemap(client: httpx.AsyncClient, base_url: str) -> Tuple[List[str], Set[str]]:
    """robots.txt + sitemap.xml'i çek ve URL çıkarımı yap. Bunlar sitenin KENDİ BEYANI
    olduğu için crawl'un en güvenilir tohumlarıdır.
    robots.txt: 'Disallow:' satırları gizli olmasa da url tohumu için değerlidir
    (genel olarak site haritasında var).
    sitemap.xml: <loc>..</loc> ile tüm URL'ler gizlidir; en zengin kaynak.
    """
    seed: List[str] = []
    seen: Set[str] = set()

    async def _add_seed(u: str):
        if u and _same_host(u, urlsplit(base_url).netloc) and u not in seen:
            seen.add(u)
            seed.append(u)

    # robots.txt
    try:
        r = await client.get(f"{base_url}/robots.txt", timeout=PER_REQUEST_TIMEOUT)
        if r.status_code == 200:
            # Türkçe: Sitemap: <url> satırları için sitemap.xml yolunu al; ayrıca Disallow yollarını
            # da raw '/...' tohumu olarak ekle. Yanlış pozitifler validator ile reddedilir.
            for line in (r.text or "").splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    sm_url = line.split(":", 1)[1].strip()
                    sm_url = _normalize_url(sm_url, base_url)
                    await _fetch_sitemap_into(client, sm_url, _add_seed)
                elif line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and not path.startswith("*"):
                        await _add_seed(_normalize_url(path, base_url))
    except Exception:
        pass

    # Son çare: standart sitemap.xml
    if not seed:
        await _fetch_sitemap_into(client, f"{base_url}/sitemap.xml", _add_seed)
    # Ek olasılıklar: sitemap_index.xml
    if not seed:
        await _fetch_sitemap_into(client, f"{base_url}/sitemap_index.xml", _add_seed)

    return seed, seen


async def _fetch_sitemap_into(client: httpx.AsyncClient, sm_url: str, add_fn) -> None:
    """Sitemap (salt liste ya da sitemap-index) çek ve URL'ler add_fn'e ver. Yinelemeli
    olabilir sitemap-index; derinlik sınırı uygula."""
    visited: Set[str] = set()
    async def _walk(u: str, depth: int):
        if depth > 2 or u in visited:
            return
        visited.add(u)
        try:
            r = await client.get(u, timeout=PER_REQUEST_TIMEOUT)
            if r.status_code != 200:
                return
            body = r.text or ""
            for m in _SITEMAP_URL_RE.finditer(body):
                loc = m.group(1).strip()
                if loc.endswith(".xml") and re.search(r"/sitemap", loc, re.I):
                    # İç sitemap referansı → derinlik+1 ile indir
                    await _walk(_normalize_url(loc, u) or loc, depth + 1)
                else:
                    await add_fn(_normalize_url(loc, u))
        except Exception:
            pass
    try:
        await _walk(sm_url, 0)
    except Exception:
        pass


def _parse_header_list(auth_headers: Optional[List[str]]) -> Dict[str, str]:
    """['Authorization: Bearer x', 'Cookie: s=1'] → {'Authorization':'Bearer x', ...} (SAF).
    Geçersiz/boş satırlar atlanır. Login-arkası yüzey keşfinin ön koşulu."""
    out: Dict[str, str] = {}
    for h in (auth_headers or []):
        if not isinstance(h, str) or ":" not in h:
            continue
        k, _, v = h.partition(":")
        k, v = k.strip(), v.strip()
        if k and v:
            out[k] = v
    return out


async def discover_endpoints(target: str, *, depth: Optional[int] = None,
                             auth_headers: Optional[List[str]] = None) -> Dict[str, Any]:
    """Ana crawler. Hedefe HTTP-BFS yapar; same-host URL/parametreli endpoint/form/JS keşifleri
    toplanır. Sıfır-bağımlılık; path_probe ile paylaşılır desen.

    auth_headers verilirse (bearer/cookie/header — 'Ad: değer' listesi) TÜM crawl istekleri
    kimlik doğrulamalı gider → login-ARKASI yüzey (gerçek zafiyetlerin ~%80'i) keşfedilir."""
    started = time.time()
    _auth = _parse_header_list(auth_headers)
    host = re.sub(r"^https?://", "", target.strip()).split("/")[0].strip()
    if not host:
        return {"target": target, "base_url": None, "seed_urls": [], "discovered_urls": [],
                "parameterized_endpoints": [], "forms": [], "js_assets": [],
                "elapsed_seconds": round(time.time() - started, 2),
                "note": "invalid_target"}

    max_depth = MAX_DEPTH if depth is None else max(1, min(depth, MAX_DEPTH))
    user_agent = _UA

    limits = httpx.Limits(max_connections=CONCURRENCY * 2, max_keepalive_connections=CONCURRENCY)
    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=PER_REQUEST_TIMEOUT, limits=limits,
        headers={"User-Agent": user_agent, **_auth},  # auth başlıkları → login-arkası crawl
    ) as client:
        base_url = await _resolve_base_url(client, host)
        if not base_url:
            return {"target": host, "base_url": None, "seed_urls": [], "discovered_urls": [],
                    "parameterized_endpoints": [], "forms": [], "js_assets": [],
                    "elapsed_seconds": round(time.time() - started, 2),
                    "note": "host_unreachable: 80/443 üzerinden HTTP erişimi yok"}

        base_host = urlsplit(base_url).netloc
        seed_urls, _seen_seed = await _fetch_robots_sitemap(client, base_url)

        # Türkçe: Taranacak URL kuyruğu — seed + base / ile başlar. Her URL (url, depth) tuple.ı.
        seen: Set[str] = set()
        all_urls: List[str] = []
        forms_out: List[Dict[str, Any]] = []
        js_assets: List[str] = []
        param_endpoints: List[Dict[str, Any]] = []

        def _add_url(u: str):
            if not u or not _same_host(u, base_host):
                return
            if _is_static(u):
                return
            if u in seen:
                return
            if len(seen) >= MAX_URLS:
                return
            seen.add(u)
            all_urls.append(u)

        # Seed URL'leri + kök
        _add_url(base_url + "/")
        for u in seed_urls:
            _add_url(u)

        queue: List[Tuple[str, int]] = [(u, 0) for u in list(all_urls)]
        # Türkçe: 'all_urls' zaten seedleri de içeriyor; ilkönce onları tarama için sıraya
        # alalım. Aşağıda gördükçe URL havuzu büyür.
        visited: Set[str] = set()

        overall_t0 = time.monotonic()
        budget_hit = False

        while queue:
            if len(all_urls) >= MAX_URLS:
                budget_hit = True
                break
            if time.monotonic() - overall_t0 > OVERALL_BUDGET:
                budget_hit = True
                break

            # Türkçe: Kuyruktan TÜM 1 krmanıdakı depth-0/1 seviyesini paralel çek. Concurrency
            # kapısıyla; her URL'ün gövdesi çekilip link/form/JS ayrıştırılır ve kuyruğa yeni
            # adaylar eklenir. Depth sınırını aşanlar crawl edilir ama link'leri takip edilmez.
            batch: List[Tuple[str, int]] = []
            while queue and len(batch) < CONCURRENCY:
                batch.append(queue.pop(0))

            async def _process_one(url: str, d: int):
                if url in visited:
                    return
                visited.add(url)
                resp, raw = await _fetch_capped(client, url)
                if resp is None:
                    return
                ctype = resp.headers.get("content-type", "")
                # Sadece HTML/JS içeriğini parse et (ikili/stream atlanır).
                if "html" in ctype or "javascript" in ctype or "text/" in ctype or "xml" in ctype:
                    try:
                        body = raw.decode("utf-8", errors="replace")
                    except Exception:
                        return
                else:
                    return

                # JS ise sadece endpoint'leri çıkar
                if "javascript" in ctype or url.endswith(".js"):
                    js_assets.append(url)
                    js_eps = _extract_js_endpoints(body, base_url)
                    for eu in js_eps:
                        before = len(all_urls)
                        _add_url(eu)
                        if len(all_urls) > before and d + 1 <= max_depth:
                            queue.append((eu, d + 1))
                    return

                # HTML: link + form + inline/external JS
                links = _extract_links_html(body, url)
                forms, form_get_urls = _extract_forms(body, base_url)
                forms_out.extend(forms)

                for ln in links:
                    before = len(all_urls)
                    _add_url(ln)
                    if len(all_urls) > before and d + 1 <= max_depth:
                        queue.append((ln, d + 1))
                for fgu in form_get_urls:
                    before = len(all_urls)
                    _add_url(fgu)
                    if len(all_urls) > before and d + 1 <= max_depth:
                        queue.append((fgu, d + 1))

                # External/internal JS dosyalarını kuyruğa ekle
                if "<script" in body.lower():
                    for s in re.findall(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", body, re.I):
                        jsu = _normalize_url(s, base_url)
                        if jsu and _same_host(jsu, base_host) and not _is_static(jsu):
                            if jsu not in seen:
                                _add_url(jsu)
                                queue.append((jsu, d + 1))

                # Inline JS: sayfa içi <script> bloğundan endpoint çıkar
                for sm in re.finditer(r"<script\b[^>]*>(.*?)</script>", body, re.I | re.S):
                    js_eps = _extract_js_endpoints(sm.group(1) or "", base_url)
                    for eu in js_eps:
                        before = len(all_urls)
                        _add_url(eu)
                        if len(all_urls) > before and d + 1 <= max_depth:
                            queue.append((eu, d + 1))

            await asyncio.gather(*[_process_one(u, d) for (u, d) in batch], return_exceptions=True)

        # Enjeksiyon/authz hedeflerini ayrıştır — DAST/IDOR bunlarda çalışır. MODERN_SURFACE
        # açıkken query-param'a EK olarak path-param REST (IDOR/BOLA) ve API rotaları
        # (JSON/GraphQL gövde) da hedef sayılır; kapalıyken yalnız klasik query-string.
        for u in all_urls:
            kind = _injection_kind(u) if MODERN_SURFACE else ("query" if _has_params(u) else None)
            if kind:
                param_endpoints.append({"url": u, "kind": kind, "params": _params_of(u)})

        elapsed = round(time.time() - started, 2)
        return {
            "target": host,
            "base_url": base_url,
            "seed_urls": seed_urls[:50],
            # Türkçe: discovered_urls tüm keşfedilen URL'lerdir — ilk 500. Graf bunları
            # ENDPOINT node'una çevirir; değerleri path-pattern ile skorlanır.
            "discovered_urls": all_urls[:MAX_URLS],
            "discovered_count": len(all_urls),
            "parameterized_endpoints": param_endpoints[:200],
            "parameterized_count": len(param_endpoints),
            # Kırılım: kaç hedef query-string, kaç path-param (IDOR), kaç API rotası —
            # operatör "modern yüzey görüldü mü"yu tek bakışta ölçsün.
            "injectable_by_kind": {
                k: sum(1 for ep in param_endpoints if ep.get("kind") == k)
                for k in ("query", "path-param", "api-route")
            },
            "forms": forms_out[:50],
            "forms_count": len(forms_out),
            "js_assets": list(dict.fromkeys(js_assets))[:50],
            "js_assets_count": len(set(js_assets)),
            "elapsed_seconds": elapsed,
            "partial": bool(budget_hit),
            "note": "budget_reached" if budget_hit else None,
        }