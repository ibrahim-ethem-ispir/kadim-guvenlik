"""
Kadim Güvenlik — Swagger/OpenAPI Keşfi (Bug Bounty P1-B)
=========================================================
Türkçe: API dokümanı keşfi, "dokümante edilmemiş API" avının İKİZ kardeşidir:
swagger.json/openapi.json açıktaysa HER endpoint + method + parametre adı bedavaya
gelir — crawl'un saatler süren tahminini tek istekle verir. Bu modül:

  1) Küratörlü doküman yollarını proplar (GET, içerik JSON/OpenAPI mi doğrulanır)
  2) Bulunan dokümanı AYRIŞTIRIR (OpenAPI 2.0 "swagger" + 3.x) → endpoint matrisi:
     yol × method × parametreler. Path-parametreleri örnek değerle doldurulur ki
     URL doğrulayıcılara hazır gelsin.
  3) Çıktı crawler havuzuna karışır: GET endpoint'ler parametreli URL olarak,
     POST/PUT/DELETE endpoint'ler method+gövde bilgisiyle P0-B hattına beslenir.

Tasarım (path_probe/endpoint_diff deseni): parse çekirdeği SAF (stdlib) → izole
test; prob I/O katmanı ince. Bulunamazsa note='not_found' — tarama düşmez.

GÜVENLİK: doküman yalnız OKUNUR; endpoint'lerin AKTİF testi mevcut doğrulayıcı
kapılarından (POC_VERIFY_ENABLED, seviye, bütçe) geçer — burası yalnız keşif.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger("openapi-discovery")

# Küratörlü API-doküman yolları — framework fark etmez (Spring, FastAPI, .NET,
# Laravel, Express...). Sıra: pratikte en sık görülen önce.
OPENAPI_PATHS: List[str] = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/docs/openapi.json",
    "/openapi.yaml",
    "/swagger.yaml",
    "/.well-known/openapi.json",
]

# Doküman başına çıkarılacak endpoint tavanı (dev spec'lar bütçeyi yemesin).
_ENDPOINT_CAP = 120

# Path-parametresi ({id}) için örnek değer — doğrulayıcı URL'yi hazır ister.
# Sayısal çağrışımlı adlara sayı, diğerlerine kısa belirteç (enjeksiyon hedefi
# olarak da anlamlı: id=1 üstüne payload eklenir).
_PATH_PARAM_NUMERIC = re.compile(r"(id|num|number|count|page|size|limit|offset|year|version|v\d+)", re.I)

_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")


def _is_openapi_doc(obj: Any) -> bool:
    """JSON nesnesi gerçekten OpenAPI/Swagger dokümanı mı? (soft-200 elemesi —
    her 200-JSON swagger değildir; 'swagger'/'openapi' kök alanı şart)."""
    if not isinstance(obj, dict):
        return False
    if str(obj.get("swagger") or "").startswith("2"):
        return True
    if str(obj.get("openapi") or "").startswith("3"):
        return True
    return False


def _base_from_doc(doc: Dict[str, Any], probe_url: str) -> str:
    """Dokümanın beyan ettiği kök (servers[0].url / basePath+host) — yoksa probun
    kendi kökü. Göreli beyanlar probe köküne göre çözülür."""
    try:
        servers = doc.get("servers") or []
        if servers and isinstance(servers[0], dict) and servers[0].get("url"):
            return urljoin(probe_url, str(servers[0]["url"]))
        # Swagger 2.0: host + basePath
        host = doc.get("host")
        base_path = doc.get("basePath") or ""
        if host:
            scheme = urlsplit(probe_url).scheme or "https"
            return f"{scheme}://{host}{base_path}"
        if base_path:
            return urljoin(probe_url, str(base_path))
    except Exception:
        pass
    p = urlsplit(probe_url)
    return f"{p.scheme}://{p.netloc}"


def _fill_path_params(path: str) -> str:
    """'/users/{id}/orders' → '/users/1/orders' — path-parametre örnek değerle
    doldurulur (doğrulayıcılar somut URL ister). Ad sayısal çağrışımlıysa '1',
    değilse 'test'."""
    def _sub(m):
        name = m.group(1)
        return "1" if _PATH_PARAM_NUMERIC.search(name) else "test"
    return re.sub(r"\{([^}]+)\}", _sub, path)


def parse_openapi(doc: Dict[str, Any], probe_url: str, *,
                  cap: int = _ENDPOINT_CAP) -> Dict[str, Any]:
    """OpenAPI 2.0/3.x dokümanından endpoint matrisi çıkar (SAF — I/O yok).

    Çıktı: {"endpoints": [{"url", "method", "params", "path_template"}],
            "title", "version", "endpoint_count"}
    - query-parametreleri URL'ye `?ad=` olarak eklenir (GET) ya da method
      gövde-adayı olarak params listesinde kalır (POST/PUT/PATCH — P0-B hattı
      gövde enjeksiyonunu orada kurar).
    - path-parametreleri örnek değerle doldurulur.
    - head/options atlanır (enjeksiyon değeri yok); get/post/put/delete/patch kalır.
    """
    out: List[Dict[str, Any]] = []
    if not _is_openapi_doc(doc):
        return {"endpoints": [], "title": None, "version": None, "endpoint_count": 0}

    base = _base_from_doc(doc, probe_url).rstrip("/")
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        return {"endpoints": [], "title": (doc.get("info") or {}).get("title"),
                "version": str(doc.get("swagger") or doc.get("openapi") or ""),
                "endpoint_count": 0}

    seen: set = set()
    for raw_path, methods in paths.items():
        if not isinstance(methods, dict) or not str(raw_path).startswith("/"):
            continue
        filled = _fill_path_params(str(raw_path))
        for method, op in methods.items():
            m = str(method).lower()
            if m not in _HTTP_METHODS or m in ("head", "options"):
                continue
            if not isinstance(op, dict):
                continue
            # Parametreler: operation seviyesi + path seviyesi (ikisi birleşir).
            params_raw = list(op.get("parameters") or []) + [
                p for p in (methods.get("parameters") or []) if isinstance(p, dict)]
            qnames: List[str] = []
            for p in params_raw:
                if not isinstance(p, dict):
                    continue
                if p.get("in") == "query" and p.get("name"):
                    qnames.append(str(p["name"]))
            qnames = list(dict.fromkeys(qnames))
            url = base + filled
            if m == "get" and qnames:
                url += "?" + "&".join(f"{n}=" for n in qnames)
            key = (m, url)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "url": url,
                "method": m,
                "params": qnames,
                "path_template": str(raw_path),
            })
            if len(out) >= cap:
                break
        if len(out) >= cap:
            break

    info = doc.get("info") or {}
    return {
        "endpoints": out,
        "title": info.get("title"),
        "version": str(doc.get("swagger") or doc.get("openapi") or ""),
        "endpoint_count": len(out),
    }


async def discover_openapi(base_url: str, *, extra_paths: Optional[List[str]] = None,
                           timeout: float = 10.0) -> Dict[str, Any]:
    """Kök üstünde doküman yollarını propla; ilk geçerli OpenAPI dokümanını parse et.

    Döner: {"found": bool, "doc_url", "endpoints": [...], "title", "version",
            "endpoint_count", "note"} — bulunamazsa found=False + note. Asla
    exception yükseltmez (keşif katmanı; tarama düşmez).
    """
    import httpx
    result: Dict[str, Any] = {"found": False, "doc_url": None, "endpoints": [],
                              "title": None, "version": None, "endpoint_count": 0,
                              "note": "not_found"}
    if not base_url:
        result["note"] = "invalid_base"
        return result
    candidates = list(dict.fromkeys((extra_paths or []) + OPENAPI_PATHS))
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False,
                                     follow_redirects=True) as client:
            for path in candidates:
                url = base_url.rstrip("/") + path
                try:
                    r = await client.get(url)
                except Exception:
                    continue
                if r.status_code != 200:
                    continue
                ctype = (r.headers.get("content-type") or "").lower()
                body = r.text or ""
                # YAML varyantları: içerik JSON değilse basit 'paths:' işareti yeter
                # (tam YAML parser bağımlılığı eklemiyoruz — JSON öncelikli).
                if "json" not in ctype and not body.lstrip().startswith("{"):
                    if path.endswith((".yaml", ".yml")) and "paths:" in body:
                        result["note"] = "yaml_doc_not_parsed"
                        result["found"] = True
                        result["doc_url"] = url
                    continue
                try:
                    doc = r.json()
                except Exception:
                    continue
                if not _is_openapi_doc(doc):
                    continue
                parsed = parse_openapi(doc, url)
                result.update({
                    "found": True, "doc_url": url,
                    "endpoints": parsed["endpoints"],
                    "title": parsed["title"], "version": parsed["version"],
                    "endpoint_count": parsed["endpoint_count"],
                    "note": "ok",
                })
                logger.info(f"📜 OpenAPI bulundu: {url} — {parsed['endpoint_count']} endpoint")
                return result
    except Exception as e:
        result["note"] = f"probe_error: {type(e).__name__}"
        logger.debug(f"OpenAPI keşfi atlandı ({base_url}): {e}")
    return result
