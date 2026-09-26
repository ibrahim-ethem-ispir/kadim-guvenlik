"""
Kadim Güvenlik — Pasif Tarihî Kaynak Keşfi (Bug Bounty P1-A)
=============================================================
Türkçe: Wayback Machine CDX API'si hedefin TARİHÎ URL arşivini döker. Bug bounty'de
klasik kaynak: artık siteden linklenmeyen ama CANLI olabilen endpoint'ler
(`/api/v1/...` kaldırıldı sanılır, sunucu hâlâ cevap verir). Pasif ve ucuzdur —
hedefe TEK istek gitmez (istek archive.org'a), WAF/log riski sıfır.

Çıktı crawler'ın keşif havuzuna karışır: parametreli tarihî URL'ler DAST/doğrulayıcı
hedefi olur (kural-tohumu hattı). "Bakılacak yer kalmadı" hissinin ikinci ilacı:
bugün görünmeyen yüzey, dünün arşivinde durur.

Tasarım (endpoint_diff deseni): karar çekirdeği SAF (filter_wayback_urls) → izole
test; I/O katmanı (fetch_wayback_endpoints) ince. Hedef scope koruması: yalnız
aynı host (www-normalize) URL'leri alınır — arşiv komşu domain karıştırabilir.

Not: GitHub/Google dork (P1-A'nın diğer ayakları) API anahtarı / kazıma kısıtı
yüzünden şimdilik kapsam dışı — Wayback en ucuz ve en yüksek getirili ayak.
"""

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit, parse_qsl

logger = logging.getLogger("passive-sources")

# CDX API — output=json ilk satırı header (["original"]) döner.
# collapse=urlkey: aynı URL'nin yıllar içindeki yüzlerce kopyasını TEKE indirir.
# filter=statuscode:200: yalnız canlı dönmüş kayıtlar (404 arşivi gürültü).
_CDX_URL = "https://web.archive.org/cdx/search/cdx"

# Varsayılan bütçe: 400 ham kayıt → tekilleştirme sonrası ~200-300 URL.
_WAYBACK_LIMIT = int(os.getenv("WAYBACK_LIMIT", "400"))
_WAYBACK_TIMEOUT = float(os.getenv("WAYBACK_TIMEOUT", "20"))

_UA = "Mozilla/5.0 (compatible; KadimGuvenlik/1.0; +security-audit)"

# Statik uzantılar — tarihî PNG/CSS enjeksiyon hedefi değil; havuzu kirletmesin.
_STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip",
    ".rar", ".tar", ".gz", ".7z", ".doc", ".docx", ".xls", ".xlsx",
)


def _canon_host(host: str) -> str:
    h = (host or "").strip().lower()
    return h[4:] if h.startswith("www.") else h


def _in_scope(netloc_host: str, base_host: str) -> bool:
    """Host hedefin KENDİSİ veya ALTDOMAIN'i mi? Bug bounty programları genelde
    wildcard scope (*.example.com) verir; Wayback PASİF kaynak olduğundan alt
    domain URL'lerini havuza almak güvenlidir (aktif test motorun scope kapısından
    yine geçer — crawl'un aynı-host kısıdı Aktif katmanda kalır)."""
    h = _canon_host(netloc_host)
    return h == base_host or h.endswith("." + base_host)


def filter_wayback_urls(rows: List[str], host: str, *, cap: int = 300) -> Dict[str, Any]:
    """Ham CDX 'original' satırlarından aynı-host URL havuzu kur (SAF — I/O yok).

    Kurallar: şema http(s), host hedefle aynı veya alt domaini (scope), statik uzantı
    yok, tekilleştirme yol+param-adı üstünden (değerler uçucu). PARAMETRELİ URL'ler
    öne alınır — doğrulayıcı hedefleri onlar; parametresizler method-matrix adayı
    olarak arkaya düşer. cap toplam tavan.
    """
    base_host = _canon_host(host)
    seen_keys: Set[Any] = set()
    parameterized: List[str] = []
    plain: List[str] = []

    for raw in rows or []:
        u = str(raw or "").strip()
        if not u:
            continue
        try:
            parts = urlsplit(u)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.netloc:
            continue
        netloc = parts.netloc.lower().split("@")[-1].split(":")[0]
        if not _in_scope(netloc, base_host):
            continue
        path = (parts.path or "/").lower()
        if any(path.endswith(ext) for ext in _STATIC_EXT):
            continue
        # Tekilleştirme anahtarı: host + yol + parametre ADLARI (değerler arşiv
        # kopyaları arasında değişir — aynı yüzeyi yüzlerce kez havuza almayalım).
        pnames = tuple(sorted(dict.fromkeys(
            k for k, _v in parse_qsl(parts.query, keep_blank_values=True) if k)))
        key = (_canon_host(netloc), parts.path or "/", pnames)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        if pnames:
            parameterized.append(u)
        else:
            plain.append(u)
        if len(parameterized) + len(plain) >= cap * 3:
            break  # ham havuz yeterince büyük — kırpma sonrası cap'e oturur

    # Parametreli öncelikli kırpma: bütçe dolunca önce düz URL'ler düşer.
    if len(parameterized) > cap:
        parameterized = parameterized[:cap]
        plain = []
    else:
        plain = plain[: max(0, cap - len(parameterized))]

    return {
        "parameterized": parameterized,
        "plain": plain,
        "total": len(parameterized) + len(plain),
    }


async def fetch_wayback_endpoints(host: str, *, cap: int = 0,
                                  timeout: Optional[float] = None) -> Dict[str, Any]:
    """Wayback CDX'den hedefin tarihî endpoint havuzunu çek (pasif — hedefe istek YOK).

    Döner: {"source": "wayback", "host", "parameterized": [...], "plain": [...],
            "total", "elapsed_seconds", "note"} — hata/erişilemezlik note alanında,
    asla exception yükseltmez (keşif lüks katman; düşerse tarama devam eder).
    """
    import time
    started = time.time()
    limit = cap if cap > 0 else _WAYBACK_LIMIT
    tmo = timeout or _WAYBACK_TIMEOUT
    base_host = _canon_host(host)
    result: Dict[str, Any] = {
        "source": "wayback", "host": base_host,
        "parameterized": [], "plain": [], "total": 0,
        "elapsed_seconds": 0.0, "note": None,
    }
    if not base_host:
        result["note"] = "invalid_host"
        return result
    try:
        import httpx
        params = {
            "url": f"*.{base_host}",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "filter": "statuscode:200",
            "limit": str(limit),
        }
        async with httpx.AsyncClient(timeout=tmo, follow_redirects=True,
                                     headers={"User-Agent": _UA}) as client:
            resp = await client.get(_CDX_URL, params=params)
            if resp.status_code != 200:
                result["note"] = f"cdx_http_{resp.status_code}"
                return result
            try:
                data = resp.json()
            except Exception:
                result["note"] = "cdx_parse_error"
                return result
        # İlk satır header (["original"]); veri satırları tek kolon.
        rows = [r[0] for r in data[1:] if isinstance(r, list) and r] if len(data) > 1 else []
        filtered = filter_wayback_urls(rows, base_host, cap=cap if cap > 0 else 300)
        result.update(filtered)
        result["note"] = "ok" if rows else "no_archive"
    except asyncio.TimeoutError:
        result["note"] = "cdx_timeout"
    except Exception as e:
        result["note"] = f"cdx_error: {type(e).__name__}"
        logger.debug(f"Wayback keşfi atlandı ({base_host}): {e}")
    result["elapsed_seconds"] = round(time.time() - started, 2)
    return result
