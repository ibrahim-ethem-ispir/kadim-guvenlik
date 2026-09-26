"""
Kadim Güvenlik — Headless Crawler Service (T1-A: JS-render yüzey keşfi)
=======================================================================
Türkçe: Orchestrator'ın httpx crawler'ı JS ÇALIŞTIRMAZ → modern SPA'ların (React/Vue/Angular)
%80-90'ı görünmez ("boş tarama"nın asıl kök-nedeni). Bu servis GERÇEK bir tarayıcı (headless
Chromium, Playwright) ile sayfayı RENDER eder ve şunları toplar:

  - Render edilmiş DOM'daki linkler (a[href]) — JS'in eklediği navigasyon dahil
  - Form'lar (action/method/input adları) — login-arkası yüzeyin tohumu
  - YAKALANAN XHR/fetch istekleri → GERÇEK API endpoint'leri (SPA'da en büyük kazanç)
  - Script (JS) varlıkları

Çıktı sözleşmesi orchestrator'ın endpoint_discovery.discover_endpoints'i ile AYNIDIR
(base_url/discovered_urls/parameterized_endpoints/forms/js_assets) → orchestrator sonuçları
MERGE eder; bu servis kapalı/erişilemezse httpx crawler'a sorunsuz düşer (degrade-safe).

auth_headers verilirse tüm render istekleri kimlik doğrulamalı gider → login-ARKASI SPA yüzeyi.
TAHRİBATSIZ: yalnız gezinme/okuma; form GÖNDERİLMEZ, buton tıklanmaz (deterministik keşif).
"""

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urljoin, parse_qsl

from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("crawler-service")

app = FastAPI(title="Kadim Headless Crawler", version="1.0.0")

MAX_PAGES = int(os.getenv("CRAWLER_MAX_PAGES", "25"))       # render pahalı → sayfa sınırı
NAV_TIMEOUT_MS = int(os.getenv("CRAWLER_NAV_TIMEOUT_MS", "15000"))
OVERALL_BUDGET_S = float(os.getenv("CRAWLER_BUDGET_S", "90"))
_STATIC_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
               ".ttf", ".eot", ".mp4", ".webp", ".pdf", ".zip", ".map")


class CrawlRequest(BaseModel):
    target: str
    depth: int = 2
    max_pages: int = MAX_PAGES
    auth_headers: List[str] = []          # ['Authorization: Bearer x', 'Cookie: s=1']


def _same_host(url: str, host: str) -> bool:
    try:
        return urlsplit(url).netloc.split("@")[-1].split(":")[0].lower() == host.lower()
    except Exception:
        return False


def _is_static(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(_STATIC_EXT)


def _headers_dict(auth_headers: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in auth_headers or []:
        if isinstance(h, str) and ":" in h:
            k, _, v = h.partition(":")
            if k.strip() and v.strip():
                out[k.strip()] = v.strip()
    return out


@app.get("/health")
async def health():
    try:
        import playwright  # noqa: F401
        return {"status": "healthy", "service": "crawler-service", "engine": "playwright-chromium"}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}


@app.post("/crawl")
async def crawl(req: CrawlRequest) -> Dict[str, Any]:
    """SPA'yı headless Chromium ile render edip yüzey keşfi yap. Hata → boş+not (degrade-safe)."""
    raw = req.target.strip()
    if "://" not in raw:
        raw = "https://" + raw
    host = urlsplit(raw).netloc.split("@")[-1].split(":")[0]
    empty = {"target": req.target, "base_url": None, "discovered_urls": [],
             "parameterized_endpoints": [], "forms": [], "js_assets": [], "rendered": True}

    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        logger.warning(f"Playwright yok: {e}")
        return {**empty, "note": "playwright_unavailable"}

    discovered: set = set()
    param_eps: Dict[str, Dict[str, Any]] = {}
    forms_out: List[Dict[str, Any]] = []
    js_assets: set = set()
    captured_api: set = set()   # XHR/fetch yakalanan URL'ler (SPA'nın gerçek API'si)
    base_url: Optional[str] = None

    def _record_url(u: str):
        if not u or not _same_host(u, host) or _is_static(u):
            return
        u = u.split("#")[0]
        if parse_qsl(urlsplit(u).query):
            param_eps.setdefault(u, {"url": u, "params": [k for k, _ in parse_qsl(urlsplit(u).query)],
                                     "source": "headless"})
        discovered.add(u)

    loop_t0 = asyncio.get_event_loop().time()
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=_headers_dict(req.auth_headers) or None,
                user_agent="Mozilla/5.0 (compatible; KadimHeadless/1.0)",
            )

            # XHR/fetch AĞ trafiğini yakala — SPA'nın gerçek API endpoint'leri buradan çıkar
            def _on_request(request):
                try:
                    if request.resource_type in ("xhr", "fetch") and _same_host(request.url, host):
                        captured_api.add(request.url.split("#")[0])
                except Exception:
                    pass
            context.on("request", _on_request)

            page = await context.new_page()
            page.set_default_navigation_timeout(NAV_TIMEOUT_MS)

            queue: List[str] = [raw]
            seen: set = set()
            while queue and len(seen) < req.max_pages:
                if asyncio.get_event_loop().time() - loop_t0 > OVERALL_BUDGET_S:
                    break
                url = queue.pop(0)
                if url in seen:
                    continue
                seen.add(url)
                try:
                    resp = await page.goto(url, wait_until="networkidle")
                    if base_url is None and resp is not None:
                        base_url = f"{urlsplit(str(page.url)).scheme}://{urlsplit(str(page.url)).netloc}"
                except Exception as e:
                    logger.debug(f"goto hatası ({url}): {e}")
                    continue
                _record_url(url)

                # 1) Render edilmiş DOM linkleri
                try:
                    hrefs = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)")
                except Exception:
                    hrefs = []
                for h in hrefs or []:
                    _record_url(h)
                    if _same_host(h, host) and not _is_static(h) and h.split("#")[0] not in seen:
                        if len(queue) + len(seen) < req.max_pages * 3:
                            queue.append(h.split("#")[0])

                # 2) Form'lar (action/method/input adları)
                try:
                    page_forms = await page.eval_on_selector_all(
                        "form",
                        """els => els.map(f => ({
                            action: f.action || '',
                            method: (f.method || 'get'),
                            inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                                       .map(i => i.name).filter(Boolean)
                        }))""")
                except Exception:
                    page_forms = []
                for f in page_forms or []:
                    action = f.get("action") or url
                    forms_out.append({"url": action, "method": (f.get("method") or "get").lower(),
                                      "inputs": f.get("inputs") or []})
                    _record_url(action)

                # 3) Script (JS) varlıkları
                try:
                    srcs = await page.eval_on_selector_all(
                        "script[src]", "els => els.map(e => e.src)")
                    for s in srcs or []:
                        if _same_host(s, host):
                            js_assets.add(s)
                except Exception:
                    pass

            await context.close()
            await browser.close()
    except Exception as e:
        logger.warning(f"Headless crawl hatası ({host}): {e}")
        return {**empty, "base_url": base_url, "note": f"crawl_error: {e}"}

    # Yakalanan XHR/fetch'leri parametreli/plain olarak ekle (SPA API kazancı)
    for u in captured_api:
        _record_url(u)

    return {
        "target": req.target,
        "base_url": base_url or (f"https://{host}"),
        "discovered_urls": sorted(discovered),
        "parameterized_endpoints": list(param_eps.values()),
        "forms": forms_out,
        "js_assets": sorted(js_assets),
        "captured_api_count": len(captured_api),
        "rendered": True,
        "note": "ok",
    }
