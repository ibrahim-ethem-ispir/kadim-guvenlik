"""
Kadim Güvenlik — vulnx (ProjectDiscovery cvemap/PDCP) CVE İstihbaratı
=====================================================================
Türkçe: Bir CVE için EPSS + KEV + **PoC var mı/kaç tane** + **hazır nuclei-template var mı**
bilgisini ProjectDiscovery Cloud (PDCP) API'sinden çeker. `kev_intel.py` (CISA KEV + EPSS) ve
[[cpe-identity-backbone]] zincirini derinleştirir: CPE/CVE → "sadece açık var" değil, "şu PoC/
template ile DOĞRULANABİLİR" sinyali.

Tasarım (kullanıcı "tek tük tarama" yapıyor → keysiz 10/dk yeterli, ama güvenli kur):
  - **Keysiz çalışır** (10/dk sınırı). `PDCP_API_KEY` verilirse `X-Api-Key` başlığıyla gider,
    limit çok yükselir (ücretsiz: cloud.projectdiscovery.io).
  - **Throttle**: kendi tarafımızda kayan-60sn pencere → sunucuya 429 yaptırmadan sınırı korur.
  - **Cache**: CVE başına 24s bellek cache → aynı CVE tekrar sorulmaz (tekrar taramalar bedava).
  - **Degrade-safe + GÖRÜNÜR**: limit dolar/hata olursa motor DÜŞMEZ; "bakılacaktı ama
    bakılamadı (rate_limit)" listesi UI'a taşınır (sessiz yutma YOK — doktrin).
"""

import os
import re
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import httpx

VULNX_BASE = os.getenv("VULNX_API_URL", "https://api.projectdiscovery.io").rstrip("/")
PDCP_API_KEY = os.getenv("PDCP_API_KEY", "").strip()
VULNX_ENABLED = os.getenv("VULNX_INTEL", "1") == "1"
# Anahtar varsa limit yüksek (elle 50 hedefle); keysiz sunucu sınırı 10/dk → 10 hedefle.
_RATE_MAX = int(os.getenv("VULNX_RATE_PER_MIN", "50" if PDCP_API_KEY else "10"))
_CACHE_TTL = float(os.getenv("VULNX_CACHE_TTL_S", "86400"))  # 24s

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{3,}$", re.IGNORECASE)
_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}   # cve -> (ts, slim)
_call_times: Deque[float] = deque()                    # son istek zaman damgaları (throttle)


class _RateLimited(Exception):
    """Sunucu 429 döndü — sonraki canlı istekler de rate_limit sayılır."""


def _headers() -> Dict[str, str]:
    h = {"User-Agent": "Kadim-Vulnx/1.0", "Accept": "application/json"}
    if PDCP_API_KEY:
        h["X-Api-Key"] = PDCP_API_KEY
    return h


def _rate_ok() -> bool:
    now = time.time()
    while _call_times and now - _call_times[0] > 60:
        _call_times.popleft()
    return len(_call_times) < _RATE_MAX


def _slim(doc: Dict[str, Any], cve: str) -> Dict[str, Any]:
    """PDCP dokümanından UI/skorlama için gereken ALANLARI süz (yanıtı şişirme)."""
    return {
        "cve": doc.get("cve_id") or cve,
        "severity": doc.get("severity"),
        "cvss": doc.get("cvss_score"),
        "epss": doc.get("epss_score"),
        "epss_pct": doc.get("epss_percentile"),
        "is_kev": bool(doc.get("is_kev")),
        "is_poc": bool(doc.get("is_poc")),
        "poc_count": doc.get("poc_count") or 0,
        "is_template": bool(doc.get("is_template")),
        "template_type": doc.get("template_type"),
        "is_remote": bool(doc.get("is_remote")),
        "is_patch_available": bool(doc.get("is_patch_available")),
        "product": doc.get("product"),
        "vendor": doc.get("vendor"),
    }


async def _fetch_one(cve: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    r = await client.get(f"{VULNX_BASE}/v2/vulnerability/{cve}", headers=_headers())
    if r.status_code == 429:
        raise _RateLimited()
    if r.status_code != 200:
        return None
    doc = (r.json() or {}).get("data") or {}
    if not isinstance(doc, dict) or not doc:
        return None
    slim = _slim(doc, cve)
    _cache[cve] = (time.time(), slim)
    return slim


def _normalize(cve_ids: List[Any]) -> List[str]:
    seen: List[str] = []
    for c in cve_ids or []:
        for one in (c if isinstance(c, (list, tuple)) else [c]):
            s = str(one or "").upper().strip()
            if _CVE_RE.match(s) and s not in seen:
                seen.append(s)
    return seen


async def enrich_cves(cve_ids: List[Any], *, max_lookups: int = 12,
                      timeout: float = 15.0) -> Dict[str, Any]:
    """CVE listesini vulnx ile zenginleştir. GÖRÜNÜR degrade: bakılan/bakılamayan ayrı döner.

    Döner: {enabled, has_key, results:{cve:slim}, checked:[cve], skipped:[{cve,reason}],
            rate_limited:bool, note}. reason ∈ {'cap','rate_limit'}. 'cap' = bu taramada
            bütçe (max_lookups) doldu; 'rate_limit' = dakikalık sınır (ücretsiz key kaldırır)."""
    out: Dict[str, Any] = {
        "enabled": VULNX_ENABLED, "has_key": bool(PDCP_API_KEY),
        "results": {}, "checked": [], "skipped": [], "rate_limited": False, "note": "ok",
    }
    if not VULNX_ENABLED:
        return {**out, "note": "disabled"}

    cves = _normalize(cve_ids)
    if not cves:
        return out

    to_check = cves[:max_lookups]
    for c in cves[max_lookups:]:
        out["skipped"].append({"cve": c, "reason": "cap"})

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            for i, c in enumerate(to_check):
                # 1) Cache (rate maliyeti YOK)
                hit = _cache.get(c)
                if hit and time.time() - hit[0] < _CACHE_TTL:
                    out["results"][c] = hit[1]
                    out["checked"].append(c)
                    continue
                # 2) Kendi throttle'ımız — sunucuya 429 yaptırmadan sınırı koru
                if not _rate_ok():
                    out["rate_limited"] = True
                    for rest in to_check[i:]:
                        if rest not in out["results"]:
                            out["skipped"].append({"cve": rest, "reason": "rate_limit"})
                    break
                _call_times.append(time.time())
                try:
                    data = await _fetch_one(c, client)
                except _RateLimited:
                    out["rate_limited"] = True
                    for rest in to_check[i:]:
                        if rest not in out["results"]:
                            out["skipped"].append({"cve": rest, "reason": "rate_limit"})
                    break
                except Exception:
                    continue  # tek CVE hatası tüm zenginleştirmeyi düşürmesin
                if data:
                    out["results"][c] = data
                    out["checked"].append(c)
    except Exception as e:
        out["note"] = f"error: {e}"
    return out
