"""
Kadim Güvenlik — PathProbe LLM İstihbarat Subayı (K2)
=====================================================
Türkçe: PathProbe'un "sezgi" katmanı. LLM hedefin PARMAK İZİNİ görür (server/tech/sürüm/
gözlenen yollar) ve YÜKSEK OLASILIKLI ek hassas yol + BEKLENEN İÇERİK İMZASI önerir.

Kritik felsefe (CLAUDE.md): LLM opsiyonel sezgi katmanıdır, KRİTİK YOL DEĞİL. Bu modül yalnız
ADAY üretir; yargı deterministik validator'da kalır (path_probe `_validate_from_signature`).
LLM güvenilmez kabul edilir → her öneri korkuluklardan geçer:
  - path sanitize: '^/...' + '://' yok → HER ZAMAN aynı host (farklı hedefe sızmaz)
  - category/severity enum'a CLAMP (LLM çöp üretemez)
  - imzasız aday REDDEDİLİR (deterministik doğrulanamayan öneri bulguya dönüşemez)
  - üst sınır + dedup
Sağlayıcı erişilemezse boş liste → PathProbe K0+K1 ile bozulmadan çalışır.

Sağlayıcı ROUTING'i ai-service'tedir (CLAUDE.md): bu modül ai-service'e fingerprint yollar,
`suggested_paths` alır; prompt + thinking-KAPALI + provider seçimi orada yapılır. Sanitize/clamp
burada (savunma derinliği: ai-service'e de güvenmeyiz).
"""
import json
import logging
import os
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("path-intel")

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8009")

# Kategori enum — LLM önerisi bunlardan birine clamp edilir (path_probe _CATEGORY_MITRE ile hizalı).
_ALLOWED_CATEGORIES = frozenset({
    "env_exposure", "credential_exposure", "vcs_exposure", "backup_exposure", "db_dump",
    "config_exposure", "log_exposure", "debug_exposure", "admin_panel", "info_disclosure",
})
_ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

# Path korkuluğu: '/' ile başlar, yalnız güvenli karakterler, şema/host yok → aynı host garantisi.
_SAFE_PATH_RE = re.compile(r"^/[\w\-./~%]+$")
_MAX_PATH_LEN = 256


def _clamp_signature(sig: Any) -> Optional[Dict[str, Any]]:
    """LLM imzasını normalize et. Geçerli sayılması için EN AZ bir doğrulama kısıtı şart
    (must_contain_any/all veya min_length) — aksi halde None (deterministik doğrulanamaz)."""
    if not isinstance(sig, dict):
        return None
    def _strlist(v):
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list):
            return []
        return [str(x)[:200] for x in v if isinstance(x, (str, int, float)) and str(x)][:20]
    out: Dict[str, Any] = {}
    ma = _strlist(sig.get("must_contain_any"))
    al = _strlist(sig.get("must_contain_all"))
    mn = _strlist(sig.get("must_not_contain"))
    if ma:
        out["must_contain_any"] = ma
    if al:
        out["must_contain_all"] = al
    if mn:
        out["must_not_contain"] = mn
    try:
        min_len = int(sig.get("min_length", 0) or 0)
    except (TypeError, ValueError):
        min_len = 0
    if min_len > 0:
        out["min_length"] = min(min_len, 100000)
    # En az bir POZİTİF kısıt (any/all/min_length) olmalı; sadece must_not_contain yetmez.
    if not (out.get("must_contain_any") or out.get("must_contain_all") or out.get("min_length")):
        return None
    return out


def _sanitize_candidate(raw: Any) -> Optional[Tuple[str, str, str, str, Dict[str, Any]]]:
    """Güvenilmez LLM adayını güvenli 5-tuple'a indir; korkuluğu geçemeyen None döner.
    Dönüş: (path, category, severity, 'signature', {'signature': {...}, 'source': 'llm'})."""
    if not isinstance(raw, dict):
        return None
    path = str(raw.get("path", "")).strip()
    if not path or len(path) > _MAX_PATH_LEN:
        return None
    if "://" in path or path.startswith("//"):
        return None  # cross-host / protokol-relatif → RED (aynı host garantisi)
    if not _SAFE_PATH_RE.match(path):
        return None
    sig = _clamp_signature(raw.get("signature"))
    if sig is None:
        return None  # imzasız öneri → RED (deterministik doğrulanamaz)
    category = str(raw.get("category", "")).strip().lower()
    if category not in _ALLOWED_CATEGORIES:
        category = "info_disclosure"
    severity = str(raw.get("severity", "")).strip().lower()
    if severity not in _ALLOWED_SEVERITIES:
        severity = "medium"
    return (path, category, severity, "signature", {"signature": sig, "source": "llm"})


def _coerce_list(raw: Any) -> List[Any]:
    """llm_call çıktısını aday listesine indir: liste | {'suggested_paths': [...]} | JSON string."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        sp = raw.get("suggested_paths")
        return sp if isinstance(sp, list) else []
    if isinstance(raw, str):
        s = raw.strip()
        # Metin içinden ilk JSON dizisini/objesini ayıkla (LLM bazen düz metin sarar)
        m = re.search(r"\[.*\]", s, re.S)
        if m:
            try:
                parsed = json.loads(m.group(0))
                return parsed if isinstance(parsed, list) else []
            except Exception:
                return []
        try:
            parsed = json.loads(s)
            return _coerce_list(parsed)
        except Exception:
            return []
    return []


async def _default_llm_call(fingerprint: Dict[str, Any]) -> Any:
    """Varsayılan sağlayıcı çağrısı: ai-service'e fingerprint yolla, `suggested_paths` al.
    Prompt + provider routing + thinking-KAPALI ai-service tarafında (analysis_type='path_intel').
    Herhangi bir hata YUKARI FIRLAR → suggest_paths_llm bunu [] fallback'e çevirir."""
    import httpx
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{AI_SERVICE_URL}/analyze",
            json={
                "scan_data": {"path_intel_fingerprint": fingerprint},
                "provider": "ollama",   # use_default=True → DB/.env varsayılanını çözer
                "model": "",
                "analysis_type": "path_intel",
                "use_default": True,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    # ai-service ya {'suggested_paths': [...]} ya da analiz metni döner — ikisini de dene.
    if isinstance(data, dict) and "suggested_paths" in data:
        return data["suggested_paths"]
    if isinstance(data, dict):
        return data.get("analysis") or data.get("raw") or []
    return data


async def suggest_paths_llm(
    fingerprint: Dict[str, Any],
    *,
    llm_call: Optional[Callable[[Dict[str, Any]], Awaitable[Any]]] = None,
    cap: int = 30,
) -> List[Tuple[str, str, str, str, Dict[str, Any]]]:
    """Parmak izinden ek hassas yol önerileri üret (sanitize edilmiş 5-tuple listesi).
    llm_call enjekte edilebilir (test); None ise ai-service çağrılır. HER hata → [] (K1 fallback).
    Üst sınır + dedup uygulanır. Çıktı doğrudan probe_sensitive_paths(extra_paths=...) beslenir."""
    try:
        caller = llm_call or _default_llm_call
        raw = await caller(fingerprint)
        candidates = _coerce_list(raw)
        out: List[Tuple[str, str, str, str, Dict[str, Any]]] = []
        seen = set()
        for c in candidates:
            row = _sanitize_candidate(c)
            if row is None or row[0] in seen:
                continue
            seen.add(row[0])
            out.append(row)
            if len(out) >= cap:
                break
        if out:
            logger.info(f"PathIntel: {len(out)} LLM yol önerisi (sanitize sonrası) kabul edildi.")
        return out
    except Exception as e:
        logger.warning(f"PathIntel LLM önerisi alınamadı — K1 fallback: {e}")
        return []
