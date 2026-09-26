"""
Kadim Güvenlik — Adaptif Payload Zanaatı (T3-A: LLM payload-üreten pentester)
=============================================================================
Türkçe: "Tarayıcı"yı gerçek "pentester"a çeviren katman. Statik payload listeleri +
deterministik WAF-mutasyonları BAŞARISIZ olduğunda ama endpoint enjekte-edilebilir
göründüğünde (parametre dinamik, WAF blokluyor, yansıma var), LLM CANLI YANITI OKUR ve
hedefe/WAF'a/framework'e ÖZGÜ payload'lar zanaatlar. İnsan pentester'ın yaptığı budur:
bloklanınca vazgeçmez, bağlamı okuyup bir sonraki denemeyi uyarlar.

KRİTİK DOKTRİN (CLAUDE.md): **LLM ZANAATLAR, DETERMİNİSTİK ÇEKİRDEK ONAYLAR.**
LLM asla "bu bir zafiyet" demez — yalnız DENENECEK payload ÖNERİR. Onların işe yarayıp
yaramadığına mevcut deterministik imzalar (SLEEP zamanlaması, marker yansıması, dosya
imzası, aritmetik değerlendirme) karar verir. LLM erişilemezse → boş liste → statik
payload'lar zaten denendi, tarama bozulmadan sürer (sıfır regresyon).

GÜVENLİK (tahribatsızlık payload YAPISIYLA garanti): her payload sınıfın PLACEHOLDER'ını
taşımak ZORUNDA ({D}=SLEEP gecikmesi / {MARKER}=XSS nonce / {A}*{B}=SSTI aritmetiği) ya da
bilinen zararsız kanaryayı (LFI: passwd/win.ini/php-filter) içermek zorunda. Bu, LLM'in
üretebileceği payload'u yapısal olarak "oku/zamanla/yansıt" ile sınırlar; yıkıcı token'lar
(DROP/DELETE/OUTFILE/xp_cmdshell/rm/shutdown...) ayrıca kara-listeyle reddedilir.

Tasarım (path_intel.py K2 deseniyle birebir): prompt/context SAF; `llm_call` enjekte
edilebilir (test); default ai-service `/analyze` (analysis_type='adaptive_payloads',
use_default=True → provider routing + thinking-KAPALI orada). Sanitize/clamp BURADA
(savunma derinliği: ai-service'e de güvenmeyiz).
"""
import json
import logging
import os
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("adaptive-payloads")

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8009")

# Adaptif payload üretilebilen sınıflar (deterministik imzası olanlar).
ADAPTIVE_CLASSES = frozenset({"sqli", "xss", "lfi", "ssti"})

# Yıkıcı/egress token kara-listesi — placeholder zorunluluğuna EK savunma derinliği.
_DESTRUCTIVE_RE = re.compile(
    r"drop\s+table|delete\s+from|truncate\s+table|insert\s+into|update\s+\w+\s+set|"
    r"into\s+outfile|into\s+dumpfile|xp_cmdshell|sp_executesql|exec\s*\(|"
    r"rm\s+-rf|mkfs|:\(\)\{|shutdown|reboot|nc\s+-|/bin/sh|/bin/bash|"
    r"wget\s|curl\s|certutil|powershell|bitsadmin", re.I)

_MAX_PAYLOAD_LEN = 400

# Madde 3 (T3): error-based SQLi — zamanlama YERİNE DB hata imzası kanıtlar. Placeholder
# yok; yapısal güvence LEHÇE-BEYAZLİSTESİ: yalnız bilinen hata-üretici vektörler
# (XPATH/duplicate/conversion/quote-break). Hepsi SELECT-bağlamı — yıkıcı regex üstte
# zaten uygulanıyor. Beyazliste dışı (ör. "COPY TO", "pg_sleep" dışı rastgele SQL) düşer.
_SQLI_ERROR_TRIGGERS = (
    "extractvalue", "updatexml", "floor(rand", "convert(int", "convert(varchar",
    "cast(@@", "cast(1 as", "geometrycollection", "multipoint(", "polygon(",
    "name_const(", "utl_inaddr", "ctxsys.", "dbms_xmlgen", "to_number(",
    "exp(~", "gp_ndls", "1=cast", "1=convert", "1=to_number",
)
# Tırnak-kırıcılar: tek başlarına sentaks hatası üreten minimal şekiller — yapısal
# olarak salt "boz" kanıtı, veri değiştirmezler. TAM eşleşme (içermedeğil).
_Q, _DQ, _BT = "\x27", "\x22", "\x60"
_SQLI_ERROR_QUOTES = frozenset({
    _Q, _DQ, _BT, "%" + _Q, "%27", "%22", "1" + _Q, "1" + _DQ,
    ")" + _Q, ")" + _DQ, _Q + ")", _DQ + ")",
    ")" + _Q + "-- -", _Q + "-- -", _DQ + "-- -",
})

# LFI kanaryaları (Madde 3 genişletme): salt-okur, imzası BİLİNEN hedefler.
# expect://, data://, zip:// BİLİNÇLİ YOK — php wrapper'ı üzerinden kod çalıştırma
# (RCE) sınıfı; platform doktrini "oku/zamanla/yansıt" — tahribatsızlık bozulur.
# Kaynak ifşası kanıtı zaten php://filter base64 ile kritik severite'de alınıyor.
_LFI_CANARIES = (
    "passwd", "win.ini", "boot.ini", "php://filter",
    "proc/self", "access.log", "access_log",
)


def _payload_ok(payload: str, vuln_class: str) -> bool:
    """Tek payload korkuluğu (SAF). Sınıfın placeholder'ı/kanaryası ŞART + yıkıcı token yok.
    Böylece LLM payload'u yapısal olarak tahribatsız (oku/zamanla/yansıt) kalır."""
    if not isinstance(payload, str):
        return False
    p = payload.strip()
    if not p or len(p) > _MAX_PAYLOAD_LEN:
        return False
    if _DESTRUCTIVE_RE.search(p):
        return False
    low = p.lower()
    # Placeholder'lar TAM-BÜYÜK/KÜÇÜK harf eşleşmeli (verify_adaptive aynen bunları
    # doldurur; küçük harfli varyant kabul edilirse doldurulmaz → sessiz kaçırma).
    if vuln_class == "sqli":
        # Zamanlama şablonu olmalı: {D} gecikme placeholder'ı (→ yapısal olarak SLEEP-tabanlı,
        # veri değiştirmez). Ek olarak bir uyku fonksiyonu geçmeli. "receive_message":
        # Oracle'un zamanlama lehçesi — DBMS_PIPE.RECEIVE_MESSAGE('a',{D}) (corpus dialect).
        return "{D}" in p and any(s in low for s in
                                  ("sleep", "pg_sleep", "waitfor", "benchmark", "receive_message"))
    if vuln_class == "sqli_error":
        # Madde 3: hata-üretici vektör beyazlistesi VEYA tırnak-kırıcı (tam eşleşme).
        return any(t in low for t in _SQLI_ERROR_TRIGGERS) or p in _SQLI_ERROR_QUOTES
    if vuln_class == "xss":
        return "{MARKER}" in p
    if vuln_class == "ssti":
        return "{A}" in p and "{B}" in p
    if vuln_class == "lfi":
        # Yalnız bilinen zararsız kanaryalar (rastgele hassas dosya okumaya izin verme).
        return any(k in low for k in _LFI_CANARIES)
    if vuln_class in ("prompt_injection", "indirect_prompt_injection", "system_prompt_leak",
                      "output_handling", "multiturn_jailbreak"):
        # AI/LLM red-team corpus şablonları: benzersiz MARKER zorunlu (deterministik oracle).
        # Yıkıcı token kapısı (_DESTRUCTIVE_RE) yukarıda zaten uygulandı → gerçek exfil/RCE yok.
        return "{MARKER}" in p
    return False


def sanitize_payloads(raw: Any, vuln_class: str, *, cap: int = 10) -> List[str]:
    """Güvenilmez LLM çıktısını güvenli payload listesine indir (SAF). Korkuluğu geçmeyen
    elenir; dedup + üst sınır. path_intel._sanitize_candidate ile aynı savunma felsefesi."""
    if vuln_class not in ADAPTIVE_CLASSES:
        return []
    items = _coerce_list(raw)
    out: List[str] = []
    seen = set()
    for it in items:
        p = it if isinstance(it, str) else (it.get("payload") if isinstance(it, dict) else None)
        if not isinstance(p, str):
            continue
        p = p.strip()
        if p in seen or not _payload_ok(p, vuln_class):
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= cap:
            break
    return out


def _coerce_list(raw: Any) -> List[Any]:
    """llm_call çıktısını listeye indir: liste | {'suggested_payloads':[...]} | JSON string
    (path_intel._coerce_list ile aynı desen)."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("suggested_payloads", "payloads"):
            v = raw.get(key)
            if isinstance(v, list):
                return v
        return []
    if isinstance(raw, str):
        s = raw.strip()
        m = re.search(r"\[.*\]", s, re.S)
        if m:
            try:
                parsed = json.loads(m.group(0))
                return parsed if isinstance(parsed, list) else []
            except Exception:
                return []
        try:
            return _coerce_list(json.loads(s))
        except Exception:
            return []
    return []


def build_probe_context(*, vuln_class: str, url: str, param: Optional[str],
                        method: str = "get",
                        baseline: str = "", blocked: str = "",
                        status_baseline: Optional[int] = None,
                        status_blocked: Optional[int] = None,
                        waf: Optional[str] = None,
                        framework: Optional[str] = None,
                        reflected_context: Optional[str] = None,
                        corpus_examples: Optional[List[str]] = None) -> Dict[str, Any]:
    """LLM'e verilecek kompakt prob bağlamını kur (SAF). Gövde snippet'leri kırpılır
    (prompt bütçesi + sır sızdırmama). Yalnız zanaat için gereken sinyaller.
    T4-A `corpus_examples`: offline corpus'un BİLİNEN şekilleri — SONA eklenir (ai-service
    prompt'u context JSON'u ~4KB'ta kırpar; snippet'ler kırpılmadan kalsın diye örnekler
    en sona), kısa kırpma + adet tavanı ile bütçe korunur."""
    def _clip(s: Any, n: int) -> str:
        return (str(s or ""))[:n]
    ctx: Dict[str, Any] = {
        "vuln_class": vuln_class,
        "url": _clip(url, 500),
        "param": param,
        "method": (method or "get").lower(),
        "waf": _clip(waf, 80) or None,
        "framework": _clip(framework, 120) or None,
        "status_baseline": status_baseline,
        "status_blocked": status_blocked,
        "baseline_snippet": _clip(baseline, 1200),
        "blocked_snippet": _clip(blocked, 1200),
        "reflected_context": _clip(reflected_context, 400) or None,
    }
    if corpus_examples:
        ctx["corpus_examples"] = [_clip(x, 140) for x in list(corpus_examples)[:6]]
    return ctx


async def _default_llm_call(context: Dict[str, Any]) -> Any:
    """Varsayılan sağlayıcı çağrısı: ai-service'e context yolla, payload listesi al.
    Prompt + provider routing + thinking-KAPALI ai-service'te (analysis_type='adaptive_payloads').
    Hata YUKARI FIRLAR → craft_payloads bunu [] fallback'e çevirir (statik payload'lar yeter)."""
    import httpx
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{AI_SERVICE_URL}/analyze",
            json={
                "scan_data": {"adaptive_payload_context": context},
                "provider": "ollama",   # use_default=True → DB/.env varsayılanını çözer
                "model": "",
                "analysis_type": "adaptive_payloads",
                "use_default": True,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    if isinstance(data, dict) and "suggested_payloads" in data:
        return data["suggested_payloads"]
    if isinstance(data, dict):
        return data.get("analysis") or data.get("raw") or []
    return data


async def craft_payloads(context: Dict[str, Any], *,
                         llm_call: Optional[Callable[[Dict[str, Any]], Awaitable[Any]]] = None,
                         cap: int = 10) -> List[str]:
    """Prob bağlamından adaptif payload üret (sanitize edilmiş liste). llm_call enjekte
    edilebilir (test); None ise ai-service. HER hata → [] (statik/mutasyon hattı fallback).
    Çıktı doğrudan verify_adaptive(payloads=...) beslenir — deterministik imza ONAYLAR."""
    vuln_class = str(context.get("vuln_class") or "")
    if vuln_class not in ADAPTIVE_CLASSES:
        return []
    try:
        caller = llm_call or _default_llm_call
        raw = await caller(context)
        payloads = sanitize_payloads(raw, vuln_class, cap=cap)
        if payloads:
            logger.info(f"AdaptivePayloads: {len(payloads)} LLM payload'u (sanitize sonrası) "
                        f"kabul edildi — sınıf={vuln_class}")
        return payloads
    except Exception as e:
        logger.warning(f"AdaptivePayloads LLM önerisi alınamadı — statik fallback: {e}")
        return []
