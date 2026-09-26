"""
Kadim Güvenlik — WordPress admin-ajax SQL Injection ORACLE (aktif kanıt)
=======================================================================
Türkçe: Güncel CVE deseninin MANŞETİ — WordPress plugin SQLi'lerinin ezici çoğunluğu
admin-ajax.php `action` handler'larının parametrelerinde. Klasik motor bunları nuclei
template'i YAYIMLANANA kadar göremez. Bu modül WP'yi "keşif prober"dan "SQLi ORACLE"a çıkarır:
action'ları hasat eder, aday enjeksiyon noktaları üretir ve KANITI motorun MEVCUT time-based
blind doğrulayıcısına (verification.verify_time_based_sqli) yaptırır → deterministik confirmed
(SLEEP enjeksiyonu yanıt süresine tutarlı yansırsa). Yeni bir enjeksiyon motoru İCAT ETMEZ —
kanıtlı çekirdeği yeniden kullanır.

AKTİF ENJEKSİYON (motorun ilk tahribat-sınırı katmanı): SLEEP-tabanlı, SALT-OKUNUR (veri
değiştirmez, yalnız sorgu süresini uzatır) ama SQL ÇALIŞTIRIR. Bu yüzden ÇOK KAPILI: pipeline
tarafında WP_SQLI_ORACLE kill-switch + recon'da çalışmaz + WP-gated (playbook wp_probe) + sıkı
cap/pacing. Doktrin: TEK kanıt yeter (ilk confirmed'de dur) → gereksiz aktif trafik yok.

Tasarım (path_probe/wp_probe deseni): harvest/build çekirdeği SAF (regex, I/O yok → izole test);
run_wp_sqli_oracle ince I/O (kendi kök+JS fetch'i + verify delegasyonu). ASLA raise etmez.

KRİTİK MEKANİK — enjekte parametre query'de ÖNE, action SONA: verify_time_based_sqli URL'nin
HER parametresine enjekte eder ve confirm TÜM gecikmeli örneklerin yansımasını ister; action'a
enjeksiyon (yansımaz) teyidi zehirlerdi. Hedef param'ı öne alınca oracle onu ÖNCE dener ve
erken-teyit action denenmeden döner → izole tek-hipotez testi.
"""

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger("wp-sqli-oracle")

# ============================================================
# SAF çekirdek — hasat & aday üretimi (I/O yok, izole test)
# ============================================================

# action adı: "action":"x" / 'action':'x' / action: 'x' / action=x / wp.ajax.post('x'
_ACTION_PATTERNS = [
    re.compile(r"""['"]?action['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{2,64})['"]"""),
    re.compile(r"""[?&]action=([a-zA-Z0-9_\-]{2,64})"""),
    re.compile(r"""wp\.ajax\.(?:post|send)\(\s*['"]([a-zA-Z0-9_\-]{2,64})['"]"""),
]
# JS data objesindeki id-benzeri anahtar (custom camelCase dahil): "postId": / 'user_id':
_PARAM_HINT = re.compile(r"""['"]([a-zA-Z][a-zA-Z0-9_]{0,30}[iI][dD])['"]\s*:""")
# <script src="...js"> — action'lar çoğu zaman enqueue edilen JS'te yaşar
_JS_SRC = re.compile(r"""<script[^>]+\bsrc=['"]([^'"]+?\.js(?:\?[^'"]*)?)['"]""", re.I)

# En sık enjekte edilen WP AJAX parametreleri (öncelik sırası). Curated, genişletilebilir.
CURATED_PARAMS: List[str] = [
    "id", "post_id", "user_id", "term_id", "order_id", "product_id", "page_id",
    "item_id", "cat", "cat_id", "parent_id", "p", "pid", "uid", "q", "s", "keyword",
]

# WP çekirdek / gürültü action'ları — enjekte etme (kanıt üretmez, boşa aktif trafik).
_SKIP_ACTIONS = {
    "heartbeat", "wp-check-locked-posts", "wp-refresh-post-lock", "dismiss-wp-pointer",
    "query-attachments", "queryattachments", "get-comments", "wp-remove-post-lock",
    "sample-permalink", "closed-postboxes", "meta-box-order", "logged-in",
}


def harvest_actions(text: str) -> List[str]:
    """HTML/JS'ten admin-ajax action adlarını çıkar (SAF). Gürültü/çekirdek action'ları eler,
    sıra korunarak dedup eder."""
    out: List[str] = []
    if not text:
        return out
    sample = text[:400000]
    for pat in _ACTION_PATTERNS:
        for m in pat.findall(sample):
            a = m.strip().lower()
            if a and a not in _SKIP_ACTIONS:
                out.append(a)
    return list(dict.fromkeys(out))


def harvest_param_hints(text: str) -> List[str]:
    """JS data objelerinden id-benzeri parametre adlarını çıkar (SAF). Custom handler'ların
    (curated listede olmayan) gerçek parametrelerini yakalar → daha isabetli enjeksiyon."""
    if not text:
        return []
    out: List[str] = []
    for m in _PARAM_HINT.findall(text[:400000]):
        out.append(m.strip())
    return list(dict.fromkeys(out))


def harvest_js_urls(html: str, base: str) -> List[str]:
    """Kök HTML'deki <script src> .js URL'lerini MUTLAK ve AYNI-HOST olarak çıkar (SAF).
    action'lar genelde JS'te olduğundan enqueue edilen betikler taranmaya değer."""
    if not html:
        return []
    try:
        host = urlsplit(base).netloc
    except Exception:
        host = ""
    out: List[str] = []
    for src in _JS_SRC.findall(html[:400000]):
        try:
            absu = urljoin(base + "/", src)
        except Exception:
            continue
        if urlsplit(absu).netloc == host and absu.lower().split("?")[0].endswith(".js"):
            out.append(absu)
    return list(dict.fromkeys(out))


def build_ajax_candidates(base: str, actions: List[str], params: List[str], *,
                          max_candidates: int = 6) -> List[Dict[str, str]]:
    """(action × param) aday enjeksiyon noktaları üret (SAF). Param DIŞTA (en olası id'ler
    önce, tüm action'lara yayılır), action İÇTE. URL'de enjekte param ÖNDE, action SONDA
    (erken-teyit mekaniği — bkz. modül başlığı). Döner [{action,param,url}], cap'li."""
    ajax = f"{base.rstrip('/')}/wp-admin/admin-ajax.php"
    param_list = [p for p in dict.fromkeys(params) if p]
    acts = [a for a in dict.fromkeys(actions) if a]
    out: List[Dict[str, str]] = []
    seen = set()
    for p in param_list:
        for a in acts:
            key = (a, p)
            if key in seen:
                continue
            seen.add(key)
            out.append({"action": a, "param": p, "url": f"{ajax}?{p}=1&action={a}"})
            if len(out) >= max_candidates:
                return out
    return out


# ============================================================
# I/O — AKTİF enjeksiyon (verify delegasyonu), best-effort
# ============================================================

async def _get_text(client, url: str, *, follow: bool = False) -> Optional[str]:
    """Tek GET → gövde metni (ilk 300KB). Hata/5xx → None."""
    try:
        r = await client.get(url, timeout=12.0, follow_redirects=follow)
        if getattr(r, "status_code", 200) >= 500:
            return None
        return (r.text or "")[:300000]
    except Exception:
        return None


async def _resolve(client, host: str) -> Optional[Tuple[str, str]]:
    """Kök URL + gövdesini bul (wp_probe._resolve_base yeniden kullanılır → tek doğruluk
    kaynağı, https→http fallback). Döner (base, body)."""
    try:
        from .wp_probe import _resolve_base
    except Exception:
        return None
    resolved = await _resolve_base(client, host)
    if not resolved:
        return None
    base, body = resolved[0], resolved[1]
    return (base, body)


async def run_wp_sqli_oracle(host: str, client, *, max_candidates: int = 6,
                             delay_seconds: float = 4.0, control_samples: int = 2,
                             max_js: int = 3) -> List[Dict[str, Any]]:
    """admin-ajax SQLi'yi AKTİF kanıtla → confirmed bulgu listesi (0 veya 1). ASLA raise etmez.
    Kök+JS'ten action/param hasat eder, aday üretir, her adayı verify_time_based_sqli'ya verir;
    İLK confirmed'de durur (gereksiz aktif trafik yok)."""
    findings: List[Dict[str, Any]] = []
    resolved = await _resolve(client, host)
    if not resolved:
        return findings
    base, body = resolved

    actions = harvest_actions(body)
    hints = harvest_param_hints(body)
    for js in harvest_js_urls(body, base)[:max_js]:
        t = await _get_text(client, js)
        if t:
            actions += harvest_actions(t)
            hints += harvest_param_hints(t)
    actions = list(dict.fromkeys(actions))[:8]
    if not actions:
        logger.debug(f"WP SQLi oracle: action bulunamadı — {base}")
        return findings

    # Öncelik: en olası curated id'ler + hasat edilen custom id'ler.
    params = list(dict.fromkeys(list(CURATED_PARAMS[:8]) + hints))
    candidates = build_ajax_candidates(base, actions, params, max_candidates=max_candidates)
    if not candidates:
        return findings

    try:
        # Madde 3: zincir orakl (error → boolean → time) — WP plugin'lerin hata sayfaları
        # error-based sızıntıya çok açık; ucuz orakllar önce, SLEEP en son (pacing aynı).
        from .verification import verify_sqli
    except Exception:
        return findings

    for i, c in enumerate(candidates):
        if i:
            await asyncio.sleep(0.2)  # pacing — aktif enjeksiyon salvosunu yumuşat
        try:
            v = await verify_sqli(
                c["url"], client, delay_seconds=delay_seconds,
                control_samples=control_samples, method="get")
        except Exception as e:
            logger.debug(f"WP SQLi verify hata ({c['url']}): {e}")
            continue
        if getattr(v, "verified", False):
            findings.append({
                "title": f"WordPress AJAX SQL Injection (action={c['action']}, param={c['param']}) @ {base}",
                "severity": "critical",
                "target": c["url"],
                "proof": (f"{v.detail} admin-ajax action '{c['action']}', enjekte edilen parametre "
                          f"'{c['param']}' (GET). Auth'suz erişilebilir handler → veritabanı okuma. "
                          f"Zaman-tabanlı blind kanıt (SLEEP yansıması)."
                          + (f" [WAF-mutasyonu: {v.mutation}]" if getattr(v, 'mutation', None) else "")),
                "confidence_tier": "confirmed",
                "cwe": ["CWE-89"], "mitre": "T1190",
                "verification_method": getattr(v, "method", "time-based-blind-sqli"),
                "verification_confidence": getattr(v, "confidence", None),
                "action": c["action"], "param": c["param"],
            })
            logger.info(f"💉 WP SQLi ORACLE: KANITLI SQLi action={c['action']} param={c['param']} @ {base}")
            break  # tek kanıt yeter — aktif trafiği durdur
    return findings
