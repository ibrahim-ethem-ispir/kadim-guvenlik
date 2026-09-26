"""
Kadim Güvenlik — Payload Corpus Loader (T4-A)
=============================================
SAF çekirdek: offline süzülmüş PATT payload corpus'unu (data/payloads/*.json) okur,
runtime güvenlik kapısından geçirir, verifier inline listeleriyle merge eder.
Kaynak/üretim: scripts/extract_patt_corpus.py (tek seferlik, geliştirici makinesi).

DOKTRİN (CLAUDE.md): corpus YARDIMCIDIR, kritik yol değil. Bayrak kapalı / dosya yok /
bozuk JSON → [] → verifier inline listelerle AYNEN çalışmaya devam eder (sıfır regresyon).
LLM/DB/ağ yok; stdlib-only (path_intel/attack_hypothesis deseni — izole test).

NEDEN runtime'da tekrar filtre: JSON geliştirici makinesinde üretilip repoya girdi —
elle düzenleme/tedarik zinciri riskine karşı loader her girdiyi AYNI kapıdan geçirir:
`adaptive_payloads._payload_ok` (placeholder zorunlu + yıkıcı token reddi — TEK kaynak)
+ bilinmeyen-placeholder süzgeci (verifier'ın doldurmayacağı `{X}` literal kalmasın).

Merge SIRASI: inline ÖNCE (sahada kanıtlanmış çekirdek), corpus SONRA (lehçe/şekil
zenginliği). Tavanlar `_MERGE_CAPS`te — SQLi en sıkı: her payload ~D saniyelik zamanlama
ölçümü, negatif taramada tüm liste denenir → latans bütçesi.
"""
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger("payload-corpus")

# data/payloads/ pipeline paketiyle birlikte dağıtılır (vendored süzülmüş JSON;
# runtime'da dışa hiçbir ağ isteği YOK — kurumsal ağ kısıtı).
_DATA_DIR = Path(__file__).resolve().parent / "data" / "payloads"

# Sınıf → verifier'ın doldurduğu placeholder kümesi (verification.py ile sabit):
# sqli {D}→saniye, xss {MARKER}→nonce, ssti {A}{B}→asal çarpımı, lfi kanarya (yersapı).
# XXE/open_redirect bilinçli YOK: XXE imzalarımızı 3 inline payload zaten kapsıyor,
# PATT türevleri dış-DTD/OOB istiyor (egress); open_redirect'in sentinel listesi sabit.
_PLACEHOLDERS: Dict[str, set] = {
    "sqli": {"{D}"},
    # Madde 3 (T3): error-based SQLi — placeholder YERİNE hata-üretici vektör
    # beyazlistesiyle korunur (adaptive_payloads._payload_ok sqli_error dalı). Kanıt
    # DB hata imzası; tek istek, gecikmesiz → timing hattından çok daha ucuz.
    "sqli_error": set(),
    "xss": {"{MARKER}"},
    "lfi": set(),
    "ssti": {"{A}", "{B}"},
    # AI/LLM red-team corpus (Faz A): şablonlar {MARKER}'ı benzersiz nonce ile doldurur;
    # kanıt oracle'ı marker yansımasıdır (llm_redteam). Gerçek exfil/RCE üretmez.
    "prompt_injection": {"{MARKER}"},
    "indirect_prompt_injection": {"{MARKER}"},
    "system_prompt_leak": {"{MARKER}"},
    "output_handling": {"{MARKER}"},
    "multiturn_jailbreak": {"{MARKER}"},
}

# Doğrulayıcıya gidecek TOPLEM tavan (inline + corpus). xss burada yok: statik XSS
# doğrulayıcı tek-marker ekonomisiyle çalışır; corpus XSS yalnız retry/few-shot'ta.
# Madde 3: sqli_error ek tavanı — error-based oracle tek istek/payload (gecikme yok),
# bu yüzden timing'den (8) geniş; yine de negatif taramada istek patlamasın diye tavanlı.
_MERGE_CAPS: Dict[str, int] = {"sqli": 8, "sqli_error": 12, "lfi": 12, "ssti": 10}
_RETRY_CAP_DEFAULT = 8


def _cap_for(klass: str, inline_len: int) -> int:
    """Sınıf tavanı — env ile operatör ayarı (Madde 3.4): PAYLOAD_CORPUS_CAP_<SINIF>
    (ör. PAYLOAD_CORPUS_CAP_SQLI=16). Bozuk/eksik env → varsayım tavan. Tavan asla
    inline uzunluğunun altına inmez (inline çekirdek hiçbir koşulda kırpılmaz)."""
    cap = _MERGE_CAPS.get(klass, inline_len + 6)
    raw = os.getenv(f"PAYLOAD_CORPUS_CAP_{klass.upper()}", "").strip()
    if raw:
        try:
            v = int(raw)
            if v > 0:
                cap = v
        except ValueError:
            pass
    return max(cap, inline_len)

_cache: Dict[str, List[str]] = {}


def _flag_on() -> bool:
    # Env her çağrıda okunur (test/operatör bayrak değişimi süreç restart'ı istemez).
    return os.getenv("PAYLOAD_CORPUS", "1").strip().lower() in ("1", "true")


def _key(payload: str) -> str:
    """Dedup anahtarı: whitespace+case nötr — inline ile aynı payload'un biçim
    farkıyla iki kez denenmesin (dokunuş bütçesi)."""
    return re.sub(r"\s+", " ", payload).strip().lower()


def load_class(klass: str) -> List[str]:
    """Sınıfın corpus payload'ları (kapıdan geçmiş, sıralı, tekilleşmiş). HER hata → []."""
    if not _flag_on() or klass not in _PLACEHOLDERS:
        return []
    if klass in _cache:
        return _cache[klass]
    out: List[str] = []
    try:
        path = _DATA_DIR / f"{klass}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data.get("entries") if isinstance(data, dict) else None
        if isinstance(entries, list):
            # Geç import: adaptive_payloads'a modül-düzey bağımlılık yok (döngü riski sıfır).
            from .adaptive_payloads import _payload_ok
            allowed = _PLACEHOLDERS[klass]
            seen = set()
            for e in entries:
                p = e.get("payload") if isinstance(e, dict) else e
                if not isinstance(p, str):
                    continue
                p = p.strip()
                found = set(re.findall(r"\{[A-Za-z_]+\}", p))
                if found - allowed:                # doldurulmayacak placeholder → düş
                    continue
                if not _payload_ok(p, klass):      # tek kaynak kapı (LLM hattıyla birebir)
                    continue
                k = _key(p)
                if k in seen:
                    continue
                seen.add(k)
                out.append(p)
    except FileNotFoundError:
        out = []
    except Exception as e:  # bozuk JSON/eksik alan → sessiz inline fallback
        logger.warning(f"PayloadCorpus: '{klass}' okunamadı — inline fallback: {e}")
        out = []
    _cache[klass] = out
    return out


def merge_with_inline(klass: str, inline: List[str]) -> List[str]:
    """Inline listeyi corpus ile genişlet (inline önce), `_MERGE_CAPS` tavanıyla.
    Bayrak kapalı / veri yok → inline kopyası: mevcut davranış birebir korunur."""
    base = list(inline)
    payloads = load_class(klass)
    if not payloads:
        return base
    cap = _cap_for(klass, len(base))
    seen = {_key(p) for p in base}
    for p in payloads:
        if len(base) >= cap:
            break
        k = _key(p)
        if k in seen:
            continue
        seen.add(k)
        base.append(p)
    return base


def retry_payloads(klass: str, cap: int = 0) -> List[str]:
    """_adaptive_reverify'in LLM-boş fallback'i (madde 1'in XSS tüketici hattı):
    offline corpus, deterministik imza ile test edilir. Tavan: PAYLOAD_CORPUS_RETRY_MAX."""
    c = cap or int(os.getenv("PAYLOAD_CORPUS_RETRY_MAX", str(_RETRY_CAP_DEFAULT)))
    return load_class(klass)[:max(0, c)]


def examples_for(klass: str, n: int = 5) -> List[str]:
    """LLM few-shot bağlamı (madde 2): sınıfın bilinen şekilleri prompt'a 'denenmiş
    format kütüphanesi' olarak girer — LLM kopyalamasın, bağlama uyarlasın."""
    return load_class(klass)[:max(0, n)]
