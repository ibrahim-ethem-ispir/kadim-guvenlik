"""
Kadim Güvenlik — Kimlik Öğrenme Döngüsü (Tier 4: kendini büyüten hızlı-yol)
==========================================================================
Türkçe: Kimlik çözümleyicinin son katmanı — "sistem kendi trafiğinden öğrenir, sen değil".
Bir hedef CPE (Tier 2) ya da LLM (Tier 3) ile tanındığında, o hedefin AYIRT EDİCİ web
sinyallerini (ürün-taşıyan header/çerez/başlık) → ürün+boyut eşlemesi olarak `identity_memory`
koleksiyonuna yazarız. Sonraki taramada AYNI sinyali gören motor, LLM'e SORMADAN ürünü tanır
(hızlı-yol büyür; niş "Spective" bir kez öğrenilince ücretsiz). path_memory (K3) deseninin
kimliğe genişletilmesi — MongoClient süreç-singleton'dur (çağıran koleksiyonu verir → fake db
ile test edilir), her DB hatası sessizce yutulur (motor bozulmaz).

KİRLENME KORKULUKLARI (kritik):
  • Yalnız AYIRT EDİCİ sinyal öğrenilir: jenerik `server:nginx` / `phpsessid` anahtar YAPILMAZ.
  • Bir sinyal >1 FARKLI ürüne eşlenirse `ambiguous` işaretlenir → recall'da ASLA uygulanmaz.
  • LLM kaynaklı öğrenme recall için ≥2 korroborasyon ister (tek-atış halüsinasyon uygulanmaz);
    CPE (otoriter) 1 gözlemde güvenilir. Ağırlık tavanı 0.78 < taze CPE (0.8) → canlı otoriter baskın.
"""

import hashlib
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("identity-memory")

# Kimlik-taşıyan header adları (değeri ayırt ediciyse öğrenilir).
_IDENTITY_HEADERS = {"server", "x-powered-by", "x-generator", "x-runtime",
                     "x-aspnet-version", "x-drupal-cache", "x-turbo-charged-by"}
# Tek başına ürün DEĞİL (jenerik sunucu/CDN) → değerde sürüm yoksa anahtar yapma.
_GENERIC_HEADER_VALUES = {"nginx", "apache", "cloudflare", "microsoft-iis", "iis",
                          "caddy", "openresty", "litespeed", "gws", "cloudfront",
                          "amazons3", "akamaighost", "envoy", "istio-envoy"}
_GENERIC_COOKIES = {"phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
                    "sessionid", "csrftoken", "xsrf-token", "_ga", "cf_bm", "__cf_bm",
                    "cf_clearance", "aws-waf-token"}

# Öğrenilen/recall edilen kimlik boyutları (target_profile boyutlarıyla birebir).
_IDENTITY_DIMS = ("os", "server", "framework", "language", "waf")

_MIN_LLM_CONFIRM = 2      # LLM kaynaklı öğrenme recall için gereken korroborasyon
_BASE_WEIGHT = {"cpe": 0.7, "llm": 0.6}
_WEIGHT_CAP = 0.78        # taze CPE (0.8) altında kalsın → canlı otoriter baskın


def _norm(s: Any) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower())[:160]


def _key(sig_type: str, sig_value: str) -> str:
    return hashlib.sha1(f"{sig_type}:{sig_value}".encode("utf-8", "replace")).hexdigest()


def _distinctive_header_value(value: str) -> bool:
    """Header değeri ürünü AYIRT EDİYOR mu? Sadece jenerik sunucu adı (sürümsüz) → hayır."""
    v = _norm(value)
    if not v:
        return False
    base = re.split(r"[/ ]", v)[0]
    if base in _GENERIC_HEADER_VALUES and not re.search(r"\d", v):
        return False
    return True


def extract_identity_signals(evidence: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Ham kanıttan AYIRT EDİCİ, yeniden-kullanılabilir kimlik sinyalleri çıkar (SAF).
    (sig_type, sig_value): header çifti (ad=değer), çerez adı, sayfa başlığı."""
    sigs: List[Tuple[str, str]] = []
    for k, val in (evidence.get("headers") or {}).items():
        kn = _norm(k)
        if kn in _IDENTITY_HEADERS or kn.startswith("x-"):
            if _distinctive_header_value(val):
                sigs.append(("header", f"{kn}={_norm(val)}"))
    for c in (evidence.get("cookies") or []):
        cn = _norm(c)
        if cn and cn not in _GENERIC_COOKIES and len(cn) >= 3:
            sigs.append(("cookie", cn))
    title = _norm(evidence.get("title"))
    if title and len(title) >= 3 and re.search(r"[a-z]", title):
        sigs.append(("title", title))
    return list(dict.fromkeys(sigs))


def distill_identity(profile: Any, cpe_products: List[str],
                     llm_products: List[str]) -> Optional[Dict[str, Any]]:
    """Bu taramada CPE/LLM ile tanınan kimliği öğrenilecek forma indir (SAF). Yalnız CPE ya
    da LLM ürün ürettiyse öğrenilir (saf tablo-hit'i zaten tanınıyor → kaydetme). Döner
    {label, dims:[[dim,value]...], source} ya da None."""
    if cpe_products:
        source, label = "cpe", cpe_products[0]
    elif llm_products:
        # "(LLM~%)" etiketini temizle → ham ürün adı
        source, label = "llm", re.sub(r"\s*\(LLM.*?\)\s*$", "", llm_products[0]).strip()
    else:
        return None
    label = (label or "").strip()[:80]
    if not label:
        return None
    dims = [[d, profile.value(d)] for d in _IDENTITY_DIMS if profile.value(d)]
    if not dims:
        return None
    return {"label": label, "dims": dims, "source": source}


def learn(collection: Any, signals: List[Tuple[str, str]],
          identity: Dict[str, Any], target: str) -> int:
    """Kimlik sinyallerini → ürün eşlemesi olarak upsert et. Sinyal başına ürün sayacı tutulur;
    >1 ürün görülürse `ambiguous`. Best-effort (DB hatası yutulur). Yazılan sinyal sayısı döner."""
    if not signals or not identity:
        return 0
    now = datetime.utcnow()
    label = identity["label"]
    written = 0
    for stype, sval in signals:
        kid = _key(stype, sval)
        try:
            doc = collection.find_one({"kind": "identity_sig", "_id": kid})
            if doc:
                prods = doc.get("products") or []
                found = next((x for x in prods if x.get("label") == label), None)
                if found:
                    found["count"] = int(found.get("count", 0)) + 1
                    found["dims"] = identity["dims"]
                    found["source"] = identity["source"]
                    found["last_seen"] = now
                else:
                    prods.append({"label": label, "count": 1, "dims": identity["dims"],
                                  "source": identity["source"], "last_seen": now})
                doc["products"] = prods
                doc["ambiguous"] = len(prods) > 1
                doc["total_count"] = int(doc.get("total_count", 0)) + 1
                doc["last_seen"] = now
                tgts = list(doc.get("targets") or [])
                if target and target not in tgts:
                    tgts.append(target)
                doc["targets"] = tgts[:20]
                collection.replace_one({"_id": kid}, doc)
            else:
                collection.insert_one({
                    "_id": kid, "kind": "identity_sig",
                    "sig_type": stype, "sig_value": sval[:200],
                    "products": [{"label": label, "count": 1, "dims": identity["dims"],
                                  "source": identity["source"], "last_seen": now}],
                    "ambiguous": False, "total_count": 1,
                    "targets": [target] if target else [],
                    "first_seen": now, "last_seen": now, "enabled": True,
                })
            written += 1
        except Exception as e:
            logger.warning(f"Kimlik hafızası yazılamadı ({stype}): {e}")
    return written


def recall(collection: Any, signals: List[Tuple[str, str]]
           ) -> Tuple[List[Tuple[str, str, float, str]], List[str]]:
    """Sinyallerden ÖĞRENİLMİŞ kimliği geri çağır → target_profile `extra` sinyalleri + etiketler.
    Yalnız AYIRT EDİCİ (tek ürün, ambiguous değil) ve yeterince korrobore (CPE≥1, LLM≥2) kayıtlar
    uygulanır. Ağırlık kaynağa+sayaca göre (tavan 0.78). DB hatası → boş (motor bozulmaz)."""
    extra: List[Tuple[str, str, float, str]] = []
    labels: List[str] = []
    if not signals:
        return extra, labels
    keys = [_key(s[0], s[1]) for s in signals]
    try:
        docs = list(collection.find({"kind": "identity_sig", "_id": {"$in": keys},
                                     "enabled": True}))
    except Exception as e:
        logger.warning(f"Kimlik hafızası okunamadı: {e}")
        return extra, labels
    for doc in docs:
        prods = doc.get("products") or []
        if doc.get("ambiguous") or len(prods) != 1:
            continue  # ayırt edici değil → uygulama
        p = prods[0]
        source = p.get("source", "llm")
        count = int(p.get("count", 1))
        if source != "cpe" and count < _MIN_LLM_CONFIRM:
            continue  # LLM/az-korroborasyon → daha fazla kanıt bekle
        weight = min(_WEIGHT_CAP, _BASE_WEIGHT.get(source, 0.6) + 0.03 * (count - 1))
        for pair in (p.get("dims") or []):
            if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[1]:
                extra.append((str(pair[0]), str(pair[1]), weight,
                              f"learned:{source}:{doc.get('sig_type')}"))
        labels.append(f"{p.get('label')} (öğrenildi~{source})")
    return extra, labels
