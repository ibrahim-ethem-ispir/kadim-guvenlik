"""
Kadim Güvenlik — PathProbe Öğrenme Döngüsü (K3)
================================================
Türkçe: "başkası buldu, biz bulamadık" bir daha yaşanmasın diye KALICI yol hafızası.
Bir kez doğrulanan (motor/LLM/insan) hassas yol `scan_memories` koleksiyonuna yazılır;
sonraki her tarama başında yüklenip probe'a enjekte edilir (extra_paths=). Zamanla hedefe
göre büyüyen, öğrenen bir katalog.

Sınır (CLAUDE.md): bu modül dispatcher sınırında çağrılır (Mongo orada). path_probe SAF
kalır — öğrenilen yollar ona `paths/extra_paths` argümanıyla girer. MongoClient süreç-başına
singleton'dur (çağıran verir); bu modül yalnız KOLEKSİYON alır → test edilebilir (fake db).

Kirlenme korkulukları: yalnız GÜÇLÜ validator geçen (veya LLM-imzalı) bulgular yazılır —
kör 200'ler (generic) hafızayı KİRLETMEZ. ≥2 farklı hedefte doğrulanan yol global'e terfi eder.
"""
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("path-memory")

# Hafızaya yazılmaya DEĞER validator'lar (güçlü imza) — kör 200/generic KİRLETMEZ.
# path_probe._STRONG_VALIDATORS ile hizalı tutulur; 'signature' (LLM-onaylı) da kabul.
_PERSISTABLE_VALIDATORS = frozenset({
    "env_file", "git_head", "git_config", "git_credentials", "npmrc", "htpasswd",
    "php_config", "sql_dump", "phpinfo", "server_status", "adminer", "phpmyadmin",
    "directory_listing", "log_file", "symfony_databases", "symfony_parameters",
    "signature",
})

_MEMORY_CAP = 500  # toplam öğrenilmiş yol tavanı (aşılırsa düşük-confidence tahliye — çağıran işi)


def _doc_to_row(d: Dict[str, Any]) -> Optional[Tuple[str, str, str, str, Dict[str, Any]]]:
    """Bir learned_path dokümanını probe 5-tuple'ına indir (source='memory')."""
    path = d.get("path")
    if not path:
        return None
    sig = d.get("signature")
    vname = d.get("validator") or ("signature" if sig else "generic")
    return (path, d.get("category", "info_disclosure"), d.get("severity", "medium"),
            vname, {"signature": sig, "source": "memory"})


def load_learned_paths(collection: Any, techs: Optional[List[str]], *,
                       cap: int = 50) -> List[Tuple[str, str, str, str, Dict[str, Any]]]:
    """Aktif öğrenilmiş yolları yükle. tech-özel yol yalnız eşleşen teknolojide döner;
    tech=[] (global) her hedefte döner. confidence/hit_count'a göre sıralı, cap ile kırpılı.
    Herhangi bir DB hatası → boş liste (motor bozulmaz)."""
    try:
        docs = list(collection.find({"kind": "learned_path", "enabled": True}))
    except Exception as e:
        logger.warning(f"Öğrenilmiş yollar okunamadı: {e}")
        return []
    tset = {str(t).lower() for t in (techs or [])}
    kept = []
    for d in docs:
        dtech = [str(t).lower() for t in (d.get("tech") or [])]
        if dtech and not (set(dtech) & tset):
            continue  # tech-özel ama hedef teknolojisi eşleşmiyor → atla
        kept.append(d)
    kept.sort(key=lambda d: (float(d.get("confidence", 0) or 0), int(d.get("hit_count", 0) or 0)),
              reverse=True)
    out = []
    for d in kept[:cap]:
        row = _doc_to_row(d)
        if row:
            out.append(row)
    return out


def record_findings(collection: Any, findings: List[Dict[str, Any]], target: str,
                    *, techs: Optional[List[str]] = None) -> int:
    """Doğrulanan bulguları hafızaya upsert et. Yalnız GÜÇLÜ/imzalı bulgular yazılır (kör 200
    kirletmez). Var olan yol → hit_count++, hedef eklenir, confidence artar; ≥2 farklı hedef →
    global terfi (tech=[]). Yeni yol → source='confirmed_finding'. Yazılan kayıt sayısını döner.
    Herhangi bir hata sessizce yutulur (kayıt best-effort; tarama sonucunu etkilemez)."""
    written = 0
    now = datetime.utcnow()
    tech_ctx = [str(t).lower() for t in (techs or [])]
    for f in findings or []:
        vname = f.get("validator")
        if vname not in _PERSISTABLE_VALIDATORS:
            continue  # generic/binary/zayıf → hafızayı kirletme
        path = f.get("path")
        if not path:
            continue
        try:
            doc = collection.find_one({"kind": "learned_path", "path": path})
            if doc:
                doc["hit_count"] = int(doc.get("hit_count", 0) or 0) + 1
                tgts = list(doc.get("targets") or [])
                if target and target not in tgts:
                    tgts.append(target)
                doc["targets"] = tgts[:20]
                doc["last_seen"] = now
                doc["confidence"] = min(0.99, float(doc.get("confidence", 0.5) or 0.5) + 0.1)
                # ≥2 farklı hedefte doğrulandıysa GLOBAL terfi (her hedefte aranır).
                if len(set(tgts)) >= 2:
                    doc["tech"] = []
                collection.replace_one({"_id": doc["_id"]}, doc)
            else:
                collection.insert_one({
                    "_id": str(uuid.uuid4()),
                    "kind": "learned_path",
                    "path": path,
                    "category": f.get("category", "info_disclosure"),
                    "severity": f.get("severity", "medium"),
                    # confirmed finding → isimli validator biliniyor; signature yok.
                    "validator": vname if vname != "signature" else None,
                    "signature": f.get("signature") if vname == "signature" else None,
                    "tech": tech_ctx,
                    "source": "confirmed_finding",
                    "hit_count": 1,
                    "confidence": 0.6,
                    "targets": [target] if target else [],
                    "first_seen": now,
                    "last_seen": now,
                    "enabled": True,
                })
            written += 1
        except Exception as e:
            logger.warning(f"Öğrenilmiş yol yazılamadı ({path}): {e}")
    return written


def learn_path_manual(collection: Any, path: str, category: str, severity: str,
                      *, signature: Optional[Dict[str, Any]] = None,
                      validator: Optional[str] = None,
                      tech: Optional[List[str]] = None) -> Dict[str, Any]:
    """Manuel ekip raporu girişi ('başkası buldu' → kalıcı hafıza). Yüksek confidence, enabled.
    signature verilirse validator='signature' (deterministik doğrulanır); validator verilirse o
    kullanılır; hiçbiri yoksa 'generic' (zayıf — operatör kanıtı var kabul). tech=None → global
    (her hedefte aranır — 'bir daha kaçırma' hedefi). Upsert'lenen dokümanı döner."""
    now = datetime.utcnow()
    if signature:
        vname = "signature"
    elif validator:
        vname = validator
    else:
        vname = "generic"
    existing = collection.find_one({"kind": "learned_path", "path": path})
    doc = {
        "_id": existing["_id"] if existing else str(uuid.uuid4()),
        "kind": "learned_path",
        "path": path,
        "category": category,
        "severity": severity,
        "validator": None if vname == "signature" else vname,
        "signature": signature if vname == "signature" else None,
        "tech": [str(t).lower() for t in (tech or [])],
        "source": "manual_report",
        "hit_count": int(existing.get("hit_count", 0) or 0) if existing else 0,
        "confidence": 0.95,
        "targets": list(existing.get("targets") or []) if existing else [],
        "first_seen": existing.get("first_seen", now) if existing else now,
        "last_seen": now,
        "enabled": True,
    }
    if existing:
        collection.replace_one({"_id": doc["_id"]}, doc, upsert=True)
    else:
        collection.insert_one(doc)
    return doc
