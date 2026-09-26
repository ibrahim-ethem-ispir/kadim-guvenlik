"""
Kadim Güvenlik — Port & Servis Varlık Envanteri Zaman Serisi (Asset Diff Engine)
=================================================================================
Türkçe: Kurumsal ASM (Attack Surface Management) disiplini. Periyodik veya tekrarlı
taramalarda hedefin port, servis ve altyapı yüzeyindeki değişimleri (Attack Surface Delta)
tespit eder:
  - Dün kapalı olup bugün açılan YENİ portlar (örn. acil açılmış 8443, test 8080, unutulmuş 22)
  - Kapatılmış servisler
  - Güncellenmiş veya değişmiş servis sürümleri (örn. Apache 2.4.49 -> 2.4.52)

Tasarım:
- SAF ÇEKİRDEK: `diff_asset_snapshots(prev, curr)` fonksiyonu I/O içermez, izole test edilebilir.
- DEGRADE-SAFE: Veritabanı yoksa veya önceki tarama bulunamazsa hata yükseltmez, boş delta döner.
- SAKLAMA: MongoDB `scan_memories` koleksiyonunda `kind="asset_snapshot"` olarak depolanır.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("asset-diff")


def build_asset_snapshot(
    target: str,
    ports_data: List[Dict[str, Any]],
    technologies: Optional[List[str]] = None,
    meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Port ve servis verilerini normalize edilmiş snapshot formatına çevirir (SAF)."""
    norm_ports = {}
    for p in ports_data:
        port_num = int(p.get("port", 0))
        if port_num <= 0:
            continue
        proto = str(p.get("protocol") or "tcp").lower()
        key = f"{port_num}/{proto}"
        norm_ports[key] = {
            "port": port_num,
            "protocol": proto,
            "service": str(p.get("service") or "unknown").lower(),
            "product": str(p.get("product") or "").strip(),
            "version": str(p.get("version") or "").strip(),
            "banner": str(p.get("banner") or "").strip(),
        }

    return {
        "target": target,
        "timestamp": time.time(),
        "ports": norm_ports,
        "technologies": sorted(list(set(str(t).lower() for t in (technologies or [])))),
        "meta": meta or {},
    }


def diff_asset_snapshots(
    prev: Optional[Dict[str, Any]],
    curr: Dict[str, Any]
) -> Dict[str, Any]:
    """
    İki varlık snapshot'ı arasındaki farkı (delta) hesaplar (SAF).
    Döner:
      {
        "has_changes": bool,
        "new_ports": [...],
        "closed_ports": [...],
        "changed_services": [...],
        "new_technologies": [...],
        "removed_technologies": [...],
      }
    """
    if not prev or not isinstance(prev, dict) or "ports" not in prev:
        # Önceki tarama yok — bu bir baz (baseline) taramasıdır.
        return {
            "has_changes": False,
            "is_baseline": True,
            "new_ports": [],
            "closed_ports": [],
            "changed_services": [],
            "new_technologies": [],
            "removed_technologies": [],
            "message": "İlk tarama — varlık referans tabanı (baseline) oluşturuldu.",
        }

    prev_ports = prev.get("ports") or {}
    curr_ports = curr.get("ports") or {}

    new_ports: List[Dict[str, Any]] = []
    closed_ports: List[Dict[str, Any]] = []
    changed_services: List[Dict[str, Any]] = []

    # 1. Yeni açılan portlar
    for p_key, p_data in curr_ports.items():
        if p_key not in prev_ports:
            new_ports.append(p_data)
        else:
            # Var olan portta servis / sürüm değişti mi?
            old = prev_ports[p_key]
            if (old.get("service") != p_data.get("service") or
                old.get("version") != p_data.get("version") or
                old.get("product") != p_data.get("product")):
                changed_services.append({
                    "port_key": p_key,
                    "old": f"{old.get('product', '')} {old.get('version', '')}".strip() or old.get("service"),
                    "new": f"{p_data.get('product', '')} {p_data.get('version', '')}".strip() or p_data.get("service"),
                })

    # 2. Kapatılan portlar
    for p_key, p_data in prev_ports.items():
        if p_key not in curr_ports:
            closed_ports.append(p_data)

    # 3. Teknoloji farkları
    prev_techs = set(prev.get("technologies") or [])
    curr_techs = set(curr.get("technologies") or [])
    new_techs = sorted(list(curr_techs - prev_techs))
    removed_techs = sorted(list(prev_techs - curr_techs))

    has_changes = bool(new_ports or closed_ports or changed_services or new_techs or removed_techs)

    return {
        "has_changes": has_changes,
        "is_baseline": False,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "changed_services": changed_services,
        "new_technologies": new_techs,
        "removed_technologies": removed_techs,
    }


def save_asset_snapshot(collection: Any, target: str, snapshot: Dict[str, Any]) -> bool:
    """MongoDB scan_memories içine snapshot kaydeder."""
    if collection is None:
        return False
    try:
        doc = {
            "kind": "asset_snapshot",
            "target": target,
            "timestamp": snapshot.get("timestamp", time.time()),
            "snapshot": snapshot,
        }
        collection.insert_one(doc)
        return True
    except Exception as e:
        logger.debug(f"Asset snapshot kaydedilemedi: {e}")
        return False


def load_latest_asset_snapshot(collection: Any, target: str) -> Optional[Dict[str, Any]]:
    """MongoDB'den hedef için en son kaydedilmiş asset snapshot'ını getirir."""
    if collection is None:
        return None
    try:
        doc = collection.find_one(
            {"kind": "asset_snapshot", "target": target},
            sort=[("timestamp", -1)]
        )
        if doc and "snapshot" in doc:
            return doc["snapshot"]
    except Exception as e:
        logger.debug(f"Asset snapshot okunamadı: {e}")
    return None
