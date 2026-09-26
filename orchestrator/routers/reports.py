"""
Türkçe: Raporlama / geçmiş sorgu route'ları.

OSINT profil, timeline, karşılaştırma + tarama listesi + zafiyet listesi.
main.py'den ayrıldı. Paylaşılan bağımlılıklar core/ paketinden import edilir
(db koleksiyonları + risk skoru). Davranış birebir aynı.
"""
import logging
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException

from plugins import registry as _registry
from core.db import get_scans_collection, get_sessions_collection, get_vulnerabilities_collection
from core.scoring import calculate_risk_score

logger = logging.getLogger(__name__)


def _session_scan_types(doc: dict) -> list:
    """Session dokümanından v1 `scan_types` türet (çalıştırılan stage araçları)."""
    stages = doc.get("stages") or {}
    tools = [st["tool"] for st in stages.values()
             if isinstance(st, dict) and st.get("tool")]
    return list(dict.fromkeys(tools)) or ["autonomous"]


def _iso(v):
    """datetime → isoformat; zaten string ise olduğu gibi bırak."""
    return v.isoformat() if hasattr(v, "isoformat") else v

router = APIRouter(tags=["reports"])

OSINT_SERVICE_URL = _registry.url("osint")


@router.get("/osint/profile/{target}")
async def get_osint_profile(target: str):
    """
    Türkçe: Domain/IP için tüm OSINT verilerini toplar
    - MongoDB'den geçmiş taramaları al
    - OSINT service'ten entity'leri al
    - Zafiyet trendini hesapla
    - Risk skorunu hesapla
    """
    scans_col = get_scans_collection()
    vulns_col = get_vulnerabilities_collection()

    # 1. Base Profile Info
    profile = {
        "target": target,
        "first_seen": datetime.utcnow().isoformat(),
        "last_scanned": None,
        "total_scans": 0,
        "scan_history": [],
        "entities": {
            "subdomains": [],
            "ip_addresses": [],
            "open_ports": [],
            "technologies": [],
            "ssl_info": None,
            "whois_data": None
        },
        "vulnerability_trend": [],
        "risk_score": 0,
        "risk_factors": []
    }

    if scans_col is not None:
        # Get all scans for target
        cursor = scans_col.find({"target": target}).sort("created_at", -1)
        scans = list(cursor)

        profile["total_scans"] = len(scans)
        if scans:
            profile["last_scanned"] = scans[0].get("created_at").isoformat() if scans[0].get("created_at") else None
            profile["first_seen"] = scans[-1].get("created_at").isoformat() if scans[-1].get("created_at") else profile["first_seen"]

            # Calculate Risk Score from latest scan
            latest_results = scans[0].get("results", {})
            profile["risk_score"] = calculate_risk_score(latest_results)

            # Populate Scan History
            for scan in scans:
                findings_count = 0
                if "nuclei" in scan.get("results", {}):
                    nuc = scan["results"]["nuclei"]
                    if isinstance(nuc, dict):
                        findings_count = nuc.get("findings_count", len(nuc.get("findings", [])))

                profile["scan_history"].append({
                    "scan_id": scan.get("scan_id"),
                    "date": scan.get("created_at").isoformat() if scan.get("created_at") else None,
                    "scan_types": scan.get("scan_types", []),
                    "findings_count": findings_count,
                    "risk_score": calculate_risk_score(scan.get("results", {}))
                })

    # 2. Fetch OSINT Data from OSINT Service
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get Graph/Entities
            graph_res = await client.get(f"{OSINT_SERVICE_URL}/graph/{target}")
            if graph_res.status_code == 200:
                graph_data = graph_res.json()
                # Parse entities from graph data if possible, or just use structure
                # This depends on graph structure. For now assume it returns nodes/edges
                nodes = graph_data.get("nodes", [])
                for node in nodes:
                    lbl = node.get("data", {}).get("label", "")
                    typ = node.get("data", {}).get("type", "")
                    if typ == "subdomain":
                        profile["entities"]["subdomains"].append(lbl)
                    elif typ == "ip":
                        profile["entities"]["ip_addresses"].append(lbl)
                    elif typ == "tech":
                        profile["entities"]["technologies"].append(lbl)

            # Get History/Whois/SSL if available via separate endpoints or history
            # history_res = await client.get(f"{OSINT_SERVICE_URL}/api/history/{target}")
            # ...

    except Exception as e:
        print(f"OSINT Service error: {e}")

    # 3. Calculate Vulnerability Trend
    if vulns_col is not None:
        pipeline = [
            {"$match": {"target": target}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$discovered_at"}},
                "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "critical"]}, 1, 0]}},
                "high": {"$sum": {"$cond": [{"$eq": ["$severity", "high"]}, 1, 0]}},
                "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "medium"]}, 1, 0]}},
                "low": {"$sum": {"$cond": [{"$eq": ["$severity", "low"]}, 1, 0]}}
            }},
            {"$sort": {"_id": 1}}
        ]
        try:
            trend_results = list(vulns_col.aggregate(pipeline))
            for t in trend_results:
                profile["vulnerability_trend"].append({
                    "date": t["_id"],
                    "critical": t["critical"],
                    "high": t["high"],
                    "medium": t["medium"],
                    "low": t["low"]
                })
        except Exception as e:
            print(f"Trend aggregation error: {e}")

    return profile


@router.get("/osint/timeline/{target}")
async def get_scan_timeline(target: str):
    """Türkçe: Hedef için tarama geçmişi timeline"""
    scans_col = get_scans_collection()
    if scans_col is None:
        return []

    cursor = scans_col.find({"target": target}).sort("created_at", -1)
    timeline = []
    for scan in cursor:
        timeline.append({
            "scan_id": scan.get("scan_id"),
            "date": scan.get("created_at").isoformat(),
            "status": scan.get("status"),
            "scan_types": scan.get("scan_types"),
            "risk_score": calculate_risk_score(scan.get("results", {}))
        })
    return timeline


@router.get("/osint/compare/{target}")
async def compare_scans(target: str, scan_id_1: str, scan_id_2: str):
    """Türkçe: İki tarama arasındaki farkları göster"""
    scans_col = get_scans_collection()
    if scans_col is None:
        raise HTTPException(status_code=500, detail="Database not available")

    scan1 = scans_col.find_one({"scan_id": scan_id_1})
    scan2 = scans_col.find_one({"scan_id": scan_id_2})

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or more scans not found")

    # Compare findings
    # Simple logic: compare findings count and list of findings

    def extract_findings(scan):
        findings = []
        if "nuclei" in scan.get("results", {}):
            nuc = scan["results"]["nuclei"]
            if isinstance(nuc, dict):
                findings = nuc.get("findings", [])
        return findings

    f1 = extract_findings(scan1)
    f2 = extract_findings(scan2)

    # Identify new and resolved
    f1_ids = {f.get("template-id") + f.get("matched-at", "") for f in f1}
    f2_ids = {f.get("template-id") + f.get("matched-at", "") for f in f2}

    new_findings = [f for f in f2 if (f.get("template-id") + f.get("matched-at", "")) not in f1_ids]
    resolved_findings = [f for f in f1 if (f.get("template-id") + f.get("matched-at", "")) not in f2_ids]

    return {
        "target": target,
        "scan1": {"id": scan_id_1, "date": scan1.get("created_at")},
        "scan2": {"id": scan_id_2, "date": scan2.get("created_at")},
        "new_findings_count": len(new_findings),
        "resolved_findings_count": len(resolved_findings),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "risk_diff": calculate_risk_score(scan2.get("results", {})) - calculate_risk_score(scan1.get("results", {}))
    }


@router.get("/scans")
async def get_all_scans(limit: int = 50, status: Optional[str] = None):
    """Türkçe: Tüm taramaları listele — İKİ kaynak birleştirilir (tutarlı tek liste):

      • Otonom (Kuşatma v2): v2_scan_sessions — otonom taramaların TEK gerçeği.
      • Manuel tarama: eski `scans` koleksiyonu (scan.tsx hâlâ buraya yazar).

    scan_id'ye göre dedup; v2 session önceliklidir (bir zamanlar otonom taramalar `scans`'a
    da yazıldığından çift kaydı önler). En yeni önce sıralanır, `limit` uygulanır."""
    by_id: dict = {}

    try:
        # 1) Otonom v2 session'lar (öncelikli)
        sessions_col = get_sessions_collection()
        if sessions_col is not None:
            q = {"status": status} if status else {}
            for doc in sessions_col.find(q, {"_id": 0}).sort("created_at", -1).limit(limit):
                sid = doc.get("scan_id")
                if not sid:
                    continue
                by_id[sid] = {
                    "scan_id": sid,
                    "target": doc.get("target"),
                    "scan_types": _session_scan_types(doc),
                    "status": doc.get("status"),
                    "created_at": _iso(doc.get("created_at")),
                    "completed_at": _iso(doc.get("completed_at")),
                }

        # 2) Manuel v1 taramalar (yalnız v2'de OLMAYAN scan_id'ler)
        scans_col = get_scans_collection()
        if scans_col is not None:
            q = {"status": status} if status else {}
            for scan in scans_col.find(q, {"_id": 0}).sort("created_at", -1).limit(limit):
                sid = scan.get("scan_id")
                if not sid or sid in by_id:
                    continue
                by_id[sid] = {
                    "scan_id": sid,
                    "target": scan.get("target"),
                    "scan_types": scan.get("scan_types", []),
                    "status": scan.get("status"),
                    "created_at": _iso(scan.get("created_at")),
                    "completed_at": _iso(scan.get("completed_at")),
                }

        scans = sorted(by_id.values(), key=lambda s: s.get("created_at") or "", reverse=True)[:limit]
        return {"scans": scans, "total": len(scans)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerabilities")
async def get_vulnerabilities(limit: int = 100, severity: Optional[str] = None,
                              confidence_tier: Optional[str] = None,
                              scan_id: Optional[str] = None):
    """Türkçe: Bulunan zafiyetleri listele.

    FALSE-POSITIVE ekseni: her kayıt confidence_tier (confirmed/probable/unconfirmed) taşır.
    `confidence_tier` filtresiyle yalnız kanıtlı bulgular istenebilir; verilmezse hepsi döner.
    name/matched_at fallback'i: otonom kayıtlar title/target alanlarını kullanır (nuclei
    'name/matched_at' yerine) — ikisi de doğru render olsun diye köprülenir.

    `scan_id`: TEK-TARAMA görünürlüğü. Koleksiyon tüm taramaları biriktirir; scan_id
    verilmezse liste taramalar-arası karışır ve "auto-scan '2 kritik' dedi ama listede
    göremiyorum" tutarsızlığı çıkar (özet kartı tek taramayı, liste hepsini sayıyordu).
    scan_id ile liste O taramaya daralır → özet kartıyla AYNI kümeyi gösterir.

    `stats`: MANŞET SAYIMLARININ TEK DOĞRULUK KAYNAĞI. Sayfalanan pencere (limit) değil,
    eşleşen TÜM kayıtlar üstünden hesaplanır ve tier-farkındadır:
      - confirmed_severity_counts: yalnız confirmed+probable (kart manşeti bunu kullanmalı —
        motorun `confirmed_critical_count`'u ile aynı kural). "2 kanıtlı kritik".
      - severity_counts: tüm bulgular (geriye-uyum).
      - tier_counts: unconfirmed = "incelenecek" kovası (manşeti şişirmesin).
    Böylece frontend kritik sayısını getirdiği 50 satırdan DEĞİL, otoriter aggregate'ten okur
    → auto-scan kartı ile zafiyet listesi ARTIK aynı sayıyı gösterir."""
    vulns_col = get_vulnerabilities_collection()
    _empty_stats = {
        "severity_counts": {}, "confirmed_severity_counts": {},
        "tier_counts": {"confirmed": 0, "probable": 0, "unconfirmed": 0},
    }
    if vulns_col is None:
        return {"vulnerabilities": [], "total": 0, "stats": _empty_stats}

    try:
        # Manşet sayımları scan-scope'una göre (severity/tier FİLTRELERİNDEN bağımsız) —
        # kullanıcı 'yalnız kritik' filtrelese bile kartlar taramanın TÜM dağılımını göstersin.
        stats_query: dict = {}
        if scan_id:
            stats_query["scan_id"] = scan_id

        # Liste sorgusu: scan-scope + aktif kullanıcı filtreleri.
        query = dict(stats_query)
        if severity:
            query["severity"] = severity
        if confidence_tier:
            query["confidence_tier"] = confidence_tier

        cursor = vulns_col.find(query).sort("discovered_at", -1).limit(limit)
        vulns = []
        for vuln in cursor:
            vulns.append({
                "scan_id": vuln.get("scan_id"),
                "target": vuln.get("target"),
                "template_id": vuln.get("template_id") or vuln.get("cve") or vuln.get("tool"),
                "name": vuln.get("name") or vuln.get("title"),
                "severity": vuln.get("severity"),
                "matched_at": vuln.get("matched_at") or vuln.get("target"),
                # KANIT — en eyleme-dönüşür alan; liste sayfasında genişleyen satırda gösterilir.
                # Otonom Evidence'lar 'proof' taşır; nuclei kayıtlarında yoksa None döner.
                "proof": vuln.get("proof"),
                "tool": vuln.get("tool"),
                "cve": vuln.get("cve"),
                # FALSE-POSITIVE ekseni — frontend confirmed'ı unconfirmed'dan ayırsın.
                "confidence_tier": vuln.get("confidence_tier") or "unconfirmed",
                "verified": vuln.get("verified"),
                "verification_confidence": vuln.get("verification_confidence"),
                "fp_reason": vuln.get("fp_reason"),
                "llm_fp_opinion": vuln.get("llm_fp_opinion"),
                "discovered_at": vuln.get("discovered_at").isoformat() if vuln.get("discovered_at") else None
            })

        total = vulns_col.count_documents(query)
        stats = _aggregate_vuln_stats(vulns_col, stats_query)
        return {"vulnerabilities": vulns, "total": total, "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _aggregate_vuln_stats(vulns_col, match_query: dict) -> dict:
    """Türkçe: Zafiyet koleksiyonundan tier-farkında MANŞET sayımlarını tek geçişte üret.

    NEDEN aggregate: sayımı sayfalanmış pencereden (limit) hesaplamak yanıltıcıydı — 50 satır
    getirilip 'kritik' oradan sayılınca, 51. kayıttaki kanıtlı kritik görünmüyordu. Eşleşen
    TÜM kayıtlar üstünden $group ile sayarız; DB tarafında ucuz, tek round-trip.

    tier eksik (eski/statik kayıt) → 'unconfirmed' varsayılır (okuyucuyla aynı kural)."""
    severity_counts: dict = {}
    confirmed_severity_counts: dict = {}
    tier_counts = {"confirmed": 0, "probable": 0, "unconfirmed": 0}
    try:
        pipeline = [
            {"$match": match_query},
            {"$group": {
                "_id": {
                    "sev": {"$ifNull": ["$severity", "unknown"]},
                    "tier": {"$ifNull": ["$confidence_tier", "unconfirmed"]},
                },
                "n": {"$sum": 1},
            }},
        ]
        for row in vulns_col.aggregate(pipeline):
            sev = row["_id"].get("sev") or "unknown"
            tier = row["_id"].get("tier") or "unconfirmed"
            if tier not in tier_counts:
                tier = "unconfirmed"
            n = int(row.get("n", 0))
            severity_counts[sev] = severity_counts.get(sev, 0) + n
            tier_counts[tier] += n
            # Manşet: yalnız confirmed+probable — unconfirmed (olası FP) kritik sayısını şişirmesin.
            if tier in ("confirmed", "probable"):
                confirmed_severity_counts[sev] = confirmed_severity_counts.get(sev, 0) + n
    except Exception as e:
        logger.warning(f"vuln stats aggregate hatası: {e}")
    return {
        "severity_counts": severity_counts,
        "confirmed_severity_counts": confirmed_severity_counts,
        "tier_counts": tier_counts,
    }
