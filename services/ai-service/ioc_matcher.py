"""
Kadim Güvenlik - IOC Matcher & APT Risk Score Calculator
Türkçe: Indicator of Compromise (IOC) eşleştirme ve APT risk skoru hesaplama.

Tarama sonuçlarından şüpheli kalıpları tespit eder:
- Port kombinasyonları (ör: 4443+8443 → Lazarus paterni)
- CDN bypass + gerçek IP açık = yüksek risk
- Servis+versiyon bazlı CVE risk eşleştirmesi
- Anomali tespiti (atipik portlar, gizli servisler)

Kullanım:
    from ioc_matcher import calculate_apt_risk_score, match_iocs
    risk = calculate_apt_risk_score(scan_results)
    iocs = match_iocs(scan_results)
"""

import logging
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger("ioc-matcher")


# ============================================================
# ŞÜPHELİ PORT KOMBİNASYONLARI
# ============================================================
# Belirli port kombinasyonları APT faaliyetini işaret edebilir

SUSPICIOUS_PORT_COMBOS: List[Dict[str, Any]] = [
    {
        "name": "Lazarus Backdoor Pattern",
        "ports": {4443, 8443},
        "confidence": 80,
        "apt_group": "lazarus",
        "description": "Lazarus grubunun sıkça kullandığı non-standard HTTPS portları",
    },
    {
        "name": "Cobalt Strike Beacon",
        "ports": {50050, 443},
        "confidence": 90,
        "apt_group": None,
        "description": "Cobalt Strike C2 sunucu pattern'i (50050 = team server)",
    },
    {
        "name": "Cobalt Strike Alt Pattern",
        "ports": {8443, 8080, 443},
        "confidence": 60,
        "apt_group": None,
        "description": "Cobalt Strike yaygın HTTP/HTTPS listener kombinasyonu",
    },
    {
        "name": "Empire C2 Pattern",
        "ports": {80, 443, 8443},
        "confidence": 40,
        "apt_group": None,
        "description": "PowerShell Empire default listener portları",
    },
    {
        "name": "Database Exposure",
        "ports": {3306, 5432,  27017},
        "confidence": 70,
        "apt_group": None,
        "description": "MySQL + PostgreSQL + MongoDB – doğrudan veritabanı erişimi",
    },
    {
        "name": "Windows AD Target",
        "ports": {445, 135, 389, 636},
        "confidence": 75,
        "apt_group": "conti",
        "description": "Active Directory hedef pattern'i – SMB + RPC + LDAP",
    },
    {
        "name": "Full RDP Exposure",
        "ports": {3389, 445},
        "confidence": 65,
        "apt_group": "darkside",
        "description": "RDP + SMB açık – ransomware giriş vektörü",
    },
    {
        "name": "Redis + Elastic Exposure",
        "ports": {6379, 9200},
        "confidence": 80,
        "apt_group": None,
        "description": "Redis + Elasticsearch açık – kimlik doğrulama olmayabilir",
    },
    {
        "name": "DNS Tunneling Potential",
        "ports": {53, 5353},
        "confidence": 50,
        "apt_group": "apt34",
        "description": "Standart ve mDNS portları açık – DNS tünelleme potansiyeli",
    },
    {
        "name": "ICS/SCADA Exposure",
        "ports": {502, 102, 44818},
        "confidence": 95,
        "apt_group": "sandworm",
        "description": "Endüstriyel kontrol sistemi portları – Modbus + S7comm + EtherNet/IP",
    },
    {
        "name": "Supply Chain CI/CD",
        "ports": {8080, 9090, 8443},
        "confidence": 50,
        "apt_group": "apt29",
        "description": "CI/CD araçlarının yaygın portları (Jenkins, GitLab, Nexus)",
    },
]


# ============================================================
# SERVİS-CVE MAPPING (otomasyon için)
# ============================================================
# Belirli servis+versiyon kombinasyonları bilinen CVE'lere karşılık gelir

SERVICE_CVE_MAP: List[Dict[str, Any]] = [
    {
        "service": "apache",
        "version_regex": r"2\.4\.(49|50)",
        "cves": ["CVE-2021-41773", "CVE-2021-42013"],
        "severity": "critical",
        "description": "Apache 2.4.49/50 path traversal RCE",
    },
    {
        "service": "exchange",
        "version_regex": r"(2013|2016|2019)",
        "cves": ["CVE-2021-26855", "CVE-2021-26857"],
        "severity": "critical",
        "description": "ProxyLogon/ProxyShell Exchange RCE chain",
    },
    {
        "service": "openssh",
        "version_regex": r"[5-7]\.",
        "cves": ["CVE-2016-0777", "CVE-2018-15473"],
        "severity": "high",
        "description": "OpenSSH eski versiyon – enumeration ve bilgi sızıntısı",
    },
    {
        "service": "nginx",
        "version_regex": r"1\.(1[0-8]|[0-9])\.",
        "cves": ["CVE-2021-23017"],
        "severity": "medium",
        "description": "nginx eski versiyon – DNS resolver vulnerability",
    },
    {
        "service": "log4j",
        "version_regex": r"2\.(0|[1-9]|1[0-4])\.",
        "cves": ["CVE-2021-44228"],
        "severity": "critical",
        "description": "Log4Shell RCE (Java uygulamalarında)",
    },
    {
        "service": "weblogic",
        "version_regex": r"(10|12|14)\.",
        "cves": ["CVE-2019-2725", "CVE-2020-14882"],
        "severity": "critical",
        "description": "Oracle WebLogic deserialization RCE",
    },
    {
        "service": "tomcat",
        "version_regex": r"[5-8]\.",
        "cves": ["CVE-2017-12617", "CVE-2020-1938"],
        "severity": "high",
        "description": "Apache Tomcat – Ghostcat AJP ve PUT method RCE",
    },
    {
        "service": "iis",
        "version_regex": r"(6|7|8)\.",
        "cves": ["CVE-2017-7269"],
        "severity": "high",
        "description": "IIS eski versiyon – WebDAV buffer overflow",
    },
    {
        "service": "activemq",
        "version_regex": r"5\.",
        "cves": ["CVE-2023-46604"],
        "severity": "critical",
        "description": "Apache ActiveMQ deserialization RCE",
    },
    {
        "service": "confluence",
        "version_regex": r"[5-7]\.",
        "cves": ["CVE-2022-26134", "CVE-2023-22515"],
        "severity": "critical",
        "description": "Atlassian Confluence OGNL injection / privilege escalation",
    },
    {
        "service": "gitlab",
        "version_regex": r"(1[0-5])\.",
        "cves": ["CVE-2021-22205"],
        "severity": "critical",
        "description": "GitLab RCE – ExifTool arbitrary file upload",
    },
    {
        "service": "fortinet",
        "version_regex": r"(5|6)\.",
        "cves": ["CVE-2018-13379", "CVE-2022-42475"],
        "severity": "critical",
        "description": "FortiOS path traversal ve heap overflow RCE",
    },
]


# ============================================================
# ANOMALİ PATERNLERİ
# ============================================================

ANOMALY_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "Unusual High Port Cluster",
        "check": "high_port_cluster",
        "description": "10000+ portlarında 3+ servisten fazlası açık – C2 veya backdoor olabilir",
        "severity": "high",
    },
    {
        "name": "CDN Bypass with Exposed Services",
        "check": "cdn_bypass_exposed",
        "description": "CDN/WAF arkasında gerçek IP tespit edildi ve tehlikeli portlar açık",
        "severity": "critical",
    },
    {
        "name": "Multiple Admin Panels",
        "check": "admin_panels",
        "description": "Birden fazla yönetim paneli portu açık (çok geniş saldırı yüzeyi)",
        "severity": "high",
    },
    {
        "name": "Unprotected Debug Ports",
        "check": "debug_ports",
        "description": "Debug/profiling portları internete açık (9090, 9229, 5005, 4848 vb.)",
        "severity": "critical",
    },
    {
        "name": "Mixed OS Services",
        "check": "mixed_os",
        "description": "Aynı host'ta hem Windows (SMB/RDP) hem Linux (SSH) servisleri – VM veya pivot",
        "severity": "medium",
    },
]


# ============================================================
# ANA FONKSİYONLAR
# ============================================================

def match_iocs(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tarama sonuçlarında IOC pattern'leri ara.

    Returns:
        {
            "port_patterns": [...],
            "service_cve_matches": [...],
            "anomalies": [...],
            "total_indicators": int,
        }
    """
    # Port verilerini topla
    ports = _extract_open_ports(scan_results)
    open_port_set = {p["port"] for p in ports}
    services = [(p.get("product", ""), p.get("version", ""), p.get("port", 0)) for p in ports]

    # ---- 1. Port kombinasyonu kontrolü ----
    port_patterns = []
    for combo in SUSPICIOUS_PORT_COMBOS:
        required_ports = combo["ports"]
        # En az 2 port eşleşmesi gerekli (veya tüm portlar)
        overlap = required_ports & open_port_set
        if len(overlap) >= min(2, len(required_ports)):
            coverage = len(overlap) / len(required_ports)
            adjusted_confidence = int(combo["confidence"] * coverage)
            port_patterns.append({
                "name": combo["name"],
                "matched_ports": list(overlap),
                "required_ports": list(required_ports),
                "confidence": adjusted_confidence,
                "apt_group": combo.get("apt_group"),
                "description": combo["description"],
            })

    # ---- 2. Servis-CVE eşleşmesi ----
    import re
    service_cve_matches = []
    for product, version, port in services:
        product_lower = product.lower() if product else ""
        version_str = str(version) if version else ""

        for mapping in SERVICE_CVE_MAP:
            if mapping["service"] in product_lower:
                if version_str and re.search(mapping["version_regex"], version_str):
                    service_cve_matches.append({
                        "port": port,
                        "service": product,
                        "version": version_str,
                        "cves": mapping["cves"],
                        "severity": mapping["severity"],
                        "description": mapping["description"],
                    })

    # ---- 3. Anomali tespiti ----
    anomalies = _detect_anomalies(scan_results, open_port_set, ports)

    total_indicators = len(port_patterns) + len(service_cve_matches) + len(anomalies)

    if total_indicators > 0:
        logger.info(
            f"🔎 IOC eşleştirme: {len(port_patterns)} port pattern, "
            f"{len(service_cve_matches)} servis-CVE, {len(anomalies)} anomali"
        )

    return {
        "port_patterns": port_patterns,
        "service_cve_matches": service_cve_matches,
        "anomalies": anomalies,
        "total_indicators": total_indicators,
    }


def calculate_apt_risk_score(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Kapsamlı APT risk skoru hesapla (0-100).

    Birden fazla faktörü ağırlıklı olarak değerlendirir:
    - Port/servis açıklıkları (%25)
    - Bilinen CVE eşleşmeleri (%30)
    - IOC pattern'leri (%20)
    - OSINT istihbarat (%15)
    - CDN/WAF durumu (%10)

    Returns:
        {
            "score": int (0-100),
            "level": str (critical/high/medium/low/info),
            "breakdown": {...},
            "summary": str,
        }
    """
    scores = {
        "port_exposure": 0,
        "vulnerability": 0,
        "ioc_patterns": 0,
        "osint_intelligence": 0,
        "cdn_exposure": 0,
    }

    # ---- Port Exposure (%25) ----
    ports = _extract_open_ports(scan_results)
    open_port_set = {p["port"] for p in ports}

    dangerous_ports = {3389, 445, 135, 139, 1433, 3306, 5432, 27017, 6379, 9200, 11211}
    exposed_dangerous = dangerous_ports & open_port_set
    scores["port_exposure"] = min(25, len(exposed_dangerous) * 5 + len(open_port_set) * 0.5)

    # ---- Vulnerability (%30) ----
    vuln_data = _extract_vulns(scan_results)
    critical_count = sum(1 for v in vuln_data if v.get("severity") == "critical")
    high_count = sum(1 for v in vuln_data if v.get("severity") == "high")
    scores["vulnerability"] = min(30, critical_count * 10 + high_count * 5)

    # ---- IOC Patterns (%20) ----
    ioc_results = match_iocs(scan_results)
    pattern_score = sum(p["confidence"] / 10 for p in ioc_results["port_patterns"])
    cve_score = len(ioc_results["service_cve_matches"]) * 3
    anomaly_score = len(ioc_results["anomalies"]) * 4
    scores["ioc_patterns"] = min(20, pattern_score + cve_score + anomaly_score)

    # ---- OSINT Intelligence (%15) ----
    osint_data = scan_results.get("osint", scan_results.get("osint_intelligence", {}))
    if isinstance(osint_data, dict) and osint_data.get("data"):
        osint_data = osint_data["data"]

    if isinstance(osint_data, dict):
        # VirusTotal kötü niyetli tespit
        vt = osint_data.get("virustotal", {})
        if isinstance(vt, dict):
            malicious = vt.get("malicious", 0)
            scores["osint_intelligence"] += min(8, malicious * 2)

        # AbuseIPDB skoru
        abuse = osint_data.get("abuseipdb", {})
        if isinstance(abuse, dict):
            abuse_score = abuse.get("confidence_score", 0)
            if abuse_score > 50:
                scores["osint_intelligence"] += min(7, abuse_score / 10)

    scores["osint_intelligence"] = min(15, scores["osint_intelligence"])

    # ---- CDN/WAF Exposure (%10) ----
    recon_data = scan_results.get("recon", scan_results.get("recon_fingerprint", {}))
    if isinstance(recon_data, dict) and recon_data.get("data"):
        recon_data = recon_data["data"]

    if isinstance(recon_data, dict):
        is_behind_cdn = recon_data.get("is_behind_cdn", False)
        origin_data = scan_results.get("origin_discovery", {})
        if isinstance(origin_data, dict) and origin_data.get("data"):
            origin_data = origin_data["data"]

        has_real_ip = False
        if isinstance(origin_data, dict):
            has_real_ip = bool(origin_data.get("best_candidate"))

        if is_behind_cdn and has_real_ip:
            scores["cdn_exposure"] = 10  # Maximum CDN risk
        elif is_behind_cdn and not has_real_ip:
            scores["cdn_exposure"] = 0  # CDN arkasında ve korunuyor
        elif not is_behind_cdn and exposed_dangerous:
            scores["cdn_exposure"] = 5  # CDN yok ve tehlikeli portlar açık

    # ---- Toplam ----
    total_score = int(sum(scores.values()))
    total_score = min(100, total_score)

    # Risk seviyesi
    if total_score >= 80:
        level = "critical"
        summary = "🔴 KRİTİK: Çok yüksek APT riski. Acil müdahale gerekli."
    elif total_score >= 60:
        level = "high"
        summary = "🟠 YÜKSEK: Önemli güvenlik açıkları tespit edildi. Hızlı aksiyon önerilir."
    elif total_score >= 40:
        level = "medium"
        summary = "🟡 ORTA: Bazı risk faktörleri mevcut. İyileştirme planlanmalı."
    elif total_score >= 20:
        level = "low"
        summary = "🟢 DÜŞÜK: Sınırlı risk. Düzenli izleme yeterli."
    else:
        level = "info"
        summary = "⚪ BİLGİ: Minimum risk. Güvenlik durumu iyi."

    logger.info(f"📊 APT Risk Skoru: {total_score}/100 ({level.upper()})")

    return {
        "score": total_score,
        "level": level,
        "breakdown": scores,
        "summary": summary,
        "weights": {
            "port_exposure": "25%",
            "vulnerability": "30%",
            "ioc_patterns": "20%",
            "osint_intelligence": "15%",
            "cdn_exposure": "10%",
        },
    }


# ============================================================
# YARDIMCI FONKSİYONLAR
# ============================================================

def _extract_open_ports(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tüm tarama kaynaklarından port bilgilerini topla."""
    ports = []
    for key in ["port_scan", "direct_ip_scan", "domain_port_scan", "fast_port_scan"]:
        stage_data = scan_results.get(key, {})
        if isinstance(stage_data, dict):
            data = stage_data.get("data", stage_data)
            if isinstance(data, dict):
                stage_ports = data.get("ports", data.get("open_ports", []))
                if isinstance(stage_ports, list):
                    ports.extend(stage_ports)
    return ports


def _extract_vulns(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tüm tarama kaynaklarından zafiyet bilgilerini topla."""
    vulns = []
    for key in ["vuln_scan", "vuln_scan_full"]:
        stage_data = scan_results.get(key, {})
        if isinstance(stage_data, dict):
            data = stage_data.get("data", stage_data)
            if isinstance(data, dict):
                findings = data.get("findings", [])
                if isinstance(findings, list):
                    vulns.extend(findings)
    return vulns


def _detect_anomalies(
    scan_results: Dict[str, Any],
    open_ports: Set[int],
    ports_data: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Anomali pattern'lerini tespit et."""
    anomalies = []

    # 1. High port cluster (10000+ portlarında 3+ servis)
    high_ports = {p for p in open_ports if p >= 10000}
    if len(high_ports) >= 3:
        anomalies.append({
            "type": "high_port_cluster",
            "severity": "high",
            "ports": sorted(high_ports),
            "description": (
                f"{len(high_ports)} adet yüksek port (10000+) açık. "
                "C2 sunucu, backdoor veya tünelleme olabilir."
            ),
        })

    # 2. CDN bypass + exposed services
    recon_data = scan_results.get("recon", scan_results.get("recon_fingerprint", {}))
    if isinstance(recon_data, dict) and recon_data.get("data"):
        recon_data = recon_data["data"]

    origin_data = scan_results.get("origin_discovery", {})
    if isinstance(origin_data, dict) and origin_data.get("data"):
        origin_data = origin_data["data"]

    is_behind_cdn = recon_data.get("is_behind_cdn", False) if isinstance(recon_data, dict) else False
    has_real_ip = isinstance(origin_data, dict) and bool(origin_data.get("best_candidate"))

    dangerous_ports = {3389, 445, 135, 139, 1433, 3306, 5432, 27017, 6379, 9200}
    exposed_dangerous = dangerous_ports & open_ports

    if is_behind_cdn and has_real_ip and exposed_dangerous:
        anomalies.append({
            "type": "cdn_bypass_exposed",
            "severity": "critical",
            "ports": sorted(exposed_dangerous),
            "description": (
                f"CDN/WAF arkasında gerçek IP keşfedildi ve {len(exposed_dangerous)} "
                f"tehlikeli port açık: {sorted(exposed_dangerous)}. "
                "CDN koruması etkisiz hale geçmiş olabilir."
            ),
        })

    # 3. Multiple admin panels
    admin_ports = {8080, 8443, 9090, 9443, 8888, 3000, 5000}
    exposed_admin = admin_ports & open_ports
    if len(exposed_admin) >= 3:
        anomalies.append({
            "type": "admin_panels",
            "severity": "high",
            "ports": sorted(exposed_admin),
            "description": (
                f"{len(exposed_admin)} yönetim paneli portu açık. "
                "Çok geniş saldırı yüzeyi."
            ),
        })

    # 4. Debug/profiling ports
    debug_ports = {9090, 9229, 5005, 4848, 8000, 5858, 9999, 1099}
    exposed_debug = debug_ports & open_ports
    if exposed_debug:
        anomalies.append({
            "type": "debug_ports",
            "severity": "critical",
            "ports": sorted(exposed_debug),
            "description": (
                f"Debug/profiling portları internete açık: {sorted(exposed_debug)}. "
                "Kimliksiz uzaktan kod çalıştırma riski."
            ),
        })

    # 5. Mixed OS services
    windows_indicators = {445, 135, 139, 3389, 1433}
    linux_indicators = {22}
    has_windows = bool(windows_indicators & open_ports)
    has_linux = bool(linux_indicators & open_ports)
    if has_windows and has_linux:
        anomalies.append({
            "type": "mixed_os",
            "severity": "medium",
            "description": (
                "Aynı host'ta hem Windows (SMB/RDP) hem Linux (SSH) servisleri. "
                "VM, konteyner veya pivot noktası olabilir."
            ),
        })

    return anomalies
