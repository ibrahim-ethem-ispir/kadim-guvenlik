"""
Kadim Güvenlik - v2 Tarama Profilleri  [DONDURULDU]
=====================================================
⚠️  TEK DOKTRIN GEÇİŞİ (docs/TEK-DOKTRIN-GECIS-TASARIMI.md):
    Statik profiller EMEKLİYE AYRILDI. Varsayılan yolda ARTIK KULLANILMAZLAR —
    her tarama otonom motordan (Kuşatma Doktrini / attack_graph) geçer.

    Buradaki PROFILES sözlüğü YALNIZCA geri-alma güvencesi için tutulur:
    LEGACY_PROFILES_ENABLED=true olduğunda eski statik yol yeniden devreye girer.

    ➜ YENİ ÖZELLİK EKLEME. Bunun yerine seviyeleri (recon/standard/deep) ve
      otonom motoru (autonomous_engine.py / attack_graph.py) geliştir.
    ➜ Profil→seviye eşlemesi: PROFILE_TO_LEVEL (aşağıda).

Türkçe: Her profil hangi toolların hangi sırada çalışacağını tanımlar (legacy).
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


# ============================================================
# TEK DOKTRIN GEÇİŞİ (docs/TEK-DOKTRIN-GECIS-TASARIMI.md §3-§4)
# Statik profiller emekliye ayrıldı. Varsayılan: her tarama otonom motordan geçer.
# Eski statik yolu geri açmak için LEGACY_PROFILES_ENABLED=true (geri-alma güvencesi).
# ============================================================

LEGACY_PROFILES_ENABLED = os.getenv("LEGACY_PROFILES_ENABLED", "false").lower() == "true"

# Eski profil adı -> yeni otonom seviye. Bilinmeyen profil güvenli varsayılana (standard) düşer.
PROFILE_TO_LEVEL: Dict[str, str] = {
    # Keşif — pasif harita
    "quick": "recon",
    "recon_only": "recon",
    # Standart — hedefli zafiyet taraması
    "normal": "standard",
    "web": "standard",
    "infra": "standard",
    "cf_bypass": "standard",
    "stealth": "standard",   # stealth artık bir kip bayrağı (nmap -T2), seviye değil
    # Derin — fuzz + tam derinlik
    "full": "deep",
    "lazarus": "deep",
}


def profile_to_level(profile_name: str) -> str:
    """Eski profil adını otonom seviyeye çevirir (varsayılan: standard)."""
    return PROFILE_TO_LEVEL.get((profile_name or "").lower(), "standard")


class ScanProfileType(str, Enum):
    """Tarama profil tipleri"""
    QUICK = "quick"
    NORMAL = "normal"
    FULL = "full"
    STEALTH = "stealth"
    WEB = "web"
    INFRA = "infra"
    CF_BYPASS = "cf_bypass"
    LAZARUS = "lazarus"
    RECON_ONLY = "recon_only"


@dataclass
class StageDefinition:
    """Bir pipeline aşamasının tanımı"""
    name: str                         # Aşama adı (discovery, enumeration, vuln_scan, ...)
    tool: str                         # Kullanılacak tool (nmap, nuclei, subfinder, ...)
    options: Dict[str, Any]           # Tool'a gönderilecek opsiyonlar
    timeout_seconds: int = 600        # Bu aşama için max timeout
    required: bool = True             # Başarısız olursa pipeline dursun mu?
    depends_on: Optional[str] = None  # Hangi aşamadan sonra çalışsın (None = önceki)
    parallel_group: Optional[str] = None  # Aynı gruptakiler paralel çalışır


@dataclass
class ScanProfile:
    """Tam bir tarama profili"""
    name: str
    description: str
    stages: List[StageDefinition]
    estimated_duration_minutes: int = 5
    ai_analysis_enabled: bool = True


# ============================================================
# PROFIL TANIMLARI
# ============================================================

PROFILES: Dict[str, ScanProfile] = {

    # ---- QUICK: Hızlı tarama (2-3 dk) ----
    "quick": ScanProfile(
        name="Hızlı Tarama",
        description="Top 100 port + kritik/yüksek zafiyet taraması",
        estimated_duration_minutes=3,
        stages=[
            StageDefinition(
                name="port_scan",
                tool="nmap",
                options={
                    "preset": "default",
                    "--top-ports": 100,
                    "-sV": True,
                },
                timeout_seconds=120,
            ),
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high"],
                    "rate_limit": 300,
                    "exclude_tags": ["dos", "fuzz"],
                },
                timeout_seconds=300,
            ),
        ],
    ),

    # ---- NORMAL: Standart tarama (5-10 dk) ----
    "normal": ScanProfile(
        name="Normal Tarama",
        description="Top 1000 port + tüm zafiyetler + subdomain keşfi",
        estimated_duration_minutes=8,
        stages=[
            StageDefinition(
                name="subdomain_discovery",
                tool="subfinder",
                options={},
                timeout_seconds=120,
                required=False,
                parallel_group="discovery",
            ),
            StageDefinition(
                name="port_scan",
                tool="nmap",
                options={
                    "preset": "default",
                    "--top-ports": 1000,
                    "-sV": True,
                    "-sC": True,
                },
                timeout_seconds=300,
                parallel_group="discovery",
            ),
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium"],
                    "rate_limit": 150,
                    "exclude_tags": ["dos", "fuzz"],
                },
                timeout_seconds=600,
            ),
        ],
    ),

    # ---- FULL: Tam tarama (15-30 dk) ----
    "full": ScanProfile(
        name="Tam Tarama",
        description="Tüm portlar + tüm zafiyetler + OSINT + fuzzing",
        estimated_duration_minutes=25,
        stages=[
            StageDefinition(
                name="subdomain_discovery",
                tool="subfinder",
                options={"recursive": True},
                timeout_seconds=180,
                required=False,
                parallel_group="discovery",
            ),
            StageDefinition(
                name="port_scan",
                tool="nmap",
                options={
                    "preset": "aggressive",
                    "-p-": True,
                    "-sV": True,
                    "-sC": True,
                    "-O": True,
                },
                # Tüm 65535 port + agresif (-A) + servis/versiyon → dakikalar sürer; 900s
                # yetmiyordu. Timeout'ta artık kısmi portlar kurtarılıyor ama yeterli süre ver.
                timeout_seconds=2400,
                parallel_group="discovery",
            ),
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium", "low"],
                    "rate_limit": 100,
                    "exclude_tags": ["dos"],
                },
                timeout_seconds=1800,
            ),
            StageDefinition(
                name="fuzz",
                tool="fuzz",
                options={},
                timeout_seconds=600,
                required=False,
            ),
        ],
    ),

    # ---- STEALTH: Gizli tarama (10-20 dk) ----
    "stealth": ScanProfile(
        name="Gizli Tarama",
        description="Yavaş ve sessiz - IDS/IPS tetiklemez",
        estimated_duration_minutes=15,
        stages=[
            StageDefinition(
                name="subdomain_discovery",
                tool="subfinder",
                options={},
                timeout_seconds=120,
                required=False,
            ),
            StageDefinition(
                name="port_scan",
                tool="nmap",
                options={
                    "preset": "stealth",
                    "-sS": True,
                    "--top-ports": 1000,
                    "-T2": True,
                    "--max-retries": 1,
                },
                timeout_seconds=600,
            ),
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high"],
                    "rate_limit": 30,
                    "exclude_tags": ["dos", "fuzz", "intrusive"],
                },
                timeout_seconds=900,
            ),
        ],
    ),

    # ---- WEB: Web uygulaması odaklı (10-15 dk) ----
    "web": ScanProfile(
        name="Web Taraması",
        description="Web portları + web zafiyetleri + dizin keşfi",
        estimated_duration_minutes=12,
        stages=[
            StageDefinition(
                name="subdomain_discovery",
                tool="subfinder",
                options={},
                timeout_seconds=120,
                required=False,
                parallel_group="discovery",
            ),
            StageDefinition(
                name="port_scan",
                tool="nmap",
                options={
                    "-p": "80,443,8080,8443,8000,8888,3000,5000,9090",
                    "-sV": True,
                    "-sC": True,
                },
                timeout_seconds=180,
                parallel_group="discovery",
            ),
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium"],
                    "tags": ["cve", "misconfig", "default-login", "exposure",
                             "xss", "sqli", "lfi", "ssrf", "rce",
                             "wordpress", "joomla", "drupal"],
                    "rate_limit": 150,
                    "exclude_tags": ["dos", "fuzz"],
                },
                timeout_seconds=900,
            ),
            StageDefinition(
                name="fuzz",
                tool="fuzz",
                options={},
                timeout_seconds=600,
                required=False,
            ),
        ],
    ),

    # ---- INFRA: Altyapı odaklı (10-20 dk) ----
    "infra": ScanProfile(
        name="Altyapı Taraması",
        description="Tüm portlar + ağ servisleri + OS tespiti",
        estimated_duration_minutes=18,
        stages=[
            StageDefinition(
                name="port_scan",
                tool="nmap",
                options={
                    "-p-": True,
                    "-sV": True,
                    "-sC": True,
                    "-O": True,
                    "--script": "vuln,auth,default",
                },
                # Tüm 65535 port + servis/versiyon/OS → 900s yetmiyordu (timeout'ta 0 port).
                timeout_seconds=2400,
            ),
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium"],
                    "tags": ["cve", "misconfig", "default-login",
                             "ssh", "ftp", "smb", "rdp", "database",
                             "network"],
                    "rate_limit": 100,
                    "exclude_tags": ["dos", "fuzz"],
                },
                timeout_seconds=1200,
            ),
        ],
    ),

    # ============================================================
    # APT SİMÜLASYON PROFİLİ - Gelişmiş Tehdit Aktörü Taraması
    # ============================================================

    # ---- APT: Advanced Persistent Threat simülasyonu (20-40 dk) ----
    "apt": ScanProfile(
        name="APT Simülasyonu",
        description=(
            "Gelişmiş tehdit aktörü simülasyonu: Recon → CF Bypass → "
            "Gerçek IP Tespiti → Direkt Port Scan → OSINT İstihbarat → "
            "Zafiyet Taraması → Fuzzing. Lazarus/APT28 tarzı metodoloji."
        ),
        estimated_duration_minutes=35,
        stages=[
            # FAZA 1: Pasif İstihbarat (paralel)
            StageDefinition(
                name="recon_fingerprint",
                tool="recon",
                options={
                    "wordlist": "files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt",
                    "concurrency": 80,
                    "delay_ms": 0,
                    "timeout_minutes": 8,
                },
                timeout_seconds=600,
                required=False,  # Recon başarısız olsa bile tarama devam etmeli
                parallel_group="passive_recon",
            ),
            StageDefinition(
                name="subdomain_enum",
                tool="subfinder",
                options={"recursive": True},
                timeout_seconds=180,
                required=False,
                parallel_group="passive_recon",
            ),
            StageDefinition(
                name="osint_intelligence",
                tool="osint",
                options={
                    "lookups": ["dns", "whois", "ssl", "shodan", "virustotal", "abuseipdb"],
                },
                timeout_seconds=120,
                required=False,
                parallel_group="passive_recon",
            ),

            # FAZA 2: Gerçek IP üzerinde agresif tarama
            # (recon'dan bulunan IP'yi otomatik kullanır)
            StageDefinition(
                name="direct_ip_scan",
                tool="nmap_real_ip",
                options={
                    "preset": "aggressive",
                    "-p-": True,
                    "-sV": True,
                    "-sC": True,
                    "-O": True,
                    "--script": "vuln,auth,default,exploit",
                },
                timeout_seconds=900,
            ),

            # FAZA 3: Domain üzerinden de tarama (WAF arkası)
            StageDefinition(
                name="domain_port_scan",
                tool="nmap",
                options={
                    "preset": "default",
                    "--top-ports": 1000,
                    "-sV": True,
                    "-sC": True,
                },
                timeout_seconds=300,
                required=False,
                parallel_group="active_scan",
            ),
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium", "low"],
                    "tags": [
                        "cve", "misconfig", "default-login", "exposure",
                        "xss", "sqli", "lfi", "ssrf", "rce", "rfi",
                        "idor", "ssti", "xxe", "deserialization",
                        "wordpress", "joomla", "drupal", "laravel",
                        "spring", "struts", "tomcat", "nginx", "apache",
                        "ssh", "ftp", "smb", "rdp", "database",
                        "network", "cloud", "aws", "azure", "gcp",
                    ],
                    "rate_limit": 100,
                    "exclude_tags": ["dos"],
                },
                timeout_seconds=1800,
                parallel_group="active_scan",
            ),

            # FAZA 4: Endpoint keşfi
            StageDefinition(
                name="endpoint_discovery",
                tool="fuzz",
                options={
                    "wordlist": "common.txt",
                },
                timeout_seconds=600,
                required=False,
            ),
        ],
    ),

    # ---- DEEP: Derin analiz (her şeyi kullanır, 45+ dk) ----
    "deep": ScanProfile(
        name="Derin Analiz",
        description=(
            "Tüm araçlar + OSINT istihbarat + CF bypass + "
            "agresif zafiyet taraması. En kapsamlı profil."
        ),
        estimated_duration_minutes=50,
        stages=[
            # Pasif faz
            StageDefinition(
                name="recon_fingerprint",
                tool="recon",
                options={
                    "wordlist": "files/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt",
                    "concurrency": 100,
                    "timeout_minutes": 12,
                },
                timeout_seconds=900,
                required=False,  # Recon başarısız olsa bile tarama devam etmeli
                parallel_group="recon_phase",
            ),
            StageDefinition(
                name="subdomain_enum",
                tool="subfinder",
                options={"recursive": True},
                timeout_seconds=300,
                required=False,
                parallel_group="recon_phase",
            ),
            StageDefinition(
                name="osint_full",
                tool="osint",
                options={
                    "lookups": ["dns", "whois", "ssl", "shodan", "virustotal", "abuseipdb"],
                },
                timeout_seconds=180,
                required=False,
                parallel_group="recon_phase",
            ),
            # Gerçek IP tarama
            StageDefinition(
                name="direct_ip_scan",
                tool="nmap_real_ip",
                options={
                    "preset": "aggressive",
                    "-p-": True,
                    "-sV": True,
                    "-sC": True,
                    "-O": True,
                    "--script": "vuln,auth,default,exploit",
                },
                timeout_seconds=1200,
            ),
            # RustScan ile hızlı port keşfi (tüm 65535 port)
            StageDefinition(
                name="fast_port_scan",
                tool="rustscan",
                options={},
                timeout_seconds=300,
                required=False,
                parallel_group="active_phase",
            ),
            # Domain port tarama
            StageDefinition(
                name="domain_port_scan",
                tool="nmap",
                options={
                    "preset": "default",
                    "--top-ports": 3000,
                    "-sV": True,
                    "-sC": True,
                },
                timeout_seconds=600,
                required=False,
                parallel_group="active_phase",
            ),
            # Agresif zafiyet taraması
            StageDefinition(
                name="vuln_scan_full",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium", "low"],
                    "rate_limit": 80,
                    "exclude_tags": ["dos"],
                },
                timeout_seconds=2400,
            ),
            # Endpoint keşfi
            StageDefinition(
                name="endpoint_fuzz",
                tool="fuzz",
                options={},
                timeout_seconds=900,
                required=False,
            ),
        ],
    ),

    # ---- CF_BYPASS: Cloudflare/WAF Bypass (10-15 dk) ----
    "cf_bypass": ScanProfile(
        name="Cloudflare Bypass",
        description="CDN/WAF arkasındaki gerçek IP'yi bul ve direkt tara. 8 farklı keşif tekniği.",
        estimated_duration_minutes=15,
        stages=[
            # 1. Origin Discovery - 8 teknikle gerçek IP bul
            StageDefinition(
                name="origin_discovery",
                tool="origin_discovery",
                options={},
                timeout_seconds=120,
                required=True,
            ),
            # 2. Recon fingerprint (paralel)
            StageDefinition(
                name="recon_fingerprint",
                tool="recon",
                options={
                    "concurrency": 30,
                    "delay_ms": 100,
                },
                timeout_seconds=180,
                required=False,
                parallel_group="initial_recon",
            ),
            # 3. Subdomain keşfi (paralel)
            StageDefinition(
                name="subdomain_enum",
                tool="subfinder",
                options={"recursive": True},
                timeout_seconds=180,
                required=False,
                parallel_group="initial_recon",
            ),
            # 4. Gerçek IP üzerinde port tarama
            StageDefinition(
                name="direct_ip_scan",
                tool="nmap_real_ip",
                options={
                    "preset": "aggressive",
                    "--top-ports": 3000,
                    "-sV": True,
                    "-sC": True,
                },
                timeout_seconds=900,
            ),
            # 5. Gerçek IP üzerinde zafiyet taraması
            StageDefinition(
                name="vuln_scan",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium"],
                    "rate_limit": 150,
                },
                timeout_seconds=1200,
            ),
            # 6. Endpoint keşfi
            StageDefinition(
                name="endpoint_fuzz",
                tool="fuzz",
                options={},
                timeout_seconds=600,
                required=False,
            ),
            # 7. OSINT
            StageDefinition(
                name="osint_intelligence",
                tool="osint",
                options={"lookups": ["shodan", "virustotal", "whois", "ssl"]},
                timeout_seconds=120,
                required=False,
            ),
        ],
    ),

    # ---- LAZARUS: Supply Chain APT Simülasyonu (25-35 dk) ----
    "lazarus": ScanProfile(
        name="Lazarus Simülasyonu",
        description="Supply chain + watering hole tarzı APT taraması. Origin keşfi, gizli servis analizi, tam zafiyet taraması.",
        estimated_duration_minutes=35,
        stages=[
            # 1. Pasif istihbarat
            StageDefinition(
                name="osint_intelligence",
                tool="osint",
                options={"lookups": ["whois", "ssl", "dns", "shodan", "virustotal"]},
                timeout_seconds=180,
                required=False,
                parallel_group="passive_recon",
            ),
            # 2. Subdomain keşfi (pasif - paralel)
            StageDefinition(
                name="subdomain_enum",
                tool="subfinder",
                options={"recursive": True},
                timeout_seconds=300,
                required=False,
                parallel_group="passive_recon",
            ),
            # 3. Origin Discovery
            StageDefinition(
                name="origin_discovery",
                tool="origin_discovery",
                options={},
                timeout_seconds=120,
            ),
            # 4. Recon fingerprint
            StageDefinition(
                name="recon_fingerprint",
                tool="recon",
                options={
                    "concurrency": 20,
                    "delay_ms": 200,  # Yavaş - tespit edilmemek için
                },
                timeout_seconds=300,
            ),
            # 5. Gerçek IP tarama (agresif)
            StageDefinition(
                name="direct_ip_scan",
                tool="nmap_real_ip",
                options={
                    "preset": "aggressive",
                    "-p-": True,
                    "-sV": True,
                    "-sC": True,
                    "-O": True,
                    "--script": "vuln,auth,default",
                },
                timeout_seconds=1500,
            ),
            # 6. Domain port tarama (paralel)
            StageDefinition(
                name="domain_port_scan",
                tool="nmap",
                options={
                    "preset": "default",
                    "--top-ports": 5000,
                    "-sV": True,
                },
                timeout_seconds=900,
                required=False,
                parallel_group="active_scan",
            ),
            # 7. RustScan paralel
            StageDefinition(
                name="fast_port_scan",
                tool="rustscan",
                options={},
                timeout_seconds=300,
                required=False,
                parallel_group="active_scan",
            ),
            # 8. Tam zafiyet taraması
            StageDefinition(
                name="vuln_scan_full",
                tool="nuclei",
                options={
                    "severity": ["critical", "high", "medium", "low"],
                    "rate_limit": 80,
                    "exclude_tags": ["dos"],
                },
                timeout_seconds=2400,
            ),
            # 9. Endpoint keşfi
            StageDefinition(
                name="endpoint_fuzz",
                tool="fuzz",
                options={},
                timeout_seconds=900,
                required=False,
            ),
        ],
    ),

    # ---- RECON_ONLY: Sadece İstihbarat (pasif, 3-5 dk) ----
    "recon_only": ScanProfile(
        name="Sadece İstihbarat",
        description="Hiçbir aktif tarama yok. Sadece pasif OSINT, DNS, CT logs, subdomain keşfi.",
        estimated_duration_minutes=5,
        stages=[
            # 1. OSINT
            StageDefinition(
                name="osint_intelligence",
                tool="osint",
                options={"lookups": ["whois", "ssl", "dns", "shodan", "virustotal"]},
                timeout_seconds=120,
                required=False,
                parallel_group="passive",
            ),
            # 2. Subdomain keşfi (paralel)
            StageDefinition(
                name="subdomain_enum",
                tool="subfinder",
                options={},
                timeout_seconds=180,
                required=False,
                parallel_group="passive",
            ),
            # 3. Origin Discovery (pasif teknikler)
            StageDefinition(
                name="origin_discovery",
                tool="origin_discovery",
                options={},
                timeout_seconds=120,
                required=False,
                parallel_group="passive",
            ),
            # 4. Recon fingerprint
            StageDefinition(
                name="recon_fingerprint",
                tool="recon",
                options={
                    "concurrency": 10,
                    "delay_ms": 500,
                },
                timeout_seconds=180,
                required=False,
            ),
        ],
    ),
}


def get_profile(profile_name: str) -> ScanProfile:
    """Profil adına göre profili döndür, yoksa normal kullan"""
    return PROFILES.get(profile_name, PROFILES["normal"])


def list_profiles() -> List[Dict[str, Any]]:
    """Tüm profilleri listele (frontend için)"""
    result = [
        {
            "id": key,
            "name": profile.name,
            "description": profile.description,
            "estimated_minutes": profile.estimated_duration_minutes,
            "stages_count": len(profile.stages),
            "tools": list(set(s.tool for s in profile.stages)),
        }
        for key, profile in PROFILES.items()
    ]
    # Otonom mod: statik stage listesi yok, motor (Kuşatma Doktrini / attack-graph) her adımı
    # kendi karar verir. start_pipeline() bu profili PROFILES dict'ine bakmadan özel yoldan yönlendirir.
    result.append({
        "id": "autonomous",
        "name": "🧠 Otonom Saldırı Simülasyonu (Kuşatma Doktrini)",
        "description": "Attack-graph tabanlı kuşatma stratejisi — dış saldırgan gibi kendi "
                        "kendine en zayıf noktayı bulur, kanıtlı zafiyet arar. Süre değişken.",
        "estimated_minutes": None,
        "stages_count": 0,
        "tools": ["dynamic"],
        "mode": "autonomous",
    })
    return result
