"""
Kadim Güvenlik - Adaptive Scanner Engine
Türkçe: AI destekli adaptif tarama karar motoru.

Bu modül tarama sonuçlarını değerlendirir ve otomatik olarak:
1. Ek tarama gereksinimi belirler
2. Nuclei template seçimi yapar (bulunan servislere göre)
3. Anomali tespiti yapar (beklenmeyen port/servis kombinasyonları)
4. Profil yükseltme kararı verir
5. Sonraki adım önerileri üretir

Entegrasyon:
    Pipeline her stage tamamlandığında AdaptiveScanner'a danışır.
    AI servisiyle konuşarak veya kural tabanlı mantıkla karar verir.

Gerçek Dünya Senaryoları:
    - Nmap Apache 2.4.51 buldu -> Nuclei CVE-2023-25690 template'i seç
    - Port 3306 açık + default creds -> Otomatik brute-force uyarısı
    - CF arkasında gerçek IP bulundu -> Profil otomatik "apt" seviyesine yükselt
    - Unusual port (4443, 9443) açık -> APT göstergesi uyarısı
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("adaptive-scanner")


# ============== Service-to-CVE Mapping ==============
# Gerçek dünyada sık exploit edilen servis-CVE eşlemeleri

SERVICE_VULNERABILITY_MAP: Dict[str, Dict[str, Any]] = {
    # Web Servers
    "apache": {
        "nuclei_tags": ["apache", "cve"],
        "critical_versions": {
            "2.4.49": ["CVE-2021-41773"],  # Path traversal + RCE
            "2.4.50": ["CVE-2021-42013"],  # Path traversal bypass
            "2.4.51": ["CVE-2023-25690"],  # HTTP Request Smuggling
            "2.4.52": ["CVE-2022-31813"],  # mod_proxy bypass
        },
        "always_check": ["mod_proxy", "mod_cgi", "mod_status", "server-status"],
        "risk_factor": 8,
    },
    "nginx": {
        "nuclei_tags": ["nginx", "cve"],
        "critical_versions": {
            "1.18": ["CVE-2021-23017"],   # DNS resolver vuln
        },
        "always_check": ["off-by-slash", "alias-traversal", "merge_slashes"],
        "risk_factor": 6,
    },
    "iis": {
        "nuclei_tags": ["iis", "microsoft", "cve"],
        "critical_versions": {
            "10.0": ["CVE-2021-31166"],   # HTTP Protocol Stack RCE
        },
        "always_check": ["shortname", "tilde", "webdav"],
        "risk_factor": 7,
    },

    # Application Frameworks
    "tomcat": {
        "nuclei_tags": ["tomcat", "cve", "default-login"],
        "critical_versions": {
            "9.0": ["CVE-2020-1938"],     # Ghostcat AJP
            "8.5": ["CVE-2020-1938"],
        },
        "always_check": ["manager", "host-manager", "ajp"],
        "risk_factor": 9,
    },
    "weblogic": {
        "nuclei_tags": ["weblogic", "oracle", "cve"],
        "critical_versions": {},  # Hepsi kritik
        "always_check": ["t3", "iiop", "console", "wls-wsat"],
        "risk_factor": 10,  # En yüksek - APT grupları sıkça hedefler
    },
    "jboss": {
        "nuclei_tags": ["jboss", "cve"],
        "always_check": ["jmx-console", "web-console", "invoker"],
        "risk_factor": 9,
    },
    "spring": {
        "nuclei_tags": ["spring", "springboot", "cve"],
        "critical_versions": {
            "spring-framework": ["CVE-2022-22965"],  # Spring4Shell
        },
        "always_check": ["actuator", "env", "heapdump"],
        "risk_factor": 8,
    },
    "laravel": {
        "nuclei_tags": ["laravel", "cve"],
        "always_check": ["debug-mode", "telescope", "env"],
        "risk_factor": 6,
    },
    "wordpress": {
        "nuclei_tags": ["wordpress", "wp-plugin", "cve"],
        "always_check": ["xmlrpc", "wp-json", "wp-cron", "wp-config"],
        "risk_factor": 7,
    },

    # ---- Modern Web/JS Framework'leri (recon/httpx teknoloji tespitinden gelir) ----
    # Bunlar nmap "servis adı" olarak DEĞİL, teknoloji fingerprint'i olarak görünür; bu yüzden
    # eskiden tabloda olmadıkları için nuclei HİÇ açılmıyordu (örn. Next.js CVE-2025-29927 gibi
    # kritik açıklar sessizce kaçıyordu). Artık tespit edilince HEDEFLİ nuclei tag taraması olur.
    "next.js": {  # tech-detect genelde "Next.js" döndürür
        "nuclei_tags": ["nextjs", "next.js", "cve"],
        "critical_versions": {},  # sürüm-bağımsız; middleware/SSRF sınıfı açıklar
        "always_check": ["middleware-bypass", "image-optimization-ssrf", "_next"],
        "risk_factor": 8,
    },
    "nextjs": {
        "nuclei_tags": ["nextjs", "next.js", "cve"],
        "always_check": ["middleware-bypass", "_next"],
        "risk_factor": 8,
    },
    "react": {
        "nuclei_tags": ["react", "javascript", "exposure"],
        "always_check": ["source-map", "env-exposure"],
        "risk_factor": 5,
    },
    "node.js": {
        "nuclei_tags": ["nodejs", "node", "express", "cve"],
        "always_check": ["debug-endpoint", "prototype-pollution"],
        "risk_factor": 7,
    },
    "express": {
        "nuclei_tags": ["express", "nodejs", "cve"],
        "always_check": ["debug", "x-powered-by"],
        "risk_factor": 6,
    },
    "django": {
        "nuclei_tags": ["django", "python", "cve"],
        "always_check": ["debug-mode", "admin", "settings-exposure"],
        "risk_factor": 7,
    },
    "flask": {
        "nuclei_tags": ["flask", "python", "werkzeug", "cve"],
        "always_check": ["debug-console", "werkzeug"],
        "risk_factor": 6,
    },
    "graphql": {
        "nuclei_tags": ["graphql", "api", "cve"],
        "always_check": ["introspection", "graphiql", "batching"],
        "risk_factor": 7,
        "apt_indicator": True,
    },
    "vercel": {
        "nuclei_tags": ["nextjs", "vercel", "cve"],
        "always_check": ["_next", "middleware-bypass"],
        "risk_factor": 7,
    },
    "vue": {
        "nuclei_tags": ["vue", "javascript", "exposure"],
        "always_check": ["source-map"],
        "risk_factor": 5,
    },
    "angular": {
        "nuclei_tags": ["angular", "javascript", "exposure"],
        "always_check": ["source-map"],
        "risk_factor": 5,
    },

    # Databases
    "mysql": {
        "nuclei_tags": ["mysql", "database", "default-login"],
        "always_check": ["default_creds", "remote_access"],
        "risk_factor": 9,
        "apt_indicator": True,  # Açık DB = yüksek risk
    },
    "postgresql": {
        "nuclei_tags": ["postgres", "database", "default-login"],
        "always_check": ["default_creds", "trust_auth"],
        "risk_factor": 9,
        "apt_indicator": True,
    },
    "mongodb": {
        "nuclei_tags": ["mongodb", "database"],
        "always_check": ["no_auth", "remote_access"],
        "risk_factor": 9,
        "apt_indicator": True,
    },
    "redis": {
        "nuclei_tags": ["redis"],
        "always_check": ["no_auth", "rce_via_slave"],
        "risk_factor": 9,
        "apt_indicator": True,
    },
    "elasticsearch": {
        "nuclei_tags": ["elasticsearch", "elastic"],
        "always_check": ["no_auth", "indices", "kibana"],
        "risk_factor": 8,
        "apt_indicator": True,
    },

    # Remote Access
    "ssh": {
        "nuclei_tags": ["ssh"],
        "always_check": ["weak_ciphers", "password_auth", "root_login"],
        "risk_factor": 5,
    },
    "rdp": {
        "nuclei_tags": ["rdp", "bluekeep"],
        "critical_versions": {},
        "always_check": ["bluekeep", "nla"],
        "risk_factor": 8,
        "apt_indicator": True,
    },
    "ftp": {
        "nuclei_tags": ["ftp", "default-login"],
        "always_check": ["anonymous", "default_creds"],
        "risk_factor": 6,
    },
    "smb": {
        "nuclei_tags": ["smb", "samba", "eternalblue"],
        "always_check": ["ms17-010", "null_session", "signing"],
        "risk_factor": 9,
        "apt_indicator": True,  # Lateral movement vektörü
    },

    # Mail
    "smtp": {
        "nuclei_tags": ["smtp", "mail"],
        "always_check": ["open_relay", "vrfy", "expn"],
        "risk_factor": 5,
    },

    # ============================================================
    # K8s / KONTEYNER ALTYAPISI — nmap -sV 6443'te "ssl/kubernetes" raporlar; tabloda
    # olmadığından eskiden hedefli nuclei tag'i HİÇ açılmıyordu (kubernetes-*
    # misconfig template'leri kaçıyordu). Kontrol düzlemi açıksa tüm küme riskli.
    # ============================================================
    "kubernetes": {  # kube-apiserver (6443/8443)
        "nuclei_tags": ["kubernetes", "cve"],
        "always_check": ["anonymous-access", "exposed-apiserver", "secrets"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1613"],  # Container and Resource Discovery
    },
    "kubelet": {
        "nuclei_tags": ["kubernetes", "cve"],
        "always_check": ["pods", "exec", "anonymous-auth"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1613", "T1610"],  # Discovery + Deploy Container
    },
    "etcd": {
        "nuclei_tags": ["etcd", "kubernetes"],
        "always_check": ["no_auth", "v2-keys", "version"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1552"],  # Unsecured Credentials
    },
    "rancher": {  # Rancher / RKE2 yönetim düzlemi (8443 UI, 9345 supervisor)
        "nuclei_tags": ["rancher", "cve", "default-login"],
        "always_check": ["default-admin", "v3-api", "dashboard"],
        "risk_factor": 8,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],  # Exploit Public-Facing Application
    },
    "rke2": {  # nmap product "RKE2" dönerse
        "nuclei_tags": ["rancher", "kubernetes", "cve"],
        "always_check": ["supervisor-9345"],
        "risk_factor": 8,
        "apt_indicator": True,
        "attack_techniques": ["T1190", "T1613"],
    },
    "k3s": {
        "nuclei_tags": ["kubernetes", "cve"],
        "always_check": ["anonymous-access"],
        "risk_factor": 8,
        "apt_indicator": True,
        "attack_techniques": ["T1613"],
    },

    # ============================================================
    # MODERN BREACH VEKİLLERİ (FAZ 1.1) — 2023-2026 kurumsal/banka ihlallerinin
    # büyük kısmı bu "perimeter appliance"/kurumsal uygulamalardan girdi. Tabloda
    # olmadıkları için nuclei HİÇ hedefli açılmıyordu. apt_groups/attack_techniques
    # alanları Evidence zenginleştirmesini (MITRE ATT&CK + tehdit aktörü) besler.
    # YENİ alanlar OPSİYONEL — eski servisler .get(...) deseniyle okunduğundan bozulmaz.
    # ============================================================
    "confluence": {
        "nuclei_tags": ["confluence", "atlassian", "cve"],
        "critical_versions": {
            "8.5": ["CVE-2023-22515", "CVE-2023-22518"],  # Broken access ctrl + improper auth
            "8.0": ["CVE-2024-21671"],
            "7.": ["CVE-2022-26134"],                       # OGNL RCE (Volt Typhoon vekili)
        },
        "always_check": ["setup", "admin", "server-info", "rest-api"],
        "risk_factor": 10,
        "apt_groups": ["Storm-0062", "Akira", "Volt Typhoon"],
        "attack_techniques": ["T1190"],  # Exploit Public-Facing Application
    },
    "fortinet": {  # FortiOS / FortiGate SSL-VPN
        "nuclei_tags": ["fortinet", "fortios", "fortigate", "cve"],
        "critical_versions": {
            "7.": ["CVE-2024-21762", "CVE-2024-55591"],   # SSL-VPN OOB write / auth bypass
            "6.": ["CVE-2022-40684", "CVE-2018-13379"],   # Auth bypass / path traversal
        },
        "always_check": ["ssl-vpn", "remote", "logincheck"],
        "risk_factor": 10,
        "apt_groups": ["Volt Typhoon", "UNC3886", "Akira"],
        "attack_techniques": ["T1190", "T1133"],  # Public-facing + External Remote Services
    },
    "citrix_netscaler": {  # Citrix ADC / NetScaler Gateway
        "nuclei_tags": ["citrix", "netscaler", "cve"],
        "critical_versions": {
            "13.": ["CVE-2023-4966", "CVE-2023-3519"],    # CitrixBleed / unauth RCE
            "14.": ["CVE-2023-4966"],
        },
        "always_check": ["vpn", "nsgw", "logon", "citrix"],
        "risk_factor": 10,
        "apt_groups": ["APT5", "LockBit", "FIN8"],
        "attack_techniques": ["T1190", "T1552"],  # Public-facing + Unsecured Credentials
    },
    "vmware_esxi": {
        "nuclei_tags": ["vmware", "esxi", "vcenter", "cve"],
        "critical_versions": {
            "7.": ["CVE-2021-21985", "CVE-2023-20887"],   # vCenter RCE
            "6.": ["CVE-2021-21972"],                      # vSphere Client RCE (ESXiArgs)
        },
        "always_check": ["ui", "sdk", "vsphere", "slp"],
        "risk_factor": 10,
        "apt_groups": ["ESXiArgs", "ALPHV/BlackCat", "Royal"],
        "attack_techniques": ["T1190"],
    },
    "ivanti": {  # Ivanti Connect Secure / Policy Secure VPN
        "nuclei_tags": ["ivanti", "pulse", "connect-secure", "cve"],
        "critical_versions": {
            "9.": ["CVE-2023-46805", "CVE-2024-21887"],   # Auth bypass + command injection zinciri
            "22.": ["CVE-2024-21887", "CVE-2025-0282"],
        },
        "always_check": ["dana-na", "api", "auth"],
        "risk_factor": 10,
        "apt_groups": ["UNC5221", "Volt Typhoon"],
        "attack_techniques": ["T1190", "T1133"],
    },
    "f5_bigip": {
        "nuclei_tags": ["f5", "bigip", "cve"],
        "critical_versions": {
            "16.": ["CVE-2022-1388", "CVE-2023-46747"],   # iControl REST auth bypass RCE
            "15.": ["CVE-2020-5902"],                      # TMUI RCE
        },
        "always_check": ["tmui", "mgmt", "icontrol", "rest"],
        "risk_factor": 10,
        "apt_groups": ["APT (çeşitli)", "fidanı geniş exploit"],
        "attack_techniques": ["T1190"],
    },
    "cisco_asa": {  # Cisco ASA / AnyConnect
        "nuclei_tags": ["cisco", "asa", "anyconnect", "cve"],
        "critical_versions": {
            "9.": ["CVE-2020-3452", "CVE-2018-0101"],      # Path traversal / RCE+DoS
        },
        "always_check": ["+CSCOE+", "webvpn", "anyconnect"],
        "risk_factor": 9,
        "apt_groups": ["Akira", "Lazarus"],
        "attack_techniques": ["T1190", "T1133"],
    },
    "exchange": {  # Microsoft Exchange
        "nuclei_tags": ["exchange", "microsoft", "owa", "cve"],
        "critical_versions": {
            "2019": ["CVE-2021-26855", "CVE-2021-34473"],  # ProxyLogon / ProxyShell
            "2016": ["CVE-2021-26855", "CVE-2022-41040"],  # ProxyLogon / ProxyNotShell
            "2013": ["CVE-2021-26855"],
        },
        "always_check": ["owa", "ecp", "autodiscover", "mapi"],
        "risk_factor": 10,
        "apt_groups": ["HAFNIUM", "Storm-0558", "APT28"],
        "attack_techniques": ["T1190", "T1114"],  # Public-facing + Email Collection
    },

    # ============================================================
    # 2026 CEPHESI — AI/AGENTIC YIĞIN (en hızlı büyüyen, funnel'ın kör noktası)
    # Bu ürünler meta-generator/Server header yazmaz; path_probe _MODERN_STACK_SIGNATURES
    # ile TESPİT edilip buraya düşer → nuclei tag + KEV ürün-taraması + NVD zinciri açılır.
    # Sürüm çoğu zaman ifşa EDİLMEZ; critical_versions boş bırakıldı, kanıt nuclei/KEV'e devir.
    # ============================================================
    "langflow": {
        "nuclei_tags": ["langflow", "cve"],
        "critical_versions": {},  # CVE-2025-3248 (auth bypass RCE), CVE-2026-33017 — sürümsüz KEV
        "always_check": ["api/v1", "auth-bypass", "code-execution"],
        "risk_factor": 10,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "n8n": {
        "nuclei_tags": ["n8n", "cve"],
        "always_check": ["rest", "credentials", "webhook"],
        "risk_factor": 8,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "flowise": {
        "nuclei_tags": ["flowise", "cve"],
        "always_check": ["api/v1", "credentials"],
        "risk_factor": 8,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "comfyui": {
        "nuclei_tags": ["comfyui", "exposure", "cve"],
        "always_check": ["object-info", "userdata"],
        "risk_factor": 7,
        "attack_techniques": ["T1190"],
    },
    "marimo": {
        "nuclei_tags": ["marimo", "cve"],
        "always_check": ["ws", "code-execution"],
        "risk_factor": 8,
        "attack_techniques": ["T1190"],
    },
    "ollama": {
        "nuclei_tags": ["ollama", "exposure", "cve"],
        "always_check": ["api/tags", "no_auth", "model-pull"],
        "risk_factor": 7,
        "apt_indicator": True,
        "attack_techniques": ["T1190", "T1552"],
    },
    "sglang": {
        "nuclei_tags": ["sglang", "cve"],
        "always_check": ["code-execution"],
        "risk_factor": 8,
        "attack_techniques": ["T1190"],
    },
    "jupyter": {
        "nuclei_tags": ["jupyter", "exposure", "cve"],
        "always_check": ["no_auth", "terminals", "notebook-rce"],
        "risk_factor": 8,
        "apt_indicator": True,
        "attack_techniques": ["T1190", "T1059"],  # Public-facing + Command Execution
    },

    # ============================================================
    # 2026 CEPHESI — NİŞ KURUMSAL / YÖNETİM DÜZLEMİ (KEV'de yoğun; funnel kör)
    # ============================================================
    "metabase": {
        "nuclei_tags": ["metabase", "cve"],
        "critical_versions": {},  # CVE-2023-38646 pre-auth RCE, CVE-2026-72898 SQLi (KEV)
        "always_check": ["api/session/properties", "setup-token", "sqli"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "teamcity": {
        "nuclei_tags": ["teamcity", "jetbrains", "cve"],
        "critical_versions": {},  # CVE-2024-27198/27199 auth bypass, CVE-2026-63077 deser (KEV)
        "always_check": ["app/rest/server", "auth-bypass", "debug"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "coldfusion": {
        "nuclei_tags": ["coldfusion", "adobe", "cve"],
        "critical_versions": {},  # CVE-2023-26360 RCE, CVE-2026-48282 aktif sömürü
        "always_check": ["CFIDE", "administrator", "deserialization"],
        "risk_factor": 10,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "gitlab": {
        "nuclei_tags": ["gitlab", "cve"],
        "always_check": ["users/sign_in", "explore", "graphql"],
        "risk_factor": 8,
        "attack_techniques": ["T1190"],
    },
    "grafana": {
        "nuclei_tags": ["grafana", "cve"],
        "critical_versions": {},  # CVE-2021-43798 path traversal (klasik)
        "always_check": ["public/plugins", "api/datasources", "path-traversal"],
        "risk_factor": 7,
        "attack_techniques": ["T1190"],
    },
    "jenkins": {
        "nuclei_tags": ["jenkins", "cve", "default-login"],
        "critical_versions": {},  # CVE-2024-23897 arbitrary file read
        "always_check": ["script", "asynchPeople", "cli", "file-read"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "kibana": {
        "nuclei_tags": ["kibana", "elastic", "cve"],
        "always_check": ["api/status", "no_auth"],
        "risk_factor": 7,
        "attack_techniques": ["T1190"],
    },
    "sharepoint": {
        "nuclei_tags": ["sharepoint", "microsoft", "cve"],
        "critical_versions": {},  # ToolShell serisi CVE-2026-45659/50522 (KEV) — deser probe teyit eder
        "always_check": ["_layouts", "_vti_bin", "toolpane", "deserialization"],
        "risk_factor": 10,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "loadmaster": {  # Progress Kemp LoadMaster (CVE-2026-8037 command inj, KEV %99 exploit)
        "nuclei_tags": ["loadmaster", "kemp", "cve"],
        "always_check": ["access", "command-injection"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1190"],
    },
    "simplehelp": {  # SimpleHelp RMM (CVE-2026-48558 auth bypass 0-day)
        "nuclei_tags": ["simplehelp", "cve"],
        "always_check": ["auth-bypass", "path-traversal"],
        "risk_factor": 9,
        "apt_indicator": True,
        "attack_techniques": ["T1190", "T1133"],
    },
}

# ============== Anomaly Detection Patterns ==============

# APT gruplarının tipik port/servis imzaları
APT_PORT_SIGNATURES = {
    "lazarus_typical": {
        "description": "Lazarus Group tipik hedef profili",
        "indicators": [
            {"ports": [443, 8443, 4443], "weight": 5},  # Atypik HTTPS portları
            {"services": ["weblogic", "struts"], "weight": 8},
            {"services": ["java", "tomcat"], "weight": 3},
        ],
    },
    "apt28_typical": {
        "description": "APT28 (Fancy Bear) tipik hedef profili",
        "indicators": [
            {"services": ["exchange", "owa"], "weight": 8},
            {"ports": [25, 587, 993], "weight": 3},  # Mail servisleri
            {"services": ["vpn", "cisco", "fortinet"], "weight": 7},
        ],
    },
    "generic_exposed": {
        "description": "Genel yüksek riskli yapılandırma",
        "indicators": [
            {"ports": [3306, 5432, 27017, 6379], "weight": 9},  # Açık DB
            {"ports": [9200, 9300], "weight": 8},  # Elasticsearch
            {"ports": [2375, 2376], "weight": 10},  # Docker API!
            {"ports": [5900, 5901], "weight": 7},  # VNC
            {"ports": [11211], "weight": 7},  # Memcached
        ],
    },
    "cf_bypass_indicators": {
        "description": "Cloudflare bypass başarılı göstergeleri",
        "indicators": [
            {"condition": "real_ip_found", "weight": 10},
            {"condition": "origin_ports_differ_from_domain", "weight": 8},
            {"condition": "ip_direct_access_200", "weight": 9},
        ],
    },
}

# Servis-port uyumsuzluğu (anomali göstergesi)
UNEXPECTED_PORT_SERVICES = {
    # Port X'te servis Y beklenmiyor -> anomali
    80: ["ssh", "ftp", "rdp", "smb", "mysql"],
    443: ["ssh", "ftp", "rdp", "smb", "mysql"],
    22: ["http", "https"],
    3389: ["http", "https", "ssh"],
    # Atypik portlarda web servisi -> gizli panel ihtimali
    "high_ports_web": {    # 8000+ portlarda web = dikkat
        "ports": range(8000, 65536),
        "services": ["http", "https"],
        "alert": "Yüksek portta web servisi - gizli yönetim paneli olabilir",
    },
}


@dataclass
class AdaptiveRecommendation:
    """Adaptif tarama önerisi"""
    action: str          # "add_nuclei_tags", "escalate_profile", "run_fuzz", "alert"
    priority: str        # "critical", "high", "medium", "low"
    reason: str          # Neden bu öneri yapılıyor
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyAlert:
    """Anomali uyarısı"""
    severity: str        # "critical", "high", "medium", "low"
    category: str        # "apt_indicator", "misconfiguration", "unusual_service", "data_exposure"
    title: str
    description: str
    affected: str        # Etkilenen servis/port
    mitre_technique: Optional[str] = None  # T1190, T1133, vb.


class AdaptiveScanner:
    """
    AI destekli adaptif tarama karar motoru.

    Pipeline her stage'den sonra bu motora danışır:
    1. "Bu sonuçlara göre ek tarama gerekli mi?"
    2. "Hangi Nuclei template'leri daha etkili olur?"
    3. "Bu kombinasyon bir anomali mi?"
    4. "Profil yükseltmeli miyiz?"
    """

    def __init__(self):
        self.recommendations: List[AdaptiveRecommendation] = []
        self.anomalies: List[AnomalyAlert] = []
        self.discovered_services: Dict[str, Any] = {}
        self.discovered_ports: List[int] = []
        self.nuclei_tags_to_add: Set[str] = set()
        # Bir APT imzası tarama başına EN FAZLA bir kez anomali üretir — aksi halde
        # birikimli liste her stage'de aynı "imza eşleşti" gürültüsünü basar.
        self._fired_apt_signatures: Set[str] = set()
        # analyze_stage_results DELTA döner: yalnız son çağrıdan beri üretilen öğeler.
        # Kümülatif dönüş hem otonom motorda not/ipucu tekrarına hem legacy pipeline'da
        # aynı anomalinin her stage'de yeniden yayınlanmasına yol açıyordu.
        self._returned_rec_count: int = 0
        self._returned_anomaly_count: int = 0

    def analyze_stage_results(
        self,
        stage_name: str,
        stage_data: Dict[str, Any],
        all_results: Dict[str, Any],
        is_behind_cdn: bool = False,
        real_ip_found: bool = False,
    ) -> Dict[str, Any]:
        """
        Bir stage tamamlandığında sonuçları analiz et ve öneriler üret.

        Returns:
            {
                "recommendations": [...],
                "anomalies": [...],
                "nuclei_tags": [...],
                "should_escalate": bool,
                "additional_stages": [StageDefinition, ...],
            }
        """
        # Stage'e göre analiz
        if stage_name in ("port_scan", "direct_ip_scan", "fast_port_scan"):
            self._analyze_port_scan(stage_data, is_behind_cdn, real_ip_found)
        elif stage_name == "vuln_scan":
            self._analyze_vuln_scan(stage_data)
        elif stage_name == "recon_fingerprint":
            self._analyze_recon(stage_data, is_behind_cdn)
        elif stage_name == "subdomain_discovery":
            self._analyze_subdomains(stage_data)
        elif stage_name == "osint_intelligence":
            self._analyze_osint(stage_data)
        elif stage_name == "endpoint_discovery":
            self._analyze_fuzz(stage_data)
        elif stage_name == "origin_discovery":
            self._analyze_origin_discovery(stage_data)

        # Çapraz analiz (tüm sonuçları birleştir)
        self._cross_analyze(all_results, is_behind_cdn, real_ip_found)

        # DELTA dönüşü: yalnız bu çağrıdan önceki çağrıdan beri üretilen öğeler.
        # İç state (self.recommendations/anomalies) kümülatif kalır — _should_escalate
        # ve risk skoru tüm tarihe bakar; ama ÇAĞIRAN yalnız yeni öğeleri görür ki aynı
        # anomali/öneri her stage'de tekrar not/event olarak basılmasın.
        # NOT: nuclei_tags bilinçli KÜMÜLATİF döner — tag'ler kenar seed'lemeye gider ve
        # kenarlar signature ile zaten dedup olur; delta tag kombinasyon kaybettirirdi.
        new_recs = self.recommendations[self._returned_rec_count:]
        new_anoms = self.anomalies[self._returned_anomaly_count:]
        self._returned_rec_count = len(self.recommendations)
        self._returned_anomaly_count = len(self.anomalies)

        return {
            "recommendations": [
                {
                    "action": r.action,
                    "priority": r.priority,
                    "reason": r.reason,
                    "details": r.details,
                }
                for r in new_recs
            ],
            "anomalies": [
                {
                    "severity": a.severity,
                    "category": a.category,
                    "title": a.title,
                    "description": a.description,
                    "affected": a.affected,
                    "mitre_technique": a.mitre_technique,
                }
                for a in new_anoms
            ],
            "nuclei_tags": list(self.nuclei_tags_to_add),
            "should_escalate": self._should_escalate(),
            "risk_score_modifier": self._calculate_risk_modifier(),
        }

    # ============ Port Scan Analysis ============

    def _analyze_port_scan(self, data: Dict, is_behind_cdn: bool, real_ip_found: bool):
        """Port tarama sonuçlarını analiz et"""
        ports = data.get("ports", [])
        if not ports:
            return

        open_ports = []
        for port_info in ports:
            port = port_info.get("port", 0)
            service = (port_info.get("service", "") or "").lower()
            product = (port_info.get("product", "") or "").lower()
            version = (port_info.get("version", "") or "").lower()

            open_ports.append(port)
            self.discovered_ports.append(port)

            # Servis-CVE eşleştirmesi
            for svc_name, svc_info in SERVICE_VULNERABILITY_MAP.items():
                if svc_name in service or svc_name in product:
                    self.discovered_services[svc_name] = {
                        "port": port,
                        "product": product,
                        "version": version,
                    }

                    # Nuclei tag önerisi
                    self.nuclei_tags_to_add.update(svc_info["nuclei_tags"])

                    # Versiyon bazlı kritik CVE kontrolü
                    crit_versions = svc_info.get("critical_versions", {})
                    for ver_pattern, cves in crit_versions.items():
                        if ver_pattern in version:
                            self.recommendations.append(AdaptiveRecommendation(
                                action="critical_cve_detected",
                                priority="critical",
                                reason=f"{product} {version} -> {', '.join(cves)} zafiyeti biliniyor",
                                details={
                                    "port": port,
                                    "product": product,
                                    "version": version,
                                    "cves": cves,
                                    "nuclei_templates": [f"cve-{cve.lower().replace('cve-', '')}" for cve in cves],
                                },
                            ))

                    # APT göstergesi kontrolü
                    if svc_info.get("apt_indicator"):
                        self.anomalies.append(AnomalyAlert(
                            severity="high",
                            category="apt_indicator",
                            title=f"Dışarıya Açık {svc_name.upper()} Servisi",
                            description=(
                                f"Port {port}'da {product} servisi dışarıdan erişilebilir. "
                                f"Bu, veri sızıntısı ve yetkisiz erişim riskini ciddi artırıyor. "
                                f"APT grupları bu tür açık servisleri ilk hedef olarak kullanır."
                            ),
                            affected=f"{port}/{service}",
                            mitre_technique="T1190",
                        ))

            # Port anomali kontrolü
            self._check_port_anomaly(port, service, product)

        # CF bypass başarılıysa
        if is_behind_cdn and real_ip_found:
            self.anomalies.append(AnomalyAlert(
                severity="critical",
                category="misconfiguration",
                title="CDN Bypass: Gerçek IP Üzerinde Portlar Açık",
                description=(
                    f"Cloudflare arkasındaki gerçek IP üzerinde {len(open_ports)} port açık. "
                    f"Bu, CDN korumasının tamamen bypass edilebileceği anlamına gelir. "
                    f"Saldırgan DDoS, port scan ve direkt exploit yapabilir."
                ),
                affected=f"Portlar: {', '.join(str(p) for p in sorted(open_ports)[:20])}",
                mitre_technique="T1590",
            ))

            self.recommendations.append(AdaptiveRecommendation(
                action="escalate_profile",
                priority="critical",
                reason="CF bypass başarılı + açık portlar -> APT profili önerilir",
                details={"suggested_profile": "apt", "open_ports": open_ports},
            ))

    def _check_port_anomaly(self, port: int, service: str, product: str):
        """Port-servis uyumsuzluğu kontrolü"""
        # Yüksek portlarda web servisi
        if port >= 8000 and service in ("http", "https"):
            self.anomalies.append(AnomalyAlert(
                severity="medium",
                category="unusual_service",
                title=f"Yüksek Portta Web Servisi: {port}",
                description=(
                    f"Port {port}'da web servisi çalışıyor ({product}). "
                    f"Bu genellikle yönetim paneli, geliştirme ortamı veya "
                    f"gizli bir uygulama olabilir."
                ),
                affected=f"{port}/{service}",
            ))

        # Docker API
        if port in (2375, 2376):
            self.anomalies.append(AnomalyAlert(
                severity="critical",
                category="data_exposure",
                title="Docker API Dışarıya Açık!",
                description=(
                    f"Port {port}'da Docker API tespit edildi. "
                    f"Bu, sunucunun tamamen ele geçirilmesine yol açabilir. "
                    f"Saldırgan yeni container başlatarak host sisteme erişebilir."
                ),
                affected=f"{port}/docker",
                mitre_technique="T1610",
            ))

        # Kubernetes API
        if port in (6443, 10250):
            self.anomalies.append(AnomalyAlert(
                severity="critical",
                category="data_exposure",
                title="Kubernetes API Dışarıya Açık!",
                description=(
                    f"Port {port}'da Kubernetes API tespit edildi. "
                    f"Tüm cluster ele geçirilebilir."
                ),
                affected=f"{port}/kubernetes",
                mitre_technique="T1610",
            ))

    # ============ Vulnerability Scan Analysis ============

    def _analyze_vuln_scan(self, data: Dict):
        """Zafiyet tarama sonuçlarını analiz et"""
        findings = data.get("findings", [])
        if not findings:
            return

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        rce_found = False
        sqli_found = False

        for finding in findings:
            severity = (finding.get("severity", "") or "").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            template_id = (finding.get("template_id", "") or "").lower()
            tags = finding.get("tags", [])

            # RCE tespit
            if any(t in str(tags) for t in ["rce", "remote-code-execution"]):
                rce_found = True

            # SQLi tespit
            if "sqli" in template_id or "sql-injection" in str(tags):
                sqli_found = True

        # Kritik zafiyet varsa
        if severity_counts.get("critical", 0) > 0:
            self.recommendations.append(AdaptiveRecommendation(
                action="deep_exploit_check",
                priority="critical",
                reason=f"{severity_counts['critical']} kritik zafiyet bulundu - exploit kontrolü gerekli",
                details={"severity_counts": severity_counts},
            ))

        # RCE varsa profile yükselt
        if rce_found:
            self.recommendations.append(AdaptiveRecommendation(
                action="escalate_profile",
                priority="critical",
                reason="RCE zafiyeti tespit edildi - tam tarama önerilir",
                details={"suggested_profile": "full"},
            ))

        # SQLi varsa fuzz öner
        if sqli_found:
            self.recommendations.append(AdaptiveRecommendation(
                action="run_fuzz",
                priority="high",
                reason="SQL Injection tespit edildi - ek fuzzing önerilir",
                details={"focus": "sqli_endpoints"},
            ))

    # ============ Recon Analysis ============

    def _analyze_recon(self, data: Dict, is_behind_cdn: bool):
        """Recon sonuçlarını analiz et"""
        technologies = data.get("technologies", [])
        real_ips = data.get("real_ips", [])

        # Teknoloji bazlı nuclei tag ekleme
        for tech in technologies:
            tech_lower = tech.lower() if isinstance(tech, str) else ""
            for svc_name in SERVICE_VULNERABILITY_MAP:
                if svc_name in tech_lower:
                    self.nuclei_tags_to_add.update(
                        SERVICE_VULNERABILITY_MAP[svc_name]["nuclei_tags"]
                    )

        # Gerçek IP bulunduysa
        if real_ips:
            self.recommendations.append(AdaptiveRecommendation(
                action="scan_real_ips",
                priority="high",
                reason=f"{len(real_ips)} gerçek IP bulundu - direkt tarama gerekli",
                details={"real_ips": real_ips},
            ))

    # ============ Subdomain Analysis ============

    def _analyze_subdomains(self, data: Dict):
        """Subdomain sonuçlarını analiz et"""
        subdomains = data.get("subdomains", [])
        if not subdomains:
            return

        # İlginç subdomain pattern'leri
        interesting_patterns = {
            "admin": "Yönetim paneli olabilir",
            "staging": "Staging ortamı - genellikle daha az korumalı",
            "dev": "Geliştirme ortamı - debug modunda olabilir",
            "test": "Test ortamı - zayıf güvenlik",
            "api": "API endpoint - ek fuzzing gerekebilir",
            "old": "Eski sistem - güncellenmemiş olabilir",
            "backup": "Yedek sistem - hassas veri",
            "vpn": "VPN gateway - erişim noktası",
            "mail": "Mail sunucu - gerçek IP olabilir",
            "ftp": "FTP sunucu - dosya erişimi",
            "db": "Veritabanı - kritik",
            "internal": "İç ağ servisi - sızıntı",
            "jenkins": "CI/CD - RCE riski",
            "gitlab": "Kod deposu - kaynak kodu sızıntısı",
            "grafana": "Monitoring - bilgi sızıntısı",
            "kibana": "Log analiz - bilgi sızıntısı",
        }

        for sub in subdomains:
            sub_lower = sub.lower() if isinstance(sub, str) else ""
            for pattern, desc in interesting_patterns.items():
                if pattern in sub_lower:
                    self.anomalies.append(AnomalyAlert(
                        severity="medium",
                        category="unusual_service",
                        title=f"İlginç Subdomain: {sub}",
                        description=f"{desc}. Bu endpoint ek tarama gerektirebilir.",
                        affected=sub,
                    ))
                    break

    # ============ OSINT Analysis ============

    def _analyze_osint(self, data: Dict):
        """OSINT sonuçlarını analiz et"""
        # Shodan'dan gelen port bilgileri
        shodan_ports = data.get("shodan_ports", [])
        if shodan_ports:
            for port in shodan_ports:
                if port not in self.discovered_ports:
                    self.recommendations.append(AdaptiveRecommendation(
                        action="scan_hidden_port",
                        priority="medium",
                        reason=f"Shodan port {port} görüyor ama nmap bulmadı - gizli port olabilir",
                        details={"port": port},
                    ))

    # ============ Fuzz Analysis ============

    def _analyze_fuzz(self, data: Dict):
        """Fuzzing sonuçlarını analiz et"""
        found_paths = data.get("found_paths", [])
        if not found_paths:
            return

        sensitive_patterns = [
            ".env", ".git", ".svn", "wp-config", "config.php",
            "phpinfo", "adminer", "phpmyadmin", "debug",
            ".htaccess", ".htpasswd", "backup", ".sql",
            "api/swagger", "api/docs", "graphql",
        ]

        for path_info in found_paths:
            path = path_info.get("path", "") if isinstance(path_info, dict) else str(path_info)
            for pattern in sensitive_patterns:
                if pattern in path.lower():
                    self.anomalies.append(AnomalyAlert(
                        severity="high",
                        category="data_exposure",
                        title=f"Hassas Dosya/Endpoint: {path}",
                        description=f"Fuzzing sırasında hassas endpoint bulundu. Veri sızıntısı riski.",
                        affected=path,
                        mitre_technique="T1083",
                    ))
                    break

    # ============ Origin Discovery Analysis ============

    def _analyze_origin_discovery(self, data: Dict):
        """Origin discovery sonuçlarını analiz et"""
        best = data.get("best_candidate")
        candidates = data.get("candidates", [])

        if best and best.get("verified"):
            self.anomalies.append(AnomalyAlert(
                severity="critical",
                category="misconfiguration",
                title="CDN Bypass: Gerçek Sunucu IP'si Doğrulandı",
                description=(
                    f"IP: {best['ip']} ({best['source']} tekniği ile bulundu). "
                    f"Güven: %{best['confidence']}. "
                    f"Bu IP üzerinden CDN koruması tamamen atlanabilir. "
                    f"Saldırgan DDoS, port scan, exploit yapabilir. "
                    f"ÖNERİ: Firewall'da sadece CDN IP'lerine izin verin."
                ),
                affected=best["ip"],
                mitre_technique="T1590.002",
            ))

            self.recommendations.append(AdaptiveRecommendation(
                action="escalate_profile",
                priority="critical",
                reason="Doğrulanmış gerçek IP bulundu - APT profili önerilir",
                details={"real_ip": best["ip"], "confidence": best["confidence"]},
            ))

        elif len(candidates) > 3:
            self.recommendations.append(AdaptiveRecommendation(
                action="verify_candidates",
                priority="high",
                reason=f"{len(candidates)} aday IP bulundu - manuel doğrulama gerekli",
                details={"candidate_count": len(candidates)},
            ))

    # ============ Cross Analysis ============

    def _cross_analyze(self, all_results: Dict, is_behind_cdn: bool, real_ip_found: bool):
        """Tüm sonuçları çapraz analiz et"""
        # APT imza eşleştirmesi
        for sig_name, signature in APT_PORT_SIGNATURES.items():
            # Tarama başına bir kez — aynı imza her stage'de tekrar anomali basmasın.
            if sig_name in self._fired_apt_signatures:
                continue
            # "Cloudflare bypass" imzası ancak ortada BYPASS EDİLECEK bir CDN varsa
            # anlamlıdır. Saf IP hedefte real_ip_found trivial olarak True'dur (hedefin
            # kendisi) — CDN'siz hedefte "CF bypass başarılı" anomalisi düzmece FP'dir.
            if sig_name == "cf_bypass_indicators" and not is_behind_cdn:
                continue
            score = 0
            for indicator in signature["indicators"]:
                if "ports" in indicator:
                    matching = set(indicator["ports"]) & set(self.discovered_ports)
                    if matching:
                        score += indicator["weight"] * len(matching)
                if "services" in indicator:
                    matching = set(indicator["services"]) & set(self.discovered_services.keys())
                    if matching:
                        score += indicator["weight"] * len(matching)
                if "condition" in indicator:
                    if indicator["condition"] == "real_ip_found" and real_ip_found:
                        score += indicator["weight"]
                    elif indicator["condition"] == "origin_ports_differ_from_domain":
                        # Origin portları ile domain portları farklıysa
                        score += indicator["weight"] if real_ip_found else 0

            if score >= 10:
                self._fired_apt_signatures.add(sig_name)
                self.anomalies.append(AnomalyAlert(
                    severity="high",
                    category="apt_indicator",
                    title=f"APT İmza Eşleşmesi: {signature['description']}",
                    description=(
                        f"Tarama sonuçları '{sig_name}' APT profiliyle eşleşiyor "
                        f"(skor: {score}). Bu, hedefin benzer profildeki APT grupları "
                        f"tarafından hedef alınma riskini artırıyor."
                    ),
                    affected="Genel sistem profili",
                    mitre_technique="T1595",
                ))

    # ============ Decision Functions ============

    def _should_escalate(self) -> bool:
        """Profil yükseltme gerekiyor mu?"""
        critical_findings = sum(
            1 for a in self.anomalies if a.severity == "critical"
        )
        critical_recs = sum(
            1 for r in self.recommendations if r.priority == "critical"
        )
        return critical_findings >= 2 or critical_recs >= 1

    def _calculate_risk_modifier(self) -> int:
        """Risk skoru modifiyeri hesapla (-20 ile +30 arası)"""
        modifier = 0

        for anomaly in self.anomalies:
            if anomaly.severity == "critical":
                modifier += 15
            elif anomaly.severity == "high":
                modifier += 8
            elif anomaly.severity == "medium":
                modifier += 3

        # APT göstergesi varsa ekstra risk
        apt_indicators = sum(
            1 for a in self.anomalies if a.category == "apt_indicator"
        )
        modifier += apt_indicators * 5

        return min(30, modifier)  # Max +30

    def get_nuclei_tags_for_services(self) -> List[str]:
        """Bulunan servislere göre Nuclei tag'leri döndür"""
        return list(self.nuclei_tags_to_add)

    def get_summary(self) -> Dict[str, Any]:
        """Özet rapor"""
        return {
            "total_recommendations": len(self.recommendations),
            "total_anomalies": len(self.anomalies),
            "critical_anomalies": sum(1 for a in self.anomalies if a.severity == "critical"),
            "high_anomalies": sum(1 for a in self.anomalies if a.severity == "high"),
            "discovered_services": list(self.discovered_services.keys()),
            "nuclei_tags_suggested": list(self.nuclei_tags_to_add),
            "should_escalate": self._should_escalate(),
            "risk_modifier": self._calculate_risk_modifier(),
        }


# ============ Standalone Test ============

if __name__ == "__main__":
    scanner = AdaptiveScanner()

    # Test: Apache + MySQL + SSH açık bir sunucu
    test_data = {
        "ports": [
            {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.51"},
            {"port": 443, "service": "https", "product": "Apache httpd", "version": "2.4.51"},
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.2"},
            {"port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0.32"},
            {"port": 8080, "service": "http", "product": "Apache Tomcat", "version": "9.0"},
            {"port": 9200, "service": "http", "product": "Elasticsearch", "version": "7.17"},
        ]
    }

    result = scanner.analyze_stage_results(
        stage_name="port_scan",
        stage_data=test_data,
        all_results={},
        is_behind_cdn=True,
        real_ip_found=True,
    )

    print("=" * 60)
    print("ADAPTIVE SCANNER TEST RESULTS")
    print("=" * 60)
    print(f"\n📊 Öneriler ({len(result['recommendations'])}):")
    for rec in result["recommendations"]:
        print(f"  [{rec['priority'].upper()}] {rec['action']}: {rec['reason']}")
    print(f"\n⚠️ Anomaliler ({len(result['anomalies'])}):")
    for anom in result["anomalies"]:
        print(f"  [{anom['severity'].upper()}] {anom['title']}")
    print(f"\n🏷️ Nuclei Tags: {', '.join(result['nuclei_tags'])}")
    print(f"⬆️ Escalate: {result['should_escalate']}")
    print(f"📈 Risk Modifier: +{result['risk_score_modifier']}")
