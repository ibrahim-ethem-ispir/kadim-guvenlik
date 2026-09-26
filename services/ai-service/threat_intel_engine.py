"""
Kadim Güvenlik - Threat Intelligence Engine
Türkçe: APT grup veritabanı ve TTP eşleştirme motoru.

20+ APT grubunun taktik, teknik ve prosedürlerini (TTP) içerir.
Tarama sonuçlarıyla karşılaştırarak hangi APT grupları için risk altında
olduğunu belirler.

Kullanım:
    from threat_intel_engine import match_apt_indicators, APT_GROUPS
    result = match_apt_indicators(scan_results)
    print(result["risk_score"])         # 0-100 risk skoru
    print(result["apt_matches"])        # Eşleşen APT grupları
    print(result["mitre_techniques"])   # Tespit edilen MITRE teknikleri
"""

import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("threat-intel")


# ============================================================
# APT GRUP VERİTABANI
# ============================================================
# Her grup için: aliases, köken, hedef sektörler, MITRE teknikleri,
# bilinen CVE'ler, tipik IOC pattern'leri

APT_GROUPS: Dict[str, Dict[str, Any]] = {
    # ---- Kuzey Kore ----
    "lazarus": {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "ZINC", "Labyrinth Chollima", "APT38"],
        "origin": "North Korea",
        "active_since": 2009,
        "targets": ["finance", "crypto", "defense", "media", "gaming"],
        "techniques": ["T1190", "T1566", "T1059", "T1071", "T1486", "T1027", "T1105"],
        "known_cves": [
            "CVE-2021-44228", "CVE-2022-0609", "CVE-2023-42793",
            "CVE-2022-47966", "CVE-2023-46604", "CVE-2021-26855",
        ],
        "indicators": {
            "ports": [4443, 8443, 9443, 1443],
            "services": ["Apache Struts", "Oracle WebLogic", "JBoss", "Apache ActiveMQ"],
            "patterns": ["supply_chain", "watering_hole", "spearphishing"],
            "suspicious_headers": [],
        },
        "risk_weight": 10,
        "description": "Kuzey Kore devlet destekli grup. Finansal hırsızlık, kripto borsası saldırıları ve supply chain saldırılarıyla tanınır.",
    },

    "kimsuky": {
        "name": "Kimsuky",
        "aliases": ["Velvet Chollima", "Thallium", "Black Banshee", "APT43"],
        "origin": "North Korea",
        "active_since": 2013,
        "targets": ["research", "defense", "government", "nuclear", "think_tanks"],
        "techniques": ["T1566", "T1059", "T1036", "T1056", "T1560", "T1114"],
        "known_cves": [
            "CVE-2017-0199", "CVE-2022-30190", "CVE-2021-40444",
        ],
        "indicators": {
            "ports": [443, 8080],
            "services": ["Apache", "IIS"],
            "patterns": ["spearphishing", "credential_harvesting", "social_engineering"],
            "suspicious_headers": [],
        },
        "risk_weight": 7,
        "description": "Kuzey Kore istihbarat birimi. Nükleer/savunma araştırmalarına yönelik istihbarat toplama.",
    },

    # ---- Rusya ----
    "apt28": {
        "name": "APT28 (Fancy Bear)",
        "aliases": ["Fancy Bear", "Sofacy", "Sednit", "Strontium", "Forest Blizzard"],
        "origin": "Russia (GRU)",
        "active_since": 2004,
        "targets": ["government", "military", "defense", "media", "energy", "transportation"],
        "techniques": ["T1190", "T1133", "T1078", "T1566", "T1059", "T1027", "T1583"],
        "known_cves": [
            "CVE-2023-23397", "CVE-2023-38831", "CVE-2020-0688",
            "CVE-2020-12641", "CVE-2020-35730", "CVE-2021-40444",
        ],
        "indicators": {
            "ports": [443, 8443, 4443, 993, 995],
            "services": ["Microsoft Exchange", "Roundcube", "Cisco"],
            "patterns": ["credential_harvesting", "zero_day", "living_off_the_land"],
            "suspicious_headers": ["X-Forwarded-For"],
        },
        "risk_weight": 10,
        "description": "Rus GRU Unit 26165. Devlet düzeyinde siber casusluk ve dezenformasyon operasyonları.",
    },

    "apt29": {
        "name": "APT29 (Cozy Bear)",
        "aliases": ["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard"],
        "origin": "Russia (SVR)",
        "active_since": 2008,
        "targets": ["government", "energy", "health", "technology", "cloud_providers"],
        "techniques": ["T1195", "T1078", "T1550", "T1098", "T1556", "T1199"],
        "known_cves": [
            "CVE-2020-2034", "CVE-2021-21972", "CVE-2023-42793",
            "CVE-2024-21410", "CVE-2023-35078",
        ],
        "indicators": {
            "ports": [443, 5986, 5985],
            "services": ["VMware", "Citrix", "Pulse Secure", "SolarWinds"],
            "patterns": ["supply_chain", "cloud_compromise", "token_theft"],
            "suspicious_headers": [],
        },
        "risk_weight": 10,
        "description": "Rus SVR. SolarWinds supply chain saldırısıyla ünlü. Cloud ve identity altyapısı hedefler.",
    },

    "turla": {
        "name": "Turla (Snake)",
        "aliases": ["Snake", "Venomous Bear", "Uroburos", "Waterbug", "Krypton"],
        "origin": "Russia (FSB)",
        "active_since": 1996,
        "targets": ["government", "embassy", "military", "research", "media"],
        "techniques": ["T1071", "T1090", "T1001", "T1059", "T1027", "T1203"],
        "known_cves": [
            "CVE-2021-40444", "CVE-2017-11882", "CVE-2022-30190",
        ],
        "indicators": {
            "ports": [443, 80, 1234, 9999],
            "services": ["nginx", "Apache", "IIS"],
            "patterns": ["satellite_hijack", "watering_hole", "usb_infection"],
            "suspicious_headers": [],
        },
        "risk_weight": 9,
        "description": "Rusya'nın en eski APT grubu (FSB). Diplomatik hedefler ve gelişmiş gizlilik teknikleri.",
    },

    "sandworm": {
        "name": "Sandworm",
        "aliases": ["Voodoo Bear", "Iridium", "Seashell Blizzard", "Unit 74455"],
        "origin": "Russia (GRU)",
        "active_since": 2009,
        "targets": ["energy", "government", "infrastructure", "telecommunications"],
        "techniques": ["T1190", "T1059", "T1486", "T1562", "T1070", "T1499"],
        "known_cves": [
            "CVE-2023-4966", "CVE-2022-41040", "CVE-2021-40539",
            "CVE-2024-1709", "CVE-2023-48788",
        ],
        "indicators": {
            "ports": [22, 443, 9090, 9443],
            "services": ["Fortinet", "Citrix", "Zimbra", "Confluence"],
            "patterns": ["wiper_attacks", "ics_scada", "destructive_operations"],
            "suspicious_headers": [],
        },
        "risk_weight": 10,
        "description": "Rus GRU Unit 74455. NotPetya, Industroyer gibi yıkıcı saldırılarla tanınır. Enerji altyapısı hedefler.",
    },

    # ---- Çin ----
    "apt41": {
        "name": "APT41 (Double Dragon)",
        "aliases": ["Double Dragon", "Winnti", "Barium", "Brass Typhoon"],
        "origin": "China",
        "active_since": 2012,
        "targets": ["technology", "health", "gaming", "education", "travel", "telecom"],
        "techniques": ["T1190", "T1195", "T1059", "T1505", "T1053", "T1574"],
        "known_cves": [
            "CVE-2021-44228", "CVE-2021-22941", "CVE-2020-10189",
            "CVE-2019-19781", "CVE-2023-46747",
        ],
        "indicators": {
            "ports": [443, 8443, 3389, 1433, 3306],
            "services": ["Citrix", "ManageEngine", "VMware", "SolarWinds", "MSSQL"],
            "patterns": ["supply_chain", "dual_espionage_financial", "web_shell"],
            "suspicious_headers": [],
        },
        "risk_weight": 9,
        "description": "Hem devlet casusluğu hem finansal motivasyonlu. Supply chain ve web uygulaması saldırıları.",
    },

    "apt10": {
        "name": "APT10 (menuPass)",
        "aliases": ["menuPass", "Stone Panda", "Red Apollo", "Cicada"],
        "origin": "China",
        "active_since": 2006,
        "targets": ["msp", "technology", "defense", "government", "health"],
        "techniques": ["T1199", "T1078", "T1053", "T1574", "T1560"],
        "known_cves": [
            "CVE-2018-7600", "CVE-2017-0199", "CVE-2021-26855",
        ],
        "indicators": {
            "ports": [443, 3389, 445],
            "services": ["IIS", "Exchange"],
            "patterns": ["msp_targeting", "cloud_hopper", "credential_theft"],
            "suspicious_headers": [],
        },
        "risk_weight": 8,
        "description": "MSP (Managed Service Provider) üzerinden hedef müşterilere erişim. Cloud Hopper operasyonu.",
    },

    "apt1": {
        "name": "APT1 (Comment Crew)",
        "aliases": ["Comment Crew", "Shanghai Group", "Unit 61398"],
        "origin": "China (PLA)",
        "active_since": 2006,
        "targets": ["technology", "aerospace", "defense", "energy", "chemical"],
        "techniques": ["T1566", "T1059", "T1005", "T1041", "T1078"],
        "known_cves": [],
        "indicators": {
            "ports": [443, 80, 8080],
            "services": ["Apache", "IIS"],
            "patterns": ["spearphishing", "custom_malware", "industrial_espionage"],
            "suspicious_headers": [],
        },
        "risk_weight": 6,
        "description": "Çin PLA Unit 61398. Endüstriyel casusluk. İlk kamuya açıklanan APT gruplarından biri.",
    },

    "hafnium": {
        "name": "Hafnium",
        "aliases": ["Silk Typhoon"],
        "origin": "China",
        "active_since": 2017,
        "targets": ["government", "defense", "research", "ngo", "law"],
        "techniques": ["T1190", "T1505", "T1003", "T1550", "T1560"],
        "known_cves": [
            "CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858",
            "CVE-2021-27065",  # ProxyLogon
        ],
        "indicators": {
            "ports": [443, 80],
            "services": ["Microsoft Exchange"],
            "patterns": ["web_shell", "exchange_exploit", "proxylogon"],
            "suspicious_headers": [],
        },
        "risk_weight": 9,
        "description": "ProxyLogon saldırısıyla tanınır. Microsoft Exchange sunucularını hedefler.",
    },

    # ---- İran ----
    "apt33": {
        "name": "APT33 (Elfin)",
        "aliases": ["Elfin", "Magnallium", "Peach Sandstorm", "Refined Kitten"],
        "origin": "Iran",
        "active_since": 2013,
        "targets": ["aviation", "energy", "petrochemical", "defense"],
        "techniques": ["T1566", "T1078", "T1486", "T1059", "T1027"],
        "known_cves": [
            "CVE-2017-11774", "CVE-2018-20250",
        ],
        "indicators": {
            "ports": [443, 80, 3389],
            "services": ["Outlook", "SharePoint"],
            "patterns": ["destructive_wiper", "password_spraying", "spearphishing"],
            "suspicious_headers": [],
        },
        "risk_weight": 7,
        "description": "İran devlet destekli. Havacılık, enerji ve petrokimya sektörlerini hedefler.",
    },

    "apt34": {
        "name": "APT34 (OilRig)",
        "aliases": ["OilRig", "Hazel Sandstorm", "Helix Kitten", "IRN2"],
        "origin": "Iran",
        "active_since": 2014,
        "targets": ["government", "finance", "energy", "telecom", "chemical"],
        "techniques": ["T1566", "T1059", "T1071", "T1078", "T1505"],
        "known_cves": [
            "CVE-2017-11882", "CVE-2017-0199",
        ],
        "indicators": {
            "ports": [443, 80, 53, 25],
            "services": ["Exchange", "SharePoint", "DNS"],
            "patterns": ["dns_tunneling", "social_engineering", "web_shell"],
            "suspicious_headers": [],
        },
        "risk_weight": 7,
        "description": "İran Ministry of Intelligence bağlantılı. DNS tünelleme ve web shell saldırıları.",
    },

    # ---- Finansal ----
    "fin7": {
        "name": "FIN7",
        "aliases": ["Carbanak", "Carbon Spider", "Sangria Tempest"],
        "origin": "Russia (Criminal)",
        "active_since": 2013,
        "targets": ["finance", "retail", "hospitality", "restaurant", "pos"],
        "techniques": ["T1566", "T1059", "T1218", "T1053", "T1555"],
        "known_cves": [
            "CVE-2017-0199", "CVE-2021-40444",
        ],
        "indicators": {
            "ports": [443, 80, 8080, 9090],
            "services": ["POS", "web_server", "RDP"],
            "patterns": ["pos_malware", "social_engineering", "js_backdoor"],
            "suspicious_headers": [],
        },
        "risk_weight": 8,
        "description": "Finansal motivasyonlu siber suç grubu. POS malware ve sosyal mühendislik.",
    },

    "darkside": {
        "name": "DarkSide",
        "aliases": ["DarkSide", "BlackMatter", "ALPHV"],
        "origin": "Russia (Criminal)",
        "active_since": 2020,
        "targets": ["infrastructure", "energy", "manufacturing", "health"],
        "techniques": ["T1190", "T1078", "T1486", "T1490", "T1048"],
        "known_cves": [
            "CVE-2021-27065", "CVE-2021-34527",
        ],
        "indicators": {
            "ports": [3389, 445, 135, 139],
            "services": ["RDP", "SMB", "VPN"],
            "patterns": ["ransomware", "double_extortion", "initial_access_broker"],
            "suspicious_headers": [],
        },
        "risk_weight": 8,
        "description": "Colonial Pipeline saldırısı. Ransomware-as-a-Service modeli. Çift şantaj taktiği.",
    },

    "revil": {
        "name": "REvil (Sodinokibi)",
        "aliases": ["Sodinokibi", "Gold Southfield", "Pinchy Spider"],
        "origin": "Russia (Criminal)",
        "active_since": 2019,
        "targets": ["technology", "msp", "manufacturing", "legal", "insurance"],
        "techniques": ["T1190", "T1195", "T1486", "T1027", "T1562"],
        "known_cves": [
            "CVE-2021-30116",  # Kaseya
            "CVE-2019-2725",   # WebLogic
            "CVE-2019-11510",  # Pulse Secure
        ],
        "indicators": {
            "ports": [3389, 445, 8443, 9090],
            "services": ["Kaseya", "WebLogic", "Pulse Secure", "Citrix"],
            "patterns": ["ransomware", "supply_chain", "msp_targeting"],
            "suspicious_headers": [],
        },
        "risk_weight": 8,
        "description": "Kaseya supply chain saldırısı. MSP üzerinden binlerce hedefe ulaşım.",
    },

    "conti": {
        "name": "Conti",
        "aliases": ["Wizard Spider", "Gold Ulrick", "DEV-0193"],
        "origin": "Russia (Criminal)",
        "active_since": 2020,
        "targets": ["government", "health", "education", "infrastructure", "retail"],
        "techniques": ["T1190", "T1566", "T1486", "T1021", "T1059"],
        "known_cves": [
            "CVE-2021-34527",  # PrintNightmare
            "CVE-2021-44228",  # Log4Shell
            "CVE-2020-1472",   # Zerologon
        ],
        "indicators": {
            "ports": [3389, 445, 139, 135],
            "services": ["RDP", "SMB", "Active Directory"],
            "patterns": ["ransomware", "cobalt_strike", "lateral_movement"],
            "suspicious_headers": [],
        },
        "risk_weight": 8,
        "description": "En büyük ransomware operasyonlarından biri. Cobalt Strike ve lateral movement.",
    },

    # ---- Diğer ----
    "equation_group": {
        "name": "Equation Group",
        "aliases": ["EQGRP", "Shadow Brokers leak"],
        "origin": "USA (NSA/TAO)",
        "active_since": 2001,
        "targets": ["infrastructure", "telecom", "government", "military", "nuclear"],
        "techniques": ["T1190", "T1195", "T1027", "T1059", "T1071"],
        "known_cves": [
            "CVE-2017-0144",  # EternalBlue
            "CVE-2017-0145",  # EternalRomance
        ],
        "indicators": {
            "ports": [445, 139, 3389, 443],
            "services": ["SMB", "Fortinet", "Cisco"],
            "patterns": ["firmware_implant", "zero_day_stockpile", "eternalblue"],
            "suspicious_headers": [],
        },
        "risk_weight": 10,
        "description": "Dünyanın en gelişmiş siber operasyon birimi. EternalBlue, firmware implantları.",
    },

    "apt32": {
        "name": "APT32 (OceanLotus)",
        "aliases": ["OceanLotus", "SeaLotus", "Canvas Cyclone"],
        "origin": "Vietnam",
        "active_since": 2014,
        "targets": ["government", "media", "ngo", "automotive", "manufacturing"],
        "techniques": ["T1566", "T1059", "T1027", "T1071", "T1105"],
        "known_cves": [
            "CVE-2017-11882", "CVE-2018-20250",
        ],
        "indicators": {
            "ports": [443, 80, 8443],
            "services": ["Apache", "nginx"],
            "patterns": ["watering_hole", "supply_chain", "social_engineering"],
            "suspicious_headers": [],
        },
        "risk_weight": 6,
        "description": "Vietnam devlet destekli. Bölgesel hedefler ve otomotiv sektörü.",
    },

    "lapsus": {
        "name": "LAPSUS$",
        "aliases": ["LAPSUS$", "DEV-0537", "Strawberry Tempest"],
        "origin": "UK/Brazil",
        "active_since": 2021,
        "targets": ["technology", "gaming", "telecom", "government", "health"],
        "techniques": ["T1078", "T1556", "T1199", "T1530", "T1528"],
        "known_cves": [],
        "indicators": {
            "ports": [443, 3389, 22],
            "services": ["VPN", "Okta", "Azure AD"],
            "patterns": ["sim_swap", "insider_recruitment", "mfa_fatigue", "social_engineering"],
            "suspicious_headers": [],
        },
        "risk_weight": 7,
        "description": "Genç hacker grubu. SIM swap, MFA fatigue, insider recruitment. Microsoft, NVIDIA, Samsung.",
    },

    "scattered_spider": {
        "name": "Scattered Spider",
        "aliases": ["0ktapus", "Scatter Swine", "Star Fraud", "Octo Tempest"],
        "origin": "UK/USA",
        "active_since": 2022,
        "targets": ["telecom", "technology", "finance", "gaming", "hospitality"],
        "techniques": ["T1078", "T1556", "T1199", "T1566", "T1621"],
        "known_cves": [],
        "indicators": {
            "ports": [443, 8443],
            "services": ["Okta", "Azure AD", "AWS"],
            "patterns": ["mfa_bypass", "sim_swap", "help_desk_social_engineering", "cloud_compromise"],
            "suspicious_headers": [],
        },
        "risk_weight": 8,
        "description": "MGM/Caesars saldırıları. Help desk social engineering ve cloud compromise.",
    },
}


# ============================================================
# MITRE ATT&CK TEKNİKLERİ MAPPING
# ============================================================

MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "İnternet'e açık uygulamalardaki zafiyetleri sömürme",
        "detection": ["WAF logları", "IDS alerts", "Application error logs"],
        "related_cves": ["CVE-2021-44228", "CVE-2023-42793", "CVE-2021-26855"],
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "VPN, RDP, Citrix gibi uzak erişim servislerini hedefleme",
        "detection": ["VPN login anomalisi", "Unusual source IP", "Brute force tespit"],
        "related_cves": ["CVE-2019-11510", "CVE-2019-19781"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": "Çalıntı veya varsayılan kimlik bilgileri ile erişim",
        "detection": ["Anomalous login patterns", "Login from unusual locations"],
        "related_cves": [],
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Hedefli oltalama saldırıları (spearphishing)",
        "detection": ["Email gateway", "Sandbox analysis", "User reporting"],
        "related_cves": [],
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": "Tedarik zinciri saldırısı - güvenilir yazılım veya hizmet üzerinden",
        "detection": ["Software integrity", "Code signing", "SBOM analizi"],
        "related_cves": [],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "PowerShell, cmd, bash, Python vb. yorumlayıcılarla komut çalıştırma",
        "detection": ["Script execution logs", "Process monitoring"],
        "related_cves": [],
    },
    "T1505": {
        "name": "Server Software Component",
        "tactic": "Persistence",
        "description": "Web shell veya sunucu yazılımı implantı yerleştirme",
        "detection": ["File integrity monitoring", "Web shell scanning"],
        "related_cves": [],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Ransomware - veri şifreleme ile fidye",
        "detection": ["File system monitoring", "Canary files"],
        "related_cves": [],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "HTTP/HTTPS, DNS üzerinden komuta kontrol iletişimi",
        "detection": ["DNS anomaly", "Unusual HTTPS traffic", "Beacon detection"],
        "related_cves": [],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Zararlı dosyaları gizleme, şifreleme, encoding",
        "detection": ["Entropy analysis", "YARA rules"],
        "related_cves": [],
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": "Initial Access",
        "description": "Güvenilir üçüncü taraf ilişkisini kullanarak erişim",
        "detection": ["Third-party access monitoring", "Unusual service account activity"],
        "related_cves": [],
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Defense Evasion / Lateral Movement",
        "description": "Token, cookie, sertifika çalarak kimlik doğrulamayı atlama",
        "detection": ["Token anomaly", "Certificate misuse", "Session hijack"],
        "related_cves": [],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "RDP, SSH, SMB ile ağ içinde yanal hareket",
        "detection": ["Lateral movement detection", "RDP/SSH login monitoring"],
        "related_cves": [],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Dışarıdan araç/malware indirme",
        "detection": ["Network download monitoring", "Endpoint detection"],
        "related_cves": [],
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Güvenlik araçlarını devre dışı bırakma",
        "detection": ["Security tool health monitoring"],
        "related_cves": [],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "System recovery/backup mekanizmalarını silme",
        "detection": ["Volume shadow copy monitoring", "Backup integrity"],
        "related_cves": [],
    },
}


# ============================================================
# BİLİNEN AKTİF EXPLOIT EDİLEN ZAFİYETLER (CISA KEV benzeri)
# ============================================================

KNOWN_EXPLOITED_VULNS: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "product": "Apache Log4j",
        "severity": "critical",
        "cvss": 10.0,
        "actively_exploited": True,
        "apt_groups": ["lazarus", "apt41", "conti", "apt29"],
        "description": "Log4j RCE - JNDI injection üzerinden uzaktan kod çalıştırma",
    },
    "CVE-2021-26855": {
        "name": "ProxyLogon",
        "product": "Microsoft Exchange",
        "severity": "critical",
        "cvss": 9.8,
        "actively_exploited": True,
        "apt_groups": ["hafnium", "lazarus", "apt10"],
        "description": "Exchange SSRF + RCE zinciri",
    },
    "CVE-2023-42793": {
        "name": "JetBrains TeamCity",
        "product": "JetBrains TeamCity",
        "severity": "critical",
        "cvss": 9.8,
        "actively_exploited": True,
        "apt_groups": ["apt29", "lazarus"],
        "description": "Authentication bypass - CI/CD pipeline compromise",
    },
    "CVE-2021-41773": {
        "name": "Apache Path Traversal",
        "product": "Apache httpd",
        "severity": "critical",
        "cvss": 9.8,
        "actively_exploited": True,
        "apt_groups": [],
        "description": "Apache 2.4.49-2.4.50 path traversal ve RCE",
    },
    "CVE-2017-0144": {
        "name": "EternalBlue",
        "product": "Windows SMB",
        "severity": "critical",
        "cvss": 9.3,
        "actively_exploited": True,
        "apt_groups": ["equation_group", "sandworm", "lazarus"],
        "description": "SMBv1 RCE - WannaCry ve NotPetya'nın temeli",
    },
    "CVE-2023-23397": {
        "name": "Outlook Elevation of Privilege",
        "product": "Microsoft Outlook",
        "severity": "critical",
        "cvss": 9.8,
        "actively_exploited": True,
        "apt_groups": ["apt28"],
        "description": "Zero-click NTLM hash leak - APT28 aktif kullanımda",
    },
    "CVE-2020-1472": {
        "name": "Zerologon",
        "product": "Windows Netlogon",
        "severity": "critical",
        "cvss": 10.0,
        "actively_exploited": True,
        "apt_groups": ["conti", "fin7"],
        "description": "Netlogon authentication bypass - domain admin",
    },
    "CVE-2021-34527": {
        "name": "PrintNightmare",
        "product": "Windows Print Spooler",
        "severity": "critical",
        "cvss": 8.8,
        "actively_exploited": True,
        "apt_groups": ["conti"],
        "description": "Print Spooler RCE - lateral movement",
    },
    "CVE-2024-1709": {
        "name": "ScreenConnect Auth Bypass",
        "product": "ConnectWise ScreenConnect",
        "severity": "critical",
        "cvss": 10.0,
        "actively_exploited": True,
        "apt_groups": ["sandworm"],
        "description": "Authentication bypass - full system access",
    },
    "CVE-2023-46604": {
        "name": "Apache ActiveMQ RCE",
        "product": "Apache ActiveMQ",
        "severity": "critical",
        "cvss": 10.0,
        "actively_exploited": True,
        "apt_groups": ["lazarus"],
        "description": "Deserialization RCE - message broker compromise",
    },
}


# ============================================================
# EŞLEŞTIRME FONKSİYONLARI
# ============================================================

def match_apt_indicators(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tarama sonuçlarını APT TTP'leriyle eşleştir.

    Args:
        scan_results: Pipeline'dan gelen tarama sonuçları
            - port_scan.data.ports[] -> port, service, product, version
            - vuln_scan.data.findings[] -> template_id, severity
            - recon.data -> technologies, is_behind_cdn, waf_detected
            - osint.data -> shodan, virustotal, whois, abuseipdb

    Returns:
        {
            "apt_matches": [...],
            "risk_score": 0-100,
            "matched_cves": [...],
            "mitre_techniques": [...],
            "recommendations": [...],
        }
    """
    apt_matches: List[Dict[str, Any]] = []
    matched_cves: Set[str] = set()
    mitre_techniques: Set[str] = set()
    recommendations: List[str] = []
    total_risk_score = 0

    # Port verilerini topla
    ports_data = _extract_ports(scan_results)
    open_ports = {p["port"] for p in ports_data}
    services = {p.get("product", "").lower() for p in ports_data if p.get("product")}
    versions = {f"{p.get('product', '')}:{p.get('version', '')}".lower() for p in ports_data}

    # CVE verilerini topla
    vuln_data = _extract_vulns(scan_results)
    found_cves = {v.get("template_id", "").upper() for v in vuln_data if v.get("template_id", "").startswith("CVE-")}

    # Recon verilerini topla
    recon_data = scan_results.get("recon", scan_results.get("recon_fingerprint", {}))
    if isinstance(recon_data, dict) and recon_data.get("data"):
        recon_data = recon_data["data"]
    is_behind_cdn = recon_data.get("is_behind_cdn", False) if isinstance(recon_data, dict) else False
    technologies = recon_data.get("technologies", []) if isinstance(recon_data, dict) else []

    # OSINT verilerini topla
    osint_data = scan_results.get("osint", scan_results.get("osint_intelligence", {}))
    if isinstance(osint_data, dict) and osint_data.get("data"):
        osint_data = osint_data["data"]

    # ---- Her APT grubunu kontrol et ----
    for group_id, group in APT_GROUPS.items():
        match_score = 0
        match_reasons = []

        # 1. Port eşleşmesi
        indicator_ports = set(group["indicators"].get("ports", []))
        port_overlap = indicator_ports & open_ports
        if port_overlap:
            match_score += len(port_overlap) * 2
            match_reasons.append(f"Port eşleşmesi: {port_overlap}")

        # 2. Servis eşleşmesi
        indicator_services = [s.lower() for s in group["indicators"].get("services", [])]
        for svc in indicator_services:
            for found_svc in services:
                if svc in found_svc or found_svc in svc:
                    match_score += 5
                    match_reasons.append(f"Servis eşleşmesi: {found_svc} ({svc})")
                    break

        # 3. CVE eşleşmesi (en güçlü sinyal)
        group_cves = set(group.get("known_cves", []))
        cve_overlap = group_cves & found_cves
        if cve_overlap:
            match_score += len(cve_overlap) * 10
            matched_cves.update(cve_overlap)
            match_reasons.append(f"CVE eşleşmesi: {cve_overlap}")

        # 4. Sektör/teknoloji eşleşmesi
        for tech in technologies:
            tech_lower = tech.lower() if isinstance(tech, str) else ""
            for svc in indicator_services:
                if svc in tech_lower:
                    match_score += 3
                    match_reasons.append(f"Teknoloji eşleşmesi: {tech}")
                    break

        # Minimum eşik: en az 1 match_reason
        if match_reasons and match_score >= 4:
            # MITRE tekniklerini ekle
            for technique_id in group.get("techniques", []):
                mitre_techniques.add(technique_id)

            apt_matches.append({
                "group_id": group_id,
                "name": group["name"],
                "aliases": group["aliases"],
                "origin": group["origin"],
                "match_score": match_score,
                "risk_weight": group["risk_weight"],
                "match_reasons": match_reasons,
                "description": group["description"],
                "targets": group["targets"],
            })

            total_risk_score += match_score * (group["risk_weight"] / 10)

    # ---- Bilinen exploit edilen CVE kontrolü ----
    kev_matches = []
    for cve_id in found_cves:
        if cve_id in KNOWN_EXPLOITED_VULNS:
            kev_info = KNOWN_EXPLOITED_VULNS[cve_id]
            kev_matches.append({
                "cve": cve_id,
                "name": kev_info["name"],
                "severity": kev_info["severity"],
                "description": kev_info["description"],
                "apt_groups_using": kev_info["apt_groups"],
            })
            total_risk_score += 15  # KEV CVE = çok yüksek risk

    # ---- CDN bypass bonus ----
    origin_data = scan_results.get("origin_discovery", {})
    if isinstance(origin_data, dict) and origin_data.get("data"):
        origin_data = origin_data["data"]
    real_ip_found = False
    if isinstance(origin_data, dict):
        real_ip_found = bool(origin_data.get("best_candidate"))
    if is_behind_cdn and real_ip_found:
        total_risk_score += 20
        recommendations.append(
            "⚠️ KRİTİK: Cloudflare/CDN arkasında gerçek IP tespit edildi. "
            "Bu durum APT gruplarının doğrudan sunucuya erişebileceği anlamına gelir."
        )

    # ---- Exposed database/dangerous port bonus ----
    dangerous_ports = {3306, 5432, 27017, 6379, 9200, 445, 1433, 3389}
    exposed_dangerous = dangerous_ports & open_ports
    if exposed_dangerous:
        total_risk_score += len(exposed_dangerous) * 5
        recommendations.append(
            f"⚠️ Tehlikeli portlar açık: {exposed_dangerous}. "
            "Bu portlar APT gruplarının lateral movement ve data exfiltration için kullandığı vektörler."
        )

    # Normalize risk score to 0-100
    risk_score = min(100, int(total_risk_score))

    # Eşleşmeleri sırala (en yüksek puanlı önce)
    apt_matches.sort(key=lambda x: x["match_score"], reverse=True)

    # MITRE tekniklerini zenginleştir
    mitre_details = []
    for t_id in mitre_techniques:
        if t_id in MITRE_TECHNIQUES:
            mitre_details.append({
                "id": t_id,
                **MITRE_TECHNIQUES[t_id],
            })

    # Genel öneriler
    if apt_matches:
        top_group = apt_matches[0]
        recommendations.insert(0,
            f"🎯 En yüksek eşleşme: {top_group['name']} ({top_group['origin']}) - "
            f"Skor: {top_group['match_score']}. {top_group['description']}"
        )

    if kev_matches:
        recommendations.append(
            f"🚨 {len(kev_matches)} adet bilinen aktif exploit edilen zafiyet tespit edildi (CISA KEV). "
            "Acil yama uygulanmalı."
        )

    logger.info(
        f"📊 APT eşleştirme tamamlandı: "
        f"{len(apt_matches)} grup eşleşti, risk={risk_score}/100, "
        f"KEV={len(kev_matches)}, MITRE={len(mitre_techniques)} teknik"
    )

    return {
        "apt_matches": apt_matches,
        "risk_score": risk_score,
        "matched_cves": list(matched_cves),
        "kev_matches": kev_matches,
        "mitre_techniques": mitre_details,
        "recommendations": recommendations,
    }


def get_threat_landscape(target_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Hedefin sektör, teknoloji ve coğrafyasına göre tehdit manzarası.

    Args:
        target_info: {"sector": str, "technologies": list, "country": str}

    Returns:
        {"relevant_groups": [...], "risk_level": str, "description": str}
    """
    sector = target_info.get("sector", "").lower()
    technologies = [t.lower() for t in target_info.get("technologies", [])]
    country = target_info.get("country", "").lower()

    relevant_groups = []
    for group_id, group in APT_GROUPS.items():
        relevance_score = 0

        # Sektör eşleşmesi
        if sector and sector in group["targets"]:
            relevance_score += 10

        # Teknoloji eşleşmesi
        for tech in technologies:
            for svc in group["indicators"].get("services", []):
                if svc.lower() in tech or tech in svc.lower():
                    relevance_score += 5
                    break

        if relevance_score > 0:
            relevant_groups.append({
                "group_id": group_id,
                "name": group["name"],
                "origin": group["origin"],
                "relevance_score": relevance_score,
                "description": group["description"],
            })

    relevant_groups.sort(key=lambda x: x["relevance_score"], reverse=True)

    # Risk seviyesi
    if len(relevant_groups) >= 5:
        risk_level = "critical"
    elif len(relevant_groups) >= 3:
        risk_level = "high"
    elif len(relevant_groups) >= 1:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "relevant_groups": relevant_groups[:10],
        "risk_level": risk_level,
        "total_relevant_groups": len(relevant_groups),
        "description": (
            f"{sector or 'Genel'} sektöründe {len(relevant_groups)} potansiyel "
            f"tehdit aktörü tespit edildi. Risk seviyesi: {risk_level.upper()}."
        ),
    }


def get_apt_group_info(group_id: str) -> Optional[Dict[str, Any]]:
    """Belirli bir APT grubunun detaylarını döndür."""
    return APT_GROUPS.get(group_id)


# ============================================================
# YARDIMCI FONKSİYONLAR
# ============================================================

def _extract_ports(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tarama sonuçlarından port bilgilerini çıkar."""
    ports = []

    # port_scan / direct_ip_scan / domain_port_scan / fast_port_scan
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
    """Tarama sonuçlarından zafiyet bilgilerini çıkar."""
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
