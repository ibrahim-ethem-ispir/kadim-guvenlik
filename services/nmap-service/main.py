from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
import subprocess
import asyncio
import logging
import json
import os
import re
import signal
from datetime import datetime
from typing import Optional, Dict, Any, List
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import xml.etree.ElementTree as ET

app = FastAPI(title="Nmap Service", version="2.0.0")

# ============== MongoDB Configuration ==============
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://mongodb:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")

# Türkçe: MongoDB bağlantısını başlat
mongo_client = None
db = None

try:
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    mongo_client.admin.command('ping')
    db = mongo_client[MONGODB_DATABASE]
    logging.info("✅ Nmap Service: MongoDB bağlantısı başarılı")
except ConnectionFailure as e:
    logging.error(f"⚠️ Nmap Service: MongoDB bağlantı hatası: {e}")
    db = None

def get_nmap_logs_collection():
    """Türkçe: NmapLogs koleksiyonunu döner"""
    if db is None:
        return None
    return db["NmapLogs"]

def get_active_scans_collection():
    """Türkçe: NmapActiveScans koleksiyonunu döner"""
    if db is None:
        return None
    return db["NmapActiveScans"]

def add_nmap_log(scan_id: str, level: str, message: str, data: Optional[Dict] = None):
    """
    Türkçe: MongoDB'ye log kaydı ekler
    Levels: INFO, WARNING, ERROR, DISCOVERY, PORT, SERVICE, SCRIPT, SCAN_START, SCAN_END
    """
    collection = get_nmap_logs_collection()
    if collection is None:
        return None
    
    try:
        doc = {
            "scan_id": scan_id,
            "timestamp": datetime.utcnow(),
            "level": level,
            "message": message,
            "data": data or {}
        }
        result = collection.insert_one(doc)
        return result.inserted_id
    except Exception as e:
        logging.error(f"Nmap Log insert error: {e}")
        return None

def save_active_scan(scan_id: str, target: str, pid: int, command: List[str] = None):
    """Türkçe: Aktif taramayı MongoDB'ye kaydeder (Recovery için)"""
    collection = get_active_scans_collection()
    if collection is None: return
    
    try:
        doc = {
            "scan_id": scan_id,
            "target": target,
            "pid": pid,
            "status": "running",
            "started_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "command": command or []
        }
        collection.update_one({"scan_id": scan_id}, {"$set": doc}, upsert=True)
    except Exception as e:
        logging.error(f"Active scan save failed: {e}")

def remove_active_scan(scan_id: str, status: str = "completed"):
    """Türkçe: Aktif taramayı tamamlandı olarak işaretler"""
    collection = get_active_scans_collection()
    if collection is None: return

    try:
        collection.update_one(
            {"scan_id": scan_id},
            {"$set": {"status": status, "updated_at": datetime.utcnow()}}
        )
    except Exception as e:
        logging.error(f"Active scan remove failed: {e}")


def parse_nmap_xml(xml_content: str) -> Dict[str, Any]:
    """
    Türkçe: Nmap XML çıktısını parse eder

    Bu fonksiyon regex tabanlı parsing'den çok daha güvenilirdir.
    Nmap'in farklı versiyonları ve çıktı formatları ile uyumludur.

    Args:
        xml_content: Nmap XML çıktısı (string)

    Returns:
        Dict: Parse edilmiş tarama sonuçları
    """
    result = {
        "hosts": [],
        "scan_info": {},
        "run_stats": {},
        "parse_errors": []
    }

    try:
        root = ET.fromstring(xml_content)

        # Scan bilgileri
        result["scan_info"] = {
            "scanner": root.get("scanner", "nmap"),
            "args": root.get("args", ""),
            "start": root.get("start", ""),
            "startstr": root.get("startstr", ""),
            "version": root.get("version", "")
        }

        # Her host için
        for host in root.findall('.//host'):
            host_data = {
                "status": None,
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": None,
                "uptime": None
            }

            # Status
            status_elem = host.find('status')
            if status_elem is not None:
                host_data["status"] = {
                    "state": status_elem.get('state'),
                    "reason": status_elem.get('reason')
                }

            # IP ve MAC adresleri
            for addr in host.findall('address'):
                host_data["addresses"].append({
                    "addr": addr.get('addr'),
                    "addrtype": addr.get('addrtype'),
                    "vendor": addr.get('vendor')
                })

            # Hostname'ler
            for hostname in host.findall('.//hostname'):
                host_data["hostnames"].append({
                    "name": hostname.get('name'),
                    "type": hostname.get('type')
                })

            # Portlar
            for port in host.findall('.//port'):
                port_data = {
                    "port": int(port.get('portid')),
                    "protocol": port.get('protocol'),
                    "state": None,
                    "service": None,
                    "scripts": []
                }

                # Port state
                state = port.find('state')
                if state is not None:
                    port_data["state"] = {
                        "state": state.get('state'),
                        "reason": state.get('reason'),
                        "reason_ttl": state.get('reason_ttl')
                    }

                # Service bilgisi
                service = port.find('service')
                if service is not None:
                    port_data["service"] = {
                        "name": service.get('name'),
                        "product": service.get('product'),
                        "version": service.get('version'),
                        "extrainfo": service.get('extrainfo'),
                        "ostype": service.get('ostype'),
                        "method": service.get('method'),
                        "conf": service.get('conf'),
                        "tunnel": service.get('tunnel')
                    }

                # NSE script sonuçları
                for script in port.findall('script'):
                    script_data = {
                        "id": script.get('id'),
                        "output": script.get('output')
                    }
                    # Script içindeki tablolar
                    for table in script.findall('.//table'):
                        script_data["table"] = table.get('key')
                    port_data["scripts"].append(script_data)

                host_data["ports"].append(port_data)

            # OS Detection
            os_elem = host.find('.//os')
            if os_elem is not None:
                os_matches = []
                for osmatch in os_elem.findall('osmatch'):
                    os_matches.append({
                        "name": osmatch.get('name'),
                        "accuracy": osmatch.get('accuracy'),
                        "line": osmatch.get('line')
                    })
                if os_matches:
                    host_data["os"] = os_matches

            # Uptime
            uptime = host.find('.//uptime')
            if uptime is not None:
                host_data["uptime"] = {
                    "seconds": uptime.get('seconds'),
                    "lastboot": uptime.get('lastboot')
                }

            result["hosts"].append(host_data)

        # Run stats
        runstats = root.find('.//runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            hosts_stat = runstats.find('hosts')

            if finished is not None:
                result["run_stats"]["finished"] = {
                    "time": finished.get('time'),
                    "timestr": finished.get('timestr'),
                    "elapsed": finished.get('elapsed'),
                    "summary": finished.get('summary'),
                    "exit": finished.get('exit')
                }

            if hosts_stat is not None:
                result["run_stats"]["hosts"] = {
                    "up": hosts_stat.get('up'),
                    "down": hosts_stat.get('down'),
                    "total": hosts_stat.get('total')
                }

    except ET.ParseError as e:
        result["parse_errors"].append(f"XML parse error: {str(e)}")
        logging.error(f"Nmap XML parse error: {e}")
    except Exception as e:
        result["parse_errors"].append(f"Unexpected error: {str(e)}")
        logging.error(f"Nmap XML processing error: {e}")

    return result


def extract_findings_from_xml(xml_result: Dict) -> List[Dict]:
    """
    Türkçe: XML parse sonucundan findings_summary formatına dönüştürür

    Bu format orchestrator'ün beklediği yapıyla uyumludur.
    """
    findings = []

    for host in xml_result.get("hosts", []):
        # IP adresini bul
        ip_addr = None
        for addr in host.get("addresses", []):
            if addr.get("addrtype") == "ipv4":
                ip_addr = addr.get("addr")
                break

        for port_data in host.get("ports", []):
            state_info = port_data.get("state", {})
            service_info = port_data.get("service", {})

            # Sadece açık portları ekle
            if state_info.get("state") != "open":
                continue

            finding = {
                "port": port_data.get("port"),
                "protocol": port_data.get("protocol"),
                "state": state_info.get("state"),
                "reason": state_info.get("reason"),
                "service": service_info.get("name"),
                "product": service_info.get("product"),
                "version": service_info.get("version"),
                "extrainfo": service_info.get("extrainfo"),
                "host": ip_addr
            }

            # Script sonuçlarını ekle
            scripts = port_data.get("scripts", [])
            if scripts:
                finding["scripts"] = [
                    {"id": s.get("id"), "output": s.get("output")[:500] if s.get("output") else None}
                    for s in scripts[:5]  # Max 5 script
                ]

            findings.append(finding)

    return findings


# ============== Kısmi Sonuç Kurtarma (timeout dayanıklılığı) ==============
# NEDEN: Yüksek kapasiteli (tüm-port/agresif) taramalar orchestrator timeout'unu aşınca
# eskiden 0 port dönüyordu — o ana kadar bulunan her şey çöpe gidiyordu. Nmap açık portları
# tararken CANLI stdout'a ("Discovered open port ...") yazar; bunları NmapLogs'a kaydediyoruz.
# XML ise ancak host TAMAMEN bitince port bloğu yazar — mid-scan timeout'ta genelde boştur —
# bu yüzden birincil canlı kaynak NmapLogs'tur, XML ikincil (tamamlanmış host varsa zengin).

_PORT_TABLE_RE = re.compile(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)', re.IGNORECASE)
_DISCOVERY_RE = re.compile(r'Discovered open port (\d+)/(tcp|udp)', re.IGNORECASE)


def recover_partial_xml(content: str) -> Optional[str]:
    """Kesik nmap XML'ini kurtarmayı dener: son tamamlanmış </host>'a kadar kırpıp kökü
    kapatır. nmap -oX çıktısı </nmaprun> ile kapanmadan biterse ET ham içeriği parse edemez."""
    idx = content.rfind("</host>")
    if idx == -1 or "<nmaprun" not in content[:idx]:
        return None
    return content[:idx + len("</host>")] + "</nmaprun>"


def findings_from_logs(scan_id: str) -> List[Dict]:
    """NmapLogs'a canlı yazılmış açık-port satırlarından findings_summary üretir.
    PORT satırı (tablo, servis adlı) önceliklidir; yoksa DISCOVERY satırı (port+proto)."""
    coll = get_nmap_logs_collection()
    if coll is None:
        return []
    by_port: Dict[tuple, Dict] = {}
    try:
        cursor = coll.find(
            {"scan_id": scan_id, "level": {"$in": ["PORT", "DISCOVERY"]}}
        ).sort("timestamp", 1)
        for doc in cursor:
            msg = (doc.get("message") or "").strip()
            m = _PORT_TABLE_RE.match(msg)
            if m:
                port, proto = int(m.group(1)), m.group(2).lower()
                by_port[(port, proto)] = {
                    "port": port, "protocol": proto, "state": "open",
                    "service": m.group(3), "product": None, "version": None,
                }
                continue
            d = _DISCOVERY_RE.search(msg)
            if d:
                port, proto = int(d.group(1)), d.group(2).lower()
                # Servisli (PORT) kayıt varsa DISCOVERY üstüne yazmasın
                by_port.setdefault((port, proto), {
                    "port": port, "protocol": proto, "state": "open",
                    "service": None, "product": None, "version": None,
                })
    except Exception as e:
        logger.warning(f"NmapLogs kısmi okuma hatası ({scan_id}): {e}")
    return list(by_port.values())

# Türkçe: Log dizini oluştur (Docker volume mount edilebilir)
LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("nmap-service")

class ScanRequest(BaseModel):
    target: str
    scan_id: str
    options: Optional[Dict[str, Any]] = {}  # Türkçe: UI'dan gelen tüm nmap parametreleri

def validate_options(options: Dict[str, Any]) -> tuple[bool, str]:
    """Türkçe: Nmap seçeneklerini validate eder
    Returns: (is_valid, error_message)
    """
    # Pozitif sayı kontrolü
    if options.get("--max-retries"):
        val = options["--max-retries"]
        if isinstance(val, (int, float)) and val < 0:
            return False, "Max Retries negatif olamaz. Pozitif bir sayı girin."
        try:
            if int(val) < 0:
                return False, "Max Retries negatif olamaz. Pozitif bir sayı girin."
        except (ValueError, TypeError):
            return False, "Max Retries geçerli bir sayı olmalı."
    
    if options.get("--min-rate"):
        val = options["--min-rate"]
        if isinstance(val, (int, float)) and val < 0:
            return False, "Min Rate negatif olamaz. Pozitif bir sayı girin."
        try:
            if int(val) < 0:
                return False, "Min Rate negatif olamaz. Pozitif bir sayı girin."
        except (ValueError, TypeError):
            return False, "Min Rate geçerli bir sayı olmalı."
    
    if options.get("--max-rate"):
        val = options["--max-rate"]
        if isinstance(val, (int, float)) and val < 0:
            return False, "Max Rate negatif olamaz. Pozitif bir sayı girin."
        try:
            if int(val) < 0:
                return False, "Max Rate negatif olamaz. Pozitif bir sayı girin."
        except (ValueError, TypeError):
            return False, "Max Rate geçerli bir sayı olmalı."
    
    if options.get("--top-ports"):
        val = options["--top-ports"]
        if isinstance(val, (int, float)) and val < 1:
            return False, "Top Ports en az 1 olmalı."
        try:
            if int(val) < 1:
                return False, "Top Ports en az 1 olmalı."
        except (ValueError, TypeError):
            return False, "Top Ports geçerli bir sayı olmalı."
    
    if options.get("--source-port"):
        val = options["--source-port"]
        try:
            port = int(val)
            if port < 1 or port > 65535:
                return False, "Kaynak Port 1-65535 arasında olmalı."
        except (ValueError, TypeError):
            return False, "Kaynak Port geçerli bir sayı olmalı."
    
    if options.get("--data-length"):
        val = options["--data-length"]
        if isinstance(val, (int, float)) and val < 0:
            return False, "Data Length negatif olamaz."
        try:
            if int(val) < 0:
                return False, "Data Length negatif olamaz."
        except (ValueError, TypeError):
            return False, "Data Length geçerli bir sayı olmalı."
    
    # Min-rate ve max-rate mantıksal kontrolü
    if options.get("--min-rate") and options.get("--max-rate"):
        try:
            min_r = int(options["--min-rate"])
            max_r = int(options["--max-rate"])
            if min_r > max_r:
                return False, "Min Rate, Max Rate'den büyük olamaz."
        except (ValueError, TypeError):
            pass
    
    return True, ""


def validate_custom_command(custom_cmd: str) -> tuple[bool, str, list]:
    """
    Türkçe: Özel nmap komutunu güvenlik kontrollerinden geçirir
    
    Güvenlik Kontrolleri:
    1. Command injection engelleme (|, ;, &&, ||, $, `, etc.)
    2. Tehlikeli flagler engelleme (--script=exploit, -iR, etc.)
    3. Privilege escalation engelleme
    4. Sadece nmap komutlarına izin ver
    
    Returns: (is_valid, error_message, sanitized_command_parts)
    """
    if not custom_cmd or not custom_cmd.strip():
        return False, "Komut boş olamaz", []
    
    custom_cmd = custom_cmd.strip()
    
    # === GÜVENLİK KONTROLÜ 1: Tehlikeli karakterler ===
    dangerous_chars = [';', '|', '&&', '||', '`', '$', '$(', '>', '<', '>>', '<<', '\n', '\r', '\\n']
    for char in dangerous_chars:
        if char in custom_cmd:
            return False, f"Güvenlik ihlali: '{char}' karakteri izin verilmiyor. Komut enjeksiyonu engellendi.", []
    
    # === GÜVENLİK KONTROLÜ 2: Komut nmap ile başlamalı ===
    parts = custom_cmd.split()
    if not parts:
        return False, "Geçersiz komut formatı", []
    
    # nmap ile başlamalı veya sadece parametreler olabilir
    if parts[0].lower() == 'nmap':
        parts = parts[1:]  # nmap'i kaldır, backend ekleyecek
    elif parts[0].startswith('-'):
        pass  # Sadece parametreler, OK
    else:
        return False, "Komut 'nmap' ile başlamalı veya nmap parametreleri olmalı", []
    
    # === GÜVENLİK KONTROLÜ 3: Root/sudo gerektiren tehlikeli flagler ===
    dangerous_flags = [
        '--privileged',
        '--interactive', '-i',
        '--script=exploit',
        '--script=brute',
        '--script-args-file',
        '-iR',  # Random target - çok tehlikeli
        '-iL',  # Target list file
        '--datadir',  # Custom data directory
        '--script-updatedb',  # Script DB update
        '--resume',  # Resume from file
        '-oG -',  # Grepable output to stdout (potential abuse)
        '-oN -',  # Normal output to stdout
        '-oX -',  # XML output to stdout
    ]
    
    cmd_lower = custom_cmd.lower()
    for flag in dangerous_flags:
        if flag.lower() in cmd_lower:
            return False, f"Güvenlik ihlali: '{flag}' tehlikeli flag izin verilmiyor", []
    
    # === GÜVENLİK KONTROLÜ 4: Script args'ta tehlikeli değerler ===
    if '--script-args' in cmd_lower:
        # Dosya yolu içerebilir mi?
        if 'file=' in cmd_lower or 'path=' in cmd_lower or '/etc/' in cmd_lower or '/root/' in cmd_lower:
            return False, "Güvenlik ihlali: Script args'ta dosya yolu izin verilmiyor", []
    
    # === GÜVENLİK KONTROLÜ 5: Çok uzun komut kontrolü (DoS önlemi) ===
    if len(custom_cmd) > 1000:
        return False, "Komut çok uzun (max 1000 karakter)", []
    
    # === GÜVENLİK KONTROLÜ 6: Minimum bir hedef olmalı ===
    # Son parametre genellikle hedeftir, IP veya domain olmalı
    # Bu kontrolü frontend'e bırakabiliriz
    
    # === İZİN VERİLEN SCRIPTLER (whitelist) ===
    allowed_script_categories = [
        'default', 'safe', 'version', 'discovery', 
        'auth', 'vuln', 'ssl-enum-ciphers', 'ssl-cert',
        'http-headers', 'http-title', 'dns-brute',
        'smb-enum-shares', 'smb-os-discovery',
        'ssh-hostkey', 'ssh-auth-methods',
        'banner', 'whois-ip', 'dns-zone-transfer'
    ]
    
    # Script varsa whitelist kontrolü
    if '--script=' in cmd_lower or '--script ' in cmd_lower:
        # Script değerini çıkar
        import re
        script_match = re.search(r'--script[=\s]+([^\s]+)', custom_cmd, re.IGNORECASE)
        if script_match:
            scripts = script_match.group(1).split(',')
            for script in scripts:
                script = script.strip().lower()
                # Wildcard kontrolü
                if '*' in script or '?' in script:
                    return False, f"Güvenlik ihlali: Script wildcard izin verilmiyor", []
                # exploit, brute, intrusive script kategorileri engellenmeli
                if script in ['exploit', 'brute', 'intrusive', 'dos', 'malware']:
                    return False, f"Güvenlik ihlali: '{script}' script kategorisi izin verilmiyor", []
    
    return True, "", parts

def build_nmap_command(target: str, options: Dict[str, Any]) -> list:
    """Türkçe: UI'dan gelen seçenekleri nmap komutuna dönüştürür
    NOT: Nmap sadece bir TCP tarama tipi kabul eder (-sS, -sT, -sF, vb.)
    Öncelik sırası: -sS > -sT > -sA > -sF > -sN > -sX
    
    Eğer options içinde 'custom_cmd' varsa, güvenlik kontrolünden geçirilip kullanılır.
    """
    
    # === CUSTOM COMMAND MODU ===
    if options.get("custom_cmd"):
        custom_cmd = options["custom_cmd"]
        is_valid, error_msg, cmd_parts = validate_custom_command(custom_cmd)
        
        if not is_valid:
            raise ValueError(error_msg)
        
        # Güvenli komut oluştur
        cmd = ["nmap", "-vv", "--reason"]  # Base güvenlik flagleri
        cmd.extend(cmd_parts)
        
        # Hedef komutta yoksa ekle
        if target and target not in cmd:
            cmd.append(target)
        
        return cmd
    
    # === STANDART MOD (mevcut mantık) ===
    cmd = ["nmap", "-vv", "--reason", "--open"]  # Premium verbosity headers
    
    # Türkçe: TCP tarama tipi seçimi (sadece bir tanesi seçilmeli)
    scan_types = options.get("scan_type", [])
    tcp_scan_added = False
    
    # Öncelik sırasına göre sadece bir tarama tipi ekle
    if "-sS" in scan_types and not tcp_scan_added:
        cmd.append("-sS")
        tcp_scan_added = True
    elif "-sT" in scan_types and not tcp_scan_added:
        cmd.append("-sT")
        tcp_scan_added = True
    elif "-sA" in scan_types and not tcp_scan_added:
        cmd.append("-sA")
        tcp_scan_added = True
    elif "-sF" in scan_types and not tcp_scan_added:
        cmd.append("-sF")
        tcp_scan_added = True
    elif "-sN" in scan_types and not tcp_scan_added:
        cmd.append("-sN")
        tcp_scan_added = True
    elif "-sX" in scan_types and not tcp_scan_added:
        cmd.append("-sX")
        tcp_scan_added = True
    
    # UDP taraması TCP ile birlikte kullanılabilir
    if "-sU" in scan_types:
        cmd.append("-sU")
    
    # Türkçe: Diğer checkbox seçenekleri
    if options.get("-sV"):
        cmd.append("-sV")
    if options.get("-O"):
        cmd.append("-O")
    if options.get("-A"):
        cmd.append("-A")
    
    # Türkçe: Port seçimi
    # NOT: "-p-" (tüm 65535 port) ayrı bir bayrak; eskiden işlenmiyordu → profil "-p-": True
    # dese bile sessizce nmap varsayılanına (top-1000) düşüyordu. Artık açıkça ekleniyor.
    if options.get("-p"):
        cmd.extend(["-p", options["-p"]])
    elif options.get("-p-"):
        cmd.append("-p-")
    elif options.get("-F"):
        cmd.append("-F")
    elif options.get("--top-ports"):
        cmd.extend(["--top-ports", str(options["--top-ports"])])
    
    # Türkçe: Zamanlama (radio group)
    timing = options.get("timing", "-T3")
    cmd.append(timing)
    
    # Türkçe: Firewall atlatma
    if options.get("-f"):
        cmd.append("-f")
    if options.get("-D"):
        cmd.extend(["-D", options["-D"]])
    if options.get("-S"):
        cmd.extend(["-S", options["-S"]])
    if options.get("--source-port"):
        cmd.extend(["--source-port", str(options["--source-port"])])
    if options.get("--data-length"):
        cmd.extend(["--data-length", str(options["--data-length"])])
    if options.get("--randomize-hosts"):
        cmd.append("--randomize-hosts")
    if options.get("--spoof-mac"):
        cmd.extend(["--spoof-mac", options["--spoof-mac"]])
    
    # Türkçe: NSE Scriptler
    scripts = []
    if options.get("--script=default"):
        scripts.append("default")
    if options.get("--script=vuln"):
        scripts.append("vuln")
    if options.get("--script=exploit"):
        scripts.append("exploit")
    if options.get("--script=auth"):
        scripts.append("auth")
    if options.get("--script=brute"):
        scripts.append("brute")
    if scripts:
        cmd.extend(["--script", ",".join(scripts)])
    
    # Türkçe: Çıktı seçenekleri
    if options.get("-v"):
        cmd.append("-v")
    if options.get("-vv"):
        cmd.append("-vv")
    if options.get("-d"):
        cmd.append("-d")
    if options.get("--reason"):
        cmd.append("--reason")
    if options.get("--open"):
        cmd.append("--open")
    
    # Türkçe: Gelişmiş seçenekler
    if options.get("--max-retries"):
        cmd.extend(["--max-retries", str(options["--max-retries"])])
    if options.get("--host-timeout"):
        cmd.extend(["--host-timeout", options["--host-timeout"]])
    if options.get("--min-rate"):
        cmd.extend(["--min-rate", str(options["--min-rate"])])
    if options.get("--max-rate"):
        cmd.extend(["--max-rate", str(options["--max-rate"])])
    if options.get("--version-intensity"):
        cmd.extend(["--version-intensity", str(options["--version-intensity"])])

    # YENİ: XML çıktı desteği (daha güvenilir parsing için)
    # XML dosyası scan_id ile kaydedilir, ayrıca normal çıktı da gösterilir
    if options.get("enable_xml_output", True):  # Varsayılan olarak açık
        # XML çıktısını dosyaya yaz (parse için)
        # -oX - yaparsak stdout'a XML gelir ama normal çıktı kaybolur
        # Bu yüzden dosyaya yazıp sonra okuyoruz
        pass  # XML dosyası run_scan içinde handle edilecek

    cmd.append(target)
    return cmd

@app.get("/health")
async def health_check():
    """Türkçe: Servis sağlık kontrolü"""
    try:
        # Nmap kontrolü
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        version = result.stdout.strip().split('\n')[0]
        
        # MongoDB kontrolü
        mongo_status = "connected" if db is not None else "disconnected"
        
        return {
            "status": "healthy" if db is not None else "degraded",
            "service": "nmap-service",
            "nmap_version": version,
            "mongodb": mongo_status
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

@app.post("/scan")
async def run_scan(request: ScanRequest):
    """
    Türkçe: Nmap taramasını başlatır ve sonucu döner

    Özellikler:
    - Normal çıktı + XML çıktı (güvenilir parsing için)
    - Detaylı findings_summary
    - Komut bilgisi response'ta
    """
    log_file = os.path.join(LOG_DIR, f"{request.scan_id}.log")
    xml_file = os.path.join(LOG_DIR, f"{request.scan_id}.xml")

    try:
        cmd = build_nmap_command(request.target, request.options)

        # XML çıktı ekle (ayrı dosyaya)
        cmd_with_xml = cmd[:-1] + ["-oX", xml_file, cmd[-1]]  # target'ı sona koy

        command_str = " ".join(cmd_with_xml)

        add_nmap_log(request.scan_id, "SCAN_START", f"Nmap taraması başlatıldı: {request.target}", {
            "target": request.target,
            "command": command_str
        })

        logger.info(f"Nmap command: {command_str}")

        # Türkçe: Nmap'i subprocess ile çalıştır ve çıktıyı logla (Async)
        with open(log_file, "w") as log:
            log.write(f"Scan started at: {datetime.now().isoformat()}\n")
            log.write(f"Command: {command_str}\n\n")

            process = await asyncio.create_subprocess_exec(
                *cmd_with_xml,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            # Recovery için kaydet
            save_active_scan(request.scan_id, request.target, process.pid, cmd_with_xml)

            output_lines = []
            open_ports_count = 0

            # Async line reading
            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                line_text = line.decode().strip()
                if not line_text: continue

                log.write(line.decode())
                log.flush()
                output_lines.append(line_text)

                # Parsing logic
                level = "INFO"
                if "Discovered" in line_text: level = "DISCOVERY"
                elif "/tcp" in line_text or "/udp" in line_text:
                    if "open" in line_text:
                        level = "PORT"
                        open_ports_count += 1
                    else: level = "INFO"
                elif line_text.startswith("|") or line_text.startswith("_"): level = "SCRIPT"
                elif "OS details" in line_text or "Service Info" in line_text: level = "SYSTEM"

                add_nmap_log(request.scan_id, level, line_text, {"raw": line_text})

            await process.wait()

            log.write(f"\nScan completed at: {datetime.now().isoformat()}\n")
            log.write(f"Exit code: {process.returncode}\n")

            add_nmap_log(request.scan_id, "SCAN_END", f"Tarama tamamlandı (exit: {process.returncode})", {
                "exit_code": process.returncode
            })
            remove_active_scan(request.scan_id, "completed" if process.returncode == 0 else "failed")

        logger.info(f"Nmap scan completed for {request.target}")

        # YENİ: XML dosyasını parse et ve zengin sonuç döndür
        findings_summary = []
        xml_parsed = None

        if os.path.exists(xml_file):
            try:
                with open(xml_file, "r") as xf:
                    xml_content = xf.read()
                xml_parsed = parse_nmap_xml(xml_content)
                findings_summary = extract_findings_from_xml(xml_parsed)
                logger.info(f"XML parsed successfully: {len(findings_summary)} ports found")
            except Exception as xml_err:
                logger.error(f"XML parse error: {xml_err}")

        # HOST DURUMU (dürüst-tarama sözleşmesi): türetim ayrı yardımcıda (test edilebilir).
        host_status = derive_host_status(xml_parsed)

        return {
            "scan_id": request.scan_id,
            "target": request.target,
            "status": "completed",
            "exit_code": process.returncode,
            "command": command_str,  # YENİ: Çalıştırılan komut
            "output": "\n".join(output_lines[-100:]),  # Son 100 satır
            "log_file": f"{request.scan_id}.log",
            "xml_file": f"{request.scan_id}.xml" if os.path.exists(xml_file) else None,
            # YENİ: Zenginleştirilmiş sonuçlar
            "findings_summary": findings_summary,
            "open_ports_count": len(findings_summary),
            "scan_stats": xml_parsed.get("run_stats") if xml_parsed else None,
            "host_status": host_status
        }

    except Exception as e:
        logger.error(f"Nmap scan failed: {str(e)}")
        add_nmap_log(request.scan_id, "ERROR", f"Tarama hatası: {str(e)}")
        remove_active_scan(request.scan_id, "failed")
        with open(log_file, "a") as log:
            log.write(f"\nERROR: {str(e)}\n")
        return {"error": str(e), "scan_id": request.scan_id, "status": "failed"}


def derive_host_status(xml_parsed: Optional[Dict]) -> str:
    """XML parse sonucundan host durumunu türet ('up'/'down').

    DÜRÜST-TARAMA sözleşmesi: runstats 'hosts up=0' VE hiç host kaydı yoksa hedef
    açıkça down. XML yoksa/belirsizse 'up' varsay (geriye-uyum — belirsiz durumda
    durdurma kararı verilmez). Orchestrator 'down' görürse taramayı boş 'temiz'
    raporu üretmeden keser."""
    if not xml_parsed:
        return "up"
    try:
        _rs_hosts = ((xml_parsed.get("run_stats") or {}).get("hosts") or {})
        _up_cnt = int(_rs_hosts.get("up") or 0)
    except (TypeError, ValueError):
        _up_cnt = 1
    if _up_cnt <= 0 and not xml_parsed.get("hosts"):
        return "down"
    return "up"


@app.get("/partial/{scan_id}")
async def get_partial_results(scan_id: str):
    """Türkçe: Devam eden/kesilen taramadan o ana kadar bulunan açık portları döner.
    Orchestrator timeout kurtarmasında (_fetch_nmap_partial) çağırır. Kaynak önceliği:
    tamamlanmış XML host bloğu (servis/versiyon zengin) → yoksa canlı NmapLogs satırları."""
    xml_file = os.path.join(LOG_DIR, f"{scan_id}.xml")
    findings: List[Dict] = []
    source = None

    if os.path.exists(xml_file):
        try:
            with open(xml_file, "r") as xf:
                content = xf.read()
            parsed = parse_nmap_xml(content)
            if not parsed.get("hosts"):
                recovered = recover_partial_xml(content)
                if recovered:
                    parsed = parse_nmap_xml(recovered)
            if parsed.get("hosts"):
                findings = extract_findings_from_xml(parsed)
                source = "xml"
        except Exception as e:
            logger.warning(f"Kısmi XML parse hatası ({scan_id}): {e}")

    # XML'de port yoksa (mid-scan timeout'ta olağan) canlı log'lara düş
    if not findings:
        findings = findings_from_logs(scan_id)
        if findings:
            source = "logs"

    return {
        "scan_id": scan_id,
        "status": "partial",
        "findings_summary": findings,
        "open_ports_count": len(findings),
        "source": source,
    }


@app.delete("/scan/{scan_id}")
async def stop_scan(scan_id: str):
    """Türkçe: Çalışan nmap taramasını durdur (orchestrator timeout kurtarmasında çağırır).
    Orphan nmap süreçleri servis kaynağını (CPU) tüketmesin diye kayıtlı PID'e SIGTERM.
    Eskiden bu endpoint YOKTU → _try_stop_scan 404 alıyor, tarama arkada saatlerce sürüyordu."""
    coll = get_active_scans_collection()
    stopped = False
    if coll is not None:
        try:
            doc = coll.find_one({"scan_id": scan_id})
            # SADECE hâlâ 'running' ise öldür: tarama bitmişse PID geri dönüşümü ile
            # masum bir süreci öldürme riskini önler.
            if doc and doc.get("status") == "running" and doc.get("pid"):
                try:
                    os.kill(int(doc["pid"]), signal.SIGTERM)
                    stopped = True
                    logger.info(f"Nmap süreci durduruldu: scan_id={scan_id} pid={doc['pid']}")
                except ProcessLookupError:
                    pass  # süreç zaten sonlanmış
                except Exception as e:
                    logger.warning(f"Nmap süreç durdurma hatası ({scan_id}): {e}")
        except Exception as e:
            logger.warning(f"Aktif tarama sorgu hatası ({scan_id}): {e}")
    remove_active_scan(scan_id, "cancelled")
    return {"scan_id": scan_id, "stopped": stopped}


@app.websocket("/scan/stream/{scan_id}")
async def scan_stream(websocket: WebSocket, scan_id: str):
    """Türkçe: Real-time nmap çıktısını WebSocket ile stream eder
    Uzun süreli taramalar için progress tracking sağlar"""
    await websocket.accept()
    
    try:
        # Türkçe: İlk mesajda scan parametrelerini al
        data = await websocket.receive_json()
        target = data.get("target")
        options = data.get("options", {})
        
        # Validation kontrolü
        is_valid, error_msg = validate_options(options)
        if not is_valid:
            await websocket.send_json({
                "type": "error",
                "message": f"Geçersiz parametre: {error_msg}"
            })
            return
        
        log_file = os.path.join(LOG_DIR, f"{scan_id}.log")
        cmd = build_nmap_command(target, options)
        
        logger.info(f"Starting streaming scan: {' '.join(cmd)}")
        
        # İlk durum mesajı gönder
        await websocket.send_json({
            "type": "status",
            "data": "Tarama başlatılıyor...",
            "timestamp": datetime.now().isoformat()
        })
        
        add_nmap_log(scan_id, "SCAN_START", f"Streaming Nmap taraması başlatıldı: {target}", {
            "target": target,
            "command": " ".join(cmd)
        })
        
        with open(log_file, "w") as log:
            log.write(f"Scan started at: {datetime.now().isoformat()}\n")
            log.write(f"Command: {' '.join(cmd)}\n\n")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            
            # Recovery için kaydet
            save_active_scan(scan_id, target, process.pid, cmd)
            
            # Türkçe: Her satırı WebSocket'e gönder ve progress bilgisi çıkar
            line_count = 0
            last_heartbeat = datetime.now()
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                line_text = line.decode().strip()
                if not line_text: continue
                
                log.write(line_text + "\n")
                log.flush()
                line_count += 1
                
                # Parsing logic
                level = "INFO"
                message_type = "output"  # Türkçe: Frontend her türlü mesajı "output" olarak kabul ediyor
                
                if "Discovered" in line_text:
                    level = "DISCOVERY"
                elif "Scanning" in line_text or "Initiating" in line_text:
                    level = "PROGRESS"
                elif "Completed" in line_text or "finished" in line_text:
                    level = "PROGRESS"
                elif "/tcp" in line_text or "/udp" in line_text:
                    if "open" in line_text:
                        level = "PORT"
                    else:
                        level = "INFO"
                elif line_text.startswith("|") or line_text.startswith("_"):
                    level = "SCRIPT"
                elif "OS details" in line_text or "Service Info" in line_text:
                    level = "SYSTEM"
                
                # MongoDB log
                add_nmap_log(scan_id, level, line_text, {"raw": line_text})
                
                # Türkçe: Frontend'e tutarlı format ile gönder
                await websocket.send_json({
                    "type": "output",  # Frontend tüm çıktıları "output" olarak bekliyor
                    "level": level,
                    "data": line_text,
                    "line_number": line_count,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Her 10 saniyede bir heartbeat gönder (uzun sessiz periyotlar için)
                now = datetime.now()
                if (now - last_heartbeat).seconds >= 10:
                    await websocket.send_json({
                        "type": "heartbeat",
                        "data": f"Tarama devam ediyor... ({line_count} satır işlendi)",
                        "timestamp": now.isoformat()
                    })
                    last_heartbeat = now
            
            await process.wait()
            
            log.write(f"\nScan completed at: {datetime.now().isoformat()}\n")
            log.write(f"Exit code: {process.returncode}\n")
            
            add_nmap_log(scan_id, "SCAN_END", f"Tarama tamamlandı (exit: {process.returncode})", {
                "exit_code": process.returncode
            })
            remove_active_scan(scan_id, "completed" if process.returncode == 0 else "failed")
            
            await websocket.send_json({
                "type": "complete",
                "exit_code": process.returncode,
                "log_file": f"{scan_id}.log",
                "total_lines": line_count,
                "timestamp": datetime.now().isoformat()
            })
            
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"Streaming scan error: {str(e)}")
        await websocket.send_json({"type": "error", "message": str(e)})

@app.websocket("/scan/monitor/{scan_id}")
async def monitor_scan(websocket: WebSocket, scan_id: str):
    """Türkçe: Devam eden bir taramanın loglarını MongoDB'den canlı izle"""
    await websocket.accept()
    
    try:
        # Türkçe: MongoDB'den logları oku (primary source)
        logs_collection = get_nmap_logs_collection()
        
        if logs_collection is not None:
            # Türkçe: MongoDB'den logları stream et
            last_timestamp = None
            scan_complete = False
            wait_iterations = 0
            max_wait_for_start = 20  # 10 saniye (0.5s x 20)
            
            while not scan_complete:
                await asyncio.sleep(0.5)
                wait_iterations += 1
                
                # Türkçe: Yeni logları al
                query = {"scan_id": scan_id}
                if last_timestamp:
                    query["timestamp"] = {"$gt": last_timestamp}
                
                logs = list(logs_collection.find(query).sort("timestamp", 1).limit(100))
                
                if logs:
                    wait_iterations = 0  # Reset wait counter
                    for log_doc in logs:
                        last_timestamp = log_doc.get("timestamp")
                        
                        # Türkçe: Frontend'e tutarlı format ile gönder
                        await websocket.send_json({
                            "type": "output",  # Frontend her çıktıyı "output" olarak bekliyor
                            "level": log_doc.get("level", "INFO"),
                            "data": log_doc.get("message", ""),
                            "timestamp": log_doc.get("timestamp").isoformat() if log_doc.get("timestamp") else ""
                        })
                        
                        # SCAN_END geldiyse tamamlandı
                        if log_doc.get("level") == "SCAN_END":
                            scan_complete = True
                            await websocket.send_json({"type": "complete", "message": "Tarama tamamlandı"})
                            break
                        
                        # ERROR varsa uyar ama devam et
                        if log_doc.get("level") == "ERROR":
                            await websocket.send_json({
                                "type": "error", 
                                "message": log_doc.get("message", "Bilinmeyen hata")
                            })
                else:
                    # Türkçe: Hiç log yoksa ve uzun süre beklediyse, tarama başlamamış olabilir
                    if wait_iterations > max_wait_for_start:
                        # Aktif tarama kontrolü
                        active_scans = get_active_scans_collection()
                        if active_scans is not None:
                            scan_doc = active_scans.find_one({"scan_id": scan_id})
                            if not scan_doc:
                                await websocket.send_json({
                                    "type": "error",
                                    "message": "Tarama bulunamadı veya henüz başlamamış."
                                })
                                break
                    
                    # Heartbeat gönder
                    if wait_iterations % 10 == 0:  # Her 5 saniyede bir
                        await websocket.send_json({
                            "type": "heartbeat",
                            "data": f"İzleniyor... (Bekliyor: {wait_iterations * 0.5:.0f}s)"
                        })
        else:
            # Türkçe: MongoDB yoksa eski file-based yaklaşım
            log_file = os.path.join(LOG_DIR, f"{scan_id}.log")
            await websocket.send_json({"type": "info", "data": "MongoDB bağlantısı yok, dosya izleniyor..."})
            
            # Log dosyası için bekle
            wait_count = 0
            while not os.path.exists(log_file) and wait_count < 20:
                await asyncio.sleep(0.5)
                wait_count += 1
            
            if not os.path.exists(log_file):
                await websocket.send_json({"type": "error", "message": "Log dosyası bulunamadı."})
                return
            
            # Dosyayı tail et
            last_position = 0
            while True:
                await asyncio.sleep(0.5)
                with open(log_file, "r") as f:
                    f.seek(last_position)
                    new_content = f.read()
                    if new_content:
                        for line in new_content.split('\n'):
                            if line.strip():
                                await websocket.send_json({"type": "output", "data": line})
                        last_position = f.tell()
                        
    except WebSocketDisconnect:
        logger.info(f"Monitor disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"Monitor error: {str(e)}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass

@app.get("/logs/{scan_id}")
async def download_log(scan_id: str):
    """Türkçe: Tarama logunu indir"""
    log_file = os.path.join(LOG_DIR, f"{scan_id}.log")
    
    if not os.path.exists(log_file):
        raise HTTPException(status_code=404, detail="Log file not found")
    
    return FileResponse(
        log_file,
        media_type="text/plain",
        filename=f"nmap_scan_{scan_id}.log"
    )

@app.on_event("startup")
async def startup_event():
    """Türkçe: Servis başlangıç kontrolleri, recovery ve indexleme"""
    logging.info("Nmap Service başlatılıyor...")
    
    # 1. MongoDB Recovery Mechanism
    collection = get_active_scans_collection()
    if collection is not None:
        logging.info("Önceki oturumdan kalan taramalar kontrol ediliyor (MongoDB)...")
        try:
            running_scans = list(collection.find({"status": "running"}))
            for scan_doc in running_scans:
                scan_id = scan_doc.get("scan_id")
                target = scan_doc.get("target")
                
                logging.warning(f"Kurtarılamayan işlem: {scan_id} (Target: {target})")
                add_nmap_log(scan_id, "ERROR", "Servis yeniden başlatıldığı için tarama yarıda kesildi.")
                collection.update_one({"scan_id": scan_id}, {"$set": {"status": "interrupted", "updated_at": datetime.utcnow()}})
            
            if running_scans:
                logging.info(f"Recovery tamamlandı, {len(running_scans)} tarama interrupted olarak işaretlendi.")
        except Exception as e:
            logging.error(f"MongoDB Recovery failed: {e}")
    
    # 2. Index ve TTL (7 gün)
    logs_collection = get_nmap_logs_collection()
    if logs_collection is not None:
        try:
            logs_collection.create_index("timestamp", expireAfterSeconds=7*24*60*60)
            logs_collection.create_index("scan_id")
            logging.info("NmapLogs indexleri oluşturuldu (TTL: 7 gün)")
        except Exception as e:
            logging.warning(f"Index creation warning: {e}")

@app.get("/config")
async def get_nmap_config():
    """Türkçe: UI için nmap konfigürasyonunu döner"""
    config_file = "/app/nmap_config.json"
    
    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    
    return {"error": "Config file not found"}

@app.post("/validate")
async def validate_scan_options(request: dict):
    """Türkçe: Scan parametrelerini validate eder (tarama başlatmadan önce)"""
    target = request.get("target", "")
    options = request.get("options", {})
    
    # Hedef IP/domain kontrolü
    if not target or not target.strip():
        return {
            "valid": False,
            "error": "Hedef IP veya domain adresi girilmeli."
        }
    
    # Options validasyonu
    is_valid, error_msg = validate_options(options)
    
    if not is_valid:
        return {
            "valid": False,
            "error": error_msg
        }
    
    return {
        "valid": True,
        "message": "Parametreler geçerli"
    }

@app.post("/preview")
async def preview_command(request: dict):
    """Türkçe: Nmap komutunu önizleme olarak döner (çalıştırmadan)"""
    target = request.get("target", "example.com")
    options = request.get("options", {})
    
    # Validation kontrolü
    is_valid, error_msg = validate_options(options)
    
    if not is_valid:
        return {
            "valid": False,
            "error": error_msg,
            "command": ""
        }
    
    # Komutu oluştur
    cmd = build_nmap_command(target, options)
    command_str = " ".join(cmd)
    
    return {
        "valid": True,
        "command": command_str,
        "target": target
    }

