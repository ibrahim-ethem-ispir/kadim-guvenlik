"""
RustScan Mikroservisi - Ultra Hızlı Port Tarayıcı
Türkçe: RustScan + Nmap entegrasyonu ile hızlı ve detaylı port taraması
Version 2.0 - MongoDB logging, async support, real-time progress
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, validator
import subprocess
import json
import os
import re
import shutil
from datetime import datetime
from typing import List, Optional, Dict
import logging
import asyncio

# MongoDB
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("rustscan-service")

app = FastAPI(title="RustScan Service", version="2.0.0")

# MongoDB Config
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://kadim:kadim_secure_2024@mongodb:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")

mongo_client = None
db = None

try:
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    mongo_client.admin.command('ping')
    db = mongo_client[MONGODB_DATABASE]
    logger.info("✅ MongoDB bağlantısı başarılı")
except ConnectionFailure as e:
    logger.error(f"⚠️ MongoDB bağlantı hatası: {e}")
    db = None


def get_logs_collection():
    """Türkçe: RustScanLogs koleksiyonunu döner"""
    if db is None:
        return None
    return db["RustScanLogs"]


def get_active_scans_collection():
    """Türkçe: RustScanActiveScans koleksiyonunu döner"""
    if db is None:
        return None
    return db["RustScanActiveScans"]


def add_log_sync(scan_id: str, level: str, message: str, data: Optional[Dict] = None):
    """Türkçe: Log kaydı ekle"""
    collection = get_logs_collection()
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
        return collection.insert_one(doc).inserted_id
    except Exception as e:
        logger.error(f"Log insert error: {e}")
        return None


class RustScanRequest(BaseModel):
    """Türkçe: RustScan tarama isteği modeli"""
    target: str
    scan_id: str
    options: dict = {}
    
    @validator('target')
    def validate_target(cls, v):
        # IP veya domain validasyonu
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        
        # URL'den host çıkar
        if v.startswith('http://') or v.startswith('https://'):
            v = re.sub(r'^https?://', '', v)
            v = v.split('/')[0]
            v = v.split(':')[0]
        
        if not (re.match(ip_pattern, v) or re.match(domain_pattern, v)):
            raise ValueError('Geçersiz IP veya domain formatı')
        
        dangerous = [';', '&', '|', '`', '$', '(', ')', '<', '>']
        if any(c in v for c in dangerous):
            raise ValueError('Hedefte geçersiz karakterler')
        return v


# Aktif taramalar
scan_processes: Dict[str, asyncio.subprocess.Process] = {}


@app.on_event("startup")
async def startup_event():
    """Türkçe: Servis başlangıç işlemleri"""
    logger.info("RustScan Service başlatılıyor...")
    
    # RustScan kontrolü
    if shutil.which("rustscan"):
        try:
            result = subprocess.run(["rustscan", "--version"], capture_output=True, text=True, timeout=5)
            logger.info(f"RustScan version: {result.stdout.strip() or result.stderr.strip()}")
        except Exception as e:
            logger.warning(f"RustScan version check failed: {e}")
    else:
        logger.error("⚠️ RustScan yüklü değil!")
    
    # Nmap kontrolü
    if shutil.which("nmap"):
        logger.info("✅ Nmap mevcut")
    else:
        logger.warning("⚠️ Nmap yüklü değil - service detection çalışmayacak")
    
    # MongoDB indexleri
    logs_col = get_logs_collection()
    if logs_col is not None:
        try:
            logs_col.create_index("scan_id")
            logs_col.create_index("timestamp")
            logger.info("MongoDB indexleri oluşturuldu")
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")


@app.get("/health")
async def health_check():
    """Türkçe: Servis sağlık kontrolü"""
    rustscan_ok = shutil.which("rustscan") is not None
    nmap_ok = shutil.which("nmap") is not None
    
    return {
        "status": "healthy" if rustscan_ok else "degraded",
        "rustscan": "installed" if rustscan_ok else "not found",
        "nmap": "installed" if nmap_ok else "not found",
        "mongodb": "connected" if db is not None else "disconnected"
    }


@app.get("/config")
async def get_config():
    """Türkçe: RustScan yapılandırma bilgileri - Frontend için"""
    return {
        "default_batch_size": 5000,
        "default_timeout": 2000,
        "default_ulimit": 5000,
        "nmap_integration": True,
        "recommended_nmap_args": [
            {"arg": "-sV", "description": "Servis/versiyon tespiti", "tooltip": "Açık portlardaki servislerin versiyonlarını belirler"},
            {"arg": "-sC", "description": "Default script taraması", "tooltip": "Nmap NSE scriptlerini çalıştırır"},
            {"arg": "-O", "description": "OS tespiti (root gerekli)", "tooltip": "İşletim sistemi parmak izi analizi"},
            {"arg": "-A", "description": "Agresif tarama (tüm özellikler)", "tooltip": "OS detection, version detection, script scanning ve traceroute"},
            {"arg": "--script=vuln", "description": "Zafiyet script'leri", "tooltip": "Bilinen güvenlik açıklarını tarar"}
        ],
        "tooltips": {
            "batch_size": "Aynı anda açılacak bağlantı sayısı. Yüksek değer = Hızlı tarama, düşük değer = Daha güvenli/stabil",
            "timeout": "Port başına maksimum bekleme süresi (milisaniye). Düşük değer = Hızlı ama bazı portlar kaçabilir",
            "ulimit": "Dosya tanımlayıcı limiti. Batch size ile orantılı olmalı (genellikle batch_size ile aynı)",
            "nmap_args": "RustScan açık portları bulduktan sonra Nmap ile detaylı analiz yapar"
        },
        "presets": {
            "fast": {"batch_size": 5000, "timeout": 1500, "nmap_args": "-sV", "description": "Hızlı tarama - temel bilgiler"},
            "balanced": {"batch_size": 3000, "timeout": 2000, "nmap_args": "-sV -sC", "description": "Dengeli - hız ve detay"},
            "thorough": {"batch_size": 1500, "timeout": 3000, "nmap_args": "-sV -sC -O", "description": "Detaylı - tüm bilgiler"}
        }
    }


@app.post("/scan")
async def start_scan(request: RustScanRequest):
    """Türkçe: Asenkron RustScan taraması başlat"""
    
    if not shutil.which("rustscan"):
        raise HTTPException(status_code=500, detail="RustScan yüklü değil")
    
    scan_id = request.scan_id
    target = request.target
    options = request.options
    
    logger.info(f"RustScan başlatılıyor: {scan_id} -> {target}")
    
    # Komutu oluştur
    cmd = ["rustscan", "-a", target]
    cmd.extend(["--ulimit", str(options.get("ulimit", 5000))])
    
    if options.get("batch_size"):
        cmd.extend(["-b", str(options["batch_size"])])
    
    if options.get("timeout"):
        cmd.extend(["-t", str(options["timeout"])])
    
    # Nmap args
    cmd.append("--")
    nmap_args = options.get("nmap_args", "-sV")
    if nmap_args:
        cmd.extend(nmap_args.split())
    
    # MongoDB'ye kaydet
    active_col = get_active_scans_collection()
    if active_col is not None:
        active_col.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "scan_id": scan_id,
                "target": target,
                "status": "running",
                "command": " ".join(cmd),
                "started_at": datetime.utcnow()
            }},
            upsert=True
        )
    
    add_log_sync(scan_id, "SCAN_START", f"Tarama başlatıldı: {target}", {
        "command": " ".join(cmd),
        "options": options
    })
    
    # Asenkron olarak çalıştır
    asyncio.create_task(run_scan_async(scan_id, target, cmd))
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "RustScan taraması arka planda başlatıldı",
        "command": " ".join(cmd)
    }


async def run_scan_async(scan_id: str, target: str, cmd: List[str]):
    """Türkçe: Taramayı asenkron çalıştır ve sonuçları kaydet"""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        scan_processes[scan_id] = process
        
        output_lines = []
        open_ports = []
        services = []
        
        async for line in process.stdout:
            decoded = line.decode().strip()
            if not decoded:
                continue
            
            output_lines.append(decoded)
            
            # RustScan port parse (örn: "Open 192.168.1.1:80")
            if "Open" in decoded:
                match = re.search(r':(\d+)', decoded)
                if match:
                    port = int(match.group(1))
                    if port not in open_ports:
                        open_ports.append(port)
                        add_log_sync(scan_id, "PORT_FOUND", f"Açık port: {port}", {"port": port})
            
            # Nmap service parse (örn: "80/tcp open http Apache httpd 2.4.41")
            if "/tcp" in decoded or "/udp" in decoded:
                add_log_sync(scan_id, "NMAP_OUTPUT", decoded)
                
                # Service bilgisi çıkar
                service_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.*)', decoded)
                if service_match:
                    port_num = int(service_match.group(1))
                    protocol = service_match.group(2)
                    state = service_match.group(3)
                    service_info = service_match.group(4).strip() if service_match.group(4) else ""
                    
                    services.append({
                        "port": port_num,
                        "protocol": protocol,
                        "state": state,
                        "service": service_info
                    })
        
        await process.wait()
        exit_code = process.returncode
        
        # Sonuçları kaydet
        results = {
            "status": "completed" if exit_code == 0 else "failed",
            "exit_code": exit_code,
            "open_ports": sorted(open_ports),
            "open_ports_count": len(open_ports),
            "services": services,
            "raw_output": "\n".join(output_lines[-500:]),
            "completed_at": datetime.utcnow().isoformat()
        }
        
        add_log_sync(scan_id, "SCAN_END", f"Tarama tamamlandı. {len(open_ports)} açık port bulundu.", results)
        
        # Active scan güncelle
        active_col = get_active_scans_collection()
        if active_col is not None:
            active_col.update_one(
                {"scan_id": scan_id},
                {"$set": results}
            )
        
        logger.info(f"✅ RustScan tamamlandı: {scan_id} - {len(open_ports)} port")
        
    except Exception as e:
        logger.error(f"RustScan hata: {e}")
        add_log_sync(scan_id, "ERROR", str(e))
        
        active_col = get_active_scans_collection()
        if active_col is not None:
            active_col.update_one(
                {"scan_id": scan_id},
                {"$set": {"status": "failed", "error": str(e)}}
            )
    finally:
        if scan_id in scan_processes:
            del scan_processes[scan_id]


@app.get("/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Türkçe: Tarama durumunu kontrol et"""
    # Memory kontrolü
    if scan_id in scan_processes:
        process = scan_processes[scan_id]
        if process.returncode is None:
            logs_col = get_logs_collection()
            ports_found = 0
            if logs_col:
                ports_found = logs_col.count_documents({"scan_id": scan_id, "level": "PORT_FOUND"})
            return {"status": "running", "ports_found": ports_found}
    
    # MongoDB kontrolü
    active_col = get_active_scans_collection()
    if active_col is not None:
        doc = active_col.find_one({"scan_id": scan_id})
        if doc:
            return {
                "status": doc.get("status", "unknown"),
                "open_ports": doc.get("open_ports", []),
                "open_ports_count": doc.get("open_ports_count", 0),
                "services": doc.get("services", [])
            }
    
    return {"status": "not_found"}


@app.get("/logs/{scan_id}")
async def get_scan_logs(scan_id: str):
    """Türkçe: Tarama loglarını döner"""
    logs_col = get_logs_collection()
    active_col = get_active_scans_collection()
    
    if logs_col is None:
        raise HTTPException(status_code=503, detail="MongoDB bağlantısı yok")
    
    logs = list(logs_col.find({"scan_id": scan_id}).sort("timestamp", 1))
    
    # Serialize
    for log in logs:
        log["_id"] = str(log["_id"])
        if log.get("timestamp"):
            log["timestamp"] = log["timestamp"].isoformat()
    
    # Sonuç bilgilerini de ekle
    result_data = {}
    if active_col is not None:
        doc = active_col.find_one({"scan_id": scan_id})
        if doc:
            result_data = {
                "open_ports": doc.get("open_ports", []),
                "open_ports_count": doc.get("open_ports_count", 0),
                "services": doc.get("services", []),
                "status": doc.get("status", "unknown"),
                "raw_output": doc.get("raw_output", "")
            }
    
    return {
        "scan_id": scan_id,
        "logs": logs,
        "result": result_data,
        "log_count": len(logs)
    }


@app.delete("/scan/{scan_id}")
async def stop_scan(scan_id: str):
    """Türkçe: Çalışan taramayı durdur"""
    if scan_id not in scan_processes:
        raise HTTPException(status_code=404, detail="Aktif tarama bulunamadı")
    
    process = scan_processes[scan_id]
    process.terminate()
    
    try:
        await asyncio.wait_for(process.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        process.kill()
    
    add_log_sync(scan_id, "SCAN_STOPPED", "Kullanıcı tarafından durduruldu")
    
    active_col = get_active_scans_collection()
    if active_col is not None:
        active_col.update_one(
            {"scan_id": scan_id},
            {"$set": {"status": "stopped", "stopped_at": datetime.utcnow()}}
        )
    
    del scan_processes[scan_id]
    logger.info(f"Tarama durduruldu: {scan_id}")
    
    return {"status": "stopped", "scan_id": scan_id}


@app.get("/active-scans")
async def get_active_scans():
    """Türkçe: Aktif taramaları listele"""
    active = []
    
    for scan_id in list(scan_processes.keys()):
        process = scan_processes.get(scan_id)
        if process and process.returncode is None:
            active_col = get_active_scans_collection()
            target = "unknown"
            if active_col:
                doc = active_col.find_one({"scan_id": scan_id})
                if doc:
                    target = doc.get("target", "unknown")
            active.append({"scan_id": scan_id, "target": target, "status": "running"})
        elif scan_id in scan_processes:
            # Biten process'i temizle
            del scan_processes[scan_id]
    
    return {"active_scans": active, "count": len(active)}


@app.websocket("/ws/monitor/{scan_id}")
async def websocket_monitor(websocket: WebSocket, scan_id: str):
    """Türkçe: Real-time tarama izleme"""
    await websocket.accept()
    logger.info(f"WebSocket bağlantısı: {scan_id}")
    
    try:
        logs_col = get_logs_collection()
        if logs_col is None:
            await websocket.send_json({"type": "error", "message": "MongoDB bağlantısı yok"})
            return
        
        last_id = None
        no_data_count = 0
        
        while True:
            # Yeni logları çek
            query = {"scan_id": scan_id}
            if last_id:
                query["_id"] = {"$gt": last_id}
            
            new_logs = list(logs_col.find(query).sort("_id", 1).limit(20))
            
            if new_logs:
                no_data_count = 0
                for log in new_logs:
                    last_id = log["_id"]
                    level = log.get("level", "LOG")
                    
                    if level == "PORT_FOUND":
                        await websocket.send_json({
                            "type": "port",
                            "port": log.get("data", {}).get("port"),
                            "message": log.get("message")
                        })
                    elif level == "SCAN_END":
                        await websocket.send_json({
                            "type": "completed",
                            "message": log.get("message"),
                            "data": log.get("data", {})
                        })
                        return
                    elif level == "SCAN_STOPPED":
                        await websocket.send_json({
                            "type": "stopped",
                            "message": log.get("message")
                        })
                        return
                    elif level == "ERROR":
                        await websocket.send_json({
                            "type": "error",
                            "message": log.get("message")
                        })
                    elif level == "NMAP_OUTPUT":
                        await websocket.send_json({
                            "type": "nmap",
                            "message": log.get("message")
                        })
                    else:
                        await websocket.send_json({
                            "type": "log",
                            "level": level,
                            "message": log.get("message")
                        })
            else:
                no_data_count += 1
                
                # Process durumunu kontrol et
                if scan_id in scan_processes:
                    process = scan_processes[scan_id]
                    if process.returncode is not None:
                        # Process bitti
                        await websocket.send_json({
                            "type": "completed",
                            "message": "Tarama tamamlandı"
                        })
                        return
                
                # Uzun süre veri gelmezse
                if no_data_count > 300:  # ~60 saniye
                    await websocket.send_json({
                        "type": "timeout",
                        "message": "Veri akışı durdu"
                    })
                    return
            
            await asyncio.sleep(0.2)
            
    except WebSocketDisconnect:
        logger.info(f"WebSocket bağlantısı kesildi: {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket hatası: {e}")
