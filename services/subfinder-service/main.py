"""
Subfinder Mikroservisi - Subdomain Keşif Motoru
ProjectDiscovery Subfinder entegrasyonu ile pasif subdomain keşfi
Türkçe: Bu servis Subfinder tarama motorunu yönetir ve real-time sonuç akışı sağlar
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, validator
import subprocess
import json
import os
import re
from datetime import datetime
from typing import List, Optional, Dict
import logging
import asyncio
import threading
import traceback

# Türkçe: MongoDB bağlantısı
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Türkçe: Gelişmiş loglama yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("subfinder-service")

app = FastAPI(title="Subfinder Service", version="1.0.0")

# ============== MongoDB Configuration ==============
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://kadim:kadim_secure_2024@mongodb:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")

# Türkçe: MongoDB bağlantısını başlat
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


def get_subfinder_logs_collection():
    """Türkçe: SubfinderLogs koleksiyonunu döner"""
    if db is None:
        return None
    return db["SubfinderLogs"]


def get_active_scans_collection():
    """Türkçe: SubfinderActiveScans koleksiyonunu döner"""
    if db is None:
        return None
    return db["SubfinderActiveScans"]


def add_log_sync(scan_id: str, level: str, message: str, data: Optional[Dict] = None):
    """
    Türkçe: MongoDB'ye senkron log kaydı ekler
    Levels: INFO, WARNING, ERROR, SUBDOMAIN, PROGRESS, SCAN_START, SCAN_END
    """
    collection = get_subfinder_logs_collection()
    if collection is None:
        logger.warning(f"MongoDB unavailable, log skipped: {message[:100]}")
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
        logger.error(f"Log insert error: {e}")
        return None


async def add_log(scan_id: str, level: str, message: str, data: Optional[Dict] = None):
    """Türkçe: MongoDB'ye asenkron log kaydı ekler (wrapper)"""
    return add_log_sync(scan_id, level, message, data)


class SubfinderScanRequest(BaseModel):
    """Türkçe: Subfinder tarama isteği modeli - Validation ile güvenlik sağlanır"""
    target: str
    scan_id: str
    sources: Optional[List[str]] = None  # Spesifik kaynaklar (crtsh, github vb.)
    all_sources: bool = False  # Tüm kaynakları kullan
    recursive: bool = False  # Recursive subdomain discovery
    timeout: int = 30  # Saniye
    rate_limit: int = 0  # 0 = sınırsız
    resolvers: Optional[List[str]] = None  # Özel DNS resolver'lar
    
    @validator('target')
    def validate_target(cls, v):
        """Türkçe: Hedef validasyonu - Domain formatı kontrolü"""
        # Domain pattern (subdomain desteği ile)
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        
        # URL'den domain çıkar
        if v.startswith('http://') or v.startswith('https://'):
            v = re.sub(r'^https?://', '', v)
            v = v.split('/')[0]  # Path'i kaldır
            v = v.split(':')[0]  # Port'u kaldır
        
        if not re.match(domain_pattern, v):
            raise ValueError('Geçersiz domain formatı')
        
        # Türkçe: Shell injection karakterlerini engelle
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>']
        if any(char in v for char in dangerous_chars):
            raise ValueError('Hedefte geçersiz karakterler')
        return v


# Türkçe: Aktif tarama process'lerini takip etmek için global dictionary
scan_processes: Dict[str, subprocess.Popen] = {}


def save_active_scan(scan_id: str, target: str, pid: int, command: List[str] = None):
    """Türkçe: Aktif taramayı MongoDB'ye kaydeder (Recovery için)"""
    collection = get_active_scans_collection()
    if collection is None:
        logger.warning(f"MongoDB unavailable, active scan not saved: {scan_id}")
        return
    
    try:
        doc = {
            "scan_id": scan_id,
            "target": target,
            "pid": pid,
            "status": "running",
            "started_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "command": command or [],
            "subdomains_found": 0
        }
        # Upsert: varsa güncelle, yoksa ekle
        collection.update_one(
            {"scan_id": scan_id},
            {"$set": doc},
            upsert=True
        )
        logger.info(f"Active scan saved to MongoDB: {scan_id}")
    except Exception as e:
        logger.error(f"Active scan save failed: {e}")


def remove_active_scan(scan_id: str, status: str = "completed", subdomains_count: int = 0):
    """Türkçe: Aktif taramayı MongoDB'de tamamlandı olarak işaretler"""
    collection = get_active_scans_collection()
    if collection is None:
        return
    
    try:
        collection.update_one(
            {"scan_id": scan_id},
            {"$set": {
                "status": status,
                "updated_at": datetime.utcnow(),
                "subdomains_found": subdomains_count
            }}
        )
        logger.info(f"Active scan marked as {status}: {scan_id}")
    except Exception as e:
        logger.error(f"Active scan remove failed: {e}")


@app.on_event("startup")
async def startup_event():
    """Türkçe: Servis başlangıç kontrolleri ve recovery"""
    logger.info("Subfinder Service başlatılıyor...")
    
    # 1. Subfinder Kontrolü
    try:
        result = subprocess.run(["subfinder", "-version"], capture_output=True, text=True, timeout=10)
        logger.info(f"Subfinder version: {result.stdout.strip() or result.stderr.strip()}")
    except Exception as e:
        logger.error(f"Subfinder not found: {e}")
    
    # 2. MongoDB Recovery Mechanism
    collection = get_active_scans_collection()
    if collection is not None:
        logger.info("Önceki oturumdan kalan taramalar kontrol ediliyor (MongoDB)...")
        try:
            # Running durumundaki taramaları bul
            running_scans = list(collection.find({"status": "running"}))
            
            for scan_doc in running_scans:
                scan_id = scan_doc.get("scan_id")
                target = scan_doc.get("target")
                
                logger.warning(f"Kurtarılamayan işlem tespit edildi: {scan_id} (Target: {target})")
                
                # MongoDB'ye error log ekle
                add_log_sync(
                    scan_id=scan_id,
                    level="SCAN_ERROR",
                    message="Servis yeniden başlatıldığı için tarama yarıda kesildi.",
                    data={"reason": "service_restart", "original_target": target}
                )
                
                # Taramayı interrupted olarak işaretle
                collection.update_one(
                    {"scan_id": scan_id},
                    {"$set": {"status": "interrupted", "updated_at": datetime.utcnow()}}
                )
            
            if running_scans:
                logger.info(f"Recovery tamamlandı, {len(running_scans)} tarama interrupted olarak işaretlendi.")
            else:
                logger.info("Kurtarılacak tarama bulunamadı.")
                
        except Exception as e:
            logger.error(f"MongoDB Recovery failed: {e}")
    
    # 3. SubfinderLogs için index oluştur (TTL YOK - kalıcı saklama)
    logs_collection = get_subfinder_logs_collection()
    if logs_collection is not None:
        try:
            logs_collection.create_index("scan_id")
            logs_collection.create_index("timestamp")
            logs_collection.create_index([("scan_id", 1), ("level", 1)])
            logger.info("SubfinderLogs indexleri oluşturuldu (TTL yok - kalıcı saklama)")
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")


def build_subfinder_command(request: SubfinderScanRequest) -> List[str]:
    """
    Türkçe: Subfinder komutunu oluşturur
    -json: JSON formatında çıktı
    -silent: Sadece sonuçları göster
    """
    cmd = [
        "subfinder",
        "-d", request.target,
        "-json",  # JSON output for parsing
        "-silent",  # Sadece subdomain'ler
        "-timeout", str(request.timeout),
    ]
    
    # Rate limit
    if request.rate_limit > 0:
        cmd.extend(["-rate-limit", str(request.rate_limit)])
    
    # All sources
    if request.all_sources:
        cmd.append("-all")
    
    # Recursive
    if request.recursive:
        cmd.append("-recursive")
    
    # Specific sources
    if request.sources:
        valid_sources = [s for s in request.sources if re.match(r'^[a-zA-Z0-9_-]+$', s)]
        if valid_sources:
            cmd.extend(["-sources", ",".join(valid_sources)])
    
    # Custom resolvers
    if request.resolvers:
        valid_resolvers = [r for r in request.resolvers if re.match(r'^[\d\.]+$', r) or re.match(r'^[a-zA-Z0-9\.-]+$', r)]
        if valid_resolvers:
            cmd.extend(["-r", ",".join(valid_resolvers)])
    
    return cmd


@app.get("/health")
async def health_check():
    """Türkçe: Servis sağlık kontrolü"""
    try:
        result = subprocess.run(
            ["subfinder", "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        version = result.stdout.strip() or result.stderr.strip()
        return {
            "status": "healthy",
            "service": "subfinder-service",
            "subfinder_version": version,
            "mongodb_connected": db is not None
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")


@app.get("/config")
async def get_subfinder_config():
    """Türkçe: Subfinder yapılandırma bilgilerini döner - Frontend için"""
    try:
        # Türkçe: Mevcut kaynakları listele
        result = subprocess.run(
            ["subfinder", "-ls"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        sources = []
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip() and not line.startswith('['):
                    sources.append(line.strip())
        
        return {
            "available_sources": sources,
            "source_count": len(sources),
            "default_timeout": 30,
            "features": [
                {"id": "recursive", "name": "Recursive Keşif", "description": "Alt subdomain'leri de tara"},
                {"id": "all_sources", "name": "Tüm Kaynaklar", "description": "Tüm pasif kaynakları kullan (yavaş)"},
            ]
        }
    except Exception as e:
        logger.error(f"Config error: {e}")
        return {
            "available_sources": ["crtsh", "hackertarget", "threatcrowd", "dnsdumpster", "sublist3r"],
            "source_count": 5,
            "default_timeout": 30,
            "features": []
        }


@app.post("/scan")
async def start_subfinder_scan(request: SubfinderScanRequest):
    """
    Türkçe: Subfinder taramasını başlatır
    Tarama arka planda çalışır ve MongoDB'ye log yazar
    """
    try:
        logger.info(f"{'='*50}")
        logger.info(f"[SCAN START] scan_id={request.scan_id}, target={request.target}")
        logger.info(f"Options: recursive={request.recursive}, all_sources={request.all_sources}, timeout={request.timeout}")

        cmd = build_subfinder_command(request)
        logger.info(f"[COMMAND] {' '.join(cmd)}")
        
        # Türkçe: MongoDB'ye SCAN_START logları yaz
        add_log_sync(request.scan_id, "SCAN_START", f"Tarama başlatıldı: {request.target}", {
            "target": request.target,
            "command": ' '.join(cmd),
            "sources": request.sources or ["all" if request.all_sources else "default"],
            "recursive": request.recursive,
            "timeout": request.timeout
        })
        
        # Türkçe: Arka planda çalıştır - PIPE ile çıktıyı yakala
        logger.info(f"[{request.scan_id}] Subprocess başlatılıyor...")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # Line buffered
        )

        # Türkçe: Process'i kaydet
        scan_processes[request.scan_id] = process

        logger.info(f"[{request.scan_id}] Subprocess başlatıldı - PID: {process.pid}")
        logger.info(f"[{request.scan_id}] Aktif tarama sayısı: {len(scan_processes)}")
        
        # Recovery için MongoDB'ye kaydet
        save_active_scan(request.scan_id, request.target, process.pid, cmd)
        
        # Türkçe: Background thread ile çıktıyı MongoDB'ye aktar
        def stream_output_to_mongodb(proc, scan_id):
            subdomains = []
            logger.info(f"[{scan_id}] Stream thread başlatıldı, PID: {proc.pid}")

            try:
                # Türkçe: Process çalıştığı sürece stdout'u oku
                while True:
                    # Process durumunu kontrol et
                    poll_result = proc.poll()

                    # stdout'tan satır oku
                    line = proc.stdout.readline()

                    if line:
                        raw_line = line.strip()
                        if raw_line:
                            logger.debug(f"[{scan_id}] Raw output: {raw_line[:100]}")

                            # Türkçe: JSON çıktıyı parse et
                            if raw_line.startswith('{'):
                                try:
                                    data = json.loads(raw_line)
                                    subdomain = data.get("host", "")
                                    source = data.get("source", "unknown")

                                    if subdomain:
                                        subdomains.append(subdomain)
                                        add_log_sync(scan_id, "SUBDOMAIN", subdomain, {
                                            "subdomain": subdomain,
                                            "source": source,
                                            "raw": data,
                                            "index": len(subdomains)
                                        })
                                        logger.info(f"[{scan_id}] Subdomain bulundu ({len(subdomains)}): {subdomain} [{source}]")
                                except json.JSONDecodeError as je:
                                    # JSON parse hatası - plain text olarak dene
                                    logger.warning(f"[{scan_id}] JSON parse error: {je}, line: {raw_line[:50]}")
                                    if '.' in raw_line:
                                        subdomains.append(raw_line)
                                        add_log_sync(scan_id, "SUBDOMAIN", raw_line, {
                                            "subdomain": raw_line,
                                            "source": "unknown",
                                            "index": len(subdomains)
                                        })
                            else:
                                # Plain text subdomain veya info mesajı
                                if raw_line and '.' in raw_line and not raw_line.startswith('['):
                                    subdomains.append(raw_line)
                                    add_log_sync(scan_id, "SUBDOMAIN", raw_line, {
                                        "subdomain": raw_line,
                                        "source": "unknown",
                                        "index": len(subdomains)
                                    })
                                    logger.info(f"[{scan_id}] Subdomain (plain): {raw_line}")
                                elif raw_line.startswith('['):
                                    # Info/progress message
                                    add_log_sync(scan_id, "INFO", raw_line)
                                    logger.info(f"[{scan_id}] Info: {raw_line}")

                    # Türkçe: Process bitti ve okunacak veri kalmadı
                    if poll_result is not None and not line:
                        logger.info(f"[{scan_id}] Process bitti, exit code: {poll_result}")
                        break

                # Process tamamlandı
                exit_code = proc.returncode if proc.returncode is not None else proc.wait()
                final_status = "completed" if exit_code == 0 else "failed"

                logger.info(f"[{scan_id}] Tarama tamamlandı - Status: {final_status}, Subdomain sayısı: {len(subdomains)}")

                add_log_sync(scan_id, "SCAN_END", f"Tarama tamamlandı. {len(subdomains)} subdomain bulundu.", {
                    "exit_code": exit_code,
                    "total_subdomains": len(subdomains),
                    "subdomains": subdomains,
                    "final_status": final_status
                })
                remove_active_scan(scan_id, final_status, len(subdomains))

                # Türkçe: Memory'den process referansını temizle
                if scan_id in scan_processes:
                    del scan_processes[scan_id]
                    logger.info(f"[{scan_id}] Process memory'den temizlendi")

            except Exception as e:
                error_trace = traceback.format_exc()
                logger.error(f"[{scan_id}] Stream error: {e}\n{error_trace}")
                add_log_sync(scan_id, "ERROR", f"Stream error: {str(e)}", {"traceback": error_trace})
                remove_active_scan(scan_id, "failed", len(subdomains))

                # Türkçe: Hata durumunda da memory'den temizle
                if scan_id in scan_processes:
                    del scan_processes[scan_id]

        threading.Thread(target=stream_output_to_mongodb, args=(process, request.scan_id), daemon=True).start()
        
        return {
            "scan_id": request.scan_id,
            "status": "started",
            "message": "Tarama arka planda başlatıldı (MongoDB logging)",
            "pid": process.pid
        }

    except Exception as e:
        logger.error(f"Scan start error: {str(e)}")
        add_log_sync(request.scan_id, "ERROR", f"Tarama başlatılamadı: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status/{scan_id}")
async def check_scan_status(scan_id: str):
    """Türkçe: Tarama durumunu kontrol eder (MongoDB)"""
    
    # 1. Memory'deki process'i kontrol et
    process = scan_processes.get(scan_id)
    
    if process:
        poll = process.poll()
        if poll is None:
            # Türkçe: Şu ana kadar bulunan subdomain sayısını al
            logs_collection = get_subfinder_logs_collection()
            found_count = 0
            if logs_collection is not None:
                found_count = logs_collection.count_documents({"scan_id": scan_id, "level": "SUBDOMAIN"})
            return {"status": "running", "pid": process.pid, "subdomains_found": found_count}
        else:
            # Türkçe: Tamamlandı, memory'den temizle
            del scan_processes[scan_id]
            return {"status": "completed", "exit_code": poll}
    
    # 2. MongoDB'den kontrol et
    collection = get_active_scans_collection()
    if collection is not None:
        try:
            scan_doc = collection.find_one({"scan_id": scan_id})
            if scan_doc:
                status = scan_doc.get("status", "unknown")
                return {
                    "status": status,
                    "target": scan_doc.get("target"),
                    "started_at": scan_doc.get("started_at").isoformat() if scan_doc.get("started_at") else None,
                    "subdomains_found": scan_doc.get("subdomains_found", 0)
                }
        except Exception as e:
            logger.error(f"MongoDB status check error: {e}")
    
    # 3. Logs collection'da var mı kontrol et
    logs_collection = get_subfinder_logs_collection()
    if logs_collection is not None:
        try:
            scan_end = logs_collection.find_one({"scan_id": scan_id, "level": "SCAN_END"})
            if scan_end:
                return {
                    "status": "completed",
                    "subdomains_found": scan_end.get("data", {}).get("total_subdomains", 0)
                }
            
            scan_start = logs_collection.find_one({"scan_id": scan_id, "level": "SCAN_START"})
            if scan_start:
                return {"status": "unknown", "message": "Scan started but no end record found"}
        except Exception as e:
            logger.error(f"MongoDB logs check error: {e}")
        
    return {"status": "not_found"}


@app.get("/logs/{scan_id}")
async def get_scan_log(scan_id: str):
    """Türkçe: MongoDB'den tarama loglarını döner"""
    
    collection = get_subfinder_logs_collection()
    if collection is None:
        raise HTTPException(status_code=503, detail="MongoDB bağlantısı yok")
    
    try:
        # Türkçe: scan_id'ye ait tüm logları çek
        logs_cursor = collection.find(
            {"scan_id": scan_id}
        ).sort("timestamp", 1)
        
        raw_logs = list(logs_cursor)
        
        if not raw_logs:
            raise HTTPException(status_code=404, detail="Log bulunamadı")
        
        # Türkçe: Subdomain listesini oluştur
        subdomains = []
        source_counts = {}
        serialized_logs = []
        
        for log in raw_logs:
            level = log.get("level", "LOG")
            message = log.get("message", "")
            data = log.get("data", {})
            timestamp = log.get("timestamp")
            ts_str = timestamp.isoformat() if timestamp else ""
            
            # SUBDOMAIN ise listeye ekle
            if level == "SUBDOMAIN":
                subdomain = data.get("subdomain", message)
                source = data.get("source", "unknown")
                
                if subdomain and subdomain not in subdomains:
                    subdomains.append(subdomain)
                    source_counts[source] = source_counts.get(source, 0) + 1
            
            # Türkçe: Serialize edilebilir log objesi oluştur
            serialized_logs.append({
                "id": str(log.get("_id", "")),
                "scan_id": log.get("scan_id", ""),
                "level": level,
                "message": message,
                "timestamp": ts_str,
                "data": data
            })
        
        # Türkçe: Log content oluştur
        log_content = "\n".join(subdomains)
        
        return {
            "scan_id": scan_id,
            "log_content": log_content,
            "subdomains": subdomains,
            "subdomains_count": len(subdomains),
            "source_counts": source_counts,
            "logs": serialized_logs,
            "total_logs": len(serialized_logs)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MongoDB log read error: {e}")
        raise HTTPException(status_code=500, detail=f"Log okunamadı: {str(e)}")


@app.get("/active-scans")
async def get_active_scans():
    """Türkçe: Aktif taramaların listesini döner (MongoDB + Memory)"""
    active = []
    
    # 1. Memory'deki process'leri kontrol et
    for scan_id, process in list(scan_processes.items()):
        if process.poll() is None:
            # MongoDB'den hedef bilgisini al
            collection = get_active_scans_collection()
            target = "unknown"
            if collection is not None:
                try:
                    doc = collection.find_one({"scan_id": scan_id})
                    if doc:
                        target = doc.get("target", "unknown")
                except:
                    pass
            
            active.append({
                "scan_id": scan_id,
                "target": target,
                "pid": process.pid,
                "status": "running"
            })
        else:
            # Türkçe: Biten process'leri temizle
            del scan_processes[scan_id]
    
    return {"active_scans": active, "count": len(active)}


@app.delete("/scan/{scan_id}")
async def stop_scan(scan_id: str):
    """Türkçe: Çalışan taramayı durdurur"""
    process = scan_processes.get(scan_id)
    
    if process and process.poll() is None:
        process.terminate()
        
        # Türkçe: Nazik kapatma için bekle
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        
        # MongoDB'ye kaydet
        add_log_sync(scan_id, "SCAN_STOPPED", "Kullanıcı tarafından durduruldu")
        
        del scan_processes[scan_id]
        remove_active_scan(scan_id, "stopped")
        logger.info(f"Scan durduruldu: {scan_id}")
        
        return {"status": "stopped", "scan_id": scan_id}
    
    raise HTTPException(status_code=404, detail="Aktif tarama bulunamadı")


@app.websocket("/ws/monitor/{scan_id}")
async def websocket_monitor(websocket: WebSocket, scan_id: str):
    """
    Türkçe: WebSocket ile tarama izleme
    MongoDB SubfinderLogs koleksiyonundan real-time polling ile frontend'e gönderir
    """
    await websocket.accept()
    logger.info(f"WebSocket bağlantısı kabul edildi: {scan_id}")
    
    try:
        collection = get_subfinder_logs_collection()
        if collection is None:
            await websocket.send_json({
                "type": "error",
                "message": "MongoDB bağlantısı yok"
            })
            return
        
        # Türkçe: İlk log kaydının gelmesini bekle (max 10 saniye)
        wait_count = 0
        while True:
            first_log = collection.find_one({"scan_id": scan_id})
            if first_log:
                break
            if wait_count > 100:  # 10 saniye
                await websocket.send_json({
                    "type": "error",
                    "message": "Tarama logu bulunamadı - tarama başlatılmamış olabilir"
                })
                return
            await asyncio.sleep(0.1)
            wait_count += 1
        
        # Türkçe: Bağlantı başarılı mesajı
        await websocket.send_json({
            "type": "status",
            "message": "Bağlantı kuruldu, tarama izleniyor..."
        })
        
        # Türkçe: MongoDB polling - son işlenen log _id'sini tut
        last_id = None
        no_data_count = 0
        subdomains_sent = 0
        
        while True:
            try:
                # Yeni logları çek
                query = {"scan_id": scan_id}
                if last_id:
                    query["_id"] = {"$gt": last_id}
                
                new_logs = list(collection.find(query).sort("_id", 1).limit(50))
                
                if new_logs:
                    no_data_count = 0
                    
                    for log in new_logs:
                        last_id = log.get("_id")
                        level = log.get("level", "LOG")
                        message = log.get("message", "")
                        data = log.get("data", {})
                        timestamp = log.get("timestamp")
                        
                        if level == "SUBDOMAIN":
                            subdomains_sent += 1
                            await websocket.send_json({
                                "type": "subdomain",
                                "subdomain": data.get("subdomain", message),
                                "source": data.get("source", "unknown"),
                                "index": subdomains_sent,
                                "timestamp": timestamp.isoformat() if timestamp else ""
                            })
                            
                        elif level == "SCAN_END":
                            await websocket.send_json({
                                "type": "completed",
                                "message": message,
                                "total_subdomains": data.get("total_subdomains", subdomains_sent),
                                "exit_code": data.get("exit_code", 0)
                            })
                            return
                            
                        elif level == "SCAN_STOPPED":
                            await websocket.send_json({
                                "type": "stopped",
                                "message": message
                            })
                            return
                            
                        elif level == "ERROR":
                            await websocket.send_json({
                                "type": "error",
                                "message": message
                            })
                            
                        elif level == "SCAN_START":
                            await websocket.send_json({
                                "type": "info",
                                "message": f"[SCAN_START] {message}",
                                "data": data
                            })
                            
                        else:
                            await websocket.send_json({
                                "type": "log" if level == "LOG" else "info",
                                "message": message
                            })
                else:
                    no_data_count += 1
                    
                    # Türkçe: Process durumunu kontrol et
                    process = scan_processes.get(scan_id)
                    if process and process.poll() is not None:
                        # Process bitti
                        scan_end = collection.find_one({"scan_id": scan_id, "level": "SCAN_END"})
                        if scan_end:
                            await websocket.send_json({
                                "type": "completed",
                                "message": "Tarama tamamlandı",
                                "total_subdomains": scan_end.get("data", {}).get("total_subdomains", subdomains_sent)
                            })
                        else:
                            await websocket.send_json({
                                "type": "completed",
                                "message": "Tarama tamamlandı",
                                "total_subdomains": subdomains_sent
                            })
                        return
                    
                    # Türkçe: Çok uzun süre veri gelmezse timeout
                    if no_data_count > 600:  # 60 saniye
                        active_collection = get_active_scans_collection()
                        if active_collection is not None:
                            scan_doc = active_collection.find_one({"scan_id": scan_id})
                            if scan_doc and scan_doc.get("status") != "running":
                                await websocket.send_json({
                                    "type": "completed",
                                    "message": f"Tarama {scan_doc.get('status')}",
                                    "total_subdomains": subdomains_sent
                                })
                                return
                
                await asyncio.sleep(0.2)  # 200ms polling interval
                
            except Exception as read_error:
                import traceback
                logger.error(f"MongoDB polling hatası: {read_error}\n{traceback.format_exc()}")
                await asyncio.sleep(0.5)
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket bağlantısı kesildi: {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket hatası: {str(e)}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": str(e)
            })
        except:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8010)
