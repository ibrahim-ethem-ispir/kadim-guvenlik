import httpx
import asyncio
import logging
import os
from datetime import datetime

logger = logging.getLogger("orchestrator")

SUBFINDER_SERVICE_URL = os.getenv("SUBFINDER_SERVICE_URL", "http://subfinder-service:8010")

async def update_scan_result_callback(scan_id: str, service: str, result: dict):
    """
    Main.py'dan import edilecek update fonksiyonu referansı
    Not: Circular import'u önlemek için bu callback sonradan set edilebilir 
    veya bu logic db_utils gibi bir yere taşınabilir.
    Şimdilik main.py'daki logic ile uyumlu olması için parametre olarak geçilebilir
    veya db instance'ı kullanılabilir.
    Basitlik adına main.py logic'ini duplicate edeceğiz ama db helper kullanmak daha doğru.
    Ancak main.py yapısı monolithic olduğu için burada db erişimini yeniden tanımlayacağız.
    """
    from pymongo import MongoClient
    MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://mongodb:27017")
    MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")
    
    try:
        client = MongoClient(MONGODB_URI)
        db = client[MONGODB_DATABASE]
        scans_col = db["scans"]
        
        # Nested update
        update_fields = {}
        for k, v in result.items():
            update_fields[f"results.{service}.{k}"] = v
            
        scans_col.update_one(
            {"scan_id": scan_id},
            {"$set": update_fields}
        )
        client.close()
    except Exception as e:
        logger.error(f"DB Update Error for {scan_id}: {e}")

async def log_activity_callback(type: str, scan_id: str, target: str, message: str, severity: str = "info"):
    from pymongo import MongoClient
    MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://mongodb:27017")
    MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")
    
    try:
        client = MongoClient(MONGODB_URI)
        db = client[MONGODB_DATABASE]
        activities_col = db["activities"]
        
        activities_col.insert_one({
            "type": type,
            "scan_id": scan_id,
            "target": target,
            "message": message,
            "severity": severity,
            "timestamp": datetime.utcnow()
        })
        client.close()
    except Exception as e:
        logger.error(f"Activity Log Error: {e}")

async def dispatch_subfinder(scan_id: str, target: str, options: dict = {}):
    """
    Türkçe: Subfinder servisine subdomain keşif isteği gönderir
    Nuclei pattern'ine benzer yapıda MongoDB entegrasyonu
    """
    try:
        # Update status to running in MongoDB
        await update_scan_result_callback(scan_id, "subfinder", {"status": "running", "started_at": datetime.utcnow().isoformat()})

        async with httpx.AsyncClient() as client:
            # Subfinder konfigürasyonu
            subfinder_config = {
                "target": target,
                "scan_id": scan_id,
                "sources": options.get("sources", []),
                "all_sources": options.get("all_sources", False),
                "recursive": options.get("recursive", False),
                "timeout": options.get("timeout", 30),
                "rate_limit": options.get("rate_limit", 0)
            }
            
            # Taramayı başlat
            response = await client.post(
                f"{SUBFINDER_SERVICE_URL}/scan", 
                json=subfinder_config, 
                timeout=30.0
            )
            
            if response.status_code != 200:
                start_result = response.json()
                raise Exception(f"Subfinder scan başlatılamadı: {start_result}")
            
            logger.info(f"✅ Subfinder scan başlatıldı: {scan_id}")
            
            # Polling ile tamamlanmayı bekle
            max_wait = 600  # 10 dakika
            poll_interval = 3  # 3 saniye
            elapsed = 0
            
            while elapsed < max_wait:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval
                
                try:
                    status_res = await client.get(f"{SUBFINDER_SERVICE_URL}/status/{scan_id}", timeout=10.0)
                    status_data = status_res.json()
                    current_status = status_data.get("status")
                    
                    # Türkçe: "unknown" veya "not_found" status için MongoDB'den kontrol et
                    # Process memory'den silindiyse ama MongoDB'ye yazıldıysa buradan yakalarız
                    if current_status in ["unknown", "not_found"]:
                        # SubfinderActiveScans veya SubfinderLogs'dan gerçek durumu kontrol et
                        try:
                            logs_res = await client.get(f"{SUBFINDER_SERVICE_URL}/logs/{scan_id}", timeout=30.0)
                            if logs_res.status_code == 200:
                                logs_data = logs_res.json()
                                # SCAN_END log'u varsa tarama tamamlanmış demektir
                                for log in logs_data.get("logs", []):
                                    if log.get("level") == "SCAN_END":
                                        final_data = log.get("data", {})
                                        current_status = final_data.get("final_status", "completed")
                                        logger.info(f"Subfinder status MongoDB'den alındı: {current_status}")
                                        break
                        except Exception as mongo_check_err:
                            logger.warning(f"MongoDB status check error: {mongo_check_err}")
                    
                    if current_status == "completed":
                        # Sonuçları al
                        log_res = await client.get(f"{SUBFINDER_SERVICE_URL}/logs/{scan_id}", timeout=60.0)
                        if log_res.status_code == 200:
                            log_data = log_res.json()
                            
                            final_result = {
                                "status": "completed",
                                "subdomains": log_data.get("subdomains", []),
                                "subdomains_count": log_data.get("subdomains_count", 0),
                                "source_counts": log_data.get("source_counts", {}),
                                "duration_seconds": elapsed
                            }
                            await update_scan_result_callback(scan_id, "subfinder", final_result)
                            await log_activity_callback("scan_completed", scan_id, target, 
                                       f"Subfinder tamamlandı - {len(log_data.get('subdomains', []))} subdomain bulundu", "info")
                        else:
                            await update_scan_result_callback(scan_id, "subfinder", {
                                "status": "completed",
                                "message": "Log dosyası bulunamadı"
                            })
                        break
                        
                    elif current_status == "failed":
                        await update_scan_result_callback(scan_id, "subfinder", {
                            "status": "failed",
                            "error": status_data.get("error", "Bilinmeyen hata")
                        })
                        break
                        
                    elif current_status == "not_found" and elapsed > 30:
                        # Türkçe: 30 saniyeden sonra hala not_found ise başarısız say
                        await update_scan_result_callback(scan_id, "subfinder", {
                            "status": "failed",
                            "message": "Tarama process'i bulunamadı"
                        })
                        break
                except Exception as poll_err:
                     logger.warning(f"Subfinder polling error: {poll_err}")
                     # Don't break immediately on transient network errors
            else:
                # Timeout
                await update_scan_result_callback(scan_id, "subfinder", {
                    "status": "timeout",
                    "message": f"Tarama {max_wait} saniye sonra timeout oldu"
                })
                
    except Exception as e:
        error_result = {"error": str(e), "status": "failed"}
        await update_scan_result_callback(scan_id, "subfinder", error_result)
        await log_activity_callback("scan_error", scan_id, target, f"Subfinder hatası: {str(e)}", "error")
