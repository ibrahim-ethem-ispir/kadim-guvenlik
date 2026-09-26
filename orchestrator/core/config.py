"""
Türkçe: Merkezi konfigürasyon - ortam değişkenleri tek noktada.

Servis URL'leri BURADA DEĞİL; onlar plugins/registry.py içinde. Burası sadece
altyapı ayarları (veritabanı, redis vb.) içindir.
"""
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://mongodb:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "kadim_security")
