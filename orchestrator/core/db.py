"""
Türkçe: MongoDB bağlantısı ve koleksiyon erişimi tek noktada.

Davranış NOTU: Bağlantı kurulamazsa `db = None` olur (eski main.py davranışıyla
birebir aynı). main.py bu modülden `db` ve getter'ları import eder; böylece
bağlantı mantığı tek yerde toplanır.
"""
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

from .config import MONGODB_URI, MONGODB_DATABASE

# Türkçe: MongoDB bağlantısı (kalıcı depolama için)
try:
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    mongo_client.admin.command('ping')
    db = mongo_client[MONGODB_DATABASE]
    print("✅ MongoDB bağlantısı başarılı")
except ConnectionFailure as e:
    print(f"⚠️ MongoDB bağlantı hatası: {e}")
    mongo_client = None
    db = None


def _ensure_scan_memories_indexes():
    """scan_memories şema düzeltmesi (idempotent, best-effort).

    Bu koleksiyon scan başına ÇOK kayıt tutar: endpoint_snapshot (endpoint_diff), doğrulanmış
    sömürü dersleri + başarısızlık kalıpları + WAF-bypass dersleri (exploit_memory). Eski
    şemadan kalma UNIQUE `scan_id` indeksi bu çok-kayıtlı yapıyla ÇELİŞİYOR:
      • endpoint_diff scan_id'yi yazıyor → aynı taramada 2. host'un snapshot'ı E11000 ile düşüyor.
      • exploit_memory scan_id'yi HİÇ yazmıyor → tüm kayıtlar scan_id=null; non-sparse unique
        indekste yalnız TEK null kabul edildiğinden İLK dersten sonrası sessizce kayboluyor
        (field-journal/öğrenme özelliği fiilen çalışmıyordu).
    Çözüm: unique kısıtını kaldır, yerine kısıtsız (non-unique) scan_id indeksi koy. İdempotent:
    zaten non-unique ise dokunmaz. Silme, mevcut veriyi bozmaz (yalnız kısıt kalkar)."""
    if db is None:
        return
    try:
        col = db["scan_memories"]
        info = col.index_information()
        existing = info.get("scan_id_1")
        if existing and existing.get("unique"):
            col.drop_index("scan_id_1")
            print("🔧 scan_memories: hatalı UNIQUE scan_id indeksi kaldırıldı "
                  "(çok-kayıt/scan için kısıtsıza çevrildi).")
        if "scan_id_1" not in col.index_information():
            # Kısıtsız indeks: scan_id ile sorgu hâlâ hızlı, ama benzersizlik dayatılmaz.
            col.create_index("scan_id", name="scan_id_1")
    except Exception as e:
        print(f"⚠️ scan_memories indeks düzeltmesi atlandı: {e}")


_ensure_scan_memories_indexes()


# Türkçe: MongoDB koleksiyonları
def get_scans_collection():
    return db["scans"] if db is not None else None


def get_sessions_collection():
    """Otonom (v2) taramaların TEK doğruluk kaynağı. Koleksiyon adı burada tek yerde
    tanımlıdır (scan_pipeline_v2._get_sessions_collection ile aynı ad)."""
    return db["v2_scan_sessions"] if db is not None else None


def get_activities_collection():
    return db["activities"] if db is not None else None


def get_vulnerabilities_collection():
    return db["vulnerabilities"] if db is not None else None


def get_scan_schedules_collection():
    """Zamanlanmış tarama kayıtları (kullanıcının 'Hedef Kayıtları' modülü).

    Sebep: Koleksiyon adı tek noktada tanımlı kuralı (yukarıdaki yorum) — yeni koleksiyon
    eklerken de aynı kalıbı izliyoruz, böylece ad değişikliği gerektiğinde tek dosya yeter.

    Index'ler startup'ta schedules_router tarafından (ensure_indexes) oluşturulur; burada
    sadece getter var — bağlantı hâlâ tek `db` instance'ı.
    """
    return db["scan_schedules"] if db is not None else None
