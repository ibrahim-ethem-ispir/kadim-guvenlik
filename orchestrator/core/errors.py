"""
Türkçe: Hata mesajı temizleme ve kullanıcı dostu hata çevirisi.

Hassas bilgileri (dosya yolları, servis URL'leri, MongoDB bağlantısı, IP'ler,
stack trace) frontend'e sızdırmadan önce temizler.
"""
import re


def sanitize_error_message(error: str) -> str:
    """
    Türkçe: Hata mesajlarından hassas bilgileri temizler

    Temizlenen bilgiler:
    - Dosya yolları (/app/, /home/, /etc/)
    - Servis URL'leri (http://xxx-service:port)
    - MongoDB bağlantı bilgileri
    - Stack trace detayları
    - Ortam değişkenleri
    """
    if not error:
        return "Unknown error occurred"

    error_str = str(error)

    # Dosya yolları
    error_str = re.sub(r'/app/[^\s"\']+', '[path-hidden]', error_str)
    error_str = re.sub(r'/home/[^\s"\']+', '[path-hidden]', error_str)
    error_str = re.sub(r'/etc/[^\s"\']+', '[path-hidden]', error_str)
    error_str = re.sub(r'/var/[^\s"\']+', '[path-hidden]', error_str)
    error_str = re.sub(r'/tmp/[^\s"\']+', '[path-hidden]', error_str)

    # Internal service URL'leri
    error_str = re.sub(r'http://[a-z-]+:\d+', '[internal-service]', error_str)
    error_str = re.sub(r'ws://[a-z-]+:\d+', '[internal-service]', error_str)

    # MongoDB bağlantı bilgileri
    error_str = re.sub(r'mongodb://[^\s"\']+', '[mongodb-hidden]', error_str)

    # IP adresleri (internal)
    error_str = re.sub(r'172\.\d+\.\d+\.\d+', '[internal-ip]', error_str)
    error_str = re.sub(r'10\.\d+\.\d+\.\d+', '[internal-ip]', error_str)
    error_str = re.sub(r'192\.168\.\d+\.\d+', '[internal-ip]', error_str)

    # Stack trace satırları
    error_str = re.sub(r'File "[^"]+", line \d+', '[trace-hidden]', error_str)
    error_str = re.sub(r'Traceback \(most recent call last\):', '', error_str)

    # Ortam değişkenleri
    error_str = re.sub(r'\$[A-Z_]+', '[env-hidden]', error_str)

    # Çok uzunsa kısalt
    if len(error_str) > 200:
        error_str = error_str[:200] + "..."

    return error_str.strip() or "An error occurred"


# ============== User-Friendly Error Messages ==============

ERROR_MESSAGES = {
    "connection refused": "Servis geçici olarak erişilemez durumda",
    "timeout": "İşlem zaman aşımına uğradı, lütfen tekrar deneyin",
    "not found": "İstenen kaynak bulunamadı",
    "unauthorized": "Yetkilendirme hatası",
    "mongodb": "Veritabanı bağlantı sorunu",
    "websocket": "Gerçek zamanlı bağlantı kesildi"
}


def get_user_friendly_error(error: str) -> str:
    """Türkçe: Kullanıcı dostu hata mesajı döndürür"""
    error_lower = str(error).lower()

    for key, message in ERROR_MESSAGES.items():
        if key in error_lower:
            return message

    return sanitize_error_message(error)
