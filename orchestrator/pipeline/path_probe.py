"""
Kadim Güvenlik — Hassas Yol / İfşa Prober'ı (Kuşatma Doktrini)
=============================================================
Türkçe: "domain/.env" sınıfı BASİT ama ÖLÜMCÜL açıkları yakalayan deterministik
HTTP prober. Nuclei template motoru neyi kaçırırsa kaçırsın (template yok, matcher
tutmadı, teknoloji yanlış tespit...) bu modül doğrudan GET + İÇERİK DOĞRULAMASI
yapar — sonuç template'e değil, sunucunun ham yanıtına dayanır.

Tasarım ilkeleri:
- Kör 200'e güvenme: paylaşımlı host'lar soft-404 (olmayan yola 200 + aynı sayfa)
  döner. Önce rastgele bir yol istenip BASELINE çıkarılır; içerik-doğrulaması zayıf
  olan bulgular baseline ile karşılaştırılıp elenir.
- Her yolun bir VALIDATOR'ı vardır: .env için KEY=VALUE deseni, .git/HEAD için
  "ref: refs/heads/" imzası gibi. Validator geçemeyen yanıt bulgu SAYILMAZ.
- Kanıt: her bulgu URL + status + boyut + (sırları MASKELENMİŞ) snippet + curl
  komutu taşır. Rapor "şu isteği attık, şu yanıt geldi" diyebilir.
- Gürültüsüz: yalnız GET, düşük eşzamanlılık, kısa timeout. Keşif sınıfı aktif
  araçtır (hedefe dokunur ama iz bırakması minimaldir).
"""

import asyncio
import logging
import os
import re
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("path-probe")

# ============================================================
# Yol kataloğu — (path, kategori, severity, validator)
# ============================================================
# Severity ağırlığı "dün başkası raporladı" sınıfına göredir: env/vcs/yedek/config
# ifşası en tepede. Panel/debug ikincil, bilgi notları (swagger vb.) en altta.
#
# validator isimleri aşağıdaki _validate_* fonksiyonlarına eşlenir. Validator'ın
# görevi soft-404 ve rastgele 200'leri elemek — İÇERİK imzası şart.

SENSITIVE_PATHS: List[Tuple[str, str, str, str]] = [
    # --- Ortam/gizli yapılandırma ifşası (en ölümcül sınıf) ---
    ("/.env", "env_exposure", "critical", "env_file"),
    ("/.env.local", "env_exposure", "critical", "env_file"),
    ("/.env.production", "env_exposure", "critical", "env_file"),
    ("/.env.development", "env_exposure", "high", "env_file"),
    ("/.env.backup", "env_exposure", "critical", "env_file"),
    ("/.env.old", "env_exposure", "critical", "env_file"),
    ("/.env.save", "env_exposure", "critical", "env_file"),
    ("/.env.example", "env_exposure", "low", "env_file"),
    ("/api/.env", "env_exposure", "critical", "env_file"),
    ("/app/.env", "env_exposure", "critical", "env_file"),
    ("/backend/.env", "env_exposure", "critical", "env_file"),
    ("/.git-credentials", "credential_exposure", "critical", "git_credentials"),
    ("/.npmrc", "credential_exposure", "high", "npmrc"),
    ("/.htpasswd", "credential_exposure", "critical", "htpasswd"),
    ("/.dockercfg", "credential_exposure", "critical", "json"),

    # --- Versiyon kontrol ifşası (kaynak kod sızıntısı) ---
    ("/.git/HEAD", "vcs_exposure", "critical", "git_head"),
    ("/.git/config", "vcs_exposure", "high", "git_config"),
    ("/.gitignore", "vcs_exposure", "low", "text_not_html"),
    ("/.svn/entries", "vcs_exposure", "high", "text_not_html"),
    ("/.hg/store", "vcs_exposure", "high", "generic"),

    # --- Yedek / veritabanı dökümü ---
    ("/wp-config.php~", "backup_exposure", "high", "php_config"),
    ("/wp-config.php.bak", "backup_exposure", "critical", "php_config"),
    ("/wp-config.php.save", "backup_exposure", "high", "php_config"),
    ("/wp-config.php.txt", "backup_exposure", "high", "php_config"),
    ("/config.php~", "backup_exposure", "high", "php_config"),
    ("/config.php.bak", "backup_exposure", "critical", "php_config"),
    ("/config.inc.php.bak", "backup_exposure", "high", "php_config"),
    ("/backup.sql", "db_dump", "critical", "sql_dump"),
    ("/dump.sql", "db_dump", "critical", "sql_dump"),
    ("/database.sql", "db_dump", "critical", "sql_dump"),
    ("/db.sql", "db_dump", "critical", "sql_dump"),
    ("/backup.zip", "backup_exposure", "high", "binary"),
    ("/backup.tar.gz", "backup_exposure", "high", "binary"),
    ("/site.zip", "backup_exposure", "high", "binary"),
    ("/www.zip", "backup_exposure", "high", "binary"),

    # --- Uygulama yapılandırma / log ifşası ---
    ("/config.yml", "config_exposure", "high", "yaml_config"),
    ("/config.yaml", "config_exposure", "high", "yaml_config"),
    ("/docker-compose.yml", "config_exposure", "high", "yaml_config"),
    # Türkçe: Symfony veritabanı kimlikleri — rakip ekibin portal.example-corp.com'da bulduğu
    # sınıf. Symfony 1.x'in databases.yml'i DB kullanıcı/parolasını DÜZ METİN taşır ve
    # eski kurulumlarda web kökünden erişilebilir kalır. Recon'un Symfony'yi tespit
    # edememesi ihtimaline karşı STATİK katalogda (tech_hints'e bağımlı değil).
    ("/symfony/config/databases.yml", "credential_exposure", "critical", "symfony_databases"),
    ("/config/databases.yml", "credential_exposure", "critical", "symfony_databases"),
    ("/app/config/parameters.yml", "credential_exposure", "high", "symfony_parameters"),
    ("/app/config/parameters.ini", "credential_exposure", "high", "ini_config"),
    ("/web.config", "config_exposure", "medium", "xml_config"),
    ("/.htaccess", "config_exposure", "medium", "htaccess"),
    ("/.user.ini", "config_exposure", "medium", "ini_config"),
    ("/storage/logs/laravel.log", "log_exposure", "high", "log_file"),
    ("/error_log", "log_exposure", "medium", "log_file"),
    ("/debug.log", "log_exposure", "medium", "log_file"),
    ("/composer.json", "info_disclosure", "low", "json"),
    ("/package.json", "info_disclosure", "low", "json"),

    # --- Teşhis / debug uçları ---
    ("/phpinfo.php", "debug_exposure", "high", "phpinfo"),
    ("/info.php", "debug_exposure", "high", "phpinfo"),
    ("/test.php", "debug_exposure", "medium", "phpinfo"),
    ("/server-status", "debug_exposure", "high", "server_status"),
    ("/server-info", "debug_exposure", "medium", "generic"),
    ("/actuator", "debug_exposure", "medium", "json"),
    ("/actuator/env", "env_exposure", "critical", "json"),
    ("/actuator/heapdump", "debug_exposure", "critical", "binary"),
    ("/elmah.axd", "debug_exposure", "high", "generic"),
    ("/trace", "debug_exposure", "medium", "generic"),
    ("/debug", "debug_exposure", "medium", "generic"),
    ("/_profiler", "debug_exposure", "high", "generic"),

    # --- API dokümanı ifşası (Bug Bounty P1-B — swagger açıksa endpoint matrisi
    # bedavaya gelir; crawl aşaması openapi_discovery ile dokümanı AYRIŞTIRIR,
    # buradaki kayıt yalnız İFŞA tespiti için güvenlik ağıdır) ---
    ("/swagger.json", "api_docs", "medium", "api_schema"),
    ("/openapi.json", "api_docs", "medium", "api_schema"),
    ("/api-docs", "api_docs", "medium", "api_schema"),
    ("/v2/api-docs", "api_docs", "medium", "api_schema"),
    ("/v3/api-docs", "api_docs", "medium", "api_schema"),
    ("/swagger/v1/swagger.json", "api_docs", "medium", "api_schema"),

    # --- Yönetim panelleri / dizin listeleme ---
    ("/adminer.php", "admin_panel", "high", "adminer"),
    ("/phpmyadmin/", "admin_panel", "medium", "phpmyadmin"),
    ("/.well-known/security.txt", "info_disclosure", "info", "text_not_html"),
    ("/.DS_Store", "info_disclosure", "low", "binary"),
    ("/backup/", "backup_exposure", "medium", "directory_listing"),
    ("/uploads/", "info_disclosure", "medium", "directory_listing"),
]

# ============================================================
# Teknoloji-özel yol setleri (dinamik genişletme)
# ============================================================
# Türkçe: Statik katalog her hedefte aynıdır; ama recon "Laravel"/"WordPress"/"Next.js"
# tespit ettiyse O framework'e özgü yollar en yüksek isabetli olanlardır. Bir tarayıcının
# sektörün önüne geçmesi burada başlar: körlemesine 64 yol değil, HEDEFİN TEKNOLOJİSİNE
# göre büyüyen katalog. Anahtar: recon'un ürettiği teknoloji etiketi (küçük harf, alt-dize
# eşleşmesi). Değer: o teknolojide en sık ifşa olan ek yollar.
TECH_SPECIFIC_PATHS: Dict[str, List[Tuple[str, str, str, str]]] = {
    "laravel": [
        ("/storage/logs/laravel.log", "log_exposure", "high", "log_file"),
        ("/.env.backup", "env_exposure", "critical", "env_file"),
        ("/telescope/requests", "debug_exposure", "high", "generic"),
        ("/_ignition/health-check", "debug_exposure", "high", "json"),
        ("/vendor/composer/installed.json", "info_disclosure", "low", "json"),
    ],
    "wordpress": [
        ("/wp-config.php.bak", "backup_exposure", "critical", "php_config"),
        ("/wp-config.php~", "backup_exposure", "high", "php_config"),
        ("/wp-content/debug.log", "log_exposure", "medium", "log_file"),
        ("/wp-json/wp/v2/users", "info_disclosure", "medium", "json"),
        ("/wp-content/uploads/", "info_disclosure", "medium", "directory_listing"),
    ],
    "next": [  # Next.js
        ("/.env.local", "env_exposure", "critical", "env_file"),
        ("/.env.production", "env_exposure", "critical", "env_file"),
        ("/_next/static/", "info_disclosure", "info", "directory_listing"),
    ],
    "nextjs": [
        ("/.env.local", "env_exposure", "critical", "env_file"),
        ("/.next/BUILD_ID", "info_disclosure", "low", "text_not_html"),
    ],
    "symfony": [
        ("/app_dev.php", "debug_exposure", "high", "phpinfo"),
        ("/_profiler", "debug_exposure", "high", "generic"),
        ("/.env.local", "env_exposure", "critical", "env_file"),
        # Türkçe: Symfony tespit edildiyse derin varyantlar da problanır — proje kökü
        # /symfony altında, uygulama bazlı config apps/<app>/config altında olabilir.
        ("/symfony/config/databases.yml", "credential_exposure", "critical", "symfony_databases"),
        ("/symfony/apps/frontend/config/databases.yml", "credential_exposure", "critical", "symfony_databases"),
        ("/symfony/apps/backend/config/databases.yml", "credential_exposure", "critical", "symfony_databases"),
        ("/apps/frontend/config/databases.yml", "credential_exposure", "critical", "symfony_databases"),
        ("/app/config/parameters.yml", "credential_exposure", "high", "symfony_parameters"),
    ],
    "django": [
        ("/.env", "env_exposure", "critical", "env_file"),
        ("/static/admin/", "info_disclosure", "info", "directory_listing"),
        ("/__debug__/", "debug_exposure", "high", "generic"),
    ],
    "node": [
        ("/.env", "env_exposure", "critical", "env_file"),
        ("/package.json", "info_disclosure", "low", "json"),
        ("/npm-debug.log", "log_exposure", "medium", "log_file"),
        ("/.npmrc", "credential_exposure", "high", "npmrc"),
    ],
    "spring": [
        ("/actuator/env", "env_exposure", "critical", "json"),
        ("/actuator/heapdump", "debug_exposure", "critical", "binary"),
        ("/actuator/health", "debug_exposure", "low", "json"),
        ("/actuator/mappings", "debug_exposure", "medium", "json"),
    ],
    "tomcat": [
        ("/manager/html", "admin_panel", "high", "generic"),
        ("/host-manager/html", "admin_panel", "high", "generic"),
    ],
}


def _paths_for_tech(tech_hints: Optional[List[str]]) -> List[Tuple[str, str, str, str]]:
    """Tespit edilen teknolojilere göre ek yol seti üret (dedup'lı). Eşleşme alt-dize
    üzerinden (recon 'Laravel 10' → 'laravel' anahtarı yakalanır). Bilinmeyen teknoloji
    ek yol getirmez — katalog sabit kalır (kör tarama üretmez)."""
    if not tech_hints:
        return []
    extra: List[Tuple[str, str, str, str]] = []
    seen_paths = set()
    for th in tech_hints:
        t = str(th).lower().strip()
        for key, paths in TECH_SPECIFIC_PATHS.items():
            if key in t:
                for row in paths:
                    if row[0] not in seen_paths:
                        seen_paths.add(row[0])
                        extra.append(row)
    return extra

# Validator eşlemesi — her biri (status, content_type, body_snippet) alır, bool döner.
# İmza taşımayan "generic" validator'lı bulgular soft-404 baseline süzgecinden geçer.


def _validate_env_file(status: int, ctype: str, body: str) -> bool:
    """.env doğrulaması: en az bir KEY=VALUE satırı + HTML sayfası OLMAMALI.
    Soft-404'ler genelde HTML döner; gerçek .env düz metindir ve DB_PASSWORD,
    APP_KEY gibi büyük-harf anahtarlar taşır."""
    if "<html" in body.lower() or "<!doctype" in body.lower():
        return False
    # Büyük harf anahtar=değer satırı (en az 1, tipik >2)
    matches = re.findall(r"(?m)^\s*[A-Z_][A-Z0-9_]{2,}\s*=\s*\S", body)
    return len(matches) >= 1


def _validate_git_head(status: int, ctype: str, body: str) -> bool:
    b = body.strip()
    return b.startswith("ref: refs/heads/") or bool(re.fullmatch(r"[0-9a-f]{40}", b))


def _validate_git_config(status: int, ctype: str, body: str) -> bool:
    return "repositoryformatversion" in body or ("[core]" in body and "[remote" in body)


def _validate_git_credentials(status: int, ctype: str, body: str) -> bool:
    # https://user:pass@host satırı
    return bool(re.search(r"https?://[^\s/]+:[^\s@]+@", body))


def _validate_npmrc(status: int, ctype: str, body: str) -> bool:
    return "_authToken" in body or "_auth=" in body or "registry=" in body


def _validate_htpasswd(status: int, ctype: str, body: str) -> bool:
    # kullanıcı:$apr1$... veya kullanıcı:{SHA}...
    return bool(re.search(r"(?m)^[\w.-]+:(\$[a-z0-9]+\$|\{SHA\}|\$2[aby]\$)", body))


def _validate_php_config(status: int, ctype: str, body: str) -> bool:
    # wp-config yedeği: DB_NAME/DB_PASSWORD define'ları veya <?php açılışı
    if "DB_PASSWORD" in body or "DB_NAME" in body:
        return True
    return body.lstrip().startswith("<?php") and ("define(" in body or "$" in body)


def _validate_sql_dump(status: int, ctype: str, body: str) -> bool:
    up = body.upper()
    return ("CREATE TABLE" in up or "INSERT INTO" in up or "DROP TABLE" in up
            or "MYSQL DUMP" in up)


def _validate_yaml_config(status: int, ctype: str, body: str) -> bool:
    if "<html" in body.lower():
        return False
    return bool(re.search(r"(?m)^\s*[\w.-]+:\s*\S", body))


def _validate_symfony_databases(status: int, ctype: str, body: str) -> bool:
    """Symfony databases.yml doğrulaması. Tipik gövde:
        all:
          propel:
            class: sfPropelDatabase
            param:
              hostspec: db.ic-host
              username: portal_user
              password: S1rr
    İki koşul birden: (1) DB motoru/bağlam imzası (sfPropelDatabase/sfDoctrineDatabase/
    propel:/doctrine:/hostspec/dsn), (2) kimlik-bilgisi alanı (username/password/hostspec).
    Tek başına 'all:' gibi zayıf YAML anahtarı yetmez — soft-404 HTML'leri ve alakasız
    YAML'ler elenir. GÜÇLÜ validator'dır: geçerse baseline karşılaştırması atlanır."""
    low = body.lower()
    if "<html" in low or "<!doctype" in low:
        return False
    has_engine = ("sfpropeldatabase" in low or "sfdoctrinedatabase" in low
                  or "propel:" in low or "doctrine:" in low
                  or "hostspec" in low or "dsn" in low)
    has_creds = ("username" in low or "password" in low or "hostspec" in low)
    return has_engine and has_creds


def _validate_symfony_parameters(status: int, ctype: str, body: str) -> bool:
    """Symfony 2/3 parameters.yml: 'parameters:' bloğu altında database_password/secret
    gibi anahtarlar. parameters: imzası + sır-taşıyan anahtar adı birlikte şart."""
    low = body.lower()
    if "<html" in low or "<!doctype" in low:
        return False
    return "parameters:" in low and ("database_" in low or "secret" in low)


def _validate_xml_config(status: int, ctype: str, body: str) -> bool:
    return "<configuration" in body or "<?xml" in body[:100]


def _validate_htaccess(status: int, ctype: str, body: str) -> bool:
    return any(k in body for k in ("RewriteEngine", "RewriteRule", "Deny from", "Require ", "Options "))


def _validate_ini_config(status: int, ctype: str, body: str) -> bool:
    return bool(re.search(r"(?m)^\s*[\w.]+\s*=\s*\S", body)) and "<html" not in body.lower()


def _validate_log_file(status: int, ctype: str, body: str) -> bool:
    # stack trace / tarihli log satırı imzası; HTML hata sayfası değil
    if "<html" in body.lower() and "stack trace" not in body.lower():
        return False
    return bool(re.search(r"\[\d{4}-\d{2}-\d{2}", body) or "Stack trace" in body
                or "production.ERROR" in body or "PHP Notice" in body or "PHP Warning" in body)


# Auth duvarı / hata zarfı imzası — 401/403 gövdeleri (ve bazen 200 dönen "token_expire"
# API'leri) İFŞA DEĞİLDİR: kaynak korumalı. Kullanıcı raporu: /api-docs 401 "token_expire"
# JSON'u _validate_json'dan geçip medium bulgu sayılıyordu (FP). İçerik validator'ları bu
# zarfı POZİTİF saymamalı.
_AUTH_WALL_RE = re.compile(
    r'token[_-]?expire|unauthor|forbidden|access\s*denied|invalid\s*token|'
    r'l[uü]tfen.{0,20}giri[sş]|giri[sş]\s*yap|oturum.{0,20}(a[çc]|sonland|zaman)|'
    r'please\s*log\s*in|authentication\s*required|not\s*authenticated', re.I)


def _looks_like_auth_error(body: str) -> bool:
    """Gövde bir auth-duvarı/hata zarfı mı? (SAF). İlk 512 bayta bakar — korumalı kaynağın
    'giriş yap / token süresi doldu / yetkisiz' yanıtı ifşa SAYILMAZ."""
    return bool(_AUTH_WALL_RE.search((body or "")[:512]))


def _validate_json(status: int, ctype: str, body: str) -> bool:
    b = body.strip()
    # Auth-hata zarfı JSON'u da geçerli JSON'dur ama İFŞA DEĞİL → reddet (200/401 fark etmez).
    if _looks_like_auth_error(b):
        return False
    return (b.startswith("{") and b.endswith("}")) or (b.startswith("[") and b.endswith("]"))


def _validate_api_schema(status: int, ctype: str, body: str) -> bool:
    """API dokümanı (Swagger/OpenAPI) GERÇEKTEN ifşa mı? (SAF). Salt 'geçerli JSON' YETMEZ —
    api-docs yolları çoğu zaman auth-korumalı 401 döner ('token_expire'); onları eleriz.
    Pozitif: OpenAPI/Swagger sürüm anahtarı VEYA paths+operasyon/tanım imzası."""
    if _looks_like_auth_error(body):
        return False
    low = body[:4096].lower()
    if '"swagger"' in low or '"openapi"' in low:
        return True
    # Redoc/Swagger-UI HTML sayfası da gerçek ifşadır (dokümanı açık sunuyor).
    if "swagger-ui" in low or "redoc" in low or "id=\"swagger" in low:
        return True
    # Ham OpenAPI JSON: paths bölümü + en az bir operasyon/tanım imzası
    return '"paths"' in low and (
        '"get"' in low or '"post"' in low or '"definitions"' in low or '"components"' in low)


def _validate_phpinfo(status: int, ctype: str, body: str) -> bool:
    low = body.lower()
    return "phpinfo()" in low or "php version" in low or "<title>phpinfo" in low


def _validate_server_status(status: int, ctype: str, body: str) -> bool:
    low = body.lower()
    return "apache server status" in low or "server uptime" in low or "total accesses" in low


def _validate_adminer(status: int, ctype: str, body: str) -> bool:
    return "adminer" in body.lower() and ("login" in body.lower() or "database" in body.lower())


def _validate_phpmyadmin(status: int, ctype: str, body: str) -> bool:
    return "phpmyadmin" in body.lower()


def _validate_directory_listing(status: int, ctype: str, body: str) -> bool:
    return "index of /" in body.lower()


def _validate_text_not_html(status: int, ctype: str, body: str) -> bool:
    return "<html" not in body.lower() and "<!doctype" not in body.lower() and len(body.strip()) > 0


def _validate_binary(status: int, ctype: str, body: str) -> bool:
    # Arşiv/döküm binary'leri: snippet'te okunabilir HTML olmamalı
    return "<html" not in body.lower() and len(body.strip()) >= 0


def _validate_generic(status: int, ctype: str, body: str) -> bool:
    return status == 200 and len(body.strip()) > 0


def _validate_from_signature(sig: Optional[Dict[str, Any]]) -> Callable[[int, str, str], bool]:
    """K2/K3 kaynaklı (LLM önerisi / öğrenilmiş yol) adaylar için imzadan DETERMİNİSTİK
    validator üret. Kritik felsefe: LLM/insan yalnız DESENİ verir, yargı burada motorun
    elinde kalır. İmza None/boşsa generic'e düşer.

    Kurallar sırayla: must_not_contain (herhangi biri gövdede varsa RED) → must_contain_all
    (hepsi şart) → must_contain_any (en az biri şart) → min_length. HTML reddi yalnız
    must_not_contain'de açıkça yazılırsa uygulanır (admin panel gibi HTML bulgulara esneklik).
    Hiç kısıt yoksa generic gibi davranır (boş gövde reddi) — bu sınıf ZAYIF validator'dır,
    soft-404 baseline elemesinden geçer (LLM bir imza uydursa bile baseline'la elenebilir)."""
    if not sig:
        return _validate_generic
    must_not = [str(s).lower() for s in sig.get("must_not_contain", []) if s]
    must_all = [str(s).lower() for s in sig.get("must_contain_all", []) if s]
    must_any = [str(s).lower() for s in sig.get("must_contain_any", []) if s]
    try:
        min_len = int(sig.get("min_length", 0) or 0)
    except (TypeError, ValueError):
        min_len = 0

    def _val(status: int, ctype: str, body: str) -> bool:
        low = body.lower()
        if any(tok in low for tok in must_not):
            return False
        if must_all and not all(tok in low for tok in must_all):
            return False
        if must_any and not any(tok in low for tok in must_any):
            return False
        if len(body.strip()) < min_len:
            return False
        if not (must_all or must_any or min_len):
            return len(body.strip()) > 0  # kısıtsız imza → generic davranış
        return True
    return _val


_VALIDATORS: Dict[str, Callable[[int, str, str], bool]] = {
    "env_file": _validate_env_file,
    "git_head": _validate_git_head,
    "git_config": _validate_git_config,
    "git_credentials": _validate_git_credentials,
    "npmrc": _validate_npmrc,
    "htpasswd": _validate_htpasswd,
    "php_config": _validate_php_config,
    "sql_dump": _validate_sql_dump,
    "yaml_config": _validate_yaml_config,
    "symfony_databases": _validate_symfony_databases,
    "symfony_parameters": _validate_symfony_parameters,
    "xml_config": _validate_xml_config,
    "htaccess": _validate_htaccess,
    "ini_config": _validate_ini_config,
    "log_file": _validate_log_file,
    "json": _validate_json,
    "api_schema": _validate_api_schema,
    "phpinfo": _validate_phpinfo,
    "server_status": _validate_server_status,
    "adminer": _validate_adminer,
    "phpmyadmin": _validate_phpmyadmin,
    "directory_listing": _validate_directory_listing,
    "text_not_html": _validate_text_not_html,
    "binary": _validate_binary,
    "generic": _validate_generic,
}

# Güçlü imza validator'ları — bunlar geçerse soft-404 baseline KARŞILAŞTIRMASI ATLANIR
# (bir soft-404 sayfasında "ref: refs/heads/" veya "DB_PASSWORD=" bulunmaz).
_STRONG_VALIDATORS = {
    "env_file", "git_head", "git_config", "git_credentials", "npmrc", "htpasswd",
    "php_config", "sql_dump", "phpinfo", "server_status", "adminer", "phpmyadmin",
    "directory_listing", "log_file",
    # Türkçe: Symfony DB kimliği imzası soft-404 sayfasında bulunmaz — baseline elemesini atla.
    "symfony_databases", "symfony_parameters",
    # OpenAPI/Swagger imzası (paths/swagger/openapi) soft-404'te bulunmaz — güçlü.
    "api_schema",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Kaynak → önce-değer önceliği. Bütçe dolarsa DÜŞÜK öncelikli (spekülatif) yollar iptal
# olsun; küratörlü/öğrenilmiş en güvenilir, şablon sonra, LLM/kanıt en son. (severity, source)
# ikilisiyle sıralanır → kritik kimlik yolu her zaman ilk semafor yuvasını alır.
_SOURCE_ORDER = {"curated": 0, "memory": 1, "template": 2, "llm": 3, "evidence": 4}


def _normalize_row(row: Tuple) -> Tuple[str, str, str, str, Dict[str, Any]]:
    """Katalog satırını (4- veya 5-tuple) tek biçime indir: (path, category, severity,
    validator_name, meta). meta = {'signature': dict|None, 'source': str}.

    4-tuple (mevcut K0/K1 named-validator) → meta üretilir (source='curated', signature=None).
    5-tuple (K2/K3 enjekte) → verilen meta korunur, eksik alanlar tamamlanır. Bu normalizasyon,
    prober'ın içinin LLM/DB bilmeden akıllanmasını sağlar: her kaynak aynı 5-tuple'a iner."""
    path, category, severity, vname = row[0], row[1], row[2], row[3]
    meta = dict(row[4]) if len(row) >= 5 and isinstance(row[4], dict) else {}
    meta.setdefault("signature", None)
    meta.setdefault("source", "curated")
    return path, category, severity, vname, meta

# Kategori → MITRE ATT&CK (rapor zenginliği)
_CATEGORY_MITRE = {
    "env_exposure": "T1552.001",        # Unsecured Credentials: Credentials In Files
    "credential_exposure": "T1552.001",
    "vcs_exposure": "T1592.004",        # Gather Victim Host Information: Software Config
    "backup_exposure": "T1083",         # File and Directory Discovery
    "db_dump": "T1005",                 # Data from Local System
    "config_exposure": "T1592.004",
    "log_exposure": "T1083",
    "debug_exposure": "T1083",
    "admin_panel": "T1190",             # Exploit Public-Facing Application
    "info_disclosure": "T1083",
}


# Pivot çıkarımı için ilgilendiğimiz .env/config anahtarları — bunların DEĞERİ bir sonraki
# saldırı adımına yön verir (iç host, alt-uygulama tabanı, açık depolama). Değerin kendisi
# (parola/anahtar) DEĞİL, yapısal ipucu (host adı, path, URL) çıkarılır. Rapora ham parola
# yazılmaz; bu ipuçları yalnız MOTOR-İÇİ pivot için kullanılır (yeni prob/host node'u).
_PIVOT_HOST_KEYS = re.compile(
    r"(?im)^\s*(DB_HOST|DATABASE_HOST|MYSQL_HOST|PG_HOST|POSTGRES_HOST|REDIS_HOST|"
    r"MEMCACHED_HOST|ELASTIC(?:SEARCH)?_HOST|MONGO_HOST|RABBITMQ_HOST|SMTP_HOST|"
    r"MAIL_HOST|CACHE_HOST|QUEUE_HOST)\s*=\s*([^\s#]+)")
_PIVOT_URL_KEYS = re.compile(
    r"(?im)^\s*(APP_URL|ASSET_URL|API_URL|BASE_URL|FRONTEND_URL|BACKEND_URL|"
    r"AWS_URL|S3_URL|CDN_URL|VITE_API_URL)\s*=\s*([^\s#]+)")
# Açık AWS/S3 depolama işaretleri (public bucket → veri sızıntısı zinciri).
_PIVOT_BUCKET_KEYS = re.compile(
    r"(?im)^\s*(AWS_BUCKET|S3_BUCKET|AWS_S3_BUCKET|BUCKET_NAME|GCS_BUCKET)\s*=\s*([^\s#]+)")
# Türkçe: YAML config'lerde DB host'u — Symfony databases.yml 'hostspec: db.ic-host',
# parameters.yml 'database_host: ...' taşır. KEY=VALUE regex'i YAML'i yakalayamaz;
# iç altyapı pivotu için ayrı desen gerekir.
_PIVOT_YAML_HOST_KEYS = re.compile(
    r"(?im)^\s*(?:hostspec|database_host|db_host)\s*:\s*[\"']?([^\s\"'#]+)")
# dsn satırı içindeki host=... (örn. mysql:host=db.internal;dbname=portal)
_PIVOT_DSN_HOST = re.compile(r"(?i)\bhost=([^;\s\"']+)")


def _extract_pivot_hints(body: str) -> Dict[str, List[str]]:
    """Bir .env/config gövdesinden BİR SONRAKİ ADIMA yön verecek yapısal ipuçlarını çıkar.

    Türkçe: Kuşatma Doktrini'nin 'zincir' katmanı. Açık .env tek başına bir bulgudur; ASIL
    değer içindeki iç altyapıyı ifşa etmesidir — DB_HOST bir iç IP/hostname verir, APP_URL
    alt-uygulama tabanını gösterir, S3_BUCKET açık depolamaya işaret eder. Bunlar yeni
    saldırı yüzeyidir (motor bunlara pathprobe/nmap seed eder). Parola/anahtar DEĞERLERİ
    ASLA çıkarılmaz — yalnız host/URL/bucket gibi yapısal hedefler. Bu çıktı motor-içidir,
    rapora/Mongo'ya ham sır yazılmaz."""
    hosts: List[str] = []
    urls: List[str] = []
    buckets: List[str] = []

    def _clean_host(v: str) -> str:
        v = v.strip().strip('"').strip("'")
        # scheme/port/path soy → çıplak host
        v = re.sub(r"^\w+://", "", v).split("/")[0].split(":")[0]
        return v.strip()

    for _k, v in _PIVOT_HOST_KEYS.findall(body):
        h = _clean_host(v)
        # localhost/127.* pivot değeri taşımaz (zaten hedefin içi) — atla.
        if h and h.lower() not in ("localhost", "127.0.0.1", "::1", "") and h not in hosts:
            hosts.append(h)
    # YAML config host'ları (hostspec/database_host) + dsn içi host=... — Symfony/
    # parameters.yml sınıfı bulgularda iç DB sunucusunu ifşa eder (zincir hedefi).
    for v in _PIVOT_YAML_HOST_KEYS.findall(body):
        h = _clean_host(v)
        if h and h.lower() not in ("localhost", "127.0.0.1", "::1", "") and h not in hosts:
            hosts.append(h)
    for v in _PIVOT_DSN_HOST.findall(body):
        h = _clean_host(v)
        if h and h.lower() not in ("localhost", "127.0.0.1", "::1", "") and h not in hosts:
            hosts.append(h)
    for _k, v in _PIVOT_URL_KEYS.findall(body):
        u = v.strip().strip('"').strip("'")
        if u and u not in urls:
            urls.append(u)
    for _k, v in _PIVOT_BUCKET_KEYS.findall(body):
        b = v.strip().strip('"').strip("'")
        if b and b not in buckets:
            buckets.append(b)
    return {"hosts": hosts[:10], "urls": urls[:10], "buckets": buckets[:10]}


def _redact_snippet(path: str, body: str, limit: int = 600) -> str:
    """Kanıt snippet'ı: gizli değerler MASKELENİR.
    .env yakalanırsa Mongo'ya/rapora ham parola yazmayız — anahtar adı + maske
    yeterli kanıttır (örn. DB_PASSWORD=***14***)."""
    snippet = body[:limit]
    if re.search(r"(?m)^\s*[A-Z_][A-Z0-9_]{2,}\s*=", snippet):
        def _mask(m: re.Match) -> str:
            val = m.group(2).strip()
            if not val or val in ("null", "true", "false"):
                return m.group(0)
            return f"{m.group(1)}=***{len(val)}***"
        snippet = re.sub(r"(?m)^(\s*[A-Z_][A-Z0-9_]{2,}\s*)=\s*(\S.*)$", _mask, snippet)
    # Türkçe: YAML config sırları (databases.yml/parameters.yml): 'password: gizli',
    # 'username: root', 'dsn: mysql://...' satırları. ENV maskesi bunları YAKALAMAZ —
    # yakalanmazsa DB parolası rapora/Mongo'ya HAM yazılır (sır sızıntısı). Değer
    # maskelenir, uzunluk bilgisi kanıt olarak kalır.
    def _mask_yaml(m: re.Match) -> str:
        val = m.group(2).strip().strip('"').strip("'")
        if not val or val.lower() in ("null", "true", "false", "~"):
            return m.group(0)
        return f"{m.group(1)}***{len(val)}***"
    # [\w.-]* önek/sonek: 'database_password', 'db_password', 'secret_key_base' gibi anahtarlar
    # da yakalansın (yalın 'password:' yetmez — parameters.yml 'database_password' taşır).
    snippet = re.sub(
        r"(?im)^(\s*[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|username|dsn)[\w.-]*\s*:\s*)(\S.*)$",
        _mask_yaml, snippet)
    # Türkçe: JSON tarzı sırlar — "password":"...", "api_key":"...", "token":"...". ENV/YAML
    # maskesi bunları YAKALAMAZ (satır 'anahtar:değer' değil, tırnaklı JSON). LLM/evidence
    # kaynaklı yeni yol sınıfları (config/*.json, actuator/env) ham sır sızdırmasın.
    def _mask_json(m: re.Match) -> str:
        val = m.group(2)
        if not val:
            return m.group(0)
        return f'{m.group(1)}"***{len(val)}***"'
    snippet = re.sub(
        r'("[\w.\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|aws[_-]?secret\w*|'
        r'client[_-]?secret|private[_-]?key)[\w.\-]*"\s*:\s*)"([^"]+)"',
        _mask_json, snippet, flags=re.I)
    # git-credentials benzeri kullanıcı:parola@ kalıbını da maskele
    snippet = re.sub(r"(https?://[^\s/:]+):[^\s@]+@", r"\1:***@", snippet)
    return snippet


# Bir yanıttan en fazla bu kadar bayt oku — validator'lar ilk 8KB'da çalışır; devasa
# dump/zip/heapdump dosyalarını tümüyle indirmek gereksiz ve taramayı kilitler. 256KB
# hem kanıt snippet'i hem de güvenli boyut karşılaştırması için fazlasıyla yeter.
_READ_CAP = int(os.getenv("PATHPROBE_READ_CAP_BYTES", str(256 * 1024)))


async def _fetch_capped(client: httpx.AsyncClient, url: str, timeout: float):
    """URL'i stream ile aç, en fazla _READ_CAP bayt oku, bağlantıyı kapat. Döner:
    (response, raw_bytes). Hata/erişilemezse (None, b'') döner. Büyük dosyayı tümüyle
    indirmeyi önler → tek yavaş yanıt tüm taramayı kilitlemez (asıl tıkanma noktası)."""
    try:
        async with client.stream("GET", url, timeout=timeout) as resp:
            chunks = bytearray()
            async for chunk in resp.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) >= _READ_CAP:
                    break  # yeterince okundu — gerisini indirme, bağlantıyı kapat
            return resp, bytes(chunks)
    except Exception:
        return None, b""


async def _resolve_base_url(client: httpx.AsyncClient, host: str) -> Optional[str]:
    """https önce, olmazsa http — hangi şema canlıysa onu döner."""
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        try:
            # Sadece bağlanabilirlik testi — gövdeyi indirme (HEAD gibi davran, stream+kapat).
            async with client.stream("GET", base + "/", timeout=8.0) as resp:
                # Herhangi bir yanıt (403 dahil) host'un canlı olduğunu gösterir
                return base
        except Exception:
            continue
    return None


# ============================================================
# Teknoloji/SÜRÜM parmak izi — "güncel CVE sende var mı?" sorusunun tetikleyicisi
# ============================================================
# NEDEN: Motor recon ile "WordPress var"ı biliyordu ama SÜRÜMÜNÜ bilmiyordu → NVD
# lookup (product+version şart) hiç tetiklenmiyor, "bu hafta çıkan WP açığı bu
# sitede var mı?" sorusu sorulamıyordu (örnek vaka: güncel WordPress zafiyeti
# tespit edilemedi). Prober zaten ana sayfaya GET atıyor — sürüm çıkarımı neredeyse
# bedava: meta generator, ?ver= parametreleri, readme.html, Server/X-Powered-By
# başlıkları. Sonuç `detected_technologies` olarak döner; attack_graph bunu
# needs_cve_lookup düğümüne çevirip NVD → hedefli nuclei zincirini başlatır.

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_WP_ASSET_VER_RE = re.compile(r'[?&]ver=(\d+\.\d+(?:\.\d+)?)')
_README_VER_RE = re.compile(r'Version\s+(\d+\.\d+(?:\.\d+)?)', re.I)

# meta generator içeriğinde tanıdığımız ürün adları (küçük harf karşılaştırma)
_KNOWN_GENERATORS = (
    "wordpress", "joomla", "drupal", "typo3", "magento", "prestashop",
    "ghost", "laravel", "woocommerce", "mediawiki",
)


def _parse_server_header(value: str) -> Optional[Dict[str, str]]:
    """'Apache/2.4.62 (Ubuntu)' → {product: apache, version: 2.4.62}"""
    if not value:
        return None
    m = re.match(r"\s*(apache|nginx|microsoft-iis|openresty|litespeed|apache-coyote)[/\s]*([\d.]+)?",
                 value, re.I)
    if not m:
        return None
    product = m.group(1).lower().replace("microsoft-iis", "iis").replace("apache-coyote", "tomcat")
    return {"product": product, "version": (m.group(2) or "").rstrip("."), "source": "server-header"}


# ============================================================
# 2026 YÜZEYİ — AI/agentic yığın + niş kurumsal uygulama imzaları
# ============================================================
# NEDEN: klasik funnel (Server header + meta-generator + WP) 2026'nın en aktif KEV
# cephesine KÖR. Langflow/n8n/Flowise/ComfyUI/marimo/Ollama gibi AI-agentic yığın ve
# Metabase/TeamCity/ColdFusion/GitLab gibi niş kurumsal uygulama meta-generator YAZMAZ,
# Server header'ı jeneriktir → huni 1. katmanda ölür ("port açık" der, geçer). Burada
# ürün adı SERVICE_VULNERABILITY_MAP + CISA KEV + CPE alias anahtarlarıyla BİREBİR seçildi
# → tek tespit noktası tüm huniyi (nuclei tag + KEV ürün-taraması + NVD) besler. Sürüm çoğu
# üründe ana sayfada ifşa edilmez; SÜRÜMSÜZ tespit bile KEV ürün-taramasına yeter (KEV'de
# sürüm aralığı yoktur, "bu ürün sahada aktif sömürülüyor" der).
#
# Biçim: (ürün, header/çerez imza-parçaları, gövde regex'leri, sürüm_regex|None).
#   - header parçaları küçük-harf "ad: değer" bloğuna (set-cookie dahil) substring bakılır.
#   - imza-parçaları AYIRT EDİCİ seçildi (title/karakteristik header/çerez) → false-positive az.
_MODERN_STACK_SIGNATURES: List[Tuple[str, Tuple[str, ...], Tuple[re.Pattern, ...], Optional[re.Pattern]]] = [
    # ---- AI / agentic yığın ----
    ("langflow", ("x-langflow",),
     (re.compile(r"<title>[^<]*langflow", re.I), re.compile(r"\blangflow\b", re.I)), None),
    ("n8n", ("n8n-auth", "n8n-version", "n8n-license"),
     (re.compile(r"<title>[^<]*n8n\b", re.I), re.compile(r"n8n\.io|window\.n8n\b", re.I)), None),
    ("flowise", (),
     (re.compile(r"<title>[^<]*flowise", re.I), re.compile(r"\bflowise\b", re.I)), None),
    ("comfyui", (),
     (re.compile(r"<title>[^<]*comfyui", re.I), re.compile(r"\bcomfyui\b|comfy\.ico", re.I)), None),
    ("marimo", (),
     (re.compile(r"<title>[^<]*marimo", re.I), re.compile(r"marimo-version|data-marimo", re.I)), None),
    ("ollama", (),
     (re.compile(r"ollama is running", re.I),), None),
    ("sglang", (),
     (re.compile(r"\bsglang\b", re.I),), None),
    ("jupyter", (),
     (re.compile(r"<title>[^<]*jupyter", re.I), re.compile(r"jupyter-config-data|jupyterhub", re.I)), None),
    # ---- Niş kurumsal / yönetim düzlemi ----
    ("metabase", ("metabase.session",),
     (re.compile(r"<title>[^<]*metabase", re.I),
      re.compile(r"window\.MetabaseBootstrap|MetabaseBootstrap", re.I)), None),
    ("teamcity", ("x-teamcity-node-id", "tcsessionid"),
     (re.compile(r"\bteamcity\b", re.I),),
     re.compile(r"teamcity[\s/]+(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("coldfusion", ("cfid=", "cftoken=", "cfmagic"),
     (re.compile(r"\bcoldfusion\b|/cfide/|cfml", re.I),), None),
    ("gitlab", ("x-gitlab-",),
     (re.compile(r"<title>[^<]*gitlab", re.I), re.compile(r"gon\.gitlab|/assets/webpack/", re.I)), None),
    ("grafana", ("grafana_session",),
     (re.compile(r"<title>[^<]*grafana", re.I), re.compile(r"grafanaBootData", re.I)),
     re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', re.I)),
    ("jenkins", ("x-jenkins",),
     (re.compile(r"<title>[^<]*jenkins", re.I),),
     re.compile(r"x-jenkins:\s*(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("confluence", ("x-confluence-request-time",),
     (re.compile(r'name="ajs-version-number"|confluence-base-url', re.I),), None),
    ("kibana", ("kbn-name", "kbn-version"),
     (re.compile(r"<title>[^<]*kibana", re.I),),
     re.compile(r"kbn-version:\s*(\d+\.\d+\.\d+)", re.I)),
    ("sharepoint", ("microsoftsharepointteamservices", "x-sharepointhealthscore", "sprequestguid"),
     (re.compile(r"/_layouts/15/|/_vti_bin/", re.I),), None),
]


def _detect_modern_stack(hdr_blob: str, body: str,
                         add_fn: Callable[[str, str, str], None]) -> None:
    """2026 yüzeyi imzalarını header/gövdede tara → tespit edileni `add_fn(ürün,sürüm,kaynak)`
    ile kaydet. SAF (I/O yok). AYIRT EDİCİ imza gerektirir; eşleşme yoksa hiçbir şey yapmaz."""
    for prod, hdr_needles, body_pats, ver_re in _MODERN_STACK_SIGNATURES:
        matched = any(n in hdr_blob for n in hdr_needles) or \
            any(p.search(body) for p in body_pats)
        if not matched:
            continue
        ver = ""
        if ver_re:
            mv = ver_re.search(body) or ver_re.search(hdr_blob)
            if mv:
                ver = mv.group(1)
        add_fn(prod, ver, "modern-stack-fingerprint")


async def _fingerprint_tech(client: httpx.AsyncClient, base_url: str, timeout: float) -> List[Dict[str, str]]:
    """Ana sayfa + (gerekiyorsa) readme.html'den ürün/sürüm çıkar. En fazla 2 istek;
    herhangi bir hata sessizce boş listeye düşer (parmak izi danışmandır, kritik yol değil)."""
    detected: List[Dict[str, str]] = []
    seen = set()

    def _add(product: str, version: str, source: str):
        product = (product or "").strip().lower()
        if not product or product in seen:
            return
        seen.add(product)
        detected.append({"product": product, "version": (version or "").strip(), "source": source})

    try:
        resp, raw = await asyncio.wait_for(
            _fetch_capped(client, f"{base_url}/", timeout), timeout=timeout + 2.0)
    except Exception:
        return detected
    if resp is None:
        return detected
    body = raw.decode("utf-8", errors="replace")

    # 1) Sunucu başlıkları — Apache/Nginx/PHP sürümü bedava gelir
    srv = _parse_server_header(resp.headers.get("server", ""))
    if srv:
        _add(srv["product"], srv["version"], srv["source"])
    m = re.match(r"\s*(php|asp\.net|express)[/\s]*([\d.]+)?",
                 resp.headers.get("x-powered-by", ""), re.I)
    if m:
        _add(m.group(1).lower(), (m.group(2) or "").rstrip("."), "x-powered-by")

    # 2) meta generator — CMS'in kendi beyanı (en güvenilir sürüm kaynağı)
    gen = _GENERATOR_RE.search(body)
    wp_version = ""
    if gen:
        content = gen.group(1).strip()
        gm = re.match(r"([A-Za-z0-9 ._-]+?)\s+(\d+\.\d+(?:\.\d+)?[a-z0-9.-]*)", content)
        for known in _KNOWN_GENERATORS:
            if known in content.lower():
                _add(known, gm.group(2) if gm else "", "meta-generator")
                if known == "wordpress" and gm:
                    wp_version = gm.group(2)
                break

    # 2.5) 2026 YÜZEYİ — AI/agentic + niş kurumsal imzaları (funnel'ın kör noktası).
    # Server header + meta-generator bunları YAZMAZ; header/çerez/title imzalarıyla yakala.
    hdr_blob = "\n".join(f"{k.lower()}: {str(v).lower()}" for k, v in resp.headers.items())
    _detect_modern_stack(hdr_blob, body, _add)

    # 3) WordPress imzası: generator yoksa bile wp-content/wp-includes yolları ele verir
    is_wp = "wordpress" in seen or "wp-content/" in body or "wp-includes/" in body
    if is_wp:
        if not wp_version:
            # En sık tekrar eden ?ver=X.Y.Z genelde çekirdek sürümüdür (tahmin — kaynakta belirtilir)
            vers = _WP_ASSET_VER_RE.findall(body)
            if vers:
                wp_version = max(set(vers), key=vers.count)
        if not wp_version:
            # Son çare: readme.html çekirdek sürümü açık yazar
            r_resp, r_raw = await _fetch_capped(client, f"{base_url}/readme.html", timeout)
            if r_resp is not None and r_resp.status_code == 200:
                rm = _README_VER_RE.search(r_raw.decode("utf-8", errors="replace"))
                if rm:
                    wp_version = rm.group(1)
        _add("wordpress", wp_version,
             "meta-generator" if "wordpress" in seen else "wp-asset-fingerprint")

    # 4) WordPress EKLENTİ sürümleri — "güncel WP açığı" vakalarının büyük çoğunluğu
    # çekirdek değil EKLENTİ zafiyetidir (Contact Form 7, Elementor, WooCommerce...).
    # Ana sayfadaki asset yollarından eklenti slug'ları çıkarılır, her birinin
    # readme.txt'sindeki 'Stable tag' sürümü okunur → NVD'ye 'slug X.Y.Z' diye
    # sorulabilir hale gelir. En fazla 5 eklenti (bütçe koruması), okuma 4KB ile sınırlı.
    if is_wp:
        slugs = list(dict.fromkeys(
            s.lower() for s in re.findall(r"/wp-content/plugins/([a-z0-9\-_]+)/", body)
        ))[:5]
        for slug in slugs:
            try:
                r_resp, r_raw = await asyncio.wait_for(
                    _fetch_capped(client, f"{base_url}/wp-content/plugins/{slug}/readme.txt", timeout),
                    timeout=timeout + 2.0,
                )
            except Exception:
                continue
            if r_resp is None or r_resp.status_code != 200:
                continue
            txt = r_raw.decode("utf-8", errors="replace")[:4096]
            m = re.search(r"Stable tag:\s*([\d.]+[a-z0-9.-]*)", txt, re.I)
            _add(slug, m.group(1).rstrip(".") if m else "", "wp-plugin-readme")

    return detected


# ============================================================
# K1 — Yol-ailesi şablonları (kombinasyonu RUNTIME üret, elle yazma)
# ============================================================
# NEDEN: k3 Symfony için '/symfony/apps/frontend/config/databases.yml' gibi kombinasyonları
# TEK TEK elle yazdı — bir hedef için düzeltir, sınıfı için değil. Bir sonraki hedefte
# 'apps/api/...' çıkarsa yine kaçar. Şablon çözümü: {taban}×{app}×{dosya} çarpımını hedefin
# teknolojisi tespit edilince runtime üret. Kimsenin yazmadığı kombinasyon da kapsanır.
PATH_FAMILIES: Dict[str, Dict[str, Any]] = {
    "symfony": {
        "bases": ["", "/symfony", "/app", "/config", "/current", "/apps/{app}"],
        "app_names": ["frontend", "backend", "api", "admin", "web", "mobile"],
        # Dosyalar SEVERITY sırasında — kritik varyantlar (databases.yml) aile başına
        # bütçe kesilse bile ilk üretilir (dış döngü dosya, iç döngü taban).
        "files": [
            ("config/databases.yml", "credential_exposure", "critical", "symfony_databases"),
            ("config/databases.yml.dist", "credential_exposure", "high", "symfony_databases"),
            ("config/parameters.yml", "credential_exposure", "high", "symfony_parameters"),
            ("config/parameters.ini", "credential_exposure", "high", "ini_config"),
            ("config/security.yml", "config_exposure", "medium", "yaml_config"),
        ],
    },
    "laravel": {
        "bases": ["", "/laravel", "/public/..", "/current"],
        "app_names": [],
        "files": [
            ("../.env", "env_exposure", "critical", "env_file"),
            (".env", "env_exposure", "critical", "env_file"),
            ("storage/logs/laravel.log", "log_exposure", "high", "log_file"),
            ("config/database.php", "config_exposure", "medium", "php_config"),
        ],
    },
    "wordpress": {
        "bases": ["", "/wordpress", "/blog", "/cms"],
        "app_names": [],
        "files": [
            ("wp-config.php.bak", "backup_exposure", "critical", "php_config"),
            ("wp-config.php~", "backup_exposure", "high", "php_config"),
            ("wp-config.php.save", "backup_exposure", "high", "php_config"),
            ("wp-config.php.orig", "backup_exposure", "high", "php_config"),
            (".env", "env_exposure", "critical", "env_file"),
        ],
    },
    "django": {
        "bases": ["", "/app", "/src", "/current"],
        "app_names": [],
        "files": [
            (".env", "env_exposure", "critical", "env_file"),
            ("settings.py", "config_exposure", "medium", "generic"),
            ("local_settings.py", "config_exposure", "high", "generic"),
        ],
    },
    "node": {
        "bases": ["", "/app", "/src", "/current", "/dist"],
        "app_names": [],
        "files": [
            (".env", "env_exposure", "critical", "env_file"),
            ("config/default.json", "config_exposure", "high", "json"),
            ("config/production.json", "config_exposure", "high", "json"),
            (".npmrc", "credential_exposure", "high", "npmrc"),
        ],
    },
    "spring": {
        "bases": ["", "/config", "/BOOT-INF/classes", "/WEB-INF/classes"],
        "app_names": [],
        "files": [
            ("application.properties", "config_exposure", "high", "ini_config"),
            ("application.yml", "config_exposure", "high", "yaml_config"),
            ("application-prod.yml", "config_exposure", "high", "yaml_config"),
        ],
    },
}


def _expand_path_families(techs: Optional[List[str]],
                          discovered_apps: Optional[List[str]] = None,
                          per_family_cap: int = 40) -> List[Tuple[str, str, str, str, Dict[str, Any]]]:
    """Tespit edilen teknolojilere göre {taban}×{app}×{dosya} çarpımını üret (5-tuple, source=
    'template'). Eşleşme alt-dize ('symfony 1.4' → 'symfony'). Bilinmeyen tech → boş (kör tarama
    üretmez). Aile başına üst sınır (bütçe koruması). Kanıttan gelen app adları önce sıralanır
    (yüksek değer). Dış döngü DOSYA (severity sırası) → kritik varyant asla cap'e kurban gitmez."""
    if not techs:
        return []
    rows: List[Tuple[str, str, str, str, Dict[str, Any]]] = []
    seen = set()
    tset = [str(t).lower() for t in techs]
    for fam_key, fam in PATH_FAMILIES.items():
        if not any(fam_key in t for t in tset):
            continue
        apps = list(dict.fromkeys(list(discovered_apps or []) + list(fam.get("app_names") or [])))
        all_bases: List[str] = []
        for base in fam.get("bases", []):
            if "{app}" in base:
                all_bases.extend(base.replace("{app}", a) for a in apps)
            else:
                all_bases.append(base)
        count = 0
        stop = False
        for (fpath, cat, sev, vname) in fam.get("files", []):
            for bv in all_bases:
                full = bv.rstrip("/") + "/" + fpath.lstrip("/")
                if not full.startswith("/"):
                    full = "/" + full
                if full in seen:
                    continue
                seen.add(full)
                rows.append((full, cat, sev, vname, {"signature": None, "source": "template"}))
                count += 1
                if count >= per_family_cap:
                    stop = True
                    break
            if stop:
                break
    return rows


# ============================================================
# K1 — Kanıt-güdümlü yol türetme (saf parse; I/O yok, ikinci dalga girdisi)
# ============================================================
def _paths_from_robots(text: str) -> List[str]:
    """robots.txt Disallow satırlarını doğrudan prob adayına çevir. Adminler hassas dizinleri
    'gizlemek' için buraya yazar → altın sinyal. Kök '/', boş ve '*' değersiz, elenir; wildcard
    içeren desen ilk '*' öncesine indirilir."""
    out, seen = [], set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.lower().startswith("disallow:"):
            continue
        val = line.split(":", 1)[1].strip().split("#")[0].strip()
        if "*" in val:
            val = val.split("*")[0]
        if not val or val == "/" or not val.startswith("/"):
            continue
        if val not in seen:
            seen.add(val)
            out.append(val)
    return out


_GIT_REMOTE_URL_RE = re.compile(r"(?im)^\s*url\s*=\s*(\S+)")


def _paths_from_git_config(text: str) -> List[str]:
    """.git/config remote URL'inden repo adını çıkar → web kökünde repo arşivi tahmini
    (/repo.zip, /repo.tar.gz). Kaynak kod sızıntısı zincirinin ucuz adımı. git@host:org/repo.git
    ve https://host/org/repo.git biçimlerini destekler."""
    out, seen = [], set()
    for url in _GIT_REMOTE_URL_RE.findall(text or ""):
        name = url.strip().rstrip("/").split("/")[-1]
        name = re.sub(r"\.git$", "", name).split(":")[-1]
        if not name or not re.match(r"^[\w.-]+$", name):
            continue
        for suf in (".zip", ".tar.gz", ".tar", "-backup.zip", ".rar"):
            p = f"/{name}{suf}"
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


_BACKUP_SUFFIXES = (".bak", "~", ".old", ".save", ".orig", ".dist", ".swp", ".backup", ".1")


def _backup_siblings(path: str) -> List[str]:
    """Var olan/atıf yapılan bir dosyanın yedek kardeşleri (çok yüksek olasılıklı ifşa):
    /config.php 200 dönüyorsa /config.php.bak yüksek olası. Dizinler (sonu '/') atlanır."""
    if not path or path.endswith("/"):
        return []
    return [f"{path}{suf}" for suf in _BACKUP_SUFFIXES]


_DIRLIST_HREF_RE = re.compile(r"""<a\s+[^>]*href\s*=\s*["']([^"']+)["']""", re.I)


def _paths_from_dir_listing(html: str, base_path: str) -> List[str]:
    """Apache/nginx 'Index of /' dizin listelemesindeki <a href> girdilerini prob adayına
    çevir. Üst-dizin bağları ('../'), sıralama sorguları ('?C=...') ve mutlak URL'ler elenir."""
    if "index of /" not in (html or "").lower():
        return []
    base = "/" + (base_path or "").strip("/")
    out, seen = [], set()
    for href in _DIRLIST_HREF_RE.findall(html or ""):
        href = href.strip()
        if not href or href.startswith("?") or href.startswith("#"):
            continue
        if ".." in href or "://" in href:
            continue
        full = href if href.startswith("/") else (base.rstrip("/") + "/" + href)
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out


class _OutOfScopeRedirect(Exception):
    """httpx redirect takibi kapsam DIŞI bir host'a çıkarken fırlatılır (aşağıdaki
    _scope_guard_hook). _fetch_capped/_resolve_base_url yakalar → istek sessizce atlanır
    (kapsam dışı hedeften veri toplanmaz, dış host'a yönlendiren yollar tutarsız sonuç üretmez)."""


def _scope_guard_hook(target_host: str) -> Callable[[httpx.Response], None]:
    """follow_redirects=True iken redirect zincirinin HEPSİ hedef host (veya alt
    domain'i) üstünde kalmasını zorunlu kılar. NEDEN: dış host'a açılan redirect
    (open-redirect istismari değil — bizim aracımızın DIŞARI sürüklenmesi) kanıtı
    kirletir: dış sunucunun 200'ü hedefin 'ifşası' gibi görünür, dış hedefte sonuç
    TUTARSIZLAŞIR (hangi CDN'e düşerse oradan yanıt döner). httpx event-hooks
    'response' kancası her ara yanıtta (redirect adımları dahil) çağrılır."""
    th = (target_host or "").strip().lower().lstrip(".")
    if not th:
        return lambda response: None

    def _hook(response: httpx.Response) -> None:
        try:
            rh = (response.request.url.host or "").lower()
        except Exception:
            return
        if rh and rh != th and not rh.endswith("." + th):
            raise _OutOfScopeRedirect(f"redirect kapsam dışına çıktı: {rh}")

    return _hook


async def probe_sensitive_paths(
    target: str,
    paths: Optional[List[Tuple]] = None,
    timeout: float = 8.0,
    concurrency: int = 6,
    redact: bool = True,
    path_base: Optional[str] = None,
    tech_hints: Optional[List[str]] = None,
    extra_paths: Optional[List[Tuple]] = None,
    discovered_apps: Optional[List[str]] = None,
    _transport: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Hedef host'ta hassas yol taraması yap.

    Args:
        target: domain veya IP (şema/sondaki-slash olmadan — temizlenir)
        paths: özel yol listesi; None ise SENSITIVE_PATHS
        timeout: istek başına timeout (sn)
        concurrency: eşzamanlı istek sayısı (düşük tut — gürültü yapma)
        path_base: uygulama alt-tabanı (ör. '/app'). Verilirse tüm yollar bu tabanın
                   ALTINDA da denenir (kök + taban). .env kökte değil 'x.com/app/.env'
                   gibi alt-tabanda olabilir (env pivot'undan gelen APP_URL ipucu).

    Returns:
        {
          "target": ..., "base_url": ..., "probed": N,
          "findings": [ {url, path, category, severity, status, content_length,
                         validator, snippet, curl, mitre} ... ],
          "severity_counts": {...}, "elapsed_seconds": ...,
          "note": "host_unreachable" gibi durum notu (varsa)
        }
    """
    started = time.time()
    # Hedef normalizasyonu: kullanıcı "https://x.com/" veya "x.com/path" girerse temizle
    host = re.sub(r"^https?://", "", target.strip()).split("/")[0].strip()

    # --- Katalog kurulumu: TÜM kaynaklar tek biçime (5-tuple) normalize edilir ---
    # Ham satırlar: K0 küratörlü çekirdek + tech-özel statik + K2/K3 enjekte (extra_paths).
    raw_rows: List[Tuple] = list(paths if paths is not None else SENSITIVE_PATHS)
    if tech_hints:
        raw_rows = raw_rows + _paths_for_tech(tech_hints)
    # extra_paths: K2 (LLM önerisi) + K3 (öğrenilmiş hafıza) — zaten 5-tuple, source/signature taşır.
    if extra_paths:
        raw_rows = raw_rows + list(extra_paths)
    catalog: List[Tuple[str, str, str, str, Dict[str, Any]]] = []
    _seen_paths = set()
    for row in raw_rows:
        nrow = _normalize_row(row)
        if nrow[0] in _seen_paths:
            continue  # dedup: aynı yol iki kez problanmaz (ilk kaynak kazanır)
        _seen_paths.add(nrow[0])
        catalog.append(nrow)
    # path_base verildiyse (env pivot: APP_URL=/app) aynı yolları alt-tabanda da dene —
    # .env kökte değil uygulama tabanında olabilir. Taban normalize edilir ('/app').
    if path_base:
        pb = "/" + path_base.strip().strip("/")
        if pb and pb != "/":
            based = []
            for (p, c, s, v, m) in catalog:
                np = f"{pb}{p}"
                if np not in _seen_paths:
                    _seen_paths.add(np)
                    based.append((np, c, s, v, dict(m)))
            catalog = catalog + based

    wave2_rows: List[Tuple] = []  # kanıt-türetme ikinci dalgası (dönüş sayımı için dışarıda)
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    }
    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=timeout, limits=limits,
        transport=_transport,  # yalnız test (MockTransport); üretimde None → varsayılan
        headers=browser_headers,
        # KAPSAM KORUMASI: redirect'ler yalnız hedef host/alt-domain'inde takip edilir;
        # dış host'a açılan zincir bu kancayla kesilir (yukarıda gerekçe).
        event_hooks={"response": [_scope_guard_hook(host)]},
    ) as client:
        base_url = await _resolve_base_url(client, host)
        if not base_url:
            return {
                "target": host, "base_url": None, "probed": 0, "findings": [],
                "severity_counts": {}, "elapsed_seconds": round(time.time() - started, 2),
                "note": "host_unreachable: 80/443 üzerinden HTTP erişimi yok",
                "detected_technologies": [], "partial": False,
            }

        # Teknoloji/SÜRÜM parmak izi: NVD → hedefli nuclei zincirinin tetikleyicisi.
        # Hassas yol taramasından bağımsız, 1-2 ek GET; hata sessizce boş döner.
        detected_tech = await _fingerprint_tech(client, base_url, timeout)

        # K1 — YOL-AİLESİ GENİŞLEMESİ: fingerprint + tech_hints birleşik teknoloji kümesinden
        # {taban}×{app}×{dosya} üret. Recon Symfony'yi kaçırsa bile fingerprint yakalarsa aile
        # açılır (databases.yml kök nedeni: recon-bağımlılığı burada kırılır).
        fam_techs = list(tech_hints or []) + [t.get("product", "") for t in detected_tech]
        for frow in _expand_path_families(fam_techs, discovered_apps):
            if frow[0] not in _seen_paths:
                _seen_paths.add(frow[0])
                catalog.append(frow)

        # --- SOFT-404 BASELINE: olmayan rastgele yolun yanıtı ölçülür ---
        baseline_status = 0
        baseline_len = -1
        try:
            rnd_resp, rnd_raw = await asyncio.wait_for(
                _fetch_capped(client, f"{base_url}/kadim-{uuid.uuid4().hex[:10]}-yok", timeout),
                timeout=timeout + 2.0,
            )
            if rnd_resp is not None:
                baseline_status = rnd_resp.status_code
                baseline_len = len(rnd_raw)
        except Exception:
            pass  # baseline alınamazsa yalnız validator'lara güvenilir

        sem = asyncio.Semaphore(concurrency)
        findings: List[Dict[str, Any]] = []
        # Kanıt toplama (ikinci dalga türetmesi için wave-1'de gözlenen sinyaller):
        evidence_bodies: Dict[str, str] = {}   # git/config + dizin-listeleme gövdeleri
        found_file_paths: List[str] = []       # 200 dönen dosya-benzeri yollar (yedek-kardeş)
        waf_block_count = 0
        waf_aborted = False

        async def _probe_one(path: str, category: str, severity: str,
                             validator_name: str, meta: Dict[str, Any]):
            nonlocal waf_block_count, waf_aborted
            if waf_aborted:
                return
            url = f"{base_url}{path}"
            try:
                async with sem:
                    if waf_aborted:
                        return
                    # stream ile aç, gövdeyi SINIRLI oku (devasa dump/zip taramayı kilitlemesin).
                    resp, raw = await asyncio.wait_for(
                        _fetch_capped(client, url, timeout), timeout=timeout + 2.0
                    )
            except Exception:
                return
            if resp is None:
                return
            status = resp.status_code

            # WAF / Rate-limit devre kesici: 429 veya ardışık WAF bloklarında taramayı kitlemeden zarifçe durdur
            if status == 429:
                waf_block_count += 1
                if waf_block_count >= 4:
                    waf_aborted = True
                    logger.warning(f"PathProbe: 429 Rate Limit algılandı, hedef ({host}) korumalı. Kalan yollar atlanıyor.")
                return

            # STATUS ÇERÇEVESİ (FP kökü): 200 = içerik SERVİS edildi (gerçek ifşa). 401/403 =
            # kaynak KORUMALI → ifşa DEĞİL. Eski guard bozuktu: 401/403 zaten izin-setinde
            # olduğundan admin_panel kısıtı HİÇ çalışmıyor, TÜM kategorilerde 401/403 geçiyordu
            # (kullanıcı raporu: /api-docs 401 'token_expire' medium bulgu). Artık 401/403 yalnız
            # admin_panel'de "panel var ama korumalı" DÜŞÜK-değer notu; gerisi düşürülür.
            if status == 200:
                pass
            elif status in (401, 403) and category == "admin_panel":
                pass
            elif status == 403:
                # 403 blok kontrolü — Cloudflare / WAF sayfası mı?
                try:
                    b_check = raw[:1024].decode("utf-8", errors="ignore").lower()
                    if "cloudflare" in b_check or "cf-ray" in str(resp.headers).lower() or "waf" in b_check:
                        waf_block_count += 1
                        if waf_block_count >= 8:
                            waf_aborted = True
                            logger.info(f"PathProbe: WAF engeli tespit edildi ({host}), aşırı istekten kaçınmak için durduruldu.")
                except Exception:
                    pass
                return
            else:
                return
            try:
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            snippet_src = body[:8192]  # validator'lar ilk 8KB'da çalışır
            ctype = resp.headers.get("content-type", "")
            body_len = len(raw)

            # Validator seçimi: signature meta varsa ondan DETERMİNİSTİK üret; yoksa isimli.
            if validator_name == "signature":
                validator = _validate_from_signature(meta.get("signature"))
            else:
                validator = _VALIDATORS.get(validator_name, _validate_generic)
            if not validator(status, ctype, snippet_src):
                return

            # Soft-404 elemesi: zayıf imzalı bulgu baseline ile örtüşüyorsa düş. signature de
            # zayıf sınıftır (LLM bir imza uydursa bile baseline ile elenebilir — çifte koruma).
            if validator_name not in _STRONG_VALIDATORS and baseline_len >= 0:
                if status == baseline_status and abs(body_len - baseline_len) <= max(64, baseline_len // 8):
                    return

            # KANIT yakala (ikinci dalga türetmesi): git/config, dizin-listeleme, 200 dosyalar.
            if status == 200:
                low = snippet_src.lower()
                if validator_name == "git_config" or "[remote" in low or "repositoryformatversion" in low:
                    evidence_bodies[path] = snippet_src
                if validator_name == "directory_listing" or "index of /" in low:
                    evidence_bodies.setdefault(path, snippet_src)
                # dosya-benzeri (uzantılı, dizin değil) → yedek-kardeş adayı
                if not path.endswith("/") and re.search(r"\.[A-Za-z0-9]{1,6}$", path):
                    found_file_paths.append(path)

            # PIVOT: .env/config sınıfı bulgudan iç altyapı ipuçlarını çıkar (zincirleme saldırı).
            pivot_hints = {}
            if category in ("env_exposure", "config_exposure", "credential_exposure"):
                pivot_hints = _extract_pivot_hints(snippet_src)

            # KORUMALI kaynak (401/403 — yalnız admin_panel buraya gelir) İFŞA değildir; en
            # fazla "panel var" bilgisidir → severity'yi low'a çek, ham katalog severity'siyle
            # (medium+) manşeti şişirme.
            eff_severity = severity if status == 200 else "low"
            findings.append({
                "url": str(resp.url),  # redirect sonrası nihai URL
                "path": path,
                "category": category,
                "severity": eff_severity,
                "status": status,
                "content_length": body_len,
                "validator": validator_name,
                # snippet: varsayılan MASKELİ (rapor güvenliği). redact=False → HAM kanıt.
                "snippet": _redact_snippet(path, snippet_src) if redact else snippet_src,
                "redacted": bool(redact),
                "curl": f"curl -sk '{base_url}{path}'",
                "mitre": _CATEGORY_MITRE.get(category),
                "pivot_hints": pivot_hints,
                # Bulgu nereden geldi (curated/template/evidence/llm/memory) — rapor + ayar sinyali.
                "source": meta.get("source", "curated"),
            })

        overall_budget = float(os.getenv("PATHPROBE_OVERALL_TIMEOUT", "40"))

        # ÖNCE-DEĞER SIRALAMASI: bütçe dolarsa DÜŞÜK-değerli/spekülatif yollar iptal olsun,
        # kritik kimlik yolları HER ZAMAN ilk semafor yuvasını alsın. (severity, source, path).
        def _prio(row: Tuple) -> Tuple:
            return (_SEVERITY_ORDER.get(row[2], 9),
                    _SOURCE_ORDER.get(row[4].get("source", "curated"), 9), row[0])

        async def _run_wave(rows: List[Tuple], budget: float) -> bool:
            """Bir yol grubunu problar; bütçe dolunca bitmeyenleri iptal eder. partial döner.
            Her yol AYRI task (asıl asılı host tüm taramayı yutamasın); açık cancel kullanılır."""
            if not rows or budget <= 0:
                return False
            tasks = [asyncio.ensure_future(_probe_one(*r)) for r in rows]
            _, pending = await asyncio.wait(tasks, timeout=budget)
            was_partial = bool(pending)
            for t in pending:
                t.cancel()
            if pending:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True), timeout=3.0)
                except Exception:
                    pass
            return was_partial

        # DALGA 1 — küratörlü + şablon + enjekte (K2/K3). Bütçenin çoğu buraya.
        catalog.sort(key=_prio)
        t0 = time.time()
        partial = await _run_wave(catalog, overall_budget)
        spent = time.time() - t0

        # DALGA 2 — kanıttan türetilmiş yollar (robots/.git/dizin/yedek-kardeş), kalan bütçeyle.
        # Dalga-1 zaten kesildiyse yeni yük ekleme (bütçe bitmiş).
        if not partial:
            remaining = max(4.0, overall_budget - spent)
            derived: List[Tuple[str, str, str, str]] = []
            # robots.txt (tek GET) → Disallow yolları (adminin sakladığı hassas dizinler)
            try:
                r_resp, r_raw = await asyncio.wait_for(
                    _fetch_capped(client, f"{base_url}/robots.txt", timeout), timeout=timeout + 2.0)
                if r_resp is not None and r_resp.status_code == 200:
                    for p in _paths_from_robots(r_raw.decode("utf-8", errors="replace")):
                        derived.append((p, "info_disclosure", "medium", "generic"))
            except Exception:
                pass
            # .git/config gövdesinden repo arşivi + dizin-listeleme içeriğinden özyineleme
            for _p, _body in evidence_bodies.items():
                if "[remote" in _body or "url =" in _body or "url=" in _body:
                    for p in _paths_from_git_config(_body):
                        derived.append((p, "backup_exposure", "high", "binary"))
                if "index of /" in _body.lower():
                    base_path = _p if _p.endswith("/") else (_p.rsplit("/", 1)[0] + "/")
                    for p in _paths_from_dir_listing(_body, base_path):
                        derived.append((p, "info_disclosure", "medium", "generic"))
            # yedek kardeşleri (wave-1'de 200 dönen dosyalar)
            for fp in found_file_paths:
                for p in _backup_siblings(fp):
                    derived.append((p, "backup_exposure", "high", "generic"))

            wave2_seen = set(_seen_paths)
            for (p, c, s, v) in derived:
                if p in wave2_seen:
                    continue
                wave2_seen.add(p)
                wave2_rows.append((p, c, s, v, {"signature": None, "source": "evidence"}))
                if len(wave2_rows) >= 40:  # kanıt dalgası bütçe koruması
                    break

            if wave2_rows:
                wave2_rows.sort(key=_prio)
                partial = await _run_wave(wave2_rows, remaining) or partial

        if partial:
            logger.warning(f"PathProbe genel bütçe ({overall_budget}s) doldu — kısmi sonuç "
                           f"({len(findings)} bulgu). host={host}")

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["path"]))
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    return {
        "target": host,
        "base_url": base_url,
        "probed": len(catalog) + len(wave2_rows),
        "findings": findings,
        "severity_counts": sev_counts,
        "elapsed_seconds": round(time.time() - started, 2),
        # Genel bütçe dolduysa True — bazı yollar taranamadan kesildi (kısmi sonuç).
        # UI bunu "tarama kısmen tamamlandı" olarak gösterebilir; bulgular yine geçerli.
        "partial": partial,
        # Sürümlü teknoloji parmak izi (wordpress 6.x, apache 2.4.x...) — graf bunu
        # NVD lookup'a bağlar; "güncel CVE bu sitede var mı?" sorusunun veri kaynağı.
        "detected_technologies": detected_tech,
    }


async def _probe_with_transport(host: str, transport: Any, **kwargs) -> Dict[str, Any]:
    """TEST-YARDIMCISI (üretimde kullanılmaz): HTTP'yi httpx.MockTransport ile mockla.
    probe_sensitive_paths'i ağsız, deterministik test etmek için client'a transport enjekte
    eder. Böylece iki-dalga/sıralama/signature akışları gerçek ağ olmadan doğrulanır."""
    return await probe_sensitive_paths(host, _transport=transport, **kwargs)
