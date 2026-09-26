"""
Kadim Güvenlik — CPE Kimlik Omurgası (identity from authoritative data)
=======================================================================
Türkçe: "10 bin sistem konfigürasyonunu elle yazamayız" probleminin temel katmanı. Fikir
şu: dünya bu kimlik verisini ZATEN üretiyor — nmap (`-sV`/`-O`) ve Shodan/InternetDB her
hedef için **CPE** (Common Platform Enumeration) döndürür: `cpe:2.3:o:canonical:ubuntu_linux:
22.04`. CPE sektörün kimlik STANDARDI ve NVD/KEV doğrudan CPE ile indekslidir → "bu nedir"
ile "neye açık" arasındaki JOIN anahtarıdır. Bizim küratörlü imza tablolarımız (target_profile)
bunun üstünde ince bir HIZLI-YOL olmalı; ana kimlik kaynağı CPE'dir (elle bakım biter).

Bu modül SAF'tır (I/O yok): CPE string'lerini ayrıştırır ve target_profile'ın anladığı
`extra` sinyallerine ((dim, value, weight, evidence)) çevirir. Ürün→boyut eşlemesi KÜÇÜK ve
kararlıdır (os/web-sunucu/dil çerçevesi için); asıl değer (kimlik + CVE join) ham CPE'dedir,
eşlemeye bağlı değildir. Tanınmayan ürün 'products' listesine düşer (operatör + gelecekteki
LLM/öğrenme katmanı tüketir) — yani kapsam kaybı YOK, sadece kaba boyut eşlemesi yapılmaz.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class CpeId:
    part: str        # o (işletim sistemi) | a (uygulama) | h (donanım/appliance)
    vendor: str
    product: str
    version: str     # "" = belirtilmemiş (* / -)
    raw: str


def parse_cpe(cpe: str) -> Optional[CpeId]:
    """CPE 2.3 (`cpe:2.3:a:vendor:product:version:...`) veya 2.2 URI (`cpe:/a:vendor:product:
    version`) ayrıştır (SAF). Geçersizse None. Küçük harfe indirir (karşılaştırma tutarlı)."""
    if not isinstance(cpe, str):
        return None
    s = cpe.strip()
    low = s.lower()
    if not low.startswith("cpe:"):
        return None
    if low.startswith("cpe:2.3:"):
        f = low.split(":")
        # f[0]=cpe f[1]=2.3 f[2]=part f[3]=vendor f[4]=product f[5]=version
        if len(f) < 5:
            return None
        part, vendor, product = f[2], f[3], f[4]
        version = f[5] if len(f) > 5 else "*"
    else:
        rest = low[len("cpe:/"):] if low.startswith("cpe:/") else low[len("cpe:"):]
        f = rest.split(":")
        if not f or not f[0]:
            return None
        part = f[0]
        vendor = f[1] if len(f) > 1 else ""
        product = f[2] if len(f) > 2 else ""
        version = f[3] if len(f) > 3 else "*"
    if part not in ("o", "a", "h"):
        return None
    version = "" if version in ("*", "-", "") else version
    return CpeId(part=part, vendor=vendor, product=product, version=version, raw=s)


# ---- OS normalizasyonu (küçük, kararlı; substring temelli — dev tablo YOK) ----
def _os_value(cid: CpeId) -> str:
    """part=o CPE'sinden kanonik OS değeri türet. Vendor+product substring'i yeterli;
    tanınmazsa 'linux'/'windows' kaba ayrımı, o da olmazsa ham product."""
    blob = f"{cid.vendor} {cid.product}"
    for needle, val in (
        ("ubuntu", "ubuntu"), ("debian", "debian"), ("canonical", "ubuntu"),
        ("centos", "rhel"), ("red_hat", "rhel"), ("redhat", "rhel"), ("rhel", "rhel"),
        ("rocky", "rhel"), ("almalinux", "rhel"), ("fedora", "fedora"),
        ("windows", "windows"), ("microsoft", "windows"),
        ("freebsd", "freebsd"), ("openbsd", "openbsd"),
        ("fortios", "fortios"), ("pan-os", "panos"), ("ios", "cisco-ios"),
        ("alpine", "alpine"), ("suse", "suse"),
    ):
        if needle in blob:
            return val
    if "linux" in blob:
        return "linux"
    return cid.product or "unknown"


# Web sunucusu ÜRÜN adları (part=a) — bunlar has_web_signal'ı besler (gerçek web yüzeyi).
# lighttpd BİLEREK yok: pfSense/embedded de kullanır → web kanıtı sayma (target_profile ile tutarlı).
_WEB_SERVER_MAP = {
    "http_server": "apache", "apache": "apache", "httpd": "apache",
    "nginx": "nginx", "iis": "iis", "internet_information_services": "iis",
    "internet_information_server": "iis", "tomcat": "tomcat", "openresty": "openresty",
    "caddy": "caddy", "litespeed": "litespeed",
}
# Dil/framework ipuçları (part=a ürününden) — kaba, opsiyonel; asıl CVE join ham CPE'de.
_LANG_HINTS = {"php": "php", "wordpress": "php", "drupal": "php", "joomla": "php",
               "python": "python", "django": "python", "openjdk": "java", "jre": "java",
               "jdk": "java", "tomcat": "java", "node.js": "node", "nodejs": "node"}
_FRAMEWORK_HINTS = {"wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
                    "django": "django", "laravel": "laravel"}
# Savunma/appliance ürünleri → waf boyutu (target_profile appliance çerçevesi).
_DEFENSE_HINTS = {"pfsense": "pfsense", "opnsense": "opnsense", "fortigate": "fortigate",
                  "fortiweb": "fortiweb", "big-ip": "f5", "cloudflare": "cloudflare"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9_.\-]", "", (s or "").lower())


def cpe_to_signals(cpes: List[str]) -> Tuple[List[Tuple[str, str, float, str]], List[str]]:
    """CPE listesini target_profile `extra` sinyallerine + insan-okunur ürün listesine çevir.

    Döner (extra, products). extra: os/server/language/framework/waf boyut oyları (CPE
    OTORİTER kaynak → yüksek ağırlık). products: 'vendor product version' (UI + öğrenme).
    Tanınmayan a/h ürünleri yalnız products'a düşer (kapsam kaybı yok, kaba eşleme yapılmaz)."""
    extra: List[Tuple[str, str, float, str]] = []
    products: List[str] = []
    seen_products: set = set()
    for raw in cpes or []:
        cid = parse_cpe(raw)
        if cid is None:
            continue
        if cid.part == "o":
            extra.append(("os", _os_value(cid), 0.8, f"cpe:{cid.product}"))
            continue
        # a / h → kimlik ürünü (insan-okunur: 'product version')
        label = f"{cid.product} {cid.version}".strip() if cid.version else cid.product
        pk = _norm(label)
        if pk and pk not in seen_products:
            seen_products.add(pk)
            products.append(label)
        prod = _norm(cid.product)
        if prod in _WEB_SERVER_MAP:
            extra.append(("server", _WEB_SERVER_MAP[prod], 0.8, f"cpe:{cid.product}"))
        for needle, val in _DEFENSE_HINTS.items():
            if needle in prod:
                extra.append(("waf", val, 0.85, f"cpe:{cid.product}"))
        for needle, val in _LANG_HINTS.items():
            if needle in prod:
                extra.append(("language", val, 0.6, f"cpe:{cid.product}"))
        for needle, val in _FRAMEWORK_HINTS.items():
            if needle in prod:
                extra.append(("framework", val, 0.7, f"cpe:{cid.product}"))
    return extra, products


# ---- nmap OS-detection STRING'i (CPE değil, serbest metin) → os sinyali ----
def os_string_to_signal(os_str: str) -> Optional[Tuple[str, str, float, str]]:
    """nmap `-O` çıktısı ('Linux 5.4', 'Ubuntu', 'Windows Server 2019') → os oyu (SAF).
    Kesinlik nmap accuracy'sinden bağımsız orta ağırlık; CPE yoksa yedek OS kaynağı."""
    if not os_str or not isinstance(os_str, str):
        return None
    b = os_str.lower()
    for needle, val in (
        ("ubuntu", "ubuntu"), ("debian", "debian"), ("centos", "rhel"),
        ("red hat", "rhel"), ("windows", "windows"), ("freebsd", "freebsd"),
        ("linux", "linux"),
    ):
        if needle in b:
            return ("os", val, 0.55, f"nmap-os:{os_str[:40]}")
    return None
