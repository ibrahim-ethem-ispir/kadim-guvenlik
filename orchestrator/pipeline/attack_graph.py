"""
Kadim Güvenlik - Kuşatma Doktrini: Attack-Graph Tabanlı Strateji Motoru
======================================================================
Türkçe: Otonom motorun dünya modeli. Hedefi düz bir liste değil,
yönlü bir graf (Node/Edge) olarak tutar; her turda hangi kenara
("hangi sura top çekilecek") en yüksek `siege_score` ile karar verilir.


Score(edge) = ( V(to) * P_breach(to) * SuccessProb(edge) / Cost(edge) ) * Urgency * Novelty

Bu modül SAF bir veri yapısıdır: LLM/HTTP çağrısı yapmaz (o sorumluluk
autonomous_engine.py'de kalır). Sadece graf durumunu tutar, büyütür,
skorlar ve öğrenir.
"""

import asyncio
import json
import logging
import math
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("attack-graph")

# NVD CVE lookup erişilebilirliği SADECE ihtiyaç anında kontrol edilir.
# Aktif import, yalnız cve_intel aktifse ve kullanılabilirse çalışır.
_cve_intel = None


def _get_cve_intel():
    global _cve_intel
    if _cve_intel is None:
        try:
            from . import cve_intel
            _cve_intel = cve_intel
        except Exception as e:
            logger.debug(f"cve_intel import edilemedi: {e}")
            _cve_intel = False
    return _cve_intel


# KEV/EPSS (aktif-sömürü istihbaratı) aynı desende tembel yüklenir.
_kev_intel = None


def _get_kev_intel():
    global _kev_intel
    if _kev_intel is None:
        try:
            from . import kev_intel
            _kev_intel = kev_intel
        except Exception as e:
            logger.debug(f"kev_intel import edilemedi: {e}")
            _kev_intel = False
    return _kev_intel


# KEV üyesi CVE'nin hedefli nuclei kenarı urgency'si. NVD adayı 1.4'tür; KEV
# "sahada aktif sömürülüyor" demek olduğundan belirgin üstüne çıkar (RAID 2.5'in
# biraz altı — .env sınıfı kesin-kazanç yine önde kalır, ama KEV her sıradan
# CVE adayını geçer). Fidye yazılımı kampanyasındaysa zirveye çekilir.
KEV_URGENCY = 2.2
KEV_RANSOMWARE_URGENCY = 2.4
# Bir üründen grafa en çok kaç KEV CVE'si seed edilir (graf şişmesin; en taze
# eklenenler önceliklidir — operatörün 'bu ay ne düştü' sorusuna hizmet eder).
KEV_MAX_PER_PRODUCT = int(os.getenv("KEV_MAX_PER_PRODUCT", "8"))
# EPSS bu eşiğin üstündeyse CVE "sıcak" sayılır: KEV'de olmasa bile olasılık
# yüksek → hedefli doğrulama kenarı urgency'si NVD tabanının üstüne çekilir.
EPSS_HOT_THRESHOLD = float(os.getenv("EPSS_HOT_THRESHOLD", "0.5"))


# ============================================================
# Doktrin sabitleri (doküman §2.1 / §2.2 birebir)
# ============================================================

NODE_VALUE_TABLE: Dict[str, float] = {
    "database": 90,
    "admin-panel": 80,
    "remote-mgmt": 75,
    "auth-endpoint": 70,
    "critical-cve-service": 95,
    "api": 55,
    "web-app": 40,
    "static": 10,
    # FAZ 1.3: yeni varlık sınıfları (data/kod sızıntısı = yüksek değer). Bunlar OPSİYONEL
    # key'ler — mevcut değerleri bozmaz; yalnız yeni node tipleri bulununca kullanılır.
    "default-creds": 90,          # bulunan varsayılan/test kimlik = doğrudan foothold
    "s3-bucket-public": 85,       # açık depolama = veri sızıntısı
    "git-repo-exposed": 75,       # kaynak kod sızıntısı
    "graphql-introspection": 60,
    "asn-block": 30,
    # APT servis-istihbaratı: mail/DNS yüzeyi (user-enum, open-relay, zone-transfer,
    # sürüm-CVE). Eskiden hiç kategorize edilmiyordu → 5/9 port görünmezdi.
    "mail-service": 60,           # SMTP/IMAP/POP3 — kullanıcı enum, kimlik, sürüm-CVE
    "dns-service": 55,            # DNS — zone transfer, cache poisoning, sürüm-CVE
    "network-service": 45,        # tanınan ama sınıflanmayan versiyonlu servis (NVD adayı)
    # K8s kontrol düzlemi: apiserver/kubelet/etcd/Rancher dışa açıksa TEK noktadan TÜM
    # küme (tüm workload'lar + sırlar) risk altındadır → en yüksek değer sınıfı.
    "k8s-control-plane": 95,
}

EDGE_COST_TABLE: Dict[str, float] = {
    "osint": 5,
    "subfinder": 10,
    "recon": 12,
    "reverse_ip": 8,
    "origin_discovery": 20,
    "nmap-top100": 15,     # Kademeli ilk temas — ucuz, hızlı, gürültüsüz
    "nmap-top1000": 25,    # Orta kademe
    "nmap-full": 50,       # -p- (65535) — pahalı, yalnız Derin + yüksek-skor host
    "rustscan-full": 35,
    "nuclei-targeted": 20,
    "nuclei-broad": 60,
    "nuclei-dast": 45,     # Aktif web/API enjeksiyon testi (xss/sqli/ssrf...) — orta-pahalı
    "fuzz": 55,
    "pathprobe": 10,       # Hassas yol probu (.env/.git/yedek) — ucuz, ~60 GET, yüksek getiri
    # Türkçe: Faz 1 — endpoint keşfi. Crawler HTTP-BFS ile URL/form/JS toplar; 60 saniyelik
    # bütçeyle orta-ağırlık. Nuclei'nin kör kök URL'i aşması için zorunlu adım.
    "crawl": 18,
}

# Web sunucusu/uygulaması olarak sınıflanan servisler — bunlar bulununca aktif web/API
# zafiyet testi (DAST) anlamlı hale gelir (madde 3).
WEB_APP_SERVICES: Set[str] = {"apache", "nginx", "iis", "spring", "laravel", "wordpress", "tomcat"}

# Bir HTTP/web servisi doğrulanınca, sunucu-özel CVE tag'lerine EK olarak eklenen genel
# web-yüzey tag'leri. Framework tespit edilemese bile (örn. IP hedefte recon atlanır) yaygın
# ve yüksek-değerli inceleme noktalarını (açık .env/.git, yedek dosya, phpMyAdmin, varsayılan
# parola, panel) yakalar. Severity filtresi altında çalışır → "kör tarama" değil, hedefli
# web yüzeyi incelemesi. PHP/legacy uygulamalarda en çok bulgu üreten sınıflar bunlardır.
WEB_SURFACE_TAGS: List[str] = ["exposure", "exposures", "misconfig", "default-login", "backup"]

# Yaygın HTTP(S) portları — 'has_http' tespiti için. Eski liste (80/443/8080/8443/8000/8888)
# standart-dışı portlarda KOŞUYOR bir web servisi görünmez kılıyordu → uygulama katmanı
# (nuclei web-yüzeyi, DAST, pathprobe raid) HİÇ doğmuyordu: "port açık ama taranmadı"
# tutarsızlığının kök nedenlerinden biri. nmap service/product adında 'http' geçiyorsa
# zaten yakalanır; bu liste ad tanınMAYAN durumlarda güvenlik ağıdır (Grafana/Node/Kibana/
# WebLogic/ES/Docker-API/consul/prometheus... hepsi burada).
COMMON_HTTP_PORTS: frozenset = frozenset({
    80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096, 2375, 2376,
    3000, 3001, 4443, 4848, 5000, 5601, 7000, 7001, 7070, 7080,
    8000, 8008, 8009, 8010, 8080, 8081, 8082, 8088, 8090, 8180, 8443, 8444, 8843, 8888,
    9000, 9001, 9080, 9090, 9200, 9443, 10000, 10250, 15672, 8500,
})

DEFAULT_NODE_VALUE = 25.0
DEFAULT_EDGE_COST = 20.0

# Keşif kenarlarının (recon/subfinder/nmap/rustscan/osint/origin_discovery) hedefi henüz
# bilinmeyen saldırı yüzeyidir — root node'un GERÇEK value/breach_prob'una göre skorlanamaz
# (root sadece başlangıç noktası, ele geçirilecek bir varlık değil). Bu araçlar sabit bir
# "keşfedilmemiş potansiyel" değeriyle skorlanır ki doktrinin "önce istihbarat" ilkesi
# (doküman §0) her zaman uygulanabilir kalsın.
# NOT: "pathprobe" hedefe dokunan AKTİF bir araçtır ama SKORLAMA açısından keşif sınıfına
# girer — bulacağı şey (açık .env/.git) henüz haritalanmamış yüzeydir ve co-hosted host'un
# düşük başlangıç değeri (static=10, breach=0.08) kenarı eşiğin altında bırakıp HİÇ
# SEÇİLMEMESİNE yol açardı (skor: 10*0.08*0.7/10=0.056 < 0.15). DISCOVERY_POTENTIAL ile
# her host'ta çalışabilir (60*0.5*0.7/10=2.1). Seviye/onay kapıları için yine ACTIVE_TOOLS
# tarafında sayılır (autonomous_engine) — pasif değildir, yalnız keşif-değeriyle skorlanır.
RECON_TOOLS: Set[str] = {"recon", "subfinder", "nmap", "rustscan", "osint", "origin_discovery", "reverse_ip", "pathprobe", "crawl"}
DISCOVERY_POTENTIAL_VALUE = 60.0
DISCOVERY_POTENTIAL_PROB = 0.5

# cPanel/Plesk STANDART DNS kayıtları: hosting kurulumunda otomatik açılır, neredeyse
# her zaman ana siteyle AYNI sunucuyu gösterir ve .env sınıfı bulgu üretmez. Bunlara
# recon+RAID seed etmek adım bütçesini çöpe harcar (örnek vaka: 28 adımın ~15'i
# webdisk/webmail/whm/autoconfig/autodiscover probuna gitti, bulgu sıfır). Node
# görünürlük için grafta kalır ama derin tarama kenarı SEED EDİLMEZ; raporda
# "cPanel varsayılan kaydı" olarak görünür.
_BOILERPLATE_LABELS: Set[str] = {
    "webdisk", "webmail", "whm", "autoconfig", "autodiscover",
    "cpanel", "cpcalendars", "cpcontacts", "plesk",
}


def _is_boilerplate_subdomain(name: str) -> bool:
    """'webdisk.x.com' → True (cPanel varsayılan kaydı — taramaya değmez)."""
    return bool(name) and name.split(".")[0] in _BOILERPLATE_LABELS


# WILDCARD/VHOST GÜRÜLTÜSÜ imzası — bir subdomain'in İÇİNE gömülü tam bir kayıtlı alan.
# Örn 'musteri-a.com.hosting-provider.com': kök 'hosting-provider.com' (son iki etiket) atılınca
# geriye 'musteri-a.com' KALIR ve bu da başlı başına bir .com alanıdır. Bu gerçek bir
# subdomain DEĞİL, hosting sağlayıcının *.root wildcard'ının / panel vhost'unun yansımasıdır
# (örnek vaka: hosting-provider.com hosting'inde subfinder onlarca 'müşteridomain.com.hosting-provider.com'
# döndürdü). Her birini RAID'lemek adım bütçesini yakar ve üçüncü-parti gibi görünen hayali
# host'lara prob açar. Deterministik ele — DNS'e dokunmadan.
_EMBEDDED_GTLDS: Set[str] = {"com", "net", "org", "gov", "edu", "info", "biz"}
# Trendy/kısa TLD'ler (io, co, dev, app, ai, xyz) BİLEREK dışarıda: gerçek subdomain
# etiketi olarak sık kullanılır (api.dev.x.com, app.io... ) → FP üretmesin.
_EMBEDDED_CC_TLDS: Set[str] = {"tr", "uk", "de", "fr", "nl", "ru", "it", "es"}


def _is_malformed_subdomain(name: str) -> bool:
    """'musteri-a.com.hosting-provider.com' → True (gömülü tam domain = wildcard/vhost yansıması).

    Kural: kökü (son iki etiket, sld.tld) at; geriye kalan ön-ek TAM bir kayıtlı alan gibi
    BİTİYORSA (…​.com / …​.net / …​.com.tr) bu bir subdomain değildir. Muhafazakâr: en az
    'label.tld' (≥2 etiket) ararız ki çıplak 'net.x.com' gibi meşru etiketler yanmasın."""
    labels = [l for l in (name or "").lower().split(".") if l]
    if len(labels) < 4:
        return False  # kök(2) + tek etiket = normal subdomain; gömülü domain için ≥4 gerekir
    prefix = labels[:-2]  # kökü (sld.tld) düş → geriye subdomain "etiketleri" kalır
    # İki-seviyeli ccTLD gömülü mü? (…​.com.tr.root gibi)
    if len(prefix) >= 3 and prefix[-1] in _EMBEDDED_CC_TLDS and prefix[-2] in _EMBEDDED_GTLDS:
        return True
    # Tek-seviyeli gTLD gömülü mü? (label.tld — ≥2 etiket şart, çıplak tld değil)
    if len(prefix) >= 2 and prefix[-1] in _EMBEDDED_GTLDS:
        return True
    return False

# Bulunan subdomainlerin kaç tanesine otomatik tarama kenarı seed edilsin (graf şişmesin).
# Motorun step bütçesi zaten fiilen kaç tanesinin çalışacağını belirler.
MAX_SUBDOMAIN_SCAN_EDGES = int(os.getenv("AUTONOMOUS_MAX_SUBDOMAIN_EDGES", "40"))

# LLM'in "likely_vuln_classes" ipucunu (path-traversal/default-login gibi) gerçek nuclei
# tag'ine çevirir. Böylece istihbarat subayının sezgisi HEDEFLİ taramaya döner (eskiden
# parse edilip çöpe gidiyordu). Eşleşmeyen sınıf sessizce atlanır (kör tarama üretmez).
VULN_CLASS_TO_NUCLEI_TAGS: Dict[str, List[str]] = {
    "path-traversal": ["lfi"], "lfi": ["lfi"], "rfi": ["rfi"],
    "rce": ["rce"], "remote-code-execution": ["rce"], "cmdi": ["rce"],
    "sqli": ["sqli"], "sql-injection": ["sqli"],
    "xss": ["xss"], "cross-site-scripting": ["xss"],
    "ssrf": ["ssrf"], "xxe": ["xxe"], "ssti": ["ssti"],
    "default-login": ["default-login"], "default-credentials": ["default-login"],
    "open-redirect": ["redirect"], "deserialization": ["deserialization"],
    "auth-bypass": ["auth-bypass"], "exposure": ["exposure"],
}

# Skor bu eşiğin altına düşerse kuşatma biter ("kırılacak sur kalmadı")
THRESHOLD = float(os.getenv("SIEGE_SCORE_THRESHOLD", "0.15"))

# ============================================================
# BİLGİ-KAZANIMI HEDEFİ (Information-Gain Objective) — flag-gated
# ============================================================
# Doktrin: siege_score "en yüksek ETKİLİ" aksiyonu seçer (değer·olasılık·başarı/maliyet).
# Ama iyi bir pentester "en çok ETKİLİ"yi değil, "İSPATA en çok BİLGİ kazandıran"ı koşar:
#   - zaten KANITLANMIŞ (breached) düğümü tekrar dövmez (yeni bilgi ~0),
#   - defalarca denenip tükenen kenara bütçe yakmaz (azalan getiri),
#   - kanıtlanmamış yüzeyde, ispat verme olasılığı yüksek aksiyonu öne çeker.
# Bu, hem verimi artırır hem de DOĞAL BİR DURMA KRİTERİ doğurur: en bilgilendirici aksiyon
# bile eşiğin altına düşünce "öğrenilecek/kanıtlanacak yeni şey kalmadı" → dur (472-bulgu
# kör listelemesinin panzehiri). KAPALIYKEN objective_score ≡ siege_score (davranış birebir).
# A2 (yol haritası §7-#1): varsayılan AÇIK. Makinesi (objective_score yeniden-şekillendirme +
# next_decision doğal-durma) zaten kanıtlı/tested; bu bayrak, motoru "en yüksek ETKİLİ"den
# "ispata en çok BİLGİ kazandıran"a çevirir ve kör 472-listeleme yerine doğal durma verir.
# Eski davranışa dönmek için INFO_GAIN_OBJECTIVE=0.
INFO_GAIN_OBJECTIVE = os.getenv("INFO_GAIN_OBJECTIVE", "1") == "1"
# En yüksek 'bilgi-kazanımı ilgililiği' bunun altına düşerse motor durur (yalnız flag açıkken).
INFO_GAIN_MIN = float(os.getenv("INFO_GAIN_MIN", "0.04"))
# Bilgi-çarpanı bu tabana/tavana sıkıştırılır → sıralamayı yeniden şekillendirir ama patlatmaz.
_INFO_FLOOR = float(os.getenv("INFO_GAIN_FLOOR", "0.25"))
_INFO_CEIL = float(os.getenv("INFO_GAIN_CEIL", "1.6"))
# Kanıtlanmış (breached) düğüme yönelen kenara uygulanan ilgililik indirimi. Sıfır DEĞİL:
# tek host'ta ikinci bir zafiyet hâlâ bulunabilsin diye yumuşak (körleşmeyi önler).
_INFO_PROVEN_WEIGHT = float(os.getenv("INFO_GAIN_PROVEN_WEIGHT", "0.35"))

# L2 — KEŞİF/MERAK terimi. İyi bir pentester imzasız ama zengin bir yüzeyde (çok
# endpoint/param/API) DAHA meraklıdır; motorun ekonomisi ise tersine "bilinen sinyal yoksa
# durur"du. Bu çarpan, HENÜZ DENENMEMİŞ enjeksiyon-hedefi endpoint'lere yönelen kenarlara
# tek seferlik bir "ilk bak" bonusu verir → api-route (JSON/GraphQL) gibi düşük-breach ama
# gerçek hedefler eşiği geçer. Yalnız taze/injectable ENDPOINT'lere uygulanır (SERVICE/CVE
# skorlarını ve mevcut testleri ETKİLEMEZ). Denendikten sonra (tried_count>0) sıfırlanır →
# gürültü/sonsuz döngü yok. Kapatmak için CURIOSITY_EXPLORE=0.
CURIOSITY_EXPLORE = os.getenv("CURIOSITY_EXPLORE", "1") == "1"
CURIOSITY_BONUS = float(os.getenv("CURIOSITY_BONUS", "1.3"))

# L3 — LLM HAM-YÜZEY brifingi. Açıkken compact_state (danışma prompt'u kaynağı) somut
# saldırı yüzeyini (injectable endpoint'ler + formlar + OpenAPI matrisi + GraphQL ops)
# LLM'e taşır → LLM graf-özetini yeniden-ağırlıklandıran danışmandan, gerçek endpoint'e
# SOMUT hipotez üreten pentester'a yükselir. Kapatılırsa (=0) eski davranış (yalnız özet).
LLM_RAW_SURFACE = os.getenv("LLM_RAW_SURFACE", "1") == "1"

# ============================================================
# SEVERITY TABANI (K2 düzeltmesi) — kurumsal görünürlük
# ============================================================
# ÖNCEDEN tag/DAST taramaları da ["critical","high"] ile kısıtlıydı → bankalarda ilk turda
# en sık çıkan info/low/medium bulgular (eksik güvenlik header, versiyon ifşası, açık
# .env/.git, dizin listeleme) FİLTRELENİYORDU → tarama "boş" görünüyordu. Artık taban
# 'medium'. İsteyen env ile 'low'a indirip daha da geniş görünürlük açabilir; 'critical'
# yaparak eski dar davranışa dönebilir. Hedefli CVE taramaları (templates) bilinçli olarak
# critical,high kalır — onlar zaten spesifik bir açığı kanıtlar, gürültü riski yok.
_SEV_LADDER = ["critical", "high", "medium", "low", "info"]


def _severity_from_floor(floor: str) -> List[str]:
    """Verilen tabandan yukarı (daha ciddi) tüm severity'leri döndürür.
    floor='medium' → ['critical','high','medium']. Bilinmeyen taban → medium'a düşer."""
    floor = (floor or "medium").strip().lower()
    if floor not in _SEV_LADDER:
        floor = "medium"
    return _SEV_LADDER[: _SEV_LADDER.index(floor) + 1]


# Varsayılan taban 'low' (APT-derinliği): açık panel, config ifşası, sürüm ifşası, dizin
# listeleme gibi düşük-şiddet ama gerçek bulgular artık taranır — eskiden 'medium' bunları
# eliyordu ("boş tarama" hissinin kökü). GÜRÜLTÜ endişesi: FP confidence-tier sistemi bunları
# 'unconfirmed/incelenmeli' kovasına koyar, manşet kritik/yüksek sayısını ŞİŞİRMEZ. 'info'
# hâlâ dışarıda (aşırı gürültü); isteyen AUTONOMOUS_SEVERITY_FLOOR=info/critical ile ayarlar.
DEFAULT_SEVERITY_FLOOR = os.getenv("AUTONOMOUS_SEVERITY_FLOOR", "low").strip().lower()
DEFAULT_SEVERITY = _severity_from_floor(DEFAULT_SEVERITY_FLOOR)

# GEÇİCİ HATA TOLERANSI (A.1): bir kenar (aksiyon) timeout/hata verdiğinde KAÇ toplam
# denemeye kadar açık (yeniden denenebilir) tutulur. Timeout çoğu zaman geçicidir (yük,
# yavaş hedef); tek hatada yolu kalıcı kapatmak yük altında sessiz tespit kaybına yol açar.
# 2 = ilk deneme + 1 yeniden deneme; tavan dolunca kenar kalıcı kapanır (sonsuz döngü yok).
EDGE_MAX_RETRIES = max(1, int(os.getenv("AUTONOMOUS_EDGE_MAX_RETRIES", "2")))

# C1 (yol haritası §7-#4): beta-posterior backoff prior gücü (sözde-gözlem sayısı). Kenar
# hata verince success_prob'u ad-hoc "yarıya böl" yerine kanıt-sayaçlı Bayes ile düşürürüz:
# başlangıç success_prob'u bu güçte bir Beta(α,β) prior'a çevrilir, her hata β'yı 1 artırır,
# yeni success_prob = α/(α+β). Sonuç yarılamadan DAHA YUMUŞAK ve kanıt-temelli bir çürümedir
# (0.8 → 0.6 → 0.48; yarılama ise 0.8 → 0.4 → 0.2). Güç yüksek = prior'a daha sadık (yavaş
# çürüme); düşük = tek hataya daha duyarlı. Online öğrenmenin kenar-içi çekirdeği.
BETA_PRIOR_STRENGTH = max(0.5, float(os.getenv("EDGE_BETA_PRIOR_STRENGTH", "3.0")))

# Servis adı -> değer tablosu kategorisi eşlemesi
_SERVICE_VALUE_CATEGORY: Dict[str, str] = {
    "mysql": "database", "postgresql": "database", "mongodb": "database",
    "redis": "database", "elasticsearch": "database",
    "ssh": "remote-mgmt", "rdp": "remote-mgmt", "telnet": "remote-mgmt",
    "smb": "remote-mgmt",
    "tomcat": "admin-panel", "jboss": "admin-panel", "weblogic": "admin-panel",
    "apache": "web-app", "nginx": "web-app", "iis": "web-app",
    "spring": "web-app", "laravel": "web-app", "wordpress": "web-app",
    # APT servis-istihbaratı: mail/DNS/FTP yüzeyi (eskiden yalnız smtp/ftp→web-app,
    # geri kalanı hiç node almıyordu → CVE korelasyonu tetiklenmiyordu).
    "smtp": "mail-service", "exim": "mail-service", "postfix": "mail-service",
    "sendmail": "mail-service", "dovecot": "mail-service", "courier": "mail-service",
    "imap": "mail-service", "pop3": "mail-service", "submission": "mail-service",
    "smtps": "mail-service", "imaps": "mail-service", "pop3s": "mail-service",
    "dns": "dns-service", "domain": "dns-service", "powerdns": "dns-service",
    "bind": "dns-service", "named": "dns-service",
    "ftp": "network-service", "vsftpd": "network-service", "proftpd": "network-service",
    "pure-ftpd": "network-service", "openssh": "remote-mgmt",
    # K8s / konteyner altyapısı: nmap -sV 6443'te "ssl/kubernetes" raporlar → substring
    # eşleşmesi "kubernetes"i yakalar. Kontrol düzlemi = tüm kümenin anahtarı (en değerli).
    "kubernetes": "k8s-control-plane", "kubelet": "k8s-control-plane",
    "etcd": "k8s-control-plane", "rancher": "k8s-control-plane",
    "rke2": "k8s-control-plane", "k3s": "k8s-control-plane",
    "kube-proxy": "k8s-control-plane", "cadvisor": "k8s-control-plane",
}

# Bilinen port -> servis kategorisi (servis ADI tanınmadığında son çare). DEĞER SKORUNDAN
# kategori TAHMİN ETMEYİZ — skor "hedef çekiciliği"dir, servis türü değil.
_PORT_SERVICE_CATEGORY: Dict[int, str] = {
    3306: "database", 5432: "database", 27017: "database", 6379: "database",
    1433: "database", 1521: "database", 9200: "database", 5984: "database", 11211: "database",
    22: "remote-mgmt", 23: "remote-mgmt", 3389: "remote-mgmt", 445: "remote-mgmt", 5900: "remote-mgmt",
    80: "web-app", 443: "web-app", 8080: "web-app", 8443: "web-app", 8000: "web-app",
    8888: "web-app", 21: "web-app", 25: "web-app",
    # K8s kontrol düzlemi portları (servis ADI tanınmadığında son çare): apiserver 6443,
    # RKE2/Rancher supervisor 9345, kubelet 10250/10255, etcd 2379/2380, kube-proxy 10256,
    # controller-manager 10257, scheduler 10259, cAdvisor 4194.
    6443: "k8s-control-plane", 9345: "k8s-control-plane",
    10250: "k8s-control-plane", 10255: "k8s-control-plane",
    2379: "k8s-control-plane", 2380: "k8s-control-plane",
    10256: "k8s-control-plane", 10257: "k8s-control-plane",
    10259: "k8s-control-plane", 4194: "k8s-control-plane",
}

# Kategori -> (attention severity, insan-okunur gerekçe). Banka analisti önceliklendirsin.
_CATEGORY_ATTENTION: Dict[str, Tuple[str, str]] = {
    "database":             ("critical", "Veritabanı servisi — dışarı açık olmamalı"),
    "critical-cve-service": ("critical", "Bilinen kritik CVE'li servis"),
    "admin-panel":          ("high", "Yönetim paneli / admin arayüzü"),
    "remote-mgmt":          ("high", "Uzaktan yönetim servisi (SSH/RDP vb.)"),
    "auth-endpoint":        ("high", "Kimlik doğrulama uç noktası"),
    "api":                  ("medium", "API yüzeyi"),
    "web-app":              ("medium", "Web uygulaması / sunucusu"),
    "mail-service":         ("high", "Mail servisi (SMTP/IMAP/POP3) — user-enum/open-relay/sürüm-CVE"),
    "dns-service":          ("high", "DNS servisi — zone-transfer/cache-poison/sürüm-CVE"),
    "network-service":      ("medium", "Ağ servisi — sürüm-CVE için NVD'ye sorulmalı"),
    "k8s-control-plane":    ("critical", "Kubernetes kontrol düzlemi (apiserver/kubelet/etcd/Rancher) — İnternete açık olmamalı"),
}


def _service_attention(node) -> Tuple[str, str, str]:
    """Bir SERVICE düğümünü GERÇEK KİMLİĞİNE göre sınıfla → (kategori, severity, gerekçe).

    Kaynak sırası: servis adı (nmap 'service'/matched_service/label öneki) → ürün adı →
    bilinen port. Düğümün `value` skoruna ASLA bakmaz: skor "hedef çekiciliği"dir ve
    kategoriler arası ÇAKIŞIR (web-app boost'u database eşiğini geçince nginx "veritabanı"
    görünüyordu — kök neden buydu). Tanınmazsa nötr ('unknown', low)."""
    meta = node.meta or {}
    cand: List[str] = []
    for k in ("service", "matched_service", "product"):
        v = str(meta.get(k) or "").strip().lower()
        if v:
            cand.append(v)
    label = str(getattr(node, "label", "") or "")
    if "@" in label:
        pre = label.split("@", 1)[0].strip().lower()
        if pre:
            cand.append(pre)
    # 1) Tam eşleşme (ör. "nginx", "ssh", "mysql")
    for c in cand:
        cat = _SERVICE_VALUE_CATEGORY.get(c)
        if cat:
            sev, reason = _CATEGORY_ATTENTION[cat]
            return cat, sev, reason
    # 2) Alt-dize eşleşmesi (ör. "openssh"→ssh, "apache httpd"→apache, "microsoft-iis"→iis)
    for c in cand:
        for name, cat in _SERVICE_VALUE_CATEGORY.items():
            if name in c:
                sev, reason = _CATEGORY_ATTENTION[cat]
                return cat, sev, reason
    # 3) Bilinen port (servis adı hiç yoksa)
    port = meta.get("port")
    try:
        cat = _PORT_SERVICE_CATEGORY.get(int(port)) if port not in (None, "") else None
    except (TypeError, ValueError):
        cat = None
    if cat:
        sev, reason = _CATEGORY_ATTENTION[cat]
        return cat, sev, reason
    # 4) Tanınmadı — nötr düşük öncelik.
    return "unknown", "low", "Tespit edilen servis"


# Fuzz ile bulunan endpoint path pattern'leri -> değer
_ENDPOINT_VALUE_PATTERNS: List[Tuple[str, float]] = [
    ("admin", NODE_VALUE_TABLE["admin-panel"]),
    ("manager", NODE_VALUE_TABLE["admin-panel"]),
    ("login", NODE_VALUE_TABLE["auth-endpoint"]),
    ("auth", NODE_VALUE_TABLE["auth-endpoint"]),
    ("backup", 70),
    (".env", 70),
    (".git", 65),
    ("api", NODE_VALUE_TABLE["api"]),
    ("config", 60),
]

# L1 — enjeksiyon yüzeyi sınıfı → breach olasılığı (siege_score'u eşiğin üstüne taşıyan
# çarpan). query/path-param doğrudan enjeksiyon/IDOR hedefi (yüksek); api-route JSON/GraphQL
# gövde enjeksiyonu (biraz düşük ama statik 0.08'in çok üstünde → aktif test seçilir).
_INJECTION_BREACH_BY_KIND: Dict[str, float] = {
    "query": 0.25,
    "path-param": 0.25,
    "api-route": 0.18,
}


# ============================================================
# Node / Edge veri yapıları
# ============================================================

class NodeType(str, Enum):
    TARGET = "target"
    HOST = "host"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    FOOTHOLD = "foothold"
    # FAZ 1.3: yeni varlık tipleri. Grafta yalnız TEK yerde (integrate nuclei dalı)
    # NodeType.SERVICE/VULNERABILITY eşleşmesi var → bu yeni tipler eski akışta GÖRÜNMEZ
    # kalır (siege_score/expand_frontier default davranışla çalışır). Opt-in genişleme.
    ASN = "asn"                    # IP bloğu / sahiplik
    JS_ASSET = "js_asset"          # JavaScript'ten çıkan endpoint/secret
    GIT_REPO = "git_repo"          # exposed .git deposu


class NodeState(str, Enum):
    UNKNOWN = "unknown"
    DISCOVERED = "discovered"
    PROBED = "probed"
    BREACHED = "breached"
    EXHAUSTED = "exhausted"
    # Ölü-host karantinası: crawl/pathprobe 'host_unreachable' (80/443 yanıtsız)
    # döndürdüğünde keşfedilmiş host bu duruma düşer → frontier'den çıkarılır,
    # siege_score 0 verir, LLM hipotezi bile ona yeni kenar üretemez.
    DEAD = "dead"


@dataclass
class Node:
    id: str
    type: NodeType
    label: str
    value: float = DEFAULT_NODE_VALUE
    breach_prob: float = 0.05
    state: NodeState = NodeState.UNKNOWN
    evidence: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    from_id: str
    to_id: str
    tool: str
    options: Dict[str, Any] = field(default_factory=dict)
    cost: float = DEFAULT_EDGE_COST
    success_prob: float = 0.6
    rationale: str = ""
    novelty: float = 1.0
    urgency: float = 1.0
    state: str = "open"          # open | executed | exhausted | skipped_danger | skipped_dead
    tried_count: int = 0
    # C1 — beta-posterior backoff sayaçları. 0/0 = henüz tohumlanmadı; ilk hatada başlangıç
    # success_prob'tan BETA_PRIOR_STRENGTH gücünde seed edilir (bkz. update_probabilities).
    alpha: float = 0.0
    beta: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)

    def signature(self) -> str:
        """Memory.signature() ile birebir davranış — tekrar tespiti burada da geçerli."""
        key = json.dumps({k: v for k, v in self.options.items() if not k.startswith("_")}, sort_keys=True)
        return f"{self.tool}:{key}"

    def key(self) -> Tuple[str, str, str]:
        return (self.from_id, self.to_id, self.signature())


def siege_score(edge: Edge, graph: "Graph") -> float:
    """Doktrin §2 formülü. Kenar kapalıysa veya hedef node yoksa 0.

    Keşif araçları (RECON_TOOLS) hedefi henüz haritalanmamış saldırı yüzeyidir;
    bunlar için to_node'un (genelde root) gerçek value/breach_prob'u yerine sabit
    DISCOVERY_POTENTIAL_* kullanılır — aksi halde root'un düşük başlangıç değeri
    keşif adımlarını hiç seçilemez hale getirir (bkz doküman §0: "önce istihbarat")."""
    to_node = graph.nodes.get(edge.to_id)
    if to_node is None or edge.cost <= 0:
        return 0.0
    # Ölü-host karantinası: 80/443 yanıtsız olduğu KANITLANMIŞ host'a puan verme.
    # Gerçek vaka: reverse-IP co-hosted domain'ler crawl'da 'host_unreachable' döndü,
    # motor buna rağmen aynı hosta tekrar crawl + BOLA probu attı (hepsi 0 sonuç).
    # Ölü sura bütçe akmaz — kuşatma canlı sura döner.
    if to_node.state == NodeState.DEAD:
        return 0.0
    # Keşif araçlarının hedefi "henüz haritalanmamış yüzey"dir: bu yalnız root için değil,
    # YENİ keşfedilmiş (henüz problanmamış) her host için de geçerli — aksi halde bir
    # subdomain/co-hosted host'un düşük başlangıç değeri (static=10) recon kenarını eşiğin
    # altında bırakır ve host HİÇ taranmaz. "Önce istihbarat" ilkesi her sur için işler.
    is_discovery_edge = edge.tool in RECON_TOOLS and (
        edge.to_id == edge.from_id
        or (to_node.type == NodeType.HOST and to_node.state == NodeState.DISCOVERED)
    )
    if is_discovery_edge:
        value, breach_prob = DISCOVERY_POTENTIAL_VALUE, DISCOVERY_POTENTIAL_PROB
    else:
        value, breach_prob = to_node.value, to_node.breach_prob
    base = (value * breach_prob * edge.success_prob) / edge.cost
    # L2 — KEŞİF/MERAK: taze (DISCOVERED), henüz denenmemiş, enjeksiyon-hedefi bir
    # endpoint'e yönelen kenara tek seferlik "ilk bak" bonusu. ≥1.0 → hiçbir kenarı eşik
    # altına itmez; yalnız modern-yüzey hedeflerini ilk turda eşiğin üstüne taşır. Taze
    # SERVICE/CVE düğümlerini ETKİLEMEZ (koşul: injectable ENDPOINT).
    curiosity = 1.0
    if (CURIOSITY_EXPLORE and edge.tried_count == 0
            and to_node.type == NodeType.ENDPOINT
            and to_node.state == NodeState.DISCOVERED
            and to_node.meta.get("injectable")):
        curiosity = CURIOSITY_BONUS
    # OBJECTIVE-DRIVEN APT (Faz 2b): kill-chain'de daha derin faza (lateral/impact) yönelen
    # kenarlara ≥1.0 çarpan → motor zinciri KOVALAR. Çarpan asla <1.0 olmadığı için hiçbir
    # kenarı eşik altına itmez (mevcut ekonomi/davranış korunur, yalnız sıralama derinleşir).
    return base * edge.urgency * edge.novelty * graph._killchain_drive_boost(edge) * curiosity


def info_relevance(edge: Edge, graph: "Graph") -> float:
    """Bu kenarı KOŞMANIN 'ispata dönük beklenen marjinal bilgi kazanımı' (0..1, SAF).

    Yüksek = hedef henüz KANITLANMAMIŞ + aksiyon ispat verme olasılığı yüksek + daha önce
    denenmemiş → öğrenilecek/kanıtlanacak çok şey var. Düşük = ya hedef zaten breached (ispat
    elde), ya kenar defalarca denenip tükendi → yeni bilgi ~0.

    NOT (bilinçli tasarım): saf Shannon-entropisi (p=0.5'te tepe) KULLANILMAZ — çünkü hedef
    'ispat toplamak', 'yazı-tura sonucu öğrenmek' değil. Bu yüzden başarı OLASILIĞI ödüllenir
    (kanıtı gerçekten getirecek aksiyon), belirsizlik değil. 'Kanıtlanmamışlık' + 'azalan
    getiri' terimleri redundansı (zaten bildiğimizi tekrar örneklemeyi) eler."""
    to_node = graph.nodes.get(edge.to_id)
    if to_node is None:
        return 0.0
    unproven = _INFO_PROVEN_WEIGHT if to_node.state == NodeState.BREACHED else 1.0
    freshness = 1.0 / (1.0 + max(0, edge.tried_count))     # tekrar → azalan getiri
    yield_p = min(0.98, max(0.02, float(edge.success_prob)))  # ispatı getirme olasılığı
    return unproven * freshness * yield_p


def objective_score(edge: Edge, graph: "Graph") -> float:
    """Motorun aksiyon seçim HEDEFİ. INFO_GAIN kapalıysa = siege_score (davranış birebir).

    Açıkken siege_score'u bilgi-kazanımı çarpanıyla yeniden şekillendirir: 'en yüksek etkili'
    yerine 'ispata en çok bilgi kazandıran' aksiyonu öne çeker. Çarpan [_INFO_FLOOR.._INFO_CEIL]
    aralığına sıkışır → kanıtlanmış/tükenmiş kenarlar söner, taze-kanıtlanmamış kenarlar öne
    çıkar; ekonomi patlamaz. Karar hâlâ DETERMİNİSTİK ve SAF (LLM yok)."""
    base = siege_score(edge, graph)
    if not INFO_GAIN_OBJECTIVE or base <= 0:
        return base
    rel = info_relevance(edge, graph)                       # 0..1
    factor = _INFO_FLOOR + (_INFO_CEIL - _INFO_FLOOR) * rel
    return base * factor


# ============================================================
# A2 — KEŞİF/SÖMÜRÜ DENGESİ (UCB1 keşif terimi) — yol haritası §7-#1
# ============================================================
# Doktrin §4.3: motorun keşfi bugüne dek yalnız 'novelty' (aslında dedup maskesi) ve tek-
# seferlik 'curiosity' bonusuyla RASTLANTISAL sağlanıyordu; ilkeli bir keşif/sömürü dengesi
# yoktu → motor "hep en yüksek skorlu kenarı döv" eğiliminde, az-örneklenmiş yüzey kör kalıyor.
# UCB1: az-denenmiş kenara, denendikçe SÖNEN bir keşif bonusu ekle. Böylece motor erken turlarda
# az-örneklenmiş yüzeyi de yoklar; bonus azaldıkça yine ekonomiye (objective_score) teslim olur.
# Neden SEÇİM katmanında (objective_score içinde DEĞİL): objective_score SAF/deterministik kalsın
# (test_info_gain sözleşmesi + 'considered' raporu bozulmasın); UCB yalnız next_decision'ın
# sıralamasını etkiler. Neden sonsuz keşfe yol açmaz: INFO_GAIN doğal-durması info_relevance'a
# dayanır (UCB'den bağımsız) → tükenen kenarların ilgililiği yine INFO_GAIN_MIN altına iner, motor
# durur. Kapatmak: EXPLORE_UCB=0 → selection_score ≡ objective_score (davranış birebir).
EXPLORE_UCB = os.getenv("EXPLORE_UCB", "1") == "1"
# Keşif ağırlığı. Skorlar ~O(0.1–birkaç), eşik 0.15; c=0.12 → hiç-denenmemiş kenara ~0.13–0.19
# bonus (eşikle kıyaslanabilir, dominant değil). Büyütmek daha meraklı, küçültmek daha ekonomik.
EXPLORE_UCB_C = max(0.0, float(os.getenv("EXPLORE_UCB_C", "0.12")))


def explore_bonus(edge: Edge, total_attempts: int) -> float:
    """UCB1 keşif terimi (SAF, toplamsal). Az-denenmiş açık kenarda büyük, denendikçe söner.

    c·sqrt(ln(N+1) / (n_i+1)) — N=toplam adım (motorun step'i), n_i=kenarın denenme sayısı.
    n_i+1 yumuşatması: hiç-denenmemiş kenarda +sonsuz PATLAMAZ (sonlu, en büyük bonus). Yalnız
    AÇIK kenara uygulanır — kapalı/tükenmiş kenarın keşif değeri yoktur. EXPLORE_UCB kapalıysa 0."""
    if not EXPLORE_UCB or EXPLORE_UCB_C <= 0.0 or edge.state != "open":
        return 0.0
    n_i = max(0, edge.tried_count)
    n = max(1, int(total_attempts))
    return EXPLORE_UCB_C * math.sqrt(math.log(n + 1) / (n_i + 1))


def selection_score(edge: Edge, graph: "Graph", total_attempts: int) -> float:
    """Motorun GERÇEK sıralama skoru: objective_score + UCB keşif bonusu (A2). next_decision
    bunu kullanır; objective_score'un kendisi SAF/keşifsiz kalır (rapor/karşılaştırma tutarlı).
    EXPLORE_UCB kapalıyken selection_score ≡ objective_score (davranış birebir)."""
    return objective_score(edge, graph) + explore_bonus(edge, total_attempts)


# ============================================================
# Graph — motorun dünya modeli (Memory'nin yerini alır)
# ============================================================

class Graph:
    def __init__(self, target: str, target_is_ip: bool):
        self.target = target
        self.target_is_ip = target_is_ip
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str, str], Edge] = {}
        self.executed_signatures: Set[str] = set()
        self.evidence: List[Any] = []   # autonomous_engine.Evidence nesneleri
        # Bulgu parmak izi kümesi: aynı bulgu (aynı template/validator + kanonik URL)
        # birden fazla kenardan/adımdan düşse bile TEK kez kanıtlanır. Kurumsal raporda
        # aynı CVE'nin 5 kez listelenmesi güven kırar — dedup grafin tek otoritesinde.
        self._evidence_keys: Set[str] = set()
        self.notes: List[str] = []
        self._seeded = False

        root = Node(
            id=f"target:{target}", type=NodeType.TARGET, label=target,
            value=DEFAULT_NODE_VALUE, breach_prob=0.1, state=NodeState.DISCOVERED,
            meta={"is_ip": target_is_ip, "is_behind_cdn": False, "real_ip": None,
                  "technologies": [], "subdomains": [], "open_ports": [], "endpoints": []},
        )
        self.nodes[root.id] = root
        self.root_id = root.id

    # ---------- Node/Edge yönetimi ----------

    def add_evidence(self, ev: Any, fingerprint: str) -> bool:
        """Kanıtı dedup'lı ekle. fingerprint aynıysa (aynı template/validator + kanonik
        URL) ikinci kopya düşürülür. True = eklendi, False = mükerrer.

        NEDEN MERKEZİ: Mükerrer bulgu yalnız görsel gürültü değil — vulnerability_count,
        critical/high sayaçları ve 'decisive_breach' kararı bu listeye bakar. Dedup'ın
        tek otoritesi graf olmalı ki UI/rapor/skor aynı gerçeği görsün."""
        if fingerprint in self._evidence_keys:
            return False
        self._evidence_keys.add(fingerprint)
        self.evidence.append(ev)
        return True

    def merge_inference_with_proof(self, proof_ev: Any) -> bool:
        """SÜRÜM-CVE ÇİFTİNİ BİRLEŞTİR (FAQ 1.5).

        Aynı CVE için İKİ kayıt testi:
          - inference: `cve_intel|CVE|svc` / `kev_intel|CVE|svc` (NVD sürüm eşleşmesi; 'unconfirmed')
          - proof:     `nuclei|template|url` (template ATEŞLEDİ; ham istek/yanıt = en güçlü kanıt)
        Bağımsız fingerprint'ler yüzünden ikisi de `add_evidence`'tan geçip raporda ÇİFTE kayıt
        olarak kalıyordu. proof gelince inference kaydına ham kanıtı AŞILAR, kademesini
        'confirmed'a çeker ve bu nuclei kopyasını eklemez (çift sayma ölür). Değişken kanıt
        (FP sinyalli / ham req-resp'siz nuclei eşleşmesi) birleşmeye DEĞMEZ — o kendi kaydında
        kalır, inference kaydı dokunulmaz."""
        cve = getattr(proof_ev, "cve", None)
        if not cve or getattr(proof_ev, "fp_reason", None):
            return False
        for existing in self.evidence:
            if getattr(existing, "cve", None) != cve:
                continue
            if str(getattr(existing, "tool", "")) not in ("cve_intel", "kev_intel"):
                continue
            # Ham kanıt gerekli: 'template eşleşti' sürüm/banner'dan çıkarıldıysa birleşme
            # 'confirmed' yapmaz (yoksa aynı FP ikiye katlanır).
            if not (getattr(proof_ev, "request", None) or getattr(proof_ev, "response", None)):
                return False
            existing.request = getattr(proof_ev, "request", None) or existing.request
            existing.response = getattr(proof_ev, "response", None) or existing.response
            existing.curl = getattr(proof_ev, "curl", None) or existing.curl
            existing.extracted = (getattr(proof_ev, "extracted", None)
                                  or existing.extracted)
            existing.attack_techniques = list(dict.fromkeys(
                (existing.attack_techniques or []) + (getattr(proof_ev, "attack_techniques", None) or [])))
            existing.apt_groups = list(dict.fromkeys(
                (existing.apt_groups or []) + (getattr(proof_ev, "apt_groups", None) or [])))
            existing.confidence_tier = "confirmed"
            existing.verification_method = "nuclei-template"
            existing.verification_confidence = 0.95
            existing.verification_detail = (
                f"Nuclei template'i SÜRÜM-CVE'sini AKTİF doğruladı: "
                f"'{getattr(proof_ev, 'tool', 'nuclei')}' ham istek/yanıt yakalandı "
                f"({getattr(proof_ev, 'target', '')}). Unconfirmed 'inference' kaydı bununla "
                f"birleşti — çift kayıt kalktı, kademe confirmed'a yükseldi."
            )
            return True
        return False

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # merge: değer/olasılık en yüksek olanı kazanır, state ilerlerse güncellenir
        existing.value = max(existing.value, node.value)
        existing.breach_prob = max(existing.breach_prob, node.breach_prob)
        if node.state != NodeState.UNKNOWN:
            existing.state = node.state
        existing.meta.update({k: v for k, v in node.meta.items() if v})
        return existing

    def add_edge(self, edge: Edge) -> Edge:
        k = edge.key()
        existing = self.edges.get(k)
        if existing is not None:
            return existing
        self.edges[k] = edge
        return edge

    # ---------- Dinamik CVE istihbaratı ----------

    async def enrich_cve_intelligence(self) -> Dict[str, Any]:
        """
        Tespit edilmiş servis düğümleri için NVD üzerinden dinamik CVE eşleştirmesi yapar.
        Statik haritada bulunamayan servis+sürüm ikililerini NVD'ye sorar; dönen yüksek-
        öncelikli CVE'leri graf üzerinde zafiyet düğümü + hedefli nuclei doğrulama kenarı
        olarak ekler.

        KEV KATMANI (aktif-sömürü istihbaratı): NVD sonucu CISA KEV listesiyle çapraz
        kontrol edilir — listedeyse düğüm/kenar YÜKSELTİLİR (urgency, breach_prob,
        'kev' meta). Ayrıca sürümü bilinmeyen servisler için ürün-adı bazlı KEV taraması
        (_kev_product_sweep) çalışır: KEV'de sürüm aralığı yoktur ama "bu ürün sahada
        aktif sömürülüyor" sinyali hedefli nuclei doğrulamasını tetiklemeye yeter.

        DAYANIKLILIK: NVD ve/veya KEV erişilemezse sessizce kalan katmanla devam edilir.
        İkisi de yoksa statik harita yedek olarak kalır — motor regresyon yaşamaz.
        """
        cve_intel = _get_cve_intel()
        cve_enabled = bool(cve_intel and getattr(cve_intel, "CVE_INTEL_ENABLED", False))
        kev_intel = _get_kev_intel()
        kev_ready = False
        if kev_intel and getattr(kev_intel, "KEV_INTEL_ENABLED", False):
            try:
                kev_ready = await kev_intel.ensure_loaded()
            except Exception as e:
                # KEV düşse bile tarama devam etmeli — doktrin: danışman kral değil.
                logger.debug(f"KEV feed hazırlanamadı: {e}")

        if not cve_enabled and not kev_ready:
            return {"lookups": 0, "new_cves": 0, "new_edges": 0, "source": "disabled"}

        candidates = [
            (node_id, node) for node_id, node in self.nodes.items()
            if node.type == NodeType.SERVICE
            and node.meta.get("needs_cve_lookup") is True
            and node.meta.get("product")
            and node.meta.get("version")
        ]
        if not candidates and not kev_ready:
            return {"lookups": 0, "new_cves": 0, "new_edges": 0, "source": "none-needed"}

        new_cves = 0
        new_edges = 0
        lookups = 0
        kev_boosts = 0
        new_cve_ids: List[str] = []
        # Önce basit ürün/sürüm normalizasyonu ile tekrarları at.
        seen: Set[Tuple[str, str]] = set()

        async def _lookup_one(product: str, version: str, svc_node_id: str, matched_svc: str, port: Any):
            nonlocal new_cves, new_edges, lookups, kev_boosts
            key = (product.lower().strip(), version.lower().strip())
            if key in seen:
                return
            seen.add(key)
            lookups += 1
            try:
                hits = await cve_intel.lookup(product, version)
            except Exception as e:
                logger.debug(f"NVD lookup hatası ({product} {version}): {e}")
                return
            if not hits:
                return
            for hit in hits:
                cve_id = hit.cve_id
                # Aynı CVE zaten grafta varsa tekrar ekleme — ama KEV sinyali
                # sonradan geldiyse mevcut düğümü YÜKSELT (öncelik kaybolmasın).
                vuln_id = f"vuln:{cve_id}"
                existing = self.nodes.get(vuln_id)
                if existing is not None:
                    if kev_ready:
                        ke = kev_intel.is_kev(cve_id)
                        if ke and not existing.meta.get("kev"):
                            existing.meta["kev"] = True
                            existing.meta["kev_date_added"] = ke.date_added
                            existing.meta["kev_ransomware"] = ke.ransomware
                            existing.breach_prob = max(
                                existing.breach_prob, 0.95 if ke.ransomware else 0.85)
                            kev_boosts += 1
                    continue
                # KEV çapraz kontrolü: CVE 'aktif sömürülüyor' listesindeyse bu artık
                # TEORİK aday değil, sahada kullanılan bir silahtır → öncelik yükselir.
                kev_entry = kev_intel.is_kev(cve_id) if kev_ready else None
                breach = min(0.95, 0.5 + (hit.cvss_score / 20.0))
                if kev_entry:
                    breach = max(breach, 0.95 if kev_entry.ransomware else 0.85)
                    kev_boosts += 1
                meta = {
                    "cves": [cve_id], "service": matched_svc,
                    "cvss_score": hit.cvss_score, "severity": hit.severity,
                    "description": hit.description,
                    "source": "nvd", "product": product, "version": version,
                }
                if kev_entry:
                    meta["kev"] = True
                    meta["kev_date_added"] = kev_entry.date_added
                    meta["kev_ransomware"] = kev_entry.ransomware
                self.add_node(Node(
                    id=vuln_id, type=NodeType.VULNERABILITY, label=cve_id,
                    value=NODE_VALUE_TABLE["critical-cve-service"],
                    breach_prob=breach,
                    state=NodeState.DISCOVERED,
                    meta=meta,
                ))
                new_cves += 1
                new_cve_ids.append(cve_id)
                templates = cve_intel.cve_ids_to_nuclei_templates([cve_id])
                if templates:
                    urgency = 1.4
                    if kev_entry:
                        urgency = KEV_RANSOMWARE_URGENCY if kev_entry.ransomware else KEV_URGENCY
                    self.add_edge(Edge(
                        from_id=svc_node_id, to_id=vuln_id, tool="nuclei",
                        options={"templates": templates, "severity": ["critical", "high"]},
                        cost=EDGE_COST_TABLE["nuclei-targeted"], success_prob=0.82,
                        rationale=(f"{'KEV+NVD' if kev_entry else 'NVD'}: {matched_svc} "
                                   f"{version} -> {cve_id} ({hit.severity}, CVSS {hit.cvss_score})"
                                   f"{'. CISA KEV: AKTİF SÖMÜRÜLÜYOR — önce bunu kanıtla' if kev_entry else ''}"
                                   f". HEDEFLİ template ile KANITLA."),
                        urgency=urgency,
                    ))
                    new_edges += 1
                # GÖRÜNÜRLÜK (APT servis-istihbaratı): NVD eşleşmesini KANIT olarak da yaz.
                # Nuclei template'i olsun olmasın, sürüm-CVE eşleşmesi raporda GÖRÜNMELİ —
                # aksi halde (template yoksa) yalnız graf düğümü kalıp kullanıcı hiç görmüyordu
                # ("PowerDNS 4.9.16 → CVE-X" kayboluyordu). Kademe 'unconfirmed': aktif exploit
                # KANITI yok, sürümden çıkarıldı → manşeti şişirmez ama 'incelenmeli'de görünür.
                try:
                    from .autonomous_engine import Evidence as _CVEEvidence
                    tgt = f"{self.target}:{port}" if port not in (None, "") else self.target
                    kev_note = (
                        f" ⚠️ CISA KEV üyesi — sahada AKTİF SÖMÜRÜLÜYOR"
                        f"{' (fidye yazılımı kampanyasında kullanıldı)' if kev_entry.ransomware else ''}"
                        f", listeye giriş: {kev_entry.date_added}."
                    ) if kev_entry else ""
                    self.add_evidence(_CVEEvidence(
                        title=(f"{matched_svc} {version} — {cve_id} (sürümden çıkarıldı)"
                               f"{' [KEV: aktif sömürü]' if kev_entry else ''}"),
                        severity=(hit.severity or "medium").lower(), cve=cve_id, target=tgt,
                        proof=(f"NVD sürüm eşleşmesi: {matched_svc} {version} → {cve_id} "
                               f"(CVSS {hit.cvss_score}, {hit.severity}).{kev_note} "
                               f"{str(hit.description or '')[:200]} "
                               f"— hedef sistemde aktif istismar KANITI henüz yok; "
                               f"sürümden çıkarıldı, doğrulanmalı."),
                        tool="cve_intel", step=0,
                        cwe=[], cvss_v3=float(hit.cvss_score) if hit.cvss_score else None,
                        poc_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        # KADEME (FAQ 1.2/1.3): sürüm-CVE'si temel 'unconfirmed' — aktif teyit yok.
                        # AMA CISA KEV üyesiyse 'probable': sahada AKTİF sömürülüyor sinyali
                        # manşette 'incele'ye düşecek kadar zayıf değil. 'confirmed' DEĞİL —
                        # hedef sürümün etkilendiği hâlâ nuclei template teyidine bağlı.
                        confidence_tier=("probable" if kev_entry else "unconfirmed"),
                        # TRIAGE (FAQ 1.2c): sürüm-CVE'sinin doğrulama yolunu operatöre söyle.
                        # Template VARSA hedefli nuclei ateşlendi/geliyor; YOKSA "yamalı olabilir"
                        # etiketiyle manuel triyaja düşer.
                        verification_detail=(
                            "CISA KEV üyeliği: vahşi doğada AKTİF SÖMÜRÜLÜYOR — 'probable'a "
                            "yükseltildi; hedefli nuclei template'i sürüm teyidini yapacak."
                            if (kev_entry and templates) else
                            "Nuclei template'i mevcut değil — sürümden çıkarılmış/yamalı "
                            "olabilir; MANUEL doğrulanmalı (triage)."
                            if not templates else None
                        ),
                    ), f"cve_intel|{cve_id}|{matched_svc}")
                except Exception as _ee:
                    logger.debug(f"CVE kanıt yazımı atlandı ({cve_id}): {_ee}")

        tasks = []
        if cve_enabled:
            for node_id, node in candidates:
                prod = str(node.meta.get("product", "")).strip()
                ver = str(node.meta.get("version", "")).strip()
                matched_svc = node.meta.get("matched_service", "")
                # matched_service yoksa label'dan çıkar (label formatı "openssh@22")
                if not matched_svc:
                    matched_svc = node.label.split("@")[0].lower().strip()
                node.meta["needs_cve_lookup"] = False  # işareti kaldır (tekrar sorma)
                tasks.append(_lookup_one(prod, ver, node_id, matched_svc, node.meta.get("port")))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # KEV ÜRÜN TARAMASI — sürümü BİLİNMEYEN servisler dahil. NVD hunisi sürüm
        # ister; KEV yalnız ürün adıyla "bu yazılım sahada hedef" sinyali verir
        # (AI/agentic yığın çoğu zaman sürüm ifşa etmez — huni burada kurtarılır).
        kev_cves = 0
        if kev_ready:
            try:
                kc, ke = self._kev_product_sweep(kev_intel)
                kev_cves += kc
                new_edges += ke
                new_cves += kc
            except Exception as e:
                logger.debug(f"KEV ürün taraması atlandı: {e}")

        # EPSS ZENGİNLEŞTİRME — KEV'de olmayan ama sömürü OLASILIĞI yüksek CVE'ler
        # "sıcak" işaretlenir: teorik-CVSS gürültüsü saha olasılığıyla dengelenir.
        epss_hot = 0
        if kev_ready and new_cve_ids:
            try:
                scores = await kev_intel.epss_scores(new_cve_ids[:60])
            except Exception as e:
                logger.debug(f"EPSS zenginleştirme atlandı: {e}")
                scores = {}
            for cid, sc in (scores or {}).items():
                node = self.nodes.get(f"vuln:{cid}")
                if node is None:
                    continue
                node.meta["epss"] = round(sc, 4)
                if sc >= EPSS_HOT_THRESHOLD and not node.meta.get("kev"):
                    epss_hot += 1
                    node.meta["epss_hot"] = True
                    node.breach_prob = max(node.breach_prob, min(0.9, 0.55 + sc / 2.0))
                    for e in self.edges.values():
                        if e.to_id == node.id and e.tool == "nuclei":
                            e.urgency = max(e.urgency, 1.8)
                    # FAQ 1.3: EPSS sıcaklığı sadece graf düğümünü değil, RAPOR KADEMESİNİ
                    # de etkilesin — aktifi sömürülme olasılığı yüksek sürüm-CVE'si manşette
                    # 'unconfirmed/incele'ye düşmesin. Yalnız inference kayıtlarına yansıt
                    # (kademe değiştir; verifier/LLM doktirinini bozma).
                    for _ev in self.evidence:
                        if (getattr(_ev, "cve", None) == cid
                                and getattr(_ev, "tool", "") in ("cve_intel", "kev_intel")
                                and _ev.effective_confidence_tier() == "unconfirmed"):
                            _kev_flag = bool(getattr(self.nodes.get(f"vuln:{cid}"),
                                                     "meta", {}).get("kev"))
                            _ev.confidence_tier = "probable"
                            _ev.verification_detail = (
                                f"EPSS={sc:.3f} (≥{EPSS_HOT_THRESHOLD}) — sömürülme olasılığı "
                                f"yüksek; 'probable'a yükseltildi."
                                + (" KEV'de aktif sömürü listesinde."
                                   if _kev_flag else ""))
                            break

        return {
            "lookups": lookups,
            "new_cves": new_cves,
            "new_edges": new_edges,
            "kev_cves": kev_cves,
            "kev_boosts": kev_boosts,
            "epss_hot": epss_hot,
            "source": "nvd+kev" if kev_ready else "nvd",
        }

    def _kev_product_sweep(self, kev_intel) -> Tuple[int, int]:
        """Servis düğümlerinin ürün adlarını CISA KEV indeksine sor; eşleşen her
        CVE için zafiyet düğümü + HEDEFLİ nuclei kenarı seed et.

        NEDEN ayrı geçiş: enrich'in NVD ayağı sürüm gerektirir (needs_cve_lookup
        yalnız product+version varken işaretlenir). Langflow/n8n/Metabase sınıfı
        yeni yığınlar çoğu zaman sürüm ifşa ETMEZ — ama KEV 'bu ürün aktif
        sömürülüyor' der. Sürüm teyidi hedefli nuclei template'ine devredilir
        (KEV CVE'lerinin neredeyse tamamının template'i vardır).

        Döner: (yeni CVE düğümü sayısı, yeni kenar sayısı). Dedup: ürün başına
        bir kez (graf ömrü); CVE başına vuln düğümü varlığı."""
        swept: Set[str] = getattr(self, "_kev_swept_products", None) or set()
        self._kev_swept_products = swept

        # ürün -> (node_id, matched_svc, port, version) — ilk gören kazanır
        products: Dict[str, Tuple[str, str, Any, str]] = {}
        for node_id, node in self.nodes.items():
            if node.type != NodeType.SERVICE:
                continue
            prod = str(node.meta.get("product", "")).strip()
            if not prod:
                continue
            pkey = prod.lower()
            if pkey in products:
                continue
            matched_svc = node.meta.get("matched_service", "") or \
                node.label.split("@")[0].lower().strip()
            products[pkey] = (node_id, matched_svc, node.meta.get("port"),
                              str(node.meta.get("version", "")).strip())

        new_cves = 0
        new_edges = 0
        for prod, (svc_node_id, matched_svc, port, version) in products.items():
            if prod in swept:
                continue
            swept.add(prod)
            try:
                entries = kev_intel.lookup_product(prod)
            except Exception as e:
                logger.debug(f"KEV ürün sorgusu hatası ({prod}): {e}")
                continue
            if not entries:
                continue
            # Ürün başına tavan: 'windows' gibi yüzlerce KEV kaydı olan ürünlerde
            # graf şişmesin — en TAZE eklenenler öncelikli (saldırgan gündemi).
            for entry in entries[:KEV_MAX_PER_PRODUCT]:
                cve_id = entry.cve_id
                vuln_id = f"vuln:{cve_id}"
                existing = self.nodes.get(vuln_id)
                if existing is not None:
                    # NVD ayağı eklediyse KEV bayraklarını yükselt (sinyal kaybolmasın).
                    if not existing.meta.get("kev"):
                        existing.meta["kev"] = True
                        existing.meta["kev_date_added"] = entry.date_added
                        existing.meta["kev_ransomware"] = entry.ransomware
                        existing.breach_prob = max(
                            existing.breach_prob, 0.95 if entry.ransomware else 0.85)
                        for e in self.edges.values():
                            if e.to_id == vuln_id and e.tool == "nuclei":
                                e.urgency = max(
                                    e.urgency,
                                    KEV_RANSOMWARE_URGENCY if entry.ransomware else KEV_URGENCY)
                    continue
                self.add_node(Node(
                    id=vuln_id, type=NodeType.VULNERABILITY, label=cve_id,
                    value=NODE_VALUE_TABLE["critical-cve-service"],
                    breach_prob=0.95 if entry.ransomware else 0.85,
                    state=NodeState.DISCOVERED,
                    meta={
                        "cves": [cve_id], "service": matched_svc, "severity": "high",
                        "source": "kev", "product": prod, "version": version,
                        "description": entry.name, "kev": True,
                        "kev_date_added": entry.date_added,
                        "kev_ransomware": entry.ransomware,
                    },
                ))
                new_cves += 1
                cve_intel = _get_cve_intel()
                templates = cve_intel.cve_ids_to_nuclei_templates([cve_id]) if cve_intel \
                    else [cve_id.lower()]
                self.add_edge(Edge(
                    from_id=svc_node_id, to_id=vuln_id, tool="nuclei",
                    options={"templates": templates, "severity": ["critical", "high"]},
                    cost=EDGE_COST_TABLE["nuclei-targeted"], success_prob=0.82,
                    rationale=(f"CISA KEV: {matched_svc} ürünü '{entry.name}' ile AKTİF "
                               f"SÖMÜRÜLÜYOR (listeye giriş {entry.date_added}"
                               f"{', fidye yazılımı kampanyası' if entry.ransomware else ''}). "
                               f"KEV'de sürüm aralığı yok — HEDEFLİ template sürüm teyidini yapar."),
                    urgency=KEV_RANSOMWARE_URGENCY if entry.ransomware else KEV_URGENCY,
                    meta={"kev": True},
                ))
                new_edges += 1
                # GÖRÜNÜRLÜK: KEV sinyali raporda görünmeli — 'unconfirmed' kademesiyle
                # (aktif istismar KANITI yok; ürün eşleşmesi + sömürü gündemi var).
                try:
                    from .autonomous_engine import Evidence as _KEVEvidence
                    tgt = f"{self.target}:{port}" if port not in (None, "") else self.target
                    self.add_evidence(_KEVEvidence(
                        title=f"{matched_svc} — {cve_id} [CISA KEV: aktif sömürü]",
                        severity="high", cve=cve_id, target=tgt,
                        proof=(f"CISA KEV kaydı: {entry.vendor} {entry.product} — {entry.name}. "
                               f"Bu CVE vahşi doğada AKTİF sömürülüyor (KEV'e giriş: "
                               f"{entry.date_added}, yama süresi: {entry.due_date or 'bilinmiyor'}"
                               f"{'; fidye yazılımı kampanyasında kullanıldı' if entry.ransomware else ''}). "
                               f"KEV sürüm aralığı taşımaz; hedefteki sürümün etkilendiği "
                               f"hedefli nuclei template'i ile doğrulanacak."),
                        tool="kev_intel", step=0, cwe=[], cvss_v3=None,
                        poc_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        # KADEME (FAQ 1.3): CISA KEV üyeliği başlı başına güçlü saha sinyalidir —
                        # 'unconfirmed' yerine en az 'probable' (aktif sömürü gündeminde).
                        # 'confirmed' DEĞİL: hedefteki sürümün etkilendiği hâlâ nuclei teyidine bağlı.
                        confidence_tier="probable",
                        verification_detail=(
                            "CISA KEV: ürün vahşi doğada AKTİF SÖMÜRÜLÜYOR — 'probable'a "
                            "yükseltildi; hedefli nuclei template'i sürüm teyidini yapacak."
                            if templates else
                            "Nuclei template'i mevcut değil — sürümden çıkarılmış/yamalı "
                            "olabilir; MANUEL doğrulanmalı (triage)."
                        ),
                    ), f"kev_intel|{cve_id}|{matched_svc}")
                except Exception as _ee:
                    logger.debug(f"KEV kanıt yazımı atlandı ({cve_id}): {_ee}")
        if new_cves:
            logger.info(f"🛰️  KEV ürün taraması: {new_cves} aktif-sömürü CVE'si grafa eklendi.")
        return new_cves, new_edges

    # ---------- Frontier / seed ----------

    # "RAID" doktrini: pathprobe (.env/.git/yedek/config ifşası) HEDEFİN DEĞERİNDEN BAĞIMSIZ,
    # ucuz ve KESİN bir kazançtır. Kuşatma skoru "en değerli suru" kovalar; ama .env sınıfı
    # açık düşük-değerli görünen (static=10) host'larda durur ve tam bu yüzden kaçardı
    # ("başkası buldu"). Bu yüzden pathprobe recon'un BAŞARISINA değil, bir HOST'un VARLIĞINA
    # bağlanır: host doğduğu an garantili, eşik-üstü bir raid kenarı seed edilir. urgency
    # yüksek tutulur ki bütçe dolmadan MUTLAKA sıraya gelsin (skor: 60*0.5*0.7/10 *2.5 ≈ 5.25).
    RAID_URGENCY = 2.5

    def _seed_pathprobe_raid(self, host_id: str, scan_target: Optional[str], label: str,
                             tech_hints: Optional[List[str]] = None) -> bool:
        """Bir host'a KOŞULSUZ pathprobe raid kenarı seed et. Dedup: aynı host+target için
        bir kez. Döner: yeni kenar eklendiyse True. host'un değerinden bağımsızdır —
        siege_score pathprobe'u RECON_TOOLS/DISCOVERY_POTENTIAL ile puanlar, raid urgency
        ile eşiğin çok üstünde kalır → her host mutlaka .env/.git için problanır.
        tech_hints: recon'un tespit ettiği teknolojiler → framework-özel yollar (dinamik
        katalog genişletme; prober tarafında _paths_for_tech ile ek yol üretir)."""
        options: Dict[str, Any] = {}
        if scan_target and scan_target != self.target:
            options["scan_target"] = scan_target
        if tech_hints:
            # İlk 6 teknoloji yeter; signature'a dahil olur — tech_hints DEĞİŞİNCE yeni raid
            # YASALDIR ve GEREKLİDİR: _paths_for_tech kataloğa framework-özel yollar ekler
            # (wordpress → /wp-content/uploads/, /wp-json/wp/v2/users...). Kök raid recon'dan
            # ÖNCE hints'siz çalışır; recon teknoloji tespit edince hints'li ikinci raid
            # WP-özel yolları problar — bulguların çoğu bu ikinci geçişten gelir. Bu yüzden
            # dedup HOST-seviyesinde DEĞİL, signature (= yol kataloğu) seviyesindedir;
            # host-seviyesi dedup denemesi gerçek bulguları kaybettirdi (regresyon).
            options["tech_hints"] = list(dict.fromkeys(str(t).lower() for t in tech_hints))[:6]
        sig = Edge(from_id=host_id, to_id=host_id, tool="pathprobe", options=options).signature()
        # Aynı signature zaten çalıştıysa veya açık kenar varsa tekrar ekleme.
        if sig in self.executed_signatures:
            return False
        for e in self.edges.values():
            if e.tool == "pathprobe" and e.signature() == sig and e.state in ("open", "executed"):
                return False
        new_edge = Edge(
            from_id=host_id, to_id=host_id, tool="pathprobe", options=options,
            cost=EDGE_COST_TABLE["pathprobe"], success_prob=0.7, urgency=self.RAID_URGENCY,
            rationale=f"RAID: {label} — açık .env/.git/yedek/config ifşası deterministik "
                      f"probla doğrulanır. Hedefin değerinden bağımsız garantili tarama "
                      f"(en sık kaçan 'basit ama ölümcül' bulgu sınıfı).",
            meta={"raid": True},
        )
        return self.add_edge(new_edge) is new_edge

    def _pivot_from_sensitive_findings(self, pp_findings: List[Dict[str, Any]]) -> List["Node"]:
        """Açık .env/config bulgularındaki pivot_hints'ten yeni saldırı yüzeyi doğur.

        - iç host (DB_HOST vb.): yeni HOST node + kademeli nmap ilk-temas + pathprobe raid.
          NOT: bu iç hostlar genelde özel IP (10./172./192.168.) olabilir — dışarıdan
          erişilemezler ama origin/aynı-segment senaryosunda değerlidir; scope guard'ı
          autonomous_engine tarafında yine geçerli (yeni host root'tan seed edilir).
        - alt-uygulama URL'i (APP_URL): o path tabanında ek pathprobe (uygulama '/app'
          altındaysa '.env' kökte değil orada olabilir — Delik 5'in çözümü).
        - bucket: yalnız not (açık depolama sinyali; aktif S3 aracı yoksa raporlanır).
        Hepsi dedup'lı; graf şişmesin diye her sınıf sınırlı."""
        out: List[Node] = []
        seen_hosts: Set[str] = set()
        for f in pp_findings:
            if not isinstance(f, dict):
                continue
            hints = f.get("pivot_hints") or {}
            if not isinstance(hints, dict):
                continue
            # 1) İç altyapı hostları → yeni host node + ilk-temas nmap + raid pathprobe
            for h in (hints.get("hosts") or [])[:8]:
                if not h or h in seen_hosts:
                    continue
                seen_hosts.add(h)
                node_id = f"host:internal:{h}"
                if node_id in self.nodes:
                    continue
                host_node = self.add_node(Node(
                    id=node_id, type=NodeType.HOST, label=h,
                    value=NODE_VALUE_TABLE["database"] * 0.6,  # iç DB/servis → değerli ama erişim belirsiz
                    breach_prob=0.2, state=NodeState.DISCOVERED,
                    meta={"source": "env_pivot", "discovered_via": "sensitive_file",
                          "internal": True, "from_finding": f.get("url")},
                ))
                out.append(host_node)
                # Kademeli ilk temas — iç host erişilebilir mi + hangi servis?
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=node_id, tool="nmap",
                    options={"--top-ports": 100, "-sV": True, "scan_type": ["-sS", "-sV"],
                             "stage": "first-contact", "scan_target": h},
                    cost=EDGE_COST_TABLE["nmap-top100"], success_prob=0.6, urgency=1.4,
                    rationale=f"ZİNCİR: açık {f.get('path')} ifşasında iç altyapı host'u '{h}' "
                              f"görüldü — erişilebilir mi ve hangi servis çalışıyor? Kademeli "
                              f"ilk temas (doktrin: ifşadan pivot).",
                    meta={"from_pivot": True},
                ))
                self._seed_pathprobe_raid(node_id, h, f"iç host {h} (.env pivot)")
            # 2) Alt-uygulama URL tabanı → o path'te ek pathprobe (kökte değil app tabanında .env)
            for u in (hints.get("urls") or [])[:5]:
                base = _url_path_base(u)
                if not base:
                    continue
                # Aynı hedefte ama farklı taban → scan_target'a path ekli özel prob.
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=self.root_id, tool="pathprobe",
                    options={"path_base": base},
                    cost=EDGE_COST_TABLE["pathprobe"], success_prob=0.6, urgency=self.RAID_URGENCY,
                    rationale=f"ZİNCİR: {f.get('path')} içinde uygulama tabanı '{base}' görüldü "
                              f"— .env/config kökte değil bu alt-tabanda olabilir, orada da prob.",
                    meta={"from_pivot": True},
                ))
            # 3) Açık bucket → not (aktif S3 aracı yok; raporlanır, analist bakar)
            for b in (hints.get("buckets") or [])[:5]:
                self.notes.append(
                    f"[pivot] Açık depolama adayı: '{b}' ({f.get('path')} ifşasından) — "
                    f"public erişim manuel doğrulanmalı (veri sızıntısı riski)."
                )
        return out

    def _seed_initial_edges(self):
        """İlk tur: hedefi tanı. Mevcut _forced_next_step'in graf-native karşılığı."""
        # RAID: kök hedefe pathprobe'u İLK TURDA, recon'a bağımlı OLMADAN seed et. Recon
        # timeout/fail olsa (veya teknoloji tespit edemese) bile .env/.git kaçmaz — bu,
        # "pathprobe recon başarısına bağlıydı" kök nedenini kapatan asıl düzeltmedir.
        self._seed_pathprobe_raid(self.root_id, None, f"kök hedef {self.target}")
        if self.target_is_ip:
            # NOT: IP hedefte recon kenarı SEED EDİLMEZ — dispatcher recon'u DOMAIN_ONLY
            # sayar ve %100 skip'ler; seed'lemek motorun adım bütçesinden çalan, UI'da
            # "recon → skipped" gürültüsü üreten ölü kenardı. Parmak izi görevini IP
            # hedefte zaten nmap (-sV servis/versiyon) üstlenir.
            # Kuşatma Doktrini: IP'de barınan TÜM domain'leri keşfet — surdaki gizli kapılar.
            self.add_edge(Edge(
                from_id=self.root_id, to_id=self.root_id, tool="reverse_ip",
                cost=EDGE_COST_TABLE["reverse_ip"], success_prob=0.85,
                rationale="Bu IP'de başka hangi domain'ler barınıyor? "
                          "Ana domain temiz, unutulmuş yan domain savunmasız olabilir — "
                          "doktrinin 'en zayıf sur' prensibi.",
            ))
            # Kademeli ilk temas: doğrudan IP hedefinde ucuz top-100 port tarama.
            self.add_edge(Edge(
                from_id=self.root_id, to_id=self.root_id, tool="nmap",
                options={"--top-ports": 100, "-sV": True, "scan_type": ["-sS", "-sV"], "stage": "first-contact"},
                cost=EDGE_COST_TABLE["nmap-top100"], success_prob=0.85,
                rationale="Kademeli ilk temas: en yaygın 100 port. -p- değil — "
                          "değer kanıtlanınca derinleşilir.",
            ))
        else:
            self.add_edge(Edge(
                from_id=self.root_id, to_id=self.root_id, tool="recon",
                cost=EDGE_COST_TABLE["recon"], success_prob=0.95,
                rationale="İlk adım: domain'i parmak izle (CDN/WAF/teknoloji tespiti).",
            ))
            self.add_edge(Edge(
                from_id=self.root_id, to_id=self.root_id, tool="subfinder",
                cost=EDGE_COST_TABLE["subfinder"], success_prob=0.8,
                rationale="Saldırı yüzeyini genişlet: subdomain keşfi.",
            ))
        self._seeded = True

    def expand_frontier(self) -> List[Edge]:
        """Uygulanabilir tüm açık kenarları döner. İlk turda seed atar."""
        if not self._seeded:
            self._seed_initial_edges()

        root = self.nodes[self.root_id]
        open_edges = [
            e for e in self.edges.values()
            if e.state == "open" and e.signature() not in self.executed_signatures
        ]

        # CDN arkasında ve gerçek IP yoksa: origin_discovery ŞART, port taramaları kapansın
        is_behind_cdn = root.meta.get("is_behind_cdn", False)
        real_ip = root.meta.get("real_ip")
        if is_behind_cdn and not real_ip:
            sig = Edge(from_id=self.root_id, to_id=self.root_id, tool="origin_discovery").signature()
            if sig not in self.executed_signatures and not any(
                e.tool == "origin_discovery" for e in open_edges
            ):
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=self.root_id, tool="origin_discovery",
                    cost=EDGE_COST_TABLE["origin_discovery"], success_prob=0.7,
                    rationale="Hedef CDN/Cloudflare arkasında. Gerçek IP bulunmadan port "
                              "taraması sadece CDN'i tarar — anlamsız. Önce origin IP keşfi.",
                ))
            open_edges = [
                e for e in open_edges
                if not (e.tool in ("nmap", "rustscan") and is_behind_cdn and not real_ip)
            ]

        return [
            e for e in self.edges.values()
            if e.state == "open" and e.signature() not in self.executed_signatures
            and not (e.tool in ("nmap", "rustscan") and is_behind_cdn and not real_ip)
            # Ölü-host karantinası: DEAD işaretli node'a giden kenarlar frontier'de yok.
            # (mark_dead açık kenarları zaten 'skipped_dead' yapar; bu satır, ölümden
            # SONRA doğan yeni kenarlar için emniyet kemeri.)
            and not (self.nodes.get(e.to_id) is not None
                     and self.nodes[e.to_id].state == NodeState.DEAD)
        ]

    # ---------- Ölü-host karantinası ----------

    def find_host_node(self, host_label: str) -> Optional[Node]:
        """Label'ı eşleşen host/servis/endpoint node'unu bul (canlılık kapısı için)."""
        canon = _canon_host(host_label or "")
        if not canon:
            return None
        for n in self.nodes.values():
            if n.type in (NodeType.HOST, NodeType.SERVICE, NodeType.ENDPOINT) \
                    and _canon_host(n.label) == canon:
                return n
        return None

    def is_dead(self, host_label: str) -> bool:
        """Bu host ölü olarak karantinada mı? (dispatch öncesi canlılık kapısı)"""
        node = self.find_host_node(host_label)
        return bool(node and node.state == NodeState.DEAD)

    def mark_dead(self, host_label: str, reason: str = "") -> bool:
        """Keşfedilmiş host'u ÖLÜ işaretle (host_unreachable kanıtında çağrılır).

        Yapdığı iş: node.state=DEAD + ona yönelen TÜM açık kenarlar 'skipped_dead'
        olur + siege_score artık 0 verir + _validate ölü hedefli kararları reddeder.
        Kök hedef hariç (kök 'down' ayrı mekanizma: dürüst-tarama erken kesme).
        Döner: YENİ işaretlendiyse True (idempotent — tekrar çağrı False)."""
        node = self.find_host_node(host_label)
        if node is None or node.id == self.root_id:
            return False
        if node.state == NodeState.DEAD:
            return False
        node.state = NodeState.DEAD
        node.meta["dead_reason"] = reason or "host_unreachable"
        closed = 0
        for e in self.edges.values():
            if e.to_id == node.id and e.state == "open":
                e.state = "skipped_dead"
                closed += 1
        self.notes.append(
            f"☠️ {node.label} ÖLÜ işaretlendi ({reason or 'host_unreachable'}) — "
            f"{closed} kenar frontier'den düşürüldü.")
        return True

    # ---------- LLM appraisal uygulama ----------

    def apply_intel(self, intel: Dict[str, Any]):
        """Doküman §3 şeması: node_values, likely_vuln_classes, suggested_edges, narration."""
        node_values = intel.get("node_values") or {}
        for node_id, val in node_values.items():
            node = self.nodes.get(node_id)
            if node is not None and isinstance(val, (int, float)):
                # LLM node değerini ±20 ayarlayabilir, mutlak sınırlar 0..100
                node.value = max(0.0, min(100.0, float(val)))

        for suggestion in (intel.get("suggested_edges") or []):
            if not isinstance(suggestion, dict):
                continue
            tool = suggestion.get("tool")
            if not tool:
                continue
            # LLM ÖNERİ SPAM SINIRI: aynı araç için graf ömrü boyunca en fazla 2 LLM
            # kenarı. Önceden LLM her turda aynı aracı farklı gerekçe/tag ile tekrar
            # önerebiliyordu (örnek vaka: 7 tur içinde 5x "nuclei ile CVE tara" — hepsi
            # ayrı signature, hepsi çalıştı, hepsi aynı bulguyu döndürdü). İlk iki öneri
            # sezgidir; sonrası tekrar eden gürültüdür — kural motoru zaten kapsıyor.
            llm_edges_for_tool = sum(
                1 for e in self.edges.values()
                if e.tool == tool and e.meta.get("from_llm")
            )
            if llm_edges_for_tool >= 2:
                continue
            why = suggestion.get("why", "Ollama önerisi")
            target_id = suggestion.get("target_node", self.root_id)
            if target_id not in self.nodes:
                target_id = self.root_id
            cost = EDGE_COST_TABLE.get(tool, DEFAULT_EDGE_COST)
            self.add_edge(Edge(
                from_id=self.root_id, to_id=target_id, tool=tool,
                options={"tags": suggestion.get("tags")} if suggestion.get("tags") else {},
                cost=cost, success_prob=0.5, rationale=why,
                meta={"from_llm": True},
            ))

        # LLM'in zafiyet-sınıfı sezgisini HEDEFLİ nuclei tag taramasına çevir (1.2 köprüsü).
        # Eskiden yalnız parse edilip kullanılmıyordu; artık istihbarat karara katkı sağlar.
        vuln_tags: List[str] = []
        for cls in (intel.get("likely_vuln_classes") or []):
            for tag in VULN_CLASS_TO_NUCLEI_TAGS.get(str(cls).strip().lower(), []):
                if tag not in vuln_tags:
                    vuln_tags.append(tag)
        if vuln_tags:
            self.add_edge(Edge(
                from_id=self.root_id, to_id=self.root_id, tool="nuclei",
                options={"tags": vuln_tags, "severity": list(DEFAULT_SEVERITY)},
                cost=EDGE_COST_TABLE["nuclei-targeted"], success_prob=0.5,
                rationale=f"İstihbarat subayı (LLM) olası zafiyet sınıfları önerdi → "
                          f"hedefli nuclei tag taraması: {', '.join(vuln_tags)}.",
                meta={"from_llm": True},
            ))

    # ---------- Web/API aktif zafiyet testi (DAST) kenarı doğur (madde 3) ----------

    def _seed_web_dast_edge(self, host_id: str, label: str, rationale: str,
                            scan_target: Optional[str] = None):
        """Bir web-app düğümü için TEK bir DAST (nuclei -dast) kenarı doğurur.

        DAST parametre tabanlı enjeksiyon sınıflarını (xss/sqli/ssrf/lfi/cmdi...) CANLI
        tetikleyerek dener — altyapı CVE taramasının kör kaldığı uygulama katmanı budur.
        Agresiftir; otonom motor bunu yalnız 'deep'/allow_fuzz seviyesinde SEÇER (bkz
        autonomous_engine seviye filtresi).

        DEDUP: dispatcher DAST'ı düğüm başına değil daima `self.target`'a çalıştırır; ayrıca
        DAST kenarlarının hepsi aynı signature'ı ('nuclei:{dast,severity}') paylaşır — ilki
        çalışınca executed_signatures onları evrensel olarak kapatır. Bu yüzden host'tan
        BAĞIMSIZ olarak TEK DAST kenarı tutulur; ikinci bir web-app bulunsa da yeni kenar
        eklenmez (guard bunu signature üzerinden dürüstçe ifade eder)."""
        options = {"dast": True, "severity": list(DEFAULT_SEVERITY)}
        if scan_target and scan_target != self.target:
            options["scan_target"] = scan_target
        sig = Edge(from_id=host_id, to_id=host_id, tool="nuclei", options=options).signature()
        if sig in self.executed_signatures:
            return
        if any(e.tool == "nuclei" and e.options.get("dast") for e in self.edges.values()):
            return
        self.add_edge(Edge(
            from_id=host_id, to_id=host_id, tool="nuclei", options=options,
            cost=EDGE_COST_TABLE["nuclei-dast"], success_prob=0.5,
            rationale=rationale, urgency=1.1,
            meta={"dast": True},
        ))

    def _seed_web_cve_sweep_edge(self, host_id: str, scan_target: Optional[str] = None):
        """GÜVENLİK AĞI: doğrulanmış bir web uygulamasına GENİŞ critical/high CVE taraması.

        Motorun 'sadece bilinen servis tag'i' kuralı, tablodaki ~servis dışındaki modern
        framework'lere (Next.js, Node, Django...) KÖR kalıyordu — nuclei o CVE için template'e
        sahip olsa bile hiç çalışmıyordu. Bu kenar, tag KISITI OLMADAN yalnız severity
        (critical/high) filtresiyle TÜM ilgili CVE template'lerini çalıştırır → örn. Next.js
        CVE-2025-29927 gibi kritik açıkları yakalar.

        Agresiftir (çok template) → DAST gibi yalnız 'deep'/allow_fuzz seviyede SEÇİLİR
        (autonomous_engine gate). Gürültüyü sınırlamak için rate_limit düşürülür (stealth).
        DEDUP: DAST ile aynı mantık — host'tan bağımsız TEK süpürme kenarı yeter."""
        options = {"cve_sweep": True, "severity": ["critical", "high"], "rate_limit": 100}
        if scan_target and scan_target != self.target:
            options["scan_target"] = scan_target
        sig = Edge(from_id=host_id, to_id=host_id, tool="nuclei", options=options).signature()
        if sig in self.executed_signatures:
            return
        if any(e.tool == "nuclei" and e.options.get("cve_sweep") for e in self.edges.values()):
            return
        self.add_edge(Edge(
            from_id=host_id, to_id=host_id, tool="nuclei", options=options,
            cost=EDGE_COST_TABLE["nuclei-broad"], success_prob=0.4,
            rationale="Doğrulanmış web uygulaması — GENİŞ critical/high CVE süpürmesi (güvenlik "
                      "ağı): tespit edilemeyen framework'lerin (Next.js/Node/...) kritik açıkları "
                      "da yakalanır. Tag kısıtı yok, yalnız severity filtresi.",
            urgency=1.0, meta={"cve_sweep": True},
        ))

    # ---------- Tool sonucunu graf mutasyonuna çevir ----------

    def integrate(self, decision, result_data: Dict[str, Any], tool: str) -> List[Node]:
        """En kritik fonksiyon: her aracın FARKLI result.data şemasını node/edge'e çevirir.
        Yeni doğan node listesini döner (event zenginleştirmesi için)."""
        new_nodes: List[Node] = []
        root = self.nodes[self.root_id]

        if tool == "recon":
            # KRİTİK: recon servisi 'technologies'i bazen düz string ("nginx"), bazen dict
            # ({"name":"nginx","version":"1.2"}) döndürür. dict hashlenemez → dict.fromkeys
            # 'unrhashable type: dict' ile PATLIYORDU ve TÜM otonom tarama fail oluyordu
            # (recon her akışın ilk adımı). Önce string'e normalize et.
            techs = _normalize_str_list(result_data.get("technologies") or [])
            # (0) HASSAS YOL GÜVENLİK AĞI: recon'un parmak izlediği HER host'a (kök veya
            # per-host subdomain) deterministik .env/.git/yedek probu seed et. Teknoloji
            # tespiti başarısız/boş olsa bile çalışır — teknoloji etiketi taşımayan çıplak
            # PHP siteleri genelde en kirli (ve .env'in en sık unutulduğu) olanlardır.
            # RAID: recon'un parmak izlediği host'a garantili pathprobe (merkezi helper —
            # urgency yüksek, host değerinden bağımsız). Recon hangi host'u taradıysa (kök
            # veya per-host subdomain) onu hedefler. Teknoloji tespit edilmese bile çalışır.
            recon_scan_target = (getattr(decision, "options", {}) or {}).get("scan_target")
            pp_host_id = self.root_id
            if recon_scan_target:
                _cst = _canon_host(recon_scan_target)
                for _cand in (f"host:{_cst}", f"host:reverse:{_cst}"):
                    if _cand in self.nodes:
                        pp_host_id = _cand
                        break
            self._seed_pathprobe_raid(
                pp_host_id,
                recon_scan_target if recon_scan_target and recon_scan_target != self.target else None,
                f"{recon_scan_target or self.target} canlı web yüzeyi",
                tech_hints=techs,  # Laravel/Next.js/WP tespit edildiyse framework-özel yollar da problanır
            )
            root.meta["technologies"] = list(dict.fromkeys(root.meta.get("technologies", []) + techs))
            if result_data.get("is_behind_cf") or result_data.get("is_cloudflare") or result_data.get("is_behind_cdn"):
                root.meta["is_behind_cdn"] = True
            for ip in (result_data.get("real_ips") or []):
                root.meta["real_ip"] = root.meta.get("real_ip") or ip
                host_node = self.add_node(Node(
                    id=f"host:{ip}", type=NodeType.HOST, label=ip,
                    value=DEFAULT_NODE_VALUE, breach_prob=0.15, state=NodeState.DISCOVERED,
                ))
                self.add_edge(Edge(from_id=self.root_id, to_id=host_node.id, tool="recon",
                                    cost=EDGE_COST_TABLE["recon"], success_prob=0.9,
                                    rationale="Recon ile gerçek IP tespit edildi.", state="executed"))
                new_nodes.append(host_node)
                # Kademeli ilk temas: ucuz top-100 port tarama. -p- (full) DEĞİL —
                # değer kanıtlanmadan 65535 port taranmaz (doktrin: az ama kesin).
                # scan_target=ip → dispatcher gerçek origin IP'yi tarar (kök domain/CDN'i DEĞİL).
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=host_node.id, tool="nmap",
                    options={"--top-ports": 100, "-sV": True, "scan_type": ["-sS", "-sV"],
                             "stage": "first-contact", "scan_target": ip},
                    cost=EDGE_COST_TABLE["nmap-top100"], success_prob=0.85,
                    rationale=f"{ip} üzerinde kademeli ilk temas: en yaygın 100 port. "
                              f"Değer kanıtlanınca derinleşilir.",
                ))
            # Bulunan subdomainlere KENDİ recon kenarını seed et — aksi halde subdomain
            # keşfedilir ama hiç taranmaz (motor hep kök hedefi tarardı). Graf şişmesin diye
            # üst sınır; motorun step bütçesi zaten kaç tanesinin çalışacağını belirler.
            for sub in (result_data.get("subdomains") or [])[:MAX_SUBDOMAIN_SCAN_EDGES]:
                name = sub.get("name") if isinstance(sub, dict) else sub
                name = _canon_host(name)
                # Kök hedefin kendisi (www'lu/www.'suz fark etmez) yeni host DEĞİLDİR —
                # aksi halde hedef kendi kendine recon kenarı doğurur, her bulgu çiftlenir.
                if not name or name == _canon_host(self.target):
                    continue
                sub_node = self.add_node(Node(
                    id=f"host:{name}", type=NodeType.HOST, label=name,
                    value=NODE_VALUE_TABLE["static"], breach_prob=0.05, state=NodeState.DISCOVERED,
                ))
                new_nodes.append(sub_node)
                # cPanel/Plesk varsayılan kaydıysa (webdisk/webmail/whm...) derin tarama
                # seed ETME — aynı sunucunun otomatik açılan takma adıdır; bütçeyi asıl
                # yüzeye sakla. Node grafta kalır (görünürlük + raporda "varsayılan kayıt").
                if _is_boilerplate_subdomain(name):
                    sub_node.meta["boilerplate"] = True
                    self.notes.append(
                        f"[keşif] {name} cPanel/Plesk varsayılan kaydı — derin tarama atlandı "
                        f"(aynı sunucunun otomatik DNS takma adı)."
                    )
                    continue
                # scan_target=name → recon gerçekten bu subdomaini parmak izler (kök hedefi değil).
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=sub_node.id, tool="recon",
                    options={"scan_target": name},
                    cost=EDGE_COST_TABLE["recon"], success_prob=0.85,
                    rationale=f"Subdomain {name} keşfedildi — kendi yüzeyini parmak izle "
                              f"(doktrin: her suru tek tek yokla).",
                ))
            root.meta["subdomains"] = list(dict.fromkeys(
                root.meta.get("subdomains", []) + _normalize_str_list(result_data.get("subdomains") or [])
            ))
            # (a) HEDEFLİ WEB-YÜZEYİ tag taraması — açık .env/.git/yedek/panel/varsayılan-parola.
            # KRİTİK: bu, standart seviyede ÇALIŞAN tek web zafiyet taramasıdır (DAST/cve_sweep
            # fuzz-gate'li, yalnız 'deep'te açılır). Önceden recon web tespit edince yalnız
            # DAST+sweep kenarı doğuyordu → standart seviyede HİÇ web taraması olmuyordu; recon
            # yolunda .env/.git gibi en sık bulgular kaçıyordu (nmap yolunda vardı, recon'da yok).
            # Bankaların çoğu domain hedefidir → asıl akış budur.
            # DÜRÜST-KAPSAMA: teknoloji tespiti BAŞARISIZ/BOŞ olsa bile (SİL, framework'süz
            # statik site, tespit edilemeyen stack) kenar seed EDİLİR — recon'un 'completed'
            # dönmesi domain'in çözüldüğünü gösterir; web uygulaması varsayımı. Aksi halde
            # 'teknoloji listesi boş' → uygulama katmanı hiç taranmaz → 'temiz' yalanı.
            tech_tags = _normalize_str_list(root.meta.get("technologies", []))[:6]
            web_tags = list(dict.fromkeys(WEB_SURFACE_TAGS + [t.lower() for t in tech_tags]))
            _tech_ctx = (f"{', '.join(tech_tags[:3])}") if tech_tags else "teknoloji tespit edilemedi"
            self.add_edge(Edge(
                from_id=self.root_id, to_id=self.root_id, tool="nuclei",
                options={"tags": web_tags, "severity": list(DEFAULT_SEVERITY)},
                cost=EDGE_COST_TABLE["nuclei-targeted"], success_prob=0.6,
                rationale=f"{self.target} canlı web uygulaması ({_tech_ctx}) — hedefli "
                          f"web-yüzeyi taraması (açık .env/.git/yedek/panel/varsayılan-parola"
                          + (f" + teknoloji CVE'leri" if tech_tags else "") + ").",
                urgency=1.2,
            ))
            # Web teknolojisi tespit edildiyse: (b)+(c) framework-bağımlı derin katmanlar.
            if root.meta.get("technologies"):
                # (b) Aktif uygulama-katmanı testi (DAST) — parametre enjeksiyonu. Fuzz-gate'li:
                # yalnız 'deep' seviyede seçilir. Altyapı CVE taraması login/parametre yüzeyine kör.
                self._seed_web_dast_edge(
                    self.root_id, self.target,
                    rationale=f"{self.target} canlı bir web uygulaması ("
                              f"{', '.join(root.meta['technologies'][:3])}). Aktif enjeksiyon "
                              f"testi (DAST: xss/sqli/ssrf...) ile uygulama katmanı sınanır.",
                )
                # (c) Güvenlik ağı: tespit edilemeyen framework CVE'lerini de yakala (Next.js vb.).
                self._seed_web_cve_sweep_edge(self.root_id)
            # (d Faz 1) Kök hedef için crawl kenarı seed et — host raid-loop'una girmez
            # çünkü root NodeType.TARGET (HOST değil). Oysa saldırı yüzeyinin kalbi kök
            # uygulamanın URL/parametre yığınıdır; nuclei `target`=kök URL'i tek başına
            # gördüğünde SQLi/XSS/SSRF/IDOR imzaları URL bulamazdı. Crawl bunları toplar.
            # Teknoloji tespitinden BAĞIMSIZ seed (yukarıdaki dürüst-kapsama gerekçesi).
            self.add_edge(Edge(
                from_id=self.root_id, to_id=self.root_id, tool="crawl", options={},
                cost=EDGE_COST_TABLE["crawl"], success_prob=0.75,
                rationale=(f"{self.target} canlı web uygulaması — same-host URL/form/JS "
                           f"keşfi (robots/sitemap + BFS). Parametreli endpoint'ler "
                           f"nuclei DAST için URL corpus'u olur."),
            ))
            # (d) HTTP güvenlik başlıklarını değerlendir: eksik HSTS/CSP/X-Frame-Options vb.
            # gibi bulgular toplanır ama raporlanmazdı; bunları info seviyesinde node olarak ekle.
            new_nodes.extend(_analyze_security_headers(self, result_data))

        elif tool == "origin_discovery":
            best = result_data.get("primary_real_ip") or result_data.get("best_candidate")
            confidence = 50.0
            verified = False
            if isinstance(best, dict):
                confidence = float(best.get("confidence", 50) or 50)
                verified = bool(best.get("verified"))
                best = best.get("ip")
            if best:
                root.meta["real_ip"] = best
                value = DEFAULT_NODE_VALUE * (1.3 if verified else 1.0)
                host_node = self.add_node(Node(
                    id=f"host:{best}", type=NodeType.HOST, label=str(best),
                    value=value, breach_prob=min(0.95, confidence / 100.0),
                    state=NodeState.DISCOVERED,
                ))
                new_nodes.append(host_node)
                # Origin IP bulundu — kademeli ilk temas (top-100) seed et.
                # scan_target=best → CDN'i değil GERÇEK origin IP'yi tarar.
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=host_node.id, tool="nmap",
                    options={"--top-ports": 100, "-sV": True, "scan_type": ["-sS", "-sV"],
                             "stage": "first-contact", "scan_target": str(best)},
                    cost=EDGE_COST_TABLE["nmap-top100"], success_prob=0.85,
                    rationale=f"Gerçek origin IP ({best}) üzerinde kademeli ilk temas: "
                              f"en yaygın 100 port.",
                ))

        elif tool == "subfinder":
            _raw_subs = _normalize_str_list(result_data.get("subdomains") or [])
            for name in _raw_subs:
                name = _canon_host(name)
                if not name or name == _canon_host(self.target):
                    continue
                # WILDCARD/VHOST GÜRÜLTÜSÜ: 'müşteridomain.com.hosting-provider.com' gibi gömülü
                # tam domain'ler gerçek subdomain değil — düğüm/kenar/RAID DOĞURMA (bütçe+kapsam).
                if _is_malformed_subdomain(name):
                    continue
                sub_node = self.add_node(Node(
                    id=f"host:{name}", type=NodeType.HOST, label=name,
                    value=NODE_VALUE_TABLE["static"], breach_prob=0.05, state=NodeState.DISCOVERED,
                ))
                if _is_boilerplate_subdomain(name):
                    sub_node.meta["boilerplate"] = True
                new_nodes.append(sub_node)
            # Meta/özet/UI listesine de YALNIZ temiz subdomain'ler yazılsın (rapor 'saçma
            # host' göstermesin) — kanonikleştirilmiş biçimde dedup edilir.
            _clean_subs = [_canon_host(s) for s in _raw_subs]
            _clean_subs = [s for s in _clean_subs if s and not _is_malformed_subdomain(s)]
            root.meta["subdomains"] = list(dict.fromkeys(
                root.meta.get("subdomains", []) + _clean_subs
            ))

        elif tool in ("nmap", "rustscan"):
            ports = result_data.get("ports") or result_data.get("services") or []
            host_id = f"host:{root.meta.get('real_ip')}" if root.meta.get("real_ip") else self.root_id
            # Gerçek IP biliniyorsa bu host'a açılan nuclei/DAST kenarları kök hedefi/CDN'i değil
            # o IP'yi hedef almalı — scan_target ile taşınır. Yoksa None (kök hedef taranır, doğru).
            host_scan_target = root.meta.get("real_ip")
            # KRİTİK: Saf IP hedefte (örn. 203.0.113.76) recon/origin atlanır, bu yüzden
            # `host:{real_ip}` düğümü HİÇ yaratılmaz. host_id bu var olmayan düğüme çözülürse
            # (a) aşağıdaki değer yükseltmesi no-op olur, (b) ona açılan nuclei/DAST/cve_sweep
            # kenarları hayalet düğümü hedefler → siege_score=0 → NUCLEI HİÇ ÇALIŞMAZ.
            # Çözüm: eksikse host düğümünü şimdi yarat ki hem değer devralınsın hem kenarlar
            # gerçek bir hedefe puanlansın.
            if host_id != self.root_id and host_id not in self.nodes:
                host_label = root.meta.get("real_ip") or host_id.split("host:", 1)[-1]
                self.add_node(Node(
                    id=host_id, type=NodeType.HOST, label=host_label,
                    value=NODE_VALUE_TABLE["static"], breach_prob=0.1,
                    state=NodeState.PROBED,
                    meta={"real_ip": root.meta.get("real_ip")},
                ))

            def _wt(opts: Dict[str, Any]) -> Dict[str, Any]:
                """Gerekiyorsa scan_target ekle (per-host hedefleme). Signature'a dahil olur."""
                if host_scan_target and host_scan_target != self.target:
                    opts = {**opts, "scan_target": host_scan_target}
                return opts
            discovered_svc_names: List[str] = []
            svc_scores: List[Tuple[float, float]] = []   # (value, breach_prob) — host değeri için
            known_ports = root.meta.setdefault("open_ports", [])
            known_port_nums = {pp.get("port") for pp in known_ports if isinstance(pp, dict)}
            for p in ports:
                if not isinstance(p, dict):
                    continue
                # Aynı portu tekrar ekleme (nmap tekrarında known_ports şişmesin — döngü/gürültü önleme)
                if p.get("port") not in known_port_nums:
                    known_ports.append(p)
                    known_port_nums.add(p.get("port"))
                svc = (p.get("service") or "").lower()
                prod = (p.get("product") or "").lower()
                version = (p.get("version") or "").lower()
                port = p.get("port")
                matched_svc = None
                for svc_name in _SERVICE_VALUE_CATEGORY:
                    if svc_name in svc or svc_name in prod:
                        matched_svc = svc_name
                        break
                if matched_svc is None:
                    # APT servis-istihbaratı: kategoride olmasa bile ÜRÜN+SÜRÜM varsa
                    # servisi çöpe atma — genel "network-service" node'u aç ve NVD CVE
                    # sorgusuna sok. Eskiden 'continue' ile mail/DNS/tanınmayan her servis
                    # görünmezdi (nmap 9 port buluyor ama 0 bulgu → kök neden buydu).
                    if prod and version:
                        # Ham servis/ürün adını kullan. GLOBAL _SERVICE_VALUE_CATEGORY'yi
                        # MUTASYONA UĞRATMA (aksi halde bir taramanın servis adı sonraki
                        # taramalara/tüm graflara sızar — süreç-ömrü kirlenme). Değer aşağıda
                        # 'network-service' tabanıyla açıkça atanır.
                        matched_svc = (svc or prod or "service").split("/")[0].strip()[:40] or "service"
                        uncategorized_versioned = True
                    else:
                        continue
                else:
                    uncategorized_versioned = False
                if matched_svc not in discovered_svc_names:
                    discovered_svc_names.append(matched_svc)
                # Kategorili servis → tablo değeri; tanınmayan-versiyonlu → network-service tabanı
                # (global tabloyu kirletmeden). Her ikisi de NVD CVE korelasyonuna girer.
                if uncategorized_versioned:
                    value = NODE_VALUE_TABLE["network-service"]
                    breach_prob = 0.4
                else:
                    value = _node_value_for_service(matched_svc)
                    breach_prob = _node_breach_prob_for_service(matched_svc, version)
                svc_scores.append((value, breach_prob))
                svc_node = self.add_node(Node(
                    id=f"svc:{matched_svc}@{port}", type=NodeType.SERVICE,
                    label=f"{matched_svc}@{port}", value=value, breach_prob=breach_prob,
                    state=NodeState.DISCOVERED,
                    # matched_service: servis türü sınıflaması (attention_items) düğümün DEĞER
                    # skoruna değil GERÇEK servis adına baksın diye saklanır (nginx≠veritabanı).
                    meta={"port": port, "product": prod, "version": version,
                          # Madde 4: banner Debian-revision'ı ("Ubuntu 4ubuntu0.4") —
                          # distro-patch-level matrisi bunu okur.
                          "extrainfo": p.get("extrainfo") or "",
                          "matched_service": matched_svc},
                ))
                new_nodes.append(svc_node)
                cost = EDGE_COST_TABLE["nmap-top1000"] if tool == "nmap" else EDGE_COST_TABLE["rustscan-full"]
                self.add_edge(Edge(from_id=host_id, to_id=svc_node.id, tool=tool,
                                    cost=cost, success_prob=0.8,
                                    rationale=f"{tool} ile {matched_svc} servisi tespit edildi.",
                                    state="executed"))

                # kritik CVE eşleşiyorsa: doğrulama kenarı (vuln node) doğur
                critical_versions = _critical_versions_for_service(matched_svc)
                static_cve_matched = False
                for ver_pattern, cves in critical_versions.items():
                    if ver_pattern and ver_pattern in version:
                        static_cve_matched = True
                        cve_id = cves[0]
                        vuln_node = self.add_node(Node(
                            id=f"vuln:{cve_id}", type=NodeType.VULNERABILITY, label=cve_id,
                            value=NODE_VALUE_TABLE["critical-cve-service"], breach_prob=0.6,
                            state=NodeState.DISCOVERED,
                            meta={"cves": cves, "service": matched_svc},
                        ))
                        new_nodes.append(vuln_node)
                        templates = [f"cve-{c.lower().replace('cve-', '')}" for c in cves]
                        self.add_edge(Edge(
                            from_id=svc_node.id, to_id=vuln_node.id, tool="nuclei",
                            options=_wt({"templates": templates, "severity": ["critical", "high"]}),
                            cost=EDGE_COST_TABLE["nuclei-targeted"], success_prob=0.85,
                            rationale=f"{prod} {version} -> {', '.join(cves)} biliniyor. "
                                      f"Genel tarama yerine bu CVE'yi HEDEFLİ template ile KANITLA.",
                            urgency=1.5,
                        ))

                # Statik haritada yoksa NVD'ye sorulacak olarak işaretle.
                # (offline/kapalıysa sessizce atlanır; servis hâlâ normal hedefli taramalara girer.)
                if not static_cve_matched and prod and version:
                    svc_node.meta["needs_cve_lookup"] = True

            # KRİTİK SKORLAMA DÜZELTMESİ: Bir host'ta değerli servisler bulunduysa, o host
            # düğümünün değeri/olasılığı bunu YANSITMALI. Aksi halde host (özellikle IP hedefte
            # root) varsayılan düşük değerde (25/0.1) kalır → ona açılan nuclei/DAST/cve_sweep
            # kenarları eşik altında skorlanır ve NUCLEI HİÇ ÇALIŞMAZ (nginx bulunur ama taranmaz).
            # Host, üzerindeki en değerli servisin value/breach_prob'unu devralır.
            host_node = self.nodes.get(host_id)
            if host_node is not None and svc_scores:
                host_node.value = max(host_node.value, max(v for v, _ in svc_scores))
                host_node.breach_prob = max(host_node.breach_prob, max(b for _, b in svc_scores))

            # Doktrin: KÖR/GENİŞ nuclei YOK. Tespit edilen servislerin tag'leriyle HEDEFLİ tarama.
            svc_tags: List[str] = []
            for svc_name in discovered_svc_names:
                for tag in _nuclei_tags_for_service(svc_name):
                    if tag not in svc_tags:
                        svc_tags.append(tag)
            # Web/HTTP servisi doğrulandıysa genel web-yüzey tag'lerini de ekle — framework
            # tespit edilemese bile (IP hedefte recon atlanır) açık .env/.git/yedek/panel/
            # varsayılan-parola gibi PHP/legacy uygulamalarda en sık çıkan bulgular yakalanır.
            has_http = any(
                "http" in (str(p.get("service", "")) + str(p.get("product", ""))).lower()
                or p.get("port") in COMMON_HTTP_PORTS
                for p in ports if isinstance(p, dict)
            ) or any(s in WEB_APP_SERVICES for s in discovered_svc_names)
            if has_http:
                for tag in WEB_SURFACE_TAGS:
                    if tag not in svc_tags:
                        svc_tags.append(tag)
            if svc_tags:
                self.add_edge(Edge(
                    from_id=host_id, to_id=host_id if host_id != self.root_id else self.root_id,
                    tool="nuclei",
                    options=_wt({"tags": svc_tags, "severity": list(DEFAULT_SEVERITY)}),
                    cost=EDGE_COST_TABLE["nuclei-targeted"], success_prob=0.6,
                    rationale=f"Tespit edilen servislere ({', '.join(discovered_svc_names)}) "
                              f"HEDEFLİ nuclei tarama — tag: {', '.join(svc_tags)}. Kör tarama yok.",
                ))

            # HTTP servisi doğrulandıysa: hassas yol RAID (.env/.git/yedek). IP hedeflerinde
            # recon atlandığı için raid'in _seed_initial_edges kök seed'i kök hedefe atılır;
            # burada gerçek origin IP host'una da garantili raid seed edilir (host_scan_target).
            if has_http:
                pp_host = host_id if host_id != self.root_id else self.root_id
                self._seed_pathprobe_raid(
                    pp_host, host_scan_target,
                    f"HTTP servisi doğrulandı ({host_scan_target or self.target})",
                )

            # Web sunucusu/uygulaması bulunduysa: aktif uygulama-katmanı testi (DAST) kenarı.
            # Hedefli CVE taraması bilinen zafiyetleri arar; DAST ise BİLİNMEYEN enjeksiyon
            # kusurlarını (parametre xss/sqli/ssrf...) canlı tetikleyerek dener (madde 3).
            web_svcs = [s for s in discovered_svc_names if s in WEB_APP_SERVICES]
            if web_svcs:
                dast_host = host_id if host_id != self.root_id else self.root_id
                self._seed_web_dast_edge(
                    dast_host, ", ".join(web_svcs),
                    rationale=f"Web sunucusu tespit edildi ({', '.join(web_svcs)}). Aktif "
                              f"enjeksiyon testi (DAST) ile uygulama katmanı sınanır.",
                    scan_target=host_scan_target,
                )
                # Güvenlik ağı: geniş critical/high CVE süpürmesi (tabloda olmayan framework'ler).
                self._seed_web_cve_sweep_edge(dast_host, scan_target=host_scan_target)

            # Kademeli derinleşme: bu bir ilk-temas (top-100) taramasıydı ve DEĞERLİ bir
            # servis (DB/admin/remote-mgmt) çıktıysa, gizli portlarda daha fazlası olabilir.
            # SADECE bu durumda -p- (full) derin tarama kenarı doğar. Değer kanıtlanmadan
            # 65535 port asla taranmaz — "az ama kesin" doktrini.
            decision_opts = getattr(decision, "options", {}) or {}
            was_first_contact = decision_opts.get("stage") == "first-contact" and tool == "nmap"
            high_value = any(
                _node_value_for_service(s) >= NODE_VALUE_TABLE["remote-mgmt"]
                for s in discovered_svc_names
            )
            if was_first_contact and high_value:
                self.add_edge(Edge(
                    from_id=host_id, to_id=host_id if host_id != self.root_id else self.root_id,
                    tool="nmap",
                    options=_wt({"-p": "1-65535", "-sV": True, "scan_type": ["-sS", "-sV"],
                                 "stage": "deep"}),
                    cost=EDGE_COST_TABLE["nmap-full"], success_prob=0.7,
                    rationale=f"İlk temasta değerli servis ({', '.join(discovered_svc_names)}) "
                              f"bulundu. Gizli portlarda daha fazlası olabilir — TÜM portlar (-p-) "
                              f"derin taranır. Değer kanıtlandığı için maliyet haklı.",
                    urgency=1.2,
                ))

        elif tool == "fuzz":
            eps = result_data.get("endpoints") or result_data.get("found") or result_data.get("directories") or []
            files = result_data.get("files") or []
            for e in list(eps) + list(files):
                path = e.get("url") if isinstance(e, dict) else str(e)
                if not path:
                    continue
                value = NODE_VALUE_TABLE["static"]
                for pattern, v in _ENDPOINT_VALUE_PATTERNS:
                    if pattern in path.lower():
                        value = v
                        break
                ep_node = self.add_node(Node(
                    id=f"endpoint:{path}", type=NodeType.ENDPOINT, label=path,
                    value=value, breach_prob=0.1, state=NodeState.DISCOVERED,
                ))
                new_nodes.append(ep_node)
            root.meta["endpoints"] = list(dict.fromkeys(
                root.meta.get("endpoints", []) + [n.label for n in new_nodes]
            ))

        elif tool == "crawl":
            # FAZ 1 — endpoint keşfi. Crawler tüm same-host URL'leri toplar; burada onları
            # ENDPOINT node'larına çeviririz. Değer: path-pattern (admin/api/auth) göre
            # skorlanır — fuzz ile AYNI desen. Ek olarak PARAMETRELİ endpoint'ler için
            # hedefli nuclei DAST kenarı seed edilir (URL listesi option olarak taşınır); nuclei
            # service `urls` alanıyla bunları tek tek `-u` ile tarar (-dast açık).
            #
            # KÖK TAVANIN KAPANIŞI: eskiden nuclei'ye yalnız `self.target` (kök sayfa)
            # verilirdi; SQLi/XSS/SSRF/IDOR template'leri parametreli URL bulamayıp hiç
            # çalışmazdı → "standart zafiyeti 1 tık buluyoruz" cümlesinin TEK en büyük tek
            # sebebi buydu. Crawl keşfi + nuclei URL corpus beslemesi bu boşluğu kapatır.
            crawled_urls = result_data.get("discovered_urls") or []
            param_endpoints = result_data.get("parameterized_endpoints") or []
            crawl_scan_target = (getattr(decision, "options", {}) or {}).get("scan_target")

            # L1: enjeksiyon/authz yüzeyi haritası. Crawler artık query-param'a EK olarak
            # path-param REST (IDOR/BOLA) ve API rotalarını (JSON/GraphQL gövde) da
            # "hedef" işaretler; her endpoint'in `kind`'ına göre breach olasılığı belirlenir.
            # Eski şema (kind yok) → query say (geriye uyum).
            inj_map: Dict[str, str] = {}
            for ep in param_endpoints:
                if isinstance(ep, dict) and ep.get("url"):
                    inj_map[ep["url"]] = ep.get("kind") or "query"

            seen_eps: Set[str] = set()
            for url in crawled_urls:
                if not isinstance(url, str) or not url:
                    continue
                ep_id = f"endpoint:{url}"
                if ep_id in seen_eps:
                    continue
                seen_eps.add(ep_id)
                value = NODE_VALUE_TABLE["static"]
                for pattern, v in _ENDPOINT_VALUE_PATTERNS:
                    if pattern in url.lower():
                        value = v
                        break
                # Enjeksiyon hedefi mi ve hangi sınıf? query/path-param → yüksek breach
                # (doğrudan enjeksiyon/IDOR); api-route → gövde/JSON enjeksiyonu, biraz düşük.
                kind = inj_map.get(url)
                if kind is None and "?" in url and "=" in url.split("?", 1)[1]:
                    kind = "query"  # sağlamlık: harita boş gelse bile query yüzeyi kaçmasın
                if kind:
                    breach = _INJECTION_BREACH_BY_KIND.get(kind, 0.2)
                    # DEĞER TABANI (L2 — soğuk-başlangıç kırıcı): enjeksiyon hedefi olan
                    # endpoint, path pattern api/admin'e eşleşmese BİLE (örn. /graphql,
                    # /search, /users/123) eşiği geçmelidir. Aksi halde value=static(10)
                    # skoru 0.15 altında kalır → motor "denenecek adım yok" deyip durur.
                    value = max(value, NODE_VALUE_TABLE["api"])
                else:
                    breach = 0.08
                ep_node = self.add_node(Node(
                    id=ep_id, type=NodeType.ENDPOINT, label=url,
                    value=value, breach_prob=breach, state=NodeState.DISCOVERED,
                    meta={"injectable": kind} if kind else {},
                ))
                new_nodes.append(ep_node)

            if crawled_urls:
                root.meta["endpoints"] = list(dict.fromkeys(
                    root.meta.get("endpoints", []) + list(crawled_urls)
                ))
                by_kind = result_data.get("injectable_by_kind") or {}
                kind_note = ""
                if by_kind:
                    kind_note = (f" [query={by_kind.get('query', 0)}, "
                                 f"path-param/IDOR={by_kind.get('path-param', 0)}, "
                                 f"api-route={by_kind.get('api-route', 0)}]")
                self.notes.append(
                    f"[faz1] Crawl: {len(crawled_urls)} URL keşfedildi, "
                    f"{len(param_endpoints)} enjeksiyon/authz hedefi (DAST/IDOR){kind_note}."
                )

            # L3 — LLM HAM-YÜZEY BRİFİNGİ: somut enjeksiyon hedeflerini (url+kind+param)
            # root.meta'ya yaz. Eskiden LLM yalnız graf-ÖZETİ görüyordu ("garbage-in") →
            # görmediği endpoint'e hipotez üretemiyordu. Bu liste compact_state üzerinden
            # danışma prompt'una "SALDIRI YÜZEYİ" olarak girer; LLM gerçek param'a SOMUT
            # hipotez (sqli/xss/lfi...) önerir, deterministik verifier kanıtlar.
            if param_endpoints:
                root.meta["injectable_endpoints"] = [
                    {"url": ep.get("url"), "kind": ep.get("kind") or "query",
                     "params": [str(p) for p in (ep.get("params") or [])][:8]}
                    for ep in param_endpoints
                    if isinstance(ep, dict) and ep.get("url")
                ][:40]

            # ---- Bug bounty genişletmesi: formlar + OpenAPI matrisi + diff + method-gap ----
            # P0-B tohum hattının veri kaynağı: HTML formlar (POST gövde hedefleri) ve
            # OpenAPI endpoint matrisi (method+parametre hazır) meta'ya yazılır; pipeline
            # _verify_hypotheses bunları kural-tohumuna besler. Diff başlığı LLM prompt'una
            # 'YENİ YÜZEY' bölümü olarak girer (compact_state üstünden değil — doğrudan
            # root.meta; prompt builder meta'yı okur).
            forms = result_data.get("forms") or []
            if forms:
                root.meta["forms"] = forms[:50]
            oa_eps = result_data.get("openapi_endpoints") or []
            if oa_eps:
                root.meta["openapi_endpoints"] = oa_eps[:120]
                self.notes.append(
                    f"[p1-b] OpenAPI: {len(oa_eps)} endpoint dokümandan matrise alındı."
                )
            diff_info = result_data.get("endpoint_diff") or {}
            if diff_info:
                root.meta["endpoint_diff"] = {
                    "headline": diff_info.get("headline"),
                    "is_first": diff_info.get("is_first", True),
                    "new_params_count": len(diff_info.get("new_params") or []),
                    "no_diff_streak": diff_info.get("no_diff_streak", 0),
                }
                if diff_info.get("headline") and not diff_info.get("is_first"):
                    self.notes.append(f"[p0-a] {diff_info['headline']}")
            wb_info = result_data.get("wayback") or {}
            if wb_info.get("total", 0) > 0:
                root.meta["wayback_fetched"] = True
            if result_data.get("openapi", {}).get("found"):
                root.meta["openapi_found"] = True

            # GraphQL introspection ifşası (T2-C) → KANIT (CWE-200). Introspection'ın
            # AÇIK dönmesi başlı başına kanıttır (yanıt = tam şema dökümü; template tahmini
            # değil → confirmed). Operasyon matrisi meta'ya girer: LLM istihbarat subayı +
            # gelecekteki GraphQL verifier (mutation'lar authz/IDOR hedefi) tüketir.
            gq_info = result_data.get("graphql") or {}
            gq_ops = result_data.get("graphql_operations") or []
            if gq_ops:
                root.meta["graphql_operations"] = gq_ops[:200]
            if gq_info.get("found"):
                root.meta["graphql_found"] = True
                root.meta["graphql_endpoint"] = gq_info.get("endpoint_url")
                gq_url = gq_info.get("endpoint_url") or self.target
                if gq_info.get("introspection_enabled"):
                    from .autonomous_engine import Evidence as _GQEvidence
                    op_n = gq_info.get("operation_count", 0)
                    mut_n = gq_info.get("mutation_count", 0)
                    self.add_evidence(_GQEvidence(
                        title=f"GraphQL Introspection Exposed @ {gq_url}",
                        severity="medium", cve=None, target=gq_url,
                        proof=(f"Introspection sorgusu tam şemayı döndürdü: {op_n} operasyon "
                               f"({mut_n} mutation) ifşa oldu. Saldırgan tüm API yüzeyini + "
                               f"argümanları haritalar (CWE-200). Mutation'lar authz/IDOR "
                               f"test hedefidir."),
                        tool="graphql_intel", step=0,
                        cwe=["CWE-200"], mitre="T1213",
                        verified=True, verification_method="graphql-introspection",
                        verification_detail=(f"POST introspection → __schema döndü; "
                                             f"{op_n} operasyon deterministik çıkarıldı."),
                        verification_confidence=0.85,
                        confidence_tier="confirmed",
                    ), f"graphql_introspection|{_canon_url(gq_url)}")
                    self.notes.append(
                        f"[t2-c] GraphQL introspection AÇIK: {op_n} operasyon ifşa — {gq_url}")
                else:
                    self.notes.append(f"[t2-c] GraphQL ucu (introspection kapalı): {gq_url}")

            # Method-swap erişim boşluğu → KANIT (CWE-285). Matrisin kendisi kanıttır
            # (GET 403 iken POST 2xx deterministik gözlem — template tahmini değil).
            mm_findings = result_data.get("method_matrix_findings") or []
            if mm_findings:
                from .autonomous_engine import Evidence as _MMEvidence
                for mf in mm_findings:
                    interp = mf.get("interpretation") or {}
                    if interp.get("kind") != "access_gap":
                        continue
                    m_url = mf.get("url") or ""
                    canon = _canon_url(m_url)
                    self.add_evidence(_MMEvidence(
                        title=f"HTTP Method-Swap Access Gap ({interp.get('method')}) @ {m_url}",
                        severity="medium", cve=None, target=m_url,
                        proof=(f"GET {interp.get('blocked_get')} (erişim reddedildi) iken "
                               f"{interp.get('method')} {interp.get('status')} döndü — erişim "
                               f"kontrolü yalnız GET'e bakıyor. Matris: {mf.get('matrix')}"),
                        tool="method_matrix", step=0,
                        cwe=["CWE-285"], mitre="T1190",
                        verified=True, verification_method="http-method-matrix",
                        verification_detail=(
                            f"Method matrisi: GET={interp.get('blocked_get')}, "
                            f"{interp.get('method')}={interp.get('status')} — "
                            f"deterministik durum-kodu ölçümü"),
                        verification_confidence=0.8,
                    ), f"method_matrix|access_gap|{canon}|{interp.get('method')}")
                self.notes.append(
                    f"[p0-b] Method matrisi: {len([m for m in mm_findings if (m.get('interpretation') or {}).get('kind') == 'access_gap'])} erişim boşluğu adayı."
                )

            # P2-C JS sır ifşası (API key / JWT / DB connection string sızıntısı).
            # Her bulgu küratörlü regex + placeholder + GÜÇ/entropi denetiminden geçer.
            # ÖNEMLİ (false-positive): saf regex eşleşmesi "verified=True" DEĞİLDİR — yalnız
            # tek-anlamlı format (PEM private key → confidence_tier="confirmed") aktif teyit
            # sayılır. Public-by-design anahtarlar (Stripe pk_, Google API key) ve düşük-entropili
            # KV değerleri js_secrets tarafında zaten "unconfirmed" + düşük severity'ye çekilir.
            js_secrets = result_data.get("js_secret_findings") or []
            if js_secrets:
                from .autonomous_engine import Evidence as _JSEvidence
                for jf in js_secrets:
                    sev = str(jf.get("severity") or "high").lower()
                    tier = jf.get("confidence_tier") or "unconfirmed"
                    url = jf.get("asset_url") or self.target
                    fp = f"js_secret|{jf.get('secret_type')}|{jf.get('value_masked')}|{url}"
                    # verified=True YALNIZ tartışmasız formatta (confirmed); aksi halde None →
                    # kademe unconfirmed/probable olarak taşınır, exploit_memory'yi kirletmez.
                    is_confirmed = tier == "confirmed"
                    # HARDCODED CREDENTIAL: kardeş username varsa bulguyu eyleme-dönüşür netlikte
                    # sun — "superadmin / Supe***123!" başlığı, generic "secret exposure" yerine.
                    uname = jf.get("username")
                    if uname:
                        _title = f"Hardcoded Credential: {uname} / {jf.get('value_masked')} in {url}"
                        _proof = (f"HARDCODED CREDENTIAL — JS bundle'da sabit login kimlik bilgisi. "
                                  f"Kullanıcı: {uname} · Parola (maskeli): {jf.get('value_masked')}. "
                                  f"Bağlam: {jf.get('line_text', '')[:220]}")
                        _vdetail = ("Küratörlü password regex + kardeş username/login-form bağlamı — "
                                    "defaultValues içinde sabit credential. Doğrudan login denemesi "
                                    "yapılmadı (tahribatsız kapsam).")
                    else:
                        _title = f"JS Secret Exposure: {jf.get('secret_type')} in {url}"
                        _proof = (f"{jf.get('secret_type')} bulundu (maskeli: {jf.get('value_masked')}). "
                                  f"Bağlam: {jf.get('line_text', '')[:220]}")
                        _vdetail = (f"Küratörlü regex: {jf.get('validator')} — "
                                    f"tek-anlamlı format (PEM private key)."
                                    if is_confirmed else None)
                    self.add_evidence(_JSEvidence(
                        title=_title,
                        severity=sev, cve=None, target=url,
                        proof=_proof,
                        tool="js_secret_scan", step=0,
                        cwe=["CWE-200", "CWE-798"], mitre="T1552.001",
                        # Doğrulanmış sayılmaz (aktif login denemesi yok, tahribatsız kapsam) —
                        # verified None kalır; kademe 'probable' + %70 güven frontend'de rozet olur.
                        verified=True if is_confirmed else None,
                        verification_method=("js-regex-match" if is_confirmed
                                             else ("credential-context-match" if uname else None)),
                        verification_detail=_vdetail,
                        verification_confidence=0.9 if is_confirmed else (0.7 if uname else None),
                        confidence_tier=tier,
                    ), f"js_secret|{jf.get('secret_type')}|{jf.get('value_masked')}|{url}")
                self.notes.append(
                    f"[p2-c] JS sır taraması: {len(js_secrets)} sızıntı — {self.target}"
                )

            # PARAMETRELİ endpoint'ler için nuclei DAST kenarı seed et. URL listesi üst
            # sınıra (100) kırpılarak seed edilir — grafın şişmesini ve nuclei'nin
            # timeout'a düşmesini önler. Kenar kök host'tan (root) doğar; scan_target
            # crawl host'unaysa (subdomain crawl) nuclei `target`'ı o hosta çevirir.
            if param_endpoints:
                dast_urls = [ep.get("url") for ep in param_endpoints
                             if isinstance(ep, dict) and ep.get("url")]
                # Cap: nuclei `urls` listesinde 100'den fazla URL çok yavaşlatır; en
                # değerli pattern-admin/api/auth) olanları preferanslı tut. Burada basit
                # sıralama: parametreli + admin/api/auth path önce.
                def _ep_score(u: str) -> int:
                    u = u.lower()
                    s = 0
                    for pat in ("admin", "api", "auth", "login", "user", "account"):
                        if pat in u:
                            s += 1
                    return s

                dast_urls = sorted(dast_urls, key=_ep_score, reverse=True)[:100]
                if dast_urls:
                    dast_opts: Dict[str, Any] = {
                        "dast": True, "urls": dast_urls,
                        "severity": list(DEFAULT_SEVERITY),
                    }
                    if crawl_scan_target and crawl_scan_target != self.target:
                        dast_opts["scan_target"] = crawl_scan_target
                    # DAST kenarını en yüksek-değerli ENDPOINT node'una bağla. Bu turda doğan
                    # endpoint'lerden en değerlisi (admin/api/auth pattern) seçilir. Neden:
                    # siege_score to_id'nin değeriyle üretildiği için, kök TARGET'a (value=25,
                    # breach=0.1) bağlanırsa skor ~0.04 olur → eşiğin (0.15) altında kalır →
                    # motor DAST'i HİÇ SEÇMEZ → URL corpus hiç taranmaz. Enjeksiyon-hedefi
                    # endpoint value≥55 breach=0.25 ile: (55*0.25*0.55)/45 * 1.3 ≈ 0.22 — eşik
                    # üstünde. Nuclei yine de `options.urls` içindeki TÜM URL'leri `-u` ile
                    # tarar; to_id yalnızca skoru etkiler, taramanın kapsamını DEĞİL.
                    #
                    # DAST kenarını, kenarın KENDİ skorunu (value×breach) en çoklayan node'a
                    # bağla — salt en yüksek value'ya değil. Aksi halde yüksek-değer ama
                    # düşük-breach bir sayfa (örn. parametresiz /admin, breach=0.08) seçilip
                    # DAST skoru eşik altına düşebilirdi. Injectable endpoint'ler (breach≥0.18)
                    # doğal olarak öne çıkar → kenar güvenle eşiği geçer.
                    best_ep_id = self.root_id
                    best_ep_metric = -1.0
                    for n in new_nodes:
                        if n.type != NodeType.ENDPOINT:
                            continue
                        metric = n.value * n.breach_prob
                        if metric > best_ep_metric:
                            best_ep_metric = metric
                            best_ep_id = n.id
                    self.add_edge(Edge(
                        from_id=self.root_id, to_id=best_ep_id, tool="nuclei",
                        options=dast_opts,
                        cost=EDGE_COST_TABLE["nuclei-dast"], success_prob=0.55,
                        rationale=(f"Crawl: {len(dast_urls)} parametreli endpoint keşfedildi — "
                                   f"nuclei -dast bu URL'lerde SQLi/XSS/SSRF/LFI canlı test eder. "
                                   f"Bu, kök-URL kör taramasının kapattığı boşluğu açar."),
                        urgency=1.3,
                    ))

            # API BOLA AKTİF SALDIRI KENARI — nesne-ID'li (path-param/query) endpoint varsa
            # planlayıcı KİTLESEL yetkisiz erişimi (TEB senaryosu) bilinçli olarak SEÇEBİLSİN.
            # Otomatik post-observe probu güvenlik ağıdır; bu kenar motorun 'kör tarayıcı' değil
            # 'saldırgan' olduğu yer — siege_score ile yarışır. Adaylar _candidates (imza-DIŞI,
            # underscore) ile taşınır → tek kararlı kenar; çalışınca executed dedup'lanır.
            try:
                from .idor_probe import extract_object_refs as _eor
                _all_eps = root.meta.get("endpoints", []) or []
                bola_cands = [u for u in _all_eps
                              if isinstance(u, str)
                              and u.startswith(("http://", "https://")) and _eor(u)]
            except Exception:
                bola_cands = []
            already_bola = any(e.tool == "probe_api_bola" and e.state in ("open", "executed")
                               for e in self.edges.values())
            if bola_cands and not already_bola:
                # En değerli endpoint node'una bağla (DAST ile aynı: value×breach maksimize).
                best_id, best_metric = self.root_id, -1.0
                for n in new_nodes:
                    if n.type != NodeType.ENDPOINT:
                        continue
                    metric = n.value * n.breach_prob
                    if metric > best_metric:
                        best_metric, best_id = metric, n.id
                # app_type=api (operatör ipucu ya da oto-tespit) → aciliyet yükselt.
                app_api = False
                try:
                    _facts = (root.meta.get("target_profile") or {}).get("facts") or {}
                    app_api = (_facts.get("app_type") or {}).get("value") == "api"
                except Exception:
                    app_api = False
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=best_id, tool="probe_api_bola",
                    options={"_candidates": bola_cands[:80]},
                    cost=EDGE_COST_TABLE.get("nuclei-dast", 45), success_prob=0.6,
                    rationale=(f"{len(bola_cands)} nesne-ID'li endpoint keşfedildi — API BOLA "
                               f"aktif saldırısı: token'sız + çapraz-kimlik erişim, id yürüyüşüyle "
                               f"KİTLESEL veri sızıntısı kanıtlanır (TEB senaryosu)."),
                    urgency=1.9 if app_api else 1.5,
                ))
                self.notes.append(
                    f"[bola] API BOLA saldırı kenarı: {len(bola_cands)} nesne-ID'li endpoint"
                    + (" (app_type=api)" if app_api else ""))

        elif tool == "nuclei":
            for ev, fp in _collect_evidence(result_data, tool, self.target):
                # FAQ 1.5: sürüm-CVE inference kaydı + nuclei ham proof çifti → birleştir
                # (inference 'confirmed'a yükselir, bu kopya eklenmez). True dönerse çaktı.
                if self.merge_inference_with_proof(ev):
                    # Birleşmede bile ilgili vuln node'unu BREACHED işaretle (sinyal kaybolmasın).
                    for node in self.nodes.values():
                        if (node.type in (NodeType.SERVICE, NodeType.VULNERABILITY)
                                and ev.cve and node.id == f"vuln:{ev.cve}"):
                            node.state = NodeState.BREACHED
                            node.breach_prob = 1.0
                    continue
                if not self.add_evidence(ev, fp):
                    continue  # mükerrer bulgu — node'u tekrar işaretleme, sayaçları şişirme
                # ilgili servis/vuln node'u breached işaretle
                for node in self.nodes.values():
                    if node.type in (NodeType.SERVICE, NodeType.VULNERABILITY) and (
                        (ev.cve and node.id == f"vuln:{ev.cve}") or node.label.split("@")[0] in ev.title.lower()
                    ):
                        node.state = NodeState.BREACHED
                        node.breach_prob = 1.0
                        node.evidence = ev.to_dict()

        elif tool == "osint":
            for port in (result_data.get("shodan_ports") or []):
                svc_node = self.add_node(Node(
                    id=f"svc:shodan@{port}", type=NodeType.SERVICE, label=f"shodan@{port}",
                    value=DEFAULT_NODE_VALUE, breach_prob=0.1, state=NodeState.DISCOVERED,
                    meta={"port": port, "source": "shodan"},
                ))
                new_nodes.append(svc_node)

        elif tool == "pathprobe":
            # Hassas yol bulguları → KANIT + vulnerability node. Her bulgu zaten içerik
            # validator'ından geçmiş DOĞRULANMIŞ ifşadır (soft-404 elenmiş); bu yüzden
            # nuclei "template eşleşti" tahmininden daha güçlü kanıt sayılır.
            pp_findings = result_data.get("findings") or []
            from .autonomous_engine import Evidence as _PPEvidence
            for f in pp_findings:
                if not isinstance(f, dict):
                    continue
                sev = str(f.get("severity", "info")).lower()
                if sev in ("info", "low"):
                    continue  # bilgi notları kanıt değeri taşımaz, graf şişmesin
                url = f.get("url") or ""
                cat = f.get("category", "exposure")
                # Dedup: aynı path aynı host'ta (www'lu/www.'suz) bir kez kanıtlanır.
                # vuln node id'si de kanonik URL'den üretilir ki node tarafı da şişmesin.
                canon = _canon_url(url)
                fp = f"pathprobe|{f.get('validator') or cat}|{canon}"
                if fp in self._evidence_keys:
                    continue
                vuln_node = self.add_node(Node(
                    id=f"vuln:path:{canon}", type=NodeType.VULNERABILITY,
                    label=f"{cat} @ {url}",
                    value=NODE_VALUE_TABLE["git-repo-exposed"] if cat == "vcs_exposure"
                          else NODE_VALUE_TABLE["default-creds"] if sev == "critical"
                          else NODE_VALUE_TABLE["web-app"] + 20,
                    breach_prob=0.9 if sev == "critical" else 0.6,
                    state=NodeState.BREACHED if sev == "critical" else NodeState.DISCOVERED,
                    meta={"category": cat, "path": f.get("path"), "status": f.get("status")},
                ))
                new_nodes.append(vuln_node)
                # Kademe: içerik imzası soft-404'ü eledi → ifşa DETERMİNİSTİK kanıtlı.
                # critical/vcs (ör. .git, .env kimlikli) tartışmasız → "confirmed"; diğer
                # ifşalar güçlü ama daha yumuşak → "probable". (Aktif enjeksiyon PoC'si değil,
                # ama tahmine dayalı da değil — nuclei "template eşleşti"den güçlü.)
                pp_tier = "confirmed" if (sev == "critical" or cat == "vcs_exposure") else "probable"
                # Kanıt: ham snippet (sırlar maskeli) + yeniden üretim curl'ü.
                self.add_evidence(_PPEvidence(
                    title=f"Hassas dosya ifşası: {f.get('path')}",
                    severity=sev, cve=None, target=url,
                    proof=(f"Doğrulanmış ifşa [{cat}] @ {url} — HTTP {f.get('status')}, "
                           f"{f.get('content_length', 0)}B, validator={f.get('validator')}. "
                           f"İçerik imzası doğrulandı (soft-404 değil)."),
                    tool="pathprobe", step=0,
                    mitre=f.get("mitre"),
                    request=f"GET {url} HTTP/1.1",
                    response=(f.get("snippet") or "")[:600] or None,
                    curl=f.get("curl"),
                    attack_techniques=[f["mitre"]] if f.get("mitre") else [],
                    confidence_tier=pp_tier,
                ), fp)
            if pp_findings:
                root.meta["sensitive_findings"] = list(dict.fromkeys(
                    root.meta.get("sensitive_findings", [])
                    + [f.get("url") for f in pp_findings if isinstance(f, dict)]
                ))
            # TEKNOLOJİ/SÜRÜM PARMAK İZİ → NVD ZİNCİRİ: prober'ın ana sayfadan çıkardığı
            # sürümlü ürünleri (wordpress 6.x, apache 2.4.x, php 8.x) SERVICE düğümüne
            # çevirip needs_cve_lookup işaretle. enrich_cve_intelligence (her turda
            # next_decision başında çalışır) bunları NVD'ye sorar → yeni çıkmış CVE'ler
            # dahil hedefli nuclei template kenarı doğar. "Güncel WP açığı kaçtı"
            # vakasının kapandığı nokta budur: sürüm bilinmeden lookup sorulamıyordu.
            for tech in (result_data.get("detected_technologies") or []):
                if not isinstance(tech, dict):
                    continue
                product = str(tech.get("product") or "").strip().lower()
                version = str(tech.get("version") or "").strip().lower()
                if not product:
                    continue
                tech_host = str(result_data.get("target") or self.target)
                svc_node = self.add_node(Node(
                    id=f"svc:web:{product}@{tech_host}", type=NodeType.SERVICE,
                    label=f"{product}@{tech_host}",
                    value=NODE_VALUE_TABLE["web-app"], breach_prob=0.15,
                    state=NodeState.DISCOVERED,
                    meta={"product": product, "version": version,
                          "matched_service": product,
                          "source": tech.get("source", "http_fingerprint"),
                          "host": tech_host},
                ))
                if version:
                    svc_node.meta["needs_cve_lookup"] = True
                # Özet/LLM de görsün — root teknoloji listesine işle
                if product not in [t.lower() for t in root.meta.get("technologies", [])]:
                    root.meta.setdefault("technologies", []).append(product)
                # Bilinen web ürünleri için ürüne-özel nuclei tag taraması seed et.
                # NVD zincirinden bağımsız ikinci yol: template kütüphanesi tazeyse
                # güncel CVE'ler (nuclei'de template'i yayınlanmış olanlar) buradan yakalanır.
                # SERVICE_VULNERABILITY_MAP'te tanımlı ürünler (klasik CMS + 2026 AI/agentic
                # + niş kurumsal) küratörlü nuclei tag'leriyle taranır; haritada yoksa ama
                # bilinen web ürünüyse ürün-adı tag'i fallback. Böylece Metabase/Langflow/
                # TeamCity gibi 2026 yüzeyi de tespit edilir edilmez HEDEFLİ template alır.
                svc_tags = _nuclei_tags_for_service(product)
                classic = product in WEB_APP_SERVICES or product in (
                    "wordpress", "joomla", "drupal", "magento", "prestashop")
                if classic or svc_tags:
                    # Klasik CMS: ürün-adı tag'i (mevcut davranış korunur). 2026 yüzeyi
                    # (haritada olan ama klasik olmayan): küratörlü map tag'leri.
                    tags = [product] if classic else svc_tags
                    self.add_edge(Edge(
                        from_id=self.root_id, to_id=svc_node.id, tool="nuclei",
                        options={"tags": tags, "severity": list(DEFAULT_SEVERITY)},
                        cost=EDGE_COST_TABLE["nuclei-targeted"], success_prob=0.6,
                        rationale=f"{product} {version or ''} HTTP parmak iziyle tespit edildi "
                                  f"— {product}'e özel nuclei template'leriyle ({', '.join(tags[:4])}) "
                                  f"hedefli tarama.",
                        urgency=1.2,
                    ))
            # FEEDBACK LOOP (zincirleme): açık .env/config içindeki iç altyapı ipuçlarından
            # YENİ saldırı yüzeyi doğur. DB_HOST → yeni host node + nmap/pathprobe raid;
            # APP_URL/alt-uygulama tabanı → o tabanda yeni pathprobe; S3_BUCKET → açık depolama
            # notu. Tek bir .env bulgusu böylece "izole bulgu" değil, bir saldırı ZİNCİRİNİN
            # ilk halkası olur — sektörün yapmadığı katman budur (bulguyu istihbarata çevir).
            new_nodes.extend(self._pivot_from_sensitive_findings(pp_findings))

        elif tool == "reverse_ip":
            domains = result_data.get("domains") or result_data.get("co_hosted_domains") or []
            source = result_data.get("source", "reverse_ip")
            for d in domains:
                name = d.get("name") if isinstance(d, dict) else str(d)
                name = _canon_host(name)
                if not name or name == _canon_host(self.target):
                    continue
                host_node = self.add_node(Node(
                    id=f"host:reverse:{name}", type=NodeType.HOST, label=name,
                    value=NODE_VALUE_TABLE.get("static", DEFAULT_NODE_VALUE),
                    breach_prob=0.08, state=NodeState.DISCOVERED,
                    meta={"source": source, "discovered_via": "reverse_ip"},
                ))
                new_nodes.append(host_node)
                # cPanel/Plesk varsayılan kaydıysa recon/subfinder seed ETME (bütçe koruması)
                if _is_boilerplate_subdomain(name):
                    host_node.meta["boilerplate"] = True
                    continue
                # Keşfedilen her domain'e kendi recon + subfinder kenarını seed et
                # — "bu domain'de ne var?" sorusu sorulur.
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=host_node.id, tool="recon",
                    options={"scan_target": name},
                    cost=EDGE_COST_TABLE["recon"], success_prob=0.9,
                    rationale=f"Reverse-IP ile keşfedilen {name} domain'i parmak izle.",
                ))
                self.add_edge(Edge(
                    from_id=self.root_id, to_id=host_node.id, tool="subfinder",
                    options={"scan_target": name},
                    cost=EDGE_COST_TABLE["subfinder"], success_prob=0.75,
                    rationale=f"{name} domain'inde subdomain keşfi — saldırı yüzeyini "
                              f"genişlet (doktrin: her suru tek tek yokla).",
                ))
                # KRİTİK GÜVENLİK AĞI: unutulmuş yan domain'de açık .env/.git var mı?
                # Bug-bounty'de en sık raporlanan "basit" bulgu sınıfı budur; ana domain
                # sertleşmişken bakımsız co-hosted domain'lerde durur. Nuclei template'ine
                # muhtaç olmayan deterministik prob — her co-hosted host'a ŞART.
        # RAID GÜVENLİK AĞI: bu turda doğan HER host node'una (recon/subfinder/reverse_ip/
        # nmap/origin fark etmez) KOŞULSUZ pathprobe raid kenarı seed et. Böylece .env/.git
        # taraması artık tek tek dallara serpiştirilmiş "belki seed edilir" değil, host'un
        # varlığına bağlı GARANTİDİR. Co-hosted host'lar strict scope'ta yine onay bekler
        # (autonomous_engine _cohosted_blocked) — raid onların kenarını doğurur ama onaysız
        # SEÇİLMEZ; onaylanınca hemen çalışır. scan_target host label'ından türetilir.
        # İSTİSNA: cPanel/Plesk varsayılan kayıtları (boilerplate) raid'lenmez — aynı
        # sunucunun otomatik takma adıdır, adım bütçesini çöpe harcar.
        for n in new_nodes:
            # Bozuk (wildcard/vhost) host'a RAID SEED ETME — bu, 'Adım 49: musteri-a.com.
            # hosting-provider.com açık .env probu' türü boşa adımların doğduğu yerdi. Emniyet kemeri:
            # ingest'te elense de başka araçtan sızarsa burada da durdur.
            if (n.type == NodeType.HOST and not n.meta.get("boilerplate")
                    and not _is_malformed_subdomain(n.label)):
                # Kök hedefin kendisiyse (www farkı dahil) scan_target=None
                # (dispatcher self.target'ı tarar).
                st = None if _canon_host(n.label) == _canon_host(self.target) else n.label
                self._seed_pathprobe_raid(n.id, st, f"{n.label}")
                # FAZ 1 — her keşfedilen web host'una KOŞULSUZ crawl kenarı seed et (pathprobe
                # RAID'i ile AYNI mantık). Crawler aynı-host URL/form/JS toplar; bulduğu
                # parametreli endpoint'ler nuclei `-dast` için URL corpus'una beslenir. Bu
                # olmadan nuclei yalnız KÖK URL'i görür ve SQLi/XSS/SSRF/IDOR imzaları test
                # edilecek URL bulamazdı. signature: crawl + (scan_target varsa) — pathprobe'a
                # DAHİL DEĞİL; bağımsız kenar, bağımsız çalışma.
                crawl_opts: Dict[str, Any] = {}
                if st:
                    crawl_opts["scan_target"] = st
                self.add_edge(Edge(
                    from_id=n.id, to_id=n.id, tool="crawl", options=crawl_opts,
                    cost=EDGE_COST_TABLE["crawl"], success_prob=0.75,
                    rationale=(f"RAID-crawl: {n.label} — same-host URL/form/JS keşfi. "
                               f"Nuclei'nin kör kök-URL taramasını aşan endpoint'leri bulur; "
                               f"parametreli olanlar DAST tabanına eklenir."),
                    meta={"raid": True},
                ))

        return new_nodes

    # ---------- Öğrenme (doktrin §4.1) ----------

    def update_probabilities(self, edge: Edge, success: bool, evidence_found: bool):
        edge.tried_count += 1
        if not success:
            # C1 — beta-posterior backoff (ad-hoc "yarıya böl" yerine kanıt-sayaçlı Bayes).
            # İlk hatada prior'ı mevcut success_prob'tan tohumla (α=p·K, β=(1-p)·K); her hata
            # β'yı 1 artırır; yeni success_prob = α/(α+β). Yarılamadan daha yumuşak + kanıt-temelli
            # çürüme → geçici hata yolu ekonomik biçimde geri plana iter ama yıkıcı bastırmaz.
            if edge.alpha <= 0.0 and edge.beta <= 0.0:
                edge.alpha = max(0.01, edge.success_prob) * BETA_PRIOR_STRENGTH
                edge.beta = max(0.01, 1.0 - edge.success_prob) * BETA_PRIOR_STRENGTH
            edge.beta += 1.0
            edge.success_prob = max(0.01, edge.alpha / (edge.alpha + edge.beta))
            # GEÇİCİ HATA ≠ KALICI KENAR ÖLÜMÜ (A.1). timeout/bağlantı hatası çoğu zaman
            # GEÇİCİDİR (eş-zamanlı yük, yavaş hedef, servis anlık meşgul). Eskiden TEK hata
            # kenarı executed_signatures'a atıp novelty=0 + state="executed" yapıyordu → o
            # saldırı yolu SONSUZA DEK terk ediliyor, yük altında sessizce tespit kaybediliyordu.
            # Artık deneme tavanına kadar YENİDEN DENEMEYE açık kalır: state 'open', signature
            # eklenmez. success_prob yarıya indiği için skoru düşer (diğer kenarlar önce denenir),
            # ama yol tümden kapanmaz. Tavan (EDGE_MAX_RETRIES) dolunca aşağıda kalıcı kapanır.
            if edge.tried_count < EDGE_MAX_RETRIES:
                self.notes.append(
                    f"{edge.tool} geçici hata (deneme {edge.tried_count}/{EDGE_MAX_RETRIES}) "
                    f"— yol açık, yeniden denenecek."
                )
                return

        if evidence_found:
            to_node = self.nodes.get(edge.to_id)
            if to_node is not None:
                to_node.breach_prob = min(0.95, to_node.breach_prob + 0.2)
                # komşu (aynı from_id'den çıkan diğer) node'lar da gedik açıldığı için P_breach artar
                for e in self.edges.values():
                    if e.from_id == edge.to_id:
                        neighbor = self.nodes.get(e.to_id)
                        if neighbor is not None:
                            neighbor.breach_prob = min(0.95, neighbor.breach_prob + 0.2)

            # kritik CVE doğrulandıysa: ilgili node'a bağlı tüm açık kenarların urgency'si artar
            for e in self.edges.values():
                if e.state == "open" and (e.from_id == edge.to_id or e.to_id == edge.to_id):
                    e.urgency = min(3.0, e.urgency * 1.5)

        if edge.signature() in self.executed_signatures:
            edge.novelty = 0.0
        else:
            self.executed_signatures.add(edge.signature())
            edge.novelty = 0.0  # bu kenar artık denendi, tekrar aynı sinyaturla önerilirse değeri yok
        edge.state = "executed"

    def decisive_breach(self) -> bool:
        """Kuşatma bozuldu mu? Yalnız KANITLANMIŞ (confirmed/probable) critical/high bulgular
        'gedik' sayılır — doğrulanmamış sürüm-CVE'leri (unconfirmed) manşeti şişirmesin."""
        for e in self.evidence:
            if getattr(e, "severity", "").lower() not in ("critical", "high"):
                continue
            fn = getattr(e, "effective_confidence_tier", None)
            tier = fn() if callable(fn) else "unconfirmed"
            if tier in ("confirmed", "probable"):
                return True
        return False

    # ---------- Ollama prompt için özet ----------

    def compact_state(self) -> Dict[str, Any]:
        root = self.nodes[self.root_id]
        state = {
            "target": self.target,
            "target_is_ip": self.target_is_ip,
            "is_behind_cdn": root.meta.get("is_behind_cdn", False),
            "real_ip": root.meta.get("real_ip"),
            "technologies": root.meta.get("technologies", [])[:15],
            "open_ports": root.meta.get("open_ports", [])[:25],
            "subdomains": root.meta.get("subdomains", [])[:10],
            "endpoints": root.meta.get("endpoints", [])[:15],
            "evidence": [ev.to_dict() if hasattr(ev, "to_dict") else ev for ev in self.evidence[:10]],
            "notes": self.notes[-8:],
            "executed_tools": list(dict.fromkeys(sig.split(":")[0] for sig in self.executed_signatures)),
            "nodes": [
                {"id": n.id, "type": n.type.value, "label": n.label, "value": n.value,
                 "breach_prob": n.breach_prob, "state": n.state.value}
                for n in self.nodes.values() if n.id != self.root_id
            ][:30],
            # P0-A: endpoint sürüm-diff monitörünün kısa özeti. LLM bu bölümü
            # görürse "YENİ YÜZEY" ipucuyla öncelikli hipotez üretebilir.
            "endpoint_diff": root.meta.get("endpoint_diff") or {},
        }
        # L3 — HAM SALDIRI YÜZEYİ: LLM'in graf-özeti yerine GERÇEK hedefleri görmesi için.
        # Somut injectable endpoint'ler (kind+param), HTML formlar (gövde hedefi), OpenAPI
        # method+path matrisi ve GraphQL operasyonları — hipotez üretiminin ham maddesi.
        if LLM_RAW_SURFACE:
            state["injectable_endpoints"] = (root.meta.get("injectable_endpoints") or [])[:20]
            state["forms"] = (root.meta.get("forms") or [])[:12]
            state["openapi_endpoints"] = (root.meta.get("openapi_endpoints") or [])[:25]
            state["graphql_operations"] = (root.meta.get("graphql_operations") or [])[:25]
        return state

    # ---------- Özet (autonomous_engine.summary() ile aynı şema) ----------

    def summary(self) -> Dict[str, Any]:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ev = sorted(self.evidence, key=lambda e: sev_order.get(getattr(e, "severity", ""), 4))
        root = self.nodes[self.root_id]
        services = [n.label for n in self.nodes.values() if n.type == NodeType.SERVICE]

        # FALSE-POSITIVE ekseni: kanıtı güç kademesine göre ayır. Manşet sayımı (confirmed_*)
        # unconfirmed'ları (olası FP) HARİÇ tutar → "8 kritik!" yerine "2 kanıtlı kritik".
        def _tier(e: Any) -> str:
            fn = getattr(e, "effective_confidence_tier", None)
            return fn() if callable(fn) else "unconfirmed"
        tier_counts = {"confirmed": 0, "probable": 0, "unconfirmed": 0}
        for e in ev:
            t = _tier(e)
            tier_counts[t if t in tier_counts else "unconfirmed"] += 1
        _promoted = [e for e in ev if _tier(e) in ("confirmed", "probable")]
        # KRİTİK/YÜKSEK MANŞETİ tier-farkında: unconfirmed (olası FP) bulgular kritik sayılmaz,
        # ayrı 'incelenmeli' kovasında (needs_review_count) kalır. Kurumsal raporda
        # "8 kritik!" değil "2 kanıtlı kritik" — doğrulanmamış sürüm-CVE manşeti şişirmez.
        critical_count = sum(1 for e in _promoted if getattr(e, "severity", "") == "critical")
        high_count = sum(1 for e in _promoted if getattr(e, "severity", "") == "high")

        # APT KILL-CHAIN (Faz 2): izole bulgu+servisleri ATT&CK saldırı zincirine diz.
        # Gözlemler = kanıtlar + servis düğümleri (keşif/ilk-erişim halkaları). SAF kompozisyon.
        kill_chain = self._compose_kill_chain(ev)

        return {
            "target": self.target,
            "open_ports": len(root.meta.get("open_ports", [])),
            "services_identified": services,
            "subdomains_found": len(root.meta.get("subdomains", [])),
            "endpoints_found": len(root.meta.get("endpoints", [])),
            "verified_vulnerabilities": [e.to_dict() for e in ev],
            "vulnerability_count": len(ev),
            "critical_count": critical_count,
            "high_count": high_count,
            # Kademe dağılımı + MANŞET (yalnız confirmed+probable) — UI/rapor FP'yi ayırsın.
            # critical/high yalnız kanıtlı+olası bulguları sayar (unconfirmed 'incele'de kalır).
            "tier_counts": tier_counts,
            # Geri-uyumluluk için aynı değerin ikiz anahtarı: 'confirmed_critical_count'
            # artık critical_count ile AYNI (critical_count zaten kanıtlı+olası kesitini sayıyor).
            "confirmed_critical_count": critical_count,
            "confirmed_high_count": high_count,
            "needs_review_count": tier_counts["unconfirmed"],
            # NEDEN medium/low de sayılır: özet kartı yalnız kritik+yüksek gösterirse, tek
            # bulgusu medium/low olan taramalar "0 kritik / 0 yüksek" ile TAMAMEN boş görünüp
            # "hiçbir şey bulunamadı" izlenimi veriyordu — oysa kanıtlı zafiyet vardı. Tüm
            # şiddet seviyeleri sayılır ki UI bulunan zafiyeti sayısal olarak da yansıtabilsin.
            "medium_count": sum(1 for e in ev if getattr(e, "severity", "") == "medium"),
            "low_count": sum(1 for e in ev if getattr(e, "severity", "") == "low"),
            # Kanıtlanmış açık ÇIKMASA bile (kullanıcının senaryosu) "detaylı incelenmesi
            # gereken maddeler": yüksek-değerli/sürümlü/web-yüzeyli varlıklar. Bunlar zafiyet
            # İDDİASI DEĞİL — analistin manuel bakması önerilen dikkat noktalarıdır. UI bunları
            # "açık yok" yerine gösterir → tarama boş görünmez, doğru yolda olunduğu belli olur.
            "attention_items": self.attention_items(),
            # Kanıt düzeyine ULAŞMAYAN ama raporlanması gereken bulgular (eksik güvenlik
            # başlıkları + NVD sürüm-eşleşmeli doğrulanamamış CVE adayları). verified'tan
            # AYRI: zafiyet iddiası değil, 'incele' listesi — 'boş tarama' hissini kırar.
            "informational_findings": self.informational_findings(),
            # APT saldırı zinciri: ATT&CK-eşlemeli, hedefe yönelen kompozisyon + anlatı.
            "kill_chain": kill_chain,
            # IPB — hedef profili + playbook (UI "hangi sistem" kartı; tamamlanmış/yeniden
            # açılan taramada canlı olay kaybolsa bile summary'den okunur).
            "target_profile": root.meta.get("target_profile"),
            "playbook": root.meta.get("playbook"),
            "success": len(ev) > 0,
        }

    def _node_observation(self, node: "Node") -> Dict[str, Any]:
        """Bir düğümü killchain.classify_ttp'nin okuyacağı gözlem dict'ine çevir (SAF)."""
        meta = node.meta or {}
        label = getattr(node, "label", "") or ""
        matched = meta.get("matched_service") or (label.split("@")[0] if "@" in label else "")
        cat = _SERVICE_VALUE_CATEGORY.get(matched, "")
        cves = meta.get("cves") or []
        return {
            "kind": node.type.value, "service": matched, "category": cat,
            "title": label, "tool": meta.get("source") or "",
            "cve": (cves[0] if cves else None), "cwe": meta.get("cwe") or [],
        }

    def _killchain_drive_boost(self, edge: "Edge") -> float:
        """OBJECTIVE-DRIVEN APT (Faz 2b): kill-chain'de DAHA DERİN faza yönelen kenarları
        önceliklendir. Hedef düğümün ATT&CK faz ağırlığı ne kadar yüksekse (lateral/impact
        > keşif) çarpan o kadar büyük. Çarpan DAİMA ≥ 1.0 → hiçbir kenarı eşik altına İTMEZ
        (yalnız sıralamayı derinliğe kaydırır) → mevcut motoru bozmaz, sadece 'zinciri kovalar'.
        AUTONOMOUS_KILLCHAIN_DRIVE=0 ile kapatılır; bonus AUTONOMOUS_KILLCHAIN_BONUS (vars. 0.5)."""
        if os.getenv("AUTONOMOUS_KILLCHAIN_DRIVE", "1") != "1":
            return 1.0
        try:
            from .killchain import classify_ttp, _PHASE_WEIGHT, PHASE_ORDER
            to_node = self.nodes.get(edge.to_id)
            if to_node is None:
                return 1.0
            tactic = classify_ttp(self._node_observation(to_node)).tactic
            w = _PHASE_WEIGHT.get(tactic, 1.0)
            max_w = max(x[2] for x in PHASE_ORDER) or 1.0
            bonus = float(os.getenv("AUTONOMOUS_KILLCHAIN_BONUS", "0.5"))
            return 1.0 + bonus * (w / max_w)
        except Exception:
            return 1.0

    def _compose_kill_chain(self, evidence_sorted: List[Any]) -> Dict[str, Any]:
        """Kanıt + servis düğümlerinden APT kill-chain'i kompoze et (SAF köprü).
        killchain.compose_killchain'e normalize gözlem listesi verir. Hata halinde boş
        zincir döner (rapor/özet ASLA düşmez — doktrin)."""
        try:
            from .killchain import compose_killchain
            observations: List[Dict[str, Any]] = []
            # 1) Kanıtlar (sürüm-CVE, ifşa, sır, enjeksiyon...) — güç kademeli
            for e in evidence_sorted:
                d = e.to_dict() if hasattr(e, "to_dict") else dict(e)
                observations.append({
                    "kind": "evidence", "tool": d.get("tool"),
                    "category": d.get("fp_reason") or "",  # sadece bilgi; sınıflama title/cwe'den
                    "cwe": d.get("cwe"), "title": d.get("title"),
                    "severity": d.get("severity"), "confidence_tier": d.get("confidence_tier"),
                    "target": d.get("target"), "cve": d.get("cve"),
                })
            # 2) Servis düğümleri (keşif/ilk-erişim/yanal halkaları) — kanıt olmasa da zincir kurar
            for n in self.nodes.values():
                if n.type != NodeType.SERVICE:
                    continue
                matched = n.meta.get("matched_service") or n.label.split("@")[0]
                cat = _SERVICE_VALUE_CATEGORY.get(matched, "")
                observations.append({
                    "kind": "service", "tool": "nmap", "service": matched, "category": cat,
                    "title": n.label, "severity": "info",
                    "confidence_tier": "probable",  # servis varlığı deterministik gözlem
                    "value": n.value, "breach_prob": n.breach_prob,
                    "target": f"{self.target}:{n.meta.get('port')}" if n.meta.get("port") else self.target,
                })
            return compose_killchain(observations).to_dict()
        except Exception as e:
            logger.debug(f"Kill-chain kompozisyonu atlandı: {e}")
            return {"links": [], "score": 0.0, "objective": "", "narrative": "", "techniques": [], "depth": 0}

    def attention_items(self) -> List[Dict[str, Any]]:
        """Kanıtlanmamış ama incelenmeye değer varlıklar — 'boş sonuç' hissini önler.

        Kaynak: graf düğümleri. Zafiyet iddiası içermez; her madde neden dikkat
        çektiğini (yüksek değer / sürüm bilgisi / web yüzeyi) `reason` ile söyler."""
        items: List[Dict[str, Any]] = []
        web_present = False
        for n in self.nodes.values():
            if n.type != NodeType.SERVICE:
                continue
            # KÖK DÜZELTME: kategori artık DEĞER SKORUNDAN değil, servisin GERÇEK KİMLİĞİNDEN
            # türetilir (nginx→web, ssh→remote-mgmt, 3306→database). Eskiden value>=eşik ile
            # tahmin ediliyordu; web-app boost'u database eşiğini geçince nginx "veritabanı,
            # kritik" görünüyordu (kredibilite katili).
            category, severity, reason = _service_attention(n)
            if category in ("web-app", "api", "auth-endpoint"):
                web_present = True
            version = str((n.meta or {}).get("version") or "")
            product = str((n.meta or {}).get("product") or "")
            detail = product.strip()
            if version:
                detail = f"{detail} {version}".strip()
                # Sürüm bilgisi VARSA manuel CVE incelemesi için değerli bir ipucu
                reason = f"{reason} — sürüm tespit edildi ({detail}), bilinen CVE'ler için incelenmeli"
            items.append({
                "label": n.label,
                "detail": detail or n.label,
                "port": (n.meta or {}).get("port"),
                "severity": severity,
                "reason": reason,
            })
        # Web yüzeyi tespit edildiyse (IP hedefte framework bilinmese de) not düş
        if web_present:
            items.append({
                "label": "Web yüzeyi",
                "detail": "Açık HTTP/HTTPS servisi",
                "port": None,
                "severity": "medium",
                "reason": "Açık dosya (.env/.git), yedek, panel ve varsayılan parola için "
                          "web yüzeyi taranmalı — legacy/PHP uygulamalarında en sık bulgu sınıfı",
            })
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(key=lambda i: sev_order.get(i["severity"], 4))
        return items

    def informational_findings(self) -> List[Dict[str, Any]]:
        """Kanıt düzeyine ULAŞMAYAN ama raporlanması gereken bulgular — verified'tan AYRI.

        İki kaynak, ikisi de toplanıp ama eskiden hiç raporlanmıyordu ('boş tarama' hissinin
        bir nedeni):
          1) Düşük-şiddet/bilgi VULNERABILITY düğümleri (ör. eksik güvenlik başlıkları).
          2) NVD sürüm-eşleşmesiyle bulunmuş ama aktif KANITLANAMAYAN CVE adayları. nuclei
             template ile tetiklenir; Ubuntu backport gibi durumlarda tetiklenemez → burada
             'aday' olarak kalır (sürüm zafiyetli GÖRÜNÜYOR ama PoC yok).
        Zafiyet İDDİASI DEĞİL — 'incele' listesi. AKTİF doğrulanmış CVE'ler (evidence) HARİÇ
        (çift sayma yok)."""
        verified_cves = {getattr(e, "cve", None) for e in self.evidence if getattr(e, "cve", None)}
        out: List[Dict[str, Any]] = []
        for n in self.nodes.values():
            if n.type != NodeType.VULNERABILITY:
                continue
            meta = n.meta or {}
            ev_meta = n.evidence if isinstance(getattr(n, "evidence", None), dict) else {}
            sev = str(meta.get("severity") or ev_meta.get("severity") or "").lower()
            cves = meta.get("cves") or ([meta["cve"]] if meta.get("cve") else [])
            # Zaten AKTİF kanıtlanmış CVE'yi tekrar 'aday' gösterme.
            if cves and any(c in verified_cves for c in cves):
                continue
            source = str(meta.get("source") or ev_meta.get("type") or "")
            is_nvd_candidate = source == "nvd" and bool(cves)
            is_info = sev in ("info", "low")
            if not (is_nvd_candidate or is_info):
                continue
            out.append({
                "label": n.label,
                "severity": sev or "info",
                "cve": cves[0] if cves else None,
                "source": source or "graph",
                "detail": (", ".join(meta["missing_headers"]) if meta.get("missing_headers")
                           else str(meta.get("description") or meta.get("category") or "")[:200]),
                "note": ("NVD sürüm eşleşmesi — aktif PoC ile doğrulanamadı, manuel inceleyin"
                         if is_nvd_candidate else "Bilgi/ifşa — düşük şiddet, manuel inceleyin"),
            })
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        out.sort(key=lambda i: order.get(i["severity"], 5))
        return out[:50]


# ============================================================
# Yardımcı fonksiyonlar — SERVICE_VULNERABILITY_MAP köprüsü
# ============================================================

# Güvenlik başlıkları seti: her biri eksik olduğunda info seviyesinde bir bulgu üretir.
_SECURITY_HEADERS: List[Tuple[str, str]] = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
]


def _analyze_security_headers(graph, result_data: Dict[str, Any]) -> List[Node]:
    """Türkçe: Recon'dan gelen HTTP başlıklarında eksik güvenlik başlıklarını
    tespit edip graf'a VULNERABILITY node'u olarak ekler. Dış tarama ürünlerinde
    en sık görülen 'tarama boş/eksik' şikayetlerinden birinin kaynağı: bu bilgiler
    toplanır ama raporlanmaz.

    NOT (kritik): Bu fonksiyon MODÜL SEVİYESİNDE olmalı. Daha önce yanlışlıkla
    Graph sınıfının GÖVDESİNE sütun-0 girintiyle konmuştu; bu, sınıfı erkenden
    kapatıp `integrate` ve sonraki tüm metotları sınıftan düşürüyordu →
    'Graph' object has no attribute 'integrate' ile TÜM otonom tarama çöküyordu."""
    headers = result_data.get("http_headers") or {}
    if not isinstance(headers, dict) or not headers:
        return []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    missing = [label for key, label in _SECURITY_HEADERS if key not in headers_lower]
    if not missing:
        return []
    score = int(((len(_SECURITY_HEADERS) - len(missing)) / len(_SECURITY_HEADERS)) * 100)
    vuln_id = f"{graph.root_id}:missing-security-headers"
    vuln_node = graph.add_node(Node(
        id=vuln_id,
        type=NodeType.VULNERABILITY,
        label="Eksik güvenlik başlıkları",
        value=15.0,
        breach_prob=0.1,
        state=NodeState.DISCOVERED,
        evidence={
            "tool": "recon",
            "type": "missing_security_headers",
            "missing": missing,
            "score": score,
            "severity": "info",
        },
        meta={"severity": "info", "missing_headers": missing, "score": score},
    ))
    graph.add_edge(Edge(
        from_id=graph.root_id,
        to_id=vuln_id,
        tool="recon",
        state="executed",
        cost=EDGE_COST_TABLE["recon"],
        success_prob=0.9,
        rationale=f"Recon HTTP başlıklarında eksik güvenlik başlıkları tespit edildi: {', '.join(missing)}",
    ))
    return [vuln_node]


def _url_path_base(url: str) -> Optional[str]:
    """Bir URL'den uygulama taban path'ini çıkar (.env pivot için).

    'https://x.com/app' → '/app'; 'https://x.com/' → None (kök zaten prob'lanıyor);
    'https://x.com' → None. Yalnız kökten farklı, anlamlı bir alt-taban varsa döner —
    böylece .env'i 'x.com/app/.env' gibi alt-tabanlarda da arayabiliriz (Delik 5)."""
    if not url or not isinstance(url, str):
        return None
    import re as _re
    m = _re.sub(r"^\w+://", "", url.strip()).strip("'\"")
    parts = m.split("/", 1)
    if len(parts) < 2:
        return None
    path = "/" + parts[1].split("?")[0].split("#")[0].rstrip("/")
    # Kök veya tek '/' ise pivot değeri yok.
    if path in ("/", ""):
        return None
    return path[:100]


def _canon_host(name: str) -> str:
    """Host kanonikleştirme: şema/path/port atılır, küçük harf, 'www.' öneki düşer.

    'https://www.blog.x.com/a' → 'blog.x.com'. Böylece www.'lu/www.'suz aynı host
    TEK varlık sayılır — aksi halde her co-hosted/subdomain keşfinde aynı sunucu iki
    kez doğar, her bulgu iki kez kanıtlanır ve saldırı yüzeyi şişer (örnek vaka:
    blog.X ile www.blog.X ayrı host sayılıp tüm pathprobe/nuclei bulguları çiftlendi).
    IP'ler ve 'www'suz isimler olduğu gibi döner."""
    if not name or not isinstance(name, str):
        return ""
    import re as _re
    h = name.strip().lower()
    h = _re.sub(r"^\w+://", "", h)
    h = h.split("/")[0].split("?")[0].split("@")[-1].split(":")[0].strip(".")
    if h.startswith("www."):
        h = h[4:]
    return h


def _canon_url(url: str) -> str:
    """Dedup parmak izi için URL kanonikleştirme: kanonik host + path (+query korunur,
    çünkü ?action=postpass gibi sorgu bulguyu ayırt eder), sondaki '/' düşer."""
    if not url or not isinstance(url, str):
        return ""
    u = url.strip().lower()
    import re as _re
    u = _re.sub(r"^\w+://", "", u)
    host, sep, rest = u.partition("/")
    host = _canon_host(host)
    rest = rest.rstrip("/")
    return f"{host}/{rest}" if (sep and rest) else host


def _normalize_str_list(items: Any) -> List[str]:
    """Karışık liste (string / {'name':...} dict / diğer) → temiz string listesi.

    Recon, subfinder gibi servisler alanları bazen düz string, bazen dict döndürür.
    Bu değerler graf meta'sına yazılıp `dict.fromkeys`/`set` ile tekilleştirildiğinde
    dict hashlenemez → tüm tarama patlardı. Burada güvenli düzleştirme yapılır."""
    out: List[str] = []
    if not isinstance(items, list):
        items = [items] if items else []
    for it in items:
        if isinstance(it, str):
            name = it.strip()
        elif isinstance(it, dict):
            name = str(it.get("name") or it.get("tech") or it.get("value") or "").strip()
        else:
            name = str(it).strip() if it is not None else ""
        if name:
            out.append(name)
    return out


def _node_value_for_service(svc_name: str) -> float:
    category = _SERVICE_VALUE_CATEGORY.get(svc_name, "web-app")
    return NODE_VALUE_TABLE.get(category, DEFAULT_NODE_VALUE)


def _node_breach_prob_for_service(svc_name: str, version: str) -> float:
    from .adaptive_scanner import SERVICE_VULNERABILITY_MAP
    info = SERVICE_VULNERABILITY_MAP.get(svc_name, {})
    base = info.get("risk_factor", 5) / 10.0
    for ver_pattern in info.get("critical_versions", {}):
        if ver_pattern and ver_pattern in version:
            return min(0.95, base + 0.3)
    return base


def _critical_versions_for_service(svc_name: str) -> Dict[str, List[str]]:
    from .adaptive_scanner import SERVICE_VULNERABILITY_MAP
    return SERVICE_VULNERABILITY_MAP.get(svc_name, {}).get("critical_versions", {})


def _nuclei_tags_for_service(svc_name: str) -> List[str]:
    """SERVICE_VULNERABILITY_MAP'ten servise özel nuclei tag'lerini döner.
    Bilinmeyen servis için boş liste — motor bu durumda nuclei AÇMAZ (kör tarama yok)."""
    from .adaptive_scanner import SERVICE_VULNERABILITY_MAP
    return list(SERVICE_VULNERABILITY_MAP.get(svc_name, {}).get("nuclei_tags", []))


def _collect_evidence(data: Dict[str, Any], tool: str, target: str) -> List[Tuple[Any, str]]:
    """Nuclei bulgularını KANIT olarak topla — autonomous_engine.Evidence kullanır.
    Döner: (Evidence, dedup_parmak_izi) çiftleri. Parmak izi = template_id + kanonik URL;
    aynı template aynı adreste birden çok kenardan tetiklense bile tek bulgu sayılır."""
    from .autonomous_engine import Evidence

    out: List[Tuple[Any, str]] = []
    findings = data.get("findings") or data.get("vulnerabilities") or []
    for f in findings:
        info = f.get("info", {}) if isinstance(f, dict) else {}
        sev = (info.get("severity") or f.get("severity") or "info").lower()
        if sev in ("info", "unknown"):
            continue
        name = info.get("name") or f.get("name") or f.get("template-id") or "Zafiyet"
        matched = f.get("matched-at") or f.get("matched_at") or f.get("host") or target
        template_id = f.get("template-id") or f.get("template_id") or name
        cve = None
        classification = info.get("classification", {}) if isinstance(info, dict) else {}
        cve_ids = classification.get("cve-id") or classification.get("cve_id")
        if cve_ids:
            cve = cve_ids[0] if isinstance(cve_ids, list) else cve_ids
        cwe = classification.get("cwe-id") if isinstance(classification, dict) else None

        # --- KANIT: bulguyu tetikleyen HAM HTTP alışverişi (nuclei -irr ile gelir) ---
        # Alan yoksa None kalır (araç -irr desteklemiyor/kapalı) → template-id kanıtına düşülür.
        req = f.get("request")
        resp = f.get("response")
        curl = f.get("curl-command") or f.get("curl_command")
        extracted = f.get("extracted-results") or f.get("extracted_results")
        if not isinstance(extracted, list):
            extracted = [str(extracted)] if extracted else None

        # proof özeti: ham kanıt varsa onu işaret et, yoksa eski davranış (template-id).
        # FALSE-POSITIVE notu: CVE var ama etkileşim kanıtı (istek/yanıt) YOKSA bu bulgu
        # büyük olasılıkla SÜRÜM/BANNER'dan çıkarıldı — istismar edilmedi. Backport'lu/
        # yamalı sürümde false-positive'dir; rapor bunu "unconfirmed" kademesinde gösterir.
        if req or resp:
            proof = (f"KANITLI — nuclei template '{template_id}' @ {matched} "
                     f"tetiklendi; ham istek/yanıt kanıt ekinde.")
        elif cve:
            proof = (f"nuclei template: {template_id} @ {matched} — CVE {cve} SÜRÜM/BANNER'dan "
                     f"çıkarıldı (aktif istismar KANITI yok; backport'lu sürümde false-positive "
                     f"olabilir, doğrulanmalı).")
        else:
            proof = f"nuclei template: {template_id} @ {matched}"

        # FAZ 1.2: MITRE ATT&CK / APT / CVSS zenginleştirme.
        # Öncelik nuclei classification (template'in kendi metadata'sı); eksikse CVE üzerinden
        # SERVICE_VULNERABILITY_MAP'teki tehdit-aktörü/teknik bilgisiyle tamamlanır.
        cwe_list = cwe if isinstance(cwe, list) else ([cwe] if cwe else [])
        techniques = classification.get("mitre") or classification.get("attack-technique") or []
        if isinstance(techniques, str):
            techniques = [techniques]
        cvss = None
        for _k in ("cvss-score", "cvss_score", "cvss-metrics"):
            _v = classification.get(_k) if isinstance(classification, dict) else None
            if isinstance(_v, (int, float)):
                cvss = float(_v)
                break
        apt_groups, map_tech = _threat_intel_for_cve(cve)
        for t in map_tech:
            if t not in techniques:
                techniques.append(t)
        poc = None
        if cve:
            poc = f"https://www.exploit-db.com/search?cve={cve}"  # REFERANS (kanıt değil)

        # FALSE-POSITIVE (P2): eşleşmenin "kanıtı" aslında bir WAF engel / giriş duvarı /
        # genel hata sayfası mı? nuclei bu sayfalardaki anahtar kelimeyi eşleyip "bulgu"
        # üretebilir (klasik FP). Yakalanan ham yanıtı deterministik sınıfla; öyleyse bulguyu
        # açıkça 'unconfirmed'a çek + neden'ini fp_reason'a yaz (yalnız DEMOTE — asla yükseltmez).
        fp_reason = None
        tier_override = None
        try:
            from .fp_signals import classify_response_page
            page_kind = classify_response_page(resp if isinstance(resp, str) else None)
        except Exception:
            page_kind = None
        if page_kind:
            fp_reason = page_kind
            tier_override = "unconfirmed"
            proof += (f" | ⚠️ FALSE-POSITIVE sinyali: yakalanan yanıt bir "
                      f"'{page_kind}' sayfasına benziyor — bulgu içeriği değil; doğrulanmalı.")

        out.append((Evidence(
            title=name, severity=sev, cve=cve, target=str(matched),
            proof=proof, tool=tool, step=0,
            mitre=(techniques[0] if techniques else (cwe_list[0] if cwe_list else None)),
            request=_clip_proof(req), response=_clip_proof(resp),
            curl=curl if isinstance(curl, str) else None,
            extracted=extracted[:20] if extracted else None,
            attack_techniques=techniques, apt_groups=apt_groups,
            cwe=[str(c) for c in cwe_list], cvss_v3=cvss, poc_url=poc,
            confidence_tier=tier_override, fp_reason=fp_reason,
        ), f"nuclei|{template_id}|{_canon_url(str(matched))}"))
    return out


def _threat_intel_for_cve(cve: Optional[str]) -> Tuple[List[str], List[str]]:
    """Bir CVE'yi SERVICE_VULNERABILITY_MAP üzerinden tehdit-aktörü ve ATT&CK tekniğine bağlar.
    Döner: (apt_groups, attack_techniques). Eşleşme yoksa iki boş liste — regresyon yok."""
    if not cve:
        return [], []
    try:
        from .adaptive_scanner import SERVICE_VULNERABILITY_MAP
    except Exception:
        return [], []
    cve_up = cve.upper()
    for _svc, info in SERVICE_VULNERABILITY_MAP.items():
        for _ver, cves in (info.get("critical_versions") or {}).items():
            if any(cve_up == str(c).upper() for c in cves):
                return list(info.get("apt_groups", [])), list(info.get("attack_techniques", []))
    return [], []


def _clip_proof(v: Any, limit: int = 8000) -> Optional[str]:
    """Ham istek/yanıtı MongoDB dokümanını şişirmeyecek boyuta kırpar (kanıt niteliği korunur)."""
    if not v or not isinstance(v, str):
        return None
    return v if len(v) <= limit else v[:limit] + "\n...[kırpıldı]"


# ============ Standalone Test ============

if __name__ == "__main__":
    def _assert(cond, msg):
        status = "OK " if cond else "FAIL"
        print(f"[{status}] {msg}")
        if not cond:
            raise SystemExit(1)

    # 1) Graf büyümesi
    g = Graph(target="example.com", target_is_ip=False)
    frontier = g.expand_frontier()
    _assert(any(e.tool == "recon" for e in frontier), "seed: recon kenari var")
    _assert(any(e.tool == "subfinder" for e in frontier), "seed: subfinder kenari var (domain)")

    nmap_data = {"ports": [
        {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"},
    ]}
    new_nodes = g.integrate(None, nmap_data, "nmap")
    _assert(any(n.type == NodeType.SERVICE for n in new_nodes), "integrate: nmap -> service node")
    vuln_nodes = [n for n in g.nodes.values() if n.type == NodeType.VULNERABILITY]
    _assert(len(vuln_nodes) == 1 and vuln_nodes[0].label == "CVE-2021-41773",
            "integrate: kritik CVE node dogru uretildi")
    cve_edge = next(e for e in g.edges.values() if e.to_id.startswith("vuln:"))
    _assert(cve_edge.cost == EDGE_COST_TABLE["nuclei-targeted"], "integrate: CVE dogrulama edge cost dogru")

    # 2) Skorlama siralamasi
    g2 = Graph(target="1.2.3.4", target_is_ip=True)
    db_node = g2.add_node(Node(id="svc:db", type=NodeType.SERVICE, label="db", value=90, breach_prob=0.9))
    static_node = g2.add_node(Node(id="svc:static", type=NodeType.SERVICE, label="static", value=10, breach_prob=0.9))
    e_db = Edge(from_id=g2.root_id, to_id=db_node.id, tool="nuclei", cost=20, success_prob=0.8)
    e_static = Edge(from_id=g2.root_id, to_id=static_node.id, tool="nuclei", cost=20, success_prob=0.8)
    _assert(siege_score(e_db, g2) > siege_score(e_static, g2), "skorlama: yuksek value daha yuksek skor")

    e_cheap = Edge(from_id=g2.root_id, to_id=db_node.id, tool="osint", cost=5, success_prob=0.8)
    e_expensive = Edge(from_id=g2.root_id, to_id=db_node.id, tool="fuzz", cost=60, success_prob=0.8)
    _assert(siege_score(e_cheap, g2) > siege_score(e_expensive, g2), "skorlama: dusuk cost daha yuksek skor")

    # 3) Ogrenme
    e_test = Edge(from_id=g2.root_id, to_id=db_node.id, tool="nmap", cost=25, success_prob=0.8)
    g2.add_edge(e_test)
    prob_before = e_test.success_prob
    g2.update_probabilities(e_test, success=False, evidence_found=False)
    _assert(e_test.success_prob == prob_before * 0.5, "ogrenme: basarisiz edge success_prob yariya indi")

    neighbor = g2.add_node(Node(id="svc:neighbor", type=NodeType.SERVICE, label="neighbor", value=50, breach_prob=0.3))
    g2.add_edge(Edge(from_id=db_node.id, to_id=neighbor.id, tool="nuclei", cost=20))
    prob_neighbor_before = neighbor.breach_prob
    e_breach = Edge(from_id=g2.root_id, to_id=db_node.id, tool="nuclei", cost=20)
    g2.add_edge(e_breach)
    g2.update_probabilities(e_breach, success=True, evidence_found=True)
    _assert(neighbor.breach_prob == min(0.95, prob_neighbor_before + 0.2), "ogrenme: komsu breach_prob +0.2")

    sig = e_breach.signature()
    _assert(sig in g2.executed_signatures, "ogrenme: tekrar -> executed_signatures'a eklendi")
    _assert(e_breach.novelty == 0.0, "ogrenme: tekrar -> novelty 0")

    print("\nTum testler basarili.")
