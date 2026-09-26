"""
Kadim Güvenlik — Hedef Profili / IPB (Intelligence Preparation of the Battlefield)
==================================================================================
Türkçe: "Önce düşmanı tanı." Savaşta hedefi tanımadan kuvvet sürmek yenilgidir; taramada da
körü körüne her aracı çalıştırmak (a) boşa gürültü → WAF/IDS bizi kesip taramayı düşürür,
(b) ilgisiz bulgu → false-positive gürültüsü, (c) motor büyüdükçe her tarama şişer.

Bu modül hedefin YAPILANDIRILMIŞ bir istihbarat resmini (TargetProfile) çıkarır: altyapı
(classic/cloud/kubernetes), web yığını (dil/framework/sunucu), uygulama tipi (spa/api/
server-rendered/static), savunma (waf/auth). Bu resim playbook.py'ın "hangi saldırı
gerekli, hangisi GEREKSİZ" kararını beslemesi içindir → bilinçli, gerekli saldırı.

Tasarım (path_probe/service_probes deseni): fingerprint ÇEKİRDEĞİ SAF (stdlib + regex) →
izole test. Girdi olarak MOTORUN ZATEN TOPLADIĞI kanıtı (header/cookie/gövde/portlar) alır;
mümkün olduğunca YENİ istek üretmez (verimlilik + gizlilik doktrini). Wappalyzer mantığı:
çok sayıda zayıf sinyal "noisy-OR" ile birleşip güven üretir. Sinyal tabloları küratörlü ve
GENİŞLETİLEBİLİR (kanon değil — yeni imza eklemek serbest).

Boyutlar (dimension): language | framework | server | infra | cloud | app_type | waf | auth_type
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ============================================================
# Sinyal tabloları — (needle/regex, dimension, value, weight 0..1)
# ============================================================
# Header eşleşmesi: "ad: değer" küçük-harf metnine substring bakılır.
_HEADER_SIGNALS: List[Tuple[str, str, str, float]] = [
    # Sunucu
    ("server: nginx", "server", "nginx", 0.9),
    ("server: apache", "server", "apache", 0.9),
    ("server: microsoft-iis", "server", "iis", 0.9),
    ("microsoft-iis", "language", "dotnet", 0.5),
    ("server: caddy", "server", "caddy", 0.9),
    ("server: openresty", "server", "openresty", 0.85),
    ("server: cloudflare", "waf", "cloudflare", 0.75),
    ("server: cloudflare", "cdn", "cloudflare", 0.9),
    # Dil / framework
    ("x-powered-by: php", "language", "php", 0.95),
    ("x-powered-by: express", "framework", "express", 0.9),
    ("x-powered-by: express", "language", "node", 0.85),
    ("x-powered-by: next.js", "framework", "nextjs", 0.9),
    ("x-powered-by: next.js", "language", "node", 0.8),
    ("x-powered-by: asp.net", "language", "dotnet", 0.9),
    ("x-aspnet-version", "language", "dotnet", 0.9),
    ("x-aspnetmvc-version", "framework", "aspnetmvc", 0.8),
    ("x-powered-by: servlet", "language", "java", 0.8),
    ("x-runtime", "language", "ruby", 0.55),          # Rails sık X-Runtime döner
    ("x-drupal-cache", "framework", "drupal", 0.9),
    ("x-drupal-cache", "language", "php", 0.8),
    ("x-generator: drupal", "framework", "drupal", 0.9),
    ("x-powered-by: plesk", "server", "plesk", 0.6),
    # Cloud sağlayıcı (header sızıntısı)
    ("x-amz-cf-id", "cloud", "aws", 0.85),
    ("x-amz-request-id", "cloud", "aws", 0.7),
    ("cloudfront", "cloud", "aws", 0.8),          # Via: 1.1 <id>.cloudfront.net (CloudFront)
    ("x-azure-ref", "cloud", "azure", 0.85),
    ("x-msedge-ref", "cloud", "azure", 0.8),
    ("x-goog-", "cloud", "gcp", 0.8),
    ("x-served-by: cache", "cdn", "fastly", 0.5),
    # WAF
    ("x-sucuri-id", "waf", "sucuri", 0.85),
    ("x-akamai", "cdn", "akamai", 0.8),
    ("cf-ray", "waf", "cloudflare", 0.7),
    # Auth tipi
    ("www-authenticate: bearer", "auth_type", "bearer", 0.7),
    ("www-authenticate: basic", "auth_type", "basic", 0.8),
    # Rancher / Kubernetes (K8s portları firewall arkasındaysa WEB imzası tek kanıt —
    # aksi halde RKE2/Rancher hedefi "sinyal yok" diye genel taramaya düşer)
    ("x-api-cattle-auth", "framework", "rancher", 0.95),   # Norman API kesin imza
    ("x-api-cattle-auth", "infra", "kubernetes", 0.9),
    ("x-api-schemas", "framework", "rancher", 0.6),        # Norman API schemas linki
    ("x-rancher", "framework", "rancher", 0.8),            # X-Rancher-* header ailesi
    ("x-rancher", "infra", "kubernetes", 0.7),
    ("audit-id", "infra", "kubernetes", 0.5),              # kube-apiserver denetim header'ı
    # SharePoint / TeamCity (P3 — deserialization probe fingerprint yüzeyi)
    ("x-sharepointhealthscore", "framework", "sharepoint", 0.95),
    ("microsoftsharepointteamservices", "framework", "sharepoint", 0.9),
    ("sprequestguid", "framework", "sharepoint", 0.85),
    ("x-teamcity-node-id", "framework", "teamcity", 0.9),
    # 2026 cephesi — AI/agentic + niş kurumsal yönetim düzlemi (header imzaları). Bunlar
    # playbook'un "bu hedefte ne saldırı gerekli" kararını besler; asıl CVE zinciri
    # path_probe _MODERN_STACK_SIGNATURES'tan gider (SERVICE node → nuclei/KEV/NVD).
    ("x-langflow", "framework", "langflow", 0.9),
    ("x-jenkins", "framework", "jenkins", 0.9),
    ("x-gitlab", "framework", "gitlab", 0.85),
    ("kbn-version", "framework", "kibana", 0.9),
    ("kbn-name", "framework", "kibana", 0.8),
    ("x-confluence-request-time", "framework", "confluence", 0.85),
    # Savunma cihazı / firewall-in-front (pfSense, OPNsense, embedded appliance). Bunlar
    # WEB YIĞINI DEĞİL, hedefin ÖNÜNDEKİ güvenlik katmanıdır → "site" değil "cihaz arkasında
    # sunucu" çerçevesi kurar. lighttpd tek başına zayıf (pfSense/embedded sık kullanır).
    ("server: lighttpd", "server", "lighttpd", 0.5),
    # API yüzeyi — kök yanıtın içerik-tipi JSON ise "bu bir API" (HTML sayfa değil).
    # TEB senaryosu: app_type=api damgalanınca UI dürüst gösterir + kitlesel BOLA/broken-auth
    # önceliklenir. Tespit ıskalansa bile mass-exposure probu yine çalışır (app_type'a bağlı DEĞİL).
    ("content-type: application/json", "app_type", "api", 0.75),
    ("content-type: application/vnd.api+json", "app_type", "api", 0.85),
    ("content-type: application/hal+json", "app_type", "api", 0.85),
]

# Çerez ADI eşleşmesi (küçük harf).
_COOKIE_SIGNALS: List[Tuple[str, str, str, float]] = [
    ("phpsessid", "language", "php", 0.95),
    ("laravel_session", "framework", "laravel", 0.9),
    ("laravel_session", "language", "php", 0.9),
    ("xsrf-token", "framework", "laravel", 0.3),
    ("ci_session", "framework", "codeigniter", 0.85),
    ("ci_session", "language", "php", 0.85),
    ("symfony", "framework", "symfony", 0.8),
    ("connect.sid", "language", "node", 0.85),
    ("connect.sid", "framework", "express", 0.6),
    ("jsessionid", "language", "java", 0.9),
    ("asp.net_sessionid", "language", "dotnet", 0.9),
    (".aspnetcore", "language", "dotnet", 0.85),
    ("csrftoken", "framework", "django", 0.6),
    ("sessionid", "framework", "django", 0.4),
    ("django", "framework", "django", 0.7),
    ("_rails", "framework", "rails", 0.7),
    ("_session_id", "framework", "rails", 0.4),
    ("wordpress_", "framework", "wordpress", 0.9),
    ("wp-settings", "framework", "wordpress", 0.85),
    ("wordpress_", "language", "php", 0.85),
    # 2026 cephesi — çerez adı imzaları (AI/agentic + niş kurumsal)
    ("metabase.session", "framework", "metabase", 0.9),
    ("grafana_session", "framework", "grafana", 0.9),
    ("n8n-auth", "framework", "n8n", 0.9),
    ("tcsessionid", "framework", "teamcity", 0.85),
    ("cfid", "framework", "coldfusion", 0.6),
    ("cftoken", "framework", "coldfusion", 0.6),
]

# Gövde/JS regex eşleşmesi (HTML ilk ~64KB).
_BODY_SIGNALS: List[Tuple[re.Pattern, str, str, float]] = [
    (re.compile(r"wp-content|wp-includes|/wp-json", re.I), "framework", "wordpress", 0.9),
    (re.compile(r"wp-content|wp-includes", re.I), "language", "php", 0.8),
    (re.compile(r"__NEXT_DATA__|/_next/static", re.I), "framework", "nextjs", 0.9),
    (re.compile(r"__NEXT_DATA__|/_next/", re.I), "app_type", "spa", 0.7),
    (re.compile(r"__NEXT_DATA__", re.I), "language", "node", 0.6),
    (re.compile(r"/_nuxt/|window.__NUXT__", re.I), "framework", "nuxt", 0.85),
    (re.compile(r"ng-version=|ng-app|angular", re.I), "framework", "angular", 0.75),
    (re.compile(r"ng-version=", re.I), "app_type", "spa", 0.8),
    (re.compile(r"data-reactroot|react-dom|_reactListening", re.I), "framework", "react", 0.7),
    (re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.I), "app_type", "spa", 0.7),
    (re.compile(r"data-v-[0-9a-f]{8}|vue(\.runtime)?(\.min)?\.js", re.I), "framework", "vue", 0.7),
    (re.compile(r'name="generator"\s+content="drupal', re.I), "framework", "drupal", 0.9),
    (re.compile(r'name="generator"\s+content="joomla', re.I), "framework", "joomla", 0.9),
    (re.compile(r"csrf-param|authenticity_token", re.I), "framework", "rails", 0.7),
    (re.compile(r"laravel|csrf-token", re.I), "framework", "laravel", 0.3),
    (re.compile(r"__VIEWSTATE|aspnetForm", re.I), "language", "dotnet", 0.85),
    (re.compile(r"/graphql|graphiql|apollo", re.I), "app_type", "api", 0.4),
    # OpenAPI/Swagger şeması açık → net API imzası (dokümante REST yüzeyi).
    (re.compile(r'"swagger"\s*:\s*"|"openapi"\s*:\s*"|swagger-ui|/openapi\.json|/swagger\.json',
                re.I), "app_type", "api", 0.7),
    # SharePoint / TeamCity gövde imzaları (P3 — deserialization probe fingerprint yüzeyi)
    (re.compile(r"/_layouts/15/|/_api/web/|/_vti_bin/", re.I), "framework", "sharepoint", 0.85),
    (re.compile(r"TeamCity \d+\.\d+", re.I), "framework", "teamcity", 0.9),  # sürüm etiketli — güçlü
    # 2026 cephesi — gövde/title imzaları (AI/agentic + niş kurumsal). Ayırt edici → FP az.
    (re.compile(r"<title>[^<]*langflow", re.I), "framework", "langflow", 0.9),
    (re.compile(r"<title>[^<]*flowise", re.I), "framework", "flowise", 0.9),
    (re.compile(r"<title>[^<]*comfyui|\bcomfyui\b", re.I), "framework", "comfyui", 0.85),
    (re.compile(r"<title>[^<]*n8n\b|window\.n8n\b", re.I), "framework", "n8n", 0.85),
    (re.compile(r"marimo-version|data-marimo", re.I), "framework", "marimo", 0.85),
    (re.compile(r"ollama is running", re.I), "framework", "ollama", 0.9),
    (re.compile(r"window\.MetabaseBootstrap|<title>[^<]*metabase", re.I), "framework", "metabase", 0.9),
    (re.compile(r"grafanaBootData|<title>[^<]*grafana", re.I), "framework", "grafana", 0.85),
    (re.compile(r"gon\.gitlab|<title>[^<]*gitlab", re.I), "framework", "gitlab", 0.85),
    (re.compile(r"jupyter-config-data|jupyterhub", re.I), "framework", "jupyter", 0.85),
    (re.compile(r"/cfide/|\bcoldfusion\b", re.I), "framework", "coldfusion", 0.8),
    # Edge/VPN/firewall appliance imzaları (P3 — appliance_probe gate yüzeyi). Ayırt edici
    # yol/uygulama imzaları; jenerik "login" DEĞİL. framework boyutuna ürün-ailesi yazılır.
    (re.compile(r"/remote/login|fgt_lang|\bfortigate\b|\bfortiweb\b", re.I), "framework", "fortinet", 0.85),
    (re.compile(r"global-?protect|/global-protect/login|pan_forgot_pass", re.I), "framework", "panos", 0.85),
    (re.compile(r"/dana-na/|/mifs/|pulse\s*secure", re.I), "framework", "ivanti", 0.85),
    (re.compile(r"/vpn/index\.html|/logon/LogonPoint|\bnetscaler\b", re.I), "framework", "citrix_netscaler", 0.85),
    (re.compile(r"\bloadmaster\b|kemp\s*technologies", re.I), "framework", "loadmaster", 0.8),
    (re.compile(r"\bsimplehelp\b", re.I), "framework", "simplehelp", 0.8),
    (re.compile(r"n-?central\b|\bn-able\b", re.I), "framework", "nable_ncentral", 0.8),
    # Rancher / Kubernetes gövde imzaları (TCP sweep boş döndüğünde bile K8s tanınsın):
    # Rancher UI (Ember/Vue) title'ında "rancher" geçer; apiserver'ın Status/Version JSON'ı
    # kök sayfada görülürse hedef doğrudan kontrol düzlemidir.
    (re.compile(r"<title>[^<]*rancher", re.I), "framework", "rancher", 0.9),
    (re.compile(r"<title>[^<]*rancher", re.I), "infra", "kubernetes", 0.8),
    (re.compile(r"rancher.dashboard|rancher/ui|ui\.rancher", re.I), "framework", "rancher", 0.85),
    (re.compile(r'"kind"\s*:\s*"Status"[^}]{0,400}"apiVersion"\s*:\s*"v1"', re.I | re.S),
     "infra", "kubernetes", 0.85),
    (re.compile(r'"gitVersion"\s*:\s*"v?\d+\.\d+[^"]*"', re.I), "infra", "kubernetes", 0.8),
    # Savunma cihazı gövde imzaları — hedefin ÖNÜNDEKİ firewall/appliance (web yığını DEĞİL).
    # pfSense/OPNsense yönetim veya blok sayfası; genel "erişim engellendi" interstitial'ı.
    # 'waf' boyutuna yazılır (savunma katmanı) → UI "site" yerine "cihaz arkasında" çerçevesi.
    (re.compile(r"pfsense", re.I), "waf", "pfsense", 0.9),
    (re.compile(r"opnsense", re.I), "waf", "opnsense", 0.9),
    (re.compile(r"login to pfsense|phpsessid.*pfsense", re.I), "waf", "pfsense", 0.6),
]

# Port → altyapı imzası (nmap/rustscan çıktısı). K8s kontrol düzlemi portları en güçlü sinyal.
_PORT_INFRA: Dict[int, Tuple[str, str, float]] = {
    6443: ("infra", "kubernetes", 0.9),   # kube-apiserver (secure)
    10250: ("infra", "kubernetes", 0.9),  # kubelet r/w
    10255: ("infra", "kubernetes", 0.85), # kubelet read-only
    2379: ("infra", "kubernetes", 0.8),   # etcd client
    2380: ("infra", "kubernetes", 0.7),   # etcd peer
    10257: ("infra", "kubernetes", 0.7),  # controller-manager
    10259: ("infra", "kubernetes", 0.7),  # scheduler
    4194: ("infra", "kubernetes", 0.6),   # cAdvisor
    9345: ("infra", "kubernetes", 0.85),  # RKE2/Rancher supervisor (apiserver-benzeri API)
    10256: ("infra", "kubernetes", 0.6),  # kube-proxy (healthz/proxyMode)
    16443: ("infra", "kubernetes", 0.8),  # k3s secure apiserver (non-root port)
}

# Web yüzeyi portları — biri açıksa hedef bir web uygulaması BARINDIRIYOR olabilir (çerçeveleme
# + net-non-web-host dışlamasının güvenlik freni: web portu açıkken web modüllerini kesme).
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}


# Bilinen web sunucusu değerleri (has_web_signal için) — bunlar gerçek web yüzeyine işaret
# eder. lighttpd BİLEREK dışarıda: pfSense/embedded appliance de kullanır → web kanıtı sayılmaz.
_WEB_SERVER_VALUES = {"nginx", "apache", "iis", "caddy", "openresty", "litespeed"}


@dataclass
class Fact:
    """Bir profil boyutunun en olası değeri + güveni + kanıtları."""
    value: str
    confidence: float
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value, "confidence": round(self.confidence, 3),
                "evidence": self.evidence[:6]}


def _noisy_or(weights: List[float]) -> float:
    """Bağımsız kanıtları birleştir: 1 - Π(1-w). Çok sayıda zayıf sinyal güveni artırır ama
    1'i aşmaz. Wappalyzer-tarzı kanıt toplama."""
    prod = 1.0
    for w in weights:
        prod *= (1.0 - max(0.0, min(1.0, w)))
    return round(1.0 - prod, 4)


@dataclass
class TargetProfile:
    """Hedefin yapılandırılmış istihbarat resmi. facts: boyut→en güçlü Fact.
    votes: boyut→{değer: birleşik güven} (şeffaflık/hata ayıklama)."""
    facts: Dict[str, Fact] = field(default_factory=dict)
    votes: Dict[str, Dict[str, float]] = field(default_factory=dict)

    # ---- Sorgu yardımcıları (playbook gating bunları kullanır) ----
    def value(self, dim: str) -> Optional[str]:
        f = self.facts.get(dim)
        return f.value if f else None

    def confidence(self, dim: str) -> float:
        f = self.facts.get(dim)
        return f.confidence if f else 0.0

    def is_(self, dim: str, value: str, min_conf: float = 0.5) -> bool:
        """dim'in en güçlü değeri `value` VE güven >= min_conf mı? (pozitif alaka)."""
        f = self.facts.get(dim)
        return bool(f and f.value == value and f.confidence >= min_conf)

    def confidently_not(self, dim: str, value: str, min_conf: float = 0.6) -> bool:
        """dim'in en güçlü değeri BAŞKA bir şey VE o güven >= min_conf mı? (kesin dışlama).
        Örn: language kesinlikle 'node' ise confidently_not('language','php') → True →
        PHP modülleri GÜVENLE atlanır. Kanıt yoksa (Fact yok) False → körü körüne dışlama YOK."""
        f = self.facts.get(dim)
        return bool(f and f.value != value and f.confidence >= min_conf)

    def has_any_value(self, dim: str, values: List[str], min_conf: float = 0.5) -> bool:
        return any(self.is_(dim, v, min_conf) for v in values)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "facts": {d: f.to_dict() for d, f in self.facts.items()},
            "summary": self.summary(),
            "kind": self.kind(),   # web | appliance | host | unknown (UI çerçevesi)
        }

    def summary(self) -> str:
        """Operatör için tek satır istihbarat özeti."""
        parts = []
        for dim in ("infra", "cloud", "os", "language", "framework", "server", "app_type", "waf"):
            f = self.facts.get(dim)
            if f:
                parts.append(f"{dim}={f.value}({f.confidence:.0%})")
        if parts:
            return ", ".join(parts)
        # Sinyal yok: en azından hedef TİPİNİ söyle ("site" varsayma).
        return {"host": "çıplak sunucu/host (web sinyali yok)",
                "appliance": "güvenlik cihazı/firewall arkasında (filtreli)",
                }.get(self.kind(), "profil: yetersiz sinyal")

    # ---- Hedef TİPİ çıkarımı (çerçeveleme + akılcı gating) ----
    def has_web_signal(self, min_conf: float = 0.4) -> bool:
        """Hedefte GERÇEK bir web uygulaması/yığını sinyali var mı? (dil/framework/app_type
        ya da bilinen web sunucusu). Yoksa hedef bir web sitesi DEĞİL (çıplak host/sunucu ya
        da cihaz arkası) → motor 'site' varsaymamalı, web-CMS modüllerini boşa koşmamalı."""
        for dim in ("language", "framework"):
            if self.facts.get(dim) and self.confidence(dim) >= min_conf:
                return True
        if self.has_any_value("app_type", ["spa", "api", "server-rendered"], min_conf):
            return True
        f = self.facts.get("server")
        if f and f.value in _WEB_SERVER_VALUES and f.confidence >= 0.6:
            return True
        return False

    def kind(self) -> str:
        """Hedef TİPİ (çerçeveleme için): 'web' | 'appliance' | 'host' | 'unknown'.
        Sıra önemli: gerçek web sinyali baskın (WAF'lı site yine 'web'). Web yoksa: savunma
        cihazı baskınsa 'appliance' (önünde pfSense/firewall), OS varsa 'host' (çıplak sunucu)."""
        if self.has_web_signal():
            return "web"
        if self.facts.get("waf"):
            return "appliance"
        # OS/sunucu sinyali VAR ve web portu (80/443…) açık DEĞİL → çıplak host. Web portu
        # açıksa (fingerprint edilememiş olsa da) 'host' deme — orada web yüzeyi olabilir.
        if self.facts.get("os") and not self.is_("web_port", "open", 0.5):
            return "host"
        return "unknown"


def _accumulate(votes_raw: Dict[str, Dict[str, List[float]]],
                dim: str, value: str, weight: float, ev: str,
                evidence: Dict[str, Dict[str, List[str]]]) -> None:
    votes_raw.setdefault(dim, {}).setdefault(value, []).append(weight)
    evidence.setdefault(dim, {}).setdefault(value, []).append(ev)


def fingerprint(*, headers: Optional[Dict[str, str]] = None,
                cookies: Optional[List[str]] = None,
                body: str = "",
                ports: Optional[List[int]] = None,
                extra: Optional[List[Tuple[str, str, float, str]]] = None) -> TargetProfile:
    """Toplanan kanıttan hedef profilini çıkar (SAF — I/O yok).

    headers: {ad: değer} (küçük/büyük fark etmez). cookies: Set-Cookie ADLARI ya da tam
    satırları. body: kök sayfa HTML/JS (ilk parça). ports: açık portlar. extra: motorun
    başka yerden türettiği sinyaller [(dim, value, weight, evidence), ...] (ör. WAF parmak-izi,
    metadata erişilebilirliği → cloud).
    """
    votes_raw: Dict[str, Dict[str, List[float]]] = {}
    evidence: Dict[str, Dict[str, List[str]]] = {}

    # Header sinyalleri
    if headers:
        hay = "\n".join(f"{k.lower()}: {str(v).lower()}" for k, v in headers.items())
        for needle, dim, value, w in _HEADER_SIGNALS:
            if needle in hay:
                _accumulate(votes_raw, dim, value, w, f"header:{needle}", evidence)

    # Çerez sinyalleri (ad bazlı)
    if cookies:
        cnames = " ".join(str(c).lower() for c in cookies)
        for needle, dim, value, w in _COOKIE_SIGNALS:
            if needle in cnames:
                _accumulate(votes_raw, dim, value, w, f"cookie:{needle}", evidence)

    # Gövde/JS sinyalleri
    if body:
        sample = body[:65536]
        for pat, dim, value, w in _BODY_SIGNALS:
            if pat.search(sample):
                _accumulate(votes_raw, dim, value, w, f"body:{pat.pattern[:24]}", evidence)

    # Port → altyapı + web-yüzeyi varlığı (çerçeveleme: web portu yoksa hedef 'site' değildir).
    if ports:
        for p in ports:
            pi = int(p) if str(p).isdigit() else -1
            sig = _PORT_INFRA.get(pi)
            if sig:
                dim, value, w = sig
                _accumulate(votes_raw, dim, value, w, f"port:{p}", evidence)
            if pi in _WEB_PORTS:
                # Dahili işaret (summary'de gösterilmez): en az bir web portu dinliyor →
                # gerçek web uygulaması OLABİLİR; net-non-web-host dışlaması bunu görürse susar.
                _accumulate(votes_raw, "web_port", "open", 0.9, f"port:{p}", evidence)

    # Dışarıdan türetilmiş sinyaller
    for dim, value, w, ev in (extra or []):
        _accumulate(votes_raw, dim, value, w, ev, evidence)

    # Birleştir → Fact
    profile = TargetProfile()
    for dim, valmap in votes_raw.items():
        combined = {val: _noisy_or(ws) for val, ws in valmap.items()}
        profile.votes[dim] = combined
        best_val = max(combined, key=combined.get)
        profile.facts[dim] = Fact(
            value=best_val, confidence=combined[best_val],
            evidence=evidence.get(dim, {}).get(best_val, []),
        )
    return profile


def parse_set_cookie_names(set_cookie_headers: Any) -> List[str]:
    """Set-Cookie başlık(lar)ından çerez ADLARINI çıkar (SAF). httpx headers.get_list veya
    tek string olabilir. 'PHPSESSID=abc; Path=/' → 'phpsessid'."""
    out: List[str] = []
    items: List[str] = []
    if isinstance(set_cookie_headers, str):
        items = [set_cookie_headers]
    elif isinstance(set_cookie_headers, (list, tuple)):
        items = [str(x) for x in set_cookie_headers]
    for line in items:
        name = line.split("=", 1)[0].strip().lower()
        if name:
            out.append(name)
    return out
