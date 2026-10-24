"""
Kadim Güvenlik — Aktör Gözlüğü (Actor Lens)
===========================================
Türkçe: Tarama biter ve operatör şu soruya cevap arar: "Lazarus / fidye yazılımı ekibi /
Ayyıldız Tim tarzı bir ekip BU yüzeye binsaydı hangi kapıdan girerdi — ve ben o kapıyı
test ettim mi?"

Mevcut sistemde her kontrol parça parça VAR (.env ifşası pathprobe'da, ESXi hypervisor
probunda, k8s kendi probunda...) ama bu kontrollerin SONUÇLARINI saldırgan-aktör
playbook'ları üzerinden OKUYAN ve KAPSAM AÇIĞI (gap) hesaplayan bir katman YOKTU:
apt_groups alanı yalnız CVE metadata'sı olarak damgalanıyor, kampanya görünümü
üretmiyordu. Bu modül o boşluğu kapatır.

FELSEFE (doktrin §6):
- SÜRÜM-BAĞIMSIZ: aktörler sürüm ifşası beklemez; "hangi kapı AÇIK ve TEST EDİLDİ"
  sorusunu sürümden bağımsız yanıtlar (cve_intel'in sürüm hunisi burada işe yaramaz).
- SAF + DETERMİNİSTİK: ağ/DB/LLM YOK. Yalnız zaten toplanmış graf verisini okur.
  Aynı girdi → aynı çıktı. Taramaya sıfır istek, sıfır gürültü ekler.
- BULGU ÜRETMEZ, OKUR: yeni Evidence yazmaz (çift sayma yok). Çıktısı üç kova:
  KAPI (exposed) = kanıtlanmış giriş noktası; GAP (untested) = sinyal var ama
  hiçbir yetenek doğrulamadı; TEMİZ (clean) = yetenek koştu, bulgu yok.
- Gap raporu operatör için OPERASYONEL sinyaldir: "kapsamda delik var" demek,
  "açık var" demek değil. ai_analysis['actor_lens'] altında UI'a/rapora taşınır.

KULLANIM (I/O katmanı ince — scan_pipeline_v2._assess_actor_lens):
    surface = surface_from_graph(engine.graph)
    result  = assess_actor_surface(surface)

İzole test: test_actor_lens.py (düz script, pytest yok).
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("actor-lens")

# ============================================================
# Sözleşme
# ============================================================
# surface = {
#   "hosts":        [{"host": "1.2.3.4", "ports": {3389: {"service": ..., "product": ..., "version": ...}}}],
#   "technologies": ["wordpress", "jenkins", ...],
#   "evidence":     [{"tool": "pathprobe", "title": ".env ifşası ...", "severity": "critical", "cve": None}],
#   "executed_tools": ["nmap", "subfinder", "pathprobe", ...]   # koşan yetenekler (kenar+kanıt araçları)
# }

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ============================================================
# AKTÖR PLAYBOOK'LARI
# ============================================================
# NEDEN bu dört aktör: kurumsal SLA yüzeyinde görülen gerçek tehdit sınıfları.
#   lazarus    — devlet destekli APT; girişi supply-chain ve açık dev/CI altyapısından
#                (Jenkins/Artifact repo/kendi-hosted git). Kurumsal yazılım tedarikçisi
#                hedefi için en gerçekçi APT senaryosu.
#   ransomware — fidye yazılımı ekipleri (LockBit/ALPHV tarzı); girişi RDP/VNC, kimliksiz
#                veri servisleri (Redis/Mongo/ES), yedek/hypervisor yüzeyi ve VPN edge.
#   hacktivist — Ayyıldız Tim tarzı kitlesel operasyon; girişi sızmış kaynak kodu
#                (.git/.env), açık admin panelleri, eski CMS, KEV spreyi, subdomain
#                takeover. "Devlet değil, kalabalık" — en olasılıklı kitlesel tehdit.
#   iab        — initial access broker; yönetim arayüzleri (iLO/iDRAC/IPMI), açık API
#                dokümantasyonu, k8s. Bulduklarını RaaS'e satar.
ACTORS: Dict[str, Dict[str, str]] = {
    "lazarus": {
        "label": "Lazarus / APT (supply-chain odaklı)",
        "profile": "Açık CI/CD + artifact deposu + kendi-hosted git + VPN edge üzerinden tedarik zinciri ve dev altyapı girişi.",
    },
    "ransomware": {
        "label": "Fidye yazılımı ekibi (LockBit/ALPHV tarzı)",
        "profile": "RDP/VNC dışa açık, kimliksiz veri servisleri, hypervisor/yedek yüzeyi — gir, veriyi kilitle, sızdır.",
    },
    "hacktivist": {
        "label": "Hacktivist operasyon (Ayyıldız Tim tarzı)",
        "profile": "Kitlesel, otomatik: sızmış kaynak/gizli (.git/.env), açık admin paneli, eski CMS, KEV spreyi, subdomain takeover.",
    },
    "iab": {
        "label": "Initial Access Broker",
        "profile": "Yönetim arayüzleri (iLO/iDRAC/IPMI), açık API dokümantasyonu, k8s — erişim satar, gerisini başkası yürütür.",
    },
}

# ============================================================
# TEHDİT VEKTÖRLERİ (başlangıç-erişim playbook'u)
# ============================================================
# Alan sözleşmesi:
#   actors          — bu vektörü kullanan aktörler (raporlama/gruplama anahtarı)
#   mitre           — ATT&CK tekniği (T1190 açık-uygulama istismarı vb.)
#   severity        — kapı AÇIKSA taşınacak risk
#   port_map        — {port: [ürün alt-dizeleri]}; boş liste = o portta HER ürün sinyal
#   tech_signals    — teknoloji parmak-izi alt-dizeleri (Wappalyzer/recon çıktısından)
#   evidence_match  — kanıt samanlığında (tool|title|cve) aranan alt-dizeler; eşleşirse KAPI AÇIK
#   covered_by      — bu vektörü DOĞRULAYAN yetenek-araç adları (executed_tools içinde
#                     aranır). Sinyal var + yetenek koşmuş + kanıt yok → TEMİZ.
#   requires_stages — keşif ön-koşulu (ör. takeover için subdomain enum). Koşmadıysa
#                     vektör DEĞERLENDİRİLEMEZ → GAP (kapsam açığı, keşif seviyesinde).
#   confirm_on_signal — sinyalin KENDİSİ kanıttır (ör. 3389'ün dışa açık olması nmap
#                     kanıtıdır) → ayrıca doğrulama beklenmez, doğrudan KAPI AÇIK.
THREAT_VECTORS: List[Dict[str, Any]] = [
    # ---------- LAZARUS / supply-chain ----------
    {
        "id": "cicd_exposed", "actors": ["lazarus", "iab"],
        "name": "CI/CD yönetim arayüzü dışa açık (Jenkins/GitLab CI/TeamCity)",
        "mitre": "T1190/T1195", "severity": "critical", "cwe": ["CWE-284"],
        "port_map": {8080: ["jenkins", "gitlab"], 9000: ["sonarqube"], 8111: ["teamcity"]},
        "tech_signals": ["jenkins", "gitlab ci", "teamcity", "sonarqube", "drone", "woodpecker"],
        "evidence_match": ["jenkins", "teamcity", "gitlab", "sonarqube"],
        "covered_by": ["nuclei", "teamcity"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "CI/CD arayüzünü VPN/SSO arkasına al; anonim erişimi kapat; build yetkilerini en az-ayrıcalıkla sınırla (supply-chain girişinin 1. adımı).",
    },
    {
        "id": "artifact_repo", "actors": ["lazarus"],
        "name": "Artifact/paket deposu dışa açık (Nexus/Artifactory)",
        "mitre": "T1195", "severity": "critical", "cwe": ["CWE-284"],
        "port_map": {8081: ["nexus"], 8082: ["artifactory"]},
        "tech_signals": ["nexus", "artifactory", "harbor"],
        "evidence_match": ["nexus", "artifactory", "harbor"],
        "covered_by": ["nuclei"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Artifact deposu internete kapanmalı; erişim SSO+role dayalı olmalı. Açık depo = aktörün size dağıttığı paketi zehirlemesi için kapı.",
    },
    {
        "id": "git_selfhosted", "actors": ["lazarus", "hacktivist"],
        "name": "Kendi-hosted git sunucusu dışa açık (GitLab/Gitea)",
        "mitre": "T1190", "severity": "high", "cwe": ["CWE-284"],
        "port_map": {3000: ["gitea"], 3200: ["gitea"], 8929: ["gitlab"]},
        "tech_signals": ["gitea", "gitlab", "gogs", "forgejo"],
        "evidence_match": ["gitea", "gitlab", "gogs", "forgejo"],
        "covered_by": ["nuclei"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Git arayüzü SSO arkasına alınmalı; açık kayıt kapatılmalı. Kaynak kodu + CI tanımları tek noktada = tek kapı bütün zincir.",
    },
    {
        "id": "vpn_edge", "actors": ["lazarus", "ransomware", "iab"],
        "name": "VPN/edge cihaz yüzeyi (Fortinet/Ivanti/Pulse/Palo Alto)",
        "mitre": "T1190", "severity": "critical", "cwe": ["CWE-20"],
        "port_map": {443: ["fortigate", "ivanti", "pulse", "paloalto", "globalprotect"], 10443: ["ivanti"], 8443: ["fortigate", "pulse"]},
        "tech_signals": ["fortigate", "fortinet", "ivanti", "pulse secure", "globalprotect", "paloalto"],
        "evidence_match": ["fortigate", "fortinet", "ivanti", "pulse", "globalprotect", "paloalto"],
        "covered_by": ["nuclei", "cve_intel", "kev_intel", "appliance"],
        "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Edge cihaz sürümünü KEV takibinde tut; yönetim arayüzünü internetten kapat. Bu sınıf, fidye yazılımı girişlerinin 1 numaralı kaynağı.",
    },
    # ---------- FİDYE YAZILIMI ----------
    {
        "id": "rdp_exposed", "actors": ["ransomware", "iab"],
        "name": "RDP dışa açık (3389)",
        "mitre": "T1133", "severity": "high", "cwe": ["CWE-732"],
        "port_map": {3389: []},
        "tech_signals": ["rdp", "remote desktop"],
        "evidence_match": ["rdp", "remote desktop", "3389"],
        "covered_by": [], "requires_stages": [], "confirm_on_signal": True,
        "remediation": "RDP'yi internetten çek, VPN arkasına al; NLA + hesap kilidi zorunlu. Açık RDP, fidye kampanyalarının klasik ilk kapısı.",
    },
    {
        "id": "vnc_exposed", "actors": ["ransomware", "iab"],
        "name": "VNC dışa açık (5900)",
        "mitre": "T1133", "severity": "high", "cwe": ["CWE-732"],
        "port_map": {5900: []},
        "tech_signals": ["vnc"],
        "evidence_match": ["vnc"],
        "covered_by": [], "requires_stages": [], "confirm_on_signal": True,
        "remediation": "VNC internete açılmamalı; mutlaka VPN arkasına. Çoğu VNC kurulumu zayıf/kimliksiz yapılandırmayla gelir.",
    },
    {
        "id": "docker_api", "actors": ["ransomware", "iab"],
        "name": "Docker API kimliksiz dışa açık (2375)",
        "mitre": "T1190", "severity": "critical", "cwe": ["CWE-306"],
        "port_map": {2375: [], 2376: []},
        "tech_signals": ["docker"],
        "evidence_match": ["docker api", "docker engine"],
        "covered_by": [], "requires_stages": [], "confirm_on_signal": True,
        "remediation": "2375 KAPALI olmalı (TLS'li 2376 dahil erişim ağla sınırlı). Açık Docker API = tek istekte host root'u; fidye ekiplerinin kelebeği.",
    },
    {
        "id": "unauth_datastore", "actors": ["ransomware", "iab"],
        "name": "Veri servisi dışa açık (Redis/MongoDB/Elasticsearch/Cassandra)",
        "mitre": "T1190", "severity": "high", "cwe": ["CWE-306"],
        "port_map": {6379: ["redis"], 27017: ["mongodb"], 9200: ["elasticsearch"], 9042: ["cassandra"]},
        "tech_signals": ["redis", "mongodb", "elasticsearch", "cassandra"],
        "evidence_match": ["redis", "mongodb", "elasticsearch", "cassandra"],
        "covered_by": ["nuclei"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Veri servisleri internete hiç açılmamalı; kimlik doğrulama + TLS + bind localhost/VPN. Kimliksiz Redis = veri silme/fidye bypass'ı.",
    },
    {
        "id": "hypervisor_esxi", "actors": ["ransomware"],
        "name": "Hypervisor yüzeyi dışa açık (VMware ESXi/Proxmox)",
        "mitre": "T1190", "severity": "critical", "cwe": ["CWE-284"],
        "port_map": {443: ["vmware esxi", "esxi"], 902: ["vmware"], 8006: ["proxmox"]},
        "tech_signals": ["esxi", "vmware", "proxmox", "vsphere"],
        "evidence_match": ["esxi", "vsphere", "proxmox"],
        "covered_by": ["hypervisor", "nuclei"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Hypervisor yönetimi ayrı yönetim ağında; ESXi patch disiplini KEV takibiyle. Hypervisor'i düşüren kampanya TÜM sanal makineleri kilitler.",
    },
    {
        "id": "backup_panel", "actors": ["ransomware"],
        "name": "Yedekleme yönetimi dışa açık (Veeam/BackupExec)",
        "mitre": "T1499", "severity": "critical", "cwe": ["CWE-284"],
        "port_map": {9392: ["veeam"], 10000: ["backup exec"]},
        "tech_signals": ["veeam", "backupexec"],
        "evidence_match": ["veeam", "backup exec"],
        "covered_by": ["nuclei"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Yedek altyapısı kurtarma planının KENDİSİDİR — fidye ekibinin ilk hedefi. Yönetim arayüzü ağ-izole + MFA olmalı, yedeklerde offline kopya.",
    },
    # ---------- HACKTİVİST (Ayyıldız Tim tarzı) ----------
    {
        "id": "secret_leak", "actors": ["hacktivist", "lazarus"],
        "name": "Kaynak/gizli sızıntısı (.env / .git / yedek dosyası)",
        "mitre": "T1552", "severity": "critical", "cwe": ["CWE-200", "CWE-538"],
        "port_map": {}, "tech_signals": [],
        "evidence_match": ["env_exposure", "env_file", ".env", "git_exposure", ".git", "backup", "sql dump"],
        "covered_by": ["pathprobe", "path_probe"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Sızan .env/.git/yedek = veritabanı parolası + kaynak kod. Dosyaları sunucudan kaldır, SIRLARI DÖNDÜR — sızıntı kapıyı açık bırakır.",
    },
    {
        "id": "admin_panel", "actors": ["hacktivist", "iab"],
        "name": "Yönetim paneli dışa açık (phpMyAdmin/Adminer/Tomcat Manager)",
        "mitre": "T1190", "severity": "high", "cwe": ["CWE-284"],
        "port_map": {},
        "tech_signals": ["phpmyadmin", "adminer", "tomcat"],
        "evidence_match": ["phpmyadmin", "adminer", "tomcat manager", "manager/html"],
        "covered_by": ["nuclei"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Yönetim panelleri IP allowlist/VPN arkasına; varsayılan hesap kapat. Açık phpMyAdmin + sızan .env ikilisi kitlesel hacktivist girişinin standart reçetesidir.",
    },
    {
        "id": "cms_wordpress", "actors": ["hacktivist"],
        "name": "CMS yüzeyi (WordPress) — eklenti/tema saldırı zemini",
        "mitre": "T1190", "severity": "medium", "cwe": ["CWE-1104"],
        "port_map": {},
        "tech_signals": ["wordpress", "wp-content", "wp-json"],
        "evidence_match": ["wordpress", "wp-plugin", "wpscan"],
        "covered_by": ["wp", "nuclei"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Eklenti envanteri + güncelleme disiplini; terk edilmiş eklentileri kaldır. Kitlesel operasyonlarda deface bu yüzden gelir.",
    },
    {
        "id": "subdomain_takeover", "actors": ["hacktivist", "iab"],
        "name": "Subdomain takeover zemini (sahipsiz CNAME)",
        "mitre": "T1584", "severity": "high", "cwe": ["CWE-1404"],
        "port_map": {}, "tech_signals": [],
        "evidence_match": ["takeover", "dangling"],
        "covered_by": ["takeover"],
        "requires_stages": ["subfinder", "subdomain", "recon"],
        "confirm_on_signal": False,
        "remediation": "Sahipsiz DNS kayıtlarını temizle. Takeover, marka adına içerik servisi (oltalama/deface) demektir — gerçek kurumsal itibar hasarı.",
    },
    {
        "id": "kev_active", "actors": ["hacktivist", "ransomware", "lazarus"],
        "name": "Aktif sömürülenen CVE varlığı (CISA KEV)",
        "mitre": "T1190", "severity": "critical", "cwe": ["CWE-1395"],
        "port_map": {}, "tech_signals": [],
        "evidence_match": ["kev", "aktif sömürü", "cve-"],
        "covered_by": ["cve_intel", "kev_intel", "nuclei"],
        "requires_stages": [], "confirm_on_signal": False,
        "remediation": "KEV listesindeki bileşenler öncelikli yama kuyruğudur; tarama sıklığını kritik yüzeyde artır.",
    },
    # ---------- IAB / komşu ----------
    {
        "id": "mgmt_iface", "actors": ["iab", "ransomware"],
        "name": "Donanım yönetim arayüzü dışa açık (iLO/iDRAC/IPMI/Redfish)",
        "mitre": "T1190", "severity": "critical", "cwe": ["CWE-284"],
        "port_map": {623: [], 443: ["ilo", "idrac", "redfish", "supermicro"], 5900: ["ilo"]},
        "tech_signals": ["ilo", "idrac", "ipmi", "redfish", "supermicro"],
        "evidence_match": ["ilo", "idrac", "ipmi", "redfish"],
        "covered_by": ["appliance", "nuclei"], "requires_stages": [], "confirm_on_signal": True,
        "remediation": "BMC arayüzleri YALNIZ yönetim ağından. Açık IPMI = fiziksel makine düzeyinde kontrol; broker'ların en sevdiği sessiz kapı.",
    },
    {
        "id": "api_docs_exposed", "actors": ["iab", "hacktivist"],
        "name": "API dokümantasyonu ifşası (Swagger/OpenAPI)",
        "mitre": "T1592", "severity": "medium", "cwe": ["CWE-200"],
        "port_map": {}, "tech_signals": ["swagger", "openapi"],
        "evidence_match": ["swagger", "openapi", "api-docs"],
        "covered_by": ["pathprobe", "path_probe", "nuclei"],
        "requires_stages": [], "confirm_on_signal": False,
        "remediation": "Üretimde API dokümantasyonunu kapat veya yetkilendir. Açık şema, BOLA/IDOR avının haritasını saldırgana verir.",
    },
    {
        "id": "k8s_exposed", "actors": ["iab", "lazarus", "ransomware"],
        "name": "Kubernetes yüzeyi dışa açık (API server/dashboard/kubelet)",
        "mitre": "T1610", "severity": "critical", "cwe": ["CWE-284"],
        "port_map": {6443: [], 10250: [], 8001: [], 10255: []},
        "tech_signals": ["kubernetes", "k3s", "rancher", "kube"],
        "evidence_match": ["kubernetes", "kubelet", "k8s", "rancher"],
        "covered_by": ["k8s"], "requires_stages": [], "confirm_on_signal": False,
        "remediation": "API server anonim erişime kapalı; dashboard asla dışa açılmaz; kubelet 10250 yetkili. Açık k8s = tüm workload'lar tek istekte.",
    },
]

# ============================================================
# SAF çekirdek (I/O yok — TDD)
# ============================================================

def _haystacks(surface: Dict[str, Any]) -> Dict[str, List[str]]:
    """Eşleştirme samanlıklarını normalize et (küçük harf, tek string)."""
    ev_hay: List[str] = []
    for ev in (surface.get("evidence") or []):
        ev_hay.append(" | ".join(str(x or "") for x in (ev.get("tool"), ev.get("title"), ev.get("cve"))).lower())
    techs = [str(t).lower() for t in (surface.get("technologies") or [])]
    tools = [str(t).lower() for t in (surface.get("executed_tools") or [])]
    return {"evidence": ev_hay, "tech": techs, "tools": tools}


def _signal_hits(vec: Dict[str, Any], surface: Dict[str, Any]) -> List[str]:
    """Vektörün port/teknoloji sinyali yüzeyde VAR MI — kanıt değil, İLGİ sinyali."""
    hits: List[str] = []
    for host in (surface.get("hosts") or []):
        for port, info in (host.get("ports") or {}).items():
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                continue
            products = (vec.get("port_map") or {}).get(port_i)
            if products is None:
                continue
            prod = str((info or {}).get("product") or "").lower()
            svc = str((info or {}).get("service") or "").lower()
            # products boş liste = o portta her hizmet sinyal sayılır (ör. 3389)
            if not products or any(p in prod or p in svc for p in products):
                hits.append(f"{host.get('host')}:{port_i}")
    tech_hay = " | ".join(str(t).lower() for t in (surface.get("technologies") or []))
    for t in (vec.get("tech_signals") or []):
        if t in tech_hay:
            hits.append(f"teknoloji: {t}")
            break
    return hits


def _evidence_hits(vec: Dict[str, Any], hay: Dict[str, List[str]]) -> List[str]:
    """Kanıt samanlığında vektör eşleşmesi — eşleşirse kapı AÇIK demektir."""
    refs: List[str] = []
    for m in (vec.get("evidence_match") or []):
        for h in hay["evidence"]:
            if m in h:
                refs.append(h[:120])
    return refs


def _assess_vector(vec: Dict[str, Any], surface: Dict[str, Any], hay: Dict[str, List[str]]) -> Dict[str, Any]:
    """Tek vektörün durumunu çıkar. Durumlar:
    exposed  = kanıt eşleşti VEYA sinyalin kendisi kanıt (confirm_on_signal)
    clean    = sinyal var, doğrulayan yetenek koştu, kanıt yok
    untested = sinyal/önkoşul var ama doğrulayan yok → KAPSAM AÇIĞI
    n/a      = bu yüzey için geçerli değil"""
    base = {
        "id": vec["id"], "name": vec["name"], "mitre": vec.get("mitre"),
        "severity": vec.get("severity", "medium"), "cwe": vec.get("cwe", []),
        "remediation": vec.get("remediation", ""),
    }
    ev_hits = _evidence_hits(vec, hay)
    if ev_hits:
        return {**base, "state": "exposed", "why": "kanıt eşleşti", "matched": ev_hits[:3]}
    sig = _signal_hits(vec, surface)
    if sig:
        if vec.get("confirm_on_signal"):
            # Sinyalin kendisi kanıt: 3389 dışa açıksa bu BİR nmap gözlemidir —
            # ayrıca 'doğrulanmadı' demek dürüstlük değil, gecikmedir.
            return {**base, "state": "exposed", "why": "port/teknoloji sinyali doğrudan kanıt", "matched": sig[:3]}
        covered = [c for c in (vec.get("covered_by") or []) if c in hay["tools"]]
        if covered:
            return {**base, "state": "clean", "why": f"doğrulayan yetenek koştu ({', '.join(covered[:3])}), bulgu yok", "matched": sig[:3]}
        return {**base, "state": "untested", "why": "sinyal var ama doğrulayan yetenek koşmadı — kapsam açığı", "matched": sig[:3]}
    # Sinyal yok: keşif ön-koşulu vektörün TEK ilgi kanalı olabilir (takeover gibi —
    # port/teknoloji sinyali taşımaz, yalnız subdomain keşfi KOŞARSA değerlendirilebilir).
    req = vec.get("requires_stages") or []
    covered = [c for c in (vec.get("covered_by") or []) if c in hay["tools"]]
    if req:
        if not any(r in " | ".join(hay["tools"]) for r in req):
            return {**base, "state": "untested", "why": f"ön-koşul keşif koşmadı ({', '.join(req[:2])}) — vektör kapsam dışı kaldı", "matched": []}
        # Keşif koştu: kontrol de koştuysa TEMİZ, koşmadıysa kapsam açığı.
        if covered:
            return {**base, "state": "clean", "why": f"keşif + doğrulayan yetenek koştu ({', '.join(covered[:3])}), bulgu yok", "matched": []}
        return {**base, "state": "untested", "why": "keşif koştu ama bu vektörün kontrolü koşmadı — kapsam açığı", "matched": []}
    # Keşif ön-koşulu gerektirmeyen ve sinyal/eşleşme taşmayan vektör bu yüzey için ilgi
    # dışıdır — uydurma gap ÜRETME (doktrin: sessiz yutma yok, ama şişirilmiş kapsam da yok).
    return {**base, "state": "n/a", "why": "bu yüzeyde sinyal yok", "matched": []}


def assess_actor_surface(surface: Dict[str, Any]) -> Dict[str, Any]:
    """Yüzeyi tüm aktör playbook'ları üzerinden oku (SAF, deterministik).

    Döner: {"actors": {aktör: {label, profile, doors, gaps, clean, coverage}},
            "doors_total": n, "gaps_total": n}
    doors = kanıtlanmış giriş kapıları (severity sıralı); gaps = kapsam açıkları.
    """
    hay = _haystacks(surface)
    actors_out: Dict[str, Any] = {}
    doors_total = 0
    gaps_total = 0
    for akey, ameta in ACTORS.items():
        doors: List[Dict[str, Any]] = []
        gaps: List[Dict[str, Any]] = []
        clean: List[str] = []
        applicable = 0
        for vec in THREAT_VECTORS:
            if akey not in (vec.get("actors") or []):
                continue
            res = _assess_vector(vec, surface, hay)
            if res["state"] == "exposed":
                applicable += 1
                doors.append(res)
            elif res["state"] == "untested":
                applicable += 1
                gaps.append(res)
            elif res["state"] == "clean":
                applicable += 1
                clean.append(res["id"])
        doors.sort(key=lambda d: _SEV_ORDER.get(d.get("severity", "medium"), 9))
        gaps.sort(key=lambda g: _SEV_ORDER.get(g.get("severity", "medium"), 9))
        checked = len(doors) + len(clean)
        actors_out[akey] = {
            "label": ameta["label"], "profile": ameta["profile"],
            "doors": doors, "gaps": gaps, "clean": clean,
            "coverage": {
                "applicable": applicable, "checked": checked,
                "pct": round(100.0 * checked / applicable, 1) if applicable else 100.0,
            },
        }
        doors_total += len(doors)
        gaps_total += len(gaps)
    return {"actors": actors_out, "doors_total": doors_total, "gaps_total": gaps_total}


# ============================================================
# GAP→SÜPÜRME KÖPRÜSÜ (plan üretimi — I/O yine wiring katmanında)
# ============================================================
# NEDEN: gözlük "sinyal var ama doğrulanmadı" (gap) dediğinde bunu yalnız RAPORLAMAK
# pasif kalırdı — operatör refleksi "o kapıyı da zorla"dır. Köprü, her gap'i motorun
# koşturabileceği bir nuclei TAG süpürmesine çevirir (yeni istek yok: kenar tohumlanır,
# koşum/skor/scope/dedup yine deterministik motorun — desen yayılımı ile aynı desen).
GAP_SWEEP_TAGS: Dict[str, List[str]] = {
    "cicd_exposed": ["jenkins", "teamcity", "gitlab"],
    "artifact_repo": ["nexus", "artifactory"],
    "git_selfhosted": ["gitlab", "gitea"],
    "vpn_edge": ["fortigate", "ivanti", "pulse-secure"],
    "unauth_datastore": ["redis", "mongodb", "elasticsearch"],
    "hypervisor_esxi": ["vmware", "esxi"],
    "backup_panel": ["veeam"],
    "admin_panel": ["phpmyadmin", "adminer", "tomcat"],
    "k8s_exposed": ["kubernetes"],
    "api_docs_exposed": ["swagger"],
    "secret_leak": ["exposures", "misconfig"],
    "cms_wordpress": ["wordpress"],
    # rdp/vnc/docker/mgmt: confirm_on_signal → hiç gap olmazlar (kapı derhal açıklanır).
    # subdomain_takeover: keşif-ön-koşullu, host'suz → köprüde değil, keşif katmanında.
}


def gap_sweep_plan(result: Dict[str, Any], base_target: str = "",
                   *, max_entries: int = 6,
                   severities=("critical", "high")) -> List[Dict[str, Any]]:
    """Aktör-gözlüğü gap'lerini hedefli süpürme planına çevir (SAF, deterministik).

    Girdi: assess_actor_surface çıktısı + tarama kök hedefi (teknoloji-sinyalli gap'ler
    için adres çözümü). Çıktı: [{vector_id, name, severity, tags, hosts, actors}] —
    severity sıralı, bütçeli. Yalnız critical/high gap'ler köprülenir (medium gürültüsü
    süpürme kuyruğunu doldurmasın)."""
    plan: Dict[str, Dict[str, Any]] = {}
    for akey, a in (result.get("actors") or {}).items():
        for gap in (a.get("gaps") or []):
            vid = gap.get("id")
            if vid not in GAP_SWEEP_TAGS or gap.get("severity") not in severities:
                continue
            hosts: List[str] = []
            tech_only = False
            for m in (gap.get("matched") or []):
                if str(m).startswith("teknoloji:"):
                    tech_only = True
                elif ":" in str(m):
                    hosts.append(str(m).split(":", 1)[0])
            # Teknoloji sinyali host'suz geldiyse kök hedef üzerinden çözülür (wiring'de
            # meta.host eşleşen SERVICE düğümü aranır).
            if not hosts and tech_only and base_target:
                hosts = [base_target]
            if not hosts:
                continue
            entry = plan.setdefault(vid, {
                "vector_id": vid, "name": gap.get("name"), "severity": gap.get("severity"),
                "tags": list(GAP_SWEEP_TAGS[vid]), "hosts": [], "actors": [],
            })
            for h in hosts:
                if h not in entry["hosts"]:
                    entry["hosts"].append(h)
            if akey not in entry["actors"]:
                entry["actors"].append(akey)
    out = sorted(plan.values(), key=lambda e: _SEV_ORDER.get(e.get("severity", "medium"), 9))
    return out[:max_entries]


# ============================================================
# Graf → yüzey çıkarma (SAF: yalnız attribute okuma, ağ/DB yok)
# ============================================================

def _tech_name(t: Any) -> Optional[str]:
    """Wappalyzer/recon teknoloji kaydını normalize et: dict ise 'name', str ise kendisi."""
    if isinstance(t, dict):
        n = t.get("name") or t.get("app") or t.get("value")
        return str(n).lower() if n else None
    if isinstance(t, str) and t.strip():
        return t.strip().lower()
    return None


def surface_from_graph(graph: Any) -> Dict[str, Any]:
    """Attack-graph'tan aktör-gözlüğü yüzeyini çıkar.

    NEDEN graf-yerel: tarama sırasında zaten toplanmış tek gerçek kaynağı yeniden
    kullanmak — sıfır ek istek, koşuya koşuya tutarlı snapshot."""
    hosts: Dict[str, Dict[str, Any]] = {}
    technologies: List[str] = []
    evidence: List[Dict[str, Any]] = []
    executed: List[str] = []

    nodes = getattr(graph, "nodes", None) or {}
    root_id = getattr(graph, "root_id", None)
    root = nodes.get(root_id) if root_id else None
    root_meta = (getattr(root, "meta", None) or {}) if root else {}

    # (a) SERVICE/PORT düğümleri → host:port envanteri
    for n in nodes.values():
        meta = getattr(n, "meta", None) or {}
        host = meta.get("host")
        port = meta.get("port")
        if not host or port in (None, ""):
            continue
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        h = hosts.setdefault(str(host), {"host": str(host), "ports": {}})
        h["ports"][port_i] = {
            "service": meta.get("matched_service") or meta.get("service") or "",
            "product": meta.get("product") or "",
            "version": meta.get("version") or "",
        }

    # (b) root open_ports (format: dict veya int — asset_diff ile aynı tolerans)
    target_host = str(getattr(graph, "target", "") or "") or (root_meta.get("host") or "")
    for p in (root_meta.get("open_ports") or []):
        if isinstance(p, dict):
            try:
                port_i = int(p.get("port"))
            except (TypeError, ValueError):
                continue
            h = hosts.setdefault(str(target_host), {"host": str(target_host), "ports": {}})
            h["ports"].setdefault(port_i, {
                "service": p.get("service") or "", "product": p.get("product") or "",
                "version": p.get("version") or "",
            })

    # (c) teknoloji parmak izi (Wappalyzer vb.)
    for t in (root_meta.get("technologies") or []):
        name = _tech_name(t)
        if name and name not in technologies:
            technologies.append(name)

    # (d) kanıtlar (tool|title|cve samanlığı için)
    for ev in (getattr(graph, "evidence", None) or []):
        evidence.append({
            "tool": getattr(ev, "tool", "") or "",
            "title": getattr(ev, "title", "") or "",
            "severity": getattr(ev, "severity", "") or "",
            "cve": getattr(ev, "cve", None) or "",
        })

    # (e) koşan yetenekler: kenar araçları + kanıt üreten araçlar
    for e in (getattr(graph, "edges", None) or {}).values():
        t = getattr(e, "tool", None)
        if t and t not in executed:
            executed.append(t)
    for ev in evidence:
        if ev["tool"] and ev["tool"] not in executed:
            executed.append(ev["tool"])

    return {
        "hosts": list(hosts.values()),
        "technologies": technologies,
        "evidence": evidence,
        "executed_tools": executed,
    }
