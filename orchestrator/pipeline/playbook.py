"""
Kadim Güvenlik — Playbook Seçici / Bilinçli Saldırı Kararı (IPB Aşama 1)
========================================================================
Türkçe: Hedef profilini (target_profile) alıp "hangi saldırı GEREKLİ, hangisi GEREKSİZ"
kararını verir. Körü körüne her aracı çalıştırmak yerine — savaş doktrini: gereksiz kuvvet
hareketi seni ele verir (WAF/IDS taramayı keser) ve motor büyüdükçe her tarama şişer.

İKİ POLİTİKA (kritik tasarım):
  • "if_relevant"    → GÜRÜLTÜLÜ / NİŞ modüller: YALNIZ pozitif istihbarat varsa çalışır.
                       (K8s portlarını yalnız K8s'te yokla; metadata-SSRF'yi yalnız cloud'da.)
  • "unless_excluded"→ UCUZ / ÇEKİRDEK modüller: KESİN dışlanmadıkça çalışır.
                       (Kendini kör etme: kanıt yoksa çalıştır; sadece emin olduğunda atla.)

Bu asimetri, "bilinçli+gerekli saldırı" ile "kendini kör etme" arasındaki dengeyi kurar:
gürültülü şeyler pozitif kanıt ister; ucuz şeyler yalnız kesin-yanlışta susar.

Tasarım: SAF (I/O yok) → izole test. Kararlar target_profile.confidently_not / is_ üstünden.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .target_profile import TargetProfile


# ============================================================
# Yetenek (Capability) manifestosu
# ============================================================

@dataclass
class Capability:
    """Bir saldırı/keşif modülünün relevans sözleşmesi.
    relevant(profile) → pozitif istihbarat var mı? excluded(profile) → kesin dışlama gerekçesi
    (yoksa None)."""
    name: str
    policy: str                      # "if_relevant" | "unless_excluded"
    cost: str                        # "cheap" | "medium" | "expensive" (öncelik/bütçe ipucu)
    relevant: Callable[[TargetProfile], bool]
    excluded: Callable[[TargetProfile], Optional[str]] = lambda p: None
    note: str = ""


# ---- Predikat yardımcıları (okunabilirlik + test) ----
def _is_k8s(p: TargetProfile) -> bool:
    return p.is_("infra", "kubernetes", 0.6)


def _is_cloudish(p: TargetProfile) -> bool:
    # Metadata-SSRF yalnız bulut/K8s'te anlamlı (169.254.169.254 orada var).
    return (p.value("cloud") is not None or p.is_("infra", "cloud", 0.5)
            or p.is_("infra", "kubernetes", 0.5))


def _is_spa(p: TargetProfile) -> bool:
    return p.is_("app_type", "spa", 0.6)


def _is_api_or_spa(p: TargetProfile) -> bool:
    return p.has_any_value("app_type", ["spa", "api"], 0.4)


def _is_php(p: TargetProfile) -> bool:
    return p.is_("language", "php", 0.5)


def _is_wordpress(p: TargetProfile) -> bool:
    # WP-özel prob YALNIZ hedef WordPress iken anlamlı. framework fingerprint (cookie
    # wordpress_/wp-settings, body wp-content/wp-includes/wp-json) yeterince ayırt edici →
    # eşik 0.5. Kanıt yoksa (Fact yok) False → WP olmayanda prob HİÇ çalışmaz (modüler gate).
    return p.is_("framework", "wordpress", 0.5)


def _is_sharepoint(p: TargetProfile) -> bool:
    return p.is_("framework", "sharepoint", 0.5)


def _is_teamcity(p: TargetProfile) -> bool:
    return p.is_("framework", "teamcity", 0.5)


def _has_viewstate_surface(p: TargetProfile) -> bool:
    # __VIEWSTATE zaten yalnız language=dotnet sinyali üretiyor (target_profile.py); ViewState
    # kabul testi SharePoint/TeamCity olmasa da klasik ASP.NET WebForms'ta anlamlıdır — canlı
    # re-confirm (kökte gerçek __VIEWSTATE formu var mı) ikinci kapı olarak geniş eşiği telafi eder.
    return p.is_("language", "dotnet", 0.5)


def _is_deserialization_relevant(p: TargetProfile) -> bool:
    return _is_sharepoint(p) or _is_teamcity(p) or _has_viewstate_surface(p)


# AI/agentic yığın aileleri — ai_redteam YALNIZ bunlarda (veya aktif keşifle bir LLM/agent
# endpoint'i bulunursa) çalışır. framework fingerprint target_profile.py'de 2026 cephesi
# olarak zaten var (langflow/flowise/comfyui/n8n/ollama/marimo). Kanıt yoksa False → profil
# AI demeden derin AI red-team koşmaz (gürültü/yanlış-hedef önlenir; keşif yine hafif çalışır).
_AI_FRAMEWORKS = ("langflow", "flowise", "comfyui", "n8n", "marimo", "ollama",
                  "dify", "openwebui", "open-webui", "vllm", "localai", "librechat",
                  "anythingllm", "text-generation-webui", "automatic1111", "gradio",
                  "streamlit", "jupyter")


def _is_ai_stack(p: TargetProfile) -> bool:
    return p.has_any_value("framework", list(_AI_FRAMEWORKS), 0.5)


# Edge/VPN/firewall appliance aileleri — appliance_probe YALNIZ bunlarda çalışır (2026 KEV'in
# en büyük auth-bypass/missing-auth dilimi). framework fingerprint (target_profile.py appliance
# gövde imzaları) yeterince ayırt edici. Kanıt yoksa False → appliance değilse prob HİÇ çalışmaz.
_APPLIANCE_FAMILIES = ("fortinet", "panos", "ivanti", "citrix_netscaler",
                       "nable_ncentral", "simplehelp", "loadmaster")


def _is_appliance(p: TargetProfile) -> bool:
    return p.has_any_value("framework", list(_APPLIANCE_FAMILIES), 0.5)


def _excl_if_not_php(p: TargetProfile) -> Optional[str]:
    if p.confidently_not("language", "php", 0.7):
        return f"dil kesinlikle {p.value('language')} (≠php) — PHP/CMS modülü gereksiz"
    # Rancher yönetim arayüzü Go backend + Vue/Ember UI'dır; PHP yüzeyi YOKTUR. Rancher
    # kesin tanındığında PHP probları saf gürültüdür (K8s hedefinde "php modülü taranıyor"
    # saçmalığının giderilmesi). K8s-üstü-PHP ihtimali framework=rancher'da geçersizdir:
    # bu imza yalnız Rancher'ın KENDİ arayüzünde görülür.
    if p.is_("framework", "rancher", 0.7):
        return "framework kesinlikle rancher (Go/Vue) — PHP/CMS modülü gereksiz"
    # K8s kontrol düzlemi (kubelet/etcd/apiserver/RKE2 supervisor portları) KESİN tespit
    # edildiğinde Rancher UI'ı görünmese BİLE (firewall arkasında, headless RKE2) dışla:
    # bu bileşenlerin hepsi Go'dur, PHP yüzeyi yok. Kullanıcı şikayetinin kök nedeni tam
    # burasıydı — "framework=rancher" kesin sinyali gelmeden (Rancher UI erişilemezken)
    # port-bazlı K8s tespiti tek başına PHP'yi dışlamıyordu, motor 'kör kalma' varsayılanına
    # düşüp PHP/CMS modülünü çıplak K8s hedefinde de çalıştırıyordu.
    if p.is_("infra", "kubernetes", 0.6):
        return "infra kesinlikle kubernetes (control-plane Go) — PHP/CMS modülü gereksiz"
    return None


def _is_non_web_host(p: TargetProfile) -> bool:
    """Hedef NET biçimde web-DIŞI bir sunucu/appliance mı? Koşul: web yığını sinyali YOK
    + web portu (80/443…) açık DEĞİL + pozitif host/savunma sinyali VAR (os ya da waf).
    Bu üçü birlikte "çıplak Ubuntu sunucu / pfSense arkası host" demektir → web-CMS/crawl
    modüllerini koşmak saçmadır (kullanıcı şikayeti: RKE2/Ubuntu'da PHP modülü)."""
    if p.has_web_signal():
        return False
    if p.is_("web_port", "open", 0.5):
        return False  # web portu açık → web app OLABİLİR; kör kalma güvenlik freni (kesme)
    return bool(p.value("os") or p.value("waf"))


def _excl_if_non_web_host(p: TargetProfile) -> Optional[str]:
    if _is_non_web_host(p):
        what = p.value("os") or p.value("waf") or "sunucu"
        return f"hedef web uygulaması değil (çıplak sunucu/appliance: {what}) — web/CMS modülü gereksiz"
    return None


def _excl_php_or_non_web(p: TargetProfile) -> Optional[str]:
    """php_modules dışlaması: dil≠php/rancher/k8s (mevcut) VEYA hedef web-dışı host."""
    return _excl_if_not_php(p) or _excl_if_non_web_host(p)


def _never(p: TargetProfile) -> Optional[str]:
    return None


def _excl_if_non_ubuntu(p: TargetProfile) -> Optional[str]:
    """Madde 4: distro matrisi Ubuntu-USN-only. OS KESİN Ubuntu-değil ise
    (windows/freebsd/rhel...) matris anlamsız — dışla. Linux/Ubuntu/bilinmeyen
    çalışmaya devam eder (banner'daki 'Ubuntu' imzası veri tarafında ayrıca gate'ler)."""
    v = (p.value("os") or "").lower()
    if v and v not in ("ubuntu", "linux"):
        return f"OS '{v}' olarak tespit edildi — Ubuntu USN matrisi anlamsız"
    return None


# ============================================================
# Varsayılan yetenek kayıtları — motorun gerçek modüllerine karşılık
# ============================================================
CAPABILITIES: List[Capability] = [
    # GÜRÜLTÜLÜ/NİŞ → yalnız pozitif istihbaratla:
    Capability("k8s_probe", "if_relevant", "medium", relevant=_is_k8s,
               note="K8s kontrol düzlemi portları yalnız K8s tespitinde yoklanır."),
    Capability("wp_probe", "if_relevant", "medium", relevant=_is_wordpress,
               note="WordPress-özel prob (plugin enum, /wp-json route hasadı, REST/author "
                    "user-enum, xmlrpc, debug.log) YALNIZ WP tespitinde çalışır — WP değilse hiç."),
    Capability("deserialization_probe", "if_relevant", "medium",
               relevant=_is_deserialization_relevant,
               note="SharePoint ToolShell yol-imzası / ASP.NET ViewState kabul testi / "
                    "TeamCity sürüm ifşası — YALNIZ framework=sharepoint|teamcity veya "
                    "language=dotnet tespitinde çalışır. Tahribatsız: gadget-chain/RCE "
                    "payload'u yok, yalnız kabul-imzası."),
    Capability("ssrf_metadata", "if_relevant", "medium", relevant=_is_cloudish,
               note="Bulut metadata (169.254.169.254) yalnız cloud/K8s'te denenir."),
    Capability("appliance_probe", "if_relevant", "medium", relevant=_is_appliance,
               note="Edge/VPN/firewall appliance auth-bypass/missing-auth probu (FortiWeb/"
                    "PAN-OS/Ivanti/NetScaler/N-able/SimpleHelp/LoadMaster) — YALNIZ appliance "
                    "ailesi tespitinde. Tahribatsız: yalnız GET; sürüm ifşası + kimliksiz "
                    "ayrıcalıklı-erişim diferansiyeli. Exploit zinciri/komut çalıştırılmaz."),
    Capability("ai_redteam", "if_relevant", "medium", relevant=_is_ai_stack,
               note="AI/agentic red-team (direct/indirect prompt injection, system-prompt "
                    "leak, output-handling, tool-abuse, multi-turn jailbreak). YALNIZ AI "
                    "yığını tespitinde VEYA aktif keşif bir LLM/agent endpoint'i bulduğunda. "
                    "Tahribatsız: marker/echo + OAST; gerçek exfil/komut icrası YOK. "
                    "Denial-of-wallet varsayılan KAPALI (AI_REDTEAM_DOW=1 + maliyet tavanı)."),
    # UCUZ/ÇEKİRDEK → kesin dışlanmadıkça (AMA net web-dışı host'ta web modülleri susar):
    Capability("headless_crawl", "unless_excluded", "expensive", relevant=_is_spa,
               excluded=_excl_if_non_web_host,
               note="SPA'da şart; belirsizde de çalışır (kör kalma). Net web-dışı host'ta atla."),
    Capability("graphql_intel", "unless_excluded", "cheap", relevant=_is_api_or_spa,
               excluded=_excl_if_non_web_host),
    Capability("php_modules", "unless_excluded", "cheap", relevant=_is_php,
               excluded=_excl_php_or_non_web,
               note="PHP-özel probları/nuclei-php: dil kesinlikle başkaysa VEYA web-dışı host'ta atla."),
    Capability("idor", "unless_excluded", "medium", relevant=lambda p: True,
               excluded=_excl_if_non_web_host),
    Capability("fac_matrix", "unless_excluded", "medium", relevant=lambda p: True,
               excluded=_excl_if_non_web_host,
               note="Dikey yetki (FAC) matrisi — ayricalikli path'lerde kimlikli diferansiyel "
                    "(anon-red + A-2xx + JWT rol sinyali) + yontem asinmasi "
                    "(X-HTTP-Method-Override/X-Original-URL/yol normalizasyonu). Yalniz GET, "
                    "tahribatsiz. IDOR'un nesne-bazli boslugunu rol/islev-bazliyla tamamlar; "
                    "auth yoksa probe kendi kendine sessizce doner."),
    Capability("web_misconfig", "unless_excluded", "cheap", relevant=lambda p: True,
               excluded=_excl_if_non_web_host),
    Capability("linux_distro_intel", "unless_excluded", "cheap",
               relevant=lambda p: (p.value("os") or "") == "ubuntu",
               excluded=_excl_if_non_ubuntu,
               note="Distro-paket zaafiyet matrisi (Ubuntu USN/KEV snapshot'ı): banner + "
                    "OS tespitinden 'bu makine şu güvenlik güncellemesinin gerisinde' "
                    "cümlesi. PASİF — ağ isteği yok, yalnız elimizdeki banner eşlenir. "
                    "OS kesin Ubuntu-değilse atla; Ubuntu-USN-only matris (Debian/RHEL "
                    "genişleme noktası: data/distro/ altına yeni snapshot dosyası)."),
]


@dataclass
class PlaybookDecision:
    """Seçim sonucu: name → (run: bool, priority, reason)."""
    decisions: Dict[str, Tuple[bool, str, str]] = field(default_factory=dict)

    def allowed(self, name: str, default: bool = True) -> bool:
        """Modül çalışsın mı? Kayıtta yoksa `default` (bilinmeyen modülü engelleme)."""
        d = self.decisions.get(name)
        return d[0] if d else default

    def reason(self, name: str) -> str:
        d = self.decisions.get(name)
        return d[2] if d else "kayıtsız (varsayılan izin)"

    def to_dict(self) -> Dict[str, Any]:
        return {n: {"run": r, "priority": pr, "reason": rs}
                for n, (r, pr, rs) in self.decisions.items()}

    def summary(self) -> str:
        run = [n for n, (r, _, _) in self.decisions.items() if r]
        skip = [n for n, (r, _, _) in self.decisions.items() if not r]
        return f"aktif: {', '.join(run) or '-'} | atlanan: {', '.join(skip) or '-'}"


def decide_capability(cap: Capability, profile: TargetProfile) -> Tuple[bool, str, str]:
    """Tek yetenek kararı (SAF). Döner (run, priority, reason)."""
    reason = cap.excluded(profile)
    if reason:
        return (False, "skip", reason)
    rel = cap.relevant(profile)
    if cap.policy == "if_relevant":
        if rel:
            return (True, "high", "pozitif istihbarat (opt-in modül aktif)")
        return (False, "skip", "pozitif istihbarat yok — gürültülü/niş modül atlandı")
    # unless_excluded
    # ÖNEMLİ (UI dürüstlüğü): priority ile "tespit" ve "genel kapsam" AYRIŞIR. rel=True →
    # hedef gerçekten bu aileye ait (priority=high, yeşil). rel=False → modül SADECE "kör
    # kalma" ilkesiyle default çalışıyor; hedefte pozitif sinyal YOK → priority=normal ve
    # gerekçe bunu AÇIKÇA söyler (ör. RKE2 sunucuda php_modules yeşil "tespit" gibi görünüp
    # operatörü yanıltmasın — "genel kapsam, tespit DEĞİL" olarak işaretlenir).
    if rel:
        return (True, "high", "pozitif sinyal — hedefe uygun (tespit edildi)")
    return (True, "normal", "pozitif sinyal YOK — genel kapsam (tespit DEĞİL, kör kalma)")


def select_playbook(profile: TargetProfile,
                    capabilities: Optional[List[Capability]] = None) -> PlaybookDecision:
    """Profile göre TÜM yetenekleri değerlendir → PlaybookDecision. Motorun beyni."""
    caps = capabilities if capabilities is not None else CAPABILITIES
    dec = PlaybookDecision()
    for cap in caps:
        dec.decisions[cap.name] = decide_capability(cap, profile)
    return dec


# ============================================================
# nuclei etiket planı — "PHP-on-node" gürültüsünü kesen asıl kazanç
# ============================================================
# Aile bazlı nuclei etiketleri. Dil KESİN başka bir aileyse o ailenin etiketleri
# -exclude-tags ile elenir (kapsamı DARALTMAZ; yalnız ilgisiz yığın gürültüsünü keser →
# generic/cve/misconfig/exposure template'leri AYNEN çalışır, sıfır regresyon).
_STACK_TAGS: Dict[str, List[str]] = {
    "php":    ["php", "wordpress", "wp-plugin", "wp-theme", "drupal", "joomla",
               "magento", "laravel", "symfony", "codeigniter", "phpmyadmin"],
    "java":   ["java", "spring", "struts", "tomcat", "weblogic", "jboss", "jenkins"],
    "dotnet": ["aspnet", "iis", "dotnet", "sharepoint", "exchange"],
    "ruby":   ["ruby", "rails"],
    "python": ["django", "flask"],
}

# Framework → dil ailesi çıkarımı (dil doğrudan yoksa). SPA-node vakası için kritik.
_FRAMEWORK_LANG: Dict[str, str] = {
    "react": "node", "vue": "node", "angular": "node", "nextjs": "node",
    "nuxt": "node", "express": "node",
    "laravel": "php", "symfony": "php", "codeigniter": "php", "wordpress": "php",
    "drupal": "php", "joomla": "php",
    "django": "python", "flask": "python",
    "rails": "ruby", "aspnetmvc": "dotnet",
    "rancher": "go",
}


def _detected_family(profile: TargetProfile, min_conf: float = 0.7) -> Optional[str]:
    """Yüksek güvenli dil ailesini bul: doğrudan language, yoksa framework'ten, yoksa
    infra=kubernetes'ten çıkar (control-plane Go'dur — kullanıcı şikayetinin kökü: çıplak
    RKE2/K8s hedefinde Rancher UI'ı bile görünmeden nuclei'nin php/java/... template'lerini
    hâlâ taraması. php_modules playbook flag'i bunu KOZMETİK olarak dışlasa da gerçek tarama
    kapsamını nuclei_tag_plan belirler — o yüzden 'go' çıkarımı burada da şart)."""
    lang = profile.value("language")
    if lang and profile.confidence("language") >= min_conf:
        return lang
    fw = profile.value("framework")
    if fw and profile.confidence("framework") >= min_conf:
        return _FRAMEWORK_LANG.get(fw)
    if profile.is_("infra", "kubernetes", 0.6):
        return "go"
    return None


def nuclei_tag_plan(profile: TargetProfile) -> Dict[str, List[str]]:
    """Profile göre nuclei etiket planı (SAF). Döner {"exclude_tags":[...], "detected":[...]}.

    KESİN başka aile tespit edilirse diğer ailelerin etiketleri exclude edilir. Dil/aile
    bilinmiyorsa BOŞ (tam tarama — kör kalma). Yalnız -exclude-tags: kapsamı daraltmaz,
    ilgisiz yığın gürültüsünü keser (PHP-on-node → php/wordpress/... elenir)."""
    fam = _detected_family(profile)
    if not fam:
        return {"exclude_tags": [], "detected": []}
    exclude: set = set()
    detected: List[str] = list(_STACK_TAGS.get(fam, []))
    for other_fam, tags in _STACK_TAGS.items():
        if other_fam != fam:
            exclude.update(tags)
    # Tespit edilen ailenin etiketlerini yanlışlıkla eleme (fam _STACK_TAGS'te yoksa —
    # ör. node — hiçbiri detected değil, hepsi exclude; bu doğru: node'da php/java/... gereksiz).
    exclude.difference_update(detected)
    return {"exclude_tags": sorted(exclude), "detected": detected, "family": fam}
