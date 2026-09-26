"""
Kadim Güvenlik — Kapsama Sözleşmesi (Coverage Contract) — A1

NEDEN: Motorun asıl hastalığı "whack-a-mole" — bir tespit sınıfını (ör. PHP/DAST)
derinleştirince, garantili tabanı OLMAYAN başka bir sınıf (ör. JS secret) skor/bütçe
ekonomisinde SESSİZCE düşüyor; K8s gibi profile-kapılı problar profil ıskaladığında HİÇ
çalışmıyor. Operatör "ne bulundu"yu görüyor ama "ne taran(a)madı"yı GÖREMİYOR. Bu, hem
satılabilirliği hem operatörün kendine-güvenini kırıyor.
(bkz. docs/2026-08-29-kapsama-tutarlilik-bosluk-analizi.md)

Bu modül o SESSİZLİĞİ öldürür: taramanın sonunda her taban-tespit-sınıfı için durum üretir:
  • bulundu (found)            — sınıf kontrol edildi VE en az bir bulgu üretti
  • temiz (clean)              — kontrol edildi, bulgu yok (iyi haber, açıkça söylenir)
  • kontrol-edilemedi (not_checked) — hiç koşmadı / girdisi yoktu / kapı kapalıydı + NEDEN

"kontrol-edilemedi + neden" en değerli çıktı: sessiz düşüşü görünür kılar, determinizm
verir (aynı hedef → aynı taban tablosu), ve UI (B adımı) ile benchmark (E adımı) bunun
üstüne oturur.

TASARIM: SAF çekirdek — build_coverage(state: dict) -> dict. HİÇ I/O yok. Çağrı yeri
(scan_pipeline_v2) motor/graf/session'dan `state`'i toplar; eksik anahtarlar güvenli
varsayılana düşer (degrade-safe: state boşsa bile çökme yok, her sınıf makul bir durum alır).
Test düz-script (bu projenin konvansiyonu; pytest yok).

DOKTRIN: Bu modül YALNIZ RAPORLAR/ÖLÇER — hiçbir prob'u tetiklemez, hiçbir kapıyı açmaz.
Yürütmeyi garanti altına almak (bariz sınıflar bütçeden bağımsız KOŞSUN) A2'nin işi; bu
katman önce "neyin koşmadığını" dürüstçe göstermek için var.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# ---- Durum sabitleri ----
FOUND = "found"
CLEAN = "clean"
NOT_CHECKED = "not_checked"

_STATUS_LABEL = {
    FOUND: "bulundu",
    CLEAN: "temiz",
    NOT_CHECKED: "kontrol-edilemedi",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


def _as_list(v: Any) -> list:
    """Degrade-safe: list değilse boş liste (int/str/None girdisi çökertmesin)."""
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> dict:
    """Degrade-safe: dict değilse boş dict."""
    return v if isinstance(v, dict) else {}


def _as_list_of_dict(v: Any) -> List[Dict[str, Any]]:
    """Degrade-safe: yalnız dict elemanları koru (bozuk kanıt satırı atlanır)."""
    return [e for e in _as_list(v) if isinstance(e, dict)]


def _top_severity(sevs: List[str]) -> Optional[str]:
    """En yüksek şiddeti döndür (critical>high>medium>low>info). Boşsa None."""
    if not sevs:
        return None
    return sorted(sevs, key=lambda s: _SEV_ORDER.get((s or "").lower(), 5))[0]


class _Ctx:
    """Tarama-sonu sinyallerine dürüst erişim sağlayan salt-okunur yardımcı (SAF).

    Tüm girdiler `state` dict'inden gelir; hiçbiri zorunlu değil (degrade-safe)."""

    def __init__(self, state: Dict[str, Any]):
        # Degrade-safe: yanlış tipteki girdiler (None/int/str) sözleşmeyi ÇÖKERTMEMELİ —
        # bu modül tarama-finalize yolunda çalışır; hata = kayıp özet. Her alan tip-korumalı.
        self.evidence: List[Dict[str, Any]] = _as_list_of_dict(state.get("evidence"))
        # session.stages anahtarları (hangi aşamalar koştu) — mevcut _compute_coverage
        # ile aynı "koştu" sinyali; substring eşleşmeli.
        self.ran_stages: List[str] = [str(s).lower() for s in _as_list(state.get("ran_stages"))]
        # Motorun denediği edge araçları (tried_count>0) — nmap/nuclei/crawl/pathprobe/...
        self.tried_tools: List[str] = [str(t).lower() for t in _as_list(state.get("tried_tools"))]
        self.meta: Dict[str, Any] = _as_dict(state.get("meta"))
        self.profile: Dict[str, Any] = _as_dict(state.get("profile"))
        self.resilience_enabled: bool = bool(state.get("resilience_enabled", False))
        self.level: str = str(state.get("level") or "standard").lower()

    # -- Bulgu (found) sinyalleri: Evidence.tool otoriter --
    def findings(self, *tools: str) -> Tuple[int, Optional[str], bool]:
        """Verilen tool etiketlerinden üretilmiş bulguları özetle.
        Döner: (adet, en_yüksek_şiddet, kanıtlı_var_mı)."""
        tset = {t.lower() for t in tools}
        hits = [e for e in self.evidence if str(e.get("tool", "")).lower() in tset]
        sevs = [str(e.get("severity", "")) for e in hits]
        confirmed = any(
            str(e.get("confidence_tier", "")).lower() == "confirmed"
            or e.get("verified") is True
            for e in hits
        )
        return len(hits), _top_severity(sevs), confirmed

    # -- "Koştu" sinyalleri --
    def ran_stage(self, *needles: str) -> bool:
        """Aşama adında (session.stages) verilen alt-dizelerden biri geçiyor mu?"""
        return any(n.lower() in s for n in needles for s in self.ran_stages)

    def tried(self, *tools: str) -> bool:
        return any(t.lower() in self.tried_tools for t in tools)

    def meta_truthy(self, *keys: str) -> bool:
        """Verilen meta anahtarlarından herhangi biri dolu/True mu?"""
        for k in keys:
            v = self.meta.get(k)
            if v:
                return True
        return False

    def meta_get(self, key: str, default: Any = None) -> Any:
        return self.meta.get(key, default)

    # -- Profil okuma (root.meta['target_profile'] serileştirilmiş dict) --
    def profile_fact(self, dim: str) -> Tuple[Optional[str], float]:
        facts = self.profile.get("facts") or {}
        f = facts.get(dim)
        if not isinstance(f, dict):
            return None, 0.0
        return f.get("value"), float(f.get("confidence") or 0.0)

    def profile_is(self, dim: str, value: str, min_conf: float = 0.5) -> bool:
        v, c = self.profile_fact(dim)
        return v == value and c >= min_conf

    def has_profile(self) -> bool:
        return bool(self.profile.get("facts"))


def _mk(key: str, label: str, family: str, status: str, reason: str,
        count: int = 0, top_sev: Optional[str] = None, confirmed: bool = False) -> Dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "family": family,
        "status": status,
        "status_label": _STATUS_LABEL[status],
        "reason": reason,
        "finding_count": count,
        "top_severity": top_sev,
        "confirmed": confirmed,
    }


# ============================================================================
# SINIF ÇÖZÜCÜLERİ — her biri _Ctx alır, tek bir sınıf durumu döndürür.
# Her çözücü "bulundu → temiz → kontrol-edilemedi" mantığını sınıfa özgü kurar;
# kontrol-edilemedi'de NEDEN operatöre eyleme geçirilebilir bir ipucu verir.
# ============================================================================

def _c_ports(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("nmap", "rustscan", "nmap_real_ip")
    ran = cx.tried("nmap", "rustscan") or cx.ran_stage("nmap", "rustscan") or bool(cx.meta_get("open_ports"))
    open_ports = cx.meta_get("open_ports") or []
    if open_ports or n:
        return _mk("surface.ports", "Port / servis envanteri", "surface", FOUND,
                   f"{len(open_ports)} açık port haritalandı.", max(n, len(open_ports)), sev, conf)
    if ran:
        return _mk("surface.ports", "Port / servis envanteri", "surface", CLEAN,
                   "Port taraması koştu; açık/ilginç port raporlanmadı.")
    return _mk("surface.ports", "Port / servis envanteri", "surface", NOT_CHECKED,
               "Port taraması (nmap/rustscan) koştuğu doğrulanamadı.")


def _c_subdomains(cx: _Ctx) -> Dict[str, Any]:
    subs = cx.meta_get("subdomains") or []
    ran = cx.tried("subfinder") or cx.ran_stage("subfinder") or bool(subs)
    if subs:
        return _mk("surface.subdomains", "Subdomain keşfi", "surface", FOUND,
                   f"{len(subs)} subdomain bulundu.", len(subs))
    if ran:
        return _mk("surface.subdomains", "Subdomain keşfi", "surface", CLEAN,
                   "Subdomain keşfi koştu; ek subdomain yok.")
    return _mk("surface.subdomains", "Subdomain keşfi", "surface", NOT_CHECKED,
               "Subdomain keşfi (subfinder) koştuğu doğrulanamadı — IP hedefinde beklenir.")


def _c_endpoints(cx: _Ctx) -> Dict[str, Any]:
    eps = cx.meta_get("endpoints") or []
    ran = cx.tried("crawl") or cx.ran_stage("crawl")
    if eps:
        return _mk("surface.endpoints", "Endpoint / crawl keşfi", "surface", FOUND,
                   f"{len(eps)} endpoint/URL haritalandı.", len(eps))
    if ran:
        return _mk("surface.endpoints", "Endpoint / crawl keşfi", "surface", CLEAN,
                   "Crawl koştu; gezilebilir endpoint bulunamadı (statik/kilitli yüzey olabilir).")
    return _mk("surface.endpoints", "Endpoint / crawl keşfi", "surface", NOT_CHECKED,
               "Crawl koşmadı — web yüzeyi haritalanmadı.")


def _c_origin_exposure(cx: _Ctx) -> Dict[str, Any]:
    behind_cdn = bool(cx.meta_get("is_behind_cdn"))
    real_ip = cx.meta_get("real_ip")
    n, sev, conf = cx.findings("origin_discovery")
    if behind_cdn and real_ip:
        return _mk("surface.origin_exposure", "Origin-behind-CDN ifşası", "surface", FOUND,
                   f"CDN arkasındaki gerçek origin IP ifşa oldu ({real_ip}) — CDN korumasını atlatılabilir.",
                   max(n, 1), sev or "medium", conf)
    if behind_cdn and not real_ip:
        return _mk("surface.origin_exposure", "Origin-behind-CDN ifşası", "surface", CLEAN,
                   "Hedef CDN arkasında; gerçek origin IP ifşa edilemedi (iyi duruş).")
    if cx.ran_stage("recon", "origin") or cx.tried("recon", "origin_discovery"):
        return _mk("surface.origin_exposure", "Origin-behind-CDN ifşası", "surface", CLEAN,
                   "Hedef CDN arkasında görünmüyor; origin ifşası ilgili değil.")
    return _mk("surface.origin_exposure", "Origin-behind-CDN ifşası", "surface", NOT_CHECKED,
               "Origin/CDN analizi (recon) koştuğu doğrulanamadı.")


def _c_sensitive_paths(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("pathprobe")
    ran = cx.tried("pathprobe") or cx.ran_stage("pathprobe") or bool(cx.meta_get("sensitive_findings"))
    sensitive = cx.meta_get("sensitive_findings") or []
    if n or sensitive:
        return _mk("exposure.sensitive_paths", "Hassas yol ifşası (.env/.git/yedek)", "exposure", FOUND,
                   f"{max(n, len(sensitive))} hassas yol/ifşa bulundu.", max(n, len(sensitive)), sev or "high", conf)
    if ran:
        return _mk("exposure.sensitive_paths", "Hassas yol ifşası (.env/.git/yedek)", "exposure", CLEAN,
                   "PathProbe (garantili taban) koştu; ifşa edilmiş hassas yol yok.")
    return _mk("exposure.sensitive_paths", "Hassas yol ifşası (.env/.git/yedek)", "exposure", NOT_CHECKED,
               "PathProbe koştuğu doğrulanamadı — garantili taban çalışmamış (araştır).")


def _c_js_secrets(cx: _Ctx) -> Dict[str, Any]:
    # KULLANICININ 1 NUMARALI ŞİKAYETİ: "PHP'yi toplarken JS kaçıyor."
    # JS sır taraması crawl mega-stage'inin İÇİNDE koşar → crawl koştuysa JS de denendi
    # (js_assets bulunduğu kadarıyla). Crawl koşmadıysa JS'in tabanı yok → kontrol-edilemedi.
    n, sev, conf = cx.findings("js_secret_scan")
    crawl_ran = cx.tried("crawl") or cx.ran_stage("crawl")
    if n:
        return _mk("exposure.js_secrets", "JS bundle sır ifşası (API key/JWT)", "exposure", FOUND,
                   f"{n} sabit-kodlu sır/kimlik JS bundle'ında bulundu.", n, sev or "high", conf)
    if crawl_ran:
        return _mk("exposure.js_secrets", "JS bundle sır ifşası (API key/JWT)", "exposure", CLEAN,
                   "Crawl+JS taraması koştu; JS bundle'larında sır bulunmadı (ya da JS varlığı yoktu).")
    return _mk("exposure.js_secrets", "JS bundle sır ifşası (API key/JWT)", "exposure", NOT_CHECKED,
               "Crawl koşmadığı için JS sır taraması girdisiz kaldı — JS yüzeyi hiç incelenmedi.")


def _c_openapi(cx: _Ctx) -> Dict[str, Any]:
    found = bool(cx.meta_get("openapi_found")) or bool(cx.meta_get("openapi_endpoints"))
    crawl_ran = cx.tried("crawl") or cx.ran_stage("crawl")
    if found:
        eps = cx.meta_get("openapi_endpoints") or []
        return _mk("exposure.openapi", "OpenAPI/Swagger ifşası", "exposure", FOUND,
                   f"OpenAPI dokümanı erişilebilir ({len(eps)} operasyon haritalandı).", len(eps) or 1, "medium")
    if crawl_ran:
        return _mk("exposure.openapi", "OpenAPI/Swagger ifşası", "exposure", CLEAN,
                   "OpenAPI keşfi koştu; açık swagger/OpenAPI dokümanı yok.")
    return _mk("exposure.openapi", "OpenAPI/Swagger ifşası", "exposure", NOT_CHECKED,
               "OpenAPI keşfi (crawl mega-stage) koşmadı.")


def _c_graphql(cx: _Ctx) -> Dict[str, Any]:
    found = bool(cx.meta_get("graphql_found")) or bool(cx.meta_get("graphql_operations"))
    crawl_ran = cx.tried("crawl") or cx.ran_stage("crawl")
    n, sev, conf = cx.findings("graphql_intel")
    if found or n:
        ops = cx.meta_get("graphql_operations") or []
        return _mk("exposure.graphql", "GraphQL introspection ifşası", "exposure", FOUND,
                   f"GraphQL uç bulundu (introspection {len(ops)} operasyon açığa çıkardı).",
                   len(ops) or max(n, 1), sev or "medium", conf)
    if crawl_ran:
        return _mk("exposure.graphql", "GraphQL introspection ifşası", "exposure", CLEAN,
                   "GraphQL keşfi koştu; GraphQL uç yok ya da introspection kapalı (iyi hijyen).")
    return _mk("exposure.graphql", "GraphQL introspection ifşası", "exposure", NOT_CHECKED,
               "GraphQL keşfi (crawl mega-stage) koşmadı.")


def _c_nuclei(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("nuclei", "kev_intel", "cve_intel")
    ran = cx.tried("nuclei") or cx.ran_stage("nuclei")
    if n:
        return _mk("vuln.nuclei", "Nuclei imza taraması (CVE/misconfig)", "vuln", FOUND,
                   f"{n} imza bulgusu (CVE/misconfig).", n, sev, conf)
    if ran:
        return _mk("vuln.nuclei", "Nuclei imza taraması (CVE/misconfig)", "vuln", CLEAN,
                   "Nuclei koştu; eşleşen imza yok.")
    return _mk("vuln.nuclei", "Nuclei imza taraması (CVE/misconfig)", "vuln", NOT_CHECKED,
               "Nuclei imza taraması koştuğu doğrulanamadı — Keşif seviyesinde kapalı olabilir.")


def _c_dast(cx: _Ctx) -> Dict[str, Any]:
    # Aktif enjeksiyon sınıfı (SQLi/XSS/LFI/SSRF/SSTI/XXE) — kanıt poc_verify/verifier'lardan.
    n, sev, conf = cx.findings("poc_verify", "jwt_verify", "cors_verify", "exploit_chain",
                               "wp_sqli_oracle", "combo_chains")
    eps = cx.meta_get("endpoints") or []
    injectable = cx.meta_get("injectable_endpoints") or []
    if n:
        return _mk("vuln.dast", "Aktif enjeksiyon (SQLi/XSS/LFI/SSRF/SSTI)", "vuln", FOUND,
                   f"{n} enjeksiyon/erişim zafiyeti aktif kanıtlandı.", n, sev or "high", conf)
    if cx.level == "recon":
        return _mk("vuln.dast", "Aktif enjeksiyon (SQLi/XSS/LFI/SSRF/SSTI)", "vuln", NOT_CHECKED,
                   "Keşif seviyesi — aktif DAST kapalı (yalnız pasif harita çıkarılır).")
    if not eps and not injectable:
        return _mk("vuln.dast", "Aktif enjeksiyon (SQLi/XSS/LFI/SSRF/SSTI)", "vuln", NOT_CHECKED,
                   "Enjekte edilebilir endpoint/parametre bulunamadı — DAST'ın girdisi yok.")
    return _mk("vuln.dast", "Aktif enjeksiyon (SQLi/XSS/LFI/SSRF/SSTI)", "vuln", CLEAN,
               "Endpoint'ler üzerinde aktif enjeksiyon denendi; kanıtlanmış zafiyet yok.")


def _c_idor(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("idor_probe", "probe_api_bola")
    ran = cx.meta_truthy("idor_probed")
    if n:
        return _mk("access.idor", "IDOR / BOLA (yetkisiz nesne erişimi)", "access", FOUND,
                   f"{n} IDOR/BOLA diferansiyeli kanıtlandı.", n, sev or "high", conf)
    if ran:
        return _mk("access.idor", "IDOR / BOLA (yetkisiz nesne erişimi)", "access", CLEAN,
                   "IDOR/BOLA probu koştu; yetkisiz nesne erişimi bulunmadı.")
    eps = cx.meta_get("endpoints") or []
    if not eps:
        return _mk("access.idor", "IDOR / BOLA (yetkisiz nesne erişimi)", "access", NOT_CHECKED,
                   "Nesne-referanslı endpoint bulunamadı — IDOR probunun girdisi yok.")
    return _mk("access.idor", "IDOR / BOLA (yetkisiz nesne erişimi)", "access", NOT_CHECKED,
               "IDOR probu koşmadı (kimlik/kanıt gerekebilir) — nesne-referanslı yüzey incelenmedi.")


def _c_kubernetes(cx: _Ctx) -> Dict[str, Any]:
    # KULLANICININ ŞİKAYETİ: "K8s var tam tespit edemiyor."
    n, sev, conf = cx.findings("k8s_probe")
    ran = cx.meta_truthy("k8s_probed")
    if n:
        return _mk("infra.kubernetes", "Kubernetes / RKE2 / Rancher ifşası", "infra", FOUND,
                   f"{n} K8s kontrol-düzlemi ifşası kanıtlandı.", n, sev or "high", conf)
    if ran:
        return _mk("infra.kubernetes", "Kubernetes / RKE2 / Rancher ifşası", "infra", CLEAN,
                   "K8s farkında prob koştu; yetkisiz apiserver/kubelet/etcd ifşası yok.")
    if cx.profile_is("infra", "kubernetes", 0.6):
        return _mk("infra.kubernetes", "Kubernetes / RKE2 / Rancher ifşası", "infra", NOT_CHECKED,
                   "Profil K8s dedi ama derin prob koşmadı — gecikme/kapı sorunu (araştır).")
    v, c = cx.profile_fact("infra")
    if v == "kubernetes":
        return _mk("infra.kubernetes", "Kubernetes / RKE2 / Rancher ifşası", "infra", NOT_CHECKED,
                   f"K8s sinyali zayıf (güven {c:.0%} < 0.6) — kontrol-düzlemi portları filtreli "
                   "olabilir; if_relevant kapısı açılmadı.")
    return _mk("infra.kubernetes", "Kubernetes / RKE2 / Rancher ifşası", "infra", NOT_CHECKED,
               "Profil K8s işareti vermedi (portlar filtreli + web imzası yok olabilir) — "
               "if_relevant kapısı kapalı; K8s doğrulanamadı.")


def _c_k8s_escape(cx: _Ctx) -> Dict[str, Any]:
    # CIS 5.2.x / NSA Hardening — pod kaçış yüzeyi (privileged/hostPID/hostPath/runtime-socket).
    # KAYNAK: anon kubelet /pods PodList gövdesi → k8s_probe.classify_pod_escape meta sinyalleri.
    label = "K8s pod kaçış yüzeyi (CIS 5.2 / NSA)"
    try:
        n = int(cx.meta_get("k8s_escape_surfaces") or 0)
    except (TypeError, ValueError):
        n = 0
    if n:
        return _mk("infra.k8s_pod_escape", label, "infra", FOUND,
                   f"{n} pod kaçış yüzeyi spec'te KANITLANDI (privileged/hostPID/hostPath/"
                   f"runtime-socket/capabilities) — CIS 5.2/NSA ihlali.", n, "critical", True)
    if cx.meta_truthy("k8s_pods_readable"):
        return _mk("infra.k8s_pod_escape", label, "infra", CLEAN,
                   "Anon PodList okundu; kaçış yüzeyi YOK (privileged/hostPID/hostPath/socket "
                   "temiz) — CIS 5.2 pod izolasyonu doğrulandı.")
    if cx.meta_truthy("k8s_probed"):
        return _mk("infra.k8s_pod_escape", label, "infra", NOT_CHECKED,
                   "K8s probu koştu ama anon PodList okunamadı (kubelet auth duvarı arkasında) — "
                   "pod spec denetlenemedi; CIS 5.2 için kimlikli erişim (kubeconfig/servis "
                   "hesabı) gerekir.")
    return _mk("infra.k8s_pod_escape", label, "infra", NOT_CHECKED,
               "K8s if_relevant kapısı açılmadı — pod kaçış denetimi kapsam dışı.")


def _c_k8s_etcd(cx: _Ctx) -> Dict[str, Any]:
    # etcd maruziyeti (2379/2380 + v3 /health /metrics) — anon anahtar/metrik sızıntısı.
    label = "K8s etcd maruziyeti (2379/2380)"
    try:
        n = int(cx.meta_get("k8s_etcd_findings") or 0)
    except (TypeError, ValueError):
        n = 0
    if n:
        return _mk("infra.k8s_etcd", label, "infra", FOUND,
                   f"{n} etcd maruziyeti kanıtlandı (anon anahtar/metrik/sürüm sızıntısı) — "
                   f"cluster durum verisi risk altında.", n, "critical", True)
    if cx.meta_truthy("k8s_probed"):
        return _mk("infra.k8s_etcd", label, "infra", CLEAN,
                   "K8s probu etcd portlarını yokladı; anon maruziyet yok (port kapalı/firewall "
                   "arkasında ya da auth'lu).")
    return _mk("infra.k8s_etcd", label, "infra", NOT_CHECKED,
               "K8s probu koşmadı — etcd maruziyeti doğrulanamadı.")


def _c_k8s_registry(cx: _Ctx) -> Dict[str, Any]:
    # NodePort yüzeyi: private container registry anon katalog + imaj-içi sır sızıntısı.
    label = "K8s private registry ifşası (NodePort)"
    if cx.meta_truthy("k8s_registry_exposed"):
        return _mk("infra.k8s_registry", label, "infra", FOUND,
                   "Anon katalog ifşası kanıtlandı — dahili imajlar ve gömülü sırlar dışarıdan "
                   "çekilebilir.", 1, "critical", True)
    if cx.meta_truthy("k8s_registry_probed"):
        return _mk("infra.k8s_registry", label, "infra", CLEAN,
                   "Registry imzası görüldü ama katalog anonim DEĞİL (auth var) — sertleştirme "
                   "kısmen doğru.")
    if cx.meta_truthy("k8s_surface_probed"):
        return _mk("infra.k8s_registry", label, "infra", CLEAN,
                   "NodePort yüzey pası koştu; Docker Distribution imzası/katalog ifşası yok.")
    return _mk("infra.k8s_registry", label, "infra", NOT_CHECKED,
               "NodePort yüzey pası koşmadı (K8S_PROBE_V2 kapalı ya da NodePort aralığında açık "
               "port yok) — registry yüzeyi incelenmedi.")


def _c_hypervisor(cx: _Ctx) -> Dict[str, Any]:
    # Hypervisor/sanallaştırma mgmt arayüzü (ESXi/vCenter/Proxmox/Cockpit/oVirt) internete açık mı.
    n, sev, conf = cx.findings("hypervisor_probe")
    ran = cx.meta_truthy("hypervisor_probed")
    if n:
        return _mk("infra.hypervisor", "Hypervisor mgmt ifşası (ESXi/Proxmox/vCenter)", "infra", FOUND,
                   f"{n} sanallaştırma yönetim arayüzü internete açık.", n, sev or "high", conf)
    if ran:
        return _mk("infra.hypervisor", "Hypervisor mgmt ifşası (ESXi/Proxmox/vCenter)", "infra", CLEAN,
                   "Hypervisor mgmt probu koştu; açık ESXi/vCenter/Proxmox/Cockpit arayüzü yok.")
    return _mk("infra.hypervisor", "Hypervisor mgmt ifşası (ESXi/Proxmox/vCenter)", "infra", NOT_CHECKED,
               "Hypervisor mgmt probu koştuğu doğrulanamadı.")


def _c_wordpress(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("wp_probe", "wp_sqli_oracle")
    ran = cx.meta_truthy("wp_probed_hosts", "wp_confirmed_hosts")
    if n:
        return _mk("app.wordpress", "WordPress-özel zafiyet", "app", FOUND,
                   f"{n} WordPress-özel bulgu.", n, sev or "high", conf)
    if ran:
        return _mk("app.wordpress", "WordPress-özel zafiyet", "app", CLEAN,
                   "WordPress probu koştu; WP-özel zafiyet yok.")
    if cx.profile_is("framework", "wordpress", 0.5):
        return _mk("app.wordpress", "WordPress-özel zafiyet", "app", NOT_CHECKED,
                   "Profil WordPress dedi ama WP probu koşmadı (araştır).")
    return _mk("app.wordpress", "WordPress-özel zafiyet", "app", NOT_CHECKED,
               "Hedef WordPress değil — WP-özel prob ilgili değil (if_relevant).")


def _c_deserialization(cx: _Ctx) -> Dict[str, Any]:
    # deser/appliance prob'ları root.meta markeri bırakmıyor → koştuğunu profil-alakasından
    # ÇIKARIRIZ (A1 dürüstlük notu: A2'de marker eklenip kesinleştirilebilir).
    n, sev, conf = cx.findings("deserialization_probe")
    relevant = (cx.profile_is("framework", "sharepoint", 0.5)
                or cx.profile_is("framework", "teamcity", 0.5)
                or cx.profile_is("language", "dotnet", 0.5))
    if n:
        return _mk("app.deserialization", "Deserialization kabul-imzası", "app", FOUND,
                   f"{n} deserialization kabul-imzası bulgusu.", n, sev or "high", conf)
    if relevant:
        return _mk("app.deserialization", "Deserialization kabul-imzası", "app", CLEAN,
                   "Profil deserialization ailesinde; prob koştu, kabul-imzası bulunmadı.")
    return _mk("app.deserialization", "Deserialization kabul-imzası", "app", NOT_CHECKED,
               "Profil SharePoint/TeamCity/.NET değil — deserialization probu ilgili değil (if_relevant).")


def _c_appliance(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("appliance_probe")
    relevant = (cx.profile.get("kind") == "appliance"
                or cx.profile_is("framework", "fortinet", 0.4)
                or cx.profile_is("framework", "panos", 0.4)
                or cx.profile_is("framework", "ivanti", 0.4)
                or cx.profile_is("framework", "citrix_netscaler", 0.4))
    if n:
        return _mk("appliance.auth_bypass", "Appliance auth-bypass / missing-auth", "appliance", FOUND,
                   f"{n} appliance auth-bypass/eksik-yetki bulgusu.", n, sev or "high", conf)
    if relevant:
        return _mk("appliance.auth_bypass", "Appliance auth-bypass / missing-auth", "appliance", CLEAN,
                   "Profil edge/appliance ailesinde; prob koştu, auth-bypass bulunmadı.")
    return _mk("appliance.auth_bypass", "Appliance auth-bypass / missing-auth", "appliance", NOT_CHECKED,
               "Profil edge/VPN/firewall appliance değil — appliance probu ilgili değil (if_relevant).")


def _c_resilience(cx: _Ctx) -> Dict[str, Any]:
    # KULLANICININ DDoS DERSİ: availability + exposure ekseni.
    n, sev, conf = cx.findings("resilience_probe")
    if n:
        return _mk("availability.resilience", "Dayanıklılık & maruz-kalma (L7/rate-limit/SSH)",
                   "availability", FOUND,
                   f"{n} dayanıklılık/maruz-kalma bulgusu (availability/exposure).", n, sev or "medium", conf)
    if cx.resilience_enabled:
        return _mk("availability.resilience", "Dayanıklılık & maruz-kalma (L7/rate-limit/SSH)",
                   "availability", CLEAN,
                   "Dayanıklılık probu koştu; cache/rate-limit/SSH duruşunda zafiyet bulunmadı.")
    return _mk("availability.resilience", "Dayanıklılık & maruz-kalma (L7/rate-limit/SSH)",
               "availability", NOT_CHECKED,
               "Operatör 'Dayanıklılık & maruz-kalma' toggle'ı kapalı (varsayılan) — "
               "availability/origin-ifşa ekseni hiç ölçülmedi.")


def _c_identity(cx: _Ctx) -> Dict[str, Any]:
    if cx.has_profile():
        summary = cx.profile.get("summary") or ""
        # Ürün/yığın kimliği çıktıysa 'found' (zafiyet değil; kimlik omurgası kuruldu).
        fw = cx.profile_fact("framework")[0]
        if fw or cx.profile_fact("language")[0] or cx.profile_fact("server")[0] \
                or cx.profile_fact("infra")[0]:
            return _mk("identity.profile", "Hedef kimliği (profil + CPE)", "identity", FOUND,
                       f"Kimlik çözüldü: {summary[:120]}", 0, None)
        return _mk("identity.profile", "Hedef kimliği (profil + CPE)", "identity", CLEAN,
                   f"Profil koştu; belirgin ürün/yığın imzası yok ({cx.profile.get('kind', 'unknown')}).")
    return _mk("identity.profile", "Hedef kimliği (profil + CPE)", "identity", NOT_CHECKED,
               "Hedef profili (target_profile) üretilmedi — kimlik omurgası kurulmadı.")


def _c_oast(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("ssrf-oast", "xxe-oast", "rce-oast", "oast")
    oast_ran = cx.meta_truthy("oast_probed")
    if n:
        return _mk("vuln.oast", "OAST asenkron callback (kör SSRF/XXE/RCE)", "vuln", FOUND,
                   f"{n} kör zafiyet OAST callback'i ile aktif kanıtlandı.", n, sev or "high", conf)
    if cx.level == "recon":
        return _mk("vuln.oast", "OAST asenkron callback (kör SSRF/XXE/RCE)", "vuln", NOT_CHECKED,
                   "Keşif seviyesi — aktif OAST enjeksiyonu kapalı.")
    if oast_ran:
        return _mk("vuln.oast", "OAST asenkron callback (kör SSRF/XXE/RCE)", "vuln", CLEAN,
                   "OAST dinleyicisi devrede; asenkron backend callback'i tetiklenmedi.")
    return _mk("vuln.oast", "OAST asenkron callback (kör SSRF/XXE/RCE)", "vuln", NOT_CHECKED,
               "OAST probu henüz çalışmadı veya aktif değil.")


def _c_race_condition(cx: _Ctx) -> Dict[str, Any]:
    n, sev, conf = cx.findings("race_probe", "concurrency_probe")
    ran = cx.meta_truthy("race_probed")
    if n:
        return _mk("app.race_condition", "Eşzamanlılık / Finansal Yarış Durumu (CWE-362)", "app", FOUND,
                   f"{n} yarış durumu (race condition) zafiyeti tespit edildi.", n, sev or "high", conf)
    if ran:
        return _mk("app.race_condition", "Eşzamanlılık / Finansal Yarış Durumu (CWE-362)", "app", CLEAN,
                   "Finansal ve durum-değiştirici uçlar denendi; yarış durumu koruması aktif.")
    eps = cx.meta_get("endpoints") or []
    if not eps:
        return _mk("app.race_condition", "Eşzamanlılık / Finansal Yarış Durumu (CWE-362)", "app", NOT_CHECKED,
                   "Endpoint keşfi henüz yapılmadı — eşzamanlılık probunun girdisi yok.")
    return _mk("app.race_condition", "Eşzamanlılık / Finansal Yarış Durumu (CWE-362)", "app", NOT_CHECKED,
               "Finansal durum-değiştirici uç bulunamadı veya eşzamanlılık probu koşmadı.")


# Sıra = operatörün okuyacağı mantıksal akış (yüzey → ifşa → zafiyet → erişim → altyapı → duruş).
_RESOLVERS = [
    _c_identity,
    _c_ports,
    _c_subdomains,
    _c_endpoints,
    _c_origin_exposure,
    _c_sensitive_paths,
    _c_js_secrets,
    _c_openapi,
    _c_graphql,
    _c_nuclei,
    _c_dast,
    _c_oast,
    _c_idor,
    _c_race_condition,
    _c_kubernetes,
    _c_k8s_escape,
    _c_k8s_etcd,
    _c_k8s_registry,
    _c_hypervisor,
    _c_wordpress,
    _c_deserialization,
    _c_appliance,
    _c_resilience,
]


def build_coverage(state: Dict[str, Any]) -> Dict[str, Any]:
    """SAF çekirdek. Tarama-sonu `state`'inden taban-tespit-sınıfı kapsama sözleşmesini üret.

    state anahtarları (hepsi opsiyonel — degrade-safe):
      evidence: [{tool, severity, confidence_tier, verified}]
      ran_stages: [str]      (session.stages anahtarları)
      tried_tools: [str]     (tried_count>0 olan edge.tool'ları)
      meta: {...}            (attack_graph root.meta)
      profile: {...}         (root.meta['target_profile'] serileştirilmiş dict)
      resilience_enabled: bool
      level: 'recon'|'standard'|'deep'

    Döner: {classes, families, found, clean, not_checked, total, coverage_percent, gaps, generated}
    'gaps' = kontrol-edilemedi sınıfların eyleme-geçirilebilir listesi (asıl değer)."""
    cx = _Ctx(state or {})
    classes: List[Dict[str, Any]] = []
    for resolve in _RESOLVERS:
        try:
            classes.append(resolve(cx))
        except Exception as e:  # noqa: BLE001 — tek sınıf çökse bile sözleşme üretilmeli
            classes.append({
                "key": getattr(resolve, "__name__", "?"), "label": "(çözülemedi)",
                "family": "unknown", "status": NOT_CHECKED, "status_label": _STATUS_LABEL[NOT_CHECKED],
                "reason": f"kapsama çözücü hatası: {type(e).__name__}", "finding_count": 0,
                "top_severity": None, "confirmed": False,
            })

    found = sum(1 for c in classes if c["status"] == FOUND)
    clean = sum(1 for c in classes if c["status"] == CLEAN)
    not_checked = sum(1 for c in classes if c["status"] == NOT_CHECKED)
    total = len(classes)
    checked = found + clean
    gaps = [
        {"key": c["key"], "label": c["label"], "reason": c["reason"], "family": c["family"]}
        for c in classes if c["status"] == NOT_CHECKED
    ]
    return {
        "classes": classes,
        "found": found,
        "clean": clean,
        "not_checked": not_checked,
        "total": total,
        # Kapsam yüzdesi = kontrol edilebilen (bulundu+temiz) / toplam. "Ne kadarını
        # gerçekten inceledik" — bulgu SAYISI değil, KAPSAM ölçüsü.
        "coverage_percent": round(checked / total * 100) if total else 0,
        "gaps": gaps,
        "generated": "coverage_contract/v1",
    }
