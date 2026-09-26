"""
Kadim Güvenlik — Kubernetes-Farkında Keşif & İfşa Probu (IPB payoff)
====================================================================
Türkçe: Klasik port taraması bir K8s sunucusunda "boş" döner — çünkü K8s'in kritik portları
(6443/10250/2379...) top-1000'de yok ve değer banner'da değil API-semantiğinde. Bu modül,
hedef profili "kubernetes" dediğinde (playbook.k8s_probe aktif) devreye girer ve K8s'e ÖZGÜ
saldırı yüzeyini yoklar:

  - kube-apiserver (6443/8443, eski insecure 8080): anonim erişim + sürüm ifşası + anon SECRET
    okuma (RBAC yanlış yapılandırması → tüm sırlar).
  - RKE2/Rancher supervisor (9345): apiserver-benzeri API; gitVersion suffix'i (+rke2r1)
    dağıtımı RKE2 olarak damgalar. Rancher yönetim arayüzü (8443) Norman-API/UI imzasıyla
    ayrıca tanınır.
  - kubelet (10250 r/w, 10255 read-only): /pods → pod spec + env (SIRLAR) ifşası; /exec = RCE
    YETENEĞİ (burada ÇALIŞTIRILMAZ — yalnız erişilebilirlik/authz gözlemi).
  - etcd (2379 client, 2380 peer): sürüm + anahtar ifşası → tüm cluster sırları.
  - kube-proxy (10256), controller-manager (10257), scheduler (10259), cAdvisor (4194):
    /healthz, /proxyMode, /api/* uçlarıyla K8s rolü damgalanır (fingerprint — düşük şiddet
    ama saldırı haritası için değerli istihbarat).

KANIT = auth'suz API YANITININ KENDİSİ (SecretList/PodList JSON döndü) → deterministik,
template tahmini değil → confirmed. TAHRİBATSIZ: yalnız GET; exec/create/delete YOK.
Doktrin: yalnız AÇIK portlar yoklanır (gereksiz gürültü yok); best-effort, ASLA raise etmez.

Tasarım: classify_* çekirdeği SAF (izole test), probe_kubernetes ince I/O.
"""

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("k8s-probe")

# Port → (bileşen, şema). Yalnız bunlar (AÇIKSA) yoklanır. Bu tablo TEK doğruluk kaynağı —
# _probe_kubernetes port filtresi de buradan okur (iki listede sürüklenme olmaz).
KUBE_PORTS: Dict[int, tuple] = {
    6443: ("apiserver", "https"),
    8443: ("apiserver", "https"),
    8080: ("apiserver-insecure", "http"),   # eski --insecure-port (1.24 öncesi) → auth'suz tam API
    9345: ("rke2-supervisor", "https"),     # RKE2/Rancher supervisor — apiserver-benzeri API
    10250: ("kubelet", "https"),
    10255: ("kubelet-ro", "http"),          # read-only, deprecated ama sahada var
    2379: ("etcd", "https"),
    2380: ("etcd-peer", "https"),           # peer ucu; mTLS gevşekse /version sızar
    10256: ("kube-proxy", "http"),          # /proxyMode + /healthz
    10257: ("kube-controller", "https"),    # controller-manager /healthz
    10259: ("kube-scheduler", "https"),     # scheduler /healthz
    4194: ("cadvisor", "http"),             # cAdvisor container metrik arayüzü
    16443: ("apiserver", "https"),          # k3s secure apiserver (non-root kurulum portu)
}


def extract_k8s_version(body: str) -> Optional[str]:
    """apiserver/kubelet /version yanıtından gitVersion çıkar (SAF) → cve_intel'e beslenir."""
    if not body:
        return None
    m = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', body)
    return m.group(1) if m else None


def classify_apiserver(status: int, body: str) -> Optional[Dict[str, Any]]:
    """apiserver yanıtı K8s API mi + ne ifşa ediyor? (SAF). Döner sınıf dict ya da None."""
    body = body or ""
    # Sürüm ucu
    if '"gitVersion"' in body and ('"major"' in body or "kubernetes" in body.lower() or "v1." in body):
        return {"kind": "apiserver_version", "version": extract_k8s_version(body)}
    # API kök/gruplar (apiserver'ın canlı olduğu deterministik işaret)
    if '"kind":"APIVersions"' in body or '"kind":"APIGroupList"' in body:
        return {"kind": "apiserver_api"}
    # apiserver'ın imza Status nesnesi (403/401 bile olsa K8s olduğunu kanıtlar)
    if '"kind":"Status"' in body and ('"apiVersion"' in body or "forbidden" in body.lower()
                                      or "unauthorized" in body.lower()):
        return {"kind": "apiserver_status", "authz": ("open" if status == 200 else "enforced")}
    return None


def classify_anon_secrets(status: int, body: str) -> Optional[Dict[str, Any]]:
    """Anonim SECRET okuma başarılı mı? (SAF). SecretList + item → confirmed kritik ifşa."""
    body = body or ""
    if status == 200 and '"kind":"SecretList"' in body:
        n = body.count('"type":')  # kaba item sayacı
        return {"exposed": True, "count_hint": n}
    return None


def classify_kubelet_pods(status: int, body: str) -> Optional[Dict[str, Any]]:
    """kubelet /pods auth'suz PodList döndü mü? (SAF). Pod env'lerinde sır sızar → kritik."""
    body = body or ""
    if status == 200 and '"kind":"PodList"' in body:
        return {"exposed": True, "pod_hint": body.count('"name":')}
    return None


def classify_etcd(status: int, body: str) -> Optional[Dict[str, Any]]:
    """etcd yanıtı (SAF). Sürüm imzası ya da anahtar ifşası."""
    body = body or ""
    if "etcdserver" in body or "etcdcluster" in body:
        mv = re.search(r'"etcdserver"\s*:\s*"([^"]+)"', body)
        return {"kind": "etcd_version", "version": mv.group(1) if mv else None}
    # etcd v2 anahtar listesi (auth'suz) → tüm sırlar
    if status == 200 and '"action":"get"' in body and '"node"' in body:
        return {"kind": "etcd_keys", "exposed": True}
    return None


def classify_distro(version: Optional[str]) -> Optional[str]:
    """gitVersion suffix'inden K8s DAĞITIMINI çıkar (SAF).
    v1.28.4+rke2r1 → rke2, v1.29.0+k3s1 → k3s, v1.28.3-gke.1000 → gke, -eks-… → eks.
    "Rancher böyle bir küme" sorusunun yanıtı burada damgalanır; None = vanilla/bilinmiyor."""
    if not version:
        return None
    v = version.lower()
    if "rke2" in v:
        return "rke2"
    if "k3s" in v:
        return "k3s"
    if "-gke." in v or "+gke." in v:
        return "gke"
    if "-eks" in v:
        return "eks"
    if "aks" in v:
        return "aks"
    if "rancher" in v:
        return "rancher"
    return None


def classify_kubelet_denied(status: int, body: str) -> Optional[Dict[str, Any]]:
    """kubelet REDDETME imzası (SAF): 401/403 + gövdede 'Unauthorized'. İki imza kabul:
    JSON hata ({"error":"Unauthorized"}) ve düz metin ('Unauthorized' — eski kubelet /
    read-only port). Generic web 401'i (HTML login sayfası) EŞLEŞMEZ — HTML gövde
    FP korumasıyla elenir; imza zorunlu."""
    body = (body or "").lower()
    if status in (401, 403) and "unauthorized" in body:
        if "<html" in body or "<!doctype" in body:
            return None  # generic web/login sayfası — kubelet imzası değil
        return {"kind": "kubelet_denied"}
    return None


# TLS sertifika kimliği — dağıtım/bileşen marker'ları. Sürüm ucu auth arkasında olduğunda
# (RKE2 CIS: anonymous-auth=false → /version 401) DAĞITIMI yakalamanın tek dış yolu TLS
# el-sıkışmasıdır: RKE2 serving-ca subject'i O=rke2, k3s CA O=k3s, CN=kube-apiserver...
_DISTRO_CERT_MARKERS = ("rke2", "k3s", "harvester", "rancher", "microk8s", "openshift", "okd")
_COMPONENT_CERT_MARKERS = ("kube-apiserver", "kubelet", "etcd", "kube-scheduler",
                           "kube-controller-manager", "ingress")


def classify_tls_identity(cert_strings: Optional[List[str]]) -> Optional[Dict[str, Any]]:
    """Sertifika DER'ından çıkarılan ASCII dizelerinde dağıtım/bileşen imzası ara (SAF).
    El-sıkışması DOĞRULANMADIĞI için kanıt ağırlığı düşüktür: kimlik-ETİKETİ için kullanılır,
    bulgu şiddetini tek başına yükseltmez. Marker yoksa None."""
    if not cert_strings:
        return None
    joined = " ".join(cert_strings).lower()
    distro = next((m for m in _DISTRO_CERT_MARKERS if m in joined), None)
    comps = [m for m in _COMPONENT_CERT_MARKERS if m in joined]
    if not distro and not comps:
        return None
    return {"distro": distro, "components": comps[:6]}


async def tls_peer_identity(host: str, port: int, timeout: float = 6.0) -> Optional[List[str]]:
    """Host:port'a TLS el-sıkışması (VERIFY YOK) → sertifika DER'ındaki ASCII dizeleri.
    Self-signed K8s uçlarında dağıtım kimliğini (rke2/k3s/...) sürüm ucu kapalıyken de yakalar.
    Stdlib-only (stack'te `cryptography` YOK): DER'ı tam parse etmeden printable-run taraması
    yapar — CN/O/SAN değerleri DER'da literal durur. Hata → None (prob asla düşmez)."""
    import asyncio
    import socket
    import ssl

    def _grab() -> bytes:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ts:
                return ts.getpeercert(binary_form=True) or b""

    try:
        der = await asyncio.to_thread(_grab)
    except Exception:
        return None
    if not der:
        return None
    return [m.decode("latin-1", "replace")
            for m in re.findall(rb"[ -~]{4,}", der)][:120]


def classify_rancher(status: int, body: str) -> Optional[Dict[str, Any]]:
    """Rancher yönetim düzlemi imzası (SAF). Norman-API 'baseType' alanı ve UI <title>
    ayırt edicidir; ikisi de yoksa None (FP koruması — 8443'teki rastgele web uygulaması
    Rancher sanılmasın)."""
    body = body or ""
    low = body.lower()
    if "<title>rancher" in low or "rancher dashboard" in low:
        return {"kind": "rancher_ui"}
    # Rancher Norman API: {"baseType":"error"|"collection", ...} + cattle/rancher referansı
    if '"baseType"' in body and ("cattle" in low or "rancher" in low):
        return {"kind": "rancher_api", "authz": ("open" if status == 200 else "enforced")}
    if '"type":"collection"' in body and '"links"' in body and ("rancher" in low or "cattle" in low):
        return {"kind": "rancher_api", "authz": ("open" if status == 200 else "enforced")}
    return None


def classify_kube_healthz(component: str, status: int, body: str) -> Optional[Dict[str, Any]]:
    """kube-proxy/scheduler/controller-manager healthz-proxymode imzası (SAF).
    Rol damgalama = saldırı haritasına "bu host K8s node'u VE rolü X" istihbaratı."""
    body = (body or "").strip().lower()
    if status != 200:
        return None
    if component == "kube-proxy" and body in ("iptables", "ipvs", "nftables", "kernelspace", "userspace"):
        return {"kind": "kube_proxy_mode", "mode": body}
    if component in ("kube-scheduler", "kube-controller") and body == "ok":
        return {"kind": "healthz_open"}
    return None


def classify_cadvisor(status: int, body: str) -> Optional[Dict[str, Any]]:
    """cAdvisor /api/* makine-bilgisi imzası (SAF). num_cores alanı ayırt edicidir."""
    body = body or ""
    if status == 200 and '"num_cores"' in body:
        return {"kind": "cadvisor_machine"}
    return None


# ============================================================
# V2 (Madde 5 / T4) — NodePort sınıflandırma + sürüm→CVE matrisi
# ============================================================
# NEDEN: rustscan tam-port taraması 30000-32767 NodePort aralığını GÖRÜYOR ama kimse
# ne olduğunu söylemiyordu: NodePort'ta yaşayan kubernetes-dashboard, anon private
# registry ve ingress-arkası apiserver "rastgele açık port" sanılıyordu. Kontrol
# düzlemi (6443) firewall'luyken bile K8s NodePort'tan DIŞARI SIZAR — tespit kördü.

# K8s servis NodePort aralığı (kube-apiserver --service-node-port-range varsayılanı).
NODEPORT_MIN, NODEPORT_MAX = 30000, 32767


def is_nodeport(port: int) -> bool:
    """Port K8s NodePort aralığında mı? (SAF)"""
    try:
        return NODEPORT_MIN <= int(port) <= NODEPORT_MAX
    except (TypeError, ValueError):
        return False


def classify_nodeport(status: int, body: str, headers: Optional[Dict[str, Any]] = None
                      ) -> Optional[Dict[str, Any]]:
    """NodePort aralığındaki bir AÇIK portun HTTP imzasını sınıflandır (SAF).
    Tek bir yanıtın (herhangi bir path) kanıtlarını birleştirir:
      - Docker-Distribution-Api-Version header'ı → private registry (K8s cluster içi sık)
      - Kubernetes Dashboard HTML/asset imzası → yönetim konsolu
      - apiserver imzaları (gitVersion / APIVersions / Status) → classify_apiserver'e devir
    Dikkat: düz "ok" body (healthz) KASITLI eşleşmez — Go dünyasında FP'dir; K8s damgası
    yalnız AYIRT EDİCİ imzayla vurulur."""
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if headers.get("docker-distribution-api-version"):
        return {"kind": "registry"}
    body = body or ""
    dash = classify_dashboard(status, body, headers)
    if dash:
        return dict(dash, kind="dashboard")   # nodeport bağlamı: tip=dashboard, alt detay korunur
    cls = classify_apiserver(status, body)
    if cls:
        return cls
    return None


def classify_registry_catalog(status: int, body: str) -> Optional[Dict[str, Any]]:
    """Private registry anonim /v2/_catalog yanıtı (SAF). 200 + repositories listesi =
    anonim imaj kataloğu ifşası (kritik: iç imajlar/dahili yazılım sızar)."""
    body = body or ""
    if status == 200 and '"repositories"' in body:
        m = re.search(r'"repositories"\s*:\s*\[(.*?)\]', body, re.S)
        repos: List[str] = []
        if m:
            repos = [x.strip(' "') for x in m.group(1).split(",") if x.strip(' "')][:10]
        return {"exposed": True, "repositories": repos}
    return None


def classify_dashboard(status: int, body: str, headers: Optional[Dict[str, Any]] = None
                       ) -> Optional[Dict[str, Any]]:
    """Kubernetes Dashboard imzası (SAF). <title> ve asset yolları ayırt edicidir;
    3xx + Location '/...' yönlendirmesi probable'dır (arkasında login olabilir).
    Grafana/rastgele SPA eşleşmez (FP koruması)."""
    body = body or ""
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    low = body.lower()
    if status == 200 and ("<title>kubernetes dashboard" in low
                          or "kubernetes dashboard</title>" in low
                          or ('"kubernetes-dashboard"' in low and "main.js" in low)):
        return {"kind": "dashboard_ui", "authz": "open" if "<title>kubernetes dashboard" in low else "unknown"}
    loc = headers.get("location") or ""
    if status in (301, 302, 303, 307, 308) and "dashboard" in loc.lower():
        return {"kind": "dashboard_redirect", "location": loc[:120]}
    return None


# ---- Sürüm karşılaştırma + resmî CVE danışma matrisi (Madde 5 / T4) ----

def parse_k8s_semver(version: str) -> Optional[tuple]:
    """K8s sürümünü (major, minor, patch) üçlüsüne indir (SAF).
    'v1.28.4+rke2r1' → (1,28,4); '1.30.2-eks-...' → (1,30,2). Dağıtım soneki
    (+rke2r1/-gke...) sürüm-KARŞILAŞTIRMADA yok sayılır — dağıtım backport'ları
    danışmanın 'affected' listesiyle çapraz okunur, minor/patch otoriterdir."""
    if not version:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(version))
    if not m:
        return None
    try:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def compare_k8s_versions(a: str, b: str) -> int:
    """K8s sürüm kıyası (SAF): a<b → -1, eşit → 0, a>b → 1. Parçalanamayan → 0."""
    ta, tb = parse_k8s_semver(a), parse_k8s_semver(b)
    if ta is None or tb is None:
        return 0
    return (ta > tb) - (ta < tb)


_K8S_CVE_SNAPSHOT: Optional[List[Dict[str, Any]]] = None


def load_k8s_cve_snapshot() -> List[Dict[str, Any]]:
    """Statik K8s CVE danışma matrisi (resmî feed'den üretilmiş snapshot; runtime ağ
    isteği YOK — doktrin). Dosya yok/bozuksa sessiz [] → sıfır regresyon."""
    global _K8S_CVE_SNAPSHOT
    if _K8S_CVE_SNAPSHOT is not None:
        return _K8S_CVE_SNAPSHOT
    import json
    from pathlib import Path
    try:
        path = Path(__file__).resolve().parent / "data" / "k8s" / "k8s_cves.json"
        data = json.loads(path.read_text())
        _K8S_CVE_SNAPSHOT = [e for e in (data.get("entries") or []) if e.get("fixed_in")]
    except Exception:
        _K8S_CVE_SNAPSHOT = []
    return _K8S_CVE_SNAPSHOT


def match_k8s_cves(component: str, version: str,
                   snapshot: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Bileşen+sürüm → resmî CVE danışma eşleşmeleri (SAF, deterministik).
    Semantik (snapshot.match_semantics ile birebir):
      - sürümün minor'ı fixed_in'de VAR → version < fixed sürümü ise zaafiyetli;
      - minor, en büyük fixed minor'ından BÜYÜK → düzeltilmiş dal;
      - minor, en küçük fixed minor'ından KÜÇÜK → zaafiyetli (fix penceresi öncesi dal).
    Kanıt ağırlığı: sürüm-kıyası deterministiktir ama aktif PoC YOKTUR → probable.
    Dağıtım sonekli sürümlerde (rke2/k3s) backport ihtimali 'affected' listesinde
    görünür — kanıt metnine taşınır, hüküm değişmez."""
    tv = parse_k8s_semver(version)
    if tv is None:
        return []
    out: List[Dict[str, Any]] = []
    for entry in (snapshot if snapshot is not None else load_k8s_cve_snapshot()):
        if component not in (entry.get("components") or []):
            continue
        fixed_in = entry.get("fixed_in") or {}
        minors: List[int] = []
        for mk in fixed_in:
            mv = parse_k8s_semver(mk + ".0")
            if mv:
                minors.append(mv[1])
        if not minors:
            continue
        lo, hi = min(minors), max(minors)
        major = tv[0]
        minor, patch = tv[1], tv[2]
        if major != 1:
            continue  # k8s major'u hep 1'dir; başka ürün yanlış eşleşmesin
        vulnerable = False
        reason = ""
        if minor in minors:
            fixed_v = fixed_in[f"{major}.{minor}"] if f"{major}.{minor}" in fixed_in else \
                fixed_in.get(f"1.{minor}")
            if fixed_v and compare_k8s_versions(version, fixed_v) < 0:
                vulnerable = True
                reason = f"{version} < düzeltme {fixed_v} ({major}.{minor} dalı)"
        elif minor > hi:
            vulnerable = False
            reason = f"{major}.{minor} dalı düzeltilmiş (fix ≥ {major}.{hi})"
        elif minor < lo:
            vulnerable = True
            reason = (f"{major}.{minor} dalı fix penceresi öncesinde "
                      f"(düzeltilen en eski dal {major}.{lo})")
        if vulnerable:
            out.append({**entry, "match_reason": reason})
    return out


# ============================================================
# I/O — TAHRİBATSIZ (yalnız GET), best-effort
# ============================================================

async def _get(client, url: str) -> Optional[tuple]:
    """Tek GET → (status, body[:16KB]). Hata → None."""
    try:
        r = await client.get(url, timeout=10.0)
        return (r.status_code, (r.text or "")[:16384])
    except Exception:
        return None


def _finding(title, severity, target, proof, *, tier="confirmed",
             cwe=None, mitre="T1613", method="k8s-unauth-probe") -> Dict[str, Any]:
    return {"title": title, "severity": severity, "target": target, "proof": proof,
            "confidence_tier": tier, "cwe": cwe or ["CWE-306"], "mitre": mitre,
            "verification_method": method,
            "verification_confidence": 0.9 if tier == "confirmed" else None}


async def probe_kubernetes(host: str, open_ports: List[int], client,
                           cert_identity=None, extra_ports: Optional[Dict[int, str]] = None
                           ) -> List[Dict[str, Any]]:
    """Açık K8s portlarını TAHRİBATSIZ yokla → bulgu listesi. ASLA raise etmez.
    Yalnız GET; kubelet /exec, apiserver create/delete DENENMEZ.

    IDENTITY-FIRST ilkesi: ifşa YOKSA bile kimliği doğrulanmış kontrol düzlemi (401/403
    K8s Status imzası) SALDIRI YÜZEYİ kaydı olarak raporlanır — eski davranışta
    sertleştirilmiş RKE2/kubeadm master 'boş tarama' gibi görünüyordu.
    cert_identity: async (host, port) -> Optional[List[str]] enjekte edilebilir TLS sertifika
    resolver'ı (varsayılan None = ağa dokunmaz; pipeline tls_peer_identity geçirir).
    extra_ports: {port: şema} — KUBE_PORTS tablosunda OLMAYAN ama HTTP-imza pasıyla K8s API'si
    olduğu DOĞRULANMIŞ portlar (NodePort/dashboard/ingress-arkası apiserver, 443...). Bunlar da
    apiserver gibi derin yoklanır → kontrol-düzlemi firewall arkasında olsa bile NodePort'tan
    sızan K8s ifşası kaçmaz. Zaten KUBE_PORTS'ta olan portlar yinelenmez."""
    findings: List[Dict[str, Any]] = []
    ports = {int(p) for p in open_ports if str(p).isdigit()}
    kube_open = [(p, KUBE_PORTS[p]) for p in ports if p in KUBE_PORTS]
    if extra_ports:
        _known = {p for p, _ in kube_open}
        for _p, _scheme in extra_ports.items():
            try:
                _pi = int(_p)
            except (TypeError, ValueError):
                continue
            if _pi in ports and _pi not in _known:
                kube_open.append((_pi, ("apiserver", _scheme or "https")))
    if not kube_open:
        return findings

    for port, (component, scheme) in kube_open:
        base = f"{scheme}://{host}:{port}"
        try:
            if component in ("apiserver", "apiserver-insecure", "rke2-supervisor"):
                # 1) Sürüm + canlılık (+ dağıtım damgası: vanilla/rke2/k3s/gke/eks/aks)
                r = await _get(client, f"{base}/version")
                if r:
                    cls = classify_apiserver(r[0], r[1])
                    if cls and cls.get("kind") == "apiserver_version":
                        ver = cls.get("version") or "?"
                        distro = classify_distro(ver)
                        label = {"rke2-supervisor": "RKE2 supervisor"}.get(component, "Kubernetes apiserver")
                        if distro and distro not in label.lower():
                            label = f"{label} ({distro.upper()})"
                        fd = _finding(
                            f"{label} İnternete Açık (sürüm {ver}) @ {base}",
                            "medium", base,
                            f"kube-apiserver {port} erişilebilir; /version gitVersion={ver}. "
                            + (f"Dağıtım damgası: {distro}. " if distro else "") +
                            f"Kontrol düzlemi dış ağa açık — sürüm→CVE ilişkilendirmesine ve "
                            f"saldırı yüzeyine işaret (cve_intel'e beslenir).",
                            cwe=["CWE-200"], mitre="T1613")
                        if ver != "?":
                            fd["version"] = ver    # pipeline: SERVICE düğümü → CVE/KEV zinciri
                        fd["product"] = "kube-apiserver"
                        fd["port"] = port
                        findings.append(fd)
                    elif cls is not None and component != "apiserver-insecure":
                        # 1b) IDENTITY-FIRST: auth zorunlu ama kapı dışa açık → kimliği
                        # doğrulanmış saldırı yüzeyi KAYDI. Eski davranış: 401/403 → sessizlik →
                        # sertleştirilmiş RKE2/kubeadm master "boş tarama" gibi görünüyordu.
                        cert_label = ""
                        cert_note = ""
                        if cert_identity is not None:
                            try:
                                ident = classify_tls_identity(await cert_identity(host, port))
                            except Exception:
                                ident = None
                            if ident:
                                bits = []
                                if ident.get("distro"):
                                    bits.append(f"dağıtım: {ident['distro'].upper()}")
                                    cert_label = f" ({ident['distro'].upper()})"
                                if ident.get("components"):
                                    bits.append("bileşen: " + ", ".join(ident["components"][:3]))
                                if bits:
                                    cert_note = "TLS sertifika kimliği (" + "; ".join(bits) + "). "
                        base_label = {"rke2-supervisor": "RKE2 supervisor"}.get(
                            component, "Kubernetes apiserver")
                        findings.append(_finding(
                            f"{base_label}{cert_label} Dış Ağa Açık — auth zorunlu @ {base}",
                            "low", base,
                            f"GET /version → HTTP {r[0]} ve Kubernetes Status imzası: kontrol düzlemi "
                            f"dış ağa erişilebilir ve kimliği doğrulanmış (anonim istek reddediliyor — "
                            f"sertleştirme doğru). {cert_note}Bu bir SALDIRI YÜZEYİ kaydıdır: credential "
                            f"atağı, gelecek apiserver CVE'leri ve yönetim kaçakları dışarıdan canlı. "
                            f"Sürüm ucu kapalı olduğundan CVE listesi dağıtım etiketiyle sınırlı.",
                            cwe=["CWE-200"], mitre="T1613", method="k8s-signature"))
                # 2) Anonim SECRET okuma (RBAC misconfig — en kritik)
                r2 = await _get(client, f"{base}/api/v1/secrets?limit=5")
                if not r2:
                    r2 = await _get(client, f"{base}/api/v1/namespaces/default/secrets?limit=5")
                if r2:
                    sec = classify_anon_secrets(r2[0], r2[1])
                    if sec and sec.get("exposed"):
                        findings.append(_finding(
                            f"Kubernetes Anonim Secret Okuma @ {base}",
                            "critical", base,
                            f"Auth'suz GET /api/v1/secrets → SecretList döndü (~{sec.get('count_hint')} "
                            f"öğe). Anonim RBAC yanlış yapılandırması: TÜM cluster sırları (token, "
                            f"kimlik) okunabilir. Anonim yanıt = deterministik kanıt.",
                            cwe=["CWE-306", "CWE-284"], mitre="T1552.007"))
                    else:
                        # API canlı ama secrets reddedildi → yine de "apiserver açık" (insecure 8080 ise kritik)
                        cls2 = classify_apiserver(r2[0], r2[1])
                        if component == "apiserver-insecure" and cls2:
                            findings.append(_finding(
                                f"Kubernetes Insecure apiserver Portu (8080) @ {base}",
                                "critical", base,
                                "Eski --insecure-port (8080) açık: auth'suz tam API erişimi. "
                                "Cluster tamamen ele geçirilebilir.",
                                cwe=["CWE-306"], mitre="T1613"))
                # 3) Rancher yönetim düzlemi (8443'te UI/Norman-API). 3 ucuz GET; marker'lar
                # ayırt edici olduğundan plain-apiserver'da FP üretmez.
                if component == "apiserver" and port == 8443:
                    for path in ("/v3-public/settings", "/v3", "/"):
                        rr = await _get(client, f"{base}{path}")
                        if not rr:
                            continue
                        rc = classify_rancher(rr[0], rr[1])
                        if rc:
                            findings.append(_finding(
                                f"Rancher Yönetim Arayüzü Dış Ağa Açık @ {base}",
                                "medium", base,
                                f"{base}{path} → Rancher imzası ({rc.get('kind')}). Kontrol düzlemi "
                                f"yönetim konsolu İnternete açık: default-login/brute-force ve "
                                f"Rancher CVE yüzeyi (nuclei 'rancher' tag'i hedeflenir). "
                                f"Authz: {rc.get('authz', 'ui')}.",
                                tier=("confirmed" if rc.get("authz") == "open" else "probable"),
                                cwe=["CWE-200"], mitre="T1190",
                                method="rancher-signature"))
                            break

            elif component in ("kubelet", "kubelet-ro"):
                r = await _get(client, f"{base}/pods")
                if r:
                    pods = classify_kubelet_pods(r[0], r[1])
                    if pods and pods.get("exposed"):
                        findings.append(_finding(
                            f"Kubernetes kubelet Auth'suz /pods İfşası @ {base}",
                            "critical", base,
                            f"kubelet {port} auth'suz PodList döndü (~{pods.get('pod_hint')} isim). "
                            f"Pod env değişkenlerinde SIRLAR sızar; 10250'de /exec ile container'a "
                            f"komut çalıştırma (RCE) yüzeyi mevcut (ÇALIŞTIRILMADI). Anonim yanıt = kanıt.",
                            cwe=["CWE-306"], mitre="T1552.007"))
                    else:
                        # kubelet kimliği auth duvarı ARDINDAN da doğrulanır (identity-first):
                        # "10250 dışa açık ve karşındaki kubelet" tek başına saldırı haritasıdır.
                        kd = classify_kubelet_denied(r[0], r[1])
                        if kd:
                            findings.append(_finding(
                                f"Kubernetes kubelet Dış Ağa Açık — auth zorunlu @ {base}",
                                "low", base,
                                f"GET /pods → HTTP {r[0]} 'Unauthorized' imzası: kubelet {port} dış "
                                f"ağından erişilebilir, anonim yoklama reddediliyor (sertleştirme doğru). "
                                f"Kimliği doğrulanmış SALDIRI YÜZEYİ: kubelet CVE yüzeyi ve credential "
                                f"atağı dışarıdan mümkün (RCE yolu /exec — ÇALIŞTIRILMADI).",
                                cwe=["CWE-200"], mitre="T1613", method="k8s-signature"))

            elif component in ("etcd", "etcd-peer"):
                r = await _get(client, f"{base}/version")
                if r:
                    et = classify_etcd(r[0], r[1])
                    if et:
                        if et.get("exposed"):
                            sev, detail = "critical", "auth'suz anahtar okuma → tüm cluster sırları."
                        else:
                            sev, detail = ("high",
                                           f"etcd {port} dış ağa açık (sürüm {et.get('version')}); "
                                           f"mTLS yoksa tüm cluster verisi risk altında.")
                        findings.append(_finding(
                            f"Kubernetes etcd Dış Ağa Açık @ {base}", sev, base, detail,
                            tier=("confirmed" if et.get("exposed") else "probable"),
                            cwe=["CWE-306"], mitre="T1552"))
                # etcd v2 anahtar denemesi
                r2 = await _get(client, f"{base}/v2/keys/?recursive=false")
                if r2:
                    et2 = classify_etcd(r2[0], r2[1])
                    if et2 and et2.get("exposed"):
                        findings.append(_finding(
                            f"Kubernetes etcd Anonim Anahtar İfşası @ {base}",
                            "critical", base,
                            "Auth'suz GET /v2/keys → anahtar ağacı döndü. Cluster sırları dökülebilir.",
                            cwe=["CWE-306"], mitre="T1552"))

            elif component in ("kube-proxy", "kube-scheduler", "kube-controller"):
                # Rol damgalama: healthz/proxyMode açık → hostun K8s rolü doğrulanır.
                # Düşük şiddet ama saldırı haritası için yüksek-değerli istihbarat.
                path = "/proxyMode" if component == "kube-proxy" else "/healthz"
                r = await _get(client, f"{base}{path}")
                if r:
                    hz = classify_kube_healthz(component, r[0], r[1])
                    if hz:
                        detail = (f"kube-proxy {port} auth'suz /proxyMode döndü (mod: {hz.get('mode')})."
                                  if hz.get("kind") == "kube_proxy_mode"
                                  else f"{component} {port} auth'suz /healthz=ok döndü.")
                        findings.append(_finding(
                            f"Kubernetes {component} Ucu Açık @ {base}",
                            "low", base,
                            f"{detail} Host K8s node'u ve rolü damgalandı — saldırı haritası "
                            f"istihbaratı (metrik/healthz bilgi ifşası).",
                            cwe=["CWE-200"], mitre="T1613"))

            elif component == "cadvisor":
                r = await _get(client, f"{base}/api/v1.3/machine")
                if r:
                    cad = classify_cadvisor(r[0], r[1])
                    if cad:
                        findings.append(_finding(
                            f"Kubernetes cAdvisor Metrik Arayüzü Açık @ {base}",
                            "low", base,
                            f"cAdvisor {port} auth'suz makine/container bilgisi döndü (num_cores "
                            f"imzası). Container env/process istihbaratı sızdırır.",
                            cwe=["CWE-200"], mitre="T1613"))
        except Exception as e:
            logger.debug(f"K8s prob hatası ({base}): {e}")
            continue

    # Dedup (aynı başlık+hedef)
    seen = set()
    out = []
    for f in findings:
        key = (f["title"], f["target"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ============================================================
# V2 I/O — NodePort yüzey pası (dashboard / registry / apiserver-sızıntı)
# ============================================================

async def _get_full(client, url: str) -> Optional[tuple]:
    """Tek GET → (status, body[:16KB], headers-dict). Hata → None. _get'ten farkı:
    header'ları da taşır — registry tespiti Docker-Distribution-Api-Version header'ı,
    dashboard yönlendirmesi Location header'ı olmadan kurulamaz."""
    try:
        r = await client.get(url, timeout=10.0)
        return (r.status_code, (r.text or "")[:16384], dict(r.headers or {}))
    except Exception:
        return None


async def probe_k8s_surface(host: str, open_ports: List[int], client,
                            max_ports: int = 24
                            ) -> tuple:
    """NodePort aralığındaki AÇIK portlarda tahribatsız imza pası (V2 / Madde 5).
    rustscan tam-port bu portları GÖRÜYOR ama kimse sınıflandırmıyordu. Port başına
    en fazla ~4 GET (yalnız ZATEN açık portlara — gürültü doktrini korunur):
      /version (https→http) → apiserver imzası + sürüm; değilse / → dashboard;
      Docker-Distribution header'ı görüldüyse /v2/_catalog → anon katalog ifşası.
    Dönüş: (findings, api_hits). api_hits = {port: şema} — KUBE_PORTS DIŞINDA doğrulanmış
    K8s API portları; pipeline bunu derin proba (extra_ports) ve profil sinyaline taşır.
    Bilinçli SAPMA (plana göre): kubelet /run/ ve metrics-server pası YOK — her ikisi de
    dışarıdan ayırt edici imza taşmaz (404=hem var hem yok) → FP riski; kubelet kimliği
    zaten /pods Unauthorized imzasıyla (probe_kubernetes) sağlam kuruluyor."""
    findings: List[Dict[str, Any]] = []
    api_hits: Dict[int, str] = {}
    cand = sorted({int(p) for p in open_ports
                   if str(p).isdigit() and is_nodeport(int(p))})[:max_ports]
    if not cand:
        return findings, api_hits

    for port in cand:
        base_https = f"https://{host}:{port}"
        base_http = f"http://{host}:{port}"
        scheme = None
        r = await _get_full(client, f"{base_https}/version")
        if r is not None:
            scheme = "https"
        else:
            r = await _get_full(client, f"{base_http}/version")
            if r is not None:
                scheme = "http"
        if r is None:
            continue
        status, body, headers = r
        base = f"{scheme}://{host}:{port}"
        try:
            # 1) Private registry — header her path'te taşınır; katalog anon açıksa kritik
            if (headers or {}).get("Docker-Distribution-Api-Version") \
                    or (headers or {}).get("docker-distribution-api-version"):
                cat = await _get_full(client, f"{base}/v2/_catalog")
                if cat and classify_registry_catalog(cat[0], cat[1]):
                    c = classify_registry_catalog(cat[0], cat[1]) or {}
                    repos = c.get("repositories") or []
                    findings.append(_finding(
                        f"Private Container Registry Anonim Katalog İfşası @ {base}",
                        "critical", base,
                        f"Auth'suz GET /v2/_catalog → 200 ve repositories listesi döndü"
                        + (f" ({len(repos)}+ imaj: {', '.join(repos[:8])})" if repos else "")
                        + ". K8s NodePort'undan sızan private registry: dahili imajlar "
                          "(gömülü sırlar/kaynak kod dahil) dışarıdan ÇEKİLEBİLİR. "
                          "Anonim yanıt = deterministik kanıt.",
                        cwe=["CWE-306", "CWE-538"], mitre="T1613"))
                else:
                    findings.append(_finding(
                        f"Private Container Registry Dış Ağa Açık @ {base}",
                        "low", base,
                        f"{base} Docker Distribution API'si (header imzası) dış ağdan "
                        f"erişilebilir; katalog anonim değil (auth var — sertleştirme "
                        f"kısmen doğru). Uç açık kalması credential-atağı yüzeyidir.",
                        tier="probable", cwe=["CWE-200"], mitre="T1613",
                        method="registry-signature"))
                continue  # registry portunda başka imza aranmaz
            # 2) Apiserver sızıntısı (ingress/LB/NodePort arkası) → derin prob beslemesi
            cls = classify_apiserver(status, body)
            if cls:
                api_hits[port] = scheme
                continue
            # 3) Dashboard — /version 404 verir; kök sayfa imzası gerekir
            rr = await _get_full(client, f"{base}/")
            if rr:
                dash = classify_dashboard(rr[0], rr[1], rr[2])
                if dash:
                    confirmed = dash.get("kind") == "dashboard_ui"
                    findings.append(_finding(
                        f"Kubernetes Dashboard NodePort'tan Dışa Açık @ {base}",
                        "medium", base,
                        f"GET / → {('200 + Dashboard HTML imzası' if confirmed else 'yönlendirme: ' + str(dash.get('location')))}"
                        f" — cluster YÖNETİM konsolu NodePort üzerinden İnternete sızıyor. "
                        f"Login brute-force, dashboard CVE'leri (nuclei 'kubernetes-dashboard' "
                        f"tag'i) ve token-atağı yüzeyi. Cluster'ın varlığının da kanıtıdır "
                        f"(kontrol düzlemi 6443 firewall'luyken bile).",
                        tier=("confirmed" if confirmed else "probable"),
                        cwe=["CWE-200"], mitre="T1190",
                        method="k8s-dashboard-signature"))
        except Exception as e:
            logger.debug(f"K8s yüzey probu hatası ({base}): {e}")
            continue

    # Dedup (başlık+hedef)
    seen = set()
    out = []
    for f in findings:
        key = (f["title"], f["target"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out, api_hits
