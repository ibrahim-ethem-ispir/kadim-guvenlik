"""Türkçe: Kubernetes probu (k8s_probe) testleri — classify çekirdeği SAF; probe_kubernetes
sahte-sunucuyla deterministik (ağ YOK).

Kök: klasik tarama K8s'te boş döner; K8s-farkında prob auth'suz API yanıtını KANIT sayar.
Testler: apiserver/kubelet/etcd sınıflandırma, sürüm çıkarımı, uçtan uca ifşa tespiti +
temiz cluster'da bulgu-yok.

Çalıştır: python3 orchestrator/pipeline/test_k8s_probe.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.k8s_probe import (  # noqa: E402
    classify_apiserver, classify_anon_secrets, classify_kubelet_pods, classify_etcd,
    classify_distro, classify_rancher, classify_kube_healthz, classify_cadvisor,
    classify_kubelet_denied, classify_tls_identity,
    extract_k8s_version, probe_kubernetes, KUBE_PORTS,
    classify_nodeport, classify_registry_catalog, classify_dashboard,
    parse_k8s_semver, compare_k8s_versions, match_k8s_cves,
    load_k8s_cve_snapshot, probe_k8s_surface, is_nodeport,
    extract_kubelet_version, classify_pod_escape, k8s_cve_pairs,
    classify_etcd_health, classify_etcd_metrics,
    extract_manifest_config_digest, classify_registry_secrets,
)


def test_classify_apiserver_version():
    body = '{"major":"1","minor":"27","gitVersion":"v1.27.3","platform":"linux/amd64"}'
    c = classify_apiserver(200, body)
    assert c and c["kind"] == "apiserver_version" and c["version"] == "v1.27.3"


def test_classify_apiserver_status_enforced():
    body = '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden"}'
    c = classify_apiserver(403, body)
    assert c and c["kind"] == "apiserver_status" and c["authz"] == "enforced"


def test_classify_anon_secrets():
    body = '{"kind":"SecretList","items":[{"type":"Opaque"},{"type":"kubernetes.io/service-account-token"}]}'
    c = classify_anon_secrets(200, body)
    assert c and c["exposed"] is True
    assert classify_anon_secrets(403, body) is None   # reddedildiyse ifşa yok


def test_classify_kubelet_pods():
    body = '{"kind":"PodList","items":[{"metadata":{"name":"web"}},{"metadata":{"name":"db"}}]}'
    c = classify_kubelet_pods(200, body)
    assert c and c["exposed"] is True
    assert classify_kubelet_pods(401, body) is None


def test_classify_etcd():
    assert classify_etcd(200, '{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}')["kind"] == "etcd_version"
    keys = '{"action":"get","node":{"key":"/","dir":true}}'
    assert classify_etcd(200, keys)["exposed"] is True


def test_extract_version():
    assert extract_k8s_version('x "gitVersion":"v1.28.1" y') == "v1.28.1"
    assert extract_k8s_version("nope") is None


def test_classify_distro():
    assert classify_distro("v1.28.4+rke2r1") == "rke2"
    assert classify_distro("v1.29.0+k3s1") == "k3s"
    assert classify_distro("v1.28.3-gke.1000") == "gke"
    assert classify_distro("v1.30.2-eks-1552ad0") == "eks"
    assert classify_distro("v1.27.3") is None        # vanilla
    assert classify_distro(None) is None


def test_classify_rancher():
    assert classify_rancher(200, "<html><title>Rancher</title>")["kind"] == "rancher_ui"
    api = '{"baseType":"error","code":"Unauthorized","message":"cattle auth required"}'
    assert classify_rancher(401, api)["kind"] == "rancher_api"
    # FP koruması: rastgele 403 K8s Status nesnesi Rancher SANILMAMALI
    assert classify_rancher(403, '{"kind":"Status","reason":"Forbidden"}') is None
    assert classify_rancher(200, "<title>Grafana</title>") is None


def test_classify_kube_healthz():
    assert classify_kube_healthz("kube-proxy", 200, "ipvs")["mode"] == "ipvs"
    assert classify_kube_healthz("kube-scheduler", 200, "ok")["kind"] == "healthz_open"
    assert classify_kube_healthz("kube-controller", 200, "ok")["kind"] == "healthz_open"
    assert classify_kube_healthz("kube-proxy", 401, "ipvs") is None
    assert classify_kube_healthz("kube-proxy", 200, "garbage") is None


def test_classify_cadvisor():
    assert classify_cadvisor(200, '{"num_cores":8,"memory_bytes":1024}') is not None
    assert classify_cadvisor(404, '{"num_cores":8}') is None
    assert classify_cadvisor(200, "<html>hi</html>") is None


def test_classify_kubelet_denied():
    # kubelet'nin ayırt edici reddetme imzası: {"error":"Unauthorized"}
    assert classify_kubelet_denied(401, '{"error":"Unauthorized"}')["kind"] == "kubelet_denied"
    assert classify_kubelet_denied(401, "Unauthorized: Please login")["kind"] == "kubelet_denied"
    assert classify_kubelet_denied(401, "<html>login</html>") is None     # generic web 401 → eşleşmez
    assert classify_kubelet_denied(200, '{"error":"x","m":"unauthorized"}') is None  # 200 değil


def test_classify_tls_identity():
    ids = classify_tls_identity(["10.0.0.5", "kube-apiserver", "kubernetes", "rke2"])
    assert ids and ids["distro"] == "rke2" and "kube-apiserver" in ids["components"]
    assert classify_tls_identity(["CN=ingress-nginx"])["distro"] is None   # bileşen var, dağıtım yok
    assert classify_tls_identity(["random", "strings"]) is None
    assert classify_tls_identity([]) is None
    assert classify_tls_identity(["rke2", "k3s"])["distro"] == "rke2"      # sıra önceliği


# ---- I/O: uçtan uca (sahte K8s sunucusu) ----

class _R:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


class ExposedK8s:
    """kubelet /pods ve apiserver anon /secrets ifşa eden yanlış-yapılandırılmış cluster.
    PodList ayrıca POD-KAÇIŞ yüzeyi taşır (privileged + hostPID + docker.sock mount)."""
    async def get(self, url, timeout=None):
        if url.endswith("/version") and ":6443" in url:
            return _R(200, '{"major":"1","gitVersion":"v1.27.3"}')
        if "/secrets" in url:
            return _R(200, '{"kind":"SecretList","items":[{"type":"Opaque"}]}')
        if url.endswith("/pods"):
            return _R(200, '{"kind":"PodList","items":['
                           '{"metadata":{"name":"web","namespace":"default"},'
                           '"spec":{"containers":[{"name":"c"}]}},'
                           '{"metadata":{"name":"evil","namespace":"default"},'
                           '"spec":{"hostPID":true,'
                           '"containers":[{"name":"x","securityContext":{"privileged":true}}],'
                           '"volumes":[{"name":"sock","hostPath":{"path":"/var/run/docker.sock"}}]}}'
                           ']}')
        return _R(404, "not found")


class HardenedK8s:
    """Sertleştirilmiş: apiserver var ama her şey 403; kubelet auth-gerektirir."""
    async def get(self, url, timeout=None):
        if url.endswith("/version"):
            return _R(200, '{"major":"1","gitVersion":"v1.29.0"}')
        return _R(403, '{"kind":"Status","apiVersion":"v1","reason":"Forbidden"}')


def test_probe_exposed_cluster():
    findings = asyncio.run(probe_kubernetes("victim.io", [443, 6443, 10250], ExposedK8s()))
    titles = " ".join(f["title"] for f in findings)
    assert "Anonim Secret" in titles       # kritik anon secret
    assert "kubelet" in titles.lower()      # kubelet /pods ifşası
    assert "Privileged Konteyner" in titles and "Runtime Socket" in titles  # CIS/NSA pod kaçış yüzeyi
    crit = [f for f in findings if f["severity"] == "critical"]
    assert crit and all(f["confidence_tier"] == "confirmed" for f in crit)


def test_probe_hardened_no_critical():
    findings = asyncio.run(probe_kubernetes("hard.example", [443, 6443, 10250], HardenedK8s()))
    # apiserver açık (medium) olabilir ama KRİTİK ifşa YOK (secrets/pods reddedildi)
    assert not any(f["severity"] == "critical" for f in findings)


def test_probe_no_kube_ports():
    # K8s portu yoksa hiç yoklama yapma
    assert asyncio.run(probe_kubernetes("x.io", [80, 443], ExposedK8s())) == []


class RancherRKE2:
    """RKE2 dağıtımı: 9345 supervisor +RKE2 gitVersion damgalı, 8443 Rancher UI,
    2380 etcd-peer sürüm sızdırıyor, 10256 kube-proxy ipvs modda."""
    async def get(self, url, timeout=None):
        if ":9345" in url and url.endswith("/version"):
            return _R(200, '{"major":"1","gitVersion":"v1.28.4+rke2r1"}')
        if ":9345" in url:
            return _R(403, '{"kind":"Status","reason":"Forbidden"}')
        if ":8443" in url and url.endswith("/v3"):
            return _R(401, '{"baseType":"error","code":"Unauthorized","message":"cattle"}')
        if ":8443" in url:
            return _R(404, "not found")
        if ":2380" in url and url.endswith("/version"):
            return _R(200, '{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}')
        if ":10256" in url and url.endswith("/proxyMode"):
            return _R(200, "ipvs")
        return _R(404, "not found")


def test_probe_rke2_rancher_cluster():
    findings = asyncio.run(probe_kubernetes(
        "rke2.corp.io", [9345, 8443, 2380, 10256], RancherRKE2()))
    text = " ".join(f["title"] + " " + f["proof"] for f in findings)
    assert "RKE2" in text                    # dağıtım damgası başlığa/kanıta işlendi
    assert "Rancher" in text                 # Rancher Norman-API imzası yakalandı
    assert "etcd" in text.lower()            # etcd-peer (2380) da yoklandı
    assert "kube-proxy" in text              # rol damgalama (ipvs)
    # Hepsi tahribatsız GET kanıtı; secrets ifşası YOK → kritik secret bulgusu olmamalı
    assert not any("Anonim Secret" in f["title"] for f in findings)


# ---- V2 (Madde 5 / T4): NodePort sınıflandırma + sürüm→CVE danışma matrisi ----

def test_is_nodeport():
    assert is_nodeport(30000) and is_nodeport(32767) and is_nodeport(31234)
    assert not is_nodeport(29999) and not is_nodeport(32768)
    assert not is_nodeport(6443) and not is_nodeport("x") and not is_nodeport(None)


def test_classify_nodeport():
    # registry: header her path'te taşınır
    c = classify_nodeport(404, "not found", {"Docker-Distribution-Api-Version": "registry/2.0"})
    assert c and c["kind"] == "registry"
    # dashboard: <title> imzası
    c = classify_nodeport(200, "<html><title>Kubernetes Dashboard</title></html>", {})
    assert c and c["kind"] == "dashboard"
    # apiserver: gitVersion (classify_apiserver'e devir)
    c = classify_nodeport(200, '{"major":"1","gitVersion":"v1.28.4"}', {})
    assert c and c["kind"] == "apiserver_version" and c["version"] == "v1.28.4"
    # apiserver: auth duvarı arkasında Status imzası (NodePort'tan sızan ingress-arkası API)
    c = classify_nodeport(403, '{"kind":"Status","apiVersion":"v1","reason":"Forbidden"}', {})
    assert c and c["kind"] == "apiserver_status"
    # FP koruması: düz "ok" (healthz) ve rastgele SPA K8s DAMGALANAMAZ
    assert classify_nodeport(200, "ok", {}) is None
    assert classify_nodeport(200, "<title>Grafana</title>", {}) is None


def test_classify_registry_catalog():
    body = '{"repositories":["internal/api","internal/worker","bank/core"]}'
    c = classify_registry_catalog(200, body)
    assert c and c["exposed"] and "internal/api" in c["repositories"]
    assert classify_registry_catalog(401, '{"errors":[{"code":"UNAUTHORIZED"}]}') is None
    assert classify_registry_catalog(200, '{"kind":"Status"}') is None


def test_classify_dashboard():
    c = classify_dashboard(200, "<html><title>Kubernetes Dashboard</title></html>", {})
    assert c and c["kind"] == "dashboard_ui"
    # yönlendirme → probable
    c = classify_dashboard(302, "", {"Location": "/dashboard/"})
    assert c and c["kind"] == "dashboard_redirect"
    # FP: Grafana / rastgele SPA / login sayfası eşleşmez
    assert classify_dashboard(200, "<title>Grafana</title>", {}) is None
    assert classify_dashboard(200, "<title>Login</title>", {}) is None


def test_parse_semver():
    assert parse_k8s_semver("v1.28.4") == (1, 28, 4)
    assert parse_k8s_semver("v1.28.4+rke2r1") == (1, 28, 4)      # dağıtım soneki yok sayılır
    assert parse_k8s_semver("1.30.2-eks-1552ad0") == (1, 30, 2)
    assert parse_k8s_semver("v1.29.0+k3s1") == (1, 29, 0)
    assert parse_k8s_semver(None) is None and parse_k8s_semver("master") is None


def test_compare_versions():
    assert compare_k8s_versions("v1.28.4+rke2r1", "1.28.12") == -1   # Terrapin-tarzı kıyas
    assert compare_k8s_versions("v1.29.0+k3s1", "v1.28.15") == 1
    assert compare_k8s_versions("v1.28.4", "v1.28.4+gke.100") == 0   # sonek farkı önemsiz
    assert compare_k8s_versions("junk", "v1.28.4") == 0


def _cves(comp, ver):
    return {c["cve"] for c in match_k8s_cves(comp, ver)}


def test_match_k8s_cves_snapshot_loaded():
    # Statik snapshot repoda MEVCUT olmalı (feed'den üretilmiş); boşsa V2 katmanı kördür.
    assert load_k8s_cve_snapshot(), "data/k8s/k8s_cves.json yüklenemedi"


def test_match_k8s_cves_vulnerable():
    # Gerçek danışma verisiyle: kube-apiserver 1.28.4 → CVE-2024-3177 (fix 1.28.9)
    hits = match_k8s_cves("kube-apiserver", "v1.28.4")
    ids = {c["cve"] for c in hits}
    assert "CVE-2024-3177" in ids
    m = [c for c in hits if c["cve"] == "CVE-2024-3177"][0]
    assert "1.28.9" in m["match_reason"]


def test_match_k8s_cves_fixed_branch():
    # 1.28.9 = düzeltme sürümü → 3177 ÇIKMAZ; 1.29+ → 2727 dalı da temiz
    assert "CVE-2024-3177" not in _cves("kube-apiserver", "v1.28.9")
    assert "CVE-2023-2727" not in _cves("kube-apiserver", "v1.29.3")


def test_match_k8s_cves_pre_window():
    # Fix penceresi ÖNCESİ dal: kubelet 1.27.9 → CVE-2024-10220 (affected: <= v1.28.11)
    ids = _cves("kubelet", "v1.27.9")
    assert "CVE-2024-10220" in ids
    # Aynı minor'da patch kıyası: 1.29.5 açık, 1.29.7 düzeltilmiş
    assert "CVE-2024-10220" in _cves("kubelet", "v1.29.5")
    assert "CVE-2024-10220" not in _cves("kubelet", "v1.29.7")


def test_match_k8s_cves_component_filter():
    # Bileşen filtresi: kubelet CVE'si apiserver sürümüne bağlanmaz (ve tersi)
    assert not (_cves("kubelet", "v1.28.4") & {"CVE-2024-3177"})
    assert not (_cves("kube-apiserver", "v1.29.5") & {"CVE-2024-10220"})


def test_match_k8s_cves_synthetic_semantics():
    # Sentetik snapshot ile semantik pin'i (gerçek veri değişse bile davranış sabit):
    snap = [{"cve": "CVE-9999-0001", "title": "t", "components": ["kube-apiserver"],
             "severity": "high", "fixed_in": {"1.30": "1.30.3", "1.29": "1.29.7"}}]
    assert _cves_snapshot("kube-apiserver", "v1.29.5", snap) == {"CVE-9999-0001"}
    assert _cves_snapshot("kube-apiserver", "v1.29.7", snap) == set()
    assert _cves_snapshot("kube-apiserver", "v1.30.3", snap) == set()
    assert _cves_snapshot("kube-apiserver", "v1.31.0", snap) == set()   # düzeltilmiş dal
    assert _cves_snapshot("kube-apiserver", "v1.28.9", snap) == {"CVE-9999-0001"}  # pencere öncesi
    assert _cves_snapshot("kubelet", "v1.29.5", snap) == set()          # bileşen filtresi


def _cves_snapshot(comp, ver, snap):
    return {c["cve"] for c in match_k8s_cves(comp, ver, snapshot=snap)}


class _R2(_R):
    """_get_full için header'lı yanıt."""
    def __init__(self, status, text, headers=None):
        super().__init__(status, text)
        self.headers = headers or {}


class NodePortFarm:
    """NodePort'larında dashboard + anon registry + apiserver sızan cluster.
    30123=dashboard, 30250=registry(anon katalog), 30321=ingress-arkası apiserver,
    30444=sıradan uygulama (bulgu ÜRETMEMELİ)."""
    async def get(self, url, timeout=None):
        if ":30123" in url and url.endswith("/version"):
            return _R2(404, "not found", {})
        if ":30123" in url:
            return _R2(200, "<html><title>Kubernetes Dashboard</title></html>", {})
        if ":30250" in url:
            return _R2(404, "404",
                       {"Docker-Distribution-Api-Version": "registry/2.0"})
        if ":30250" in url.replace("https", "http"):
            return _R2(404, "404",
                       {"Docker-Distribution-Api-Version": "registry/2.0"})
        if ":30321" in url and url.endswith("/version"):
            return _R2(403, '{"kind":"Status","apiVersion":"v1","reason":"Forbidden"}', {})
        if ":30444" in url and url.endswith("/version"):
            return _R2(404, "nope", {})
        if ":30444" in url:
            return _R2(200, "<html><title>Blog</title></html>", {})
        return _R2(404, "not found", {})

    async def get_catalog(self, url):
        # yardımcı değil — sadece imza
        return _R2(200, '{"repositories":["internal/api","bank/core"]}', {})


class NodePortFarmRegistry(NodePortFarm):
    """Katalog anonim AÇIK: /v2/_catalog 200 + repositories."""
    async def get(self, url, timeout=None):
        if "/v2/_catalog" in url:
            return _R2(200, '{"repositories":["internal/api","bank/core"]}', {})
        return await super().get(url, timeout)


def test_probe_k8s_surface():
    findings, hits = asyncio.run(probe_k8s_surface(
        "farm.io", [30123, 30321, 30444], NodePortFarm()))
    titles = " ".join(f["title"] for f in findings)
    assert "Dashboard" in titles                       # NodePort'tan yönetim konsolu
    assert hits.get(30321) in ("https", "http")        # apiserver sızıntısı → derin prob beslemesi
    assert not any("Registry" in t for t in [f["title"] for f in findings])  # katalog yok
    # sıradan uygulama (30444) bulgu ÜRETMEZ — FP-güvenlik
    assert not any("30444" in f["target"] for f in findings)


def test_probe_k8s_surface_registry_exposed():
    findings, _hits = asyncio.run(probe_k8s_surface(
        "farm2.io", [30250, 30123], NodePortFarmRegistry()))
    crit = [f for f in findings if f["severity"] == "critical"]
    assert crit and "Registry" in crit[0]["title"] and "Katalog" in crit[0]["title"]
    assert "internal/api" in crit[0]["proof"]          # kanıt repoları taşır
    assert crit[0]["confidence_tier"] == "confirmed"   # anonim 200 = deterministik kanıt


def test_probe_k8s_surface_no_nodeports():
    findings, hits = asyncio.run(probe_k8s_surface("x.io", [80, 443, 6443], NodePortFarm()))
    assert findings == [] and hits == {}


# ---- Pod kaçış yüzeyi + kubelet sürüm + CVE çift üretimi (SAF) ----

def test_extract_kubelet_version():
    assert extract_kubelet_version(
        'kubelet_version_info{git_version="v1.28.4",goversion="go1.21"}') == "v1.28.4"
    assert extract_kubelet_version('kubelet_version_info{git_version="1.27.3"}') == "1.27.3"
    assert extract_kubelet_version("metrik yok") is None


def test_classify_pod_escape_json():
    import json
    podlist = json.dumps({
        "kind": "PodList",
        "items": [
            {"metadata": {"name": "evil", "namespace": "default"},
             "spec": {
                 "hostPID": True,
                 "containers": [{"name": "c1",
                                 "securityContext": {"privileged": True,
                                                     "capabilities": {"add": ["SYS_ADMIN"]}}}],
                 "volumes": [{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}],
             }},
            {"metadata": {"name": "rooty", "namespace": "default"},
             "spec": {"containers": [{"name": "c2",
                                      "securityContext": {"runAsUser": 0,
                                                          "allowPrivilegeEscalation": True}}]}},
            {"metadata": {"name": "ok", "namespace": "kube-system"},
             "spec": {"containers": [{"name": "c", "securityContext": {"runAsNonRoot": True}}]}},
        ]})
    surf = classify_pod_escape(podlist)
    kinds = {s["kind"] for s in surf}
    assert {"privileged", "runtime_sock", "host_ns", "caps", "root_escalation"} <= kinds
    assert all(s["tier"] == "confirmed" for s in surf)
    by = {s["kind"]: s for s in surf}
    assert by["runtime_sock"]["severity"] == "critical"
    assert by["privileged"]["severity"] == "critical"
    assert "CIS 5.2.1" in by["privileged"]["proof"]
    # temiz pod listesi → yüzey YOK (FP yok)
    clean = classify_pod_escape(json.dumps({"kind": "PodList", "items": [
        {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c"}]}}]}))
    assert clean == []


def test_classify_pod_escape_truncated_fallback():
    # kubelet /pods gövdesi _get'te 16KB kırpılır → JSON parse düşer, regex sinyal taraması çalışır
    frag = ('{"kind":"PodList","items":[{"spec":{"privileged":true,"hostPID":true,'
            '"volumes":[{"hostPath":{"path":"/etc"}}]}}')
    surf = classify_pod_escape(frag)
    kinds = {s["kind"] for s in surf}
    assert {"privileged", "host_ns", "hostpath"} <= kinds
    assert all(s["tier"] == "probable" for s in surf)


def test_k8s_cve_pairs_direct_and_proxy():
    # 1) doğrudan ölçüm: kubelet /metrics'ten okunan sürüm
    pairs = k8s_cve_pairs([
        {"product": "kube-apiserver", "version": "v1.27.3", "target": "https://h:6443"},
        {"product": "kubelet", "version": "v1.28.4", "target": "https://h:10255"},
    ])
    by = {(p["product"], p["version"]) for p in pairs}
    assert ("kube-apiserver", "v1.27.3") in by and ("kubelet", "v1.28.4") in by
    # 2) ölçüm yoksa apiserver gitVersion'ı KÜME GENELİ proxy'si (kubelet + controller-manager)
    pairs2 = k8s_cve_pairs([{"product": "kube-apiserver", "version": "v1.27.3", "target": "https://h:6443"}])
    prods = {p["product"] for p in pairs2}
    assert {"kube-apiserver", "kubelet", "kube-controller-manager"} <= prods
    assert all("proxy" in p["source"] for p in pairs2 if p["product"] != "kube-apiserver")
    # 3) sürüm sinyali yoksa çift yok (uydurma eşleme yok)
    assert k8s_cve_pairs([{"product": "etcd"}]) == []


# ---- etcd v3 yüzeyi + registry imaj-içi sır taraması ----

class EtcdOpen:
    """etcd 2379 anon açık: sürüm + v3 /health + /metrics sızdırıyor (v2 kapalı)."""
    async def get(self, url, timeout=None):
        if url.endswith("/version"):
            return _R(200, '{"etcdserver":"3.5.9","etcdcluster":"3.5.9"}')
        if url.endswith("/health"):
            return _R(200, '{"health":"true","reason":""}')
        if url.endswith("/metrics"):
            return _R(200, 'etcd_server_version{server_version="3.5.9"} 1\n'
                           "etcd_mvcc_db_total_size_in_bytes 1.048e+07\n"
                           "etcd_debugging_mvcc_keys_total 123\n")
        return _R(404, "not found")


class RegistryWithSecrets(NodePortFarmRegistry):
    """Anon katalog + imaj config'inde GÖMÜLÜ SIR taşıyan private registry."""
    async def get(self, url, timeout=None):
        if "/v2/_catalog" in url:
            return _R2(200, '{"repositories":["internal/api"]}', {})
        if url.endswith("/tags/list"):
            return _R2(200, '{"name":"internal/api","tags":["1.2.0"]}', {})
        if "/manifests/" in url:
            return _R2(200, '{"schemaVersion":2,"config":{"digest":"sha256:abc123"},"layers":[]}', {})
        if "/blobs/sha256:abc123" in url:
            return _R2(200, '{"config":{"Env":["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",'
                            '"PATH=/usr/bin"]},"history":[{"created_by":"ENV DB_PASSWORD=Sup3rS3cret99"}]}', {})
        return _R2(404, "404", {"Docker-Distribution-Api-Version": "registry/2.0"})


def test_classify_etcd_health_and_metrics():
    h = classify_etcd_health(200, '{"health":"true","reason":""}')
    assert h and h["kind"] == "etcd_v3_health" and h["healthy"] is True
    assert classify_etcd_health(200, "<html>nope</html>") is None
    m = classify_etcd_metrics(200, 'etcd_server_version{server_version="3.5.9"} 1\n'
                                   "etcd_mvcc_db_total_size_in_bytes 1.048e+07\n"
                                   "etcd_debugging_mvcc_keys_total 123\n")
    assert m and m["version"] == "3.5.9" and m["keys"] == 123 and m["db_bytes"] == 10480000
    assert classify_etcd_metrics(200, "düz metin") is None


def test_registry_secret_classifier_masks_values():
    body = ('{"config":{"Env":["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI","PATH=/usr/bin"]},'
            '"history":[{"created_by":"ENV DB_PASSWORD=Sup3rS3cret99"}]}')
    secs = classify_registry_secrets(body)
    keys = {s["key"] for s in secs}
    assert {"AWS_SECRET_ACCESS_KEY", "DB_PASSWORD"} <= keys
    assert "PATH" not in keys
    joined = str(secs)
    assert "wJalrXUtnFEMI" not in joined and "Sup3rS3cret99" not in joined  # MASKE zorunlu
    assert all(s["masked_value"].endswith(")") and "***" in s["masked_value"] for s in secs)
    assert classify_registry_secrets('{"config":{"Env":["PATH=/usr/bin"]}}') == []


def test_extract_manifest_config_digest():
    d = extract_manifest_config_digest(
        '{"config":{"mediaType":"x","digest":"sha256:deadbeef","size":1}}')
    assert d == "sha256:deadbeef"
    assert extract_manifest_config_digest("{}") is None


def test_probe_etcd_v3_surface():
    findings = asyncio.run(probe_kubernetes("etcd.io", [2379], EtcdOpen()))
    titles = " ".join(f["title"] for f in findings)
    assert "etcd v3 API Yüzeyi" in titles and "Metrik" in titles
    assert any(f.get("product") == "etcd" and f.get("version") == "3.5.9" for f in findings)
    # v3 /health + /metrics imzaları deterministik → confirmed (sürüm-imzası bulgusu
    # 'Dış Ağa Açık' ise tasarıma göre probable kalır — aktif sızıntı kanıtı değil)
    v3 = next(f for f in findings if "v3 API Yüzeyi" in f["title"])
    assert v3["confidence_tier"] == "confirmed"


def test_registry_config_secret_exposure():
    findings, _hits = asyncio.run(probe_k8s_surface("farm3.io", [30250], RegistryWithSecrets()))
    titles = " ".join(f["title"] for f in findings)
    assert "Katalog" in titles                      # anon katalog (critical)
    assert "Gömülü Sır" in titles                   # imaj config'inde sır (high)
    secret = next(f for f in findings if "Gömülü Sır" in f["title"])
    assert "AWS_SECRET_ACCESS_KEY" in secret["proof"]
    assert "wJalrXUtnFEMI" not in secret["proof"] and "Sup3rS3cret99" not in secret["proof"]
    assert secret["verification_method"] == "registry-config-scan"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
