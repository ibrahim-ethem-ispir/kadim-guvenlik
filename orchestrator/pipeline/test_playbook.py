"""Türkçe: Playbook seçici (playbook) testleri — SAF; ağ YOK.

Kök: bilinçli+gerekli saldırı. Testler: iki politika (if_relevant vs unless_excluded),
K8s/SSRF opt-in, PHP dışlama, nuclei tag planı (PHP-on-node gürültüsünü kesme + kör-kalma
güvenliği).

Çalıştır: python3 orchestrator/pipeline/test_playbook.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.target_profile import fingerprint  # noqa: E402
from pipeline.playbook import (  # noqa: E402
    select_playbook, nuclei_tag_plan, decide_capability, Capability, CAPABILITIES,
)


def test_k8s_probe_opt_in():
    # K8s tespiti YOK → gürültülü k8s_probe atlanır (if_relevant)
    p_plain = fingerprint(headers={"Server": "nginx"})
    assert select_playbook(p_plain).allowed("k8s_probe") is False
    # K8s portları var → aktif
    p_k8s = fingerprint(ports=[6443, 10250])
    assert select_playbook(p_k8s).allowed("k8s_probe") is True


def test_wp_probe_opt_in():
    # WordPress tespiti YOK → WP-özel prob atlanır (if_relevant). Kullanıcı doktrini:
    # 'WP değilse kesinlikle bu tarama yapılmamalı'.
    p_node = fingerprint(headers={"X-Powered-By": "Express"},
                         body='<div id="__NEXT_DATA__"></div>')
    assert select_playbook(p_node).allowed("wp_probe") is False
    p_plain = fingerprint(headers={"Server": "nginx"})
    assert select_playbook(p_plain).allowed("wp_probe") is False
    # WP imzası (cookie + body) → aktif
    p_wp = fingerprint(cookies=["wordpress_logged_in_x"],
                       body='<link href="/wp-content/themes/x/style.css">')
    assert select_playbook(p_wp).allowed("wp_probe") is True


def test_deserialization_probe_opt_in():
    # SharePoint/TeamCity/dotnet tespiti YOK → prob atlanır (if_relevant).
    p_php = fingerprint(headers={"X-Powered-By": "PHP/8.1"})
    assert select_playbook(p_php).allowed("deserialization_probe") is False
    p_plain = fingerprint(headers={"Server": "nginx"})
    assert select_playbook(p_plain).allowed("deserialization_probe") is False
    # SharePoint imzası → aktif
    p_sp = fingerprint(headers={"SPRequestGuid": "abc-123"})
    assert select_playbook(p_sp).allowed("deserialization_probe") is True
    # TeamCity imzası → aktif
    p_tc = fingerprint(headers={"X-TeamCity-Node-Id": "MAIN_SERVER"})
    assert select_playbook(p_tc).allowed("deserialization_probe") is True
    # Genel ASP.NET (ViewState yüzeyi) → aktif (SharePoint/TeamCity olmasa da anlamlı)
    p_dotnet = fingerprint(headers={"X-Aspnet-Version": "4.0.30319"})
    assert select_playbook(p_dotnet).allowed("deserialization_probe") is True


def test_ssrf_metadata_opt_in():
    p_onprem = fingerprint(headers={"Server": "nginx"})
    assert select_playbook(p_onprem).allowed("ssrf_metadata") is False   # cloud değil → atla
    p_cloud = fingerprint(headers={"X-Amz-Cf-Id": "x", "Via": "1.1 cloudfront"})
    assert select_playbook(p_cloud).allowed("ssrf_metadata") is True


def test_php_modules_excluded_on_node():
    # Node kesin → PHP modülü GÜVENLE atlanır (kesin dışlama)
    p_node = fingerprint(headers={"X-Powered-By": "Express"}, cookies=["connect.sid"])
    d = select_playbook(p_node)
    assert d.allowed("php_modules") is False
    assert "php" in d.reason("php_modules").lower()


def test_php_modules_run_on_php_and_unknown():
    p_php = fingerprint(cookies=["PHPSESSID"])
    assert select_playbook(p_php).allowed("php_modules") is True
    # Bilinmeyen dil → KÖR KALMA: php_modules yine çalışır (unless_excluded)
    p_unknown = fingerprint(headers={"Server": "nginx"})
    assert select_playbook(p_unknown).allowed("php_modules") is True


def test_php_modules_excluded_on_bare_k8s_without_rancher_ui():
    # Kullanıcı şikayetinin kökü: Rancher UI'ı görünmeyen (firewall arkasında/headless)
    # çıplak RKE2/K8s hedefinde bile php_modules dışlanmalı — control-plane portları
    # (kubelet/etcd/apiserver) tek başına yeterli kanıt, framework=rancher şart değil.
    p_k8s_ports_only = fingerprint(ports=[10250, 2379])
    d = select_playbook(p_k8s_ports_only)
    assert d.allowed("php_modules") is False
    assert "kubernetes" in d.reason("php_modules").lower()
    assert d.allowed("k8s_probe") is True


def test_nuclei_tag_plan_excludes_php_on_bare_k8s():
    # php_modules flag'i kozmetik — gerçek tarama kapsamını nuclei_tag_plan belirler.
    # K8s port-only sinyalde de php/java/dotnet/... template'leri elenmeli (Go control-plane).
    p = fingerprint(ports=[10250, 2379])
    plan = nuclei_tag_plan(p)
    assert plan["family"] == "go"
    assert "php" in plan["exclude_tags"] and "wordpress" in plan["exclude_tags"]
    assert "java" in plan["exclude_tags"] and "dotnet" in plan["exclude_tags"]


def test_core_modules_default_on():
    # idor / web_misconfig / graphql_intel → belirsizde bile çalışır (çekirdek)
    p = fingerprint()
    d = select_playbook(p)
    assert d.allowed("idor") and d.allowed("web_misconfig") and d.allowed("graphql_intel")
    # fac_matrix (T2-A2): idor'un çekirdek ailesi — belirsizde de çalışır
    assert d.allowed("fac_matrix")


def test_nuclei_tag_plan_node_excludes_php():
    # PHP-on-node problemi: node tespitinde php/wordpress/java/... elenir
    p = fingerprint(headers={"X-Powered-By": "Express"})
    plan = nuclei_tag_plan(p)
    assert "php" in plan["exclude_tags"] and "wordpress" in plan["exclude_tags"]
    assert "java" in plan["exclude_tags"]


def test_nuclei_tag_plan_php_keeps_php_excludes_others():
    p = fingerprint(cookies=["PHPSESSID"], headers={"X-Powered-By": "PHP/8"})
    plan = nuclei_tag_plan(p)
    assert "php" not in plan["exclude_tags"]        # kendi ailesi korunur
    assert "wordpress" not in plan["exclude_tags"]  # php ailesi
    assert "java" in plan["exclude_tags"] and "django" in plan["exclude_tags"]


def test_nuclei_tag_plan_unknown_is_empty():
    # Dil/aile bilinmiyor → BOŞ exclude (tam tarama, kör kalma)
    p = fingerprint(headers={"Server": "nginx"})
    assert nuclei_tag_plan(p)["exclude_tags"] == []


def test_nuclei_tag_plan_spa_framework_infers_node():
    # Dil doğrudan yok ama React (SPA) framework'ü → node ailesi çıkarımı → php elenir
    body = '<div data-reactroot></div><script src="/_next/static/x.js"></script>'
    p = fingerprint(body=body)
    plan = nuclei_tag_plan(p)
    assert "php" in plan["exclude_tags"]


def test_decide_capability_policies():
    p = fingerprint(ports=[6443])
    # if_relevant + relevant → run
    cap_r = Capability("x", "if_relevant", "medium", relevant=lambda pr: True)
    assert decide_capability(cap_r, p)[0] is True
    # if_relevant + not relevant → skip
    cap_nr = Capability("y", "if_relevant", "medium", relevant=lambda pr: False)
    assert decide_capability(cap_nr, p)[0] is False
    # unless_excluded + excluded → skip
    cap_ex = Capability("z", "unless_excluded", "cheap",
                        relevant=lambda pr: False, excluded=lambda pr: "dışlandı")
    assert decide_capability(cap_ex, p)[0] is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
