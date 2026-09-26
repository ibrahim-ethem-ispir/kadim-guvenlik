"""Türkçe: Hedef Profili (target_profile) fingerprint çekirdeği testleri — SAF; ağ YOK.

Kök: "önce düşmanı tanı." Testler: header/cookie/gövde/port sinyallerinden dil/framework/
altyapı/app-tipi çıkarımı, noisy-OR güven birleştirme, confidently_not (kesin dışlama —
PHP-on-node problemini çözen mantık).

Çalıştır: python3 orchestrator/pipeline/test_target_profile.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.target_profile import (  # noqa: E402
    fingerprint, _noisy_or, parse_set_cookie_names, TargetProfile,
)


def test_php_stack():
    p = fingerprint(headers={"X-Powered-By": "PHP/8.1", "Server": "Apache"},
                    cookies=["PHPSESSID"], body="<html>home</html>")
    assert p.is_("language", "php", 0.8)
    assert p.is_("server", "apache")
    # phpsessid(.95) + x-powered-by(.95) noisy-OR → çok yüksek
    assert p.confidence("language") > 0.95


def test_node_express_stack():
    p = fingerprint(headers={"X-Powered-By": "Express"}, cookies=["connect.sid"])
    assert p.is_("language", "node")
    assert p.is_("framework", "express")
    # Kritik: node kesinken PHP GÜVENLE dışlanır (PHP-on-node problemi)
    assert p.confidently_not("language", "php") is True


def test_kubernetes_ports():
    p = fingerprint(ports=[443, 6443, 10250])
    assert p.is_("infra", "kubernetes", 0.8)


def test_react_spa_body():
    body = '<div data-reactroot></div><script src="/_next/static/x.js"></script>'
    p = fingerprint(body=body)
    assert p.is_("app_type", "spa")
    assert p.value("framework") in ("react", "nextjs")


def test_dotnet_viewstate():
    p = fingerprint(headers={"X-AspNet-Version": "4.0"},
                    body='<form id="aspnetForm"><input name="__VIEWSTATE"></form>')
    assert p.is_("language", "dotnet")


def test_cloud_aws_header():
    p = fingerprint(headers={"Via": "1.1 abc.cloudfront.net (CloudFront)",
                             "X-Amz-Cf-Id": "xyz"})
    assert p.is_("cloud", "aws")


def test_extra_signals():
    # Motorun metadata-erişilebilirliğinden türettiği cloud sinyali
    p = fingerprint(extra=[("infra", "cloud", 0.8, "metadata_reachable")])
    assert p.is_("infra", "cloud", 0.7)


def test_confidently_not_kanit_yoksa_false():
    # Hiç sinyal yok → körü körüne dışlama YAPMA (kendini kör etme)
    p = fingerprint()
    assert p.confidently_not("language", "php") is False
    assert p.value("language") is None


def test_noisy_or():
    assert _noisy_or([0.9, 0.9]) > 0.98
    assert 0.7 < _noisy_or([0.5, 0.5]) < 0.8   # 0.75
    assert _noisy_or([]) == 0.0
    assert _noisy_or([1.0]) == 1.0


def test_parse_set_cookie_names():
    assert parse_set_cookie_names("PHPSESSID=abc; Path=/; HttpOnly") == ["phpsessid"]
    assert parse_set_cookie_names(["A=1", "connect.sid=xyz"]) == ["a", "connect.sid"]
    assert parse_set_cookie_names(None) == []


def test_rancher_header_sinyali():
    # Rancher Norman API imzası: K8s portları firewall arkasındayken bile WEB'den K8s tanınır
    p = fingerprint(headers={"X-Api-Cattle-Auth": "false"})
    assert p.is_("framework", "rancher", 0.8)
    assert p.is_("infra", "kubernetes", 0.6)


def test_rancher_title_sinyali():
    p = fingerprint(body="<html><head><title>Rancher</title></head></html>")
    assert p.is_("framework", "rancher", 0.8)
    assert p.is_("infra", "kubernetes", 0.6)


def test_apiserver_status_body():
    body = '{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden"}'
    p = fingerprint(body=body)
    assert p.is_("infra", "kubernetes", 0.6)


def test_rancher_playbook_php_dislar():
    # Kullanıcı şikayetinin kökü: Rancher hedefinde php_modules çalışması. Rancher kesin
    # tanınınca PHP/CMS modülü GÜVENLE dışlanır; k8s_probe ise pozitif istihbaratla AÇILIR.
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), ".."))
    from pipeline.playbook import select_playbook
    p = fingerprint(headers={"X-Api-Cattle-Auth": "false"})
    d = select_playbook(p)
    assert d.allowed("php_modules") is False
    assert d.allowed("k8s_probe") is True
    assert d.allowed("ssrf_metadata") is True


def test_summary_ve_todict():
    p = fingerprint(headers={"X-Powered-By": "PHP"}, ports=[6443])
    d = p.to_dict()
    assert "facts" in d and "language" in d["facts"]
    assert "php" in p.summary() and "kubernetes" in p.summary()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
