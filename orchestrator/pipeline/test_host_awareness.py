"""Türkçe: Hedef TİPİ farkındalığı — 'her hedefi site sayma' düzeltmesi. SAF; ağ YOK.

Kök: motor RKE2/Ubuntu sunucuyu (pfSense/firewall arkası) 'web sitesi' sanıp CMS/GraphQL
modülleri koşuyordu. Bu testler: os/savunma sinyali → kind() (web|appliance|host|unknown),
has_web_signal(), web_port sinyali ve playbook'un NET web-dışı host'ta web modüllerini
DIŞLAMASI (ama web portu açıkken KESMEMESİ — kör kalma güvenlik freni).

Çalıştır: python3 orchestrator/pipeline/test_host_awareness.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.target_profile import fingerprint  # noqa: E402
from pipeline.playbook import select_playbook  # noqa: E402


# ---- target_profile: os / kind / has_web_signal / web_port ----
def test_os_from_banner_and_kind_host():
    # SSH/OS banner (nmap -sV) → os=ubuntu; web sinyali yok → kind=host (çıplak sunucu)
    p = fingerprint(ports=[22], extra=[("os", "ubuntu", 0.85, "banner:openssh ubuntu")])
    assert p.value("os") == "ubuntu"
    assert p.has_web_signal() is False
    assert p.kind() == "host"
    assert "ubuntu" in p.summary().lower()


def test_kind_web_when_real_web_signal():
    p = fingerprint(headers={"Server": "nginx"}, ports=[443])
    assert p.has_web_signal() is True
    assert p.kind() == "web"     # WAF'lı bile olsa gerçek web → 'web'


def test_kind_appliance_pfsense():
    # pfSense blok/login sayfası → waf=pfsense; web yığını yok → kind=appliance (önünde cihaz)
    p = fingerprint(body="<title>Login to pfSense</title> pfSense webConfigurator")
    assert p.value("waf") == "pfsense"
    assert p.has_web_signal() is False
    assert p.kind() == "appliance"


def test_web_port_signal_present():
    p = fingerprint(ports=[443], extra=[("os", "linux", 0.5, "svc:ssh")])
    assert p.is_("web_port", "open", 0.5) is True
    # web portu açık → web app OLABİLİR → non-web-host DEĞİL
    assert p.kind() != "host"


def test_lighttpd_alone_is_not_web_signal():
    # lighttpd pfSense/embedded'de de var → tek başına 'web uygulaması' kanıtı SAYILMAZ
    p = fingerprint(headers={"Server": "lighttpd"}, extra=[("os", "linux", 0.5, "svc:ssh")])
    assert p.has_web_signal() is False


# ---- playbook: akılcı gating (web-dışı host'ta web modülleri sus) ----
_WEB_MODULES = ("php_modules", "graphql_intel", "idor", "web_misconfig", "headless_crawl",
                "fac_matrix")


def test_non_web_host_excludes_web_modules():
    # os var, web sinyali yok, web portu yok → TÜM web modülleri dışlanır
    p = fingerprint(ports=[22], extra=[("os", "ubuntu", 0.85, "banner:ssh ubuntu")])
    d = select_playbook(p)
    for m in _WEB_MODULES:
        assert d.allowed(m) is False, f"{m} web-dışı host'ta dışlanmalıydı"
    # gerekçe dürüst olmalı (sunucu/appliance)
    assert "web uygulaması değil" in d.reason("idor").lower()


def test_web_port_open_keeps_web_modules():
    # SSH + OS AMA 443 açık → web app olabilir → web modülleri KESİLMEZ (güvenlik freni)
    p = fingerprint(ports=[22, 443], extra=[("os", "ubuntu", 0.85, "banner:ssh ubuntu")])
    d = select_playbook(p)
    assert d.allowed("php_modules") is True
    assert d.allowed("idor") is True
    assert d.allowed("web_misconfig") is True


def test_web_signal_keeps_web_modules():
    # Gerçek web yığını (PHP) → web modülleri çalışır (host değil)
    p = fingerprint(headers={"X-Powered-By": "PHP/8.1"}, ports=[22])
    d = select_playbook(p)
    assert d.allowed("php_modules") is True
    assert d.allowed("idor") is True


def test_empty_profile_still_default_runs_web_modules():
    # HİÇ sinyal yok (os/waf/web da yok) → net web-dışı DEĞİL → kör kalma default (çalışır).
    # Bu, "pozitif host kanıtı olmadan web modüllerini kesme" güvencesidir.
    p = fingerprint()
    d = select_playbook(p)
    assert d.allowed("idor") is True
    assert d.allowed("php_modules") is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
