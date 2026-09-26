"""Türkçe: CPE kimlik omurgası testleri — SAF; ağ YOK.

Kök: "10k config'i elle yazamayız". nmap/Shodan zaten CPE veriyor → kimlik + CVE join.
Bu testler CPE ayrıştırma (2.3 + 2.2 URI) + boyut sinyaline çevirme (os/server/waf/framework)
+ nmap OS-string yedeğini ve target_profile ile entegrasyonu (kind/has_web_signal) doğrular.

Çalıştır: python3 orchestrator/pipeline/test_cpe_intel.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.cpe_intel import (  # noqa: E402
    parse_cpe, cpe_to_signals, os_string_to_signal,
)
from pipeline.target_profile import fingerprint  # noqa: E402


# ---- parse_cpe ----
def test_parse_cpe_23():
    c = parse_cpe("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*")
    assert c and c.part == "o" and c.vendor == "canonical"
    assert c.product == "ubuntu_linux" and c.version == "22.04"


def test_parse_cpe_22_uri():
    c = parse_cpe("cpe:/a:apache:http_server:2.4.52")
    assert c and c.part == "a" and c.product == "http_server" and c.version == "2.4.52"


def test_parse_cpe_invalid():
    assert parse_cpe("not-a-cpe") is None
    assert parse_cpe("cpe:2.3:x:foo:bar") is None   # geçersiz part
    assert parse_cpe(None) is None


# ---- cpe_to_signals ----
def test_signals_os_and_webserver():
    extra, products = cpe_to_signals([
        "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
        "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*",
        "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*",
    ])
    dims = {(d, v) for (d, v, _w, _e) in extra}
    assert ("os", "ubuntu") in dims
    assert ("server", "apache") in dims
    # openssh tanınan boyuta gitmez ama products'ta kimlik olarak durur (kapsam kaybı yok)
    assert any("http_server" in p for p in products)
    assert any("openssh" in p for p in products)


def test_signals_defense_and_framework():
    extra, _ = cpe_to_signals([
        "cpe:2.3:a:netgate:pfsense:2.7.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*",
    ])
    dims = {(d, v) for (d, v, _w, _e) in extra}
    assert ("waf", "pfsense") in dims
    assert ("framework", "wordpress") in dims
    assert ("language", "php") in dims   # wordpress → php ipucu


def test_os_string_fallback():
    assert os_string_to_signal("Ubuntu 22.04")[:2] == ("os", "ubuntu")
    assert os_string_to_signal("Linux 5.4")[:2] == ("os", "linux")
    assert os_string_to_signal("Windows Server 2019")[:2] == ("os", "windows")
    assert os_string_to_signal("") is None


# ---- target_profile entegrasyonu (uçtan uca kimlik) ----
def test_cpe_makes_profile_identity_web():
    extra, _ = cpe_to_signals([
        "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
        "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*",
    ])
    p = fingerprint(ports=[443], extra=extra)
    assert p.value("os") == "ubuntu"          # kimlik CPE'den (elle imza YOK)
    assert p.value("server") == "nginx"
    assert p.has_web_signal() is True         # nginx → gerçek web
    assert p.kind() == "web"


def test_cpe_bare_server_no_web():
    # Sadece OS + SSH CPE'si (web yok) → çıplak sunucu (host) çerçevesi
    extra, _ = cpe_to_signals([
        "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
        "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*",
    ])
    p = fingerprint(ports=[22], extra=extra)
    assert p.value("os") == "ubuntu"
    assert p.has_web_signal() is False
    assert p.kind() == "host"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
