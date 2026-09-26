"""Türkçe: Hypervisor mgmt ifşa probu — SAF classify testleri; ağ YOK.

Kök: kullanıcı "ana makine (ESXi/Proxmox) görünür mü?" istedi. VM→host eşlemesi imkansız;
YAPILABİLİR olan: hedefin KENDİSİ hypervisor mgmt arayüzünü internete açıyor mu. Testler
katı imzaları (Proxmox kimliksiz sürüm ucu, ESXi/vCenter/Cockpit/oVirt) + normal HTTPS
sitesinde FP ÜRETMEME'yi doğrular.

Çalıştır: PYTHONPATH=orchestrator python3 orchestrator/pipeline/test_hypervisor_probe.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.hypervisor_probe import classify_hypervisor_response, HYPERVISOR_PORTS  # noqa: E402


def test_proxmox_version_endpoint_confirmed():
    f = classify_hypervisor_response(
        8006, "/api2/json/version", 200,
        headers={"content-type": "application/json"},
        body='{"data":{"version":"8.2.2","release":"8.2"}}',
        json_obj={"data": {"version": "8.2.2", "release": "8.2"}})
    assert f and f["product"] == "Proxmox VE"
    assert f["confidence_tier"] == "confirmed" and f["severity"] == "high"
    assert "8.2.2" in f["proof"]


def test_proxmox_backup_server_8007():
    f = classify_hypervisor_response(
        8007, "/api2/json/version", 200, {"content-type": "application/json"},
        '{"data":{"version":"3.1.0"}}', {"data": {"version": "3.1.0"}})
    assert f and f["product"] == "Proxmox Backup Server"


def test_proxmox_login_cookie():
    f = classify_hypervisor_response(
        8006, "/", 200, {"set-cookie": "PVEAuthCookie=xxx; path=/"},
        "<title>Proxmox Virtual Environment</title>")
    assert f and f["product"] == "Proxmox VE" and f["confidence_tier"] == "confirmed"


def test_esxi_host_client():
    f = classify_hypervisor_response(
        443, "/ui/", 200, {"server": "VMware"},
        "<title>VMware ESXi</title> Host Client")
    assert f and f["product"] == "VMware ESXi" and f["confidence_tier"] == "confirmed"


def test_vcenter_vsphere():
    f = classify_hypervisor_response(
        443, "/ui/", 200, {}, "<html>vSphere Client login websso</html>")
    assert f and "vCenter" in f["product"]


def test_cockpit():
    f = classify_hypervisor_response(
        9090, "/", 200, {"content-type": "text/html"},
        "<title>Cockpit</title>")
    assert f and "Cockpit" in f["product"]


def test_esxi_mob_exposed():
    f = classify_hypervisor_response(
        443, "/mob/", 200, {}, "Managed Object Browser vim25")
    assert f and "MOB" in f["product"] and f["confidence_tier"] == "confirmed"


def test_ovirt():
    f = classify_hypervisor_response(
        443, "/ovirt-engine/", 200, {}, "<html>oVirt Engine</html>")
    assert f and "oVirt" in f["product"]


def test_normal_https_site_no_false_positive():
    # KRİTİK: normal bir web sitesi (443) hypervisor imzası taşımaz → bulgu YOK.
    assert classify_hypervisor_response(
        443, "/", 200, {"server": "nginx"},
        "<html><title>Şirket Ana Sayfa</title>Hoş geldiniz</html>") is None
    # Port 8006 ama içerik alakasız → yine None (yalnız imza tetikler).
    assert classify_hypervisor_response(
        8006, "/", 404, {}, "Not Found") is None


def test_ports_table_sane():
    assert 8006 in HYPERVISOR_PORTS and 443 in HYPERVISOR_PORTS and 9090 in HYPERVISOR_PORTS


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
