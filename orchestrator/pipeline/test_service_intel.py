"""Türkçe: APT servis-istihbaratı testleri — mail/DNS/tanınmayan servisler artık node alır
ve NVD CVE korelasyonuna girer; sürüm-CVE nuclei template'i olmadan bile 'unconfirmed'
kanıt olarak GÖRÜNÜR.

Kök vaka (regresyon): e4b taramasında nmap 9 port (PowerDNS 4.9.16, Dovecot, mail) buldu
ama hepsi kategoride olmadığı için 'continue' ile atlanıp 0 bulgu üretiliyordu.

Çalıştır: PYTHONPATH=orchestrator python3 orchestrator/pipeline/test_service_intel.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from types import SimpleNamespace  # noqa: E402
from pipeline import attack_graph as AG  # noqa: E402
from pipeline.attack_graph import Graph, NodeType  # noqa: E402


def _nmap_integrate(g, services):
    dec = SimpleNamespace(tool="nmap", options={}, to_id=g.root_id)
    g.integrate(dec, {"services": services}, "nmap")


def test_mail_dns_services_get_nodes():
    g = Graph(target="e4b.example.com", target_is_ip=False)
    _nmap_integrate(g, [
        {"port": 53, "service": "domain", "product": "PowerDNS", "version": "4.9.16"},
        {"port": 143, "service": "imap", "product": "Dovecot imapd", "version": ""},
        {"port": 25, "service": "smtp", "product": "Exim", "version": "4.94"},
    ])
    svc = [n for n in g.nodes.values() if n.type == NodeType.SERVICE]
    labels = {n.label.split("@")[0] for n in svc}
    # Eskiden bunların hiçbiri node almıyordu (kategoride yoktu → continue)
    assert "dns" in labels or "domain" in labels
    assert "dovecot" in labels
    assert "exim" in labels or "smtp" in labels


def test_versioned_service_marked_for_cve_lookup():
    g = Graph(target="x.example.com", target_is_ip=False)
    _nmap_integrate(g, [
        {"port": 53, "service": "domain", "product": "PowerDNS", "version": "4.9.16"},
        {"port": 143, "service": "imap", "product": "Dovecot imapd", "version": ""},  # sürümsüz
    ])
    need = [n for n in g.nodes.values()
            if n.type == NodeType.SERVICE and n.meta.get("needs_cve_lookup")]
    versions = {n.meta.get("version") for n in need}
    assert "4.9.16" in versions          # versiyonlu → lookup'a girer
    assert "" not in versions            # versiyonsuz → lookup'a girmez (NVD anlamsız)


def test_uncategorized_versioned_service_gets_node():
    """Kategoride HİÇ olmayan bir servis bile ürün+sürüm varsa node alır ve CVE'ye sokulur."""
    g = Graph(target="x.example.com", target_is_ip=False)
    _nmap_integrate(g, [
        {"port": 7777, "service": "unknownsvc", "product": "AcmeApp", "version": "2.1.0"},
        {"port": 7778, "service": "unknownsvc2", "product": "NoVersionApp", "version": ""},
    ])
    need = [n for n in g.nodes.values()
            if n.type == NodeType.SERVICE and n.meta.get("needs_cve_lookup")]
    assert any(n.meta.get("version") == "2.1.0" for n in need)   # versiyonlu tanınmayan → lookup
    # Versiyonsuz tanınmayan → node YOK (gürültü üretme)
    labels = {n.label for n in g.nodes.values() if n.type == NodeType.SERVICE}
    assert not any("7778" in l for l in labels)


def test_version_cve_becomes_unconfirmed_evidence_without_template():
    """En kritik davranış: NVD bir CVE bulur ama nuclei template'i YOKSA bile bulgu
    'unconfirmed' kanıt olarak GÖRÜNÜR (eskiden sessizce kayboluyordu)."""
    class _FakeHit:
        cve_id = "CVE-2024-9999"; cvss_score = 8.1; severity = "high"
        description = "PowerDNS uzaktan DoS"

    class _FakeIntel:
        CVE_INTEL_ENABLED = True
        async def lookup(self, product, version):
            return [_FakeHit()]
        def cve_ids_to_nuclei_templates(self, ids):
            return []  # template YOK
    AG._cve_intel = _FakeIntel()
    try:
        g = Graph(target="e4b.example.com", target_is_ip=False)
        _nmap_integrate(g, [{"port": 53, "service": "domain",
                             "product": "PowerDNS", "version": "4.9.16"}])
        res = asyncio.new_event_loop().run_until_complete(g.enrich_cve_intelligence())
        assert res["new_cves"] == 1
        evs = [e.to_dict() for e in g.evidence]
        hit = [e for e in evs if e["tool"] == "cve_intel"]
        assert hit, "cve_intel kanıtı üretilmedi"
        assert hit[0]["cve"] == "CVE-2024-9999"
        assert hit[0]["confidence_tier"] == "unconfirmed"   # manşeti şişirmez, görünür
    finally:
        AG._cve_intel = None  # global sahte durumu temizle


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
