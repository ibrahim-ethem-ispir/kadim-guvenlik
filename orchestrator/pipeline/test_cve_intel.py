"""
Dinamik CVE istihbaratı (cve_intel + attack_graph entegrasyonu) için hızlı testler.
Çalıştır: python3 -m pytest orchestrator/pipeline/test_cve_intel.py -v
veya:     python3 orchestrator/pipeline/test_cve_intel.py
"""

import asyncio
import os
import sys

# Repo kökünden çalıştırılabilirlik
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("CVE_INTEL_ENABLED", "true")

from pipeline.attack_graph import Graph, Node, NodeType, NodeState
from pipeline import cve_intel, kev_intel

# KEV feed'i bu testlerin konusu değil (test_kev_intel.py kapsar) — ağa çıkmasın,
# sonuçlar deterministik kalsın. Modül bayrağını kapatmak enrich akışında KEV
# katmanını tamamen atlatır (degrade-safe yol test edilir).
kev_intel.KEV_INTEL_ENABLED = False


def test_cve_hit_to_template():
    assert cve_intel.cve_ids_to_nuclei_templates(["CVE-2021-41773"]) == ["cve-2021-41773"]
    assert cve_intel.cve_ids_to_nuclei_templates(["cve-2022-22965"]) == ["cve-2022-22965"]


def test_normalize_version():
    assert cve_intel._normalize_version("OpenSSH_9.7p1") == "9.7p1"
    assert cve_intel._normalize_version("2.4.49") == "2.4.49"


async def _fake_lookup(product: str, version: str = ""):
    """NVD'yi gerçekten çağırmadan entegrasyonu test eden sahte lookup."""
    if product.lower() == "openssh" and "9.7" in version:
        return [cve_intel.CVEHit(
            cve_id="CVE-2008-3844", severity="medium", cvss_score=5.0,
            cvss_version="2.0", description="Test OpenSSH CVE",
        )]
    if product.lower() == "nginx" and "1.18" in version:
        return [
            cve_intel.CVEHit(cve_id="CVE-2021-23017", severity="high", cvss_score=7.7),
        ]
    return []


async def test_enrich_creates_vuln_edges():
    g = Graph("example.com", target_is_ip=False)
    g._seeded = True
    g.add_node(Node(
        id="svc:openssh@22", type=NodeType.SERVICE, label="openssh@22",
        value=75, breach_prob=0.4, state=NodeState.DISCOVERED,
        meta={"port": 22, "product": "OpenSSH", "version": "9.7",
              "needs_cve_lookup": True},
    ))

    original = cve_intel.lookup
    try:
        cve_intel.lookup = _fake_lookup
        result = await g.enrich_cve_intelligence()
    finally:
        cve_intel.lookup = original

    assert result["lookups"] == 1
    assert result["new_cves"] == 1
    assert result["new_edges"] == 1
    assert "vuln:CVE-2008-3844" in g.nodes
    vuln = g.nodes["vuln:CVE-2008-3844"]
    assert vuln.meta["source"] == "nvd"
    assert vuln.meta["cvss_score"] == 5.0


async def test_enrich_disabled_returns_empty():
    g = Graph("example.com", target_is_ip=False)
    g._seeded = True
    g.add_node(Node(
        id="svc:nginx@80", type=NodeType.SERVICE, label="nginx@80",
        value=40, breach_prob=0.2, state=NodeState.DISCOVERED,
        meta={"port": 80, "product": "nginx", "version": "1.18",
              "needs_cve_lookup": True},
    ))

    old = cve_intel.CVE_INTEL_ENABLED
    try:
        cve_intel.CVE_INTEL_ENABLED = False
        result = await g.enrich_cve_intelligence()
        assert result["source"] == "disabled"
        assert result["new_cves"] == 0
        assert len(g.nodes) == 2  # target + service only
    finally:
        cve_intel.CVE_INTEL_ENABLED = old


async def main():
    test_cve_hit_to_template()
    print("[OK] cve_hit_to_template")
    test_normalize_version()
    print("[OK] normalize_version")
    await test_enrich_creates_vuln_edges()
    print("[OK] enrich_creates_vuln_edges")
    await test_enrich_disabled_returns_empty()
    print("[OK] enrich_disabled_returns_empty")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    asyncio.run(main())
