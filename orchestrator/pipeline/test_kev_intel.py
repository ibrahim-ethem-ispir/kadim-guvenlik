"""
Aktif-sömürü istihbaratı (kev_intel + attack_graph entegrasyonu) için hızlı testler.
Çalıştır: python3 -m pytest orchestrator/pipeline/test_kev_intel.py -v
veya:     python3 orchestrator/pipeline/test_kev_intel.py
"""

import asyncio
import os
import sys
import time

# Repo kökünden çalıştırılabilirlik (test_cve_intel.py deseni)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("CVE_INTEL_ENABLED", "true")
os.environ.setdefault("KEV_INTEL_ENABLED", "true")

from pipeline.attack_graph import Graph, Node, NodeType, NodeState, KEV_URGENCY
from pipeline import cve_intel, kev_intel


# ---------------------------------------------------------------
# Sahte KEV feed'i — gerçek CISA şemasının minyatürü
# ---------------------------------------------------------------
FAKE_KEV_PAYLOAD = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.08.14",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-1281",
            "vendorProject": "Ivanti",
            "product": "Endpoint Manager Mobile (EPMM)",
            "vulnerabilityName": "Ivanti EPMM Code Injection Vulnerability",
            "dateAdded": "2026-02-03",
            "dueDate": "2026-02-17",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "Apply mitigations per vendor instructions.",
        },
        {
            "cveID": "CVE-2026-33017",
            "vendorProject": "Langflow",
            "product": "Langflow",
            "vulnerabilityName": "Langflow Code Injection Vulnerability",
            "dateAdded": "2026-07-30",
            "dueDate": "2026-08-13",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        },
        {
            "cveID": "CVE-2021-23017",
            "vendorProject": "F5",
            "product": "NGINX",
            "vulnerabilityName": "NGINX DNS Resolver Off-by-One Heap Write",
            "dateAdded": "2021-11-17",
            "dueDate": "2021-12-01",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
    ],
}


def _load_fake_feed():
    """Ağa çıkmadan KEV durumunu sahte payload ile yükle."""
    kev_intel._ingest(FAKE_KEV_PAYLOAD)
    kev_intel._STATE["loaded_at"] = time.monotonic()


async def _always_loaded(force: bool = False):
    return True


async def _fake_epss(cve_ids):
    return {}


def _patch_kev(monkey_state=None):
    """ensure_loaded/epss_scores'i ağsız sahtelerle değiştir; geri alma fonksiyonu döner."""
    orig_ensure = kev_intel.ensure_loaded
    orig_epss = kev_intel.epss_scores
    kev_intel.ensure_loaded = _always_loaded
    kev_intel.epss_scores = _fake_epss
    _load_fake_feed()

    def restore():
        kev_intel.ensure_loaded = orig_ensure
        kev_intel.epss_scores = orig_epss
        kev_intel._STATE["by_cve"] = {}
        kev_intel._STATE["by_product"] = {}
        kev_intel._STATE["loaded_at"] = 0.0
    return restore


# ---------------------------------------------------------------
# Birim testler (saf fonksiyonlar)
# ---------------------------------------------------------------

def test_normalize_key():
    assert kev_intel._normalize_key("Palo Alto Networks PAN-OS") == "paloaltonetworkspanos"
    assert kev_intel._normalize_key("Exchange Server") == "exchangeserver"
    assert kev_intel._normalize_key("") == ""


def test_ingest_and_is_kev():
    _load_fake_feed()
    try:
        entry = kev_intel.is_kev("cve-2026-1281")     # case-insensitive
        assert entry is not None
        assert entry.vendor == "Ivanti"
        assert entry.ransomware is False
        ransomware_entry = kev_intel.is_kev("CVE-2026-33017")
        assert ransomware_entry.ransomware is True
        assert kev_intel.is_kev("CVE-9999-0000") is None
    finally:
        kev_intel._STATE["by_cve"] = {}
        kev_intel._STATE["by_product"] = {}
        kev_intel._STATE["loaded_at"] = 0.0


def test_lookup_product_alias():
    _load_fake_feed()
    try:
        hits = kev_intel.lookup_product("epmm")       # alias tablosu üzerinden
        assert [h.cve_id for h in hits] == ["CVE-2026-1281"]
        hits = kev_intel.lookup_product("Langflow")   # normalize tam eşleşme
        assert [h.cve_id for h in hits] == ["CVE-2026-33017"]
        assert kev_intel.lookup_product("bilinmeyen-urun") == []
    finally:
        kev_intel._STATE["by_cve"] = {}
        kev_intel._STATE["by_product"] = {}
        kev_intel._STATE["loaded_at"] = 0.0


# ---------------------------------------------------------------
# Graf entegrasyonu
# ---------------------------------------------------------------

async def _fake_nvd_lookup(product: str, version: str = ""):
    """NVD'yi gerçekten çağırmadan entegrasyonu test eden sahte lookup."""
    if product.lower() == "nginx" and "1.18" in version:
        return [cve_intel.CVEHit(cve_id="CVE-2021-23017", severity="high", cvss_score=7.7)]
    return []


async def test_kev_boosts_nvd_hit():
    """NVD'nin bulduğu CVE KEV üyesiyse düğüm yükseltilir ve kenar urgency'si artar."""
    restore = _patch_kev()
    original = cve_intel.lookup
    try:
        cve_intel.lookup = _fake_nvd_lookup
        g = Graph("example.com", target_is_ip=False)
        g._seeded = True
        g.add_node(Node(
            id="svc:nginx@80", type=NodeType.SERVICE, label="nginx@80",
            value=40, breach_prob=0.2, state=NodeState.DISCOVERED,
            meta={"port": 80, "product": "nginx", "version": "1.18",
                  "needs_cve_lookup": True},
        ))
        result = await g.enrich_cve_intelligence()
    finally:
        cve_intel.lookup = original
        restore()

    assert result["new_cves"] == 1
    assert result["kev_boosts"] == 1
    assert result["source"] == "nvd+kev"
    vuln = g.nodes["vuln:CVE-2021-23017"]
    assert vuln.meta["kev"] is True
    assert vuln.breach_prob >= 0.85          # KEV yükseltmesi (NVD tabanı ~0.885 üstü değilse)
    edge = next(e for e in g.edges.values() if e.to_id == "vuln:CVE-2021-23017")
    assert edge.urgency == KEV_URGENCY       # NVD tabanı 1.4 → KEV 2.2
    assert "KEV" in edge.rationale


async def test_kev_product_sweep_without_version():
    """Sürümü BİLİNMEYEN servis (AI/agentic deseni) KEV ürün taramasıyla yakalanır."""
    restore = _patch_kev()
    original = cve_intel.lookup
    try:
        cve_intel.lookup = _fake_nvd_lookup   # langflow için NVD boş döner
        g = Graph("example.com", target_is_ip=False)
        g._seeded = True
        g.add_node(Node(
            id="svc:langflow@7860", type=NodeType.SERVICE, label="langflow@7860",
            value=40, breach_prob=0.2, state=NodeState.DISCOVERED,
            meta={"port": 7860, "product": "langflow"},   # version YOK — NVD hunisi burada ölür
        ))
        result = await g.enrich_cve_intelligence()
    finally:
        cve_intel.lookup = original
        restore()

    assert result["kev_cves"] == 1
    vuln = g.nodes.get("vuln:CVE-2026-33017")
    assert vuln is not None
    assert vuln.meta["source"] == "kev"
    assert vuln.meta["kev_ransomware"] is True
    assert vuln.breach_prob == 0.95          # fidye yazılımı kampanyası → zirve
    edge = next(e for e in g.edges.values() if e.to_id == "vuln:CVE-2026-33017")
    assert edge.tool == "nuclei"
    assert "cve-2026-33017" in edge.options["templates"]
    # kanıt satırı da yazılmış olmalı (unconfirmed kademesi)
    assert any(ev.cve == "CVE-2026-33017" and ev.tool == "kev_intel" for ev in g.evidence)


async def test_kev_disabled_no_regression():
    """KEV kapalıyken davranış eski haliyle birebir korunur (NVD-only)."""
    restore = _patch_kev()
    original = cve_intel.lookup
    old_flag = kev_intel.KEV_INTEL_ENABLED
    try:
        kev_intel.KEV_INTEL_ENABLED = False
        cve_intel.lookup = _fake_nvd_lookup
        g = Graph("example.com", target_is_ip=False)
        g._seeded = True
        g.add_node(Node(
            id="svc:nginx@80", type=NodeType.SERVICE, label="nginx@80",
            value=40, breach_prob=0.2, state=NodeState.DISCOVERED,
            meta={"port": 80, "product": "nginx", "version": "1.18",
                  "needs_cve_lookup": True},
        ))
        result = await g.enrich_cve_intelligence()
    finally:
        kev_intel.KEV_INTEL_ENABLED = old_flag
        cve_intel.lookup = original
        restore()

    assert result["new_cves"] == 1           # NVD yolu çalışır
    assert result["kev_boosts"] == 0
    assert result["kev_cves"] == 0
    vuln = g.nodes["vuln:CVE-2021-23017"]
    assert "kev" not in vuln.meta            # KEV sinyali üretilmedi
    edge = next(e for e in g.edges.values() if e.to_id == "vuln:CVE-2021-23017")
    assert edge.urgency == 1.4               # eski NVD urgency'si korunur


async def main():
    test_normalize_key()
    print("[OK] normalize_key")
    test_ingest_and_is_kev()
    print("[OK] ingest_and_is_kev")
    test_lookup_product_alias()
    print("[OK] lookup_product_alias")
    await test_kev_boosts_nvd_hit()
    print("[OK] kev_boosts_nvd_hit")
    await test_kev_product_sweep_without_version()
    print("[OK] kev_product_sweep_without_version")
    await test_kev_disabled_no_regression()
    print("[OK] kev_disabled_no_regression")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    asyncio.run(main())
