"""
Kadim Güvenlik — informational_findings testleri.

Graph.informational_findings() kanıt düzeyine ULAŞMAYAN ama raporlanması gereken bulguları
(eksik güvenlik başlıkları + NVD sürüm-eşleşmeli doğrulanamamış CVE adayları) verified'tan
AYRI yüzeye çıkarır. Bu, 'boş tarama' hissinin bir nedeni olan 'toplanıyor ama gösterilmiyor'
sinyalini kapatır. AKTİF kanıtlanmış CVE'ler çift sayılmamalı. Düz script (pytest yok).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.attack_graph import Graph, Node, NodeType, NodeState  # noqa: E402


class _Ev:
    """Minimal evidence çiftliği (graph.evidence yalnız .cve/.severity okur)."""
    def __init__(self, cve, severity="high"):
        self.cve = cve
        self.severity = severity


def _labels(findings):
    return {f["label"] for f in findings}


def test_missing_headers_surface_as_info():
    g = Graph(target="portal.test", target_is_ip=False)
    g.add_node(Node(id=f"{g.root_id}:missing-security-headers",
                    type=NodeType.VULNERABILITY, label="Eksik güvenlik başlıkları",
                    value=15.0, breach_prob=0.1, state=NodeState.DISCOVERED,
                    meta={"severity": "info", "missing_headers": ["HSTS", "CSP"]}))
    fnd = g.informational_findings()
    it = next(f for f in fnd if f["label"] == "Eksik güvenlik başlıkları")
    assert it["severity"] == "info"
    assert "HSTS" in it["detail"] and "CSP" in it["detail"]
    print("[OK] test_missing_headers_surface_as_info")


def test_nvd_candidate_surfaces_with_review_note():
    g = Graph(target="1.2.3.4", target_is_ip=True)
    g.add_node(Node(id="vuln:CVE-2026-60002", type=NodeType.VULNERABILITY,
                    label="CVE-2026-60002", value=95.0, breach_prob=0.7,
                    state=NodeState.DISCOVERED,
                    meta={"cves": ["CVE-2026-60002"], "severity": "high",
                          "source": "nvd", "product": "openssh", "version": "8.9p1"}))
    it = next(f for f in g.informational_findings() if f["cve"] == "CVE-2026-60002")
    assert it["severity"] == "high"
    assert it["source"] == "nvd"
    assert "doğrulanamadı" in it["note"]
    print("[OK] test_nvd_candidate_surfaces_with_review_note")


def test_verified_cve_not_double_listed():
    """AKTİF kanıtlanmış CVE informational'da TEKRAR görünmemeli (çift sayma yok)."""
    g = Graph(target="1.2.3.4", target_is_ip=True)
    g.add_node(Node(id="vuln:CVE-2021-41773", type=NodeType.VULNERABILITY,
                    label="CVE-2021-41773", value=95.0, breach_prob=0.9,
                    state=NodeState.BREACHED,
                    meta={"cves": ["CVE-2021-41773"], "severity": "critical", "source": "nvd"}))
    g.evidence.append(_Ev("CVE-2021-41773", "critical"))  # aktif kanıtlandı
    assert "CVE-2021-41773" not in {f["cve"] for f in g.informational_findings()}
    print("[OK] test_verified_cve_not_double_listed")


def test_non_info_non_nvd_excluded():
    """Kaynağı NVD olmayan ve info/low olmayan (ör. graf-içi medium) düğüm informational'a girmez
    — yalnız 'aday/bilgi' niteliğindekiler."""
    g = Graph(target="1.2.3.4", target_is_ip=True)
    g.add_node(Node(id="vuln:x", type=NodeType.VULNERABILITY, label="graf-medium",
                    value=50.0, breach_prob=0.5, state=NodeState.DISCOVERED,
                    meta={"severity": "medium", "source": "adaptive"}))
    assert "graf-medium" not in _labels(g.informational_findings())
    print("[OK] test_non_info_non_nvd_excluded")


def test_summary_includes_informational():
    g = Graph(target="portal.test", target_is_ip=False)
    g.add_node(Node(id=f"{g.root_id}:missing-security-headers",
                    type=NodeType.VULNERABILITY, label="Eksik güvenlik başlıkları",
                    value=15.0, breach_prob=0.1, state=NodeState.DISCOVERED,
                    meta={"severity": "info", "missing_headers": ["HSTS"]}))
    s = g.summary()
    assert "informational_findings" in s
    assert any(f["label"] == "Eksik güvenlik başlıkları" for f in s["informational_findings"])
    print("[OK] test_summary_includes_informational")


if __name__ == "__main__":
    test_missing_headers_surface_as_info()
    test_nvd_candidate_surfaces_with_review_note()
    test_verified_cve_not_double_listed()
    test_non_info_non_nvd_excluded()
    test_summary_includes_informational()
    print("\nTüm testler geçti.")
