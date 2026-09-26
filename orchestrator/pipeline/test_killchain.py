"""Türkçe: APT kill-chain kompozisyonu (killchain) birim testleri — SAF; ağ yok.

Kapsam: classify_ttp (gözlem→ATT&CK), compose_killchain (fazları hedefe diz + skor).

Çalıştır: python3 orchestrator/pipeline/test_killchain.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.killchain import classify_ttp, compose_killchain, PHASE_ORDER  # noqa: E402


def test_classify_sqli_execution():
    t = classify_ttp({"cwe": ["CWE-89"], "title": "SQL Injection"})
    assert t.tactic == "execution" and t.technique_id == "T1190"


def test_classify_exposure_credential_access():
    t = classify_ttp({"tool": "pathprobe", "category": "vcs_exposure", "title": ".git/HEAD"})
    assert t.tactic == "credential-access" and t.technique_id == "T1552.001"


def test_classify_ssh_lateral():
    t = classify_ttp({"kind": "service", "service": "ssh", "category": "remote-mgmt"})
    assert t.tactic == "lateral-movement" and t.technique_id == "T1021"


def test_classify_mail_collection():
    t = classify_ttp({"kind": "service", "service": "dovecot", "category": "mail-service"})
    assert t.tactic == "collection" and t.technique_id == "T1114"


def test_classify_cve_initial_access():
    t = classify_ttp({"tool": "cve_intel", "cve": "CVE-2024-1", "title": "PowerDNS CVE"})
    assert t.tactic == "initial-access"


def test_classify_unknown_recon():
    t = classify_ttp({"title": "mystery"})
    assert t.tactic == "reconnaissance"


def test_compose_empty():
    kc = compose_killchain([])
    assert len(kc.links) == 0 and kc.score == 0.0


def test_compose_orders_phases_and_scores():
    obs = [
        {"kind": "service", "service": "apache", "category": "web-app", "title": "apache@443",
         "confidence_tier": "probable", "value": 40, "breach_prob": 0.5},
        {"tool": "poc_verify", "cwe": ["CWE-89"], "title": "SQLi", "severity": "critical",
         "confidence_tier": "confirmed", "target": "x?id=1"},
        {"tool": "pathprobe", "category": "vcs_exposure", "title": ".git", "severity": "high",
         "confidence_tier": "confirmed"},
        {"kind": "service", "service": "ssh", "category": "remote-mgmt", "title": "ssh@22",
         "confidence_tier": "probable", "value": 75, "breach_prob": 0.5},
    ]
    kc = compose_killchain(obs)
    phases = [l.phase for l in kc.links]
    # Kill-chain sırası korunmalı (initial-access, execution, credential-access, lateral)
    idx = {name: i for i, (name, _, _) in enumerate(PHASE_ORDER)}
    assert phases == sorted(phases, key=lambda p: idx[p])
    assert "execution" in phases and "lateral-movement" in phases
    assert kc.score > 0 and len(kc.links) >= 4
    assert kc.objective == "Yanal Hareket"  # ulaşılan en ileri faz
    assert "T1190" in kc.techniques


def test_confirmed_outweighs_unconfirmed_same_phase():
    # Aynı fazda kanıtlı gözlem, doğrulanmamıştan daha güçlü halka olmalı
    obs = [
        {"tool": "cve_intel", "cve": "CVE-1", "title": "zayif-aday", "severity": "high",
         "confidence_tier": "unconfirmed", "value": 95, "breach_prob": 0.9},
        {"tool": "pathprobe", "category": "exposure", "title": "kanitli-ifsa", "severity": "high",
         "confidence_tier": "confirmed", "value": 60, "breach_prob": 0.6},
    ]
    kc = compose_killchain(obs)
    ia = [l for l in kc.links if l.phase == "initial-access"]
    assert ia and ia[0].title == "kanitli-ifsa"  # kademe çarpanı kanıtlıyı öne çıkardı


def test_objective_driven_boost_prefers_deeper_phase():
    """Faz 2b: aynı değer/cost'ta, kill-chain'de DAHA DERİN faza (lateral) yönelen kenar
    daha yüksek skorlanır — motor zinciri kovalar. Kapatınca (env=0) eşitlenir (regresyon yok)."""
    import os as _os
    from pipeline.attack_graph import Graph, Node, Edge, NodeType, NodeState, siege_score
    g = Graph(target="x.example.com", target_is_ip=False)
    g.add_node(Node(id="svc:ssh@22", type=NodeType.SERVICE, label="ssh@22", value=60,
                    breach_prob=0.5, state=NodeState.DISCOVERED, meta={"matched_service": "ssh", "port": 22}))
    g.add_node(Node(id="svc:apache@80", type=NodeType.SERVICE, label="apache@80", value=60,
                    breach_prob=0.5, state=NodeState.DISCOVERED, meta={"matched_service": "apache", "port": 80}))
    e_ssh = Edge(from_id=g.root_id, to_id="svc:ssh@22", tool="nuclei", cost=20, success_prob=0.6)
    e_web = Edge(from_id=g.root_id, to_id="svc:apache@80", tool="nuclei", cost=20, success_prob=0.6)
    g.add_edge(e_ssh); g.add_edge(e_web)
    _os.environ.pop("AUTONOMOUS_KILLCHAIN_DRIVE", None)  # varsayılan açık
    assert siege_score(e_ssh, g) > siege_score(e_web, g)
    assert g._killchain_drive_boost(e_ssh) >= 1.0  # asla <1.0 (hiçbir kenarı bastırmaz)
    _os.environ["AUTONOMOUS_KILLCHAIN_DRIVE"] = "0"
    try:
        assert abs(siege_score(e_ssh, g) - siege_score(e_web, g)) < 1e-9  # kapalı = eski davranış
    finally:
        _os.environ.pop("AUTONOMOUS_KILLCHAIN_DRIVE", None)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
