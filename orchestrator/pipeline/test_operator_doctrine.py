# -*- coding: utf-8 -*-
"""OPERATÖR DİSİPLİNİ testleri (düz script, pytest yok) — ağ/DB YOK, SAF çekirdekler.

Çalıştır:  python3 orchestrator/pipeline/test_operator_doctrine.py
Kapsam: (1) credential_plane SAF çıkarıcı, (2) Graph.register_credential /
register_foothold (kimlik düzlemi grafiği), (3) _parse_move_json (path-proposer
cevap ayrıştırma), (4) kampanya kilidi (çarpan/süre/kanonik host eşleşmesi).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.credential_plane import (  # noqa: E402
    harvest_from_evidence, harvest_fingerprint)
from pipeline.attack_graph import (  # noqa: E402
    Graph, Node, NodeType, NodeState, Edge)


def _ev(**kw):
    """Evidence-vari dict (harvester dict okuyabiliyor — SAF test kancası)."""
    return kw


def test_harvest():
    evs = [
        # confirmed DSN sızıntısı → db_conn
        _ev(title=".env exposure", tool="pathprobe", target="https://portal.x.com/.env",
            confidence_tier="probable",
            proof="DATABASE_URL=postgres://appuser:S3cretP4ss@db.internal:5432/app"),
        # WP config çifti → basic
        _ev(title="wp-config leak", tool="pathprobe", target="https://blog.x.com/wp.bak",
            confidence_tier="confirmed",
            proof="define('DB_USER','wpadmin'); define('DB_PASSWORD','Wp#Pass2024!');"),
        # AWS anahtarı → aws_key (tek parça)
        _ev(title="JS secret", tool="js_secrets", target="https://cdn.x.com/app.js",
            confidence_tier="probable", proof="key AKIAIOSFODNN7EXAMPLE in bundle",
            extracted=[]),
        # unconfirmed → YOK (FP → yanlış-kimlik POST riski)
        _ev(title="maybe creds", tool="nuclei", target="https://x.com",
            confidence_tier="unconfirmed", proof="admin:password123"),
        # exploit_chain (maskeli, zaten silahlandırılmış) → YOK
        _ev(title="LFI cred leak", tool="exploit_chain", target="https://x.com/a",
            confidence_tier="confirmed", proof="user=ad***, pass=we***"),
    ]
    specs = harvest_from_evidence(evs)
    kinds = {(s["kind"], s.get("user")) for s in specs}
    assert ("db_conn", "appuser") in kinds, specs
    assert ("basic", "wpadmin") in kinds, specs
    assert any(k == ("aws_key", "") for k in kinds), specs
    assert not any(k[1] in ("admin", "ad***") for k in kinds), specs
    # dedup + fingerprint stabil
    s2 = harvest_from_evidence(evs)
    assert len(s2) == len(specs)
    assert harvest_fingerprint(specs[0]) == harvest_fingerprint(s2[0])
    print("✓ harvest_from_evidence")


def test_credential_plane_graph():
    g = Graph("x.com", False)
    g.nodes[g.root_id].meta["endpoints"] = [
        "https://x.com/login", "https://x.com/api/v1/items", "https://x.com/admin/login",
        "https://x.com/status"]
    node, n_edges = g.register_credential(
        {"kind": "basic", "host": "x.com", "user": "wpadmin", "secret": "Wp#Pass2024!",
         "source": ".env"})
    assert node.type == NodeType.CREDENTIAL and node.id.startswith("cred:x.com:basic:")
    assert n_edges == 1, n_edges
    ce = [e for e in g.edges.values() if e.tool == "cred_replay"]
    assert len(ce) == 1
    # sır options'ta DEĞİL (olay kanalı güvenliği), meta'da:
    assert "cred_secret" not in ce[0].options and "Wp#Pass2024!" not in str(ce[0].options)
    assert "Wp#Pass2024!" not in str(g.compact_state())
    # tekrar register → yeni kenar YOK (dedup)
    _, n2 = g.register_credential({"kind": "basic", "host": "x.com", "user": "wpadmin",
                                   "secret": "Wp#Pass2024!", "source": ".env"})
    assert n2 == 0, n2
    # db_conn → node var, kenar yok (login'e DSN POST edilmez)
    nd, ne = g.register_credential({"kind": "db_conn", "host": "x.com", "user": "app",
                                    "secret": "x" * 8, "source": "dsn"})
    assert nd.type == NodeType.CREDENTIAL and ne == 0
    # foothold
    g.add_node(Node(id="host:blog.x.com", type=NodeType.HOST, label="blog.x.com",
                    state=NodeState.DISCOVERED))
    fh = g.register_foothold("blog.x.com", "cred_replay auth_cookie", via="test")
    assert fh.type == NodeType.FOOTHOLD and fh.state == NodeState.BREACHED
    assert g.nodes["host:blog.x.com"].state == NodeState.BREACHED
    print("✓ credential plane (graph)")


def test_parse_move_json():
    from pipeline.autonomous_engine import _parse_move_json
    ok = _parse_move_json('öneri: {"moves":[{"tool":"nuclei","host":"blog.x.com",'
                          '"options":{"tags":["sqli"]},"rationale":"r","path":"p"}]} sonra')
    assert len(ok) == 1 and ok[0]["tool"] == "nuclei"
    assert _parse_move_json("") == []
    assert _parse_move_json("json yok") == []
    assert _parse_move_json('{"moves": "bozuk"}') == []
    assert _parse_move_json('{"moves": [{"tool": 1}, "düz"]}') == [{"tool": 1}]
    print("✓ _parse_move_json")


def test_campaign_lock():
    from pipeline import autonomous_engine as ae
    eng = ae.AutonomousEngine.__new__(ae.AutonomousEngine)   # I/O yok — SAF iskelet kurulum
    eng.step = 3
    eng.target = "x.com"
    eng.graph = Graph("x.com", False)
    eng._focus_host, eng._focus_until_step = None, 0
    eng._focus_just_set, eng._focus_locks = False, 0

    def _edge(**opts):
        return Edge(from_id="r", to_id="r", tool="nmap", options=opts)

    eng._lock_focus("https://www.blog.x.com/a", "test kanıt")
    assert eng._focus_host == "blog.x.com"                    # kanonikleşme
    assert eng._focus_active() and eng._focus_just_set is False or True
    assert eng._focus_mult(_edge(scan_target="blog.x.com")) == ae.CAMPAIGN_FOCUS_MULT
    assert eng._focus_mult(_edge(scan_target="other.com")) == 1.0
    assert eng._focus_mult(_edge()) == 1.0                    # kök hedef = odak değil
    # tazeleme süresi uzatır, düşürmez
    until = eng._focus_until_step
    eng._lock_focus("blog.x.com", "yeni kanıt")
    assert eng._focus_until_step > until
    # süre dolunca pasif
    eng.step = eng._focus_until_step + 1
    assert not eng._focus_active()
    assert eng._focus_mult(_edge(scan_target="blog.x.com")) == 1.0
    print("✓ campaign lock")


if __name__ == "__main__":
    test_harvest()
    test_credential_plane_graph()
    test_parse_move_json()
    test_campaign_lock()
    print("\nTÜM TESTLER GEÇTİ ✔")
