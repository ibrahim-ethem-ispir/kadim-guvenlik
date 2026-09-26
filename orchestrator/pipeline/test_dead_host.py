"""Türkçe: Ölü-host karantinası testleri — SAF; ağ YOK.

KÖK SENARYO (gerçek vaka, 25 Eylül taraması): reverse-IP ile keşfedilen co-hosted
domain crawl'da 'host_unreachable: 80/443 üzerinden HTTP erişimi yok' döndürdü.
Motor bunu bilmeye RAĞMEN aynı hosta yeniden crawl attı ve 9 adım sonra BOLA
probu koştu (candidates_probed: 0) — "kapalı domainde ne arıyorsun" durumu.

Bu modül üç savunma katmanını doğrular:
  1) mark_dead: node DEAD olur + açık kenarları 'skipped_dead' kapanır (idempotent).
  2) siege_score/expand_frontier: ölü hedefe puan 0 / frontier dışı (ölümden sonra
     doğan LLM kenarları için emniyet kemeri dahil).
  3) observe() + _validate(): host_unreachable verisi karantinayı tetikler; ölü
     hosta scan_target'lı karar (LLM hipotezi dâhil) reddedilir.

Çalıştır: python3 orchestrator/pipeline/test_dead_host.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.attack_graph import (  # noqa: E402
    Graph, Node, Edge, NodeType, NodeState, siege_score,
)
from pipeline.autonomous_engine import (  # noqa: E402
    AutonomousEngine, Decision, DecisionAction,
)

DEAD_HOST = "dead-co-api.example"
LIVE_HOST = "canli-site.example.com"


def _assert(cond, msg):
    status = "OK  " if cond else "FAIL"
    print(f"[{status}] {msg}")
    if not cond:
        raise SystemExit(1)


def _graph_with_cohosted() -> Graph:
    """Reverse-IP sonrası durum: kök + bir ölü olacak co-hosted + bir canlı host."""
    g = Graph(target="203.0.113.84", target_is_ip=True)
    dead_node = g.add_node(Node(
        id=f"host:reverse:{DEAD_HOST}", type=NodeType.HOST, label=DEAD_HOST,
        value=10, breach_prob=0.08, state=NodeState.DISCOVERED,
        meta={"discovered_via": "reverse_ip"},
    ))
    live_node = g.add_node(Node(
        id=f"host:reverse:{LIVE_HOST}", type=NodeType.HOST, label=LIVE_HOST,
        value=10, breach_prob=0.08, state=NodeState.DISCOVERED,
    ))
    for node in (dead_node, live_node):
        g.add_edge(Edge(from_id=g.root_id, to_id=node.id, tool="crawl",
                        options={"scan_target": node.label}))
        g.add_edge(Edge(from_id=g.root_id, to_id=node.id, tool="pathprobe",
                        options={"scan_target": node.label}))
    return g, dead_node, live_node


def test_mark_dead_closes_edges():
    g, dead_node, live_node = _graph_with_cohosted()
    dead_edges = [e for e in g.edges.values() if e.to_id == dead_node.id
                  and e.state == "open"]
    _assert(len(dead_edges) == 2, "kurulum: ölü aday host'a 2 açık kenar var")

    ok = g.mark_dead(DEAD_HOST, "host_unreachable: 80/443 üzerinden HTTP erişimi yok")
    _assert(ok is True, "mark_dead: ilk işaretleme True döner")
    _assert(dead_node.state == NodeState.DEAD, "mark_dead: node.state=DEAD")
    _assert(dead_node.meta.get("dead_reason"), "mark_dead: dead_reason meta'da")
    _assert(all(e.state == "skipped_dead" for e in dead_edges),
            "mark_dead: ölü hosta giden açık kenarlar 'skipped_dead' kapandı")

    # İdempotent: ikinci işaretleme yeni karantina sayılmaz
    _assert(g.mark_dead(DEAD_HOST) is False, "mark_dead: ikinci çağrı False (idempotent)")

    # Canlı hosta dokunulmadı
    live_edges = [e for e in g.edges.values() if e.to_id == live_node.id]
    _assert(all(e.state == "open" for e in live_edges),
            "mark_dead: canlı hostun kenarları açık kaldı")


def test_root_cannot_be_killed():
    g = Graph(target="example.com", target_is_ip=False)
    root = g.nodes[g.root_id]
    _assert(g.mark_dead("example.com") is False,
            "kök hedef mark_dead ile öldürülemez (erken-kesme mekanizması ayrı)")
    _assert(root.state != NodeState.DEAD, "kök node durumu değişmedi")


def test_frontier_and_score_exclude_dead():
    g, dead_node, live_node = _graph_with_cohosted()
    g.mark_dead(DEAD_HOST, "host_unreachable")

    frontier = g.expand_frontier()
    _assert(all(e.to_id != dead_node.id for e in frontier),
            "expand_frontier: ölü node'a giden kenar frontier'de YOK")
    _assert(any(e.to_id == live_node.id for e in frontier),
            "expand_frontier: canlı host kenarları frontier'de duruyor")

    dead_edge = Edge(from_id=g.root_id, to_id=dead_node.id, tool="crawl",
                     options={"scan_target": DEAD_HOST})
    _assert(siege_score(dead_edge, g) == 0.0,
            "siege_score: ölü hedefli kenar puanı 0")

    # Emniyet kemeri: ölümden SONRA doğan (ör. LLM önerisi) yeni kenar da dışlanır
    g.add_edge(Edge(from_id=g.root_id, to_id=dead_node.id, tool="probe_api_bola",
                    options={"scan_target": DEAD_HOST}, meta={"from_llm": True}))
    _assert(all(e.to_id != dead_node.id for e in g.expand_frontier()),
            "emniyet kemeri: ölümden sonra seed edilen LLM kenarı da frontier dışı")


def test_is_dead_lookup():
    g, _, _ = _graph_with_cohosted()
    g.mark_dead(DEAD_HOST)
    _assert(g.is_dead(DEAD_HOST) is True, "is_dead: birebir label bulur")
    _assert(g.is_dead("  DEAD-CO-API.EXAMPLE ") is True,
            "is_dead: case/boşluk normalize eder")
    _assert(g.is_dead(LIVE_HOST) is False, "is_dead: canlı host False")
    _assert(g.is_dead("hiç-yok.example.com") is False, "is_dead: bilinmeyen host False")


def test_observe_quarantines_and_validate_rejects():
    """Uçtan uca: observe() host_unreachable'i karantinaya çevirir → _validate ölü
    hosta scan_target'lı kararı (LLM BOLA hipotezi senaryosu) reddeder."""
    engine = AutonomousEngine(
        scan_id="test-dead-host", target="203.0.113.84", target_is_ip=True, emit=None)
    g = engine.graph
    dead_node = g.add_node(Node(
        id=f"host:reverse:{DEAD_HOST}", type=NodeType.HOST, label=DEAD_HOST,
        value=10, breach_prob=0.08, state=NodeState.DISCOVERED,
        meta={"discovered_via": "reverse_ip"},
    ))

    # 1) Ölü crawl gözlemi (25 Eylül taramasındaki gerçek veri şekli)
    crawl_decision = Decision(
        action=DecisionAction.RUN_TOOL, tool="crawl",
        options={"scan_target": DEAD_HOST},
        reasoning="RAID-crawl", stage_name="crawl_step18")
    engine.observe(crawl_decision, {
        "target": DEAD_HOST,
        "base_url": f"https://{DEAD_HOST}",
        "discovered_urls": [], "discovered_count": 1,
        "parameterized_endpoints": [], "forms": [], "js_assets": [],
        "elapsed_seconds": 0.17,
        "note": "host_unreachable: 80/443 üzerinden HTTP erişimi yok",
    }, "completed")

    _assert(DEAD_HOST in engine.newly_dead_hosts,
            "observe: host_unreachable → newly_dead_hosts'a yazıldı (pipeline duyurur)")
    _assert(dead_node.state == NodeState.DEAD, "observe: node karantinaya alındı")

    # 2) LLM hipotezi: aynı ölü hosta BOLA probu (gerçek vakadaki step 27)
    bola_decision = Decision(
        action=DecisionAction.RUN_TOOL, tool="probe_api_bola",
        options={"scan_target": DEAD_HOST},
        reasoning="dead-co-api API hostları — kitlesel PII sızıntısı (LLM hipotezi)",
        source="llm", stage_name="probe_api_bola_step27")
    bola_edge = Edge(from_id=g.root_id, to_id=dead_node.id, tool="probe_api_bola",
                     options={"scan_target": DEAD_HOST})
    verdict = engine._validate(bola_decision, bola_edge, g)
    _assert(verdict is None,
            "_validate: ÖLÜ hosta scan_target'lı karar reddedildi (LLM hipotezi kapıdan döner)")

    # 3) Kenar-yolu güvencesi: scan_target yok ama kenarın hedefi ölü
    edge_only = Decision(
        action=DecisionAction.RUN_TOOL, tool="pathprobe", options={},
        stage_name="pathprobe_step29")
    verdict2 = engine._validate(edge_only, bola_edge, g)
    _assert(verdict2 is None, "_validate: kenarın to_node'u ölüyse karar yine reddedilir")

    # 4) Canlı hedef etkilenmez
    ok_decision = Decision(
        action=DecisionAction.RUN_TOOL, tool="pathprobe",
        options={"scan_target": LIVE_HOST}, stage_name="pathprobe_step30")
    ok_edge = Edge(from_id=g.root_id, to_id=g.root_id, tool="pathprobe",
                   options={"scan_target": LIVE_HOST})
    _assert(engine._validate(ok_decision, ok_edge, g) is not None,
            "_validate: canlı hedefli karar geçerli (aşırı karantina yok)")


if __name__ == "__main__":
    test_mark_dead_closes_edges()
    test_root_cannot_be_killed()
    test_frontier_and_score_exclude_dead()
    test_is_dead_lookup()
    test_observe_quarantines_and_validate_rejects()
    print("\nTÜM TESTLER GEÇTİ ☠️→✅")
