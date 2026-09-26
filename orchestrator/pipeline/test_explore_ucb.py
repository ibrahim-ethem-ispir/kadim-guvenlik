"""
Kadim Güvenlik — A2 keşif/sömürü dengesi (UCB1 keşif terimi) testleri
=====================================================================
Türkçe: explore_bonus / selection_score sözleşmesini izole doğrular (düz script, pytest yok,
ağ yok). Kanıtlanan sözleşme:
  - EXPLORE_UCB KAPALI → selection_score ≡ objective_score (davranış birebir, regresyon yok).
  - explore_bonus az-denenmiş kenarda büyük, tried_count arttıkça söner (keşif çürümesi).
  - hiç-denenmemiş (tried_count=0) kenarda SONLU (n_i+1 yumuşatması → +sonsuz patlaması yok).
  - yalnız AÇIK kenara uygulanır; kapalı/tükenmiş kenar keşif değeri taşımaz.
  - toplam adım (N) arttıkça log terimi büyür (geç turlarda keşif iştahı ölçekli artar).

Çalıştır: python3 orchestrator/pipeline/test_explore_ucb.py
"""
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pipeline.attack_graph as ag  # noqa: E402
from pipeline.attack_graph import (  # noqa: E402
    Graph, Node, Edge, NodeType, NodeState, objective_score, selection_score, explore_bonus,
)


def _graph_with_edge(tried=0, state="open"):
    g = Graph("t.example", False)
    g.nodes["svc:a"] = Node(id="svc:a", type=NodeType.SERVICE, label="a",
                            value=80.0, breach_prob=0.5, state=NodeState.DISCOVERED)
    e = Edge(from_id=g.root_id, to_id="svc:a", tool="nuclei", cost=45.0, success_prob=0.8)
    e.tried_count = tried
    e.state = state
    return g, e


def test_kapali_birebir_objective():
    """EXPLORE_UCB kapalı → selection_score ≡ objective_score (bonus 0)."""
    old = ag.EXPLORE_UCB
    ag.EXPLORE_UCB = False
    try:
        g, e = _graph_with_edge()
        assert explore_bonus(e, 10) == 0.0
        assert selection_score(e, g, 10) == objective_score(e, g)
    finally:
        ag.EXPLORE_UCB = old


def test_hic_denenmemis_sonlu_ve_pozitif():
    """tried_count=0 → bonus SONLU (n_i+1 yumuşatması) ve pozitif (EXPLORE_UCB açıkken)."""
    old = ag.EXPLORE_UCB
    ag.EXPLORE_UCB = True
    try:
        g, e = _graph_with_edge(tried=0)
        b = explore_bonus(e, 8)
        assert math.isfinite(b) and b > 0.0, b
        # Beklenen: c·sqrt(ln(N+1)/(0+1))
        assert abs(b - ag.EXPLORE_UCB_C * math.sqrt(math.log(9) / 1)) < 1e-9
    finally:
        ag.EXPLORE_UCB = old


def test_denendikce_soner():
    """tried_count arttıkça keşif bonusu MONOTON azalır (az-örneklenmişi kayırır)."""
    old = ag.EXPLORE_UCB
    ag.EXPLORE_UCB = True
    try:
        g, _ = _graph_with_edge()
        prev = None
        for t in range(0, 5):
            _, e = _graph_with_edge(tried=t)
            b = explore_bonus(e, 20)
            if prev is not None:
                assert b < prev, (t, b, prev)
            prev = b
    finally:
        ag.EXPLORE_UCB = old


def test_toplam_adim_artinca_buyur():
    """N (toplam adım) büyüdükçe log terimi büyür → geç turlarda keşif iştahı ölçekli artar."""
    old = ag.EXPLORE_UCB
    ag.EXPLORE_UCB = True
    try:
        _, e = _graph_with_edge(tried=1)
        assert explore_bonus(e, 50) > explore_bonus(e, 5)
    finally:
        ag.EXPLORE_UCB = old


def test_yalniz_acik_kenara():
    """Kapalı/tükenmiş kenar keşif değeri taşımaz → bonus 0."""
    old = ag.EXPLORE_UCB
    ag.EXPLORE_UCB = True
    try:
        for st in ("executed", "exhausted", "skipped_danger"):
            _, e = _graph_with_edge(state=st)
            assert explore_bonus(e, 10) == 0.0, st
    finally:
        ag.EXPLORE_UCB = old


def test_selection_toplamsal():
    """selection_score = objective_score + explore_bonus (toplamsal sözleşme)."""
    old = ag.EXPLORE_UCB
    ag.EXPLORE_UCB = True
    try:
        g, e = _graph_with_edge(tried=2)
        assert abs(selection_score(e, g, 15) - (objective_score(e, g) + explore_bonus(e, 15))) < 1e-12
    finally:
        ag.EXPLORE_UCB = old


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
