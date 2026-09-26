"""
Kadim Güvenlik — Bilgi-Kazanımı Hedefi (information-gain objective) testleri
============================================================================
Türkçe: objective_score / info_relevance ve doğal durma kriterini izole doğrular
(düz script, pytest yok, ağ yok). Kanıtlanan sözleşme:
  - Flag KAPALI → objective_score ≡ siege_score (davranış birebir, regresyon yok).
  - Flag AÇIK   → kanıtlanmamış+taze kenar öne çıkar, kanıtlanmış/tükenmiş kenar söner.
  - Doğal durma → yalnız kanıtlanmış/tükenmiş kenar kalınca en yüksek ilgililik eşiğin altı.

Çalıştır: python3 orchestrator/pipeline/test_info_gain.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pipeline.attack_graph as ag  # noqa: E402
from pipeline.attack_graph import (  # noqa: E402
    Graph, Node, Edge, NodeType, NodeState, siege_score, objective_score,
    info_relevance, INFO_GAIN_MIN,
)


def _graph_with_two_services():
    """Aynı değer/olasılıkta iki servis: biri KANITLANMAMIŞ (discovered), biri KANITLANMIŞ
    (breached). Kenarlar birebir aynı → base siege_score EŞİT; fark yalnız bilgi-kazanımından."""
    g = Graph("t.example", False)
    g.nodes["svc:a"] = Node(id="svc:a", type=NodeType.SERVICE, label="a",
                            value=80.0, breach_prob=0.5, state=NodeState.DISCOVERED)
    g.nodes["svc:b"] = Node(id="svc:b", type=NodeType.SERVICE, label="b",
                            value=80.0, breach_prob=0.5, state=NodeState.BREACHED)
    e_unproven = Edge(from_id=g.root_id, to_id="svc:a", tool="nuclei", cost=45.0, success_prob=0.8)
    e_proven = Edge(from_id=g.root_id, to_id="svc:b", tool="nuclei", cost=45.0, success_prob=0.8)
    return g, e_unproven, e_proven


def _set_flag(on):
    ag.INFO_GAIN_OBJECTIVE = on


# ---------------- Flag KAPALI: birebir siege_score ----------------

def test_flag_kapali_birebir_siege():
    _set_flag(False)
    g, e_un, e_pr = _graph_with_two_services()
    assert objective_score(e_un, g) == siege_score(e_un, g)
    assert objective_score(e_pr, g) == siege_score(e_pr, g)
    # Kanıtlanmışlık farkı flag kapalıyken sıralamayı DEĞİŞTİRMEZ (base eşit).
    assert abs(objective_score(e_un, g) - objective_score(e_pr, g)) < 1e-9


# ---------------- info_relevance semantiği ----------------

def test_relevance_kanitlanmamis_yuksek():
    _set_flag(False)  # relevance flag'den bağımsız SAF
    g, e_un, e_pr = _graph_with_two_services()
    r_un = info_relevance(e_un, g)
    r_pr = info_relevance(e_pr, g)
    assert r_un > r_pr, (r_un, r_pr)                 # kanıtlanmamış > kanıtlanmış
    assert abs(r_un - 0.8) < 1e-9                    # 1.0 * 1.0 * 0.8
    assert abs(r_pr - 0.35 * 0.8) < 1e-9            # proven_weight * fresh * yield


def test_relevance_tekrar_azalan_getiri():
    _set_flag(False)
    g, e_un, _ = _graph_with_two_services()
    e_un.tried_count = 3
    assert abs(info_relevance(e_un, g) - (1.0 / 4.0) * 0.8) < 1e-9   # freshness=1/(1+3)


# ---------------- Flag AÇIK: yeniden şekillenme ----------------

def test_flag_acik_kanitlanmamis_one_cikar():
    _set_flag(True)
    try:
        g, e_un, e_pr = _graph_with_two_services()
        # base EŞİT ama objective: kanıtlanmamış > kanıtlanmış (bilgi-kazanımı öne çeker).
        assert siege_score(e_un, g) == siege_score(e_pr, g)
        assert objective_score(e_un, g) > objective_score(e_pr, g)
        # Taze-kanıtlanmamış kenar tabanın ÜSTÜNE (factor>1), kanıtlanmış kenar ALTINA (factor<1).
        assert objective_score(e_un, g) > siege_score(e_un, g)
        assert objective_score(e_pr, g) < siege_score(e_pr, g)
    finally:
        _set_flag(False)


def test_flag_acik_tukenmis_kenar_soner():
    _set_flag(True)
    try:
        g, e_un, _ = _graph_with_two_services()
        fresh = objective_score(e_un, g)
        e_un.tried_count = 5                # defalarca denendi → bilgi ~0 → sönmeli
        assert objective_score(e_un, g) < fresh
    finally:
        _set_flag(False)


# ---------------- Doğal durma kriteri ----------------

def test_dogal_durma_kanitlanmamis_varken_durMAZ():
    _set_flag(False)
    g, e_un, e_pr = _graph_with_two_services()
    max_rel = max(info_relevance(e, g) for e in (e_un, e_pr))
    assert max_rel >= INFO_GAIN_MIN                  # taze-kanıtlanmamış var → durmaz


def test_dogal_durma_hepsi_tukenince_durur():
    _set_flag(False)
    g, _, e_pr = _graph_with_two_services()
    # Yalnız kanıtlanmış + çok-denenmiş + düşük-başarı kenarlar kalsın:
    e_pr.tried_count = 5
    e_pr.success_prob = 0.1
    exhausted = [e_pr]
    max_rel = max(info_relevance(e, g) for e in exhausted)
    assert max_rel < INFO_GAIN_MIN, max_rel        # 0.35 * (1/6) * 0.1 ≈ 0.0058 → dur


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
