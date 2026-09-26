"""
Kadim Güvenlik — A.1 geçici-hata kenar toleransı testleri.

update_probabilities(success=False) bir kenarı ARTIK tek hatada kalıcı öldürmemeli:
deneme tavanına (EDGE_MAX_RETRIES) kadar 'open' + yeniden-denenebilir kalmalı; tavan
dolunca kalıcı kapanmalı (executed_signatures + novelty=0). Başarı yolu değişmez.
Bu, yük altında geçici timeout'un saldırı yolunu sessizce terk etmesini (tespit kaybı)
önler. Düz script (pytest yok).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.attack_graph import Graph, Edge, EDGE_MAX_RETRIES, BETA_PRIOR_STRENGTH  # noqa: E402


def _graph_with_edge():
    g = Graph(target="1.2.3.4", target_is_ip=True)
    e = Edge(from_id=g.root_id, to_id=g.root_id, tool="nuclei",
             options={"tags": ["nginx"]}, cost=20, success_prob=0.8)
    g.add_edge(e)
    return g, e


def test_transient_failure_keeps_edge_open():
    """İlk hata (tavan=2 iken): kenar açık kalır, executed_signatures'a girmez, novelty>0."""
    g, e = _graph_with_edge()
    sp_before = e.success_prob
    g.update_probabilities(e, success=False, evidence_found=False)
    assert e.tried_count == 1
    assert e.state == "open", f"kenar kapandı: {e.state}"
    assert e.signature() not in g.executed_signatures, "kenar kalıcı işaretlendi"
    assert e.novelty > 0.0, "novelty sıfırlandı (skor ölür)"
    # C1: backoff artık beta-posterior (ad-hoc yarılama DEĞİL). İlk hata sonrası
    # success_prob = α/(α+β), α=p·K, β=(1-p)·K+1 (K=BETA_PRIOR_STRENGTH).
    a0 = sp_before * BETA_PRIOR_STRENGTH
    b0 = (1.0 - sp_before) * BETA_PRIOR_STRENGTH + 1.0
    expected = max(0.01, a0 / (a0 + b0))
    assert abs(e.success_prob - expected) < 1e-9, (e.success_prob, expected)
    assert e.success_prob < sp_before, "backoff yok (success_prob düşmedi)"
    assert e.success_prob > max(0.01, sp_before * 0.5), "beta yarılamadan daha yumuşak olmalı"
    print("[OK] test_transient_failure_keeps_edge_open")


def test_failure_reaches_cap_closes_permanently():
    """EDGE_MAX_RETRIES hataya ulaşınca kenar kalıcı kapanır (döngü yok)."""
    g, e = _graph_with_edge()
    for _ in range(EDGE_MAX_RETRIES):
        g.update_probabilities(e, success=False, evidence_found=False)
    assert e.tried_count == EDGE_MAX_RETRIES
    assert e.state == "executed", f"tavanda kapanmadı: {e.state}"
    assert e.signature() in g.executed_signatures, "tavanda kalıcı işaretlenmedi"
    assert e.novelty == 0.0
    print("[OK] test_failure_reaches_cap_closes_permanently")


def test_success_closes_immediately():
    """Başarı yolu DEĞİŞMEZ: başarılı kenar hemen kalıcı kapanır (tekrar taranmaz)."""
    g, e = _graph_with_edge()
    g.update_probabilities(e, success=True, evidence_found=False)
    assert e.state == "executed"
    assert e.signature() in g.executed_signatures
    assert e.novelty == 0.0
    print("[OK] test_success_closes_immediately")


def test_beta_backoff_monotonic_and_gentler_than_halving():
    """C1: tekrarlanan hatada success_prob beta-posterior ile MONOTON düşer, 0.01 tabanına
    saplanmaz ve her adımda eski yarılamadan (p·0.5^k) daha yumuşaktır (kanıt-temelli çürüme)."""
    g = Graph(target="1.2.3.4", target_is_ip=True)
    e = Edge(from_id=g.root_id, to_id=g.root_id, tool="nuclei",
             options={"tags": ["x"]}, cost=20, success_prob=0.8)
    g.add_edge(e)
    p0 = e.success_prob
    prev = p0
    halving = p0
    # Tavan davranışını bu testte kapatıp yalnız çürüme matematiğini izole edelim.
    import pipeline.attack_graph as ag
    old_cap = ag.EDGE_MAX_RETRIES
    ag.EDGE_MAX_RETRIES = 999
    try:
        for _ in range(4):
            g.update_probabilities(e, success=False, evidence_found=False)
            halving = max(0.01, halving * 0.5)
            assert e.success_prob < prev, "beta çürümesi monoton azalmıyor"
            assert e.success_prob >= 0.01, "taban altına düştü"
            assert e.success_prob > halving, (e.success_prob, halving)  # yarılamadan yumuşak
            prev = e.success_prob
    finally:
        ag.EDGE_MAX_RETRIES = old_cap
    print("[OK] test_beta_backoff_monotonic_and_gentler_than_halving")


def test_open_after_transient_is_reselectable_by_frontier():
    """Geçici hatadan sonra kenar expand_frontier tarafından TEKRAR döndürülebilir olmalı;
    tavan dolunca artık döndürülmemeli."""
    g, e = _graph_with_edge()
    g.update_probabilities(e, success=False, evidence_found=False)  # 1. hata → açık
    sigs_open = {ed.signature() for ed in g.expand_frontier()}
    assert e.signature() in sigs_open, "geçici hatadan sonra kenar frontier'da yok (retry imkânsız)"
    # tavana kadar hata ver → kapanmalı
    while e.tried_count < EDGE_MAX_RETRIES:
        g.update_probabilities(e, success=False, evidence_found=False)
    sigs_closed = {ed.signature() for ed in g.expand_frontier()}
    assert e.signature() not in sigs_closed, "tavan dolunca kenar hâlâ frontier'da (sonsuz döngü)"
    print("[OK] test_open_after_transient_is_reselectable_by_frontier")


if __name__ == "__main__":
    print(f"(EDGE_MAX_RETRIES={EDGE_MAX_RETRIES})")
    test_transient_failure_keeps_edge_open()
    test_failure_reaches_cap_closes_permanently()
    test_success_closes_immediately()
    test_beta_backoff_monotonic_and_gentler_than_halving()
    test_open_after_transient_is_reselectable_by_frontier()
    print("\nTüm testler geçti.")
