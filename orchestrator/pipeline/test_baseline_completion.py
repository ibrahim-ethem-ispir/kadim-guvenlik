"""Türkçe: A2 — Garantili yürütme (baseline completion) testleri — SAF; ağ YOK.

Kök: whack-a-mole — bir sınıfı derinleştirirken (PHP/DAST) 40-adım bütçe orada yanınca başka
bir taban sınıfı (JS/.env/crawl) sessizce hiç koşmadan düşüyordu. A2: yaratıcı bütçe dolsa bile
taban RAID edge'leri (pathprobe/crawl) BOUNDED ek bütçeyle garanti koşar. Testler budget_left
ve _pending_baseline_edges'in tam davranışını (scope + seviye + tavan + tried) doğrular.

Çalıştır: PYTHONPATH=orchestrator python3 orchestrator/pipeline/test_baseline_completion.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.autonomous_engine import (  # noqa: E402
    AutonomousEngine, BASELINE_EXTRA_STEPS, COHOSTED_NODE_PREFIX,
)
from pipeline.attack_graph import Edge  # noqa: E402


def _eng(target="203.0.113.10", target_is_ip=True, level="standard"):
    return AutonomousEngine("s", target, target_is_ip=target_is_ip, level=level)


def _raid_edge(to_id="host:example.com", tool="pathprobe", tried=0, state="open"):
    return Edge(from_id="root", to_id=to_id, tool=tool, meta={"raid": True},
                tried_count=tried, state=state)


def test_normal_creative_budget():
    e = _eng()
    e.step = 0
    assert e.budget_left() is True
    e.step = 39  # < max_steps(40)
    assert e.budget_left() is True


def test_exhausted_without_baseline_stops():
    # Yaratıcı bütçe doldu, koşmamış taban edge'i YOK → dur (eski davranış korunur).
    e = _eng()
    e.step = e.level.max_steps  # 40
    assert e.budget_left() is False


def test_exhausted_with_pending_baseline_grants_extra():
    # Yaratıcı bütçe doldu AMA koşmamış taban (pathprobe) edge'i var → ek bütçe verilir.
    e = _eng()
    e.graph.edges["b1"] = _raid_edge(tool="pathprobe")
    e.step = e.level.max_steps
    assert e.budget_left() is True
    assert len(e._pending_baseline_edges()) == 1


def test_already_run_baseline_no_extra():
    # Taban edge KOŞMUŞSA (tried_count>0) ek bütçe yok.
    e = _eng()
    e.graph.edges["b1"] = _raid_edge(tool="pathprobe", tried=1)
    e.step = e.level.max_steps
    assert e._pending_baseline_edges() == []
    assert e.budget_left() is False


def test_non_raid_edge_not_baseline():
    # RAID işareti olmayan edge taban SAYILMAZ (yaratıcı keşif ek bütçe almaz).
    e = _eng()
    e.graph.edges["c1"] = Edge(from_id="root", to_id="host:x", tool="nuclei", meta={})
    e.step = e.level.max_steps
    assert e._pending_baseline_edges() == []
    assert e.budget_left() is False


def test_extra_steps_cap():
    # Ek bütçe TAVANI aşılınca dur (sonsuz döngü koruması).
    e = _eng()
    e.graph.edges["b1"] = _raid_edge(tool="pathprobe")
    e.step = e.level.max_steps + BASELINE_EXTRA_STEPS
    assert e.budget_left() is False


def test_cancelled_stops_even_with_baseline():
    e = _eng()
    e.graph.edges["b1"] = _raid_edge(tool="pathprobe")
    e.step = e.level.max_steps
    e.cancel()
    assert e.budget_left() is False


def test_cohosted_blocked_baseline_excluded_domain_target():
    # Domain hedef + strict scope: onaysız co-hosted taban edge'i floor'a GİRMEZ (scope güvenli).
    e = _eng(target="example.com", target_is_ip=False)
    e.scope = "strict"
    e.graph.edges["b1"] = _raid_edge(to_id=f"{COHOSTED_NODE_PREFIX}neighbor-cf.example", tool="crawl")
    e.step = e.level.max_steps
    assert e._pending_baseline_edges() == []
    assert e.budget_left() is False
    # Onaylanınca floor'a girer.
    e._approved_cohosted.add(f"{COHOSTED_NODE_PREFIX}neighbor-cf.example")
    assert len(e._pending_baseline_edges()) == 1


def test_cohosted_baseline_allowed_ip_target():
    # IP hedef: doğrulanmış co-hosted vhost taban edge'i floor'a GİRER (sahiplik).
    e = _eng(target="203.0.113.10", target_is_ip=True)
    e.scope = "strict"
    e.graph.edges["b1"] = _raid_edge(to_id=f"{COHOSTED_NODE_PREFIX}cdn-admin.example-corp.com",
                                     tool="crawl")
    assert len(e._pending_baseline_edges()) == 1


def test_recon_level_excludes_active_baseline():
    # Keşif seviyesi: crawl/pathprobe seviye-izinli DEĞİL → floor'a girmez (pasif-only korunur).
    e = _eng(level="recon")
    e.graph.edges["b1"] = _raid_edge(tool="crawl")
    e.graph.edges["b2"] = _raid_edge(tool="pathprobe")
    assert e._pending_baseline_edges() == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
