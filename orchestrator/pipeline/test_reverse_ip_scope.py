"""Türkçe: Reverse-IP co-hosted DNS-doğrulama + scope kapısı testleri — SAF; ağ YOK.

Kök (gerçek olay 2026-08-29): hedef IP'ye (203.0.113.10) tarama yapıldı; motor
üçüncü-parti domainlere (neighbor-cf.example → Cloudflare, neighbor-adjacent.example → komşu IP) resilience
probu attı. Sebep: reverse-IP kaynakları bayat/hatalı passive-DNS döndürüyordu ve doğrulama
yoktu + post-observe problar scope kapısını baypas ediyordu.

Testler: (1) partition_cohosted_by_ip yalnız GÜNCEL A kaydı target_ip'ye çözülen domain'i
'verified' sayar; Cloudflare/komşu-IP/çözülemez → 'unverified' (taranmaz). (2) _cohosted_blocked
IP hedefte co-hosted'ı serbest bırakır (sahiplik), domain hedefte onay ister.

Çalıştır: PYTHONPATH=orchestrator python3 orchestrator/pipeline/test_reverse_ip_scope.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.scan_pipeline_v2 import partition_cohosted_by_ip  # noqa: E402


# --- gerçek olayın verisi (DNS'ten teyit edilmiş) ---
TARGET_IP = "203.0.113.10"
RESOLVED = {
    "cdn-admin.example-corp.com": ["203.0.113.10"],       # GERÇEKTEN sunucuda
    "neighbor-cf.example": ["104.21.74.220", "172.67.163.213"],    # Cloudflare — sunucuda DEĞİL
    "example-corp.com": ["172.67.221.139", "104.21.25.10"],  # Cloudflare — DEĞİL
    "neighbor-adjacent.example": ["203.0.113.227"],                      # komşu IP (aynı provider) — DEĞİL
    "neighbor-dead.example": [],                                          # çözülemedi
}


def test_only_same_ip_verified():
    candidates = sorted(RESOLVED.keys())
    verified, unverified = partition_cohosted_by_ip(candidates, TARGET_IP, RESOLVED)
    # Yalnız gerçekten 203.0.113.10'a çözülen kalmalı.
    assert verified == ["cdn-admin.example-corp.com"]
    names = {u["name"] for u in unverified}
    assert names == {"neighbor-cf.example", "example-corp.com",
                     "neighbor-adjacent.example", "neighbor-dead.example"}


def test_cloudflare_domain_never_verified():
    # ŞİKAYETİN ÇEKİRDEĞİ: Cloudflare-fronted domain asla co-hosted sayılmaz.
    v, u = partition_cohosted_by_ip(["neighbor-cf.example"], TARGET_IP, RESOLVED)
    assert v == []
    assert u[0]["name"] == "neighbor-cf.example"
    assert "104.21" in u[0]["resolved"] or "172.67" in u[0]["resolved"]


def test_neighbor_ip_dropped():
    # Komşu IP (203.0.113.227 ≠ .183.110) aynı provider bloğunda bile olsa elenir.
    v, u = partition_cohosted_by_ip(["neighbor-adjacent.example"], TARGET_IP, RESOLVED)
    assert v == [] and u[0]["resolved"] == "203.0.113.227"


def test_unresolved_and_missing_are_unverified():
    # Hiç çözülmeyen (boş) VE haritada olmayan (cap üstü senaryosu) → güvenli tarafta unverified.
    v, u = partition_cohosted_by_ip(["neighbor-dead.example", "capustu.example"], TARGET_IP, RESOLVED)
    assert v == []
    reasons = {x["name"]: x["resolved"] for x in u}
    assert reasons["neighbor-dead.example"] == "çözülemedi"
    assert reasons["capustu.example"] == "çözülemedi"  # resolved'da yok → doğrulanmadı


def test_empty_candidates():
    assert partition_cohosted_by_ip([], TARGET_IP, {}) == ([], [])


def test_cohosted_blocked_ip_vs_domain_target():
    # _cohosted_blocked: IP hedefte co-hosted serbest (sahiplik), domain hedefte onay ister.
    from pipeline.autonomous_engine import AutonomousEngine, COHOSTED_NODE_PREFIX

    class FakeEdge:
        def __init__(self, to_id): self.to_id = to_id

    cohosted_edge = FakeEdge(f"{COHOSTED_NODE_PREFIX}cdn-admin.example-corp.com")

    # IP hedef → strict scope olsa bile co-hosted (doğrulanmış same-IP) taranabilir.
    eng_ip = AutonomousEngine("s1", "203.0.113.10", target_is_ip=True)
    eng_ip.scope = "strict"
    assert eng_ip._cohosted_blocked(cohosted_edge) is False

    # Domain hedef → strict scope'ta co-hosted ONAY ister (paylaşımlı-hosting riski).
    eng_dom = AutonomousEngine("s2", "example.com", target_is_ip=False)
    eng_dom.scope = "strict"
    assert eng_dom._cohosted_blocked(cohosted_edge) is True
    # Onaylanınca engel kalkar.
    eng_dom._approved_cohosted.add(cohosted_edge.to_id)
    assert eng_dom._cohosted_blocked(cohosted_edge) is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
