"""Türkçe: #3 subdomain kapsama — _wp_candidate_hosts testleri (gerçek pipeline metodu, mock yok).

Kök: WP probu/oracle yalnız engine.target'ta çalışıyordu; subfinder'ın bulduğu WP subdomain'leri
(blog.corp.io) hiç yoklanmıyordu. _wp_candidate_hosts grafta WEB işareti taşıyan host'ları
(crawl/nuclei-dast/cve_sweep) kök hedefle birleştirip normalize+dedup eder. pathprobe (iç DB
host'larına da raid eder) KAYNAK ALINMAZ.

Çalıştır: python3 orchestrator/pipeline/test_wp_multihost.py
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.scan_pipeline_v2 import ScanPipelineV2  # noqa: E402


class _Edge:
    def __init__(self, tool, options):
        self.tool = tool
        self.options = options


def _engine(target, edges):
    graph = SimpleNamespace(edges={i: e for i, e in enumerate(edges)})
    return SimpleNamespace(target=target, graph=graph)


def _pipeline():
    # __init__'i atla (DB/servis bağımlılığı yok) — saf metodları test ediyoruz.
    return ScanPipelineV2.__new__(ScanPipelineV2)


def test_candidate_hosts_includes_web_subdomains():
    p = _pipeline()
    edges = [
        _Edge("crawl", {"scan_target": "blog.corp.io"}),
        _Edge("nuclei", {"dast": True, "scan_target": "shop.corp.io"}),
        _Edge("nuclei", {"cve_sweep": True, "scan_target": "corp.io"}),
        _Edge("nmap", {}),                                   # web değil → yok sayılır
        _Edge("pathprobe", {"scan_target": "db.internal"}),  # web kaynağı değil → yok sayılır
    ]
    hosts = p._wp_candidate_hosts(_engine("corp.io", edges))
    assert "corp.io" in hosts           # kök hedef her zaman aday
    assert "blog.corp.io" in hosts      # crawl subdomain
    assert "shop.corp.io" in hosts      # nuclei-dast subdomain
    assert "db.internal" not in hosts   # pathprobe iç host KAYNAK ALINMAZ
    assert hosts.count("corp.io") == 1  # dedup


def test_candidate_hosts_normalizes_scheme():
    p = _pipeline()
    edges = [_Edge("crawl", {"scan_target": "https://blog.corp.io/wp/"})]
    hosts = p._wp_candidate_hosts(_engine("https://corp.io", edges))
    assert "blog.corp.io" in hosts      # şema/port/path soyulur → bare host
    assert "corp.io" in hosts
    assert not any("://" in h for h in hosts)


def test_candidate_hosts_target_only_when_no_web_edges():
    p = _pipeline()
    hosts = p._wp_candidate_hosts(_engine("corp.io", [_Edge("nmap", {})]))
    assert hosts == ["corp.io"]         # web origin yok → yalnız kök


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
