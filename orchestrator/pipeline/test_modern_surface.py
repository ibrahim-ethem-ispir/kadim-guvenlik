"""Türkçe: MODERN YÜZEY (L1) + KEŞİF/MERAK (L2) testleri — SAF; ağ YOK.

Kök sorun: motor yalnız klasik `?param=` yüzeyini "değerli" sayıyor; modern kurumsal
hedeflerin yüzeyi (path-param REST/IDOR, API rotaları, JSON/GraphQL) "değersiz statik"
damgalanıp HİÇ aktif test edilmiyordu → "standart açık yoksa işe yaramıyor". Bu testler:
  L1a) endpoint_discovery._injection_kind sınıflandırıcısı (query/path-param/api-route).
  L1b) attack_graph crawl-integrate → endpoint node değer/breach + DAST kenarı eşik üstü.
  L2)  siege_score keşif/merak çarpanı taze injectable endpoint'i eşiğin üstüne taşır ama
       SERVICE/CVE düğümlerini ve mevcut skor-sıralama değişmezlerini ETKİLEMEZ.

Çalıştır: python3 orchestrator/pipeline/test_modern_surface.py
"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.endpoint_discovery import (  # noqa: E402
    _injection_kind, _has_path_id, _API_ROUTE_RE,
)
from pipeline import attack_graph  # noqa: E402
from pipeline.attack_graph import (  # noqa: E402
    Graph, Node, NodeType, NodeState, Edge, siege_score, THRESHOLD,
    NODE_VALUE_TABLE, EDGE_COST_TABLE, _INJECTION_BREACH_BY_KIND,
)

EDGE_COST_TABLE_DAST = EDGE_COST_TABLE["nuclei-dast"]  # test okunabilirliği için


# ============================================================
# L1a — sınıflandırıcı (SAF)
# ============================================================
def test_injection_kind_query():
    assert _injection_kind("https://x.com/search?q=1") == "query"
    assert _injection_kind("https://x.com/report?file=a.pdf&id=3") == "query"


def test_injection_kind_path_param_idor():
    # Sayısal id: /users/123 → path-param (IDOR/BOLA yüzeyi)
    assert _injection_kind("https://x.com/users/123") == "path-param"
    # UUID nesne referansı
    assert _injection_kind(
        "https://x.com/accounts/550e8400-e29b-41d4-a716-446655440000/tx") == "path-param"
    # Uzun hex/hash
    assert _injection_kind("https://x.com/orders/9f8e7d6c5b4a3f21") == "path-param"
    # path-param, api-route'tan ÖNCE gelmeli (daha spesifik/değerli): /api/users/7
    assert _injection_kind("https://x.com/api/users/7") == "path-param"


def test_injection_kind_api_route():
    assert _injection_kind("https://x.com/api/orders") == "api-route"
    assert _injection_kind("https://x.com/graphql") == "api-route"
    assert _injection_kind("https://x.com/gql") == "api-route"
    assert _injection_kind("https://x.com/v2/products") == "api-route"  # versiyonlu API
    assert _injection_kind("https://x.com/rest/catalog") == "api-route"


def test_injection_kind_none_and_fp_guards():
    # Statik/anlamsız yol → None (aktif test hedefi değil)
    assert _injection_kind("https://x.com/about") is None
    assert _injection_kind("https://x.com/contact/") is None
    # Yıl-önekli yol yanlış-pozitif OLMAMALI: /2024/report → None (id İLK segment olamaz,
    # kendinden önce harf içeren 'kaynak' segmenti şart)
    assert _injection_kind("https://x.com/2024/report") is None
    assert _has_path_id("/2024/report") is False
    # Versiyon segmenti (v2) sayısal-id desenine takılmaz
    assert _has_path_id("/api/v2/list") is False
    assert bool(_API_ROUTE_RE.search("/api/v2/list")) is True


# ============================================================
# L1b — graf değerleme + DAST kenarı eşik üstü
# ============================================================
def _crawl_result(discovered, injectable):
    """injectable: [(url, kind)]. discovered: [url]."""
    by_kind = {k: sum(1 for _, kk in injectable if kk == k)
               for k in ("query", "path-param", "api-route")}
    return {
        "discovered_urls": discovered,
        "parameterized_endpoints": [{"url": u, "kind": k, "params": []}
                                    for (u, k) in injectable],
        "injectable_by_kind": by_kind,
    }


def _integrate_crawl(result):
    g = Graph(target="app.example.com", target_is_ip=False)
    decision = SimpleNamespace(options={})
    g.integrate(decision, result, "crawl")
    return g


def test_modern_endpoints_are_valued_injection_targets():
    g = _integrate_crawl(_crawl_result(
        discovered=[
            "https://app.example.com/about",              # statik → değersiz
            "https://app.example.com/users/123",          # path-param IDOR
            "https://app.example.com/graphql",            # api-route (JSON/GraphQL)
            "https://app.example.com/search?q=x",         # query
        ],
        injectable=[
            ("https://app.example.com/users/123", "path-param"),
            ("https://app.example.com/graphql", "api-route"),
            ("https://app.example.com/search?q=x", "query"),
        ],
    ))
    nodes = {n.label: n for n in g.nodes.values() if n.type == NodeType.ENDPOINT}

    # Statik: düşük değer + düşük breach (eski davranış korunur)
    st = nodes["https://app.example.com/about"]
    assert st.value == NODE_VALUE_TABLE["static"] and st.breach_prob == 0.08

    # path-param / query: yüksek breach (0.25) + değer TABANI ≥ api(55) → eşik geçer
    idor = nodes["https://app.example.com/users/123"]
    assert idor.breach_prob == _INJECTION_BREACH_BY_KIND["path-param"]
    assert idor.value >= NODE_VALUE_TABLE["api"]
    assert idor.meta.get("injectable") == "path-param"

    # api-route (parametresiz /graphql): eskiden value=static(10) breach=0.08 idi → artık
    # breach 0.18 + değer tabanı 55. Bu, "SPA/JSON API yüzeyi kör" boşluğunun tam kapanışı.
    gq = nodes["https://app.example.com/graphql"]
    assert gq.breach_prob == _INJECTION_BREACH_BY_KIND["api-route"]
    assert gq.value >= NODE_VALUE_TABLE["api"]


def test_dast_edge_seeded_and_clears_threshold():
    g = _integrate_crawl(_crawl_result(
        discovered=["https://app.example.com/api/users/42",
                    "https://app.example.com/graphql"],
        injectable=[("https://app.example.com/api/users/42", "path-param"),
                    ("https://app.example.com/graphql", "api-route")],
    ))
    dast_edges = [e for e in g.edges.values()
                  if e.tool == "nuclei" and e.options.get("dast")]
    assert len(dast_edges) == 1, "tek DAST corpus kenarı seed edilmeli"
    dast = dast_edges[0]
    # Kenar, kendi skorunu en çoklayan (value×breach) injectable endpoint'e bağlanmalı
    to_node = g.nodes[dast.to_id]
    assert to_node.type == NodeType.ENDPOINT and to_node.meta.get("injectable")
    # ASIL İDDİA: motor bu kenarı SEÇEBİLMELİ (skor ≥ eşik). Eski dünyada api-only yüzeyde
    # bu skor eşik altında kalıp DAST HİÇ seçilmiyordu.
    assert siege_score(dast, g) >= THRESHOLD, (
        f"DAST skoru {siege_score(dast, g):.3f} < eşik {THRESHOLD}")


def test_pure_api_surface_no_query_still_active():
    """Regresyon güvencesi: HİÇ query-string olmayan saf API/SPA yüzeyi. Eski motor burada
    param_endpoints boş → DAST kenarı YOK → 'denenecek adım yok' → dururdu. Artık api-route
    hedefleri var → DAST seed edilir ve eşiği geçer."""
    g = _integrate_crawl(_crawl_result(
        discovered=["https://app.example.com/api/orders",
                    "https://app.example.com/api/invoices",
                    "https://app.example.com/graphql"],
        injectable=[("https://app.example.com/api/orders", "api-route"),
                    ("https://app.example.com/api/invoices", "api-route"),
                    ("https://app.example.com/graphql", "api-route")],
    ))
    dast_edges = [e for e in g.edges.values()
                  if e.tool == "nuclei" and e.options.get("dast")]
    assert len(dast_edges) == 1
    assert siege_score(dast_edges[0], g) >= THRESHOLD


# ============================================================
# L2 — keşif/merak çarpanı
# ============================================================
def test_curiosity_lifts_fresh_injectable_endpoint():
    g = Graph(target="app.example.com", target_is_ip=False)
    ep = g.add_node(Node(id="endpoint:e", type=NodeType.ENDPOINT, label="/api/x",
                         value=NODE_VALUE_TABLE["api"], breach_prob=0.18,
                         state=NodeState.DISCOVERED, meta={"injectable": "api-route"}))
    edge = Edge(from_id=g.root_id, to_id=ep.id, tool="nuclei",
                options={"dast": True}, cost=EDGE_COST_TABLE_DAST, success_prob=0.55,
                urgency=1.3)
    g.add_edge(edge)
    score_fresh = siege_score(edge, g)

    # Denendikten sonra merak bonusu düşer (tek seferlik "ilk bak")
    edge.tried_count = 1
    score_tried = siege_score(edge, g)
    assert score_fresh > score_tried, "merak bonusu yalnız denenmemiş kenara uygulanmalı"


def test_curiosity_does_not_touch_service_nodes():
    """Değişmez: keşif/merak çarpanı SERVICE/CVE düğümlerine DOKUNMAZ (mevcut ekonomi/skor
    testleri korunur). Aynı value/breach ile SERVICE node → çarpan 1.0."""
    g = Graph(target="1.2.3.4", target_is_ip=True)
    svc = g.add_node(Node(id="svc:x", type=NodeType.SERVICE, label="x",
                          value=NODE_VALUE_TABLE["api"], breach_prob=0.18,
                          state=NodeState.DISCOVERED, meta={"injectable": "api-route"}))
    e_svc = Edge(from_id=g.root_id, to_id=svc.id, tool="nuclei",
                 cost=EDGE_COST_TABLE_DAST, success_prob=0.55, urgency=1.3)
    g.add_edge(e_svc)
    # Beklenen: merak yok → base skoru. Aynı parametreli ENDPOINT'te ise merak var.
    ep = g.add_node(Node(id="endpoint:x", type=NodeType.ENDPOINT, label="/api/x",
                         value=NODE_VALUE_TABLE["api"], breach_prob=0.18,
                         state=NodeState.DISCOVERED, meta={"injectable": "api-route"}))
    e_ep = Edge(from_id=g.root_id, to_id=ep.id, tool="nuclei",
                cost=EDGE_COST_TABLE_DAST, success_prob=0.55, urgency=1.3)
    g.add_edge(e_ep)
    assert siege_score(e_ep, g) > siege_score(e_svc, g), (
        "merak yalnız ENDPOINT'e uygulanmalı — SERVICE düğümü etkilenmemeli")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
