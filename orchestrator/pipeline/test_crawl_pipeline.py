"""Faz 1 — endpoint keşfi (crawl) integrate testi.

Crawl çıktısının grafta doğru ENDPOINT node'larına + nuclei DAST kenarına çevrilmesini
dogrular. "Standart zafiyeti 1 tık buluyoruz" tavanının kapandigi noktadir.

Çalistir: python3 -m pipeline.test_crawl_pipeline
"""
import asyncio
from pipeline.attack_graph import Graph, NodeType, NodeState, EDGE_COST_TABLE, siege_score, THRESHOLD


def _crawl_result(*, urls, param_endpoints=None, target="example.com"):
    return {
        "target": target,
        "base_url": f"https://{target}",
        "discovered_urls": urls,
        "discovered_count": len(urls),
        "parameterized_endpoints": param_endpoints or [],
        "parameterized_count": len(param_endpoints or []),
        "forms": [],
        "forms_count": 0,
        "js_assets": [],
        "js_assets_count": 0,
        "elapsed_seconds": 1.0,
        "partial": False,
        "note": None,
    }


def test_crawl_creates_endpoint_nodes_per_url():
    g = Graph(target="example.com", target_is_ip=False)
    class _D: options = {}
    new_nodes = g.integrate(_D(), _crawl_result(urls=[
        "https://example.com/",
        "https://example.com/admin",
        "https://example.com/api/users",
        "https://example.com/login?next=/home",
    ]), "crawl")
    ep_nodes = [n for n in new_nodes if n.type == NodeType.ENDPOINT]
    assert len(ep_nodes) == 4, f"4 endpoint bekleniyordu, {len(ep_nodes)} oldu"
    # admin/api/login desenleri yüksek değer almalı (NODE_VALUE_TABLE)
    admin = next(n for n in ep_nodes if "admin" in n.label)
    assert admin.value > 10, f"admin endpoint düşük değerli: {admin.value}"
    # Parametreli endpoint breach olasılığı yüksek tutuldu
    login = next(n for n in ep_nodes if "login" in n.label)
    assert login.breach_prob > 0.1, f"parametreli endpoint düşük breach_prob: {login.breach_prob}"
    # root meta endpoints listesi doldu
    assert "https://example.com/login?next=/home" in g.nodes[g.root_id].meta["endpoints"]
    print("[OK] test_crawl_creates_endpoint_nodes_per_url")


def test_crawl_seeds_nuclei_dast_edge_with_urls_when_parameterized():
    g = Graph(target="example.com", target_is_ip=False)
    class _D: options = {}
    p_eps = [
        {"url": "https://example.com/api/v2/transfer?amount=1", "params": ["amount"]},
        {"url": "https://example.com/admin/users?id=5", "params": ["id"]},
        {"url": "https://example.com/search?q=test", "params": ["q"]},
    ]
    g.integrate(_D(), _crawl_result(urls=[pe["url"] for pe in p_eps],
                                    param_endpoints=p_eps), "crawl")
    dast_edges = [e for e in g.edges.values()
                  if e.tool == "nuclei" and e.options.get("dast") and e.options.get("urls")]
    assert len(dast_edges) == 1, f"tek DAST kenarı bekleniyordu, {len(dast_edges)} oldu"
    urls = dast_edges[0].options["urls"]
    # DAST kenarı url'leri parametreli endpoint listesinden beslenir
    assert "https://example.com/api/v2/transfer?amount=1" in urls
    assert len(urls) <= 100
    # Maliyet nuclei-dast tablosundan gelir
    assert dast_edges[0].cost == EDGE_COST_TABLE["nuclei-dast"]
    print("[OK] test_crawl_seeds_nuclei_dast_edge_with_urls_when_parameterized")


def test_crawl_no_parameterized_endpoints_no_dast_edge():
    g = Graph(target="example.com", target_is_ip=False)
    class _D: options = {}
    g.integrate(_D(), _crawl_result(urls=[
        "https://example.com/about",
        "https://example.com/contact",
    ]), "crawl")
    dast_edges = [e for e in g.edges.values()
                  if e.tool == "nuclei" and e.options.get("dast")]
    assert len(dast_edges) == 0, "parametresiz crawl DAST kenari doğurmamalı"
    print("[OK] test_crawl_no_parameterized_endpoints_no_dast_edge")


def test_crawl_dedup_existing_endpoint_node():
    # Aynı URL iki crawl turunda gelirse node tekrar yaratılmaz (add_node merge'ler).
    g = Graph(target="example.com", target_is_ip=False)
    class _D: options = {}
    url = "https://example.com/admin"
    g.integrate(_D(), _crawl_result(urls=[url]), "crawl")
    new_second = g.integrate(_D(), _crawl_result(urls=[url]), "crawl")
    ep = g.nodes.get(f"endpoint:{url}")
    assert ep is not None and ep.type == NodeType.ENDPOINT
    # İkinci turda yeni node doğmaz (merge; existing döner)
    assert all(n.id != f"endpoint:{url}" or n is ep for n in new_second)
    print("[OK] test_crawl_dedup_existing_endpoint_node")


def test_recon_seeds_crawl_edge_on_root_when_web_tech_detected():
    # Türkçe: recon web teknolojisi tespit edince kök host'a crawl edge'i doğar (root
    # NodeType.TARGET olduğu için raid-loop'onun crawl seed'i yapmazdı — bu kök seed
    # bizzat recon dalında veriliyor).
    g = Graph(target="example.com", target_is_ip=False)
    class _D: options = {}
    g.integrate(_D(), {
        "technologies": ["nginx", "Laravel 10"],
        "is_behind_cdn": False, "real_ips": [],
        "subdomains": [],
    }, "recon")
    crawl_edges = [e for e in g.edges.values() if e.tool == "crawl"]
    assert len(crawl_edges) >= 1, "recon web tespitinde crawl edge seed edilmeli"
    # Üstelik kök düzeyde
    assert any(e.from_id == g.root_id and e.to_id == g.root_id for e in crawl_edges)
    print("[OK] test_recon_seeds_crawl_edge_on_root_when_web_tech_detected")


def test_crawl_dast_edge_score_above_threshold():
    """DAST kenarı kök ROOT'a değil en yüksek-değerli ENDPOINT'e bağlanmalı — aksi halde
    siege_score eşiğin altında kalır ve motor DAST'i hiç seçmez (URL corpus kör kalır)."""
    g = Graph(target="example.com", target_is_ip=False)
    class _D: options = {}
    p_eps = [
        {"url": "https://example.com/admin/users?id=5", "params": ["id"]},
        {"url": "https://example.com/api/v2/transfer?amount=1", "params": ["amount"]},
    ]
    g.integrate(_D(), _crawl_result(
        urls=[pe["url"] for pe in p_eps], param_endpoints=p_eps,
    ), "crawl")
    dast_edges = [e for e in g.edges.values()
                  if e.tool == "nuclei" and e.options.get("dast")]
    assert len(dast_edges) == 1
    e = dast_edges[0]
    # to_id ROOT değil ENDPOINT olmalı
    assert e.to_id != g.root_id, "DAST kenarı kök'e bağlı kalmış — skor düşük olur"
    from pipeline.attack_graph import siege_score, THRESHOLD
    assert siege_score(e, g) >= THRESHOLD, f"DAST skor {siege_score(e, g):.3f} < {THRESHOLD}"
    print("[OK] test_crawl_dast_edge_score_above_threshold")


def test_crawl_permitted_from_standard_level():
    """Türkçe: crawl artık STANDART seviyeden itibaren İZİNLİ (allow_crawl) — uygulama-katmanı
    keşfi standart taramanın parçasıdır. Eski regresyon endişesi (crawl'ın pathprobe ifşa
    raid'ini bütçe/WAF yoluyla ezmesi) KAPASİTE kapısıyla değil, SIRALAMAYLA çözülür:
    pathprobe raid urgency=2.5 ile skorlamada her zaman crawl'dan önce gelir (ayrı test:
    test_crawl_raid_score_lower_than_pathprobe_raid bunu pinler). Bu test seviye izinlerini
    doğrular: Keşif=kapalı, Standart/Derin=açık; pathprobe her seviyede korunur."""
    from pipeline.autonomous_engine import (
        PASSIVE_DISCOVERY_TOOLS, ACTIVE_TOOLS, resolve_level,
    )
    # crawl ACTIVE'de olmalı (aktif-tier: GET ile sayfa çeker) ama pasif keşif tierında DEĞİL
    assert "crawl" in ACTIVE_TOOLS, "crawl aktif tierda olmalı"
    assert "crawl" not in PASSIVE_DISCOVERY_TOOLS, "crawl pasif tierda regression riski"
    # Keşif (pasif harita): crawl KAPALI — yalnız pasif keşif araçları.
    recon = resolve_level("recon")
    assert recon.tool_permitted("crawl") is False, "keşif seviyesinde crawl açık olmamalı"
    # Standart: crawl + DAST AÇIK (uygulama-katmanı değeri), yalnız dizin fuzz kapalı.
    std = resolve_level("standard")
    assert std.tool_permitted("crawl") is True, "standart seviyede crawl açık olmalı"
    assert std.allow_dast is True, "standart seviyede DAST açık olmalı"
    assert std.allow_fuzz is False, "standart seviyede dizin fuzz kapalı olmalı"
    assert std.tool_permitted("pathprobe") is True  # ifşa raid'i her seviyede korunur
    assert std.tool_permitted("fuzz") is False       # ağır dizin fuzz yalnız Derin'de
    # Derin: her şey açık (Faz 1 tam gücü + geniş cve süpürmesi).
    deep = resolve_level("deep")
    assert deep.tool_permitted("crawl") is True
    assert deep.tool_permitted("fuzz") is True
    assert deep.allow_fuzz is True
    print("[OK] test_crawl_permitted_from_standard_level")


def test_crawl_raid_score_lower_than_pathprobe_raid():
    """Aynı host için crawl raid siege_score < pathprobe raid — pathprobe her zaman ÖNCE
    seçilir. Bu sıralama crawl herhangi bir host'ta pathprobe'u ezip ifşa kaybına yol
    açmasın diye garanti."""
    g = Graph(target="bank.example.com", target_is_ip=False)
    class _D: options = {}
    g.integrate(_D(), {"domains": [{"name": "app.bank.example.com"}],
                      "source": "reverse_ip"}, "reverse_ip")
    pp_scores = [siege_score(e, g) for e in g.edges.values() if e.tool == "pathprobe"]
    cr_scores = [siege_score(e, g) for e in g.edges.values() if e.tool == "crawl"]
    assert pp_scores and max(pp_scores) > max(cr_scores) if cr_scores else True, (
        f"pathprobe {pp_scores} > crawl {cr_scores} değil"
    )
    for pp in pp_scores:
        assert pp >= 1.0, f"pathprobe raid çok düşük skor: {pp}"
    print("[OK] test_crawl_raid_score_lower_than_pathprobe_raid")


def test_host_raid_loop_seeds_crawl_edge_for_non_boilerplate_host():
    # Türkçe: reverse_ip ile yeni bir co-hosted host doğunca hem pathprobe hem crawl
    # raid'i seed edilmeli (cPanel varsayılan kayıtları hariç).
    g = Graph(target="example.com", target_is_ip=False)
    class _D: options = {}
    g.integrate(_D(), {
        "domains": [{"name": "blog-neighbor.com"}, {"name": "webdisk.blog-neighbor.com"}],
        "source": "reverse_ip",
    }, "reverse_ip")
    crawl_edges = [e for e in g.edges.values() if e.tool == "crawl"]
    # blog-neighbor.com için crawl raid var; webdisk (boilerplate) için yok
    blog_crawl = [e for e in crawl_edges if "blog-neighbor" in e.from_id]
    webdisk_crawl = [e for e in crawl_edges if "webdisk" in e.from_id]
    assert len(blog_crawl) >= 1, "non-boilerplate host crawl raid almalı"
    assert len(webdisk_crawl) == 0, "boilerplate host crawl raid almamalı"
    print("[OK] test_host_raid_loop_seeds_crawl_edge_for_non_boilerplate_host")


if __name__ == "__main__":
    test_crawl_creates_endpoint_nodes_per_url()
    test_crawl_seeds_nuclei_dast_edge_with_urls_when_parameterized()
    test_crawl_no_parameterized_endpoints_no_dast_edge()
    test_crawl_dedup_existing_endpoint_node()
    test_crawl_dast_edge_score_above_threshold()
    test_crawl_permitted_from_standard_level()
    test_crawl_raid_score_lower_than_pathprobe_raid()
    test_recon_seeds_crawl_edge_on_root_when_web_tech_detected()
    test_host_raid_loop_seeds_crawl_edge_for_non_boilerplate_host()
    print("Tüm testler geçti.")