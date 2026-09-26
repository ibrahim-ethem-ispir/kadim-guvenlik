"""Türkçe: WordPress probu (wp_probe) testleri — classify/parse çekirdeği SAF; probe_wordpress
sahte-sunucuyla deterministik (ağ YOK).

Kök: güncel CVE'lerin çoğu WP ekseninde; WP saldırı yüzeyi deterministiktir (nuclei beklemeden
yoklanır). KRİTİK: WP olmayan hedefte prob HİÇ bulgu üretmemeli (çift-kapı) — ayrı test.

Çalıştır: python3 orchestrator/pipeline/test_wp_probe.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.wp_probe import (  # noqa: E402
    extract_core_version, is_wordpress, parse_assets, parse_readme_stable_tag,
    parse_wp_json, idor_candidates_from_routes, _route_to_probe_url,
    classify_rest_users, classify_author_redirect, classify_xmlrpc, validate_debug_log,
    probe_wordpress,
)


# ============================================================
# SAF çekirdek testleri (ağ yok)
# ============================================================

def test_extract_core_version():
    assert extract_core_version('<meta name="generator" content="WordPress 6.4.2" />') == "6.4.2"
    assert extract_core_version('<script src="/wp-includes/js/wp-emoji.min.js?ver=6.3.1">') == "6.3.1"
    assert extract_core_version("<html>no wp here</html>") is None


def test_is_wordpress():
    ok, ev = is_wordpress(body='<link href="/wp-content/themes/x/style.css">')
    assert ok and ev
    ok2, _ = is_wordpress(body="<html><body>plain nginx</body></html>")
    assert ok2 is False
    ok3, _ = is_wordpress(body="", cookie_names=["wordpress_logged_in_abc", "sessionid"])
    assert ok3 is True


def test_parse_assets():
    html = (
        '<link href="/wp-content/plugins/contact-form-7/style.css?ver=5.8.1">'
        '<script src="/wp-content/plugins/woocommerce/app.js?ver=8.2.0"></script>'
        '<link href="/wp-content/themes/astra/style.css?ver=4.1.0">'
    )
    inv = parse_assets(html)
    assert inv["plugins"]["contact-form-7"] == "5.8.1"
    assert inv["plugins"]["woocommerce"] == "8.2.0"
    assert inv["themes"]["astra"] == "4.1.0"


def test_parse_readme_stable_tag():
    assert parse_readme_stable_tag("=== My Plugin ===\nStable tag: 1.4.2\n") == "1.4.2"
    assert parse_readme_stable_tag("Stable tag: trunk") is None    # dev sürüm → None
    assert parse_readme_stable_tag("no tag here") is None


def test_parse_wp_json():
    body = '{"namespaces":["wp/v2","gh/v3"],"routes":{"/wp/v2/users":{},"/wp/v2/posts/(?P<id>[\\\\d]+)":{}}}'
    p = parse_wp_json(body)
    assert "wp/v2" in p["namespaces"] and "gh/v3" in p["namespaces"]
    assert "/wp/v2/posts/(?P<id>[\\d]+)" in p["routes"]
    assert parse_wp_json("bozuk json")["routes"] == []


def test_route_to_probe_url():
    base = "https://blog.example.com"
    assert _route_to_probe_url(base, "/wp/v2/posts/(?P<id>[\\d]+)") == \
        "https://blog.example.com/wp-json/wp/v2/posts/1"
    # sayısal-olmayan grup (slug) → bozuk URL üretme, atla
    assert _route_to_probe_url(base, "/wp/v2/types/(?P<type>[\\w-]+)") is None
    # değişkensiz route → aday değil
    assert _route_to_probe_url(base, "/wp/v2/settings") is None


def test_idor_candidates_from_routes():
    base = "https://blog.example.com"
    routes = ["/wp/v2/posts/(?P<id>[\\d]+)", "/wp/v2/settings", "/gh/v3/contacts/(?P<id>[\\d]+)"]
    cands = idor_candidates_from_routes(base, routes, namespaces=["wp/v2"])
    assert "https://blog.example.com/wp-json/wp/v2/posts/1" in cands
    assert "https://blog.example.com/wp-json/gh/v3/contacts/1" in cands
    # wp/v2 namespace → çekirdek koleksiyonlar garanti seed
    assert "https://blog.example.com/wp-json/wp/v2/users/1" in cands
    # dedup: settings (değişkensiz) hiç girmemeli
    assert all("settings" not in c for c in cands)


def test_idor_bridge_accepts_wp_seeds():
    # #6 köprü: wp_probe'un seed ettiği /wp-json/<res>/<id> adayları _probe_idor'un
    # extract_object_refs süzgecinden GERÇEKTEN geçmeli (aksi halde sessizce düşerler).
    from pipeline.idor_probe import extract_object_refs
    for url in ("https://blog.example.com/wp-json/wp/v2/users/1",
                "https://blog.example.com/wp-json/gh/v3/contacts/1",       # Groundhogg (CVE sınıfı)
                "https://blog.example.com/wp-json/wp/v2/comments/1",
                "https://blog.example.com/wp-json/wp/v2/media/1"):
        assert extract_object_refs(url), f"IDOR süzgeci seed'i düşürdü: {url}"


def test_classify_rest_users():
    body = '[{"id":1,"name":"admin","slug":"admin"},{"id":2,"name":"editor","slug":"editor"}]'
    c = classify_rest_users(200, "application/json", body)
    assert c and c["exposed"] and c["count"] == 2 and "admin" in c["sample"]
    assert classify_rest_users(401, "application/json", body) is None   # reddedildi → ifşa yok
    assert classify_rest_users(200, "text/html", "<html></html>") is None


def test_classify_author_redirect():
    assert classify_author_redirect(301, "https://x/author/admin/", "") == "admin"
    assert classify_author_redirect(200, "", '<body class="archive author-jsmith author-2">') == "jsmith"
    assert classify_author_redirect(404, "", "not found") is None


def test_classify_xmlrpc():
    assert classify_xmlrpc(405, "XML-RPC server accepts POST requests only.")["enabled"] is True
    assert classify_xmlrpc(200, "<html>normal page</html>") is None


def test_validate_debug_log():
    assert validate_debug_log(200, "text/plain",
                              "[12-Aug-2026] PHP Warning:  foo in /var/www/wp/x.php on line 42") is True
    assert validate_debug_log(200, "text/html", "<html>soft 404</html>") is False
    assert validate_debug_log(404, "text/plain", "PHP Warning: x") is False


# ============================================================
# Uçtan uca — sahte sunucu (ağ YOK)
# ============================================================

class _R:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
    # httpx headers.get(name, default) uyumu — dict zaten .get sağlar


class FakeWPClient:
    """WordPress sitesi taklidi: URL yoluna göre deterministik yanıt."""
    def __init__(self, scheme_ok="https"):
        self._scheme_ok = scheme_ok

    async def get(self, url, timeout=10.0, follow_redirects=False):
        # Şema kontrolü: yalnız _scheme_ok cevap versin (https→http fallback testi için)
        if not url.startswith(self._scheme_ok + "://"):
            raise RuntimeError("connection refused")
        path = url.split("://", 1)[1]
        path = "/" + path.split("/", 1)[1] if "/" in path else "/"

        if path in ("/", ""):
            html = (
                '<html><head><meta name="generator" content="WordPress 6.4.2" />'
                '<link rel="stylesheet" href="/wp-content/plugins/woocommerce/a.css?ver=8.2.0">'
                '<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/b.css?ver=5.8.1">'
                '<link rel="stylesheet" href="/wp-content/themes/astra/style.css?ver=4.1.0">'
                '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.2"></script>'
                '</head><body>Hoş geldiniz</body></html>'
            )
            return _R(200, html, {"content-type": "text/html"})
        if path == "/wp-content/plugins/woocommerce/readme.txt":
            return _R(200, "=== WooCommerce ===\nStable tag: 8.2.1\n", {"content-type": "text/plain"})
        if path == "/wp-content/plugins/contact-form-7/readme.txt":
            return _R(404, "not found", {"content-type": "text/html"})
        if path == "/wp-json/":
            body = ('{"namespaces":["wp/v2","oembed/1.0"],'
                    '"routes":{"/wp/v2/posts/(?P<id>[\\\\d]+)":{},"/wp/v2/settings":{}}}')
            return _R(200, body, {"content-type": "application/json"})
        if path == "/wp-json/wp/v2/users":
            body = '[{"id":1,"name":"admin","slug":"admin"},{"id":2,"name":"yazar","slug":"yazar"}]'
            return _R(200, body, {"content-type": "application/json"})
        if path == "/xmlrpc.php":
            return _R(405, "XML-RPC server accepts POST requests only.", {"content-type": "text/plain"})
        if path == "/wp-content/debug.log":
            return _R(200, "[12-Aug-2026] PHP Fatal error: boom in /var/www/wp/wp-load.php on line 10",
                      {"content-type": "text/plain"})
        if path.startswith("/?author=1"):
            return _R(301, "", {"location": "https://blog.example.com/author/admin/"})
        return _R(404, "not found", {"content-type": "text/html"})


class FakeHardenedWPClient(FakeWPClient):
    """Body marker'ı MASKELEYEN WP (security plugin wp-content'i gizler) ama wordpress_ çerezi
    set eder. #1 regresyon testi: eski halde (ölü cookie/Link kanalı) prob TAMAMEN atlıyordu."""
    async def get(self, url, timeout=10.0, follow_redirects=False):
        path = url.split("://", 1)[1]
        path = "/" + path.split("/", 1)[1] if "/" in path else "/"
        if not url.startswith("https://"):
            raise RuntimeError("refused")
        if path in ("/", ""):
            # Gövdede TEK wp-content/wp-includes/wp-json yok → yalnız çerez kanalı kalır.
            return _R(200, "<html><head><title>Kurumsal</title></head><body>Hoş geldiniz</body></html>",
                      {"content-type": "text/html",
                       "set-cookie": "wordpress_logged_in_9f=1; Path=/; HttpOnly"})
        return await super().get(url, timeout=timeout, follow_redirects=follow_redirects)


class FakeNonWPClient:
    """WordPress OLMAYAN site (düz nginx). Çift-kapı testi: prob HİÇ bulgu üretmemeli."""
    async def get(self, url, timeout=10.0, follow_redirects=False):
        if not url.startswith("https://"):
            raise RuntimeError("refused")
        return _R(200, "<html><body>Just an nginx landing page.</body></html>",
                  {"content-type": "text/html"})


def test_probe_wordpress_end_to_end():
    res = asyncio.run(probe_wordpress("blog.example.com", FakeWPClient()))
    assert res["confirmed_wp"] is True
    assert res["core_version"] == "6.4.2"
    titles = " || ".join(f["title"] for f in res["findings"])
    assert "Çekirdek Sürümü" in titles
    assert "Kullanıcı Enümerasyonu" in titles          # REST user-enum (confirmed/medium)
    assert "XML-RPC" in titles
    assert "debug.log" in titles
    assert "Envanteri" in titles
    # readme.txt KESİN sürümü ?ver='i ezmeli (woocommerce 8.2.0 → 8.2.1)
    assert res["inventory"]["plugins"]["woocommerce"] == "8.2.1"
    # readme 404 olan plugin ?ver='de kalır
    assert res["inventory"]["plugins"]["contact-form-7"] == "5.8.1"
    # IDOR adayları seed'lendi (route + wp/v2 çekirdek)
    assert "https://blog.example.com/wp-json/wp/v2/posts/1" in res["idor_candidates"]
    assert "https://blog.example.com/wp-json/wp/v2/users/1" in res["idor_candidates"]
    # REST user-enum bulundu → author-scan (düşük değerli ikinci yol) ÇALIŞMAMALI
    assert "Author-Scan" not in titles
    # Tüm bulgular confirmed (deterministik kanıt)
    assert all(f["confidence_tier"] == "confirmed" for f in res["findings"])


def test_probe_wordpress_double_gate_non_wp():
    # KRİTİK: profil yanlışlıkla WP dese bile (bu modül playbook'tan sonra çağrılır), canlı
    # imza yoksa TEK bulgu bile üretilmemeli — kullanıcı doktrini.
    res = asyncio.run(probe_wordpress("static.example.com", FakeNonWPClient()))
    assert res["confirmed_wp"] is False
    assert res["findings"] == []
    assert res["idor_candidates"] == []


def test_probe_wordpress_hardened_cookie_channel():
    # #1: gövde marker'ı yok, yalnız wordpress_ çerezi → yine de WP tanınmalı (canlanan kanal).
    res = asyncio.run(probe_wordpress("kurumsal.example.com", FakeHardenedWPClient()))
    assert res["confirmed_wp"] is True
    assert any("Kullanıcı Enümerasyonu" in f["title"] for f in res["findings"])


def test_probe_wordpress_scheme_fallback():
    # https reddederse http'ye düşer; yine WP tanınır.
    res = asyncio.run(probe_wordpress("blog.example.com", FakeWPClient(scheme_ok="http")))
    assert res["confirmed_wp"] is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
