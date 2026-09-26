"""Türkçe: WordPress admin-ajax SQLi oracle (wp_sqli_oracle) testleri.

harvest/build çekirdeği SAF (ağ YOK). Uçtan uca: sahte ZAMANLI client — SLEEP payload'u
hedef parametrede görünürse asyncio.sleep ile gecikir; GERÇEK verify_time_based_sqli bunu
zaman-tabanlı blind SQLi olarak TEYİT eder. Böylece 'keşif→oracle' zinciri kanıtlanır.

KRİTİK: enjekte param query'de önde, action sonda → erken-teyit hedef param üstünde çalışır,
action enjeksiyonu (yansımaz) teyidi zehirlemez.

Çalıştır: python3 orchestrator/pipeline/test_wp_sqli_oracle.py
"""
import asyncio
import os
import re
import sys
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.wp_sqli_oracle import (  # noqa: E402
    harvest_actions, harvest_param_hints, harvest_js_urls, build_ajax_candidates,
    run_wp_sqli_oracle, CURATED_PARAMS,
)


# ============================================================
# SAF çekirdek testleri (ağ yok)
# ============================================================

def test_harvest_actions_forms():
    a = harvest_actions("jQuery.post(ajaxurl,{action:'get_products', id:1})")
    assert "get_products" in a
    assert "foo" in harvest_actions('var d={"action":"foo","x":1}')
    assert "bar" in harvest_actions("/wp-admin/admin-ajax.php?action=bar&x=1")
    assert "send_it" in harvest_actions("wp.ajax.post('send_it', {})")


def test_harvest_actions_skips_core():
    a = harvest_actions("{action:'heartbeat'} {action:'get_products'} {action:'query-attachments'}")
    assert "get_products" in a
    assert "heartbeat" not in a and "query-attachments" not in a


def test_harvest_param_hints():
    h = harvest_param_hints('{"postId": 5, "user_id": 3, "productID": 9, "name":"x"}')
    assert "postId" in h and "user_id" in h and "productID" in h
    assert "name" not in h                         # id-benzeri değil → elenir


def test_harvest_js_urls_same_host_only():
    html = ('<script src="/wp-content/plugins/x/app.js?ver=1"></script>'
            '<script src="https://cdn.other.com/y.js"></script>')
    u = harvest_js_urls(html, "https://blog.example.com")
    assert "https://blog.example.com/wp-content/plugins/x/app.js?ver=1" in u
    assert all("other.com" not in x for x in u)    # farklı host elenir


def test_build_ajax_candidates_order_and_cap():
    c = build_ajax_candidates("https://h", ["a1", "a2"], ["id", "post_id"], max_candidates=3)
    assert len(c) == 3
    # param DIŞTA, action İÇTE → ilk üç: (id,a1),(id,a2),(post_id,a1)
    assert (c[0]["param"], c[0]["action"]) == ("id", "a1")
    assert (c[1]["param"], c[1]["action"]) == ("id", "a2")
    assert (c[2]["param"], c[2]["action"]) == ("post_id", "a1")
    # enjekte param ÖNDE, action SONDA (erken-teyit mekaniği)
    url = c[0]["url"]
    assert url == "https://h/wp-admin/admin-ajax.php?id=1&action=a1"
    assert url.index("id=1") < url.index("action=")


# ============================================================
# Uçtan uca — sahte ZAMANLI sunucu (GERÇEK verify_time_based_sqli)
# ============================================================

class _R:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _payload_sleep_seconds(value: str) -> int:
    """Parametre değerinde SLEEP/pg_sleep/WAITFOR payload'u varsa saniyeyi çıkar (test cap 2)."""
    m = (re.search(r"sleep\((\d+)\)", value, re.I)
         or re.search(r"waitfor delay '0:0:(\d+)'", value, re.I))
    return min(int(m.group(1)), 2) if m else 0


class FakeSqliClient:
    """WordPress + zamanlı admin-ajax taklidi. vuln_action'ın vuln_param'ında SLEEP payload'u
    görünürse gerçekten bekler → verify_time_based_sqli teyit eder. Diğer her şey hızlı."""
    def __init__(self, vuln_action="get_products", vuln_param="id"):
        self.va = vuln_action
        self.vp = vuln_param

    async def get(self, url, **kwargs):
        parts = urlsplit(url)
        path = parts.path
        if "admin-ajax.php" in path:
            qs = parse_qs(parts.query, keep_blank_values=True)
            action = (qs.get("action") or [""])[0]
            pv = (qs.get(self.vp) or [""])[0]
            if action == self.va:                       # action bozulmamış (enjeksiyon param'da)
                secs = _payload_sleep_seconds(pv)        # hedef param'da SLEEP mi?
                if secs > 0:
                    await asyncio.sleep(secs)
                return _R(200, "1")
            return _R(200, "0")                          # yanlış/bozuk action → hızlı
        if path.endswith(".js"):
            return _R(200, "jQuery.post(ajaxurl,{action:'search_items', term_id:3});",
                      {"content-type": "application/javascript"})
        # kök
        html = ("<html><head><script src='/wp-content/plugins/shop/app.js'></script></head>"
                "<body>/wp-content/ wordpress"
                "<script>jQuery.post(ajaxurl,{action:'get_products', product_id:5});</script>"
                "</body></html>")
        return _R(200, html, {"content-type": "text/html"})


def test_oracle_confirms_ajax_sqli_end_to_end():
    # delay_seconds=1 → test hızlı; gerçek verify_time_based_sqli çalışır.
    findings = asyncio.run(run_wp_sqli_oracle(
        "blog.example.com", FakeSqliClient(vuln_action="get_products", vuln_param="id"),
        max_candidates=6, delay_seconds=1, control_samples=2))
    assert len(findings) == 1
    f = findings[0]
    assert f["action"] == "get_products" and f["param"] == "id"
    assert f["severity"] == "critical" and f["confidence_tier"] == "confirmed"
    assert f["cwe"] == ["CWE-89"]
    assert "SQL Injection" in f["title"]


def test_oracle_no_sqli_no_findings():
    # Hiçbir action/param zafiyetli değil → confirmed yok (FP üretmez).
    findings = asyncio.run(run_wp_sqli_oracle(
        "blog.example.com", FakeSqliClient(vuln_action="__none__", vuln_param="id"),
        max_candidates=4, delay_seconds=1, control_samples=2))
    assert findings == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
