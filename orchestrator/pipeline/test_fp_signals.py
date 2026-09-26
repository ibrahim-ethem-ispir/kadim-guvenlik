"""Türkçe: False-positive sinyalleri (fp_signals) birim testleri — SAF çekirdek; ağ yok.

Kapsam: classify_response_page (WAF/auth/hata/boş sayfa), is_catchall_from_samples
(var-olmayan yola 2xx → catch-all), looks_like_exposure_finding.

Çalıştır: python3 orchestrator/pipeline/test_fp_signals.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.fp_signals import (  # noqa: E402
    classify_response_page, is_catchall_from_samples, looks_like_exposure_finding,
    random_probe_paths,
)


def test_waf_block_detected():
    body = "<html><body>Attention Required! | Cloudflare — Ray ID: 12ab</body></html>"
    assert classify_response_page(body) == "waf_block"


def test_auth_wall_text():
    assert classify_response_page("You must be logged in to view this page.") == "auth_wall"


def test_auth_wall_password_form_on_401():
    body = '<form><input type="password" name="pw"></form>'
    assert classify_response_page(body, status=401) == "auth_wall"
    # 200 statüde salt password formu tek başına auth_wall saymaz (login sayfası normal olabilir)
    assert classify_response_page(body, status=200) is None


def test_generic_error_soft404():
    assert classify_response_page("<h1>404 Not Found</h1> the page does not exist") == "generic_error"


def test_maintenance():
    assert classify_response_page("Site is under maintenance, be right back!") == "maintenance"


def test_empty():
    assert classify_response_page("   ") == "empty"
    assert classify_response_page("") == "empty"
    assert classify_response_page(None) == "empty"


def test_real_content_none():
    body = "<html><body><h1>Dashboard</h1><table><tr><td>user1</td></tr></table></body></html>"
    assert classify_response_page(body) is None


def test_catchall_all_2xx():
    # Var-olmayan yollara 2xx → catch-all
    assert is_catchall_from_samples([200, 200], ["shell", "shell"]) is True


def test_not_catchall_when_404():
    assert is_catchall_from_samples([404, 404]) is False
    assert is_catchall_from_samples([200, 404]) is False


def test_not_catchall_insufficient_samples():
    assert is_catchall_from_samples([200]) is False


def test_catchall_body_divergence_rejected():
    # 2xx ama gövde uzunlukları çok farklı → dinamik içerik, catch-all sayma
    small = "x" * 100
    big = "y" * 5000
    assert is_catchall_from_samples([200, 200], [small, big]) is False


def test_exposure_hint():
    assert looks_like_exposure_finding("Git Config Exposure", "git-config-exposure") is True
    assert looks_like_exposure_finding("Admin Panel Detect", "") is True
    assert looks_like_exposure_finding("SQL Injection", "sqli") is False


def test_random_probe_paths_unique():
    ps = random_probe_paths(3)
    assert len(ps) == 3 and len(set(ps)) == 3 and all(p.startswith("/kadim-fp-probe-") for p in ps)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
