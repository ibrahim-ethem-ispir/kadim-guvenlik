"""Türkçe: Pasif tarihî kaynak keşfi (passive_sources / Wayback CDX) birim testleri.
SAF filtre çekirdeği test edilir — ağ isteği YOK (fetch_wayback_endpoints CDX'e gider,
burada yalnız filter_wayback_urls doğrulanır).

Kök derdimiz: artık linklenmeyen ama CANLI tarihî endpoint'ler klasik bug kaynağı;
filtre aynı-host koruması + parametre-önceliği + tekilleştirme garantisi verir.

Çalıştır: python3 orchestrator/pipeline/test_passive_sources.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.passive_sources import filter_wayback_urls  # noqa: E402


def test_ayni_host_filtresi():
    rows = [
        "https://example.com/api/v1/users?id=1",
        "https://evil.com/example.com/x",          # yabancı host — düşer
        "https://sub.example.com/legacy?token=a",  # alt domain — kalır (scope geniş)
        "ftp://example.com/file",                  # http(s) değil — düşer
    ]
    out = filter_wayback_urls(rows, "example.com")
    urls = out["parameterized"] + out["plain"]
    assert any("/api/v1/users" in u for u in urls)
    assert any("sub.example.com" in u for u in urls)
    assert not any("evil.com" in u for u in urls)
    assert not any("ftp://" in u for u in urls)


def test_parametreli_onceelikli():
    rows = [f"https://example.com/page{i}" for i in range(10)]
    rows += ["https://example.com/search?q=1", "https://example.com/item?id=2"]
    out = filter_wayback_urls(rows, "example.com", cap=5)
    # Bütçe 5: 2 parametreli + 3 düz (parametreli her zaman önde)
    assert len(out["parameterized"]) == 2
    assert out["total"] == 5


def test_deger_tekillestirme():
    """Aynı yol+param-adı, farklı değerler → TEK kayıt (arşiv kopya patlaması yok)."""
    rows = [
        "https://example.com/item?id=1",
        "https://example.com/item?id=2",
        "https://example.com/item?id=999",
    ]
    out = filter_wayback_urls(rows, "example.com")
    assert len(out["parameterized"]) == 1


def test_statik_uzantilar_duser():
    rows = [
        "https://example.com/logo.png",
        "https://example.com/app.css",
        "https://example.com/api/export?format=csv",
    ]
    out = filter_wayback_urls(rows, "example.com")
    urls = out["parameterized"] + out["plain"]
    assert len(urls) == 1
    assert "api/export" in urls[0]


def test_www_normalizasyon():
    rows = ["https://www.example.com/a?x=1", "https://example.com/b"]
    out = filter_wayback_urls(rows, "www.example.com")
    assert out["total"] == 2


def test_bos_ve_cop_girdi():
    assert filter_wayback_urls([], "example.com")["total"] == 0
    assert filter_wayback_urls(["", None, "   "], "example.com")["total"] == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
