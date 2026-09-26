"""Türkçe: Kombinasyon zincirleri (combo_chains) testleri — SAF; ağ YOK.

Kök: APT tek başına düşük bulguları BİRLEŞTİRİP yüksek-etki kurar. Testler: brute-force yüzeyi
(user-enum+xmlrpc), kitlesel sızıntı (enum+IDOR), hedefli exploit (debug.log+sürüm), host
izolasyonu (farklı hostların sinyalleri birleşmez), tek-sinyal negatifi.

Çalıştır: python3 orchestrator/pipeline/test_combo_chains.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.combo_chains import (  # noqa: E402
    Signal, find_combinations, normalize_host,
    SIG_WP_USER_ENUM, SIG_WP_AUTHOR_SCAN, SIG_WP_XMLRPC, SIG_WP_DEBUG_LOG,
    SIG_WP_CORE_VERSION, SIG_WP_INVENTORY, SIG_IDOR_CONFIRMED,
)


def test_normalize_host():
    assert normalize_host("https://blog.example.com/wp-json/x?a=1") == "blog.example.com"
    assert normalize_host("blog.example.com:443") == "blog.example.com"
    assert normalize_host("blog.example.com") == "blog.example.com"
    assert normalize_host("") == ""


def test_bruteforce_surface_fires():
    sigs = [
        Signal(SIG_WP_USER_ENUM, "https://h1/wp-json/wp/v2/users", "medium", "REST user-enum"),
        Signal(SIG_WP_XMLRPC, "https://h1/xmlrpc.php", "low", "xmlrpc açık"),
    ]
    combos = find_combinations(sigs)
    assert len(combos) == 1
    c = combos[0]
    assert c["combo"] == "wp-bruteforce-surface"
    assert c["severity"] == "high"                   # low+medium → high (yükseltme)
    assert c["target"] == "h1"
    assert "REST user-enum" in c["proof"] and "xmlrpc açık" in c["proof"]  # kaynaklar cite


def test_mass_user_exfil_author_variant():
    # author-scan da user-enum grubunu karşılar (alternatif); IDOR ile birleşir.
    sigs = [
        Signal(SIG_WP_AUTHOR_SCAN, "https://h1/", "low", "author-scan admin"),
        Signal(SIG_IDOR_CONFIRMED, "https://h1/wp-json/wp/v2/users/2", "high", "IDOR kanıtlı"),
    ]
    combos = find_combinations(sigs)
    names = {c["combo"] for c in combos}
    assert "wp-mass-user-exfil" in names


def test_targeted_exploit_intel():
    sigs = [
        Signal(SIG_WP_DEBUG_LOG, "https://h1/wp-content/debug.log", "high", "debug.log"),
        Signal(SIG_WP_INVENTORY, "https://h1/", "info", "envanter woocommerce@8.2.1"),
    ]
    combos = find_combinations(sigs)
    assert any(c["combo"] == "wp-targeted-exploit-intel" for c in combos)


def test_host_isolation():
    # Sinyaller FARKLI hostlarda → birleşmez (aynı sistem değil).
    sigs = [
        Signal(SIG_WP_USER_ENUM, "https://h1/wp-json/wp/v2/users", "medium", "enum"),
        Signal(SIG_WP_XMLRPC, "https://h2/xmlrpc.php", "low", "xmlrpc"),
    ]
    assert find_combinations(sigs) == []


def test_single_signal_no_combo():
    sigs = [Signal(SIG_WP_XMLRPC, "https://h1/xmlrpc.php", "low", "xmlrpc")]
    assert find_combinations(sigs) == []


def test_multiple_combos_same_host():
    # Zengin kanıt: hem brute-force hem kitlesel-sızıntı aynı hostta tetiklenebilir.
    sigs = [
        Signal(SIG_WP_USER_ENUM, "https://h1/wp-json/wp/v2/users", "medium", "enum"),
        Signal(SIG_WP_XMLRPC, "https://h1/xmlrpc.php", "low", "xmlrpc"),
        Signal(SIG_IDOR_CONFIRMED, "https://h1/wp-json/wp/v2/users/2", "high", "IDOR"),
    ]
    names = {c["combo"] for c in find_combinations(sigs)}
    assert "wp-bruteforce-surface" in names and "wp-mass-user-exfil" in names


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
