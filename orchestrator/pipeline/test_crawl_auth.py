"""Türkçe: T1-B crawl auth başlık ayrıştırma testi — SAF; ağ yok.
Çalıştır: python3 orchestrator/pipeline/test_crawl_auth.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.endpoint_discovery import _parse_header_list  # noqa: E402


def test_parse_valid_and_invalid():
    r = _parse_header_list(["Authorization: Bearer T", "bad-line", "Cookie: s=1; t=2", "", "  : x"])
    assert r == {"Authorization": "Bearer T", "Cookie": "s=1; t=2"}


def test_parse_none_empty():
    assert _parse_header_list(None) == {}
    assert _parse_header_list([]) == {}


def test_parse_strips_whitespace():
    assert _parse_header_list(["  X-API-Key :  123  "]) == {"X-API-Key": "123"}


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
