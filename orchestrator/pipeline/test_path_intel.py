"""Türkçe: K2 — LLM istihbarat subayı sanitize/clamp/fallback birim testleri (SAF; gerçek
LLM YOK — llm_call enjekte edilir).

Kritik felsefe: LLM yalnız ADAY yol + imza önerir; yargı deterministik validator'da kalır.
Bu testler, güvenilmez LLM çıktısının korkuluklardan (path sanitize, enum clamp, üst sınır,
sağlayıcı-yoksa boş) geçtiğini sabitler. Sağlayıcı erişilemezse motor bozulmaz (K1 fallback).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.path_intel import _sanitize_candidate, suggest_paths_llm  # noqa: E402


def test_sanitize_cross_host_ve_gecersiz_red():
    assert _sanitize_candidate({"path": "http://evil/x", "signature": {"must_contain_any": ["x"]}}) is None
    assert _sanitize_candidate({"path": "//evil/x", "signature": {"must_contain_any": ["x"]}}) is None
    assert _sanitize_candidate({"path": "/a b", "signature": {"must_contain_any": ["x"]}}) is None
    assert _sanitize_candidate({"path": "relative", "signature": {"must_contain_any": ["x"]}}) is None
    assert _sanitize_candidate({}) is None


def test_sanitize_imzasiz_red():
    """İmzasız (must_contain_any/all ve min_length yok) aday REDDEDİLİR — deterministik
    doğrulanamayan öneri bulguya dönüşemez (precision koruması)."""
    assert _sanitize_candidate({"path": "/x.conf"}) is None
    assert _sanitize_candidate({"path": "/x.conf", "signature": {}}) is None


def test_sanitize_clamp_ve_source():
    row = _sanitize_candidate({
        "path": "/c.dist", "category": "garbage", "severity": "ULTRA",
        "signature": {"must_contain_any": ["x"], "must_not_contain": ["<html"], "min_length": 5},
    })
    assert row is not None
    assert row[0] == "/c.dist"
    assert row[1] in {"config_exposure", "info_disclosure"}          # bilinmeyen kategori clamp
    assert row[2] in {"critical", "high", "medium", "low", "info"}   # geçersiz severity clamp
    assert row[3] == "signature"
    assert row[4]["source"] == "llm"
    assert row[4]["signature"]["must_contain_any"] == ["x"]


def test_sanitize_gecerli_kategori_korunur():
    row = _sanitize_candidate({
        "path": "/actuator/env", "category": "env_exposure", "severity": "critical",
        "signature": {"must_contain_any": ["propertySources", "systemEnvironment"]},
    })
    assert row[1] == "env_exposure" and row[2] == "critical"


def test_suggest_fallback_bos_saglayici_yok():
    async def boom(_fp):
        raise RuntimeError("no provider")
    assert asyncio.run(suggest_paths_llm({"tech": []}, llm_call=boom)) == []


def test_suggest_ust_sinir_ve_dedup():
    async def many(_fp):
        rows = [{"path": f"/p{i}", "signature": {"must_contain_any": ["x"]}} for i in range(100)]
        rows += [{"path": "/p0", "signature": {"must_contain_any": ["x"]}}]  # duplike
        return rows
    out = asyncio.run(suggest_paths_llm({}, llm_call=many, cap=30))
    assert len(out) <= 30
    paths = [r[0] for r in out]
    assert len(paths) == len(set(paths))  # dedup


def test_suggest_liste_ve_dict_sarim():
    """llm_call ham liste VEYA {'suggested_paths': [...]} dönebilir — ikisi de kabul."""
    async def as_dict(_fp):
        return {"suggested_paths": [{"path": "/x.conf", "signature": {"must_contain_any": ["k"]}}]}
    out = asyncio.run(suggest_paths_llm({}, llm_call=as_dict))
    assert len(out) == 1 and out[0][0] == "/x.conf"


def test_suggest_json_string_parse():
    async def as_str(_fp):
        return '[{"path": "/y.conf", "signature": {"must_contain_any": ["k"]}}]'
    out = asyncio.run(suggest_paths_llm({}, llm_call=as_str))
    assert len(out) == 1 and out[0][0] == "/y.conf"


def main():
    tests = [
        test_sanitize_cross_host_ve_gecersiz_red,
        test_sanitize_imzasiz_red,
        test_sanitize_clamp_ve_source,
        test_sanitize_gecerli_kategori_korunur,
        test_suggest_fallback_bos_saglayici_yok,
        test_suggest_ust_sinir_ve_dedup,
        test_suggest_liste_ve_dict_sarim,
        test_suggest_json_string_parse,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"[OK] {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {t.__name__}: {type(e).__name__}: {e}")
    if failed:
        print(f"\n{failed} test BAŞARISIZ.")
        sys.exit(1)
    print("\nTüm K2 testleri geçti.")


if __name__ == "__main__":
    main()
