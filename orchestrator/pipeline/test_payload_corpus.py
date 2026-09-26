"""Türkçe: T4-A payload corpus loader (payload_corpus) testleri — SAF, ağ/DB YOK.

NEDEN: Corpus, kurumsal taramanın payload kapsamını genişletir ama elle-düzenleme/
tedarik riskine karşı runtime kapısından geçer. Testler: kapı reddi (yıkıcı token,
bilinmeyen placeholder), inline-önce merge + tavan, bayrak kapalıyken BİREBİR inline
(sıfır regresyon kilidi), retry/examples tavaları, ve repoya girmiş GERÇEK veri
dosyalarının geçerliliği.

Çalıştır: python3 orchestrator/pipeline/test_payload_corpus.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline import payload_corpus as pc  # noqa: E402

_INLINE = ["' AND SLEEP({D})-- -", "'||pg_sleep({D})--"]


def _fresh_loader(entries_by_class: dict, tmp: Path):
    """Test-izole loader: veri dizinini geçici klasöre çevir, önbelleği sıfırla."""
    d = tmp / "payloads"
    d.mkdir(parents=True, exist_ok=True)
    for klass, entries in entries_by_class.items():
        (d / f"{klass}.json").write_text(
            json.dumps({"class": klass, "entries": entries}), encoding="utf-8")
    old_dir, old_cache = pc._DATA_DIR, dict(pc._cache)
    pc._DATA_DIR = d
    pc._cache.clear()
    return old_dir, old_cache


def _restore(old_dir, old_cache):
    pc._DATA_DIR = old_dir
    pc._cache.clear()
    pc._cache.update(old_cache)


def test_kapi_yikici_token_reddi():
    with tempfile.TemporaryDirectory() as td:
        od, oc = _fresh_loader({"sqli": [
            {"payload": "' AND SLEEP({D})-- -"},
            {"payload": "'; DROP TABLE users; SLEEP({D})-- -"},   # yıkıcı → elenir
            {"payload": "1; UPDATE t SET x=1 AND SLEEP({D})"},    # yıkıcı → elenir
        ]}, Path(td))
        assert pc.load_class("sqli") == ["' AND SLEEP({D})-- -"]
        _restore(od, oc)


def test_kapi_bilinmeyen_placeholder_reddi():
    with tempfile.TemporaryDirectory() as td:
        od, oc = _fresh_loader({"sqli": [
            {"payload": "{TOKEN} AND SLEEP({D})"},   # verifier {TOKEN} doldurmaz → düş
            {"payload": "' AND SLEEP({D})#"},
        ]}, Path(td))
        assert pc.load_class("sqli") == ["' AND SLEEP({D})#"]
        _restore(od, oc)


def test_kapi_sinif_placeholder_sarti():
    with tempfile.TemporaryDirectory() as td:
        od, oc = _fresh_loader({
            "xss": [{"payload": "<b>no-marker</b>"}, {"payload": "<b>{MARKER}</b>"}],
            "lfi": [{"payload": "../../../../etc/shadow"},        # kanarya değil → düş
                    {"payload": "php://filter/convert.base64-encode/resource=a"}],
        }, Path(td))
        assert pc.load_class("xss") == ["<b>{MARKER}</b>"]
        assert pc.load_class("lfi") == ["php://filter/convert.base64-encode/resource=a"]
        _restore(od, oc)


def test_merge_inline_once_corpus_sonu_dedup_tavan():
    with tempfile.TemporaryDirectory() as td:
        corpus = [{"payload": f"' AND SLEEP({{D}})/*{i}*/"} for i in range(50)]
        od, oc = _fresh_loader({"sqli": corpus}, Path(td))
        merged = pc.merge_with_inline("sqli", _INLINE)
        assert merged[:2] == _INLINE                          # inline ÖNCE
        assert len(merged) == pc._MERGE_CAPS["sqli"]          # tavan
        assert len(set(merged)) == len(merged)                # dedup
        # Inline ile birebir aynı payload corpus'ta tekrar eklenmez:
        m2 = pc.merge_with_inline("sqli", [corpus[0]["payload"], "x"])
        assert m2.count(corpus[0]["payload"]) == 1
        _restore(od, oc)


def test_bayrak_kapali_birebir_inline():
    """SIFIR REGRESYON KİLİDİ: PAYLOAD_CORPUS=0 → merge inline'ın kopyası, load []."""
    with tempfile.TemporaryDirectory() as td:
        od, oc = _fresh_loader({"sqli": [{"payload": "' AND SLEEP({D})-- -"}]}, Path(td))
        old = os.environ.get("PAYLOAD_CORPUS")
        os.environ["PAYLOAD_CORPUS"] = "0"
        try:
            assert pc.load_class("sqli") == []
            assert pc.merge_with_inline("sqli", _INLINE) == _INLINE
            assert pc.retry_payloads("sqli") == []
            assert pc.examples_for("sqli") == []
        finally:
            if old is None:
                del os.environ["PAYLOAD_CORPUS"]
            else:
                os.environ["PAYLOAD_CORPUS"] = old
        _restore(od, oc)


def test_dosya_yok_bozuk_json_bos():
    with tempfile.TemporaryDirectory() as td:
        od, oc = _fresh_loader({}, Path(td))
        assert pc.load_class("sqli") == []          # dosya yok → []
        (pc._DATA_DIR / "xss.json").write_text("{bozuk", encoding="utf-8")
        pc._cache.clear()
        assert pc.load_class("xss") == []           # bozuk JSON → []
        assert pc.merge_with_inline("xss", ["a"]) == ["a"]
        _restore(od, oc)


def test_tanimisiz_sinif_bos():
    assert pc.load_class("rce") == []
    assert pc.merge_with_inline("rce", ["x"]) == ["x"]


def test_retry_cap_ve_examples():
    with tempfile.TemporaryDirectory() as td:
        corpus = [{"payload": f"<s{i}>{ '{MARKER}' }"} for i in range(20)]
        od, oc = _fresh_loader({"xss": corpus}, Path(td))
        old = os.environ.get("PAYLOAD_CORPUS_RETRY_MAX")
        os.environ["PAYLOAD_CORPUS_RETRY_MAX"] = "6"
        try:
            assert len(pc.retry_payloads("xss")) == 6
            assert len(pc.retry_payloads("xss", cap=3)) == 3
            assert len(pc.examples_for("xss", 4)) == 4
            assert pc.examples_for("xss", 0) == []
        finally:
            if old is None:
                del os.environ["PAYLOAD_CORPUS_RETRY_MAX"]
            else:
                os.environ["PAYLOAD_CORPUS_RETRY_MAX"] = old
        _restore(od, oc)


# ---------------- repoya girmiş GERÇEK veri: yapı + kapı sağlamlığı ----------------

def test_gercek_veri_klasorleri_gecitten_geler():
    assert pc._DATA_DIR.exists(), "data/payloads repoyla dağıtılmalı"
    for klass in ("sqli", "xss", "lfi", "ssti"):
        items = pc.load_class(klass)
        assert items, f"{klass}.json yok/tüm girdiler kapıdan düştü"
        for p in items:
            assert len(p) <= 400 and p.strip() == p


def test_gercek_sqli_merge_tavani_korur():
    """Doğrulayıcıya giden SQLi listesi zamanlama bütçesini aşamaz."""
    merged = pc.merge_with_inline("sqli", _INLINE)
    assert len(merged) <= pc._MERGE_CAPS["sqli"]
    assert any("{D}" in p for p in merged)


# ---------------- Madde 3: sqli_error sınıfı + env tavanı + derinlik ----------------

def test_sqli_error_kapi_beyazliste():
    """sqli_error: yalnız hata-üretici vektör beyazlistesi/tırnak-kırıcı geçer;
    düz SELECT bile olsa beyazliste dışı SQL düşer (yapısal tahribatsızlık)."""
    with tempfile.TemporaryDirectory() as td:
        od, oc = _fresh_loader({"sqli_error": [
            {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))-- -"},
            {"payload": "'"},                                     # tırnak-kırıcı ✓
            {"payload": "SELECT username FROM users"},            # beyazliste dışı → düş
            {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e));"
                        " DROP TABLE users;-- -"},                # yıkıcı → düş
        ]}, Path(td))
        got = pc.load_class("sqli_error")
        assert got == ["' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))-- -", "'"]
        _restore(od, oc)


def test_env_tavan_override():
    """PAYLOAD_CORPUS_CAP_<SINIF> merge tavanını operatör ayarına çevirir (Madde 3.4);
    bozuk env varsayıma düşer, tavan inline'ın altına inmez."""
    with tempfile.TemporaryDirectory() as td:
        corpus = [{"payload": f"' AND SLEEP({{D}})/*{i}*/"} for i in range(50)]
        od, oc = _fresh_loader({"sqli": corpus}, Path(td))
        old = os.environ.get("PAYLOAD_CORPUS_CAP_SQLI")
        try:
            os.environ["PAYLOAD_CORPUS_CAP_SQLI"] = "30"
            assert len(pc.merge_with_inline("sqli", _INLINE)) == 30
            os.environ["PAYLOAD_CORPUS_CAP_SQLI"] = "çöp"
            assert len(pc.merge_with_inline("sqli", _INLINE)) == pc._MERGE_CAPS["sqli"]
            os.environ["PAYLOAD_CORPUS_CAP_SQLI"] = "1"   # inline altı → inline korunur
            assert pc.merge_with_inline("sqli", _INLINE) == _INLINE
        finally:
            if old is None:
                del os.environ["PAYLOAD_CORPUS_CAP_SQLI"]
            else:
                os.environ["PAYLOAD_CORPUS_CAP_SQLI"] = old
        _restore(od, oc)


def test_gercek_veri_madde3_derinligi():
    """Repoya girmiş GERÇEK corpus — Madde 3 hedef alt sınırları (geriye dönüş kilidi)."""
    assert len(pc.load_class("sqli")) >= 60, "timing SQLi havuzu küçüldü"
    err = pc.load_class("sqli_error")
    assert len(err) >= 20, "error-based SQLi havuzu küçüldü"
    assert any("extractvalue" in p.lower() for p in err)
    lfi = pc.load_class("lfi")
    assert len(lfi) >= 30, "LFI havuzu küçüldü"
    assert any("proc/self" in p for p in lfi)
    assert any("%252f" in p or "%c0%af" in p for p in lfi)   # çift-encode/overlong
    assert len(pc.load_class("ssti")) >= 8
    assert len(pc.load_class("xss")) >= 100


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print(f"\n{len(tests)} test geçti.")


if __name__ == "__main__":
    main()
