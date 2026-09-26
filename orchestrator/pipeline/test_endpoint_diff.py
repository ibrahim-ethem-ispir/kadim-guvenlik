"""Türkçe: Endpoint sürüm-diff monitörü (endpoint_diff) birim testleri — SAF; sahte
koleksiyon, gerçek Mongo YOK.

Kök derdimiz: "bakılacak yer kalmadı" hissi. Snapshot→diff zinciri YENİ yüzeyi
(yol/parametre/form) ölçülebilir yapar. Testler: anahtar normalizasyonu (değerler
uçucu, yol+param-adı kalıcı), baseline davranışı, yeni yol/parametre/form tespiti,
no_diff_streak sayacı, DB yazma/okuma.

Çalıştır: python3 orchestrator/pipeline/test_endpoint_diff.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.endpoint_diff import (  # noqa: E402
    url_key, param_key, form_key, build_snapshot, diff_snapshots,
    diff_has_news, diff_headline, new_surface_urls,
    load_latest_snapshot, save_snapshot,
)


class FakeCol:
    """Minimal in-memory Mongo koleksiyonu (test_exploit_memory.FakeCol deseni)."""
    def __init__(self):
        self.docs = []

    def find_one(self, query):
        for d in self.docs:
            if all(d.get(k) == v for k, v in query.items()):
                return d
        return None

    def insert_one(self, doc):
        self.docs.append(doc)

    def replace_one(self, filt, doc, upsert=False):
        for i, d in enumerate(self.docs):
            if all(d.get(k) == v for k, v in filt.items()):
                self.docs[i] = doc
                return
        if upsert:
            self.docs.append(doc)


# ---------- Anahtar normalizasyonu ----------

def test_url_key_değerleri_atar():
    """Sorgu DEĞERLERİ (CSRF token vb.) uçucudur — anahtar yalnız host+path."""
    assert url_key("https://example.com/api/users?id=1&token=abc") == ("example.com", "/api/users")
    assert url_key("http://www.example.com/x") == ("example.com", "/x")
    assert url_key("example.com/y") == ("example.com", "/y")
    assert url_key("") is None
    assert url_key("mailto:a@b.c") is None


def test_param_key_adlari_siralar():
    k = param_key("https://example.com/search?q=1&lang=tr")
    assert k == ("example.com", "/search", ("lang", "q"))
    assert param_key("https://example.com/no-params") is None


def test_form_key_method_ve_inputlari_tutar():
    fk = form_key({"action": "https://example.com/login", "method": "POST",
                   "inputs": ["user", "pass", "user"]})
    assert fk == ("example.com", "/login", "post", ("pass", "user"))
    assert form_key({"action": ""}) is None


# ---------- Snapshot + diff ----------

def _snap(urls, params=(), forms=()):
    return build_snapshot(list(urls), [ {"url": p} for p in params ], list(forms))


def test_baseline_ilk_taramada_yeni_yuzey_sayilmaz():
    """Önceki snapshot yoksa her şey ilk kez görülüyor — 'yeni' alarmı VERİLMEZ."""
    curr = _snap(["https://example.com/", "https://example.com/a?id=1"],
                 ["https://example.com/a?id=1"])
    d = diff_snapshots(None, curr)
    assert d["is_first"] is True
    assert not diff_has_news(d)
    assert "baseline" in diff_headline(d)


def test_yeni_yol_tespiti():
    prev = _snap(["https://example.com/", "https://example.com/old"])
    curr = _snap(["https://example.com/", "https://example.com/old",
                  "https://example.com/new-page"])
    d = diff_snapshots(prev, curr)
    assert d["is_first"] is False
    assert ["example.com", "/new-page"] in d["new_urls"]
    assert diff_has_news(d)
    assert "YENİ YÜZEY" in diff_headline(d)


def test_bilinen_yolda_yeni_parametre():
    """Aynı yol ama parametre kümesi büyüdü → new_param (değer değil, AD diff'i)."""
    prev = _snap(["https://example.com/item?id=1"], ["https://example.com/item?id=1"])
    curr = _snap(["https://example.com/item?id=1&ref=x"],
                 ["https://example.com/item?id=1&ref=x"])
    d = diff_snapshots(prev, curr)
    assert d["new_urls"] == []
    assert len(d["new_params"]) == 1
    assert d["new_params"][0]["params"] == ["ref"]
    assert d["new_params"][0]["kind"] == "new_param"
    assert diff_has_news(d)


def test_deger_degisimi_yeni_sayilmaz():
    """id=1 → id=999: değer değişti ama yüzey aynı — diff SESSİZ (false-positive yok)."""
    prev = _snap(["https://example.com/item?id=1"], ["https://example.com/item?id=1"])
    curr = _snap(["https://example.com/item?id=999"], ["https://example.com/item?id=999"])
    d = diff_snapshots(prev, curr)
    assert not diff_has_news(d)
    assert d["unchanged_url_count"] >= 1


def test_yeni_form_tespiti():
    prev = _snap(["https://example.com/"], forms=[])
    curr = _snap(["https://example.com/"],
                 forms=[{"action": "https://example.com/upload", "method": "post",
                         "inputs": ["file"]}])
    d = diff_snapshots(prev, curr)
    assert len(d["new_forms"]) == 1
    assert diff_has_news(d)


def test_daralan_yuzey_sayilir():
    prev = _snap(["https://example.com/a", "https://example.com/b"])
    curr = _snap(["https://example.com/a"])
    d = diff_snapshots(prev, curr)
    assert d["removed_url_count"] == 1
    assert not diff_has_news(d)  # daralma 'yeni yüzey' değil — ama kayıt altında


def test_new_surface_urls_donusturme():
    prev = _snap(["https://example.com/"])
    curr = _snap(["https://example.com/", "https://example.com/api/x?token=1"],
                 ["https://example.com/api/x?token=1"])
    d = diff_snapshots(prev, curr)
    urls = new_surface_urls(d)
    assert any("/api/x?token=" in u for u in urls)


# ---------- DB katmanı ----------

def test_snapshot_yazilir_okunur_streak_sayilir():
    c = FakeCol()
    s1 = _snap(["https://example.com/"])
    d1 = diff_snapshots(None, s1)
    assert save_snapshot(c, host="example.com", snapshot=s1, scan_id="scan1", diff=d1)
    doc = load_latest_snapshot(c, "example.com")
    assert doc and doc["scan_id"] == "scan1"
    assert doc["no_diff_streak"] == 0

    # Aynı yüzey tekrar → streak 1
    d2 = diff_snapshots(doc["snapshot"], s1)
    assert not diff_has_news(d2)
    save_snapshot(c, host="example.com", snapshot=s1, scan_id="scan2", diff=d2)
    doc2 = load_latest_snapshot(c, "example.com")
    assert doc2["no_diff_streak"] == 1
    assert doc2["scan_id"] == "scan2"

    # YENİ yüzey → streak sıfırlanır
    s3 = _snap(["https://example.com/", "https://example.com/yeni"])
    d3 = diff_snapshots(doc2["snapshot"], s3)
    assert diff_has_news(d3)
    save_snapshot(c, host="example.com", snapshot=s3, scan_id="scan3", diff=d3)
    doc3 = load_latest_snapshot(c, "example.com")
    assert doc3["no_diff_streak"] == 0


def test_www_ve_duz_host_ayni_anahtar():
    c = FakeCol()
    s = _snap(["https://www.example.com/"])
    save_snapshot(c, host="www.example.com", snapshot=s, scan_id="s1")
    assert load_latest_snapshot(c, "example.com") is not None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
