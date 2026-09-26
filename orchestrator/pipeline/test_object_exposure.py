"""Türkçe: L4 — BRONZE kip (kimliksiz nesne ifşası / BOLA-lite) testleri. SAF; ağ YOK.

Kök: golden/silver IDOR kipleri A kimliği ister; dıştan yetkili testin çoğu unauth'tur →
path-param nesne yüzeyi keşfedilir/değerlenir ama TEST EDİLMEZDİ. BRONZE bu boşluğu kapatır.
Bu testler kararın (adjudicate_anonymous) FP kapılarını ve JSON/veri ayırt etmeyi (
_looks_like_data) doğrular — bir unauth prob için en pahalı şey yanlış-pozitiftir.

Çalıştır: python3 orchestrator/pipeline/test_object_exposure.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.idor_probe import (  # noqa: E402
    Measured, ObjectRef, adjudicate_anonymous, _looks_like_data,
    extract_object_refs, neighbor_values,
)


def _m(status, body, ctype="application/json", page_class=None):
    return Measured(status=status, body=body, page_class=page_class,
                    length=len(body), content_type=ctype)


_REF = ObjectRef(location="path", value="123", kind="numeric", index=2,
                 name="users", name_hint=True)


# ============================================================
# _looks_like_data — JSON/veri vs public HTML ayrımı (FP kalkanı)
# ============================================================
def test_looks_like_data_json_content_type():
    assert _looks_like_data(_m(200, '{"id":1}', "application/json")) is True
    assert _looks_like_data(_m(200, "x" * 40, "application/vnd.api+json")) is True


def test_looks_like_data_html_is_not_data():
    # HTML content-type → veri nesnesi DEĞİL (public blog/ürün sayfası FP kalkanı)
    assert _looks_like_data(_m(200, '{"looks":"jsonish"}', "text/html")) is False
    assert _looks_like_data(_m(200, "<html><body>post 1</body></html>", "text/html")) is False


def test_looks_like_data_body_shape_when_no_ctype():
    assert _looks_like_data(_m(200, '  {"id":1,"email":"a@x"}', "")) is True
    assert _looks_like_data(_m(200, "<!doctype html><p>merhaba</p>", "")) is False


# ============================================================
# adjudicate_anonymous — pozitif + FP kapıları
# ============================================================
def test_anon_positive_enumerable_distinct_json():
    owner = _m(200, '{"id":1,"email":"alice@x.com","name":"Alice Aaa","role":"user"}')
    n1 = _m(200, '{"id":2,"email":"bob@y.com","name":"Bob Bbb","role":"user"}')
    v = adjudicate_anonymous(owner, [n1], ref=_REF)
    assert v["is_idor"] is True
    assert v["tier"] == "probable"        # ASLA confirmed (kimliksizken niyet ispatlanamaz)
    assert v["walked"] == 1


def test_anon_fp_when_resource_protected():
    # Kimliksiz istek reddedildi (401/auth-wall) → iyi haber, ifşa YOK
    owner = _m(401, '{"error":"unauthorized, login required please now"}', page_class="auth_wall")
    v = adjudicate_anonymous(owner, [], ref=_REF)
    assert v["is_idor"] is False
    assert v["tier"] is None


def test_anon_fp_when_html_page():
    # Kimliksiz 200 ama HTML sayfa (public blog) → veri nesnesi değil → ifşa sayma
    owner = _m(200, "<html><body>Public article number one, welcome!</body></html>", "text/html")
    n1 = _m(200, "<html><body>Public article number two, welcome!</body></html>", "text/html")
    v = adjudicate_anonymous(owner, [n1], ref=_REF)
    assert v["is_idor"] is False


def test_anon_fp_when_static_shell():
    # Komşu id AYNI gövdeyi döndürüyor (id'ye duyarsız statik route / SPA shell) → ifşa değil
    body = '{"app":"shell","version":"1.0.0","routes":["/a","/b"],"static":true}'
    owner = _m(200, body)
    n1 = _m(200, body)      # birebir aynı → sim ~1.0 ≥ _SIM_DISTINCT_MAX → distinct DEĞİL
    v = adjudicate_anonymous(owner, [n1], ref=_REF)
    assert v["is_idor"] is False


def test_anon_fp_when_no_neighbor_substantive():
    # owner veri döndürdü ama komşular boş/hata → enumerasyon kanıtı yok → probable değil
    owner = _m(200, '{"id":1,"email":"a@x.com","name":"Alice Aaa","secret":"k"}')
    n_empty = _m(404, "not found", "application/json")
    v = adjudicate_anonymous(owner, [n_empty], ref=_REF)
    assert v["is_idor"] is False


# ============================================================
# Hedef seçim kapısı — yalnız SAYISAL + HASSAS-adlı koleksiyon (extract + neighbor)
# ============================================================
def test_target_gate_sensitive_numeric_selected():
    refs = extract_object_refs("https://x.com/api/users/123")
    assert refs and refs[0].kind == "numeric" and refs[0].name_hint is True
    assert neighbor_values(refs[0])  # enumere edilebilir


def test_target_gate_nonsensitive_or_paging_excluded():
    # 'products' hassas-ad listesinde YOK → sayısal path-id ref üretilmez (BRONZE atlar)
    assert extract_object_refs("https://x.com/products/2") == []
    # sayfalama gürültüsü (page) → hint yok, sayısal query ref üretilmez
    assert extract_object_refs("https://x.com/list?page=2") == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
