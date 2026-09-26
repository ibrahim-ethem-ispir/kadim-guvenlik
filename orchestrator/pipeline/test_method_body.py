"""Türkçe: P0-B — HTTP method + gövde kapsamı testleri (attack_hypothesis gövde
alanları, verification gövde enjeksiyon çekirdeği, method_probe yorumu). SAF;
ağ isteği YOK (doğrulayıcıların I/O katmanı değil, karar/üretim çekirdeği pinlenir).

Kök derdimiz: doğrulayıcılar yalnız GET query-param dünyasında yaşıyordu; gerçek
API zafiyetlerinin çoğu POST/PUT/JSON gövdesinde. Bu testler gövde hattının
sözleşmesini pinler.

Çalıştır: python3 orchestrator/pipeline/test_method_body.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.attack_hypothesis import (  # noqa: E402
    parse_hypotheses, seed_hypotheses_from_endpoints, AttackHypothesis,
)
from pipeline.verification import (  # noqa: E402
    body_params_dict, build_injected_bodies,
)
from pipeline.method_probe import interpret_method_matrix  # noqa: E402


# ---------- parse_hypotheses: method + gövde ----------

def test_post_govde_hipotezi_kabul():
    raw = [{
        "url": "http://x/api/transfer", "vuln_class": "sqli", "param": "amount",
        "method": "POST",
        "body_params": {"amount": "100", "account": "1"},
        "body_kind": "json",
    }]
    hyps = parse_hypotheses(raw)
    assert len(hyps) == 1
    h = hyps[0]
    assert h.method == "post"
    assert h.body_params == (("amount", "100"), ("account", "1"))
    assert h.body_kind == "json"


def test_bilinmeyen_method_gete_duser():
    raw = [{"url": "http://x?a=1", "vuln_class": "sqli", "method": "HACK"}]
    hyps = parse_hypotheses(raw)
    assert hyps[0].method == "get"
    assert hyps[0].body_params is None


def test_govde_metodu_govdesiz_duser():
    """POST hipotezi ama body_params yok → enjekte edilecek yer yok → sessizce düşer
    (kanıtlanamayacak hipotez kuyruğu şişirmesin)."""
    raw = [{"url": "http://x/api", "vuln_class": "sqli", "method": "post"}]
    assert parse_hypotheses(raw) == []


def test_get_govde_tasimaz():
    raw = [{"url": "http://x?a=1", "vuln_class": "sqli", "method": "get",
            "body_params": {"x": "1"}}]
    hyps = parse_hypotheses(raw)
    assert hyps[0].body_params is None


def test_ayni_url_farkli_method_ayri_hipotez():
    """GET temiz ama POST gövde vulnerable olabilir — ikisi ayrı hipotez (dedup
    method'u içerir)."""
    raw = [
        {"url": "http://x/item", "vuln_class": "sqli", "method": "get",
         "param": "id"},
        {"url": "http://x/item", "vuln_class": "sqli", "method": "post",
         "body_params": {"id": "1"}},
    ]
    hyps = parse_hypotheses(raw)
    assert len(hyps) == 2
    assert {h.method for h in hyps} == {"get", "post"}


# ---------- seed: form + OpenAPI tohumları ----------

def test_form_post_tohumu():
    """Crawler form çıkardı (action+method+inputs) → gövde hipotezi tohumlanır."""
    forms = [{
        "action": "http://x/search", "method": "POST",
        "inputs": ["q", "csrf"],
    }]
    hyps = seed_hypotheses_from_endpoints([], forms=forms)
    assert len(hyps) == 1
    h = hyps[0]
    assert h.vuln_class == "xss"          # 'q' → xss kuralı
    assert h.method == "post"
    assert dict(h.body_params) == {"q": "1", "csrf": "1"}
    assert h.body_kind == "form"


def test_form_get_tohum_uretmez():
    """GET formlar URL'e dönüşür (crawl zaten havuza katar) — gövde tohumu YOK."""
    forms = [{"action": "http://x/s", "method": "get", "inputs": ["q"]}]
    assert seed_hypotheses_from_endpoints([], forms=forms) == []


def test_openapi_post_tohumu():
    """OpenAPI matrisi method+parametreyi bedavaya verir → JSON gövde tohumu."""
    api = [{"url": "http://x/api/users", "method": "post", "params": ["name", "email"]}]
    hyps = seed_hypotheses_from_endpoints([], api_endpoints=api)
    assert len(hyps) == 1
    h = hyps[0]
    assert h.vuln_class == "ssti"         # 'name' → ssti kuralı (ilk eşleşen)
    assert h.method == "post"
    assert h.body_kind == "json"
    assert dict(h.body_params)["email"] == "kadim@example.com"


def test_openapi_get_url_kurulumu():
    """GET OpenAPI endpoint'i sorgusuzsa parametreler boş değerle URL'ye kurulur."""
    api = [{"url": "http://x/api/items", "method": "get", "params": ["id"]}]
    hyps = seed_hypotheses_from_endpoints([], api_endpoints=api)
    assert len(hyps) == 1
    assert hyps[0].url == "http://x/api/items?id="
    assert hyps[0].vuln_class == "sqli"


def test_seed_uc_kaynak_birlesik_butce():
    """Üç kaynak birlikte max_items tavanına uyar (bütçe patlamaz)."""
    eps = [f"http://x/i?id={i}" for i in range(10)]
    forms = [{"action": "http://x/f", "method": "post", "inputs": ["q"]}]
    api = [{"url": "http://x/a", "method": "put", "params": ["file"]}]
    hyps = seed_hypotheses_from_endpoints(eps, forms=forms, api_endpoints=api,
                                          max_items=5)
    assert len(hyps) == 5


# ---------- verification: gövde enjeksiyon çekirdeği ----------

def test_body_params_dict_donusturme():
    assert body_params_dict((("a", "1"), ("b", "2"))) == {"a": "1", "b": "2"}
    assert body_params_dict(None) == {}
    assert body_params_dict(()) == {}
    assert body_params_dict("çöp") == {}


def test_build_injected_bodies_append():
    """XSS/SSTI/SQLi-append: payload değerin SONUNA eklenir (bağlam korunur)."""
    bodies = build_injected_bodies({"a": "1", "b": "2"}, "PAY")
    assert ({"a": "1PAY", "b": "2"}, "a") in bodies
    assert ({"a": "1", "b": "2PAY"}, "b") in bodies
    assert len(bodies) == 2


def test_build_injected_bodies_replace():
    """LFI/redirect: değer payload ile EZİLİR (değerin kendisi dosya yolu olmalı)."""
    bodies = build_injected_bodies({"file": "home"}, "../../etc/passwd", replace=True)
    assert bodies == [({"file": "../../etc/passwd"}, "file")]


def test_build_injected_bodies_only_param_ve_tavan():
    bodies = build_injected_bodies({"a": "1", "b": "2", "c": "3"}, "P", only_param="c")
    assert bodies == [({"a": "1", "b": "2", "c": "3P"}, "c")]
    many = {f"p{i}": str(i) for i in range(10)}
    assert len(build_injected_bodies(many, "P", max_params=3)) == 3


def test_build_injected_bodies_bos():
    assert build_injected_bodies({}, "PAY") == []


# ---------- method_probe: matris yorumu ----------

def test_access_gap_get403_post200():
    """GET 403 ama POST 200 → method-swap erişim boşluğu (CWE-285 kanıtı)."""
    r = interpret_method_matrix({"GET": 403, "POST": 200, "PUT": 403, "DELETE": 403})
    assert r == {"kind": "access_gap", "method": "POST", "status": 200, "blocked_get": 403}


def test_access_gap_get401_put200():
    r = interpret_method_matrix({"GET": 401, "PUT": 204})
    assert r and r["kind"] == "access_gap" and r["method"] == "PUT"


def test_body_only_sinyali():
    """GET 405 + POST 200 → endpoint gövdeye özel (P0-B tohum sinyali, bulgu değil)."""
    r = interpret_method_matrix({"GET": 405, "POST": 200})
    assert r == {"kind": "body_only", "method": "POST", "status": 200}


def test_normal_matris_sinyalsiz():
    assert interpret_method_matrix({"GET": 200, "POST": 200}) is None
    assert interpret_method_matrix({"GET": 403, "POST": 403}) is None
    assert interpret_method_matrix({"GET": 0, "POST": 200}) is None  # ölçüm hatası
    assert interpret_method_matrix({}) is None


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
