"""Türkçe: Swagger/OpenAPI keşfi (openapi_discovery) birim testleri — SAF parse
çekirdeği; ağ isteği YOK.

Kök derdimiz: API dokümanı açıksa HER endpoint+method+parametre bedavaya gelir.
Testler: 2.0/3.x ayrımı, path-parametre doldurma, query-parametre çıkarma,
soft-200 elemesi (her JSON swagger değildir), servers/basePath kök çözümü.

Çalıştır: python3 orchestrator/pipeline/test_openapi_discovery.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.openapi_discovery import parse_openapi, _is_openapi_doc  # noqa: E402


_SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Test API"},
    "host": "api.example.com",
    "basePath": "/v1",
    "paths": {
        "/users/{userId}/orders": {
            "get": {
                "parameters": [
                    {"name": "userId", "in": "path", "type": "integer"},
                    {"name": "status", "in": "query", "type": "string"},
                ],
            },
            "post": {
                "parameters": [{"name": "payload", "in": "body"}],
            },
        },
        "/health": {"get": {}},
        "/internal": {"head": {}},   # head/options atlanmalı
    },
}

_OPENAPI3 = {
    "openapi": "3.0.2",
    "info": {"title": "Modern API"},
    "servers": [{"url": "https://api.example.com"}],
    "paths": {
        "/items": {
            "get": {"parameters": [{"name": "q", "in": "query"}]},
            "delete": {},
        },
    },
}


def test_dogrulama_yalniz_gercek_openapi():
    assert _is_openapi_doc(_SWAGGER2)
    assert _is_openapi_doc(_OPENAPI3)
    assert not _is_openapi_doc({"status": "ok"})          # soft-200 JSON — değil
    assert not _is_openapi_doc([1, 2])
    assert not _is_openapi_doc({"openapi": "2.9"})


def test_swagger2_parse():
    out = parse_openapi(_SWAGGER2, "https://example.com/swagger.json")
    assert out["title"] == "Test API"
    eps = out["endpoints"]
    # GET: path-param örnek değerle doldu + query param URL'ye eklendi
    get_ep = next(e for e in eps if e["method"] == "get" and "orders" in e["url"])
    assert "https://api.example.com/v1/users/1/orders" in get_ep["url"]
    assert "status=" in get_ep["url"]
    assert get_ep["params"] == ["status"]
    # POST: gövde adayı — URL sade, method bilgisi taşınır (P0-B hattı)
    post_ep = next(e for e in eps if e["method"] == "post")
    assert post_ep["url"].endswith("/users/1/orders")
    # head atlandı
    assert not any(e["method"] == "head" for e in eps)


def test_openapi3_parse():
    out = parse_openapi(_OPENAPI3, "https://example.com/openapi.json")
    assert out["version"].startswith("3")
    eps = out["endpoints"]
    get_ep = next(e for e in eps if e["method"] == "get")
    assert get_ep["url"] == "https://api.example.com/items?q="
    del_ep = next(e for e in eps if e["method"] == "delete")
    assert del_ep["url"] == "https://api.example.com/items"


def test_servers_goreli_kok_cozumu():
    doc = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api"}],   # göreli kök — prob URL'sine göre çözülür
        "paths": {"/x": {"get": {}}},
    }
    out = parse_openapi(doc, "https://example.com/v3/api-docs")
    assert out["endpoints"][0]["url"] == "https://example.com/api/x"


def test_gecersiz_dokuan_bos_doner():
    out = parse_openapi({"foo": "bar"}, "https://example.com/swagger.json")
    assert out["endpoint_count"] == 0


def test_cap_siniri():
    doc = {"openapi": "3.0.0", "paths": {f"/p{i}": {"get": {}} for i in range(50)}}
    out = parse_openapi(doc, "https://example.com/openapi.json", cap=10)
    assert out["endpoint_count"] == 10


def test_path_parametresi_sayisal_ayrimi():
    doc = {"openapi": "3.0.0",
           "paths": {"/users/{id}/files/{slug}": {"get": {}}}}
    out = parse_openapi(doc, "https://example.com/openapi.json")
    # id → sayısal (1), slug → metin (test)
    assert out["endpoints"][0]["url"] == "https://example.com/users/1/files/test"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
