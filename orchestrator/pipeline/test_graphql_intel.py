"""Türkçe: GraphQL introspection istihbaratı (graphql_intel) birim testleri — SAF
parse çekirdeği; ağ isteği YOK.

Kök derdimiz: modern API tek `/graphql` ucundan konuşur; REST crawl kördür. Introspection
açıksa TÜM operasyon+argüman matrisi tek istekle gelir + "introspection prod'da açık"
başlı başına bulgudur. Testler: tip sarmalı çözme (NON_NULL/LIST), query/mutation ayrımı,
introspection-kapalı tespiti, soft-200 elemesi, cap.

Çalıştır: python3 orchestrator/pipeline/test_graphql_intel.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.graphql_intel import (  # noqa: E402
    parse_introspection, looks_like_graphql_response, _unwrap_type,
)


_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "user",
                         "args": [{"name": "id"}],
                         "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                        {"name": "search",
                         "args": [{"name": "q"}, {"name": "limit"}],
                         "type": {"kind": "LIST", "name": None,
                                  "ofType": {"kind": "OBJECT", "name": "Result",
                                             "ofType": None}}},
                    ],
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "deleteUser",
                         "args": [{"name": "id"}],
                         "type": {"kind": "NON_NULL", "name": None,
                                  "ofType": {"kind": "SCALAR", "name": "Boolean",
                                             "ofType": None}}},
                    ],
                },
                {"name": "User", "kind": "OBJECT", "fields": []},
            ],
        }
    }
}


def test_unwrap_type_zinciri():
    # [Result] → Result (LIST sarmalı çözülür)
    t = {"kind": "LIST", "name": None,
         "ofType": {"kind": "OBJECT", "name": "Result", "ofType": None}}
    assert _unwrap_type(t) == "Result"
    # Boolean! → Boolean (NON_NULL sarmalı)
    t2 = {"kind": "NON_NULL", "name": None,
          "ofType": {"kind": "SCALAR", "name": "Boolean", "ofType": None}}
    assert _unwrap_type(t2) == "Boolean"
    assert _unwrap_type({"name": "User", "ofType": None}) == "User"
    assert _unwrap_type(None) is None


def test_introspection_parse_operasyonlar():
    out = parse_introspection(_SCHEMA, "https://x.com/graphql")
    assert out["introspection_enabled"] is True
    assert out["query_type"] == "Query"
    assert out["mutation_type"] == "Mutation"
    assert out["operation_count"] == 3
    assert out["mutation_count"] == 1
    ops = {o["name"]: o for o in out["operations"]}
    assert ops["user"]["op_type"] == "query"
    assert ops["user"]["args"] == ["id"]
    assert ops["user"]["return_type"] == "User"
    assert ops["search"]["args"] == ["q", "limit"]
    assert ops["search"]["return_type"] == "Result"
    assert ops["deleteUser"]["op_type"] == "mutation"
    assert ops["deleteUser"]["return_type"] == "Boolean"
    # Her operasyon uç URL'sini taşır (verifier hazır bulur)
    assert ops["user"]["endpoint_url"] == "https://x.com/graphql"


def test_bare_schema_de_kabul():
    # Sarmalsız (__schema doğrudan) girdi de çalışır
    bare = {"__schema": _SCHEMA["data"]["__schema"]}
    out = parse_introspection(bare, "https://x.com/graphql")
    assert out["introspection_enabled"] is True
    assert out["operation_count"] == 3


def test_introspection_kapali_bos_doner():
    # Introspection reddedildi (yaygın prod hijyeni) → boş matris, enabled=False
    denied = {"errors": [{"message": "GraphQL introspection is not allowed"}]}
    out = parse_introspection(denied, "https://x.com/graphql")
    assert out["introspection_enabled"] is False
    assert out["operation_count"] == 0


def test_cap_siniri():
    many = {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": None,
        "subscriptionType": None,
        "types": [{"name": "Query", "kind": "OBJECT",
                   "fields": [{"name": f"f{i}", "args": [],
                               "type": {"name": "String", "ofType": None}}
                              for i in range(50)]}],
    }}}
    out = parse_introspection(many, "https://x.com/graphql", cap=10)
    assert out["operation_count"] == 10


def test_gecersiz_girdi():
    assert parse_introspection({"status": "ok"}, "https://x.com/graphql")["operation_count"] == 0
    assert parse_introspection([1, 2], "https://x.com/graphql")["introspection_enabled"] is False
    assert parse_introspection(None, "https://x.com/graphql")["operation_count"] == 0


def test_graphql_yanit_tespiti():
    # __typename probu döndü → GraphQL
    assert looks_like_graphql_response({"data": {"__typename": "Query"}})
    # GraphQL biçimli hata mesajı → GraphQL
    assert looks_like_graphql_response({"errors": [{"message": "Cannot query field 'x'"}]})
    assert looks_like_graphql_response({"data": None, "errors": [{"message": "boom"}]})
    # Rastgele JSON (soft-200) → GraphQL DEĞİL
    assert not looks_like_graphql_response({"status": "ok", "result": 1})
    assert not looks_like_graphql_response([1, 2, 3])
    assert not looks_like_graphql_response("hello")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
