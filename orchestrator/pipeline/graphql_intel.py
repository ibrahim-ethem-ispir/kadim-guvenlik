"""
Kadim Güvenlik — GraphQL İstihbaratı / Introspection Keşfi (Bug Bounty T2-C)
============================================================================
Türkçe: OpenAPI keşfinin (openapi_discovery.py) GraphQL kardeşi. Modern API'lerin
büyük kısmı tek bir `/graphql` ucundan konuşur — REST crawl'ı buna KÖRDÜR (tek URL,
gövdede operasyon). Bu ucun gerçek yüzeyi, şemasında saklıdır:

  1) `/graphql` gibi küratörlü yolları proplar (POST introspection sorgusu).
  2) INTROSPECTION AÇIK ise → tüm Query/Mutation/Subscription operasyonları + argüman
     adları bedavaya gelir (yüzlerce endpoint'lik matris, tek istekle). Ayrıca
     "introspection prod'da açık" başlı başına bir bulgudur (CWE-200 bilgi ifşası —
     bug bounty programlarının kabul ettiği KANITLI bir yanlış yapılandırma).
  3) INTROSPECTION KAPALI ise → hafif bir `{__typename}` probu ile ucun GraphQL olup
     olmadığı yine de doğrulanır (yüzey var, şema kilitli — iyi hijyen sinyali).

Tasarım (openapi_discovery deseniyle birebir): parse çekirdeği SAF (stdlib) → izole
test; prob I/O katmanı ince, ASLA exception yükseltmez (keşif katmanı — tarama düşmez).

GÜVENLİK: şema yalnız OKUNUR. Operasyonların (özellikle mutation'ların) AKTİF testi
mevcut doğrulayıcı kapılarından geçer — burası yalnız keşif + introspection-açık tespiti.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("graphql-intel")

# Küratörlü GraphQL uç yolları — framework fark etmez (Apollo, Hasura, Graphene,
# graphql-yoga, WPGraphQL...). Sıra: pratikte en sık görülen önce.
GRAPHQL_PATHS: List[str] = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",         # Hasura varsayılanı
    "/query",
    "/gql",
    "/graphql/v1",
    "/api/gql",
    "/index.php?graphql",  # WPGraphQL
    "/graphql/console",
    "/graphiql",
]

# Şemadan çıkarılacak operasyon tavanı (dev şemalar bütçeyi yemesin).
_OP_CAP = 200

# Kompakt introspection sorgusu — kök operasyon tiplerinin adları + tüm tiplerin
# alanları (Query/Mutation tipinin alanları = operasyonlar) + argüman adları + dönüş
# tipi. Tam introspection'dan hafif (enumValues/inputFields/directives atlanır) ama
# operasyon matrisini çıkarmaya yeter.
INTROSPECTION_QUERY = (
    "query KadimIntrospect{__schema{"
    "queryType{name} mutationType{name} subscriptionType{name} "
    "types{name kind fields(includeDeprecated:true){name "
    "args{name} "
    "type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"
)

# Introspection kapalıyken ucun GraphQL olduğunu doğrulayan minimal prob.
_TYPENAME_PROBE = "{__typename}"


def _unwrap_type(type_ref: Any, _depth: int = 0) -> Optional[str]:
    """GraphQL tip sarmalını (NON_NULL/LIST → ofType zinciri) çözüp okunur adı döndür.
    '[User!]!' gibi bir dönüş tipini 'User' olarak sadeleştirir (kabaca; DAST için
    tip ADI yeterli). Derinlik sınırlı (bozuk/döngülü şemaya karşı)."""
    if not isinstance(type_ref, dict) or _depth > 8:
        return None
    name = type_ref.get("name")
    if name:
        return str(name)
    return _unwrap_type(type_ref.get("ofType"), _depth + 1)


def looks_like_graphql_response(data: Any) -> bool:
    """Bir JSON yanıtı GraphQL'e mi benziyor? (SAF — introspection kapalıyken uç
    doğrulaması için). GraphQL yanıtları ya `data` ya da GraphQL biçimli `errors`
    (message alanlı nesne listesi) taşır. Rastgele 200-JSON'u elemek için."""
    if not isinstance(data, dict):
        return False
    if "data" in data and isinstance(data.get("data"), (dict, type(None))):
        # __typename probu döndüyse en güçlü işaret
        d = data.get("data")
        if isinstance(d, dict) and "__typename" in d:
            return True
    errs = data.get("errors")
    if isinstance(errs, list) and errs:
        for e in errs:
            if isinstance(e, dict) and "message" in e:
                msg = str(e.get("message", "")).lower()
                # GraphQL motorlarının imza hata dilleri
                if any(sig in msg for sig in (
                    "graphql", "cannot query field", "must provide query",
                    "syntax error", "introspection", "querytype", "unknown operation")):
                    return True
        # `errors` yapısı GraphQL biçiminde ama mesaj eşleşmese de zayıf işaret:
        # yalnız `data`+`errors` birlikteliği tipiktir.
        if "data" in data:
            return True
    return False


def parse_introspection(payload: Any, endpoint_url: str, *,
                        cap: int = _OP_CAP) -> Dict[str, Any]:
    """Introspection yanıtından operasyon matrisi çıkar (SAF — I/O yok).

    Girdi tam yanıt (`{"data":{"__schema":{...}}}`) ya da doğrudan `__schema` sahibi
    olabilir. Çıktı:
      {"introspection_enabled": bool,
       "query_type", "mutation_type", "subscription_type",
       "operations": [{"name","op_type"(query|mutation|subscription),"args":[...],
                       "return_type","endpoint_url"}],
       "operation_count", "mutation_count"}
    Introspection kapalı/geçersizse introspection_enabled=False + boş matris.
    """
    empty = {"introspection_enabled": False, "query_type": None,
             "mutation_type": None, "subscription_type": None,
             "operations": [], "operation_count": 0, "mutation_count": 0}
    if not isinstance(payload, dict):
        return empty
    # Sarmalı aç: {"data":{"__schema":...}} ya da {"__schema":...}
    schema = None
    if isinstance(payload.get("data"), dict):
        schema = payload["data"].get("__schema")
    if schema is None:
        schema = payload.get("__schema")
    if not isinstance(schema, dict):
        return empty

    query_type = ((schema.get("queryType") or {}) or {}).get("name")
    mutation_type = ((schema.get("mutationType") or {}) or {}).get("name")
    subscription_type = ((schema.get("subscriptionType") or {}) or {}).get("name")

    # Kök operasyon tipi adı → op_type etiketi eşlemesi.
    root_types = {}
    if query_type:
        root_types[str(query_type)] = "query"
    if mutation_type:
        root_types[str(mutation_type)] = "mutation"
    if subscription_type:
        root_types[str(subscription_type)] = "subscription"

    operations: List[Dict[str, Any]] = []
    mutation_count = 0
    for t in (schema.get("types") or []):
        if not isinstance(t, dict):
            continue
        tname = t.get("name")
        op_type = root_types.get(str(tname))
        if not op_type:
            continue
        for f in (t.get("fields") or []):
            if not isinstance(f, dict) or not f.get("name"):
                continue
            args = [str(a.get("name")) for a in (f.get("args") or [])
                    if isinstance(a, dict) and a.get("name")]
            operations.append({
                "name": str(f["name"]),
                "op_type": op_type,
                "args": args,
                "return_type": _unwrap_type(f.get("type")),
                "endpoint_url": endpoint_url,
            })
            if op_type == "mutation":
                mutation_count += 1
            if len(operations) >= cap:
                break
        if len(operations) >= cap:
            break

    return {
        "introspection_enabled": True,
        "query_type": query_type,
        "mutation_type": mutation_type,
        "subscription_type": subscription_type,
        "operations": operations,
        "operation_count": len(operations),
        "mutation_count": mutation_count,
    }


async def discover_graphql(base_url: str, *, extra_paths: Optional[List[str]] = None,
                           auth_headers: Optional[List[str]] = None,
                           timeout: float = 10.0) -> Dict[str, Any]:
    """Kök üstünde GraphQL uç yollarını propla; introspection dene, olmazsa `{__typename}`
    ile ucu doğrula. auth_headers verilirse (login-arkası GraphQL) POST'lara eklenir.

    Döner: {"found", "endpoint_url", "introspection_enabled", "operations", "operation_count",
            "mutation_count", "query_type", "mutation_type", "note"} — bulunamazsa
    found=False + note. ASLA exception yükseltmez (keşif katmanı; tarama düşmez).
    """
    import httpx
    # Auth başlıklarını ayrıştır (endpoint_discovery ile aynı sözleşme).
    try:
        from .endpoint_discovery import _parse_header_list
        _auth = _parse_header_list(auth_headers)
    except Exception:
        _auth = {}

    result: Dict[str, Any] = {"found": False, "endpoint_url": None,
                              "introspection_enabled": False, "operations": [],
                              "operation_count": 0, "mutation_count": 0,
                              "query_type": None, "mutation_type": None,
                              "note": "not_found"}
    if not base_url:
        result["note"] = "invalid_base"
        return result

    candidates = list(dict.fromkeys((extra_paths or []) + GRAPHQL_PATHS))
    headers = {"Content-Type": "application/json",
               "Accept": "application/json", **_auth}
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False,
                                     follow_redirects=True) as client:
            for path in candidates:
                url = base_url.rstrip("/") + path
                # 1) Introspection dene.
                try:
                    r = await client.post(url, headers=headers,
                                          content=json.dumps({"query": INTROSPECTION_QUERY}))
                except Exception:
                    continue
                if r.status_code >= 500:
                    continue
                try:
                    data = r.json()
                except Exception:
                    data = None

                if isinstance(data, dict):
                    parsed = parse_introspection(data, url)
                    if parsed["introspection_enabled"]:
                        result.update({
                            "found": True, "endpoint_url": url,
                            "introspection_enabled": True,
                            "operations": parsed["operations"],
                            "operation_count": parsed["operation_count"],
                            "mutation_count": parsed["mutation_count"],
                            "query_type": parsed["query_type"],
                            "mutation_type": parsed["mutation_type"],
                            "note": "introspection_enabled",
                        })
                        logger.info(
                            f"🔮 GraphQL introspection AÇIK: {url} — "
                            f"{parsed['operation_count']} operasyon "
                            f"({parsed['mutation_count']} mutation)")
                        return result

                    # Introspection kapalı olabilir ama uç GraphQL olabilir.
                    if looks_like_graphql_response(data):
                        # Yine de `{__typename}` ile teyit et (introspection reddi
                        # başka bir yanıt biçimi de olabilir).
                        result.update({"found": True, "endpoint_url": url,
                                       "introspection_enabled": False,
                                       "note": "graphql_no_introspection"})
                        logger.info(f"🔮 GraphQL ucu (introspection kapalı): {url}")
                        return result

                # 2) Introspection net değilse minimal typename probu.
                try:
                    r2 = await client.post(url, headers=headers,
                                           content=json.dumps({"query": _TYPENAME_PROBE}))
                    d2 = r2.json()
                except Exception:
                    d2 = None
                if isinstance(d2, dict) and looks_like_graphql_response(d2):
                    result.update({"found": True, "endpoint_url": url,
                                   "introspection_enabled": False,
                                   "note": "graphql_no_introspection"})
                    logger.info(f"🔮 GraphQL ucu (introspection kapalı): {url}")
                    return result
    except Exception as e:
        result["note"] = f"probe_error: {type(e).__name__}"
        logger.debug(f"GraphQL keşfi atlandı ({base_url}): {e}")
    return result
