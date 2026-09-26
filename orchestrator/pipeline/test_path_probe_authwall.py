"""PathProbe auth-duvarı / api_docs FP regresyonu — düz script (pytest yok).
Kullanıcı raporu: /api-docs 401 'token_expire' JSON medium bulgu sayılıyordu (FP)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from orchestrator.pipeline.path_probe import (
    _validate_json, _validate_api_schema, _looks_like_auth_error,
    _VALIDATORS, _STRONG_VALIDATORS, SENSITIVE_PATHS,
)

_p = _f = 0
def ok(c, m):
    global _p, _f
    if c: _p += 1
    else: _f += 1; print("  FAIL:", m)

TEB = ('{"result":null,"result_message":{"type":"token_expire","title":"Hata",'
       '"message":"Lütfen tekrar giriş yapınız."}}')

# Auth-duvarı algılama
ok(_looks_like_auth_error(TEB), "token_expire auth-wall")
ok(_looks_like_auth_error('{"error":"Unauthorized"}'), "Unauthorized auth-wall")
ok(_looks_like_auth_error('{"message":"authentication required"}'), "auth required")
ok(not _looks_like_auth_error('{"openapi":"3.0.0"}'), "openapi auth-wall DEĞİL")

# json validator artık auth-error reddeder (status fark etmez)
ok(_validate_json(401, "application/json", TEB) is False, "401 auth JSON reddedildi")
ok(_validate_json(200, "application/json", TEB) is False, "200 auth-error JSON de reddedildi")
ok(_validate_json(200, "application/json", '[{"id":1}]') is True, "normal array JSON geçer")

# api_schema: gerçek imza şart
ok(_validate_api_schema(401, "application/json", TEB) is False, "api_schema auth-error red")
ok(_validate_api_schema(200, "application/json", '{"swagger":"2.0","paths":{}}') is True, "swagger kabul")
ok(_validate_api_schema(200, "application/json", '{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}') is True, "openapi kabul")
ok(_validate_api_schema(200, "text/html", '<div id="swagger-ui"></div>') is True, "swagger-ui HTML kabul")
ok(_validate_api_schema(200, "application/json", '{"foo":"bar"}') is False, "rastgele JSON api_schema DEĞİL")

# api_docs katalog satırları artık api_schema kullanıyor (json değil)
api_docs_rows = [r for r in SENSITIVE_PATHS if r[1] == "api_docs"]
ok(len(api_docs_rows) >= 3, f"api_docs satır sayısı: {len(api_docs_rows)}")
ok(all(r[3] == "api_schema" for r in api_docs_rows), "tüm api_docs → api_schema validator")

# api_schema kayıtlı + güçlü (soft-404 baseline atlar)
ok("api_schema" in _VALIDATORS, "api_schema _VALIDATORS'ta")
ok("api_schema" in _STRONG_VALIDATORS, "api_schema güçlü set'te")

print(f"\n{'='*40}\nGeçti: {_p}  Kaldı: {_f}")
sys.exit(1 if _f else 0)
