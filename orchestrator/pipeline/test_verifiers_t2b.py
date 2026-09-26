"""Türkçe: T2-B verifier genişletmesi (CORS/JWT/SSRF/XXE) birim testleri — SAF karar
çekirdekleri; ağ isteği YOK (JWT tamamen offline; CORS/SSRF/XXE'nin SAF parçaları).

Kök derdimiz: mevcut 5 verifier'ı (sqli/xss/lfi/redirect/ssti) sektör kapsamına çıkarmak.
Testler: CORS yansıma kararı (reflected+creds=high / null / *+creds / güvenli), JWT decode/
analyze/HMAC-sır kırma (offline), SSRF metadata imzası, classify/meta yönlendirmesi.

Çalıştır: python3 orchestrator/pipeline/test_verifiers_t2b.py
"""
import base64
import hashlib
import hmac
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.verification import (  # noqa: E402
    is_cors_vulnerable, decode_jwt, analyze_jwt, crack_jwt_secret, verify_jwt,
    detect_ssrf_signature, _url_like_params, classify_evidence_class,
    evidence_meta_for, CLASS_EVIDENCE_META,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _make_hs256(payload: dict, secret: str, alg: str = "HS256") -> str:
    """Test için gerçek HS256 token üret (crack testinin doğruluğu bağımsız kanıtlansın)."""
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = _b64url(hmac.new(secret.encode(), signing_input, algo).digest())
    return f"{h}.{p}.{sig}"


def _make_none_token(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


# ---------------- CORS ----------------

def test_cors_reflected_with_credentials_high():
    v, sev, reason = is_cors_vulnerable("https://evil.invalid", "https://evil.invalid", "true")
    assert v is True and sev == "high"


def test_cors_reflected_no_credentials_FP_kacinma():
    # Credentials yoksa reflected-origin sömürülemez → confirmed DEĞİL (FP disiplini)
    v, sev, _ = is_cors_vulnerable("https://evil.invalid", "https://evil.invalid", None)
    assert v is False


def test_cors_null_origin():
    v, sev, _ = is_cors_vulnerable("https://evil.invalid", "null", "true")
    assert v is True and sev == "high"


def test_cors_wildcard_with_credentials_reddedilir():
    # '*' + credentials tarayıcıca reddedilir → doğrudan sömürülemez → confirmed DEĞİL
    v, sev, _ = is_cors_vulnerable("https://evil.invalid", "*", "true")
    assert v is False


def test_cors_wildcard_no_creds_safe():
    # public API deseni — tek başına bulgu değil
    v, sev, _ = is_cors_vulnerable("https://evil.invalid", "*", None)
    assert v is False


def test_cors_fixed_origin_safe():
    v, _, _ = is_cors_vulnerable("https://evil.invalid", "https://trusted.com", "true")
    assert v is False


def test_cors_no_acao_safe():
    v, _, _ = is_cors_vulnerable("https://evil.invalid", None, None)
    assert v is False


# ---------------- JWT (offline) ----------------

def test_jwt_decode():
    tok = _make_hs256({"sub": "1", "admin": False}, "secret")
    dec = decode_jwt(tok)
    assert dec is not None
    assert dec["header"]["alg"] == "HS256"
    assert dec["payload"]["sub"] == "1"


def test_jwt_analyze_alg_none():
    tok = _make_none_token({"sub": "admin"})
    info = analyze_jwt(tok)
    assert info["valid_jwt"] and info["alg_none"] is True


def test_jwt_crack_weak_secret():
    tok = _make_hs256({"sub": "1"}, "secret")
    assert crack_jwt_secret(tok) == "secret"
    # güçlü sır kırılmaz
    strong = _make_hs256({"sub": "1"}, "a9F3!x_Zq82ncVm10ExtremelyStrongSecretValue")
    assert crack_jwt_secret(strong) is None


def test_jwt_crack_hs512():
    tok = _make_hs256({"sub": "1"}, "password", alg="HS512")
    assert crack_jwt_secret(tok) == "password"


def test_verify_jwt_cracked_critical():
    tok = _make_hs256({"sub": "1", "role": "user"}, "changeme")
    v = verify_jwt(tok)
    assert v.verified is True and v.severity == "critical"
    assert "kırıldı" in v.detail


def test_verify_jwt_alg_none_high():
    v = verify_jwt(_make_none_token({"admin": True}))
    assert v.verified is True and v.severity == "high"


def test_verify_jwt_strong_not_verified():
    tok = _make_hs256({"sub": "1"}, "b7!Kq92_Zx01LmProperlyRandomLongSecretNobodyGuesses")
    v = verify_jwt(tok)
    assert v.verified is False


def test_verify_jwt_invalid():
    assert verify_jwt("not.a.jwt").verified is False
    assert verify_jwt("").verified is False


# ---------------- SSRF ----------------

def test_ssrf_signature_metadata():
    aws = "ami-id\nami-launch-index\ninstance-type\niam/security-credentials/role"
    assert detect_ssrf_signature(aws) is not None
    gcp = '{"compute": {"instance": 1}, "computeMetadata": true}'
    assert detect_ssrf_signature(gcp) is not None


def test_ssrf_signature_random_safe():
    assert detect_ssrf_signature("<html><body>welcome home page</body></html>") is None
    assert detect_ssrf_signature("") is None


def test_url_like_params():
    ps = _url_like_params("https://x.com/fetch?url=http://a.com&page=2&image_url=y")
    assert "url" in ps and "image_url" in ps
    assert "page" not in ps


# ---------------- classify / meta yönlendirmesi ----------------

def test_classify_new_classes():
    assert classify_evidence_class({"cwe": ["CWE-942"]}) == "cors"
    assert classify_evidence_class({"cwe": ["CWE-347"]}) == "jwt"
    assert classify_evidence_class({"cwe": ["CWE-918"]}) == "ssrf"
    assert classify_evidence_class({"cwe": ["CWE-611"]}) == "xxe"
    assert classify_evidence_class({"title": "SSRF in url param"}) == "ssrf"
    assert classify_evidence_class({"title": "CORS misconfiguration"}) == "cors"


def test_meta_for_new_classes():
    for k in ("cors", "jwt", "ssrf", "xxe"):
        assert k in CLASS_EVIDENCE_META
        assert evidence_meta_for(k)["cwe"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
