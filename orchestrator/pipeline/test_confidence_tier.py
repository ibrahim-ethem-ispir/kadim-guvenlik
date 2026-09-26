"""Türkçe: False-positive azaltma katmanı birim testleri — SAF çekirdek; ağ yok.

Kapsam:
- derive_confidence_tier / Evidence.effective_confidence_tier (kanıt güç kademesi)
- js_secrets.secret_strength (public-by-design anahtar + entropi elemesi)
- classify_evidence_class (CWE/başlık → doğrulanabilir sınıf)
- build_autonomous_scan_results tier sayımları (rapor sözleşmesi)

Çalıştır: python3 orchestrator/pipeline/test_confidence_tier.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.autonomous_engine import (  # noqa: E402
    Evidence, derive_confidence_tier, CONFIDENCE_TIERS,
)
from pipeline.js_secrets import secret_strength, scan_js_content, _shannon_entropy  # noqa: E402
from pipeline.verification import classify_evidence_class  # noqa: E402
from pipeline.autonomous_report import build_autonomous_scan_results  # noqa: E402


# ---------- derive_confidence_tier ----------

def test_verified_true_confirmed():
    assert derive_confidence_tier(verified=True, verification_method="reflected-xss",
                                  tool="poc_verify") == "confirmed"


def test_verified_false_unconfirmed():
    # Doğrulama DENENDİ ama geçmedi → olası false-positive
    assert derive_confidence_tier(verified=False, verification_method="reflected-xss",
                                  tool="poc_verify") == "unconfirmed"


def test_pathprobe_none_probable():
    assert derive_confidence_tier(verified=None, verification_method=None,
                                  tool="pathprobe") == "probable"


def test_nuclei_none_unconfirmed():
    # Ham nuclei severity — bağımsız kontrol yok → unconfirmed (manşeti şişirmez)
    assert derive_confidence_tier(verified=None, verification_method=None,
                                  tool="nuclei") == "unconfirmed"


def test_explicit_override_wins():
    assert derive_confidence_tier(verified=None, verification_method=None,
                                  tool="nuclei", explicit="confirmed") == "confirmed"
    # Geçersiz explicit yok sayılır → türetmeye düşer
    assert derive_confidence_tier(verified=None, verification_method=None,
                                  tool="nuclei", explicit="bogus") == "unconfirmed"


def test_evidence_to_dict_has_tier():
    ev = Evidence(title="x", severity="critical", cve=None, target="http://t",
                  proof="p", tool="nuclei", step=1)
    d = ev.to_dict()
    assert d["confidence_tier"] == "unconfirmed"
    ev2 = Evidence(title="x", severity="high", cve=None, target="http://t",
                   proof="p", tool="poc_verify", step=1, verified=True)
    assert ev2.to_dict()["confidence_tier"] == "confirmed"
    ev3 = Evidence(title="x", severity="high", cve=None, target="http://t",
                   proof="p", tool="js_secret_scan", step=1, confidence_tier="probable")
    assert ev3.to_dict()["confidence_tier"] == "probable"


def test_to_dict_ispat_paketi_yoksa_hic_yazilmaz():
    # Kanıt Sözleşmesi: bundle taşımayan bulgu dict'i BİREBİR eski hâlde (anahtar HİÇ yok).
    ev = Evidence(title="x", severity="high", cve=None, target="http://t",
                  proof="p", tool="nuclei", step=1)
    d = ev.to_dict()
    assert "proof_bundle" not in d and "proof_fingerprint" not in d


def test_to_dict_ispat_paketi_varsa_akar():
    # Tekrar-koşulabilir ispat + kararlı kimlik rapora/DB'ye ULAŞIR (eskiden zincirde düşüyordu).
    bundle = {"claim": "JWT forge @ /admin", "verdict": "confirmed", "fingerprint": "abc123def4567890"}
    ev = Evidence(title="x", severity="critical", cve=None, target="http://t",
                  proof="p", tool="exploit_chain", step=1, verified=True,
                  proof_bundle=bundle, proof_fingerprint="abc123def4567890")
    d = ev.to_dict()
    assert d["proof_bundle"]["verdict"] == "confirmed"
    assert d["proof_fingerprint"] == "abc123def4567890"
    assert d["confidence_tier"] == "confirmed"   # diğer eksen bozulmadı


# ---------- js_secrets.secret_strength ----------

def test_stripe_publishable_demoted():
    # pk_live_ = tasarımı gereği public → sır değil, düşük severity + unconfirmed
    tier, sev = secret_strength("pk_live_51Habc123DEF456ghi789", "api_key")
    assert tier == "unconfirmed" and sev == "low"


def test_recaptcha_site_key_demoted():
    tier, sev = secret_strength("6LcABCdefGHIjklMNOpqrSTUvwx1234567890abcd", "api_key")
    assert tier == "unconfirmed" and sev == "low"


def test_private_key_confirmed():
    tier, sev = secret_strength("-----BEGIN RSA PRIVATE KEY-----", "private_key")
    assert tier == "confirmed" and sev is None


def test_google_api_demoted():
    tier, sev = secret_strength("***SAHTE_TEST_ANAHTARI***", "google_api")
    assert tier == "unconfirmed" and sev == "low"


def test_high_entropy_api_key_probable():
    tier, sev = secret_strength("aZ9x7Kq2Wp5Lm8Rt3Vb6Yn1Cd4Ef0Gh", "api_key")
    assert tier == "probable" and sev is None


def test_low_entropy_password_unconfirmed():
    # Düşük entropili / kelime → gerçek rastgele sır değil
    tier, sev = secret_strength("password123", "password")
    assert tier == "unconfirmed" and sev == "medium"


def test_db_url_with_creds_probable():
    tier, _ = secret_strength("mongodb://admin:s3cr3tPwd@10.0.0.5:27017/db", "db_url")
    assert tier == "probable"


def test_db_url_no_creds_unconfirmed():
    tier, sev = secret_strength("mongodb://localhost:27017/appdb", "db_url")
    assert tier == "unconfirmed" and sev == "medium"


def test_entropy_orders():
    assert _shannon_entropy("aaaaaaaa") < _shannon_entropy("aZ9x7Kq2Wp5Lm8Rt")


def test_scan_js_content_carries_tier():
    # Google API key: bulgu üretilir ama unconfirmed + low (FP koruması)
    js = 'var k = "***SAHTE_TEST_ANAHTARI***";'
    fs = scan_js_content(js)
    g = [f for f in fs if f["validator"] == "google_api"]
    assert g and g[0]["confidence_tier"] == "unconfirmed" and g[0]["severity"] == "low"


# ---------- classify_evidence_class ----------

def test_classify_by_cwe():
    assert classify_evidence_class({"cwe": ["CWE-89"]}) == "sqli"
    assert classify_evidence_class({"cwe": ["CWE-79"]}) == "xss"
    assert classify_evidence_class({"cwe": ["CWE-22"]}) == "lfi"
    assert classify_evidence_class({"cwe": ["CWE-601"]}) == "open_redirect"
    assert classify_evidence_class({"cwe": ["CWE-1336"]}) == "ssti"


def test_classify_by_title():
    assert classify_evidence_class({"title": "Reflected Cross-Site Scripting"}) == "xss"
    assert classify_evidence_class({"title": "Open Redirect in next param"}) == "open_redirect"
    assert classify_evidence_class({"title": "Path Traversal"}) == "lfi"


def test_classify_unknown_none():
    # RCE/SSRF gibi deterministik doğrulayıcısı olmayan sınıf → None (unconfirmed kalır)
    assert classify_evidence_class({"title": "Remote Code Execution", "cwe": ["CWE-78"]}) is None
    assert classify_evidence_class({}) is None


# ---------- build_autonomous_scan_results tier sayımları ----------

def test_report_tier_counts():
    evidence = [
        {"severity": "critical", "title": "SQLi", "confidence_tier": "confirmed", "verified": True},
        {"severity": "critical", "title": "CVE-x", "confidence_tier": "unconfirmed", "verified": None},
        {"severity": "high", "title": "Exposure", "confidence_tier": "probable", "verified": None},
        {"severity": "high", "title": "FP-XSS", "confidence_tier": "unconfirmed", "verified": False},
    ]
    res = build_autonomous_scan_results(evidence, {})
    nuc = res["nuclei"]
    assert nuc["severity_counts"]["critical"] == 2       # toplam (geriye-uyumlu)
    assert nuc["confirmed_severity_counts"]["critical"] == 1  # manşet: yalnız confirmed+probable
    assert nuc["confirmed_severity_counts"]["high"] == 1
    assert nuc["tier_counts"] == {"confirmed": 1, "probable": 1, "unconfirmed": 2}
    # Her bulgu kademe/verified taşır
    assert all("confidence_tier" in f for f in nuc["findings"])


def test_report_replayable_sinyali_akar():
    # Kanıt Sözleşmesi: bundle taşıyan bulgu özete 'replayable' + fingerprint sızdırır;
    # taşımayan 'replayable': False (full bundle özete KONMAZ — token israfı).
    evidence = [
        {"severity": "critical", "title": "Forged JWT", "confidence_tier": "confirmed",
         "verified": True, "proof_bundle": {"verdict": "confirmed"}, "proof_fingerprint": "fp16chars000000x"},
        {"severity": "high", "title": "Plain nuclei", "confidence_tier": "unconfirmed"},
    ]
    findings = build_autonomous_scan_results(evidence, {})["nuclei"]["findings"]
    forged = next(f for f in findings if f["info"]["name"] == "Forged JWT")
    plain = next(f for f in findings if f["info"]["name"] == "Plain nuclei")
    assert forged["replayable"] is True and forged["proof_fingerprint"] == "fp16chars000000x"
    assert plain["replayable"] is False and plain["proof_fingerprint"] is None
    assert "proof_bundle" not in forged   # full paket özete taşınmaz


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
