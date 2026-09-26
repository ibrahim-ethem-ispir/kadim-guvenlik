"""Türkçe: JS sır taraması (js_secrets) birim testleri — SAF çekirdek; ağ yok.

Kök derdimiz: crawler JS indiriyor ama sızmış AWS key/JWT/API token'ı raporlamıyor.
Küratörlü regex + placeholder denetimi + maske ile güvenli sır avı.

Çalıştır: python3 orchestrator/pipeline/test_js_secrets.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.js_secrets import (  # noqa: E402
    scan_js_content, mask_secret, _is_placeholder,
    _find_sibling_username, _is_credential_context,
)

# Türkçe: Örnek "sahte" anahtarlar runtime'da parçalanarak üretilir. Neden: dosya
# metninde geçerli sır formatı geçmesin (secret tarayıcı false-positive'i), test
# anında ise dedektörün tanıdığı TAM format oluşsun.
SAHTE_AWS_KEY = "AKIA" + "JLKH7W74PJTKQBNA"
SAHTE_AWS_SECRET = "qMOyZLAtsqFnNuGDIEY" + "GGTMtGpnsRycJRlZkNIuk"
SAHTE_GH_TOKEN = "ghp_" + "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0"
SAHTE_GOOGLE_KEY = "AIza" + "SyD-1234567890AbCdEfGhIjKlMnOpQrStU"
SAHTE_CARD_TOKEN = "sk-live-" + "abcdefghijklmnop1234567890"
SAHTE_MASK_ORNEGI = "AKIA" + "1234567890ABCD"


def test_mask_short_and_long():
    assert mask_secret("abc") == "***"
    assert mask_secret(SAHTE_MASK_ORNEGI) == "AKIA***ABCD"


def test_aws_access_key_detected():
    js = f'const config = {{ accessKeyId: "{SAHTE_AWS_KEY}" }};'
    findings = scan_js_content(js)
    types = [f["secret_type"] for f in findings]
    assert "AWS Access Key" in types


def test_aws_secret_with_context():
    """40-char secret yakınında 'secret'/'aws' anahtar kelimesi varsa yakalanır."""
    js = f'secretAccessKey: "{SAHTE_AWS_SECRET}"'
    findings = scan_js_content(js)
    types = [f["secret_type"] for f in findings]
    assert "AWS Secret Key" in types


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMiJ9.abc123def456"
    js = f'const token = "{jwt}";'
    findings = scan_js_content(js)
    assert any(f["secret_type"] == "JWT Token" for f in findings)


def test_github_token_detected():
    js = f'token = "{SAHTE_GH_TOKEN}"'
    findings = scan_js_content(js)
    assert any(f["secret_type"] == "GitHub Personal Access Token" for f in findings)


def test_slack_webhook_detected():
    js = 'webhook = "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnop"'
    findings = scan_js_content(js)
    assert any(f["secret_type"] == "Slack Webhook URL" for f in findings)


def test_google_api_key_detected():
    js = f'key = "{SAHTE_GOOGLE_KEY}"'
    findings = scan_js_content(js)
    assert any(f["secret_type"] == "Google API Key" for f in findings)


def test_db_connection_string_detected():
    js = 'url = "mongodb://admin:secret123@db.internal:27017/app"'
    findings = scan_js_content(js)
    assert any(f["secret_type"] == "Database Connection String" for f in findings)


def test_placeholder_elendi():
    js = 'password = "your_password_here"; apiKey: "YOUR_API_KEY"'
    findings = scan_js_content(js)
    assert len(findings) == 0  # placeholder'lar sessizce düşer


def test_null_undefined_placeholder():
    js = 'apiKey: "null", token: "undefined", secret: "TODO"'
    assert scan_js_content(js) == []


def test_secret_masked_in_preview():
    js = f'apiKey = "{SAHTE_CARD_TOKEN}"'
    findings = scan_js_content(js)
    assert findings
    preview = findings[0]["line_text"]
    assert "sk-l***7890" in preview           # maskeli hali var
    assert SAHTE_CARD_TOKEN not in preview  # çıplak hali yok


def test_max_per_asset_cap():
    """Çok sayıda API token içeren bundle'da max 8 bulgu döner (gürültü tavanı)."""
    lines = []
    for i in range(20):
        lines.append(f'apiKey: "sk-test-{i:040d}"')
    js = "\n".join(lines)
    findings = scan_js_content(js)
    assert 1 <= len(findings) <= 8


def test_bos_input_tolere():
    assert scan_js_content("") == []
    assert scan_js_content(None) == []


def test_internal_ip_detected():
    js = 'baseUrl = "http://10.0.1.5:8080/api"; ip = "192.168.1.100"'
    findings = scan_js_content(js)
    types = [f["secret_type"] for f in findings]
    assert "Internal IP + Port" in types


# ============================================================
# HARDCODED CREDENTIAL zekası — kardeş username + login/form bağlamı
# ============================================================

def test_hardcoded_credential_with_sibling_username():
    """Login form defaultValues'unda username+password çifti: high/probable kalır,
    username çıkarılır, entropi-cezası uygulanmaz (insan şifresi düşük-entropili)."""
    js = ('useForm({defaultValues:{userNameOrEmail:"superadmin",'
          'password:"SuperAdmin123!",mode:"onBlur"}})')
    findings = scan_js_content(js, "https://panel.example.com/app.js")
    pw = [f for f in findings if f["secret_type"] == "Password/Secret (KV)"]
    assert pw, "password bulgusu gelmedi"
    f = pw[0]
    assert f["username"] == "superadmin"
    assert f["severity"] == "high"          # medium'a DÜŞMEMELİ
    assert f["confidence_tier"] == "probable"  # unconfirmed'a DÜŞMEMELİ
    assert f["value_masked"] == "Supe***123!"
    assert "superadmin" in f["line_text"]   # username bağlamda görünür


def test_password_no_context_downgraded():
    """Bağlam yoksa düşük-entropili password hâlâ unconfirmed/medium'a düşer."""
    js = 'var p = { password: "shortpass" };'
    findings = scan_js_content(js)
    pw = [f for f in findings if f["secret_type"] == "Password/Secret (KV)"]
    assert pw
    assert pw[0]["confidence_tier"] == "unconfirmed"
    assert pw[0]["severity"] == "medium"
    assert pw[0]["username"] is None


def test_password_form_context_only_boosts():
    """Username yok ama defaultValues/login bağlamı var → probable/high."""
    js = 'useForm({defaultValues:{password:"Kisa123!"}})'
    findings = scan_js_content(js)
    pw = [f for f in findings if f["secret_type"] == "Password/Secret (KV)"]
    assert pw
    assert pw[0]["confidence_tier"] == "probable"
    assert pw[0]["severity"] == "high"


def test_find_sibling_username_variants():
    body = 'email:"admin@corp.com",password:"x"'
    assert _find_sibling_username(body, body.index("password")) == "admin@corp.com"
    body2 = 'user:"root", pwd:"y"'
    assert _find_sibling_username(body2, body2.index("pwd")) == "root"
    assert _find_sibling_username('password:"z"', 0) is None


def test_credential_context_markers():
    assert _is_credential_context('defaultValues:{password:"x"}', 20)
    assert _is_credential_context('loginForm password="x"', 15)
    assert not _is_credential_context('var apiKey = "abc";', 10)


# ============================================================
# TEMA 3.1 — reveal (unmask) yolu
# ============================================================

def test_reveal_off_by_default_no_raw():
    """Varsayılan tarama HAM değer/ham satır SIZDIRMAZ (regresyon kalkanı)."""
    js = 'const u="superadmin"; const password="SuperSecret123!";'
    findings = scan_js_content(js)
    assert findings
    for f in findings:
        assert "value" not in f
        assert "line_text_raw" not in f
        # value_masked ham parolayı içermez
        assert "SuperSecret123!" not in f["value_masked"]


def test_reveal_on_carries_raw_value():
    """reveal=True → maskeyle birlikte HAM value + maskesiz line_text_raw taşınır."""
    js = 'const u="superadmin"; const password="SuperSecret123!";'
    findings = scan_js_content(js, reveal=True)
    cred = [f for f in findings if f.get("value") == "SuperSecret123!"]
    assert cred, "ham parola reveal modunda dönmeli"
    f = cred[0]
    assert f["value_masked"] == mask_secret("SuperSecret123!")
    assert "SuperSecret123!" in (f.get("line_text_raw") or "")
    # maskeli line_text ham parolayı HÂLÂ içermez
    assert "SuperSecret123!" not in f["line_text"]


def test_reveal_mask_stays_masked_line_text():
    """reveal açık olsa bile maskeli alanlar maskeli kalır (DB bu alanları yazar)."""
    js = f'aws_secret_key = "{SAHTE_AWS_SECRET}"'
    findings = scan_js_content(js, reveal=True)
    assert findings
    for f in findings:
        assert SAHTE_AWS_SECRET not in f["value_masked"]
        assert SAHTE_AWS_SECRET not in f["line_text"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
