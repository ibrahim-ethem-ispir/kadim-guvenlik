"""
Kanıt-zinciri derinliği (exploit_chain ZİNCİR-2/3) testleri — SAF çekirdek + sahte-uc (ağ YOK).

NEDEN: Ayrık bulgu "zayıflık var" der; zincir "sistem düştü" kanıtını kurar. Bu testler
zincirin üç kritik disiplinini pinler:
  1) config-cred çözümleme ÇİFT şartlı (kullanıcı+parola) ve kanıt MASKELİ;
  2) login yanıtı yanlış-kimlik BASELINE'ından bağımsız imzayla sınıflanır (yanlış-kimlik
     'başarılı' görünüyorsa zincir KENDİ kendini REFUTE eder);
  3) metadata 2. adımda yalnız kimlik YOLU okunur — geçici kimlik ASLA çekilmez.

Çalıştır: python3 orchestrator/pipeline/test_chain_depth.py
"""

import asyncio
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.exploit_chain import (
    parse_config_credentials, classify_login_response, _mask_cred,
    run_lfi_credential_chain, run_ssrf_metadata_chain,
)

_WP_CONFIG = (
    "<?php\n"
    "define('DB_NAME', 'appdb');\n"
    "define('DB_USER', 'portal_user');\n"
    "define('DB_PASSWORD', 'Sup3rS3cret99!');\n"
    "define('DB_HOST', 'db.internal');\n"
)


# ---- SAF çekirdek ----

def test_parse_wp_define_pair_masked():
    creds = parse_config_credentials(_WP_CONFIG)
    assert len(creds) == 1 and creds[0]["source"] == "wp-define"
    assert "portal_user" not in creds[0]["username"] and "***" in creds[0]["username"]
    assert "Sup3rS3cret99" not in creds[0]["password"] and "***" in creds[0]["password"]


def test_parse_dsn_and_raw_mode():
    body = "DATABASE_URL=mysql://root:hunter2@db.internal:3306/app"
    creds = parse_config_credentials(body, mask=False)
    assert creds and creds[0]["username"] == "root" and creds[0]["password"] == "hunter2"
    masked = parse_config_credentials(body)
    assert "hunter2" not in str(masked)


def test_parse_requires_pair_not_single_key():
    # yalnız parola anahtarı — kullanıcı YOK → çift şart: kimlik iddiası ÜRETİLMEZ
    assert parse_config_credentials("DB_PASSWORD=onlypass123") == []
    assert parse_config_credentials("") == []


def test_mask_cred_never_leaks():
    assert _mask_cred("secretpass").startswith("se") and "cretpass" not in _mask_cred("secretpass")


def test_login_response_signatures():
    # (a) panel yönlendirmesi
    assert classify_login_response(302, {"Location": "/dashboard"}, "", "") == "redirect_panel"
    # login hata sayfasına yönlendirme ≠ başarı
    assert classify_login_response(302, {"Location": "/login?error=1"}, "", "") is None
    # (b) auth cookie
    assert classify_login_response(200, {"Set-Cookie": "session=abc; HttpOnly"},
                                   "<html>ok</html>", "<html>fail</html>") == "auth_cookie"
    # (c) oturum sayfası imzası
    assert classify_login_response(200, {}, "Hoş geldin <a>Çıkış</a>", "login form") == "session_page"
    # yanlış-kimlik gövdesiyle AYNI yanıt → başarı DEĞİL
    assert classify_login_response(200, {}, "login form", "login form") is None
    # hata metni → başarı DEĞİL
    assert classify_login_response(200, {"Set-Cookie": "session=x"},
                                   "Invalid credentials", "other") is None


# ---- ZİNCİR-2: LFI config → login (sahte-uc) ----

class _ChainTarget:
    """LFI config sızıntısı + login kabulü olan sahte uygulama (yanlış-kimlik RED).
    MockTransport handler deseni: tek httpx.Request alır."""
    def __init__(self):
        self.login_posts = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        body = (request.content or b"").decode("utf-8", "ignore")
        if request.method == "POST" and u.endswith("/login"):
            self.login_posts += 1
            if "username=portal_user" in body and "password=Sup3rS3cret99" in body:
                return httpx.Response(302, headers={"Location": "/dashboard"})
            return httpx.Response(200, text="<html>Invalid credentials</html>")
        if "wp-config.php" in u:
            return httpx.Response(200, text=_WP_CONFIG + "\n// tail padding for length")
        return httpx.Response(200, text="<html>normal sayfa</html>")


def test_lfi_credential_chain_full():
    t = _ChainTarget()
    client = httpx.AsyncClient(transport=httpx.MockTransport(t.handler))
    findings = asyncio.run(run_lfi_credential_chain(
        "https://shop.test/view?file=doc.txt", "file", client,
        login_endpoints=["https://shop.test/login"]))
    kinds = {f["kind"] for f in findings}
    assert "config_creds" in kinds and "cred_replay" in kinds
    replay = next(f for f in findings if f["kind"] == "cred_replay")
    assert replay["chain"] == "lfi→config_read→credential→login"
    assert "Sup3rS3cret99" not in replay["proof"] and "portal_user" not in replay["proof"]
    assert "KABUL EDİLDİ" in replay["proof"]
    assert replay["proof_bundle"]["verdict"] == "confirmed"   # adımlardan TÜRETİLDİ
    assert replay["fingerprint"]                            # tekrar-koşulabilir kimlik
    assert t.login_posts <= 4                                # 1 baseline + tavan 3 deneme
    asyncio.run(client.aclose())


def test_lfi_credential_chain_wrong_creds_no_replay_finding():
    class _NoLogin(_ChainTarget):
        def handler(self, request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200, text="<html>Invalid credentials</html>")
            return super().handler(request)

    t = _NoLogin()
    client = httpx.AsyncClient(transport=httpx.MockTransport(t.handler))
    findings = asyncio.run(run_lfi_credential_chain(
        "https://shop.test/view?file=doc.txt", "file", client,
        login_endpoints=["https://shop.test/login"]))
    kinds = {f["kind"] for f in findings}
    assert "config_creds" in kinds          # sızıntı kanıtı KALIR
    assert "cred_replay" not in kinds       # login KABUL EDİLMEDİ → 'sistem düştü' iddiası YOK
    asyncio.run(client.aclose())


def test_lfi_credential_chain_no_config_no_finding():
    def handler(request):
        return httpx.Response(200, text="<html>normal sayfa</html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    findings = asyncio.run(run_lfi_credential_chain(
        "https://shop.test/view?file=doc.txt", "file", client))
    assert findings == []
    asyncio.run(client.aclose())


# ---- ZİNCİR-3: SSRF → metadata kimlik yolu (sahte-uc) ----

def test_ssrf_metadata_chain_role_read_without_secret_pull():
    from urllib.parse import unquote_plus
    seen_targets = []

    def handler(request):
        u = unquote_plus(str(request.url))
        if "169.254.169.254" in u and u.rstrip("/").endswith("security-credentials"):
            seen_targets.append(u)
            return httpx.Response(200, text="my-web-role")
        if "instance-identity/document" in u:
            seen_targets.append(u)
            return httpx.Response(404, text="")
        seen_targets.append(u)
        return httpx.Response(200, text="ok")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    findings = asyncio.run(run_ssrf_metadata_chain(
        "https://api.test/fetch?url=http://x.test", "url", client))
    assert findings and findings[0]["kind"] == "metadata_identity"
    assert "my-web-role" in findings[0]["proof"]
    assert "ÇEKİLMEDİ" in findings[0]["proof"]              # sır toplama YOK — dürüst not
    assert findings[0]["proof_bundle"]["verdict"] == "confirmed"
    # KRİTİK DOKTRİN: rol ADI okundu ama kimlik bilgisi çekilmedi — alt yola inilmedi
    assert not any("security-credentials/my-web-role" in u for u in seen_targets)
    asyncio.run(client.aclose())


def test_metadata_role_name_fp_gate():
    from pipeline.exploit_chain import _is_plausible_role_name
    assert _is_plausible_role_name("my-web-role") is True
    assert _is_plausible_role_name("ecsTaskRole") is True
    assert _is_plausible_role_name("ok") is False          # sıradan yanıt ≠ rol adı
    assert _is_plausible_role_name("error") is False
    assert _is_plausible_role_name("<html>x</html>") is False


def main():
    tests = [
        test_parse_wp_define_pair_masked,
        test_parse_dsn_and_raw_mode,
        test_parse_requires_pair_not_single_key,
        test_mask_cred_never_leaks,
        test_login_response_signatures,
        test_lfi_credential_chain_full,
        test_lfi_credential_chain_wrong_creds_no_replay_finding,
        test_lfi_credential_chain_no_config_no_finding,
        test_ssrf_metadata_chain_role_read_without_secret_pull,
        test_metadata_role_name_fp_gate,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()