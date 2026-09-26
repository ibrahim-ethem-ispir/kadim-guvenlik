"""Türkçe: K1 — kanıt-güdümlü türetme + satır normalizasyonu + signature-validator
birim testleri (SAF; ağ I/O yok, HTTP gerektirenler MockTransport ile).

Neden: PathProbe artık hedefe göre kendini genişletir. Bu testler, "aday üretimi"
katmanının (şablon/kanıt/imza) deterministik ve güvenli kaldığını sabitler —
yeni katmanlar yargıyı (validator) bozmamalı, yalnız daha akıllı aday üretmeli.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx  # noqa: E402

from pipeline import path_probe  # noqa: E402
from pipeline.path_probe import (  # noqa: E402
    _normalize_row,
    _validate_from_signature,
    _paths_from_robots,
    _paths_from_git_config,
    _backup_siblings,
    _paths_from_dir_listing,
)


# ---------------------------------------------------------------------------
# Task 1 — satır normalizasyonu + signature-validator
# ---------------------------------------------------------------------------
def test_normalize_4_ve_5_tuple():
    """4-tuple (mevcut K0/K1) → source='curated', signature=None. 5-tuple (K2/K3) meta korunur."""
    p, c, s, v, m = _normalize_row(("/x", "cat", "high", "generic"))
    assert (p, c, s, v) == ("/x", "cat", "high", "generic")
    assert m["source"] == "curated" and m["signature"] is None

    row5 = ("/y", "config_exposure", "low", "signature",
            {"signature": {"must_contain_any": ["a"]}, "source": "llm"})
    p, c, s, v, m = _normalize_row(row5)
    assert v == "signature" and m["source"] == "llm"
    assert m["signature"]["must_contain_any"] == ["a"]


def test_signature_validator_kurallari():
    """LLM/hafıza imzası → deterministik kontrol. must_not_contain > must_contain_any > min_length."""
    val = _validate_from_signature({
        "must_contain_any": ["DB_", "define("],
        "must_not_contain": ["<html"],
        "min_length": 10,
    })
    assert val(200, "", "DB_HOST=localhost app secret here") is True
    assert val(200, "", "<html>DB_HOST=x</html>") is False          # must_not_contain tuttu
    assert val(200, "", "short") is False                            # min_length + anahtar yok
    assert val(200, "", "long enough text but no keys at all here") is False  # must_contain_any yok


def test_signature_validator_bos_imza_generic():
    """İmza None/boş → generic davranış (200 + gövde var)."""
    val = _validate_from_signature(None)
    assert val(200, "", "bir şey") is True
    assert val(200, "", "   ") is False


def test_signature_must_contain_all():
    val = _validate_from_signature({"must_contain_all": ["foo", "bar"]})
    assert val(200, "", "foo and bar here") is True
    assert val(200, "", "only foo here") is False


# ---------------------------------------------------------------------------
# Task 3 — kanıt-güdümlü türetme (saf parse; I/O yok)
# ---------------------------------------------------------------------------
def test_robots_disallow_yol_uretir():
    out = _paths_from_robots("User-agent: *\nDisallow: /admin/\nDisallow: /secret\nAllow: /public")
    assert "/admin/" in out and "/secret" in out
    assert "/public" not in out  # Allow türetilmez


def test_robots_wildcard_ve_bos_elenir():
    out = _paths_from_robots("Disallow: /\nDisallow:\nDisallow: *")
    assert "/" not in out and "" not in out and "*" not in out


def test_git_config_repo_yedegi():
    cfg = '[remote "origin"]\n\turl = git@github.com:acme/portal.git\n'
    out = _paths_from_git_config(cfg)
    assert "/portal.zip" in out and "/portal.tar.gz" in out


def test_git_config_https_remote():
    cfg = '[remote "origin"]\n\turl = https://gitlab.com/team/webapp.git'
    out = _paths_from_git_config(cfg)
    assert "/webapp.zip" in out


def test_yedek_kardesleri():
    out = _backup_siblings("/config.php")
    for suf in (".bak", "~", ".old", ".save", ".orig", ".dist", ".swp"):
        assert f"/config.php{suf}" in out


def test_dizin_listeleme_href():
    html = '<title>Index of /backup</title><a href="db.sql">db.sql</a><a href="../">up</a>'
    out = _paths_from_dir_listing(html, "/backup")
    assert "/backup/db.sql" in out
    assert not any(".." in p for p in out)  # üst dizin bağı türetilmez


def test_dizin_listeleme_degilse_bos():
    assert _paths_from_dir_listing("<html>normal sayfa</html>", "/x") == []


# ---------------------------------------------------------------------------
# Task 4 — iki-dalga + önce-değer sıralama (MockTransport)
# ---------------------------------------------------------------------------
def _mk_transport(routes):
    """path -> (status, body) sözlüğünden httpx.MockTransport üret. Bilinmeyen yol → 404."""
    def handler(request):
        st, body = routes.get(request.url.path, (404, "not found"))
        return httpx.Response(st, text=body)
    return httpx.MockTransport(handler)


_SYMFONY_DB_BODY = ("all:\n  propel:\n    class: sfPropelDatabase\n    param:\n"
                    "      hostspec: db.example.local\n      username: portal_user\n"
                    "      password: Sup3rS3cret\n")


def test_kritik_yol_bulunur_ve_ilk_sirada():
    routes = {"/symfony/config/databases.yml": (200, _SYMFONY_DB_BODY)}
    res = asyncio.run(path_probe._probe_with_transport("x.com", _mk_transport(routes)))
    paths = [f["path"] for f in res["findings"]]
    assert "/symfony/config/databases.yml" in paths
    assert res["findings"][0]["severity"] == "critical"
    # source alanı taşınıyor
    assert res["findings"][0]["source"] in ("curated", "template", "memory", "evidence", "llm")


def test_extra_paths_signature_ile_bulgu():
    """K2/K3 enjekte edilen signature yol → deterministik doğrulanır."""
    routes = {"/custom/secret.conf": (200, "api_token = ABC123XYZ very long content here ok")}
    extra = [("/custom/secret.conf", "credential_exposure", "high", "signature",
              {"signature": {"must_contain_any": ["api_token"], "must_not_contain": ["<html"],
                             "min_length": 10}, "source": "llm"})]
    res = asyncio.run(path_probe._probe_with_transport("x.com", _mk_transport(routes), extra_paths=extra))
    got = [f for f in res["findings"] if f["path"] == "/custom/secret.conf"]
    assert got and got[0]["source"] == "llm"


def test_evidence_yedek_kardes_ikinci_dalga():
    """İlk dalga /config.php'yi 200 görür → ikinci dalgada /config.php.bak türetilir ve bulunur."""
    routes = {
        "/config.php": (200, "<?php define('DB_PASSWORD','x'); $conf=1;"),
        "/config.php.bak": (200, "<?php define('DB_PASSWORD','leaked'); $conf=1;"),
    }
    extra = [("/config.php", "config_exposure", "high", "php_config")]
    res = asyncio.run(path_probe._probe_with_transport("x.com", _mk_transport(routes), extra_paths=extra))
    paths = [f["path"] for f in res["findings"]]
    assert "/config.php.bak" in paths


def test_sablon_statik_disi_databases_yml_yakalar():
    """MANŞET: /apps/api/config/databases.yml statik katalogda YOK. tech='symfony' ile aile
    şablonu bu kombinasyonu üretir → LLM'siz, deterministik yakalanır. k3'ün elle-kombinasyon
    kırılganlığını kapatan asıl kanıt."""
    from pipeline.path_probe import SENSITIVE_PATHS
    assert "/apps/api/config/databases.yml" not in {r[0] for r in SENSITIVE_PATHS}  # statikte YOK
    routes = {"/apps/api/config/databases.yml": (200, _SYMFONY_DB_BODY)}
    res = asyncio.run(path_probe._probe_with_transport(
        "x.com", _mk_transport(routes), tech_hints=["symfony"]))
    got = [f for f in res["findings"] if f["path"] == "/apps/api/config/databases.yml"]
    assert got, "şablon üretmeliydi ama yol problanmadı"
    assert got[0]["severity"] == "critical" and got[0]["source"] == "template"
    # sır maskeli, host pivotu açık (zincir hedefi)
    assert "Sup3rS3cret" not in got[0]["snippet"]
    assert "db.example.local" in got[0].get("pivot_hints", {}).get("hosts", [])


def main():
    tests = [
        test_sablon_statik_disi_databases_yml_yakalar,
        test_normalize_4_ve_5_tuple,
        test_signature_validator_kurallari,
        test_signature_validator_bos_imza_generic,
        test_signature_must_contain_all,
        test_robots_disallow_yol_uretir,
        test_robots_wildcard_ve_bos_elenir,
        test_git_config_repo_yedegi,
        test_git_config_https_remote,
        test_yedek_kardesleri,
        test_dizin_listeleme_href,
        test_dizin_listeleme_degilse_bos,
        test_kritik_yol_bulunur_ve_ilk_sirada,
        test_extra_paths_signature_ile_bulgu,
        test_evidence_yedek_kardes_ikinci_dalga,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"[OK] {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {t.__name__}: {type(e).__name__}: {e}")
    if failed:
        print(f"\n{failed} test BAŞARISIZ.")
        sys.exit(1)
    print("\nTüm K1 testleri geçti.")


if __name__ == "__main__":
    main()
