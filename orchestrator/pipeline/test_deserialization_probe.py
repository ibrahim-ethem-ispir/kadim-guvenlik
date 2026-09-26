"""Türkçe: Deserialization kabul-imza probu (deserialization_probe) testleri — classify/is_*_live
çekirdeği SAF; probe_deserialization sahte-sunucuyla deterministik (ağ YOK).

Kök: SharePoint ToolShell / ASP.NET ViewState / TeamCity deserialization sınıfı için motorda
hiç aktif doğrulayıcı yoktu (docs/2026-08-14-guncel-50-cve-tespit-bosluk-analizi.md, Boşluk 3).
KRİTİK: ilgisiz hedefte prob HİÇ bulgu üretmemeli VE hiçbir path'e istek atmamalı (çift-kapı) —
ayrı testler. TAHRİBATSIZLIK: __VIEWSTATE formu yoksa POST hiç denenmemeli — ayrı test.

Çalıştır: python3 orchestrator/pipeline/test_deserialization_probe.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.deserialization_probe import (  # noqa: E402
    is_sharepoint_live, is_teamcity_live, classify_sharepoint_path,
    classify_viewstate_acceptance, classify_teamcity_version, extract_form_action,
    probe_deserialization,
)


# ============================================================
# SAF çekirdek testleri (ağ yok)
# ============================================================

def test_is_sharepoint_live():
    ok, ev = is_sharepoint_live(body='<a href="/_layouts/15/start.aspx">Home</a>')
    assert ok and ev
    ok2, _ = is_sharepoint_live(body="<html><body>plain nginx</body></html>")
    assert ok2 is False
    ok3, _ = is_sharepoint_live(headers={"SPRequestGuid": "abc-123"})
    assert ok3 is True


def test_is_teamcity_live():
    ok, ev = is_teamcity_live(body="<title>TeamCity 2024.03.2</title>")
    assert ok and ev
    ok2, _ = is_teamcity_live(body="<html>generic ci page</html>")
    assert ok2 is False
    ok3, _ = is_teamcity_live(headers={"X-TeamCity-Node-Id": "MAIN_SERVER"})
    assert ok3 is True


def test_classify_sharepoint_path_positive():
    c = classify_sharepoint_path(
        "/_layouts/15/ToolPane.aspx", 200, "text/html",
        '<html><body>SharePoint __VIEWSTATE form</body></html>')
    assert c is not None and c["status"] == 200
    c2 = classify_sharepoint_path("/_layouts/SignOut.aspx", 302, "text/html", "")
    assert c2 is not None and c2["status"] == 302


def test_classify_sharepoint_path_negative_soft404():
    # 200 ama içerik SharePoint imzası TAŞIMIYOR (paylaşımlı host soft-404) → None
    c = classify_sharepoint_path(
        "/_layouts/15/ToolPane.aspx", 200, "text/html",
        "<html><body>Generic landing page, nothing here.</body></html>")
    assert c is None
    assert classify_sharepoint_path("/_layouts/15/x.aspx", 404, "text/html", "not found") is None
    assert classify_sharepoint_path("/_layouts/15/x.aspx", 500, "text/html", "error") is None


def test_classify_viewstate_mac_enforced():
    c = classify_viewstate_acceptance(500, "Validation of viewstate MAC failed.")
    assert c == {"mac_status": "enforced"}


def test_classify_viewstate_mac_disabled():
    c = classify_viewstate_acceptance(200, "<html><body>Normal page rendered fine.</body></html>")
    assert c == {"mac_status": "disabled"}


def test_classify_viewstate_ambiguous():
    c = classify_viewstate_acceptance(500, "Invalid postback or callback argument.")
    assert c is None


def test_classify_teamcity_version_positive():
    v = classify_teamcity_version(200, "application/xml", '<server version="2024.03.2" webUrl="x"/>')
    assert v == {"version": "2024.03.2"}
    v2 = classify_teamcity_version(200, "application/json", '{"version":"2023.11.1"}')
    assert v2 == {"version": "2023.11.1"}


def test_classify_teamcity_version_negative():
    assert classify_teamcity_version(401, "text/html", "unauthorized") is None
    assert classify_teamcity_version(200, "text/html", "<html>no version here</html>") is None


def test_extract_form_action():
    base = "https://intranet.example.com"
    assert extract_form_action(
        '<form action="/default.aspx" method="post"><input name="__VIEWSTATE"></form>', base
    ) == "https://intranet.example.com/default.aspx"
    # action yok → self-post (base'in kendisi)
    assert extract_form_action(
        '<form method="post"><input name="__VIEWSTATE"></form>', base) == base
    # __VIEWSTATE hiç yok → None (test hiç yapılmaz)
    assert extract_form_action('<form action="/x.aspx"><input name="q"></form>', base) is None
    # farklı origin'e post eden form → None (yan etkili cross-host POST riski yok)
    assert extract_form_action(
        '<form action="https://evil.example.net/x"><input name="__VIEWSTATE"></form>', base
    ) is None


# ============================================================
# Uçtan uca — sahte sunucu (ağ YOK)
# ============================================================

class _R:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class FakeSharePointClient:
    """SharePoint sitesi taklidi + ViewState MAC AKTİF (iyi durum)."""
    def __init__(self):
        self.post_calls = 0

    async def get(self, url, timeout=10.0, follow_redirects=False):
        if not url.startswith("https://"):
            raise RuntimeError("connection refused")
        path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
        if path in ("/", ""):
            html = ('<html><head><title>Intranet</title></head><body>'
                    '<form action="/default.aspx" method="post">'
                    '<input type="hidden" name="__VIEWSTATE" value="garbage">'
                    '</form></body></html>')
            return _R(200, html, {"content-type": "text/html", "SPRequestGuid": "abc-123"})
        if path == "/_layouts/15/ToolPane.aspx":
            return _R(200, "<html><body>SharePoint ToolPane __VIEWSTATE</body></html>",
                      {"content-type": "text/html"})
        return _R(404, "not found", {"content-type": "text/html"})

    async def post(self, url, data=None, timeout=10.0, follow_redirects=False):
        self.post_calls += 1
        return _R(500, "Validation of viewstate MAC failed.", {"content-type": "text/html"})


class FakeViewStateMacOffClient(FakeSharePointClient):
    """MAC KAPALI: rastgele ViewState'e sunucu hata vermeden normal yanıt döner (kritik)."""
    async def post(self, url, data=None, timeout=10.0, follow_redirects=False):
        self.post_calls += 1
        return _R(200, "<html><body>Page rendered normally.</body></html>",
                  {"content-type": "text/html"})


class FakeTeamCityClient:
    """TeamCity sitesi taklidi: /app/rest/server auth'suz sürüm sızdırıyor."""
    def __init__(self):
        self.post_calls = 0

    async def get(self, url, timeout=10.0, follow_redirects=False):
        if not url.startswith("https://"):
            raise RuntimeError("connection refused")
        path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
        if path in ("/", ""):
            return _R(200, "<html><title>TeamCity 2024.03.2</title></html>",
                      {"content-type": "text/html"})
        if path == "/app/rest/server":
            return _R(200, '<server version="2024.03.2"/>', {"content-type": "application/xml"})
        return _R(404, "not found", {"content-type": "text/html"})

    async def post(self, url, data=None, timeout=10.0, follow_redirects=False):
        self.post_calls += 1
        return _R(404, "not found", {"content-type": "text/html"})


class FakeIrrelevantClient:
    """SharePoint/TeamCity/dotnet OLMAYAN site (düz nginx). Çift-kapı testi: prob HİÇ bulgu
    üretmemeli VE hiçbir SharePoint/TeamCity path'ine istek atmamalı."""
    def __init__(self):
        self.get_paths = []
        self.post_calls = 0

    async def get(self, url, timeout=10.0, follow_redirects=False):
        if not url.startswith("https://"):
            raise RuntimeError("connection refused")
        path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
        self.get_paths.append(path)
        if path in ("/", ""):
            return _R(200, "<html><body>Just an nginx landing page.</body></html>",
                      {"content-type": "text/html"})
        return _R(404, "not found", {"content-type": "text/html"})

    async def post(self, url, data=None, timeout=10.0, follow_redirects=False):
        self.post_calls += 1
        return _R(404, "not found", {"content-type": "text/html"})


class FakeBrokenClient:
    """Her istekte patlayan sunucu — best-effort: probe_deserialization raise ETMEMELİ."""
    async def get(self, url, timeout=10.0, follow_redirects=False):
        raise RuntimeError("network unreachable")

    async def post(self, url, data=None, timeout=10.0, follow_redirects=False):
        raise RuntimeError("network unreachable")


def test_probe_deserialization_sharepoint_mac_enforced():
    client = FakeSharePointClient()
    res = asyncio.run(probe_deserialization("intranet.example.com", client))
    assert res["confirmed_sharepoint"] is True
    assert res["viewstate_tested"] is True
    titles = " || ".join(f["title"] for f in res["findings"])
    assert "SharePoint Yönetim Yüzeyi Açık" in titles
    assert "ViewState MAC Doğrulaması Aktif" in titles
    # MAC aktifse severity info olmalı, critical DEĞİL
    vs_finding = next(f for f in res["findings"] if "ViewState MAC Doğrulaması Aktif" in f["title"])
    assert vs_finding["severity"] == "info"
    assert client.post_calls == 1  # tek POST — cap/pacing disiplini


def test_probe_deserialization_viewstate_mac_disabled_critical():
    client = FakeViewStateMacOffClient()
    res = asyncio.run(probe_deserialization("intranet.example.com", client))
    titles = " || ".join(f["title"] for f in res["findings"])
    assert "ViewState MAC Doğrulaması KAPALI" in titles
    vs_finding = next(f for f in res["findings"] if "MAC Doğrulaması KAPALI" in f["title"])
    assert vs_finding["severity"] == "critical"
    assert vs_finding["confidence_tier"] == "confirmed"


def test_probe_deserialization_teamcity_confirmed():
    res = asyncio.run(probe_deserialization("ci.example.com", FakeTeamCityClient()))
    assert res["confirmed_teamcity"] is True
    titles = " || ".join(f["title"] for f in res["findings"])
    assert "TeamCity Sürüm İfşası (2024.03.2)" in titles
    # dotnet/ViewState formu yok → POST hiç denenmemeli
    assert res["viewstate_tested"] is False


def test_probe_deserialization_double_gate_irrelevant():
    # KRİTİK: profil yanlışlıkla ilgili dese bile (bu modül playbook'tan sonra çağrılır), canlı
    # imza yoksa TEK bulgu bile üretilmemeli — kullanıcı doktrini (WP probe ile aynı kural).
    client = FakeIrrelevantClient()
    res = asyncio.run(probe_deserialization("static.example.com", client))
    assert res["confirmed_sharepoint"] is False
    assert res["confirmed_teamcity"] is False
    assert res["viewstate_tested"] is False
    assert res["findings"] == []
    # hiçbir SharePoint/TeamCity path'ine istek atılmadı — yalnız kök GET
    assert client.get_paths == ["/"]
    assert client.post_calls == 0


def test_probe_deserialization_no_viewstate_no_post():
    # __VIEWSTATE formu yoksa POST hiç denenmemeli (tahribatsızlık garantisi).
    client = FakeTeamCityClient()
    asyncio.run(probe_deserialization("ci.example.com", client))
    assert client.post_calls == 0


def test_probe_deserialization_best_effort():
    # Ağ tamamen patlarsa raise ETMEMELİ, boş sonuç dönmeli.
    res = asyncio.run(probe_deserialization("unreachable.example.com", FakeBrokenClient()))
    assert res["findings"] == []
    assert res["confirmed_sharepoint"] is False
    assert res["confirmed_teamcity"] is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
