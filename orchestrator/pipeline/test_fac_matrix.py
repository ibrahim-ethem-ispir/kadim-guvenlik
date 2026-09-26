"""Türkçe: FAC matrisi (fac_matrix_probe) birim testleri — SAF karar çekirdeği + sahte
httpx ile I/O kipi. GERÇEK ağ isteği YOK.

Kök dert: dikey yetki yükseltme imza değil DİFERANSİYEL gözlemdir. Testler: ayrıcalıklı
URL seçimi, aşınma varyantı üretimi, JWT rol sinyali (üç değerli), kip-1 (yöntem aşınması)
confirmed/probable/red kararları, kip-2 (anon-red + A-2xx) rol-eşikli kanıt, FP kalkanları
(public uç, SPA-kabuk, A gerçekten admin).

Çalıştır: python3 orchestrator/pipeline/test_fac_matrix.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncio  # noqa: E402
import types  # noqa: E402

from pipeline.fac_matrix_probe import (  # noqa: E402
    select_privileged_urls, tamper_variants, jwt_nonadmin,
    adjudicate_method_tamper, adjudicate_privileged_access, probe_fac_matrix,
)
from pipeline.idor_probe import Measured  # noqa: E402


def _sub(body, status=200):
    """Anlamlı (substantive) ölçüm: 2xx + temiz sayfa + yeterli uzunluk."""
    return Measured(status=status, body=body, page_class=None, length=len(body))


def _denied(status=403):
    return Measured(status=status, body="forbidden", page_class="auth_wall", length=9)


# ---- select_privileged_urls ----

def test_select_hint_once_ve_sentetik():
    pool = ["https://x.com/api/users/1", "https://x.com/admin/users",
            "https://x.com/api/settings"]
    out = select_privileged_urls(pool)
    # hint-eşleşenler ÖNCE (gerçek keşif > sentetik tahmin)
    assert out[0] == "https://x.com/admin/users"
    assert out[1] == "https://x.com/api/settings"
    # sentetik klasik yollar kök origin'e örülür (kap SONRASI kesilebilir → ilk sentetik /admin)
    assert "https://x.com/admin" in out and len(out) <= 8
    # nesne-ref'li düz uç (hint'siz) seçilmez
    assert "https://x.com/api/users/1" not in out


def test_select_dedup_ve_kap():
    pool = ["https://x.com/admin", "https://x.com/admin", "https://y.com/debug"]
    out = select_privileged_urls(pool, max_targets=3)
    assert len(out) == 3
    assert out.count("https://x.com/admin") == 1


def test_select_bos_havuz():
    assert select_privileged_urls([]) == []


# ---- tamper_variants ----

def test_tamper_variants_baslik_ve_query():
    vs = tamper_variants("https://x.com/admin")
    labels = [v[0] for v in vs]
    assert "x-method-override:GET" in labels and "x-original-url" in labels
    # sorgu varyanti _method ekler, mevcut query korunur
    qv = [v for v in vs if v[0] == "query:_method=GET"][0]
    assert qv[1] == "https://x.com/admin?_method=GET"
    # X-Original-URL hedef path'i taşır
    hov = [v for v in vs if v[0] == "x-original-url"][0]
    assert hov[2] == {"X-Original-URL": "/admin"}
    assert len(set(labels)) == len(labels)


def test_tamper_variants_yinelenen_method_yok():
    # _method zaten varsa ikinci kez eklenmez (isteği bozma)
    vs = tamper_variants("https://x.com/admin?_method=PUT")
    assert not any("_method=GET" in v[1] for v in vs)


# ---- jwt_nonadmin (üç değerli) ----

def test_jwt_nonadmin_boolean():
    assert jwt_nonadmin({"is_admin": False}) is True
    assert jwt_nonadmin({"is_admin": "false"}) is True
    assert jwt_nonadmin({"is_admin": True}) is False


def test_jwt_nonadmin_role():
    assert jwt_nonadmin({"role": "user"}) is True
    assert jwt_nonadmin({"roles": ["member", "buyer"]}) is True
    assert jwt_nonadmin({"role": "ADMIN"}) is False
    assert jwt_nonadmin({"realm_access": {"roles": ["superadmin"]}}) is False


def test_jwt_nonadmin_sinyal_yok():
    assert jwt_nonadmin({"sub": "42", "exp": 123}) is None
    assert jwt_nonadmin({}) is None
    assert jwt_nonadmin(None) is None


# ---- KİP 1: yöntem aşınması ----

def test_tamper_confirmed_json():
    base = _denied()
    v = adjudicate_method_tamper(base, [("query:_method=GET",
                                         _sub('{"users":[{"id":1,"email":"root@corp.local","api_key":"sk_live_9"}]}'))])
    assert v["is_fac"] is True and v["tier"] == "confirmed"


def test_tamper_probable_html_kabuk():
    base = _denied()
    html = "<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>"
    v = adjudicate_method_tamper(base, [("x-original-url", _sub(html))])
    assert v["is_fac"] is True and v["tier"] == "probable"  # SPA-kabuk kalkanı


def test_tamper_baseline_reddedilmediyse_kip1_degil():
    v = adjudicate_method_tamper(_sub('{"ok":1,"data":"substantive response body here"}'),
                                 [("x-original-url", _sub('{"leak":"data data data data data"}'))])
    assert v["is_fac"] is False


def test_tamper_tumu_reddedildi():
    v = adjudicate_method_tamper(_denied(), [("x-method-override:GET", _denied()),
                                             ("path:double-slash", _denied())])
    assert v["is_fac"] is False and "erisim_kontrolu_calisiyor" in v["reason"]


# ---- KİP 2: ayrıcalıklı yol erişimi ----

def test_priv_nonadmin_confirmed():
    owner = _sub('{"users":[{"id":1,"email":"admin@corp.local","role":"superadmin"}]}')
    v = adjudicate_privileged_access(owner, _denied(), a_is_nonadmin=True)
    assert v["is_fac"] is True and v["tier"] == "confirmed"


def test_priv_rol_bilinmiyor_probable():
    owner = _sub('{"users":[{"id":1,"email":"admin@corp.local","role":"superadmin"}]}')
    v = adjudicate_privileged_access(owner, _denied(), a_is_nonadmin=None)
    assert v["is_fac"] is True and v["tier"] == "probable"


def test_priv_a_admin_normal_erisim():
    owner = _sub('{"users":[{"id":1,"email":"admin@corp.local","role":"superadmin"}]}')
    v = adjudicate_privileged_access(owner, _denied(), a_is_nonadmin=False)
    assert v["is_fac"] is False and "yonetici" in v["reason"]


def test_priv_uc_public_fp_kalkani():
    body = '{"settings":{"theme":"dark","public":true,"note":"herkes erisebilir bir uc"}}'
    v = adjudicate_privileged_access(_sub(body), _sub(body), a_is_nonadmin=True)
    assert v["is_fac"] is False and "korunakli_degil" in v["reason"]


# ---- I/O (sahte httpx) ----

def _fake_httpx(client_cls):
    m = types.ModuleType("httpx")
    m.AsyncClient = client_cls
    m.Limits = lambda **k: None
    return m


class _R:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _run(client_cls, urls, auth_a, a_is_nonadmin=None):
    orig = sys.modules.get("httpx")
    sys.modules["httpx"] = _fake_httpx(client_cls)
    try:
        return asyncio.run(probe_fac_matrix(urls, auth_a=auth_a,
                                            a_is_nonadmin=a_is_nonadmin))
    finally:
        if orig is not None:
            sys.modules["httpx"] = orig
        else:
            sys.modules.pop("httpx", None)


class _TamperClient:
    """A'ya kanonik GET 403; biçim-varyantları JSON veri döndürüyor (tipik WAF/ACL aşınması)."""
    _LEAK = '{"users":[{"id":1,"email":"root@corp.local","role":"superadmin","api_key":"sk_live_42"}]}'

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, headers=None):
        h = headers or {}
        if not h.get("Authorization"):
            return _R(403, "forbidden")                       # anon reddedildi
        tampered = (h.get("X-HTTP-Method-Override") or h.get("X-Original-URL")
                    or h.get("X-Rewrite-URL") or "_method=GET" in url
                    or "//admin" in url)
        if tampered:
            return _R(200, self._LEAK, {"content-type": "application/json"})
        return _R(403, "forbidden")


class _PrivPathClient:
    """anon 403; A'nın düz GET'i dolu JSON alıyor (rol dışarıdan bilinmiyor)."""
    _LEAK = '{"users":[{"id":1,"email":"admin@corp.local","role":"superadmin","api_key":"sk_live_42"}]}'

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, headers=None):
        if (headers or {}).get("Authorization"):
            return _R(200, self._LEAK, {"content-type": "application/json"})
        return _R(403, "forbidden")


class _PublicClient:
    """Uç herkese açık (anon 200) → FAC bulgusu DEĞİL (web_misconfig kapsamı)."""
    _BODY = '{"settings":{"theme":"dark","public":true,"note":"herkes erisebilir bir uc"}}'

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, headers=None):
        return _R(200, self._BODY, {"content-type": "application/json"})


def test_probe_authsiz_bos():
    assert _run(_TamperClient, ["https://x.com/admin"], {}) == []


def test_probe_yontem_asinmasi_confirmed():
    res = _run(_TamperClient, ["https://x.com/admin"], {"Authorization": "Bearer A"})
    assert res and res[0]["tier"] == "confirmed"
    assert res[0]["kind"] == "method-tamper"
    assert res[0]["severity"] == "critical"


def test_probe_priv_yol_nonadmin_confirmed():
    res = _run(_PrivPathClient, ["https://x.com/admin"], {"Authorization": "Bearer A"},
               a_is_nonadmin=True)
    assert res and res[0]["tier"] == "confirmed"
    assert res[0]["kind"] == "privileged-path"


def test_probe_priv_yol_rol_bilinmiyor_probable():
    res = _run(_PrivPathClient, ["https://x.com/admin"], {"Authorization": "Bearer A"})
    assert res and res[0]["tier"] == "probable"


def test_probe_priv_yol_a_admin_bulgu_yok():
    assert _run(_PrivPathClient, ["https://x.com/admin"], {"Authorization": "Bearer A"},
                a_is_nonadmin=False) == []


def test_probe_public_uc_bulgu_degil():
    assert _run(_PublicClient, ["https://x.com/admin"], {"Authorization": "Bearer A"},
                a_is_nonadmin=True) == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
