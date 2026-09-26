"""Türkçe: IDOR / BOLA diferansiyel probu (idor_probe) birim testleri — SAF karar
çekirdeği; ağ isteği YOK.

Kök derdimiz: IDOR bir imza değil DİFERANSİYEL gözlemdir. Testler: id sınıflandırma,
ref çıkarımı (query+path, ad-ipucu), enumerasyon komşuları, iki-hesap confirmed kararı
+ FP kapıları (cross farklı nesne = yetki çalışıyor / kaynak public), tek-hesap probable.

Çalıştır: python3 orchestrator/pipeline/test_idor_probe.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncio  # noqa: E402
import types  # noqa: E402

from pipeline.idor_probe import (  # noqa: E402
    classify_id, extract_object_refs, replace_ref, neighbor_values,
    bodies_similar, Measured, adjudicate_two_account, adjudicate_single_account,
    alt_id_value, probe_idor,
)


def _sub(body):
    """Anlamlı (substantive) ölçüm üret: 2xx + temiz sayfa + yeterli uzunluk."""
    return Measured(status=200, body=body, page_class=None, length=len(body))


def test_classify_id():
    assert classify_id("1042") == "numeric"
    assert classify_id("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert classify_id("507f1f77bcf86cd799439011") == "objectid"  # 24 hex
    assert classify_id("d41d8cd98f00b204e9800998ecf8427e") == "hash"  # 32 hex
    assert classify_id("hello") is None
    assert classify_id("") is None


def test_extract_refs_query_ad_ipucu():
    # order_id sayısal + ad-ipuçlu → alınır; page=2 (ipucu yok) → alınmaz
    refs = extract_object_refs("https://x.com/api?order_id=5581&page=2")
    names = [(r.name, r.value, r.location) for r in refs]
    assert ("order_id", "5581", "query") in names
    assert not any(n[0] == "page" for n in names)


def test_extract_refs_path():
    # /users/1042 → path segment 1042, önceki segment 'users' ad-ipucu
    refs = extract_object_refs("https://x.com/api/users/1042/profile")
    path_refs = [r for r in refs if r.location == "path"]
    assert path_refs and path_refs[0].value == "1042"
    assert path_refs[0].name == "users"
    assert path_refs[0].name_hint is True


def test_extract_refs_uuid_tek_basina():
    # uuid ad-ipucu olmadan da ayırt edici → alınır
    refs = extract_object_refs("https://x.com/doc/550e8400-e29b-41d4-a716-446655440000")
    assert any(r.kind == "uuid" for r in refs)


def test_replace_ref_path_ve_query():
    u = "https://x.com/api/users/1042/profile"
    r = extract_object_refs(u)[0]
    assert replace_ref(u, r, "1043") == "https://x.com/api/users/1043/profile"
    u2 = "https://x.com/api?order_id=5581&page=2"
    r2 = [r for r in extract_object_refs(u2) if r.name == "order_id"][0]
    assert "order_id=5580" in replace_ref(u2, r2, "5580")
    assert "page=2" in replace_ref(u2, r2, "5580")  # diğer param korunur


def test_neighbor_values():
    r = extract_object_refs("https://x.com/users/100")[0]
    nbs = neighbor_values(r)
    assert "101" in nbs and "99" in nbs
    # uuid enumerasyon anlamsız → boş
    r2 = extract_object_refs("https://x.com/doc/550e8400-e29b-41d4-a716-446655440000")[0]
    assert neighbor_values(r2) == []


def test_two_account_confirmed():
    owner = _sub('{"user":"alice","ssn":"111-22-3333","balance":9000}')
    cross = _sub('{"user":"alice","ssn":"111-22-3333","balance":9000}')  # B, A'nın verisini aldı
    anon = Measured(status=302, body="", page_class="redirect", length=0)  # anon reddedildi
    v = adjudicate_two_account(owner, cross, anon)
    assert v["is_idor"] is True
    assert v["tier"] == "confirmed"


def test_two_account_yetki_calisiyor():
    # B kendi nesnesini aldı (gövde farklı) → IDOR DEĞİL (sunucu id'yi kimliğe kapsıyor)
    owner = _sub('{"user":"alice","ssn":"111-22-3333","balance":9000,"aaaaaaaaaa":1}')
    cross = _sub('{"user":"bob","ssn":"999-88-7777","balance":15,"zzzzzzzzzz":2}')
    anon = Measured(status=401, body="unauthorized", page_class="auth_wall", length=12)
    v = adjudicate_two_account(owner, cross, anon)
    assert v["is_idor"] is False


def test_two_account_public_kaynak():
    # anon da aynı içeriği alıyor → public, IDOR değil
    doc = '{"article":"public news","body":"lorem ipsum dolor sit amet"}'
    owner, cross, anon = _sub(doc), _sub(doc), _sub(doc)
    v = adjudicate_two_account(owner, cross, anon)
    assert v["is_idor"] is False
    assert "public" in v["reason"]


def test_two_account_cross_reddedildi():
    owner = _sub('{"user":"alice","data":"secret stuff here padding padding"}')
    cross = Measured(status=403, body="forbidden", page_class="auth_wall", length=9)
    v = adjudicate_two_account(owner, cross, None)
    assert v["is_idor"] is False
    assert "yetki_calisiyor" in v["reason"]


def test_single_account_probable():
    owner = _sub('{"id":100,"owner":"alice","note":"my private note number 100 padding"}')
    anon = Measured(status=302, body="", page_class="redirect", length=0)  # korumalı
    n1 = _sub('{"id":101,"owner":"bob","note":"totally different note 101 padding here"}')
    v = adjudicate_single_account(owner, anon, [n1])
    assert v["is_idor"] is True
    assert v["tier"] == "probable"


def test_single_account_anon_erisebiliyor_public():
    # anon nesneyi alabiliyor → public, probable bile değil
    doc = '{"public":"data","body":"some content that is long enough to be substantive"}'
    owner, anon = _sub(doc), _sub(doc)
    v = adjudicate_single_account(owner, anon, [_sub('{"other":"record here padding padding"}')])
    assert v["is_idor"] is False


def test_single_account_komsu_ayni_sablon():
    # komşu id owner ile birebir aynı (şablon) → farklı kayıt değil → sinyal yok
    body = '{"id":100,"template":"static page identical for all ids padding padding here"}'
    owner = _sub(body)
    anon = Measured(status=401, body="no", page_class="auth_wall", length=2)
    v = adjudicate_single_account(owner, anon, [_sub(body)])
    assert v["is_idor"] is False


def test_bodies_similar():
    assert bodies_similar("aaaa", "aaaa") == 1.0
    assert bodies_similar("", "") == 1.0
    assert bodies_similar("abc", "") == 0.0
    assert 0.0 <= bodies_similar("hello world", "hello there") <= 1.0


def test_alt_id_value():
    n = extract_object_refs("https://x.com/users/1042")[0]
    assert alt_id_value(n) in ("1043", "1041")   # farklı sayısal id
    u = extract_object_refs("https://x.com/doc/550e8400-e29b-41d4-a716-446655440000")[0]
    assert alt_id_value(u) == "00000000-0000-0000-0000-000000000000"


# ---- I/O: SPA-shell FP kalkanı + gerçek IDOR hâlâ confirmed ----

def _fake_httpx(client_cls):
    m = types.ModuleType("httpx")
    m.AsyncClient = client_cls
    m.Limits = lambda **k: None
    return m


class _R:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.headers = {}


def _run_probe(client_cls, url, auth_a, auth_b):
    orig = sys.modules.get("httpx")
    sys.modules["httpx"] = _fake_httpx(client_cls)
    try:
        return asyncio.run(probe_idor([url], auth_a=auth_a, auth_b=auth_b))
    finally:
        if orig is not None:
            sys.modules["httpx"] = orig
        else:
            sys.modules.pop("httpx", None)


def test_probe_idor_spa_shell_reddedilir():
    # Sunucu her id için AYNI kabuğu döner (client-side render) → id'ye duyarsız → IDOR DEĞİL
    class ShellClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers=None):
            if not (headers or {}).get("Authorization"):
                return _R(302, "")   # anon reddedildi
            return _R(200, "SPA SHELL identical for every id padding padding padding text")
    res = _run_probe(ShellClient, "https://x.com/api/accounts/1042",
                     {"Authorization": "Bearer A"}, {"Authorization": "Bearer B"})
    assert res == []   # kalkan devrede: shell confirmed IDOR üretmez


def test_probe_idor_gercek_idor_confirmed():
    # id'ye DUYARLI: her id GERÇEKTEN farklı nesne (alice vs bob — sadece id rakamı değil,
    # tüm içerik farklı, gerçek per-object veri gibi). B, A'nın id'sini isteyince A'nın
    # verisini alır → confirmed. alt-id (komşu) bariz farklı → SPA-shell kalkanı tetiklenmez.
    class IdorClient:
        _DATA = {
            "1042": "user alice private ssn 111-22-3333 balance 9000 email alice@corp secret alpha",
            "1043": "user bob other ssn 999-88-7777 balance 42 email bob@corp secret bravo delta",
            "1041": "user carol distinct ssn 555-44-3333 balance 71 email carol@corp secret gamma",
        }
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers=None):
            if not (headers or {}).get("Authorization"):
                return _R(302, "")   # anon reddedildi
            idv = url.rstrip("/").split("/")[-1].split("?")[0]
            return _R(200, self._DATA.get(idv, f"unknown object {idv} generic empty record"))
    res = _run_probe(IdorClient, "https://x.com/api/accounts/1042",
                     {"Authorization": "Bearer A"}, {"Authorization": "Bearer B"})
    assert res and res[0]["tier"] == "confirmed"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
