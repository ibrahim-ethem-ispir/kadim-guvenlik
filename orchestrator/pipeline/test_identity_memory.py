"""Türkçe: Tier 4 — kimlik öğrenme döngüsü testleri. SAF; GERÇEK Mongo YOK (fake koleksiyon).

Kök: sistem kendi trafiğinden öğrensin — bir kez tanınan ürün (CPE/LLM) sonraki taramada
LLM'siz tanınsın. Bu testler: ayırt edici sinyal çıkarımı (jenerik eleme), learn+recall
roundtrip, KİRLENME korkulukları (ambiguous → uygulama; LLM ≥2 korroborasyon), distill.

Çalıştır: python3 orchestrator/pipeline/test_identity_memory.py
"""
import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.identity_memory import (  # noqa: E402
    extract_identity_signals, distill_identity, learn, recall,
)
from pipeline.target_profile import fingerprint  # noqa: E402


class FakeCol:
    """MongoDB koleksiyonunun minimal taklidi (find_one/insert_one/replace_one/find $in)."""
    def __init__(self):
        self.docs = {}

    def find_one(self, q):
        _id = q.get("_id")
        d = self.docs.get(_id)
        return copy.deepcopy(d) if d else None

    def insert_one(self, doc):
        self.docs[doc["_id"]] = copy.deepcopy(doc)

    def replace_one(self, q, doc, upsert=False):
        self.docs[q["_id"]] = copy.deepcopy(doc)

    def find(self, q):
        kind = q.get("kind")
        idq = q.get("_id", {})
        inlist = idq.get("$in") if isinstance(idq, dict) else None
        out = []
        for d in self.docs.values():
            if kind and d.get("kind") != kind:
                continue
            if inlist is not None and d["_id"] not in inlist:
                continue
            if "enabled" in q and d.get("enabled") != q["enabled"]:
                continue
            out.append(copy.deepcopy(d))
        return out


# ---- extract_identity_signals (ayırt edicilik) ----
def test_extract_distinctive_vs_generic():
    ev = {"headers": {"Server": "pfSense/2.7", "X-Powered-By": "Express"},
          "cookies": ["PHPSESSID", "my_app_sid"], "title": "Login to Acme Portal"}
    sigs = dict(extract_identity_signals(ev))
    # ayırt edici header/çerez/başlık → var
    assert ("header", "server=pfsense/2.7") in extract_identity_signals(ev)
    assert ("cookie", "my_app_sid") in extract_identity_signals(ev)
    assert ("title", "login to acme portal") in extract_identity_signals(ev)
    # jenerik → yok
    assert ("cookie", "phpsessid") not in extract_identity_signals(ev)


def test_extract_generic_server_no_version_skipped():
    ev = {"headers": {"Server": "nginx"}, "cookies": [], "title": None}
    assert extract_identity_signals(ev) == []   # sürümsüz nginx → ayırt edici değil


# ---- learn + recall roundtrip ----
def test_cpe_learn_then_recall_immediate():
    col = FakeCol()
    ev = {"headers": {"Server": "SpectiveBlock/2.1"}, "cookies": [], "title": None}
    sigs = extract_identity_signals(ev)
    ident = {"label": "SpectiveBlock 2.1", "dims": [["waf", "spective"]], "source": "cpe"}
    assert learn(col, sigs, ident, "1.2.3.4") == len(sigs) >= 1
    extra, labels = recall(col, sigs)
    dims = {(d, v) for (d, v, _w, _e) in extra}
    assert ("waf", "spective") in dims
    assert any("SpectiveBlock" in l for l in labels)
    # ağırlık taze CPE'nin (0.8) ALTINDA (canlı otoriter baskın kalsın)
    assert all(w <= 0.78 for (_d, _v, w, _e) in extra)


def test_llm_needs_two_confirmations():
    col = FakeCol()
    ev = {"headers": {"X-Powered-By": "NimbleAppd/1.0"}, "cookies": [], "title": None}
    sigs = extract_identity_signals(ev)
    ident = {"label": "NimbleAppd", "dims": [["framework", "nimble"]], "source": "llm"}
    learn(col, sigs, ident, "t1")
    assert recall(col, sigs)[0] == []          # 1 gözlem LLM → recall YOK (halüsinasyon freni)
    learn(col, sigs, ident, "t2")
    extra, _ = recall(col, sigs)
    assert ("framework", "nimble") in {(d, v) for (d, v, _w, _e) in extra}  # 2 gözlem → uygulanır


def test_ambiguous_signal_never_applied():
    col = FakeCol()
    ev = {"headers": {"Server": "Shared/1.0"}, "cookies": [], "title": None}
    sigs = extract_identity_signals(ev)
    learn(col, sigs, {"label": "ProductA", "dims": [["framework", "a"]], "source": "cpe"}, "t1")
    learn(col, sigs, {"label": "ProductB", "dims": [["framework", "b"]], "source": "cpe"}, "t2")
    # aynı sinyal 2 farklı ürün → ambiguous → recall ASLA uygulamaz (kirlenme freni)
    assert recall(col, sigs)[0] == []


# ---- distill_identity ----
def test_distill_prefers_cpe_then_llm():
    p = fingerprint(headers={"Server": "nginx"})
    d_cpe = distill_identity(p, ["nginx 1.24"], ["something (LLM~60%)"])
    assert d_cpe and d_cpe["source"] == "cpe" and d_cpe["label"] == "nginx 1.24"
    assert ["server", "nginx"] in d_cpe["dims"]
    # CPE yok → LLM; "(LLM~%)" eki temizlenir
    d_llm = distill_identity(p, [], ["Flarum (LLM~70%)"])
    assert d_llm and d_llm["source"] == "llm" and d_llm["label"] == "Flarum"


def test_distill_none_when_no_product_or_no_dims():
    p = fingerprint(headers={"Server": "nginx"})
    assert distill_identity(p, [], []) is None          # ürün yok
    p_empty = fingerprint()                              # dims yok
    assert distill_identity(p_empty, ["x"], []) is None


# ---- entegrasyon: recall sinyali profile işlenir ama deterministik baskın ----
def test_recalled_signal_feeds_profile_but_deterministic_wins():
    col = FakeCol()
    ev = {"headers": {"Server": "AcmeWAF/3"}, "cookies": [], "title": None}
    sigs = extract_identity_signals(ev)
    learn(col, sigs, {"label": "AcmeWAF", "dims": [["waf", "acme"]], "source": "cpe"}, "t1")
    extra, _ = recall(col, sigs)
    p = fingerprint(ports=[443], extra=extra)
    assert p.value("waf") == "acme"                    # öğrenilmiş kimlik profile girdi
    assert p.kind() == "appliance"                     # waf var, web yok → appliance çerçevesi


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
