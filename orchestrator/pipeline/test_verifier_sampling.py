"""
Türkçe: Verifier-guided generate-and-verify (Best-of-N) SAF testleri — ağ/DB YOK.
Çalıştır: python3 orchestrator/pipeline/test_verifier_sampling.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline import verifier_sampling as VS  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


async def main():
    print("== plan_best_of_n: çeşitlilik + dedup + tavan ==")
    cands = [
        VS.Candidate("b1", "builtin", "p1", prior=3.0),
        VS.Candidate("b2", "builtin", "p2", prior=2.0),
        VS.Candidate("c1", "corpus", "p3", prior=1.0),
        VS.Candidate("c2", "corpus", "p4", prior=0.5),
        VS.Candidate("m1", "mutation", "p5", prior=0.2),
    ]
    plan = VS.plan_best_of_n(cands, 3)
    check("tavan uygulandı (3)", len(plan) == 3)
    fams = {c.family for c in plan}
    check("aile çeşitliliği (>=2 aile)", len(fams) >= 2)
    check("en yüksek prior aile ilk", plan[0].family == "builtin")

    dup = [
        VS.Candidate("x", "builtin", "same", prior=1.0),
        VS.Candidate("y", "corpus", "same", prior=1.0),
    ]
    plan2 = VS.plan_best_of_n(dup, 5, dedup_key=lambda c: c.payload)
    check("aynı payload dedup edildi", len(plan2) == 1)

    check("n=0 → boş", VS.plan_best_of_n(cands, 0) == [])

    print("== select_best: kanıtlanan kazanır ==")
    c_ok = VS.Candidate("a", "builtin", "x", prior=1.0)
    c_bad = VS.Candidate("b", "corpus", "y", prior=5.0)
    results = [
        (c_bad, VS.Verdict(False, 0.0, "no-match")),
        (c_ok, VS.Verdict(True, 0.7, "marker echo", finding={"title": "PI"})),
    ]
    w, wv = VS.select_best(results)
    check("verified seçildi", w is c_ok and wv.finding["title"] == "PI")

    c1 = VS.Candidate("c1", "builtin", "a", prior=1.0)
    c2 = VS.Candidate("c2", "corpus", "b", prior=1.0)
    results2 = [
        (c1, VS.Verdict(True, 0.6, "x")),
        (c2, VS.Verdict(True, 0.9, "y")),
    ]
    w2, _ = VS.select_best(results2)
    check("yüksek confidence kazandı", w2 is c2)
    check("hiç verified yok → None", VS.select_best([(c1, VS.Verdict(False))])[0] is None)

    print("== outcome_summary: aile kazanma oranı ==")
    summ = VS.outcome_summary([
        (VS.Candidate("a", "builtin", "x"), VS.Verdict(True, 0.9)),
        (VS.Candidate("b", "builtin", "y"), VS.Verdict(False, 0.0)),
        (VS.Candidate("c", "corpus", "z"), VS.Verdict(True, 0.5)),
    ])
    check("builtin tried=2 wins=1", summ["builtin"]["tried"] == 2 and summ["builtin"]["wins"] == 1)
    check("builtin win_rate=0.5", summ["builtin"]["win_rate"] == 0.5)
    check("corpus win_rate=1.0", summ["corpus"]["win_rate"] == 1.0)

    print("== run_best_of_n: erken çıkış + hata toleransı ==")
    calls = []

    def make_verify(hit_id):
        async def _v(c):
            calls.append(c.id)
            if c.id == hit_id:
                return VS.Verdict(True, 0.8, "ok", finding={"t": c.id})
            return VS.Verdict(False, 0.0, "no")
        return _v

    r = await VS.run_best_of_n(cands, make_verify("c1"), 4, early_exit=True)
    check("kazanan bulundu (c1)", r.winner is not None and r.winner.id == "c1")
    check("erken çıkış (c1'de durdu)", calls[-1] == "c1" and "m1" not in calls)
    check("tried kaydedildi", r.tried == len(r.results))
    check("family_stats dolu", "builtin" in r.family_stats)

    async def boom(c):
        raise RuntimeError("verifier patladı")
    r2 = await VS.run_best_of_n(cands, boom, 2, early_exit=True)
    check("hata toleransı (winner None, tried=2)", r2.winner is None and r2.tried == 2)
    check("hata verdict'e yazıldı", "verify-error" in r2.results[0][1].detail)

    r3 = await VS.run_best_of_n(cands, make_verify("__none__"), 3, early_exit=False)
    check("early_exit=False → tüm plan denendi", r3.tried == 3 and r3.winner is None)

    print("== sampling_memory: family_delta + fake-db roundtrip ==")
    from pipeline import sampling_memory as SM
    check("delta: yeni aile tümü",
          SM.family_delta({"builtin": {"tried": 2, "wins": 1}}, {}) ==
          {"builtin": {"tried": 2, "wins": 1}})
    check("delta: artım",
          SM.family_delta({"builtin": {"tried": 3, "wins": 2}},
                          {"builtin": {"tried": 2, "wins": 1}}) ==
          {"builtin": {"tried": 1, "wins": 1}})
    check("delta: değişim yok → boş",
          SM.family_delta({"a": {"tried": 1, "wins": 1}}, {"a": {"tried": 1, "wins": 1}}) == {})

    class _FakeColl:
        def __init__(self):
            self.doc = None
        def find_one(self, q):
            return self.doc
        def update_one(self, q, upd, upsert=False):
            self.doc = upd.get("$set")

    class _FakeDB:
        def __init__(self):
            self.c = _FakeColl()
        def __getitem__(self, k):
            return self.c

    fdb = _FakeDB()
    SM.record_family_outcomes(fdb, {"builtin": {"tried": 2, "wins": 1}})
    SM.record_family_outcomes(fdb, {"builtin": {"tried": 2, "wins": 2}})
    pri = SM.load_family_priors(fdb)
    check("fake-db kümülatif merge win_rate=0.75", pri["builtin"] == 0.75)
    check("fake-db tried=4 wins=3",
          fdb.c.doc["families"]["builtin"]["tried"] == 4 and
          fdb.c.doc["families"]["builtin"]["wins"] == 3)
    check("db None → {} (degrade)", SM.load_family_priors(None) == {})

    print(f"\nPASS={PASS} FAIL={FAIL}")
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())