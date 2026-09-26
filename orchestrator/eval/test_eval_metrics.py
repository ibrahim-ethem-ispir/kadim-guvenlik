"""
Kadim Güvenlik — LLM-Katkı Eval metrik çekirdeği testleri (düz script, pytest yok)
=================================================================================
Çalıştır: `python3 test_eval_metrics.py` (orchestrator/eval içinden).
Karşılaştırma/hüküm mantığını canlı stack olmadan izole doğrular.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_metrics import contribution_report, group_by_target, format_report_text

_fail = []


def ok(cond, msg):
    print(("  [OK] " if cond else "  [FAIL] ") + msg)
    if not cond:
        _fail.append(msg)


def _rec(mode, target, verified, steps, llm_calls, keys=None):
    return {"mode": mode, "target": target, "verified_findings": verified,
            "confirmed_findings": verified, "findings": verified, "steps": steps,
            "duration_s": steps * 10.0, "llm_calls": llm_calls,
            "verified_keys": keys or []}


def test_llm_helps():
    recs = [
        _rec("rules-only", "a.com", 2, 20, 0, ["CVE-1", "CVE-2"]),
        _rec("deepseek", "a.com", 4, 26, 6, ["CVE-1", "CVE-2", "CVE-3", "CVE-4"]),
    ]
    rep = contribution_report(recs)
    agg = rep["aggregate"]["deepseek"]
    ok(agg["total_delta"] == 2, f"toplam Δ=2 (LLM +2 doğrulanmış): {agg['total_delta']}")
    ok(agg["targets_improved"] == 1, "1 hedefte katkı")
    ok("KATKI KANITLI" in rep["verdict"]["deepseek"], "hüküm: katkı kanıtlı")
    ok(agg["llm_calls_per_added_finding"] == 3.0, f"6 çağrı / 2 bulgu = 3.0: {agg['llm_calls_per_added_finding']}")


def test_llm_no_help():
    recs = [
        _rec("rules-only", "b.com", 3, 18, 0),
        _rec("ollama", "b.com", 3, 22, 8),   # aynı bulgu, ekstra maliyet
    ]
    rep = contribution_report(recs)
    ok(rep["aggregate"]["ollama"]["total_delta"] == 0, "Δ=0 (katkı yok)")
    ok("KANITLANAMADI" in rep["verdict"]["ollama"], "hüküm: katkı kanıtlanamadı")


def test_llm_regression():
    recs = [
        _rec("rules-only", "c.com", 5, 20, 0),
        _rec("deepseek", "c.com", 3, 30, 10),  # LLM yanlış yöne itti, daha az doğrulandı
    ]
    rep = contribution_report(recs)
    ok(rep["aggregate"]["deepseek"]["total_delta"] == -2, "Δ=-2 (regresyon)")
    ok("ZARARLI" in rep["verdict"]["deepseek"], "hüküm: zararlı/gürültü")


def test_precision_recall():
    gt = {"d.com": ["CVE-1", "CVE-2", "CVE-9"]}  # beklenen 3
    recs = [
        _rec("rules-only", "d.com", 1, 20, 0, ["CVE-1"]),
        _rec("deepseek", "d.com", 3, 28, 5, ["CVE-1", "CVE-2", "CVE-XX"]),  # 2 doğru, 1 yanlış
    ]
    rep = contribution_report(recs, ground_truth=gt)
    d = rep["per_target"]["d.com"]["modes"]["deepseek"]
    ok(d["precision"] == round(2 / 3, 3), f"precision=2/3: {d['precision']}")
    ok(d["recall"] == round(2 / 3, 3), f"recall=2/3: {d['recall']}")


def test_missing_baseline_skipped():
    recs = [_rec("deepseek", "e.com", 4, 20, 5)]  # taban yok
    rep = contribution_report(recs)
    ok("e.com" not in rep["per_target"], "taban'sız hedef karşılaştırmadan çıkarıldı")


def test_grouping_and_format():
    recs = [_rec("rules-only", "f.com", 2, 20, 0), _rec("deepseek", "f.com", 3, 24, 4)]
    g = group_by_target(recs)
    ok(set(g["f.com"].keys()) == {"rules-only", "deepseek"}, "gruplama iki kolu topladı")
    txt = format_report_text(contribution_report(recs))
    ok("LLM-KATKI EVAL" in txt and "TOPLU HÜKÜM" in txt, "metin rapor üretildi")


if __name__ == "__main__":
    for fn in (test_llm_helps, test_llm_no_help, test_llm_regression,
               test_precision_recall, test_missing_baseline_skipped, test_grouping_and_format):
        print(f"=== {fn.__name__} ===")
        fn()
    print()
    if _fail:
        print(f"{len(_fail)} test BAŞARISIZ")
        sys.exit(1)
    print("Tüm eval-metrik testleri geçti.")
