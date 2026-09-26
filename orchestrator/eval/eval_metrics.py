"""
Kadim Güvenlik — LLM-Katkı Eval: Metrik & Karşılaştırma Çekirdeği (SAF, stdlib)
==============================================================================
Türkçe: Denetimin EN KRİTİK bulgusu — "otonom motorun LLM katmanı gerçekten fark yaratıyor
mu, yoksa maliyetli bir inanç mı?" — kanıta bağlanmalı. Bu modül, aynı hedef setini üç kolda
koşup (rules-only / ollama / deepseek) toplanan ÇALIŞMA KAYITLARINI karşılaştırır ve tek
soruyu yanıtlar: **LLM kolu, taban (rules-only) koluna göre kaç EK DOĞRULANMIŞ bulgu buldu,
hangi maliyetle?**

Bu dosya SAF ve I/O'suz → izole test edilir (test_eval_metrics.py). Canlı taramayı süren
kısım llm_contribution_eval.py'dir (bu çekirdeği besler).

Çalışma-kaydı (run record) sözleşmesi — her (mode, target) için bir dict:
    {
      "mode": "rules-only" | "ollama" | "deepseek",
      "target": "bank.com.tr",
      "verified_findings": int,     # verified=True kanıt sayısı (ALTIN metrik: aktif kanıtlanmış)
      "confirmed_findings": int,    # confirmed+probable toplam (rapor manşeti)
      "findings": int,              # toplam kanıt (unconfirmed dahil)
      "severity": {"critical":int,"high":int,"medium":int,"low":int,"info":int},  # confirmed_severity_counts
      "steps": int,                 # motorun harcadığı adım (maliyet)
      "duration_s": float,          # süre (maliyet)
      "llm_calls": int,             # LLM danışma sayısı (rules-only'de 0)
      "verified_keys": [str, ...],  # (ops.) doğrulanan bulgu kimlikleri — precision/recall için
    }
"""
from typing import Any, Dict, List, Optional

BASELINE_MODE = "rules-only"
_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _num(rec: Dict[str, Any], key: str, default: float = 0) -> float:
    try:
        return float(rec.get(key, default) or 0)
    except (TypeError, ValueError):
        return default


def group_by_target(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """[{mode,target,...}] → {target: {mode: record}}. Aynı (target,mode) tekrarında
    SON kayıt kazanır (yeniden koşum idempotent)."""
    out: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for rec in records or []:
        tgt = str(rec.get("target") or "").strip()
        mode = str(rec.get("mode") or "").strip()
        if not tgt or not mode:
            continue
        out.setdefault(tgt, {})[mode] = rec
    return out


def _prec_recall(verified_keys, expected_keys):
    """precision = doğru-doğrulanan / tüm-doğrulanan; recall = doğru-doğrulanan / beklenen.
    expected_keys None ise (ground-truth yok) → (None, None)."""
    if expected_keys is None:
        return None, None
    v = {str(k) for k in (verified_keys or [])}
    e = {str(k) for k in expected_keys}
    if not v and not e:
        return 1.0, 1.0
    tp = len(v & e)
    precision = tp / len(v) if v else 0.0
    recall = tp / len(e) if e else 0.0
    return round(precision, 3), round(recall, 3)


def contribution_report(
    records: List[Dict[str, Any]],
    ground_truth: Optional[Dict[str, List[str]]] = None,
    baseline: str = BASELINE_MODE,
) -> Dict[str, Any]:
    """Kolları taban'a göre karşılaştır. Döner: {per_target, aggregate, verdict}.

    per_target[target][mode]: {verified, delta_vs_baseline, extra_steps, extra_duration_s,
                               llm_calls, cost_per_added_finding, precision, recall, verdict}
    aggregate[mode]: toplulaştırılmış katkı + maliyet + ortalama precision/recall.
    verdict[mode]: LLM kolu maliyetini hak ediyor mu? (kanıta dayalı tek-cümle)."""
    grouped = group_by_target(records)
    gt = ground_truth or {}
    modes = sorted({str(r.get("mode")) for r in (records or []) if r.get("mode")} - {baseline})

    per_target: Dict[str, Any] = {}
    agg = {m: {"targets": 0, "total_delta": 0.0, "baseline_verified": 0.0,
               "mode_verified": 0.0, "improved": 0, "regressed": 0, "neutral": 0,
               "extra_steps": 0.0, "extra_duration_s": 0.0, "llm_calls": 0.0,
               "prec_sum": 0.0, "prec_n": 0, "rec_sum": 0.0, "rec_n": 0}
           for m in modes}

    for tgt, by_mode in grouped.items():
        base = by_mode.get(baseline)
        if base is None:
            continue  # taban kolu olmayan hedef karşılaştırılamaz (atla)
        base_v = _num(base, "verified_findings")
        expected = gt.get(tgt)
        row: Dict[str, Any] = {"baseline_verified": base_v, "modes": {}}
        for m in modes:
            rec = by_mode.get(m)
            if rec is None:
                continue
            v = _num(rec, "verified_findings")
            delta = v - base_v
            extra_steps = _num(rec, "steps") - _num(base, "steps")
            extra_dur = _num(rec, "duration_s") - _num(base, "duration_s")
            llm_calls = _num(rec, "llm_calls")
            cost_per_added = (llm_calls / delta) if delta > 0 else None
            precision, recall = _prec_recall(rec.get("verified_keys"), expected)
            verdict = "katkı+" if delta > 0 else ("regresyon-" if delta < 0 else "nötr=")
            row["modes"][m] = {
                "verified": v, "delta_vs_baseline": delta,
                "extra_steps": extra_steps, "extra_duration_s": round(extra_dur, 2),
                "llm_calls": llm_calls,
                "cost_per_added_finding": (round(cost_per_added, 2) if cost_per_added else None),
                "precision": precision, "recall": recall, "verdict": verdict,
            }
            a = agg[m]
            a["targets"] += 1
            a["total_delta"] += delta
            a["baseline_verified"] += base_v
            a["mode_verified"] += v
            a["extra_steps"] += extra_steps
            a["extra_duration_s"] += extra_dur
            a["llm_calls"] += llm_calls
            a["improved"] += 1 if delta > 0 else 0
            a["regressed"] += 1 if delta < 0 else 0
            a["neutral"] += 1 if delta == 0 else 0
            if precision is not None:
                a["prec_sum"] += precision; a["prec_n"] += 1
            if recall is not None:
                a["rec_sum"] += recall; a["rec_n"] += 1
        per_target[tgt] = row

    aggregate: Dict[str, Any] = {}
    verdict: Dict[str, str] = {}
    for m, a in agg.items():
        n = a["targets"] or 1
        avg_prec = round(a["prec_sum"] / a["prec_n"], 3) if a["prec_n"] else None
        avg_rec = round(a["rec_sum"] / a["rec_n"], 3) if a["rec_n"] else None
        cost_per_added = round(a["llm_calls"] / a["total_delta"], 2) if a["total_delta"] > 0 else None
        aggregate[m] = {
            "targets": a["targets"],
            "baseline_total_verified": a["baseline_verified"],
            "mode_total_verified": a["mode_verified"],
            "total_delta": a["total_delta"],
            "targets_improved": a["improved"],
            "targets_regressed": a["regressed"],
            "targets_neutral": a["neutral"],
            "pct_targets_improved": round(100.0 * a["improved"] / n, 1),
            "total_llm_calls": a["llm_calls"],
            "total_extra_steps": a["extra_steps"],
            "total_extra_duration_s": round(a["extra_duration_s"], 2),
            "llm_calls_per_added_finding": cost_per_added,
            "avg_precision": avg_prec,
            "avg_recall": avg_rec,
        }
        # Kanıta dayalı tek-cümle hüküm.
        if a["total_delta"] > 0:
            verdict[m] = (
                f"{m}: taban'a göre +{a['total_delta']:.0f} ek DOĞRULANMIŞ bulgu "
                f"({a['improved']}/{a['targets']} hedefte katkı), maliyet ~{cost_per_added} "
                f"LLM-çağrısı/bulgu → KATKI KANITLI."
            )
        elif a["total_delta"] == 0:
            verdict[m] = (
                f"{m}: taban'a göre ek doğrulanmış bulgu YOK (+0), ama {a['llm_calls']:.0f} "
                f"LLM-çağrısı harcandı → KATKI KANITLANAMADI (maliyet var, getiri yok)."
            )
        else:
            verdict[m] = (
                f"{m}: taban'dan DAHA AZ doğrulanmış bulgu ({a['total_delta']:.0f}); "
                f"{a['regressed']}/{a['targets']} hedefte regresyon → ZARARLI/gürültü, gözden geçir."
            )

    return {"per_target": per_target, "aggregate": aggregate,
            "verdict": verdict, "baseline": baseline, "modes": modes}


def format_report_text(report: Dict[str, Any]) -> str:
    """İnsan-okunur özet (operatör/CI çıktısı)."""
    lines: List[str] = []
    base = report.get("baseline")
    lines.append(f"=== LLM-KATKI EVAL (taban: {base}) ===")
    lines.append("")
    lines.append("Hedef bazında (Δ = ek doğrulanmış bulgu):")
    for tgt, row in report.get("per_target", {}).items():
        lines.append(f"  {tgt}  (taban doğrulanmış: {row['baseline_verified']:.0f})")
        for m, d in row.get("modes", {}).items():
            pr = "" if d["precision"] is None else f", P={d['precision']} R={d['recall']}"
            cpa = "" if d["cost_per_added_finding"] is None else f", {d['cost_per_added_finding']} çağrı/bulgu"
            lines.append(f"      {m:<10} Δ={d['delta_vs_baseline']:+.0f}  {d['verdict']}"
                         f"  (+{d['extra_steps']:.0f} adım, {d['llm_calls']:.0f} LLM çağrısı{cpa}{pr})")
    lines.append("")
    lines.append("TOPLU HÜKÜM:")
    for m, v in report.get("verdict", {}).items():
        lines.append(f"  • {v}")
    return "\n".join(lines)
