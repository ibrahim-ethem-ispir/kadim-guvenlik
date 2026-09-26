"""
Kadim Güvenlik — LLM-Katkı Eval Harness (canlı sürücü)
======================================================
Türkçe: "İstihbarat subayı (LLM) gerçekten fark yaratıyor mu, deepseek yerel-9B'den iyi mi?"
sorusunu KANITA bağlar. Aynı yetkili hedef setini ÜÇ kolda koşar:
    rules-only   → AUTONOMOUS_LLM_DISABLE=1 (motor saf kural+graf)
    ollama       → yerel 9B danışman
    deepseek     → bulut danışman
ve her kolun DOĞRULANMIŞ (verified=True) bulgu sayısını + maliyetini (adım/süre/LLM-çağrısı)
karşılaştırır (eval_metrics çekirdeği). Çıktı: hedef-bazlı Δ + toplu hüküm + JSON.

⚠️ KOŞUM ORTAMI: Motor `AUTONOMOUS_LLM_DISABLE`'ı ve aktif sağlayıcıyı KENDİ SÜRECİNDE okur.
Bu yüzden harness IN-PROCESS çalışmalı (orchestrator konteyneri/venv içinde, servisler
erişilebilirken). Ayrıca YALNIZ yetkili hedeflerde koşun — AUTHORIZED_TARGETS'i doldurun
(kapsam kapısı zaten zorlar).

İki mod:
  1) Canlı sürüş:  python3 llm_contribution_eval.py --manifest targets.json --out out.json
  2) Sadece rapor: python3 llm_contribution_eval.py --records records.json
     (önceden toplanmış run-record'ları karşılaştırır — canlı stack gerekmez)
"""
import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_metrics import contribution_report, format_report_text  # noqa: E402

MODES = ("rules-only", "ollama", "deepseek")


# ---------- Session → run-record çıkarımı (şema-bağımsız, savunmacı) ----------
def _find_findings_block(obj: Any):
    """Session dict'inde `findings` listesi + (varsa) confirmed_severity_counts taşıyan
    ilk bloğu recursive bul. Rapor şemasının tam yolu sürümden sürüme değişebildiği için
    yola bağlanmayız; imzaya (findings + confidence_tier) bakarız."""
    if isinstance(obj, dict):
        f = obj.get("findings")
        if isinstance(f, list) and (
            "confirmed_severity_counts" in obj or "tier_counts" in obj
            or any(isinstance(x, dict) and "confidence_tier" in x for x in f)
        ):
            return obj
        for v in obj.values():
            hit = _find_findings_block(v)
            if hit is not None:
                return hit
    elif isinstance(obj, list):
        for v in obj:
            hit = _find_findings_block(v)
            if hit is not None:
                return hit
    return None


def _finding_key(f: Dict[str, Any]) -> str:
    info = f.get("info") or {}
    return (f.get("template-id") or info.get("name") or "?") + "@" + str(f.get("matched-at") or "")


def run_record_from_session(session: Dict[str, Any], *, mode: str, target: str) -> Dict[str, Any]:
    """Bitmiş session dict'inden standart run-record üret. verified_findings = ALTIN metrik
    (verified=True). LLM-çağrısı bilinemezse ai_analysis timeline'ından yaklaşık sayılır."""
    block = _find_findings_block(session) or {}
    findings = block.get("findings") or []
    verified_keys = [_finding_key(f) for f in findings if f.get("verified") is True]
    conf = block.get("confirmed_severity_counts") or {}
    confirmed = sum(conf.values()) if conf else sum(
        1 for f in findings if str((f.get("confidence_tier") or "")).lower() in ("confirmed", "probable")
    )
    ai = session.get("ai_analysis") or {}
    timeline = ai.get("agent_timeline") or []
    steps = len(timeline) or int(ai.get("steps") or 0)
    # rules-only'de LLM çağrısı yok (kill-switch). Diğer kollarda timeline'daki danışma
    # işaretlerini say (yoksa adım sayısını üst sınır olarak kullan — yaklaşık, dokümante).
    if mode == "rules-only":
        llm_calls = 0
    else:
        llm_calls = sum(1 for t in timeline if isinstance(t, dict)
                        and ("apprais" in str(t).lower() or "llm" in str(t).lower() or "danış" in str(t).lower()))
        llm_calls = llm_calls or steps
    return {
        "mode": mode, "target": target,
        "verified_findings": len(verified_keys),
        "confirmed_findings": confirmed,
        "findings": len(findings),
        "severity": conf,
        "steps": steps,
        "duration_s": float(session.get("duration_seconds") or 0),
        "llm_calls": llm_calls,
        "verified_keys": verified_keys,
    }


# ---------- Canlı sürüş ----------
def _apply_mode_env(mode: str) -> Optional[str]:
    """Kolun modunu süreç ortamına uygula. Döner: geri-yükleme için önceki sağlayıcı (ollama/
    deepseek kollarında) ya da None. rules-only → AUTONOMOUS_LLM_DISABLE=1."""
    os.environ.pop("AUTONOMOUS_LLM_DISABLE", None)
    if mode == "rules-only":
        os.environ["AUTONOMOUS_LLM_DISABLE"] = "1"
        return None
    # Sağlayıcıyı runtime toggle ile seç (DB > .env resolver'ı bunu okur).
    from integrations.llm_env_config import get_autonomous_provider, set_autonomous_provider
    prev = get_autonomous_provider()
    set_autonomous_provider(mode)
    return prev


def _restore_provider(prev: Optional[str]) -> None:
    os.environ.pop("AUTONOMOUS_LLM_DISABLE", None)
    if prev:
        from integrations.llm_env_config import set_autonomous_provider
        set_autonomous_provider(prev)


async def drive_scan(pipeline, target: str, level: str, mode: str,
                     poll_s: float = 5.0, timeout_s: float = 3600.0) -> Dict[str, Any]:
    """Tek (mode,target) taramasını sür: env ayarla → başlat → tamamlanana dek poll → metrik."""
    prev = _apply_mode_env(mode)
    try:
        started = await pipeline.start_pipeline(target=target, level=level, profile_name="normal")
        scan_id = started.get("scan_id") or started.get("session_id")
        deadline = time.time() + timeout_s
        session = None
        while time.time() < deadline:
            session = pipeline.get_session_by_scan_id(scan_id) or {}
            if str(session.get("status") or "").lower() in ("completed", "failed", "cancelled", "done"):
                break
            await asyncio.sleep(poll_s)
        return run_record_from_session(session or {}, mode=mode, target=target)
    finally:
        _restore_provider(prev)


async def run_live(manifest: Dict[str, Any], modes: List[str]) -> List[Dict[str, Any]]:
    from pipeline.scan_pipeline_v2 import ScanPipelineV2
    pipeline = ScanPipelineV2()
    records: List[Dict[str, Any]] = []
    level = manifest.get("level", "standard")
    for tgt in manifest.get("targets", []):
        target = tgt if isinstance(tgt, str) else tgt.get("target")
        tlevel = level if isinstance(tgt, str) else tgt.get("level", level)
        for mode in modes:
            print(f"▶ {target} × {mode} ...", flush=True)
            rec = await drive_scan(pipeline, target, tlevel, mode)
            print(f"  ← doğrulanmış={rec['verified_findings']} adım={rec['steps']} süre={rec['duration_s']:.0f}s")
            records.append(rec)
    return records


def _ground_truth(manifest: Dict[str, Any]) -> Optional[Dict[str, List[str]]]:
    gt = {}
    for tgt in manifest.get("targets", []):
        if isinstance(tgt, dict) and tgt.get("expected_findings"):
            gt[tgt["target"]] = tgt["expected_findings"]
    return gt or None


def main():
    ap = argparse.ArgumentParser(description="Kadim LLM-katkı eval harness")
    ap.add_argument("--manifest", help="hedef manifesti (targets.json) — canlı sürüş")
    ap.add_argument("--records", help="önceden toplanmış run-record'lar (JSON list) — sadece rapor")
    ap.add_argument("--modes", default=",".join(MODES), help="virgülle kollar (varsayılan hepsi)")
    ap.add_argument("--out", help="run-record'ları JSON'a yaz")
    args = ap.parse_args()

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    ground_truth = None

    if args.records:
        with open(args.records, encoding="utf-8") as fh:
            records = json.load(fh)
    elif args.manifest:
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = json.load(fh)
        ground_truth = _ground_truth(manifest)
        records = asyncio.run(run_live(manifest, modes))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(records, fh, ensure_ascii=False, indent=2)
            print(f"📝 run-record'lar yazıldı: {args.out}")
    else:
        ap.error("--manifest (canlı) ya da --records (sadece rapor) verin.")

    report = contribution_report(records, ground_truth=ground_truth)
    print()
    print(format_report_text(report))
    if args.out:
        rep_path = args.out.rsplit(".", 1)[0] + ".report.json"
        with open(rep_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"\n📊 karşılaştırma raporu: {rep_path}")


if __name__ == "__main__":
    main()
