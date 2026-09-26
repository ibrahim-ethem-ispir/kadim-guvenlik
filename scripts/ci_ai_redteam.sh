#!/usr/bin/env bash
# ==============================================================================
# CI: AI Red-Team Sürekli Ölçüm Kapısı (GERÇEK ayrım — mock değil)
# ------------------------------------------------------------------------------
# Türkçe: Her PR/commit'te AI red-team motorunun tespit kabiliyetini ÖLÇER ve
# regresyonda CI'ı KIRAR. Dört iş tek komutta:
#   0) Birim kapı      — compliance_map + llm_redteam + ai_redteam SAF testleri (ağ yok)
#   1) Süit kapısı     — ÇOK-PROFİLLİ yerel adversarial süit: all expected detected (recall=1.0)
#                        VE sertleştirilmiş bed'lerde tek bir FP yok (specificity=1.0)
#   2) Regresyon kapısı— commit'li baseline'a göre kayıp/FP varsa exit!=0
#   3) Skor tablosu    — geçmişe ekler + kendi-kendine yeten HTML dashboard üretir
#
# NEDEN çok-profilli: tek naif mock recall=1.0 verir ama HİÇBİR ŞEY ölçmez. Süit; naif +
# SERTLEŞTİRİLMİŞ (temiz kalmalı) + sadece-indirect + sadece-çok-tur + system-sızdıran +
# çıktı-işleyen + tool-çalıştıran profilleri içerir → hem recall hem specificity ölçer.
#
# Kullanım (CI adımı veya lokal):
#   bash scripts/ci_ai_redteam.sh
# Canlı testbed'leri de katmak için (opsiyonel, ağ ister):
#   AI_RT_CONFIG=scripts/ai_redteam_beds.json bash scripts/ci_ai_redteam.sh
#
# Ortam değişkenleri (hepsi opsiyonel):
#   AI_RT_BASELINE  baseline JSON (varsa regresyon kapısı açılır)   [scripts/ai_redteam_baseline.json]
#   AI_RT_HISTORY   koşum geçmişi JSON dizisi                       [scripts/ai_redteam_history.json]
#   AI_RT_BOARD     üretilecek HTML skor tablosu                    [scripts/ai_redteam_scoreboard.html]
#   AI_RT_CONFIG    canlı testbed ground-truth (ek koşum)           [yok]
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASELINE="${AI_RT_BASELINE:-scripts/ai_redteam_baseline.json}"
HISTORY="${AI_RT_HISTORY:-scripts/ai_redteam_history.json}"
BOARD="${AI_RT_BOARD:-scripts/ai_redteam_scoreboard.html}"

echo "▶ 0/3 Birim kapı: compliance + red-team SAF testleri"
python3 orchestrator/pipeline/test_compliance_map.py
python3 orchestrator/pipeline/test_ai_redteam.py
python3 orchestrator/pipeline/test_llm_redteam.py
python3 orchestrator/pipeline/test_verifier_sampling.py

echo "▶ 1+2+3/3 Yerel adversarial süit + regresyon kapısı + skor tablosu"
MOCK_ARGS=(--local --history "$HISTORY" --scoreboard "$BOARD")
if [ -f "$BASELINE" ]; then
  echo "  baseline bulundu → regresyon kapısı AÇIK: $BASELINE"
  MOCK_ARGS+=(--gate --baseline "$BASELINE")
else
  echo "  ⚠ baseline yok ($BASELINE) → yalnız süit kapısı. Tohumla:"
  echo "     python3 scripts/ai_redteam_benchmark.py --local --write-baseline $BASELINE"
fi
python3 scripts/ai_redteam_benchmark.py "${MOCK_ARGS[@]}"

# Opsiyonel: canlı testbed'ler (ağ gerektirir; ground-truth verildiyse).
if [ -n "${AI_RT_CONFIG:-}" ] && [ -f "${AI_RT_CONFIG}" ]; then
  echo "▶ Canlı testbed koşumu: ${AI_RT_CONFIG}"
  python3 scripts/ai_redteam_benchmark.py --config "${AI_RT_CONFIG}" --history "$HISTORY" --scoreboard "$BOARD"
fi

echo "✅ CI kapısı geçti · skor tablosu: $BOARD"