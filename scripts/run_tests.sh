#!/usr/bin/env bash
# Türkçe: Toplu test koşucu — repo doktrini: pytest YOK; her test_*.py düz scripttir
# (sys.path'ini kendi kurar, ağ/DB/LLM gerekmez). CI ve yerel için TEK giriş noktası.
#
# Kullanım:
#   bash scripts/run_tests.sh              # tüm suite
#   bash scripts/run_tests.sh test_k8s     # dosya adında filtre (opsiyonel)
set -u
cd "$(dirname "$0")/.."

filtre="${1:-}"
gecen=0
dusen=0
dusenler=()

while IFS= read -r dosya; do
  if [ -n "$filtre" ] && [[ "$dosya" != *"$filtre"* ]]; then
    continue
  fi
  cikti="$(python3 "$dosya" 2>&1)"
  if [ $? -eq 0 ]; then
    gecen=$((gecen + 1))
    echo "✓ $dosya"
  else
    dusen=$((dusen + 1))
    dusenler+=("$dosya")
    echo "✗ $dosya"
    echo "$cikti" | tail -12
  fi
done < <(find orchestrator services scripts -name 'test_*.py' \
           -not -path '*/node_modules/*' -not -path '*/target/*' | sort)

echo "────────────────────────────"
echo "geçen: $gecen  düşen: $dusen"
if [ "$dusen" -gt 0 ]; then
  echo "DÜŞENLER:"
  printf '  %s\n' "${dusenler[@]}"
  exit 1
fi