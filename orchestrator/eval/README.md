# LLM-Katkı Eval Harness

**Amaç:** Denetimin en kritik bulgusunu kapatmak — *"otonom motorun LLM katmanı gerçekten
fark yaratıyor mu, deepseek yerel-9B'den iyi mi?"* sorusunu **kanıta** bağlamak. Aynı yetkili
hedef setini üç kolda koşar ve **doğrulanmış (verified=True) bulgu farkını × maliyeti** ölçer.

## Kollar

| Kol | Nasıl | Ne ölçülür |
|-----|-------|-----------|
| `rules-only` | `AUTONOMOUS_LLM_DISABLE=1` (kill-switch) — motor saf kural+graf | Taban (baseline) |
| `ollama` | aktif sağlayıcı = ollama (yerel 9B danışman) | LLM katkısı |
| `deepseek` | aktif sağlayıcı = deepseek (bulut danışman) | Bulut katkısı |

**Altın metrik:** `verified_findings` (aktif kanıtlanmış bulgu). Manşet sayımı değil — motorun
"tarayıcı"dan "pentester"a çıkıp çıkmadığını ölçen tek dürüst sayı. Maliyet: adım/süre/LLM-çağrısı.

## Çalıştırma

> ⚠️ **IN-PROCESS koş:** Motor `AUTONOMOUS_LLM_DISABLE`'ı ve aktif sağlayıcıyı kendi sürecinde
> okur → harness'i orchestrator konteyneri/venv içinde, servisler erişilebilirken çalıştırın.
> **Yalnız YETKİLİ hedefler:** `AUTHORIZED_TARGETS`'i doldurun (kapsam kapısı zaten zorlar).

```bash
# 1) Canlı sürüş — üç kolu tüm hedeflerde koş, karşılaştır
export AUTHORIZED_TARGETS="juice-shop.local,dvwa.local,testphp.vulnweb.local"
python3 llm_contribution_eval.py --manifest targets.json --out sonuc.json

# tek kol / seçili kollar
python3 llm_contribution_eval.py --manifest targets.json --modes rules-only,deepseek

# 2) Sadece rapor — önceden toplanmış run-record'ları karşılaştır (canlı stack GEREKMEZ)
python3 llm_contribution_eval.py --records sonuc.json
```

Manifest formatı için `targets.example.json`. `expected_findings` verilirse precision/recall
da hesaplanır (bulgu kimliği: `template-id@matched-at` ya da CVE).

## Çıktı (örnek yorum)

```
=== LLM-KATKI EVAL (taban: rules-only) ===
Hedef bazında (Δ = ek doğrulanmış bulgu):
  dvwa.local  (taban doğrulanmış: 3)
      deepseek   Δ=+2  katkı+  (+6 adım, 6 LLM çağrısı, 3.0 çağrı/bulgu)
TOPLU HÜKÜM:
  • deepseek: taban'a göre +2 ek DOĞRULANMIŞ bulgu (1/1 hedefte katkı) ... → KATKI KANITLI.
```

- **`total_delta > 0`** → LLM katkısı kanıtlı; "kaç LLM-çağrısı / ek bulgu" maliyeti gösterir.
- **`total_delta == 0`** → maliyet var, getiri yok → LLM'i bu profilde savunmak zor.
- **`total_delta < 0`** → LLM gürültü/zararlı; prompt ya da gating gözden geçirilmeli.

## Dosyalar

- `eval_metrics.py` — SAF karşılaştırma/hüküm çekirdeği (I/O yok, `test_eval_metrics.py` ile test).
- `llm_contribution_eval.py` — canlı sürücü (start→poll→metrik) + `--records` rapor modu.
- `test_eval_metrics.py` — çekirdek testleri (`python3 test_eval_metrics.py`).

## Not: metrik çıkarımı

`run_record_from_session` bitmiş session dict'inde `findings + confidence_tier` imzalı bloğu
**recursive** arar (rapor şemasının tam yoluna bağlanmaz). Sizin sürümünüzde rapor farklı bir
anahtarda duruyorsa çıkarım yine çalışır; `verified_findings` beklenenden düşük çıkarsa
`_find_findings_block` imzasını kendi şemanıza göre daraltın.
