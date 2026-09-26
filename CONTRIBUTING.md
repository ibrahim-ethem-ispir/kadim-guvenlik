# Katkıda Bulunma Rehberi

Katkılar memnuniyetle karşılanır — yeni araç servisi, prob modülü, hata düzeltmesi veya dokümantasyon.

## Akış

1. Depoyu **fork** edin.
2. `feature/yeni-ozellik` veya `fix/hata-aciklamasi` biçiminde branch açın.
3. Değişikliği yapın ve test edin.
4. Pull Request açın — **ne** yaptığınızı ve **neden** yaptığınızı yazın.

## Geliştirme ortamı

```bash
docker compose up -d          # tam stack (UI: http://localhost:5566)
cd frontend && pnpm dev       # frontend geliştirme
```

Tek servis üzerinde çalışmak için ilgili `services/<araç>-service/` klasörüne bakın; her araç bağımsız bir mikroservistir.

## Yeni araç servisi ekleme

1. `services/<yeni-arac>-service/` klasörünü mevcut bir servisten örnek alarak oluşturun.
2. `docker-compose.yml`'e ekleyin (iç ağ `kadim-net`).
3. `orchestrator/integrations/` içine proxy, `orchestrator/pipeline/scan_pipeline_v2.py` içine dispatcher kaydı ekleyin.
4. Sonuç sözleşmesinde `results` anahtarı zorunludur (`orchestrator/pipeline/autonomous_report.py`).

Yeni yerli prob: `orchestrator/pipeline/<x>_probe.py` (ağ/DB bağımsız saf çekirdek) → `_probe_<x>` → post-observe'a best-effort çağrı → `playbook.py` relevance gate → env flag.

## Testler

Python testleri düz script'tir (pytest yok). Tüm suite tek komutta (CI ile aynı):

```bash
bash scripts/run_tests.sh                # tüm test dosyaları
bash scripts/run_tests.sh test_k8s       # isim filtresi (opsiyonel)
python3 orchestrator/pipeline/test_playbook.py   # tek dosya
```

PR'dan önce `bash scripts/run_tests.sh` yeşil olmalı; etkilediğiniz modülün testini çalıştırın, yoksa ekleyin. Statik analiz: `ruff check .` (bkz. `ruff.toml`).

## Commit mesajları

Conventional Commits: `feat:`, `fix:`, `docs:`, `chore:`

## Kurallar

- PR tek bir konuya odaklansın.
- Yeni bağımlılık ekliyorsanız gerekçesini yazın.
- API anahtarı, parola veya `.env` içeriği **asla** commit etmeyin.
- Güvenlik açıklarını issue ile değil [SECURITY.md](SECURITY.md) üzerinden bildirin.