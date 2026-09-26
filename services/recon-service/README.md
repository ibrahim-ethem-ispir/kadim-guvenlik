# recon-service (Rust)

Kadim Güvenlik **keşif/istihbarat** mikroservisi — otonom motorun "hedefi tanıma" katmanı.

## Ne yapar

- **Subdomain keşfi** (`subdomain.rs`): wordlist tabanlı enum + DNS doğrulama (`dns.rs`)
- **Teknoloji parmak izi** (`tech_detector_clean.rs`): Wappalyzer-benzeri imza tabanı —
  isim/sürüm/kategori/CPE (Kubernetes/Rancher, CMS'ler, framework'ler, sunucu yazılımları)
- **Origin / gerçek IP keşfi** (`spoof.rs`): CDN/Cloudflare arkasındaki origin IP'yi
  DNS/HTTP sinyalleriyle arama
- **HTTP keşif** (`http.rs`): başlık/gövde analizi
- **MongoDB kayıt** (`database.rs`): sonuçlar `kadim_security` DB'sine yazılır

Orchestrator bu servisi HTTP ile tetikler; bulgular `scan_pipeline_v2` keşif aşamasına
beslenir (teknoloji → CVE/nuclei tag zincirinin tetikleyicisi).

## Geliştirme

```bash
cd services/recon-service
cargo build --release
```

Ortam değişkenleri: `MONGODB_URI`, `MONGODB_DATABASE`, `RUST_LOG`, `PORT`
(değerler için bkz. `docker-compose.yml`).

## Docker

Platform düzeyinde: `docker compose up -d recon-service` (iç ağ `kadim-net`).