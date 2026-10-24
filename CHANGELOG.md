# Changelog

Önemli değişiklikler.

## [Unreleased]

### Değişen — Docker imaj/build optimizasyonu
- 7 Rust servisi (`auth`, `recon`, `osint`, `fuzz`, `hash-cracker`, `stress`, `researcher`)
  **tek Cargo workspace** altında toplandı: `services/rust/`. Ortak bağımlılıklar bir kez
  derlenir, tek `Cargo.lock`, tek `target/`. `wifi-service` Kali/actix tabanı nedeniyle ayrı kaldı.
- Servis başına 7 `Dockerfile` silindi → tek `services/rust/Dockerfile`
  (`SERVICE` / `BIN` / `PORT` / `EXTRA_APT` build argümanları) + BuildKit cache mount'ları.
- Build context'leri küçültüldü (`Dockerfile.dockerignore`): recon-service 1.6 GB → 8.5 kB.
- Python servislerine `.dockerignore` eklendi (venv/`__pycache__`/log imaja girmiyor).
- `crawler-service` base imajı `playwright/python:1.62.0-jammy` → `python:3.11-slim` +
  `playwright install --only-shell chromium`: imaj **3.73 GB → 1.43 GB**.
- Release profili tek yerde (`services/rust/Cargo.toml`): `lto + codegen-units=1 + strip`.
  Rust imajları: auth 185→161 MB, recon 181→168 MB, osint 252→168 MB, fuzz 189→181 MB,
  stress (yeni) 156 MB.

## [1.0.0] - 2026-09-26

İlk açık kaynak sürüm.

### Eklenen
- Otonom tarama motoru: attack-graph skorlama, playbook gate, bütçe/timeout, loop-guard
- 15 mikroservis (Python / Rust / Go): nmap, rustscan, nuclei, subfinder, recon, osint, fuzz (Feroxbuster), crawler (headless), fingerprint (wappalyzergo), hash-cracker, stress, researcher, wifi, ai-service, auth-service (Rust/JWT) + React UI
- AI danışman katmanı: LLM skoru etkiler, karar deterministik kural+graf; erişilemezse kural-fallback (Ollama / DeepSeek / Claude / Gemini)
- Security Memory: Qdrant vektör hafıza (best-effort, varsayılan kapalı)
- Rapor motoru + otonom tarama sonuç sözleşmesi
- Kayıt sistemi: `REGISTER_ENABLED` / `AUTO_ACTIVATE_USERS` varsayılan açık
- MIT lisansı, katkı rehberi, issue/PR şablonları