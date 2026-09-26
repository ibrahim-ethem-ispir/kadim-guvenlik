# Changelog

Önemli değişiklikler.

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