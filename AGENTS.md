# AGENTS.md — Kadim Güvenlik

Derin mimari/konvansiyon: kök **CLAUDE.md** (tek kaynak). Bu dosya hızlı navigasyon. Dil **Türkçe**.

## 1. Özet
Otonom güvenlik tarama platformu. Her araç (nmap, nuclei, subfinder, recon, osint, fuzz, crawler, ...) ayrı FastAPI mikroservisi; **orchestrator** bir pipeline'da birleştirir; React Router 7 frontend olayları WebSocket'ten izler. LLM "istihbarat subayı" DANIŞIR ama **karar deterministik kural+graf skorunda** — düşerse motor kural-fallback ile sürer.

## 2. Dizin haritası
| Yol | Sorumluluk |
|-----|-----------|
| `orchestrator/main.py` | FastAPI :8000; router'lar + REST (`/scan`, `/v2/scan`) |
| `orchestrator/pipeline/` | Tarama beyni — motor, graf, prob'lar (bkz. §4) |
| `orchestrator/core/` | `db.py` (Mongo singleton), `config`, `scoring`, `auth_middleware` |
| `orchestrator/integrations/` | servis proxy'leri + `settings_router` + `llm_env_config.py` |
| `services/ai-service/main.py` | LLM analiz+chat, provider routing (`analyze_with_*`) |
| `services/<tool>-service/` | tekil tarayıcı FastAPI'leri |
| `frontend/app/routes/auto-scan.tsx` | otonom tarama sayfası (ana UI) |
| `frontend/app/hooks/usePipelineStream.ts` | canlı WS akışı (reconnect+replay) |
| `nginx/` + `docker-compose.yml` | gateway `5566:80`, mongo `27018:27017` |

## 3. Nereye bakılır
| İş | Dosya |
|----|-------|
| Yeni araç aşaması (dış servis) | `scan_pipeline_v2.py` → `ToolDispatcher._dispatch_*` + `_DISPATCH` map (~597) |
| Yeni yerli prob | yeni `pipeline/<x>_probe.py` (SAF) + `_probe_*` metodu + playbook gate + flag |
| Bulgu/severity/dedup | `autonomous_engine.py` `Evidence` (~367); `attack_graph.py` `integrate` |
| Skorlama (hamle sırası) | `attack_graph.py` `siege_score` (~432) |
| Rapor sözleşmesi | `pipeline/autonomous_report.py` + ai-service `report_engine.py`/`scan_analyzer.py` |
| CVE/imza/tag | `cve_intel.py`, `kev_intel.py`, `adaptive_scanner.py` (tech→tag) |
| LLM sağlayıcı ekle | `llm_env_config.py` (**İKİ kopya!**) + ai-service routing + `get_ai_models` + `AIModelSelector` |
| Hedef profili/gating | `target_profile.py`, `playbook.py` |
| Payload corpus (PATT süzülmüş) | `payload_corpus.py` loader + `data/payloads/*.json`; üretim: `scripts/extract_patt_corpus.py` (runtime DEĞİL) |
| Davranış denetimi (loop-guard) | `behavior_monitor.py` (SAF) → engine `observe`/`next_decision` çarpanı; env `LOOP_GUARD_*` |
| Vektör hafıza (Qdrant) | `memory_store.py` (SAF, best-effort) → pipeline recall/write; env `VECTOR_MEMORY_ENABLED` (vars. KAPALI), `QDRANT_URL`, `VECTOR_EMBED_MODEL`; compose `qdrant` servisi |

## 4. OTONOM TARAMA (ana senaryo)
**Giriş:** `POST /api/v2/scan {target, profile:"autonomous", level, target_kind, auth, auth_b}` → `start_pipeline` (~2767). `profile==autonomous` veya `LEGACY_PROFILES_ENABLED=false` → `_run_autonomous` (asyncio task, ~3094).

**Akış:** `ToolDispatcher` + `AutonomousEngine(...emit=narrate)` → `preflight()` (LLM sağlığı) + `_probe_required_services` (servis ayakta mı) → `_ensure_target_profile` (recon-first) → **döngü** `while engine.budget_left()`:
1. **DECIDE** `next_decision()`: CVE enrich → `expand_frontier` → (ops) LLM `appraise` → `siege_score` sırala → `_validate`. Döner `(Decision, considered)`.
2. `_verify_hypotheses` — LLM hipotezini deterministik verifier KANITLAR.
3. Terminal: `STOP` / `REQUEST_APPROVAL` / `PHASE_GATE` (keşif→sömürü onay kapısı).
4. **ACT** `to_stage()` → `dispatcher.dispatch` (8sn heartbeat, iptal ≤8sn). Artifact sakla; düşen aşama `is_degraded`→WARNING.
5. **OBSERVE** `observe(decision,data,status)`: grafa yaz, `AdaptiveScanner` besle, öğren → yeni Evidence sayısı.
6. Post-observe (best-effort, playbook-gate'li): `_verify_new_evidence`, `_annotate_catchall_findings` (FP demote), `_adjudicate_unconfirmed`, WAF fingerprint, `_probe_discovered_services`/`_kubernetes`/`_wordpress`/`_wp_sqli`/`_idor`/`_web_misconfig`/`_deserialization`, `_execute_chains`, `_synthesize_combinations`, `_redteam_llm_endpoints`.

**Çıkış:** `engine.summary()` (+stage_health+coverage) → `session.ai_analysis`; `_save_autonomous_evidence`; `emit_scan_completed`; `_trigger_autonomous_report` → ai-service `POST /brain/analyze/v2`.

**Önceliklendirme:** `siege_score = base(hedef değeri) × urgency × novelty × killchain_drive × curiosity`; en yüksek kenar seçilir. LLM yalnız `apply_intel` ile skoru etkiler, karar vermez.

**Bütçe/timeout:** Seviye `SCAN_LEVELS` (~211): `recon`/`standard`(varsayılan)/`deep` — `max_steps`, `threshold`, `allow_crawl/dast/fuzz`. `AUTONOMOUS_MAX_STEPS`, `AUTONOMOUS_MAX_SECONDS`; nmap `nmap_stage_timeout(opts)` (kapsama-duyarlı); `session.stealth`→nmap `-T2`.

**Bulgu modeli** `Evidence` (~367): `title,severity,cve,target,proof,tool,step,request/response/curl,cwe,cvss_v3,attack_techniques,apt_groups`. FP ekseni AYRI: `verified` (aktif teyit), `confidence_tier` (confirmed/probable/unconfirmed, `effective_confidence_tier()` türetir), `fp_reason`, `llm_fp_opinion`. Dedup: graf `executed_signatures` + nuclei tag kayıt.

**Sonuç (Mongo `kadim_security`):** `v2_scan_sessions` (oturum+`ai_analysis`), `scan_artifacts` (ham çıktı), `scan_llm_logs` (admin-özel), `scan_memories` (dersler). Rapor sözleşmesi `build_autonomous_scan_results` → `{tool_name:data}`, **`results` anahtarı zorunlu**.

**Yeni prob sözleşmesi:** SAF çekirdek `pipeline/<x>_probe.py` (ağ/DB yok, izole test) → `_probe_<x>(self,session,engine,narrate)` → post-observe'a **best-effort try/except** ile bağla → `playbook.py` `if_relevant` gate (profil sinyali yoksa ÇALIŞMASIN) → env flag → `test_<x>.py` düz script.

**Kırılgan noktalar:** servis kapalı→dispatch sessiz `failed`→"boş tarama" (uyarı görünür yapar); LLM truncated JSON→kural-fallback (DeepSeek thinking KAPALI); WS "bağlanıyor" donması genelde `usePipelineStream` senkronu; otonom yalnız `v2_scan_sessions`'ta, `ai_analysis`'i EZME.

## 5. Komutlar
```
docker compose up -d                 # tüm stack (UI: localhost:5566)
docker compose logs -f orchestrator  # motor logları
cd frontend && pnpm dev              # frontend dev (pnpm, npm DEĞİL)
python3 orchestrator/pipeline/test_playbook.py   # test = düz script (pytest yok)
```
Tarama başlat: `curl -X POST http://localhost:5566/api/v2/scan -H 'Content-Type: application/json' -d '{"target":"example.com","profile":"autonomous","level":"standard"}'`
Env (`.env`): `AUTONOMOUS_MAX_STEPS/MAX_SECONDS/LLM_DISABLE/SCOPE/SEVERITY_FLOOR`; prob flag'leri (`WP_PROBE`, `IDOR_PROBE`, `COMBO_CHAINS`, `KEV_INTEL_ENABLED`, `TARGET_PROFILING`, ...) çoğu **varsayılan AÇIK** (getenv `"1"`/`"true"`).

## 6. Konvansiyonlar
- Yorumlar Türkçe, "neden"i açıklar. Log/değişken de Türkçe.
- **MongoClient süreç başına bir kez** (singleton `core/db.py`).
- Doktrin: LLM opsiyonel; hatası taramayı düşürmez → kural-fallback + operatöre bildir.
- Provider seçimi **DB(Settings) > .env**; anahtarlar .env'de. DeepSeek v4 (`deepseek-v4-flash/pro`), danışmada **thinking KAPALI**. `VALID_PROVIDERS=(ollama,deepseek,claude,gemini)`.
- Commit yalnız kullanıcı isteyince.

## 7. Ajan kuralları
- Komut çıktısını `| tail -40` / `sed -n 'A,Bp'` ile kırp.
- Dosyayı BÜTÜN okuma, satır aralığı oku — `scan_pipeline_v2.py` ~6500, `attack_graph.py` ~2760 satır.
- "Nerede kullanılıyor/tanımlı" sorusunu **grep**'le çöz, dosya okuyarak değil.
- Emin olmadığını yazma; doğrula.
