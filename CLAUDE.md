# Kadim Güvenlik — Claude Kılavuzu

Otonom / yarı-otonom güvenlik tarama platformu. Dağıtık mikroservis mimarisi:
her tarama aracı (nmap, nuclei, subfinder, recon, osint, hash, fuzz, stress) ayrı bir
FastAPI servisi; orchestrator hepsini bir pipeline'da birleştirir; frontend (React Router 7)
canlı olayları WebSocket üzerinden izler. LLM katmanı taramaları analiz eder ve otonom
motora "istihbarat subayı" olarak danışmanlık yapar.

Not/yorum dili **Türkçe**. Kod, değişken ve log mesajları da çoğunlukla Türkçe — bu
konvansiyonu koru.

## Çalıştırma

Her şey Docker Compose ile ayağa kalkar:

```bash
docker compose up -d          # tüm stack
docker compose logs -f orchestrator   # motor loglarını izle
docker compose restart ai-service     # tek servis yeniden başlat
```

- **Frontend dev** (container dışında): `cd frontend && pnpm dev` (React Router 7 + Vite).
  Build: `pnpm build`. Paket yöneticisi **pnpm** (npm değil).
- Konteynerler `kadim-net` ağında; servisler birbirine servis adıyla erişir
  (`http://orchestrator:8000`, `http://ai-service:...`, `http://mongodb:27017`).

## Mimari

- **gateway** (nginx, [nginx/](nginx/)): tek giriş. `/` → frontend, `/api/` → orchestrator
  (WebSocket dahil), `/api/recon/`, `/api/cf-analyzer/` gibi bazı yollar doğrudan servislere.
  Frontend'den backend'e her istek gateway üzerinden geçer.
- **orchestrator** ([orchestrator/main.py](orchestrator/main.py)): FastAPI, port 8000.
  Router'ları `include_router` ile bağlar (`recon_router`, `ai_router`, `settings_router`,
  `hash_cracker_router`, `fuzz_router`, ...). Tarama pipeline'ının beyni.
- **ai-service** ([services/ai-service/main.py](services/ai-service/main.py)): LLM analiz +
  chat servisi. Provider routing burada (`ollama` / `deepseek` / `claude` / `gemini`).
- **Tarama servisleri**: nmap, rustscan, nuclei, subfinder, recon, osint, hash-cracker,
  fuzz, stress, researcher — her biri kendi FastAPI'si; orchestrator HTTP ile tetikler,
  sonuçları poll eder.
- **mongodb**: kalıcı depo (kimlik `MONGO_USER`/`MONGO_PASS` `.env`'den — varsayılan parola YOK;
  port yalnız `127.0.0.1:27018`; DB: `kadim_security`).

## Pipeline (kritik dosyalar)

- [orchestrator/pipeline/scan_pipeline_v2.py](orchestrator/pipeline/scan_pipeline_v2.py) —
  aşama zinciri (`StageDefinition` → `_dispatch_*` → `StageResult`). Stage hatası/timeout'unda
  `_maybe_recon_fallback` devreye girer; hard-fail yerine kısmi sonuç kurtarmaya çalışır.
  Koleksiyonlar: `v2_scan_sessions` (oturum durumu), `scan_llm_logs`, `scan_artifacts`,
  `scan_memories`.
- [orchestrator/pipeline/path_probe.py](orchestrator/pipeline/path_probe.py) — **`pathprobe`**
  aracı: hassas yol/ifşa probu (`.env`, `.git/HEAD`, yedek, config — 64 küratörlü yol).
  Nuclei template'inden bağımsız deterministik GET + içerik validator'ları (soft-404 baseline
  elemesi); bulgu snippet'lerinde sırlar maskelenir. Attack graph her web hostuna + her
  co-hosted domain'e otomatik kenar seed eder; skorlama RECON_TOOLS keşif-potansiyeliyle
  (yoksa düşük-değerli host'larda eşik altında kalıp hiç seçilmez). UI tarafında aynı prober
  `POST /api/redteam/path-probe` ile canlı çalışır (integrations/redteam_proxy.py — ayrıca
  `POST /api/redteam/analyze` yüzey snapshot'ı + ai-service `analysis_type="redteam"` analizi).
- [orchestrator/pipeline/k8s_probe.py](orchestrator/pipeline/k8s_probe.py) — K8s/RKE2/Rancher
  farkında tahribatsız prob (yalnız GET). `KUBE_PORTS` tek doğruluk kaynağı: `_infra_port_sweep`
  (target_profile'a port sinyali), `_probe_kubernetes` port filtresi ve derin prob aynı tabloyu
  okur (apiserver 6443/8443/8080, RKE2-Rancher supervisor 9345, kubelet 10250/10255, etcd
  2379/2380, kube-proxy 10256, controller/scheduler 10257/10259, cAdvisor 4194). `classify_distro`
  gitVersion suffix'inden dağıtım damgalar (rke2/k3s/gke/eks/aks); `classify_rancher` Norman-API
  (`baseType`) + UI title imzasıyla Rancher'ı tanır. Grafa giriş: `attack_graph.py`
  `k8s-control-plane` kategorisi (değer 95) + `adaptive_scanner.py` kubernetes/kubelet/etcd/
  rancher/rke2/k3s girdileri (nuclei `kubernetes`/`rancher` tag'leri). Playbook `k8s_probe`
  if_relevant gate'li — profil `infra=kubernetes` demeden portlar yoklanmaz.
- [orchestrator/pipeline/kev_intel.py](orchestrator/pipeline/kev_intel.py) — **aktif-sömürü
  istihbaratı**: CISA KEV feed'i (24s önbellek, stale-while-error) + FIRST EPSS olasılık
  skorları. `attack_graph.enrich_cve_intelligence` içinde iki yönden çalışır: (1) NVD
  bulgusu KEV üyesiyse düğüm/kenar yükseltilir (`KEV_URGENCY=2.2`, fidye=2.4), (2) sürümü
  BİLİNMEYEN servisler için ürün-adı bazlı `_kev_product_sweep` hedefli nuclei kenarı seed
  eder (AI/agentic yığın sürüm ifşa etmediğinde huniyi kurtarır). EPSS ≥0.5 "sıcak" CVE'yi
  KEV'de olmasa bile yükseltir. Bayraklar: `KEV_INTEL_ENABLED`, `EPSS_INTEL_ENABLED`.
- [orchestrator/pipeline/deserialization_probe.py](orchestrator/pipeline/deserialization_probe.py) —
  **deserialization kabul-imza probu**: SharePoint ToolShell yol-imzası, ASP.NET
  `__VIEWSTATE` MAC-kabul testi (rastgele/bozuk ViewState ile sunucunun MAC doğrulamasını
  AÇIK/KAPALI işlediğini gözlemler — gerçek gadget-chain/RCE ÇALIŞTIRILMAZ), TeamCity sürüm
  ifşası. Playbook `deserialization_probe` if_relevant gate'li — profil
  `framework=sharepoint|teamcity` ya da `language=dotnet` demeden hiç çalışmaz. Bayraklar:
  `DESERIALIZATION_PROBE`, `DESERIALIZATION_PROBE_MAX_HOSTS`.
- [orchestrator/pipeline/verification.py](orchestrator/pipeline/verification.py) — deterministik
  doğrulayıcılar (PoC teyidi). T4-A: payload listeleri (SQLi/LFI/SSTI) inline çekirdeğin
  üstüne **offline süzülmüş PATT corpus'u** ile merge edilir
  ([payload_corpus.py](orchestrator/pipeline/payload_corpus.py) + `data/payloads/*.json`,
  üretim `scripts/extract_patt_corpus.py` — runtime'da değil). Bayrak `PAYLOAD_CORPUS`
  (kapalıysa birebir inline); her girdi runtime'da `adaptive_payloads._payload_ok` kapısından
  tekrar geçer. XSS corpus'u ana hot-path'i şişirmez — yalnız `_adaptive_reverify` corpus
   fallback'i + LLM few-shot (`build_probe_context.corpus_examples`).
- [orchestrator/pipeline/autonomous_engine.py](orchestrator/pipeline/autonomous_engine.py) —
  **"Kuşatma Doktrini"** otonom saldırı simülasyonu. Her turda hedefi analiz eder, LLM'e
  ("istihbarat subayı") danışır, ama **nihai karar deterministik kural+graf skorundadır** —
  LLM erişilemezse motor kural-fallback ile bozulmadan çalışır. `_preflight_*` (ollama/deepseek/
  cloud) taramadan önce sağlayıcı sağlığını yoklar.
- [orchestrator/pipeline/behavior_monitor.py](orchestrator/pipeline/behavior_monitor.py) —
  **davranış denetimi (loop-guard)**: PentAGI execution-monitor'ün SAF kural karşılığı.
  Aynı araç `LOOP_GUARD_SAME_LIMIT` (vars. 5) kez koşulunca `next_decision` skorlamasında
  deterministik ceza çarpanı (`LOOP_GUARD_PENALTY`, vars. 0.55) + AGENT_THINKING uyarısı.
  LLM-token maliyeti sıfır; `LOOP_GUARD_ENABLED=0` → davranış birebir. Sayaç `observe()`da
  işlenir (başarısız koşular da sayılır — takıntı genelde boş-tekrar olarak görünür).
- [orchestrator/pipeline/memory_store.py](orchestrator/pipeline/memory_store.py) —
  **vektör hafıza (Qdrant)**: `scan_memories`/Evidence semantik karşılığı. Tarama başında
  `gecmis_dersleri_hatirla()` benzer geçmiş bulguları `engine.memory_lessons`'a ekler
  (LLM prompt "GEÇMİŞ DERSLER" + saha bağlamı); tarama sonunda `bulgulari_hafizaya_yaz()`
  kanıtları embedding'ler. Field-journal'ı TAMAMLAR (düz-metin eşleşmenin bulamadığı
  farklı-hedef/benzer-teknoloji dersleri). Varsayılan KAPALI: `VECTOR_MEMORY_ENABLED=1`
  + `VECTOR_EMBED_MODEL` gerekir (embedding dış API maliyeti üretir). Qdrant/embedding
  düşerse sessiz no-op — motor hafızasız eksiksiz çalışır. Karar HEP graf+kuralda;
  vektör yalnız bağlam/sinyal. Test: `test_memory_store.py` (canlı kol `VECTOR_LIVE=1`).
- `ScanEventBus` / [scan_events.py](orchestrator/pipeline/scan_events.py) — olaylar
  WebSocket'e buradan yayılır.

## Frontend

- **React Router 7** (framework mode), TypeScript, Tailwind. Rotalar
  [frontend/app/routes/](frontend/app/routes/): `auto-scan` (Kuşatma Doktrini), `scan`,
  `nmap-advanced`, `recon-intelligence`, `hash-cracker`, `vulnerabilities`, `osint/`, `admin/`.
- **Canlı tarama akışı**: [frontend/app/hooks/usePipelineStream.ts](frontend/app/hooks/usePipelineStream.ts)
  — `/api/scan/events/{scanId}` WebSocket'ine bağlanır, kopunca 3sn'de reconnect + `event_history`
  replay ile idempotent besleme. Ekran "bağlanıyor"da donuyorsa şüpheli ilk yer burasıdır
  (bu, backend tarama tamamlansa bile olabilir — WS senkron sorunu).
- Ortak bileşenler [frontend/app/components/](frontend/app/components/): `AIAnalysisPanel`,
  `AIModelSelector`, `LlmLogsModal`, `AutonomousTimeline`, `AutonomousLlmStatus`.
- Kimlik `AuthContext`; admin-only özellikler `isAdmin` ile korunur.

## LLM Sağlayıcı Katmanı

- Ortak config: `llm_env_config.py` **iki yerde** kopyalanmış —
  [orchestrator/integrations/llm_env_config.py](orchestrator/integrations/llm_env_config.py)
  ve [services/ai-service/llm_env_config.py](services/ai-service/llm_env_config.py). Birini
  değiştirirken diğerini de senkron tut. `VALID_PROVIDERS = ("ollama","deepseek","claude","gemini")`.
- **Varsayılan sağlayıcı seçimi DB > .env**: aktif provider/model MongoDB Settings'ten gelir
  (`resolve_ai_service_default`); API **anahtarları** `.env`'dedir. `.env`'de
  `AUTONOMOUS_LLM_PROVIDER=ollama` yazsa bile DB'de deepseek seçiliyse motor deepseek kullanır.
- **DeepSeek** (2026): OpenAI-uyumlu (`{BASE_URL}/chat/completions`). Modeller
  `deepseek-v4-flash` (varsayılan/ekonomik), `deepseek-v4-pro`. Eski `deepseek-chat` /
  `deepseek-reasoner` **2026-07-24'te deprecate** — v4 isimlerini kullan. Thinking modu
  request parametresiyle kontrol edilir: `"thinking": {"type": "disabled"}`. Danışma/analiz
  çağrılarında **thinking KAPALI** tutulur — açık kalırsa CoT `reasoning_content`'e akıp
  `max_tokens`'ı yer ve `content` boş/truncated döner (taramadan taramaya tutarsız sonuç).
  Content boşsa `reasoning_content`'e fallback yapılır.
- Provider routing: [services/ai-service/main.py](services/ai-service/main.py) içinde
  `if provider == "..."` dalları (`analyze_with_deepseek`, `process_chat_deepseek`, ollama/
  claude/gemini karşılıkları). Yeni sağlayıcı eklerken: config + routing + `get_ai_models`
  listesi + frontend `AIProvider` tipi + `AIModelSelector` `providerInfo`'yu birlikte güncelle.

## Konvansiyonlar

- Yorumlar Türkçe ve "neden"i açıklar (mekanik "ne yaptığını" değil). Bu tonu koru.
- MongoClient'ı süreç başına **bir kez** oluştur (singleton) — her çağrıda yeni client
  bağlantı havuzu + monitör thread sızdırır.
- Motor felsefesi: **LLM opsiyonel bir sezgi katmanı, kritik yol değil.** Sağlayıcı hatası
  taramayı düşürmez; kural-fallback'e geçilir ve durum operatöre bildirilir.
- Commit'i yalnızca kullanıcı isteyince yap.
