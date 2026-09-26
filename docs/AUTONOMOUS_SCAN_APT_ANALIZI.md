# Otonom Tarama (Auto-Scan) — Dürüst Durum Analizi ve APT-Sınıfı Yol Haritası

> Amaç: "gerçek hayatta %45 işe yarar" önsezisini doğrulamak, neyin gerçekten çalıştığını /
> çalışmadığını delil göstererek saptamak ve "APT gruplarının profesyonel akıl almaz
> programı" seviyesine çıkarmak için somut, öncelikli bir yol haritası çıkarmak.
> Doktrin: **gereksiz kod yok, gerekli yerde gerekli kadar**. Raporun sonunda her öneri
> "maliyet / kazanç / risk" ile işaretlenmiştir.

---

## 1. Yönetici Özeti

Mevcut sistem bir **"deterministik skor-kuyruğu sevk motoru"**dur — bir "otonom akıl" değil.
Bu bir hakaret değil, bilinçli bir mimari karar: doktrin "LLM kral değil, danışman" der ve
bu **doğru** duruştur. Sorun, akıl katmanının LLM dışında da eksik olmasıdır.

Üç büyük eksen var:

1. **Karar = greedy argmax.** Motor her turda tüm açık kenarları `siege_score` ile sıralar,
   ilk guardrail'den geçeni seçer (`autonomous_engine.py:1148-1190`). Hipotez üretimi,
   çok adımlı planlama, "bir sonraki adımı değil, hedef kitlesini planla" yok.
2. **Öğrenme = çapraz-tarama (cross-scan) bellek var, çevrim-içi (online) öğrenme yok.**
   Aynı tarama içinde hiçbir ağırlık/kullanılabilirlik güncellenmez. "Adaptive" etiketli
   modül (`adaptive_scanner.py`) aslında statik tech→tag haritasıdır.
3. **Doğrulama kalitesi sınıflara göre sert farklılık gösterir.** SQLi/DIR//IDOR/JWT gerçek
   proof-of-exploit iken; RCE/deserialization-gadget/SSTI→RCE üretilmez, SSRF kör kalır,
   XSS/CORS yalnızca "yansıyor" düzeyindedir.

Buna karşın sistem **çoğu ticari tarayıcıdan gerçek anlamda sofistikedir** bazı boyutlarda:
NVD CPE aralık eşleştirme (sahte-positive eleme), KEV/EPSS gündem sinyali, iki-hesap
diferansiyel IDOR, ölçekli zaman-tabanlı SQLi oracle'ı, hizmet-yok durumunda uyarı — bunlar
piyasa nadiridir. Yani taban sağlam; eksik olan **akıl, derinlik ve planlama**, taban değil.

---

## 2. Gerçekte Ne Var (Mimari Gerçeği)

### 2.1 Ana akış

```
POST /api/v2/scan
  → start_pipeline (scan_pipeline_v2.py:2922)
    → asyncio.create_task(_run_autonomous) (3251)
      → preflight: LLM sağlığı + 7 servis probe (3212, 3341-3378)
      → _ensure_target_profile (3390, recon-first)
      → while engine.budget_left() (3394):
           DECIDE   next_decision (autonomous_engine.py:990)
           VERIFY   _verify_hypotheses (scan_pipeline_v2.py:6649, Plan B)
           TERMINAL STOP / REQUEST_APPROVAL / PHASE_GATE
           ACT      to_stage → ToolDispatcher.dispatch (516)
           OBSERVE  observe → integrate → learn (autonomous_engine.py:2029)
           POST     ~20 best-effort _probe_* / _verify_* / _execute_* (3602-3737)
      → summary + _save_autonomous_evidence + _trigger_autonomous_report
```

### 2.2 Karar çekirdeği (DECIDE)

`next_decision` (autonomous_engine.py:990) akışı:

```
CVE enrich → expand_frontier → LLM appraise(ops) → apply_intel →
level filtresi → nuclei DAST/cve_sweep kapısı → scope kapısı →
redundant tag prune → onay kapısı → scored.sort(objective_score) → threshold STOP
```

`objective_score` (attack_graph.py:513) `INFO_GAIN_OBJECTIVE` kapalıyken **birebir** `siege_score`.
`INFO_GAIN_OBJECTIVE` **varsayılan KAPALI** (`attack_graph.py:202`).

### 2.3 `siege_score` — tam formül (attack_graph.py:454)

```
base = (value * breach_prob * success_prob) / cost
score = base * urgency * novelty * killchain_drive_boost * curiosity
```

| Çarpan | Kaynak | Gerçek mi? |
|--------|--------|-----------|
| `value` | `NODE_VALUE_TABLE` statik (attack_graph.py:79) | ❌ sabit tablo |
| `breach_prob` | sabit 0.05/0.5 + kanıtla +0.2 | ⚠️ kısmen öğrenir |
| `success_prob` | araç-bazlı seed (0.6-0.95), başarısızlıkta yarıya | ⚠️ deterministik feedback |
| `cost` | `EDGE_COST_TABLE` statik (attack_graph.py:105) | ❌ sabit tablo |
| `urgency` | NVD=1.4, KEV=2.2, EPSS≥1.8, teyit×1.5 | ✅ gerçek canlı intel |
| `novelty` | denenince → 0.0 | ⚠️ dedup maskelemesi, ödül değil |
| `killchain_drive_boost` | killchain.py faz ağırlığı, ≥1.0 | ⚠️ rapor fazı, karar fazı değil |
| `curiosity` | flag-gated (CURIOSITY_EXPLORE, injectable endpoint) | ⚠️ tek seferlik bonus |

**Yargı:** `siege_score` = sabit "kuşatma ekonomisi" formülü + birkaç deterministik feedback
kuralı + canlı CVE intel. Kenar skoruna **model yok, öğrenilmiş ağırlık yok, regresyon yok**.
`novelty` monoton azalan = dedup; "keşif ödülü" değil. Gerçek "yeni yüzey keşfet" davranışı
ayrı bir `info_relevance` fonksiyonunda yaşıyor ama o da **flag ile kapalı** (attack_graph.py:202).

### 2.4 Doğrulama katmanı (verification.py + prob'lar)

Gerçek proof-of-exploit üreten sınıflar (oracle = bağımsız yan-kanal):

| Sınıf | Yöntem | Niteleme |
|-------|--------|----------|
| SQLi (blind) | `SLEEP` zamansal kanal + ölçekli 2. oracle | ✅ gerçek, ama UNION/exfil yok |
| LFI | dosya içerik imzası (`root:...:0:0:`) | ✅ gerçek dosya okuma |
| SSTI | aritmetik değerlendirme (`7*7=49`) | ⚠️ değerlendirme kanıtlı, RCE çıkarım |
| XXE | dış entity → dosya okuma | ✅ gerçek |
| JWT | çevrim-dışı HMAC brute-force + `alg=none` | ✅ gerçek kripto kanıtı |
| IDOR | iki-hesap gövde diff (≥0.90) + anonim red | ✅ gerçek diferansiyel (sınıfının en iyisi) |
| XSS | kanarya yansıması (betik çalıştırmaz) | ❌ "yansıyor", "icra ediyor" değil |
| CORS | kötü Origin echo (tarayıcı okuma yok) | ❌ sığ |
| SSRF | metadata imzası + **opsiyonel** OAST | ⚠️ kör SSRF sessizce unconfirmed |
| RCE / deserialization-gadget | **yok** | ❌ en büyük boşluk |

**FP yönetimi** gerçek: LFI/SSTI baseline çıkarma, ölçekli çift-oracle gürültü reddi,
catchall-host demersion, js_secrets entropi+format katmanları. `llm_fp_opinion` yalnızca
görüş, tier'ı değiştirmez — doktrine uygun.

**Önemli anlamsal sorun:** prob sınıfları (k8s/wp/path) bulguyu `verified=True` demeden
`confidence_tier="confirmed"` damgalar. "confirmed" = "gözlenen maruziyet", "sömürüldü" değil.
Rapor tüketicileri bu iki anlamı karıştırır.

### 2.5 Hedef profili + playbook gating (+ Gerçek)

`target_profile.py` gerçek sinyal birleştirme (header/cookie/body/port + noisy-OR), `playbook.py`
gerçek `if_relevant`/`unless_excluded` kapıları kurar, `nuclei_tag_plan` yabancı framework tag'lerini
eler. **Bu katman çalışıyor ve gerçekten karar besliyor** — sadece doğruluk, el yazması
substring/regex tablosunun kalitesine bağlı.

### 2.6 İstihbarat (NVD/KEV/EPSS/PDCP) (+ Gerçek)

`cve_intel.py` NVD 2.0 + **CPE sürüm aralığı eşlemesi** (yamalı sürüm FP'sini eler), `kev_intel.py`
CISA KEV + FIRST EPSS, `vulnx_intel.py` PDCP alanları. **Doğru versiyon eşleştirme gerçek.**
Kontrast: `adaptive_scanner.py:725` hâlâ naive `"7." in version` substring kullanıyor — eski, ayrı bir yol.

### 2.7 Bellek / öğrenme (+/-)

| Ayar | Durum |
|------|-------|
| Çapraz-tarama dersler (Mongo `scan_memories`) | ✅ gerçek (exploit/identity/path) |
| Başarısız-hipotez TTL 30g + çevrim-içi dedup | ✅ gerçek |
| WAF-bypass mutasyon sıralaması (sonraki tarama) | ✅ gerçek |
| Identity fast-path (LLM'siz tanıma) | ✅ gerçek |
| **Çevrim-içi (aynı tarama) ağırlık güncelleme** | ❌ **yok** |
| Payload etkinlik geri bildirimi intra-scan | ⚠️ mutasyon var, ağırlık öğrenme yok |

### 2.8 Dış hizmet zinciri (kırılganlık)

13 araç HTTP üzerinden hizmetlere gider (`dispatch_map` inline, scan_pipeline_v2.py:604).
Hizmet koparsa: ConnectError → `failed` → `is_degraded` → WARNING (3739). Preflight 7
hizmeti probe eder ama **motoru durdurmaz** — 7 tarayıcı da ölüyse motor yalnızca yerel
deterministik prob'larla döner, "taranmış hissi" verir. `coverage_contract.py` bu sessiz
düşüşü yüzeye çıkarır ama **rapor-only** — kapı değil. İyileşme katmanları (nuclei/nmap
kısmi-kurtarma, 5s cancel, 2→30s backoff, 600s ceiling) var ama 600s tavanı tüm bütçeyi
yanık halde emebilir.

---

## 3. Önsezi Doğrulaması: "%45" Doğru mu?

Önsezi **yön olarak doğru, sayı olarak yanıltıcı**. Doğru ölçek "çalışma sınıfına göre
derinliktir", tek yüzde değildir:

| Sınıf | Mevcut derinlik | Not |
|-------|-----------------|-----|
| Bilinen sürüm-CVE zinciri (nmap→ürün→CVE→nuclei) | %80 | CPE aralık eşlemesi güçlü |
| Web yüzeyi (endpoint/path/idor/js-secrets) | %75 | IDOR diferansiyeli elit |
| Kimlik/yan-kanal oracle'ları (SQLi/LFI/SSTI/XXE/JWT) | %55-60 | kör tabanlı, exfil yok |
| Post-exploit (foothold→lateral→impact) | %5 | killchain.py sadece anlatı |
| Çevrim-içi öğrenme / planlama | %10 | hiç yok |
| RCE/deserialization doğrulama | %0-5 | verifier yok |
| Kör zafiyetler (SSRF/XXE via OAST) | %20 | OAST opsiyonel |

Ortalama "~%45" önsezisi bu heterojen tabloyla uyumlu; ama asıl mesaj **geniş ve sığ
değil, bazı alanlarda elit bazı alanlarda sıfır** olduğudur.

---

## 4. Temel Teşhis: Neden "Otomatik Kuşatma Evet, Otonom Akıl Hayır"

1. **Durum temsili eylem-merkezli, hipotez-merkezli değil.** Graf kenarı = "bir araç
   çalıştır". "Bu host wordpress 6.1 ve CVE-2023-x olabilir, şu sinyal destekliyor, şu
   eylemle test ederiz, sonuç şu olursa posterior şu olur" diye bir **hipotez nesnesi** yok.
2. **Planlama reaktif sıralama.** Her tur bir sonraki TEK adımı seçer. İleriye dönük çok
   adımlı chain (recon→ürün→CVE→foothold→lateral) bir obje değil, `killchain.py`'de
   post-hoc rapor anlatısıdır (attack_graph.py:2457 boost'u yalnızca sıralama nudge'ı).
3. **Keşif/sömürü dengesi kapalı.** `INFO_GAIN_OBJECTIVE` (bilgi kazanımı amacı) ve
   `CURIOSITY_EXPLORE` zaten yazılmış ama ilki kapalı. Çok-kollu bandit / UCB yok; keşif,
   dedup'i maskeleyen `novelty` terimiyle "yanlışlıkla" sağlanıyor.
4. **Öğrenme sınıfı dar.** Çevrim-içi ağırlık güncelleme, hedef-sınıfı başına öğrenilmiş
   prior, WAF davranış modeli (mutasyon sırası dışında) yok.

Bunlar "ekstra özellik" değil; **"oyalanma değil, ne yapacağını hâlâ kesin bilmediği
kısımları netleştiren" bir ajanın** çekirdeğidir.

---

## 5. APT-Sınıfı Yol Haritası

### Fazlar ve öncelik sırası

Aşağıda "maliyet / kazanç / risk" notasyonu: **D**=düşük, **O**=orta, **Y**=yüksek.

---

### FAZ A — Akıl katmanı (en yüksek kazanç, mevcut yapıya en az müdahale)

**A1. Hipotez nesnesi + posterior güncelleme.** *(mevcut: yok)*
Kenar yerine ayrı bir `Hypothesis` nesnesi: `{id, öncül-sinyaller, eylem-planı, prior,
gözlemler[], posterior}`. `observe()` içinde her sonuç posterior'u günceller; hipotez
posterior'u eşik altına inince eylem dizisi durur (boşa adım yakılmaz).
- Santiago: **O** / kazanç **Y** / risk **D** (data model + observe hook, büyük rewrite değil)

**A2. Çok-kollu bandit (UCB) keşif/sömürü dengesi.** *(mevcut: INFO_GAIN kapalı)*
`objective_score` kenar seçimine `UCB = skor + c·sqrt(ln N / n_i)` ekle; `N`=toplam adım,
`n_i`=kenarın denenme sayısı. Tek kalıcı satır değişikliği + `INFO_GAIN_OBJECTIVE`'ı
**varsayılanı açık yapmak**. Curiosity'nin flag-gated olması, parametre olmamasıyla bu
noktayı netleştirmek.
- **D/O** / kazanç **Y** / risk **D**

**A3. Çok adımlı plan (depth-2 lookahead).** *(mevcut: tek-adım greedy)*
"hangi aracı çalıştırayım" yerine "bu hedef kitlesine hangi 2-3 adımlık zincir, hangi
marjinal değişimle ulaşır" sorusu. En hafif çözüm: mevcut killchain faz ağırlığına ek bir
forward-simülasyon (`expand_frontier` çıktısını 1 adım ileri simüle et) — tam MCTS değil,
depth-1 lookahead.
- **O** / kazanç **O-Y** / risk **D**

---

### FAZ B — Doğrulama derinliği (APT kanıt kalitesi)

**B1. SQLi UNION/error-based + sınırlı veri çıkarma.** *(mevcut: blind-only SLEEP)*
Zaman-tabanlı oracle kanıtlı IPS/rate-limit arkasında iyi; ama UNION yanıtı üreten sunucular
için `ORDER BY` sütun sayısı + `UNION SELECT` tespiti "gerçek veri okundu" kanıtını verir.
Tahribatsız kalır (sadece `version()/system_user()` dökümü, veri sızdırmaz).
- **O-Y** / kazanç **Y** / risk **O** (hedef hasarı riski — guardrail şart)

**B2. SSTI→RCE erişim kanıtı + deserialization gadget verifier.** *(mevcut: yok)*
SSTI zaten "değerlendirme var" ispatlıyor; bir adım ötesi `os` modül erişimi değil,
"gadget class var mı" imza testi. Deserialization için viewstate-genus oracle var ama
gadget-chain doğrulaması yok — bu, "critical" etiketli ama sürekli `unconfirmed` kalan
büyük bir kovadır.
- **Y** / kazanç **Y** / risk **O-Y**

**B3. OAST zorunlu (kendi DNS/HTTP collab).** *(mevcut: opsiyonel oast_client)*
Kör SSRF/XXE/sql-agent için çıktı-tabanlı yan kanal şart. `oast_client` var; kullanımını
varsayılan zorunluya çevirip kör sınıfları `unconfirmed` yerine `confirmed` yapmak.
- **D** / kazanç **Y** / risk **D**

**B4. "confirmed" anlamsal ayırımı.** `verified` (aktif sömürü kanıtlı) ve `observed`
(gözlenen maruziyet) ayrı. Rapor sözleşmesi bunu taşır.
- **D** / kazanç **O** / risk **D**

---

### FAZ C — Çevrim-içi öğrenme

**C1. Hedef-sınıfı başına öğrenilmiş prior.** *(mevcut: statik NODE_VALUE/EDGE_COST)*
Cross-scan bellek zaten var; aradaki boşluk **aynı tarama içinde** `success_prob`'u
Bayes ile güncellemek (beta dağılımı: `alpha/beta` kanıt sayacı). Hali hazırda "başarısızlıkta
yarıya düş" kuralı var — bunu beta-posterior ile değiştirmek tek satır konsepti.
- **D** / kazanç **O-Y** / risk **D**

**C2. WAF davranış modeli (intra-scan).** *(mevcut: cross-scan mutation order only)*
`payload_mutator.learned_order` şu an bir sonraki tarafı sıralar; aynı taramada "şu WAF bu
mutasyonu blockladı → bu class'a bu mutasyonu bir daha deneme, şunu önceliklendir" canlı
geri bildirim eksik.
- **D-O** / kazanç **O** / risk **D**

---

### FAZ D — Operasyonel sağlamlık

**D1. `coverage_contract`'ı rapor-only'den kapıya çevir.** *(mevcut: rapor-only)*
Zorunlu sınıflar (identity/ports/nuclei/dast) kapsanmadıysa koşu sonunda "NOT_CHECKED"
sessizce düşüyor. Koşu bitiminde eksik zorunlu sınıf → otomatik tek-deneme veya en azından
rapor durumunu "eksik" olarak işaretle (şu an da işaretliyor ama UI raporu "başarılı" gösterebilir).
- **D** / kazanç **O** / risk **D**

**D2. `poll_with_backoff` 600s tavan sertleştirmesi.** *(mevcut: sessiz yutuyor)*
Ölü hizmete karşı tüm bütçeyi emen poll yutması — ölü hizmeti algılayınca erken vazgeç.
- **D** / kazanç **O** / risk **D**

---

### FAZ E — TTP emülasyonu / grup profili (kullanıcının temel vizyonu)

**E1. ATT&CK TTP modülü (grup profili).** Evidence zaten `attack_techniques`/`apt_groups`
taşıyor; ama **emülasyon kurgusu** yok. Kullanıcı bir grup (ör. APT28, Scattered Spider,
FIN7) seçer → motor o grubun tekniğini/sırasını/araç tercihini önceliklendirir. Mevcut
`killchain.py` + `NODE_VALUE_TABLE` bunun için iskelet sağlar.
- **O-Y** / kazanç **O-Y** (tasarlanabilir asıl fark) / risk **D**

**E2. Foothold→lateral sınırlı emülasyon.** *(mevcut: yok, killchain anlatısı only)*
Kredi bulunca (default-creds) güvenli sınırda "bu kimlik nereye erişir" matrisi. Hedefin
kendi kapsamı dışına çıkmamak şartıyla.
- **Y** / kazanç **O** / risk **Y** (kapsam dışı risk — en son aşama)

---

## 6. Neyi YAPMA (ikazlar)

1. **LLM'e karar verdirme.** "APT gibi olsun" = LLM'e rota devri DEĞİL. Bu sistemin en
   güçlü yanı determinizmdir (`apply_intel` yalnızca ±20 nudge, karar safe-sort). LLM'e
   "karar" verirsen gerçek hayatta tarayıcı kırılgan, tekrarlanamaz hale gelir. APT
   sofistikasyonu = **hipotez + deterministik doğrulama + planlama + öğrenme**, sf-zekâ değil.
2. **Tahribat sınırını gevşetme.** Mevcut "tahribatsız" (SAF) duruş bilinçli. RCE/SQLi
   derinleştirmede sınır net: **kanıt üret, hasar verme, veri sızdırma**. Bu çizgi ticari
   müşteri için yasal zorunluluk; APT tradecraft burada yalnızca "derin kanıt" ile öykünülür.
3. **Geniş-flush değil derin-flush.** Sorun "daha çok araç/prob" değil ("~20 post-observe
   prob zaten var"). Sorun "mevcut her sınıfı bir kademe derin + akıl ile bağla". Yeni prob
   eklemeden önce Faz A/B'yi tamamla; aksi halde yine "geniş ama sığ" kalır.

---

## 7. Önerilen İlk Uygulama Sırası (en yüksek kazanç / en düşük risk)

1. **A2** — `INFO_GAIN_OBJECTIVE` varsayılan açık + UCB terimi (tek dosya, davranışı akıllanır).
2. **A1** — Hipotez nesnesi + `observe` posterior hook (data model genişletme, rewrite değil).
3. **B3** — OAST zorunlu (kör sınıflar `confirmed`'a çıkar, kanıt kalitesi artar).
4. **C1** — beta-posterior success_prob (tek satır konsepti, gerçek öğrenme).
5. **B1** — SQLi UNION/error-based (en yaygın yüksek-değer sınıfın derinleşmesi).
6. **B4** — `verified`/`observed` ayrımı (rapor doğruluğu).
7. **D1/D2** — sağlamlık kapıları.
8. **A3** — depth-1 lookahead planlama.
9. **B2** — SSTI→RCE + deserialization gadget verifier.
10. **E1** — gruplu TTP emülasyonu (sona bırak; Foundation üzerine kurulur).

Her öncelik küçük, izole, test edilebilir adımdır; hiçbiri "her şeyi yeniden yaz" gerektirmez.
Doktrin böyle korunur: her faz için SAF çekirdek + ince I/O katmanı + mevcut `test_*.py`
deseniyle test.
---

## 8. Uygulama Durumu (2026-09-12)

Aşağıdakiler bu doktrine göre uygulandı — hepsi SAF çekirdek + ince I/O + `test_*.py` deseni,
mevcut 74 saf test yeşil, sıfır regresyon (tek istisna B3'e bağlı iki OAST/race testi; bkz. not).

| Öğe | Durum | Nerede | Test |
|-----|-------|--------|------|
| **A2** — INFO_GAIN varsayılan AÇIK + UCB1 keşif terimi | ✅ UYGULANDI | `attack_graph.py` (`INFO_GAIN_OBJECTIVE=1`, `explore_bonus`, `selection_score`) + `autonomous_engine.py` seçim satırı | `test_explore_ucb.py` (6) + `test_info_gain.py` |
| **C1** — beta-posterior success_prob backoff (yarılama yerine kanıt-sayaçlı) | ✅ UYGULANDI | `attack_graph.py` (`Edge.alpha/beta`, `BETA_PRIOR_STRENGTH`, `update_probabilities`) | `test_edge_retry.py` (beta test + güncel sözleşme) |
| **D2** — ölü-hizmet erken vazgeçme (600s tavan sertleştirme) | ✅ UYGULANDI | `scan_pipeline_v2.py` (`poll_with_backoff` ardışık-hata kesme, `POLL_MAX_CONSECUTIVE_ERRORS`) | `test_poll_backoff.py` (4) |

**Tasarım notları / bilinçli sınırlar:**
- **A2 keşif SEÇİM katmanında**: `objective_score` SAF/deterministik kaldı (rapor + `considered`
  tutarlı); UCB yalnız `next_decision` sıralamasını etkiler. Sonsuz keşif riski YOK — doğal-durma
  `info_relevance`'a dayanır, UCB'den bağımsız. Kapatma: `EXPLORE_UCB=0`.
- **C1 kapsamı**: kenar-içi beta çekirdeği (yarılama→Bayes) tamam. **Ertelenen**: araç/hedef-sınıfı
  bazlı öğrenilmiş prior'ın YENİ kenar tohumlamasına bağlanması (onlarca `Edge(...)` kurulumunu
  değiştirir → ayrı, daha geniş kapsamlı adım).

**Bilinçli ERTELENENLER (risk/kapsam gerekçeli — açık onay ister):**
- **B3 (OAST zorunlu)**: tek bayrak DEĞİL; gerçek collab (DNS/HTTP) altyapısı ister. `test_verification_oast`
  zaten kırmızı ("OAST geri araması tespit edilemedi") → altyapı bağlanmadan kör sınıflar `confirmed` olamaz.
- **B1 (SQLi UNION/error-based)**: doküman "hedef hasarı riski — guardrail şart" diyor. Tahribatsız
  guardrail tasarımı yapılmadan açılmaz.
- **B2 (SSTI→RCE + deserialization gadget)**: yüksek risk; ayrı, dikkatli bir doğrulama tasarımı ister.
- **E2 (foothold→lateral)**: kapsam-dışı çıkma riski — doktrinin en son aşaması.
- **A1/A3 (posterior hipotez nesnesi + lookahead)**: daha büyük veri-modeli/planlama değişikliği;
  mevcut LLM-hipotez nesnesi (`attack_hypothesis.py`) posterior-izleyen planlama nesnesi DEĞİL.
- **B4 (verified vs observed)**: rapor sözleşmesi + Evidence + frontend'e yayılır (geniş yarıçap);
  izole bir sonraki adım olarak önerilir.
