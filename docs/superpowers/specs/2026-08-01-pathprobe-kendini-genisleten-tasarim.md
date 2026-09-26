# PathProbe — Kendini-Genişleten, Kanıt-Güdümlü Hassas Yol Prober'ı

**Tarih:** 2026-08-01
**Durum:** Tasarım onaylandı — implementasyon planı bekliyor
**İlgili dosyalar:** [orchestrator/pipeline/path_probe.py](../../../orchestrator/pipeline/path_probe.py),
[scan_pipeline_v2.py](../../../orchestrator/pipeline/scan_pipeline_v2.py),
[attack_graph.py](../../../orchestrator/pipeline/attack_graph.py),
[integrations/redteam_proxy.py](../../../orchestrator/integrations/redteam_proxy.py)
**İlgili yol haritası:** [docs/fatih-doktrini-derin-analiz-ve-tespit-yol-haritasi.md](../../fatih-doktrini-derin-analiz-ve-tespit-yol-haritasi.md) (§3.1, §3.5, §3.7)

---

## 1. Motivasyon

Farklı bir ekip `https://portal.arneca.com/symfony/config/databases.yml` yolunda düz-metin DB
kimlik bilgisi (Symfony 1.x `databases.yml`) buldu. Bizim sistem aynı hedefi tarayınca **bulamadı**.

Bu, tekil bir yol eksikliği değil, **yapısal bir tavanın** belirtisi: PathProbe yalnız insanın elle
eklediği küratörlü statik yolları arıyor; hedefe göre genişlemiyor ve geçmişten öğrenmiyor. Bir
sonraki alışılmadık yol (`sites/default/settings.php`, `WEB-INF/web.xml`, `apps/api/config/databases.yml`…)
yine kaçırılacak — biri elle eklemedikçe.

## 2. Teşhis (kök nedenler)

Databases.yml kaçırılmasının tek bir nedeni yok; zincirin farklı halkalarında birikti:

1. **Yol katalogda yoktu.** k3 düzeltmesinden önce `/symfony/config/databases.yml` ne statik
   katalogda ne de `symfony` tech-setinde vardı. Prober var olmayan yolu sormaz.
2. **Düzeltme deploy edilmemiş.** k3'ün eklemeleri commit'siz; orchestrator konteyneri yeniden
   derlenmedikçe çalışan sistem eski kataloğu kullanır.
3. **Tech-path recon'a bağımlı.** `symfony` özel yolları yalnız recon "Symfony" etiketi üretirse
   tetikleniyor ([attack_graph.py:485](../../../orchestrator/pipeline/attack_graph.py#L485)).
   Symfony 1.x eski kurulumda parmak izi zayıftır → recon kaçırır → tech-set açılmaz.
4. **Büyüyen katalogda sessiz iptal.** `PATHPROBE_OVERALL_TIMEOUT=40s`, eşzamanlılık 6. Katalog
   büyüdükçe bütçe dolunca kalan yollar iptal ediliyor (`partial=True`); yol katalogun ortasındaysa
   hiç sıra gelmeden kesilebilir. "Daha çok yol ekle"nin sessiz tavanı budur.

## 3. Kararlar

- **Kapsam:** K1 + K2 + K3 (tam paket) — kanıt-güdümlü şablonlar + LLM istihbarat subayı + öğrenme
  döngüsü.
- **k3'ün commit'siz işi:** olduğu gibi kalır, üstüne eklenir. k3'ün validator/maskeleme/pivot işi
  kaliteli ve tutulur; elle yazılmış Symfony kombinasyon satırları, K1 şablon üretiminin dedup'lı
  alt kümesi olarak zararsız kalır (mükerrer ama sorun değil).
- **Felsefe (değişmez kısıt):** LLM opsiyonel sezgi katmanı, kritik yol değil. Zekâ dışarıda üretilir,
  **yargı içeride ve deterministik** kalır. Sağlayıcı/DB erişilemezse prober bozulmadan çalışır.

## 4. Neden "statik → LLM" değil de hibrit?

Sektör lideri araçlar (Nuclei, Burp, ffuf) küratörlü listelerle çalışır — küratörlü liste kusur değil,
temeldir: hızlı, deterministik, maskelenebilir, MITRE etiketlenebilir. Sorun statik olması değil,
**hedefe-kör ve öğrenmiyor** olması.

| Yaklaşım | Güç | Zayıflık | Rol |
|---|---|---|---|
| Statik katalog | Yüksek isabet, deterministik, gürültüsüz | Kapsam insanın hatırladığıyla sınırlı | **Temel — atılmaz** |
| Fuzz (feroxbuster, mevcut) | Geniş kapsam | İçerik doğrulaması yok → soft-404 gürültü, iz; wordlist de elle küratörlü | Tamamlayıcı |
| LLM | Hedefe göre yaratıcı genişleme | Yavaş, non-deterministik, tek başına isabeti düşürür | **Genişletici, yargıç değil** |

Doğru hamle "PathProbe'u LLM'e devret" değil; **hibrit**: LLM/kanıt aday yolu ÖNERİR, deterministik
validator ONAYLAR.

## 5. Mimari — modül sınırları

`path_probe.py` **saf** kalır (Mongo yok, LLM istemcisi yok): test edilebilirlik, motor felsefesi ve
`redteam_proxy` canlı modunun (servissiz/DB'siz) aynı fonksiyonu çağırması için.

| Katman | Nerede yaşar | Neden |
|---|---|---|
| **K0** küratörlü çekirdek | `path_probe.py` (mevcut) | Değişmez |
| **K1** şablon + kanıt-türetme | `path_probe.py` içi (saf HTTP+parse) | Dış bağımlılık yok → canlı redteam de kazanır |
| **K2** LLM istihbarat subayı | Dispatcher sınırı (`scan_pipeline_v2`/`redteam_proxy`) | LLM erişimi orada; öneri `paths=` ile enjekte |
| **K3** öğrenme döngüsü | Dispatcher sınırı (Mongo orada) | Öğrenilen yollar `paths=` ile enjekte; bulgular yazılır |

**Anahtar mekanizma:** `probe_sensitive_paths` zaten `paths` argümanı + dinamik `catalog` birleştirme
mantığına sahip. K2 ve K3 hesapladıkları ek yolları bu argümandan **içeri verir**; prober onları normal
katalogmuş gibi (aynı validator + soft-404 + maskeleme + pivot altyapısıyla) işler. Prober'ın içi hiç
LLM/DB bilmeden akıllanır.

```
                    ┌─ K0 küratörlü çekirdek (her zaman) ────────┐
_fingerprint_tech ──┤─ K1 aile şablonu + kanıt türetme (saf) ────┤
   (dispatcher)     │─ K2 LLM öneri → sanitize/clamp ────────────┼─→ paths= ─→ probe (SAF, det. yargı)
                    └─ K3 hafıza oku (Mongo) ───────────────────┘                     │
                                                          onaylanan bulgu → K3 yaz + manuel /learn-path
```

## 6. K0 — Küratörlü çekirdek (mevcut, değişmez)

Bugünkü `SENSITIVE_PATHS` + `TECH_SPECIFIC_PATHS` + validator + soft-404 baseline + maskeleme + pivot.
Her hedefte çalışan hızlı güvenlik ağı. k3'ün Symfony validator/maskeleme/pivot eklemeleri bu katmanın
parçası olarak kalır.

## 7. K1 — Yol-ailesi şablonları + kanıt-güdümlü türetme (deterministik)

### 7a. Yol-ailesi şablonları

Kombinasyonu elle yazmak yerine `{taban} × {app} × {dosya}` çarpımını runtime üret:

```python
PATH_FAMILIES = {
  "symfony": {
    "bases":     ["", "/symfony", "/app", "/config", "/current", "/apps/{app}"],
    "app_names": ["frontend", "backend", "api", "admin", "web", "mobile"],  # + kanıttan gelenler
    "files": [
      ("config/databases.yml",      "credential_exposure", "critical", "symfony_databases"),
      ("config/databases.yml.dist", "credential_exposure", "high",     "symfony_databases"),
      ("config/parameters.yml",     "credential_exposure", "high",     "symfony_parameters"),
      ("config/parameters.ini",     "credential_exposure", "high",     "ini_config"),
      ("config/security.yml",       "config_exposure",     "medium",   "yaml_config"),
    ],
  },
  # laravel / wordpress / spring / node / django ... aynı desen
}
```

- **Tetikleyici:** `_fingerprint_tech` (mevcut, ana sayfadan tech tespiti) Symfony bulursa aile runtime
  genişler — recon Symfony'yi kaçırsa bile. Bu, teşhis #3'ü kapatır.
- Üretim kataloğa **dedup** ile eklenir; k3'ün elle satırları zararsız alt küme olur.
- Kombinasyon patlamasına karşı **aile başına üst sınır ≤40**.
- `{app}` yer tutucusu `app_names` + kanıttan keşfedilen app adlarıyla genişler.

### 7b. Kanıt-güdümlü türetme (ikinci dalga)

İlk dalga çalışırken kanıt topla, sonra sınırlı ikinci dalga üret:

| Kanıt | Türetilen yol |
|---|---|
| `robots.txt` Disallow | Her gizli dizin doğrudan problanır (altın sinyal) |
| Bulunan `.git/config` remote URL | Repo adı → `/{repo}.zip`, `.tar.gz`, `{repo}-backup.zip` |
| Dizin listelemesi (`Index of /`) | `<a href>` girdileri özyinelenir (derinlik ≤2, sınırlı) |
| Var olan/atıf yapılan dosya | Yedek kardeşleri: `.bak`, `~`, `.old`, `.save`, `.orig`, `.dist`, `.swp` |
| HTML/JS'te sızan dosya/dizin adı | Doğrudan problanır |

- **Yedek-kardeş türetme** en ucuz-en yüksek getiri (`/config.php` 200 → `/config.php.bak` yüksek olası).
- `path_probe` standalone olmalı (redteam canlı) → `robots.txt`'yi kendi çeker; küçük duplikasyon kabul
  ([endpoint_discovery.py:247](../../../orchestrator/pipeline/endpoint_discovery.py#L247) deseni).
- İkinci dalga da bütçe için kırpılır (**≤40 yol**).

Her iki motorun çıktısı aynı `catalog`'a girer → aynı validator/soft-404/maskeleme/pivot. **Yeni yargı
kuralı yok, sadece daha akıllı aday üretimi.**

## 8. K2 — LLM istihbarat subayı (öneri üretir, asla yargılamaz)

Dispatcher sınırında yeni yardımcı: `suggest_paths_llm(fingerprint) -> List[candidate]`. Küçük,
opsiyonel, hatası sessizce `[]` döner.

**Girdi (parmak izi paketi):** `_fingerprint_tech` çıktısı (ürün+sürüm), `Server`/`X-Powered-By`
başlıkları, gözlenen yollar (K0/K1'de 200/403 dönenler), `robots.txt` özeti, hata sayfası imzası,
`base_url`.

**Çıktı sözleşmesi (katı JSON):**
```json
[{
  "path": "/config/config.php.dist",
  "category": "config_exposure", "severity": "high",
  "reason": "Symfony 1.x .dist genelde okunur bırakılır",
  "signature": {
    "must_contain_any": ["hostspec", "sfPropelDatabase", "database"],
    "must_not_contain": ["<html", "<!doctype"],
    "min_length": 20
  }
}]
```

**Güvenilmez çıktı → deterministik yargı:** Yeni `_validate_from_signature(sig)` ham baytı LLM'in verdiği
desene göre kontrol eder. Bu validator **ZAYIF sınıfta** (`_STRONG_VALIDATORS`'a girmez) → **soft-404
baseline elemesinden geçer**. Çifte koruma: hem imza tutacak hem baseline'dan farklı olacak.

**Zorunlu güvenlik korkulukları:**
- `path` sanitize: `^/[\w\-./~%]+$`, `://` içeremez → hep aynı host.
- `category`/`severity` enum whitelist'e **clamp**.
- Üst sınır **≤30 öneri**, dedup, kataloğa enjekte.
- Sağlayıcı `resolve_ai_service_default` (DB > .env), **thinking KAPALI** (danışma çağrısı — DeepSeek v4
  sözleşmesi), kısa timeout, `_preflight` sağlık yoklaması. Erişilemezse `[]` → K1 fallback.
- **Maliyet/tekrar:** öneriler parmak-izi imzasına göre K3'e önbelleğe yazılır → benzer hedefte LLM'e
  tekrar ödenmez.

## 9. K3 — Öğrenme döngüsü (`scan_memories` canlanıyor)

Bugün `scan_memories` kodda hiç okunmuyor (ölü). Onu kalıcı "öğrenilmiş yol hafızası" yapıyoruz. Okuma/
yazma dispatcher sınırında; MongoClient **süreç-başına singleton** (CLAUDE.md).

**Doküman şeması (`kind: "learned_path"`):**
```json
{
  "kind": "learned_path",
  "path": "/symfony/config/databases.yml",
  "category": "credential_exposure", "severity": "critical",
  "validator": "symfony_databases",
  "signature": { "must_contain_any": ["hostspec", "password"] },
  "tech": ["symfony"],
  "source": "confirmed_finding | manual_report | llm_confirmed",
  "hit_count": 3, "confidence": 0.9,
  "targets": ["portal.arneca.com"],
  "first_seen": "...", "last_seen": "...", "enabled": true
}
```

- **Okuma (tarama başında):** `enabled=true` ve (tech eşleşen VEYA `tech=[]` global) yollar çekilir,
  confidence/hit_count'a göre sıralanıp **≤50** kırpılır, `paths=` ile enjekte. Mevcut dedup mükerreri eler.
- **Yazma (tarama sonunda):** Onaylanan her bulgu upsert — `hit_count++`, hedef eklenir, `last_seen`
  güncellenir. **Kirlenme korkulukları:** yalnız GÜÇLÜ validator geçen (veya zayıf+baseline'dan farklı)
  bulgular yazılır; kör 200'ler yazılmaz. ≥2 farklı hedefte doğrulanan yol → confidence yükselir →
  `tech=[]` global'e terfi. Toplam **≤500 yol**, düşük-confidence tahliyesi.
- **Manuel ekip raporu girişi:** Admin-only `POST /api/redteam/learn-path` — ekip bir URL (+ opsiyonel
  imza) yapıştırır, `source="manual_report"`, yüksek confidence, `enabled=true` kaydedilir. O andan
  itibaren her tarama o yolu proplar. "Başkası buldu biz bulamadık" tek seferlik olur; sonra kalıcı hafıza.

## 10. Bütçe, güvenlik, determinizm

**Bütçe (en önemli operasyonel risk):** Enjekte yollar kataloğu 200+'a çıkarabilir.
- **Önce-değer sıralaması:** Görevler **(severity, kaynak-confidence)** sırasıyla oluşturulur; bütçe
  biterse en düşük değerliler iptal olur, kritik kimlik yolları her zaman ilk semafor yuvasını alır.
  (Şu an sıralama yalnız bulgu sonrası yapılıyor — kritik fark: [path_probe.py:846](../../../orchestrator/pipeline/path_probe.py#L846).)
- **İki-faz bütçe + kaynak tavanları:** Dalga-1 (küratörlü + enjekte yüksek-değer) garantili bütçe;
  Dalga-2 (kanıt) kalanı kullanır. Tavanlar: aile ≤40, kanıt ≤40, LLM ≤30, hafıza ≤50 → toplam sınırlı.
  `partial` hangi kaynağın kesildiğini raporlar.

**Determinizm & fallback:** K0+K1 tam deterministik, her zaman çalışır. K2/K3 eklemeli; LLM/Mongo hatası
→ boş enjeksiyon → K0+K1 etkilenmez. K2/K3 **env flag** arkasında (`PATHPROBE_LLM_INTEL`,
`PATHPROBE_MEMORY`); kapatınca davranış bugünküyle bit-bit aynı. LLM önbelleği (K3) non-determinizmi azaltır.

**Güvenlik & gürültü:** Yalnız GET, düşük eşzamanlılık, kısa timeout, denetim UA'sı korunur. K2 path
sanitize → farklı hosta sızmaz. **Maskeleme:** LLM-imzalı/manuel bulgular da maskeden geçer; mevcut
env+YAML maskesine genel sır-deseni (parola/token/key) catch-all eklenir.

## 11. Test (TDD)

`test_path_probe_symfony.py` (mevcut, commit'siz) üstüne, `httpx.MockTransport` ile:
- Şablon genişleme (`apps/api/...` üretiliyor mu), kanıt-türetme (robots/.git/dizin/yedek-kardeş).
- `_validate_from_signature`, LLM çıktı sanitize/clamp, hafıza oku-yaz-birleştir, YAML+imza maskesi.
- **Determinizm testi:** LLM kapalı → iki koşuda birebir aynı çıktı.
- **Bütçe testi:** çok sayıda yavaş yol enjekte → kritik yol yine ilk problanıyor, `partial` doğru.

## 12. Gözlemlenebilirlik

Her bulgu `source` alanı taşır (curated/template/evidence/llm/memory) → rapor yolun nereden geldiğini
gösterir (değer kanıtı + ayar için sinyal). Mevcut `ScanEventBus` olayları korunur.

## 13. Rollout & "sistemi bozma" güvencesi

- Her şey **eklemeli** ve fallback arkasında; flag'ler kapalıyken K0 aynen çalışır.
- K2 (`PATHPROBE_LLM_INTEL`) ve K3 (`PATHPROBE_MEMORY`) varsayılan **kapalı** başlatılıp kademeli açılır.
- **Deploy notu:** commit'siz değişiklikler canlı değil — orchestrator konteyneri yeniden derlenmeli.

## 14. Kapsam dışı (YAGNI)

- PathProbe'u fuzz servisiyle (feroxbuster) birleştirmek — ayrı araç, ayrı rol; bu tasarımda birleştirilmez.
- Aktif exploit/enjeksiyon — PathProbe keşif sınıfıdır; yargı yalnız içerik doğrulaması.
- Parametreli endpoint keşfi — crawl/endpoint_discovery'nin işi (yol haritası §3.1), bu spec'in dışı.

## 15. Başarı ölçütü

- portal.arneca.com sınıfı `databases.yml` **K0/K1 ile (LLM'siz) yakalanır** — determinizmle.
- Manuel bulunan bir yol `/learn-path` ile bir kez girildiğinde sonraki taramalarda otomatik yakalanır.
- LLM/DB kapalıyken davranış bugünküyle aynı (regresyon yok).
