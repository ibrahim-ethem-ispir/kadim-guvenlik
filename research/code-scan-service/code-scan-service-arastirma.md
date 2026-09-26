# code-scan-service — Kaynak Kod Güvenlik Analizi (SAST) Modülü — Araştırma Notu

**Tarih:** 2026-08-30
**Durum:** ARAŞTIRMA (henüz uygulanmadı) — kullanıcı ayrıca araştıracak
**Not:** Bu doküman ana proje pipeline'ından bağımsız bir *fikir/plan*tır; yapmadan önce
tartışılacak. Burada "ne, neden, nasıl, hangi araçlar, hangi riskler" toplanmıştır.

---

## 1. Problem — black-box'ın kör noktası

Kadim şu an **black-box** tarar (dışarıdan, IP/domain üzerinden ağ + web). Bu yaklaşım
fundamental olarak **kaynak-kod seviyesi** açıkları göremez:

- **Auth/yetki mantığı hataları** (kodda yanlış kontrol; ör. `if (user.role = 'admin')` atama
  hatası, eksik yetki kontrolü, IDOR'un kod-kökü).
- **Sadece belirli kod-yolundan ulaşılan injection sink'leri** (black-box o parametreye hiç
  ulaşamaz ama kodda `exec($_GET['x'])` durur).
- **Kaynak koddaki hardcoded sırlar** (API key, DB parolası, private key — git geçmişinde bile).
- **Insecure deserialization / komut çalıştırma sink'leri** kod içinde.
- **Açıklı bağımlılıklar** (package.json/requirements.txt'te bilinen-açık kütüphane).

Kullanıcının cümlesi: *"biz böyle tarıyoruz açık yok diyoruz ama uygulama kodunda auth işlemli
gerçek RCE olabilir."* → **white-box (kaynak) analizi, black-box'ı TAMAMLAR (tekrar değil).**

Hedef kullanım: kendi projelerimizi + open-source projeleri (GitHub/GitLab bağla ya da .zip
yükle) güvenlik + sızma açısından tara, bul, raporla.

---

## 2. Kritik ilke — sıfırdan SAST motoru YAZMA (şişme tuzağı)

Gerçek SAST = kodu AST'ye ayır + taint/dataflow analizi (source→sink) + dil-başına. Semgrep,
CodeQL, Snyk bunu yıllarda yaptı. Sıfırdan yazmak projeyi **korkulan şekilde şişirir.**

**Doğru mimari = olgun açık-kaynak araçları SARMALA (platformun DNA'sı).** nmap/nuclei/subfinder
nasıl sarmalanmış dış araçsa, SAST de öyle: **ayrı, izole `code-scan-service` mikroservisi.**

---

## 3. Önerilen araç yığını (sarmalanacaklar)

| Katman | Araç | Ne yakalar | Lisans/not |
|--------|------|-----------|-----------|
| Pattern SAST | **Semgrep** | Injection sink, tehlikeli fonksiyon, misconfig; çok-dilli; geniş ücretsiz güvenlik kuralı | Açık kaynak (community rules ücretsiz) |
| Sır taraması | **Gitleaks** veya **TruffleHog** | Hardcoded key/parola/token (git GEÇMİŞİ dahil) | Açık kaynak |
| Bağımlılık (SCA) | **Trivy** veya **OSV-Scanner** / **Grype** | Bilinen-açık kütüphaneler (Log4Shell vb.), ayrıca IaC/config | Açık kaynak |
| Dil-özel (opsiyonel) | Bandit(Py), gosec(Go), njsscan(Node), brakeman(Ruby) | Dile özgü derin desenler | Açık kaynak |
| **Logic/auth RCE** | **LLM-review** (mevcut LLM katmanı) | Semgrep'in kaçırdığı auth-akış / mantık hataları (semantik) | Kendi altyapımız |

**Neden LLM-review katmanı önemli:** Kullanıcının asıl derdi "auth işlemli gerçek RCE" — bu
*mantık* hatası, pattern-SAST zayıf, LLM semantik olarak güçlü. AMA doktrin: **LLM önerir,
deterministik çekirdek onaylar.** SAST'ta "onay" zor (kaynak-kod RCE'sini güvenle çalıştırıp
kanıtlamak her zaman mümkün değil) → kademe modeli (§5).

---

## 4. Mimari (mevcut desene birebir uyum)

```
Kullanıcı: GitHub/GitLab URL  ya da  .zip yükle
      │
      ▼
orchestrator ──HTTP──► code-scan-service (yeni, izole Docker kutusu)
                          │  git clone / unzip → geçici workspace
                          │  paralel: Semgrep + Gitleaks + Trivy (+ dil-özel)
                          │  yüksek-riskli dosyalar (auth/session/exec sink) → LLM-review
                          ▼
                       bulgular → orchestrator normalize eder →
                       mevcut Evidence + confidence_tier + rapor + UI (yeni ekran YOK)
```

**Şişmeyi önleyen kurallar:**
- Ayrı mikroservis → mevcut tarama pipeline'ına **hiç dokunmaz**.
- İnce sarmalayıcı → motor yazmıyoruz.
- Sonuçlar mevcut `Evidence`/`confidence_tier`/rapor/`coverage_contract` modeline girer.
- Feature-flag'li → kapatınca sıfır maliyet.
- Geçici workspace → tarama bitince temizlenir (disk şişmesi yok).

---

## 5. Confidence tier (SAST bulguları için)

Black-box'taki confirmed/probable/unconfirmed ekseni burada da:
- **Semgrep pattern eşleşmesi** → `probable` (desen var ama sömürülebilirlik kanıtı yok).
- **Gitleaks sır** → doğrulanabilirse (canlı key testi, tahribatsız) `confirmed`, yoksa `probable`.
- **Trivy SCA** → sürüm-eşleşmeli CVE → `probable`/`unconfirmed` (kullanımı kanıtlanmadıkça).
- **LLM-review hipotezi** → `unconfirmed` (hipotez); asla tek başına `confirmed` olamaz.
- **`confirmed` için** ya ulaşılabilir güvenli PoC (→ black-box motorla runtime kanıt), ya da
  manuel doğrulama gerekir.

---

## 6. İleri vizyon — white-box + black-box sinerjisi (şimdi değil)

SAST kodda bir RCE **sink**'i bulur (ör. `/api/x` içinde `exec(userInput)`) → **black-box motor
o endpoint'e runtime'da ULAŞIP güvenli-kanıtlar** → `confirmed`. İkisi birbirini besler:
white-box "nerede" der, black-box "gerçekten sömürülebilir mi" der. Bu, iki motoru birleştiren
asıl fark yaratıcı son hal. (MVP'de değil; hedef mimari.)

---

## 7. Açık araştırma soruları (kullanıcının bakacağı)

1. **Repo ingestion:** git clone (kimlik/token yönetimi, private repo) vs .zip upload — hangisi
   önce? Büyük monorepo ölçeği?
2. **Lisans:** CodeQL çok güçlü (dataflow) ama lisans şartları (yalnız open-source ücretsiz) —
   Semgrep community yeterli mi? Semgrep Pro kuralları gerekli mi?
3. **Dil önceliği:** hangi diller önce? (projelerin çoğu PHP/Node/Python mı?)
4. **FP yönetimi:** Semgrep gürültülü olabilir — kural seti seçimi + LLM-hakem eleme.
5. **Sır geçmişi:** git history taraması gizlilik/etik (silinmiş ama commit'te duran sırlar).
6. **Grafta temsil:** kod bulgusu attack_graph'a nasıl girer? (dosya:satır düğümü?) Yoksa ayrı
   rapor bölümü mü?
7. **Performans:** büyük repo Semgrep süresi; cap/timeout/incremental (yalnız diff).

---

## 8. Önerilen başlangıç (sıralama)

**Önce benchmark (ölçüm omurgası), sonra bu modül.** Gerekçe: SAST'ı da körlemesine yaparsak
"ölçemiyorum/şişiyor" derdini yeni eksende tekrarlarız. Benchmark, SAST'ı 1. günden ölçülebilir
kılar (savunmasız repo'lar = SAST ground-truth).

**MVP (en küçük değerli parça):**
1. `code-scan-service` iskeleti (FastAPI, mevcut servis deseni) + .zip upload.
2. Semgrep + Gitleaks sarmalama → normalize → mevcut rapor.
3. Bilinen-savunmasız bir repo'ya karşı benchmark (ground-truth ile puanla).
4. Sonra: Trivy (SCA) + LLM-review (auth/RCE) katmanları.
5. İleri: SAST sink → black-box runtime kanıt sinerjisi.

---

## 9. İlgili
- Benchmark çalışması: `benchmarks/nextjs-cve-2025-29927/` (black-box tarafın ilk vakası).
- Ana güvenilirlik raporu: `docs/2026-08-30-auto-scan-guvenilirlik-calismasi-raporu.md`.
- Kapsama sözleşmesi (SAST bulguları buraya da sınıf olarak girebilir): `coverage_contract.py`.
