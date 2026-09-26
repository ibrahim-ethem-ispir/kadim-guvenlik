# Kadim Güvenlik Auto-Scan — APT & Kurumsal Bankacılık Perspektifinden Gerçekçi Durum, Düzeltmeler ve Gelişim Raporu

**Tarih:** 2026-09-06  
**Revizyon:** 2.0 (Kod Doğrulaması + APT Tehdit Aktörü & Bankacılık Mimarisi Perspektifi)  
**Kapsam:** `orchestrator/pipeline/` (AutonomousEngine, AttackGraph, ScanPipelineV2, CoverageContract, Verification, IDOR, EndpointDiff), `services/*` (Crawler Playwright, Nmap, Nuclei, RustScan) ve `frontend/app/`

---

## 1. Yönetici Özeti & İlk Raporun Kod Tabanlı Düzeltmesi (Errata)

Önceki değerlendirmede yer alan bazı maddeler kod tabanının derinlikleriyle karşılaştırıldığında **haksız bulunmuş ve düzeltilmiştir**. Sistemin hakkını teslim etmek, gerçek açıkları doğru tespit edebilmenin ön şartıdır.

### 1.1 Çürütülen Haksız Eleştiriler (Kodda Zaten Var Olan Yetenekler)
1. ❌ *"Headless browser (DOM/JS/SPA) yok, saf httpx var"* **→ YANLIŞ.**  
   `services/crawler-service/main.py` incelendiğinde; Playwright ve headless Chromium ile çalışan tam bir SPA tarayıcısı mevcuttur. Render edilmiş DOM linklerini, formları ve en önemlisi arka plandaki **XHR / fetch API çağrılarını** yakalamakta, `auth_headers` ile login-arkası SPA sayfalarını başarıyla haritalandırmaktadır.
2. ❌ *"Zamanlanmış tarama ve varlık diff'i yok"* **→ YANLIŞ / EKSİK.**  
   `orchestrator/integrations/schedules_router.py` (48 KB) periyodik taramaları, cron aralıklarını ve AI jitter mekanizmasını yönetmektedir. Ayrıca `orchestrator/pipeline/endpoint_diff.py` scheduled taramalar arasında snapshot alıp **yeni endpoint, yeni parametre ve yeni form** yüzey değişimlerini (diff) çıkarmaktadır. (Yalnızca port seviyesinde envanter diff'i henüz eksiktir).
3. ❌ *"IDOR/BOLA testi prototip seviyesinde, iki hesaplı A/B matrisi yok"* **→ YANLIŞ.**  
   `orchestrator/pipeline/idor_probe.py` doğrudan **ALTIN KİP** (User A nesnesi → User B token'ı → gövde benzerliği analizi + anonim red kontrolü) ile deterministik PoC kanıtlamakta, ikinci hesap yoksa **GÜMÜŞ KİP** (n±1 enumerasyon) ile probable işaretlemektedir.
4. ❌ *"Sadece tek bir hedefe kilitlenir, fan-out yapamaz"* **→ KISMEN YANLIŞ.**  
   `scan_pipeline_v2.py:561` üzerinde **PER-HOST HEDEFLEME** mimarisi vardır. Keşfedilen her alt alan adı (subdomain) ve origin IP için graf üzerinde yeni saldırı kenarları üretilir ve dinamik hedef swap mekanizmasıyla alt hedefler tek tek yoklanır.

---

### 1.2 Kod Tarafından Doğrulanan Gerçek Eksikler (Kritik Boşluklar)
1. ✅ **Out-of-Band (OAST) Altyapısının Olmaması:**  
   `orchestrator/pipeline/verification.py:1335` satırında kod bunu açıkça itiraf eder:  
   *`"OOB callback altyapımız YOK"`*  
   Interactsh / Collaborator benzeri bir dinleyici olmadığı için kör (blind) SSRF, blind XXE, kör RCE (Log4j vb.) ve DNS exfiltration gerektiren açıklar in-band HTTP yanıtı dönmediği sürece yakalanamaz.
2. ✅ **Dağıtık Görev Kuyruğu (Distributed Queue) Yokluğu:**  
   `scan_pipeline_v2.py:2964` otonom taramayı doğrudan `asyncio.create_task(_run_autonomous)` ile tek bir FastAPI süreci içinde başlatır. Container restart veya OOM durumunda bellek içi görev kurtarılamaz.
3. ✅ **Sessiz Aşama Düşüşleri (Degraded Stages):**  
   `scan_pipeline_v2.py:3563` ve `:3340` satırlarında belirtildiği gibi, Docker servislerinden biri ConnectError verdiğinde motor taramayı durdurmaz ama o koldan veri alamadığı için tarama hedefsiz kalabilir.
4. ✅ **Aşırı Katı Doğrulamanın Zafiyet Kaçırması (FP Korkusu → FN Tuzağı):**  
   `autonomous_report.py:67` satırında açıkça belirtilmiştir:  
   *`"Manşet sayımı: unconfirmed'ı SAYMA"`*  
   WAF arkasındaki veya özel HTTP bağlamı gerektiren karmaşık bir zafiyet deterministik PoC'den geçemezse `unconfirmed` kalır ve üst yönetici rapor manşetinden düşürülür.
5. ✅ **Dış Kurumsal Entegrasyonların (Jira / SIEM / Webhook) Yokluğu:**  
   Kod tabanında biletleme (Jira, ServiceNow) veya SOC entegrasyonu (CEF/LEEF Syslog, Slack/Teams) yer almamaktadır.

---

## 2. APT Tehdit Aktörleri Gözüyle Bakış: Bir Banka / Kurumsal Altyapı Nasıl Taranır ve Korunur?

Lazarus Group, APT29 (Cozy Bear), FIN7 veya Volt Typhoon gibi gelişmiş tehdit aktörleri kurumsal bankacılık ve finans altyapılarına rastgele Nmap taramalarıyla saldırmaz. Bankaların dış yüzeyi ve savunma mekanizmaları standart KOBİ'lerden kökten farklıdır:

```
[ APT Saldırganı ]
       │
       ▼  (Low & Slow, Dağıtık Proxy, WAF Evasion)
[ Banka Dış Savunma Hattı ] ── Akamai Kona / Cloudflare Ent / F5 BIG-IP / Imperva
       │
       ▼  (Sınır Cihazı / Gateway Açığı: Fortinet, Citrix, Ivanti, Pulse)
[ Perimeter DMZ ] ──────────── API Gateway, Reverse Proxy, mTLS, WAF
       │
       ▼  (Asenkron Mesajlaşma: Kafka, RabbitMQ, IBM MQ, ESB)
[ İç Ağ & Core Banking ] ──── SWIFT, Veritabanları, Kredi/Hesap Servisleri (İnternete Kapalı)
```

Bu mimarideki temel savunma unsurları ve APT yaklaşımları:

### 2.1 WAF / Anti-DDoS ve SOC Alarm Mekanizmaları
* **Banka Savunması:** Banka perimeter'ında Akamai Kona, Imperva Incapsula veya Cloudflare Enterprise bulunur. Arkasında 7/24 çalışan bir SOC (Splunk, QRadar, CrowdStrike) vardır.
* **Mevcut Sistemin Tehlikesi:** Standart bir Nmap veya RustScan ile saniyede yüzlerce SYN paketi göndermek ya da Nuclei ile 3000 template'i arka arkaya çalıştırmak, banka WAF'ında saniyeler içinde **IP'nin karalisteye alınmasına** yol açar. Tarayıcı banlandığını fark edemezse dönen 403/429 yanıtlarını tarayarak kendini kandırır.
* **APT Taktiği (Low-and-Slow & Adaptive Jitter):** İstekler günlere yayılır, aralarına insan davranışı taklit eden rastgele gecikmeler (jitter) eklenir, istekler residential/tor proxy havuzlarından dağıtılır ve HTTP header anomalileri gizlenir.

### 2.2 Sınır Cihazları ve Ağ Donanımı (Perimeter Gateway Exploitation)
* **Banka Savunması:** Bankalar dış dünyaya açık web portallarında çok sıkı güvenlik yamaları uygular. Ancak **VPN ağ geçitleri, SSL-VPN portalları, ADC (Application Delivery Controller) ve güvenlik duvarı yönetim arayüzleri** (Citrix NetScaler, Fortinet FortiGate, Ivanti Connect Secure, Palo Alto GlobalProtect) kritik kör noktalardır.
* **APT Taktiği:** Son 3 yıldaki banka ve kritik altyapı ihlallerinin %60'ından fazlası bu ağ cihazlarındaki 0-day/N-day zafiyetlerden (örn. Citrix Bleed CVE-2023-4966, FortiOS RCE CVE-2024-21762, Ivanti SSRF CVE-2024-21887) kaynaklanmıştır.

### 2.3 Asenkron Mimariler ve Out-of-Band (OAST) Zorunluluğu
* **Banka Savunması:** Banka web ve mobil API'ları gelen istekleri doğrudan veritabanına işlemez. API Gateway isteği alır, doğrular ve iç ağdaki bir mesaj kuyruğuna (Kafka, RabbitMQ, IBM MQ) bırakır.
* **Zafiyetin Doğası:** İsteğe enjekte edilen bir zararlı payload (Kör XXE, Deserialization, Log4j benzeri JNDI, Kör SSRF), dışarıya açık API Gateway üzerinde değil; dakikalar veya saatler sonra iç ağdaki bir fatura/raporlama işleyicisi (worker) tarafından parse edildiğinde tetiklenir.
* **Sonuç:** OAST (Out-of-Band Callback Server) olmadan bir bankanın backend sistemlerindeki bu asenkron zafiyetleri tespit etmek **matematiksel olarak imkansızdır**.

### 2.4 İş Mantığı (Business Logic) & Finansal Manipülasyon (BOLA/Race Condition)
* **Banka Gerçeği:** Bankalarda en yıkıcı zafiyetler klasik SQL Injection değildir (veritabanları zaten ORM arkasında ve parametrik sorgulardadır). Asıl felaket getiren açıklar:
  * **Race Condition (Limit Aşımı / Çift Harcama):** Bakiyeden para düşülmeden önce aynı milisaniyede paralel 10 istek atarak tek bakiye ile 10 transfer yapabilmek (HTTP/2 Single-Packet Attack).
  * **BOLA / Finansal IDOR:** Başka müşterinin IBAN'ına, hesap dökümüne veya kredi kartı limitine kimliksiz ya da yetkisiz erişebilmek (`idor_probe.py`'nin Altın Kipi bunu hedefler).
  * **3D Secure / Ödeme Callback Manipülasyonu:** Sanal POS'tan dönen `MDStatus` veya ödeme onay webhook'unun hash'siz/imzasız manipüle edilmesi.

---

## 3. Kadim Güvenlik Auto-Scan'in APT & Kurumsal Olgunluk Değerlendirmesi

| Güvenlik Boyutu | APT & Banka Savunma Standardı | Kadim Güvenlik Mevcut Durumu | Hüküm & İhtiyaç |
| :--- | :--- | :--- | :--- |
| **WAF / IDS / SOC Evasion** | Low-and-slow tarama, dinamik jitter, proxy rotasyonu, WAF bypass encoding | WAF tespiti var (`waf_detect.py`), ancak tarama hızını dinamik yavaşlatma / proxy havuzu sınırlı | ⚠️ Banka WAF'ı agresif modda tarayıcıyı anında bloklayabilir. |
| **Ağ Cihazları (Perimeter)** | Citrix, Fortinet, Ivanti, F5, Pulse Secure özel KEV/0-day istihbaratı | `appliance_probe.py` ve `hypervisor_probe.py` mevcut; KEV kataloğu aktif | 🌟 **Güçlü taban; appliance exploit zincirleri derinleştirilebilir.** |
| **Kör Zafiyetler (OAST)** | İnternete kapalı iç servislerden tetiklenen callback dinleyicisi (DNS/HTTP/LDAP) | OOB callback sunucusu YOK (`verification.py:1335`) | ❌ **En büyük kör nokta! Bankacılık backend zafiyetleri kaçar.** |
| **Modern Web (SPA/API)** | Playwright/Chromium DOM render, XHR/fetch yakalama, JWT/mTLS | Playwright crawler (`crawler-service`) ve `auth_headers` aktif | 🌟 **Başarılı ve güncel modern web yüzey keşfi.** |
| **Yetki & IDOR (BOLA)** | Çift hesaplı diferansiyel analiz, parametre enumerasyonu | `idor_probe.py` Altın Kip (A/B) ve Gümüş Kip aktif | 🌟 **Piyasadaki DAST'ların çoğundan daha ileride bir mantık.** |
| **İş Mantığı (Race Condition)** | HTTP/2 tek paketli paralel yarış durumu denetimi | Yok (Mevcut probe'lar sıralı HTTP istekleri atar) | ⚠️ Finansal API'lar için race condition motoru eksik. |
| **Envanter Zaman Serisi** | Port/servis/sertifika delta izleme (günlük/haftalık değişim) | `endpoint_diff.py` var (URL/parametre), ama port/servis seviyesinde diff yok | ⚠️ Yüzey genişlemesi yalnız URL bazında takip ediliyor. |
| **Orkestrasyon & Dayanıklılık** | Dağıtık kuyruk (Celery/Temporal), worker restart dayanıklılığı | Tekil FastAPI `asyncio.create_task` | ⚠️ Kurumsal ölçekte çökme durumunda tarama kurtarılamaz. |

---

## 4. Sistemi Kurumsal / Banka Seviyesine Yükseltecek Gerçekçi Yol Haritası

Sistemin mevcut "akıllı saldırı grafı" çekirdeğini bozmadan, kurumsal ve APT tehdit aktörü seviyesine çıkarmak için yapılması gereken somut adımlar:

```
                  ┌──────────────────────────────────────────────────────────┐
                  │              KADIM GÜVENLİK 3.0 MİMARİSİ                 │
                  └──────────────────────────────────────────────────────────┘
                                                │
         ┌──────────────────────────────────────┼──────────────────────────────────────┐
         ▼                                      ▼                                      ▼
[ GİZLİLİK & EVASION ]                 [ KÖR AÇIKLAR & OAST ]                 [ DAĞITIK ORKESTRASYON ]
• Adaptive Jitter & Rate Limiter       • ProjectDiscovery Interactsh          • Celery / Redis Task Queue
• WAF-Aware Request Shaping            • DNS / HTTP / LDAP Callback           • Persistent State Recovery
• Residential / Rotating Proxy Pool    • Asenkron Backend Vuln Teyidi         • Multi-Worker Yatay Ölçek
         │                                      │                                      │
         └──────────────────────────────────────┼──────────────────────────────────────┘
                                                │
         ┌──────────────────────────────────────┼──────────────────────────────────────┐
         ▼                                      ▼                                      ▼
[ FİNANSAL İŞ MANTIĞI ]                [ VARLIK DELTA RADARI ]                [ KURUMSAL ENTEGRASYON ]
• HTTP/2 Single-Packet Race Cond.      • Port & Servis Değişim Takibi         • Otomatik Jira / ServiceNow
• Multi-Step Transaction Abuse         • SSL/TLS Sertifika Bitiş Radarı       • SOC SIEM Loglama (CEF/LEEF)
• BOLA Altın Kip Genişletmesi          • Subdomain Takeover İzleme            • Slack / Teams / Webhook Alert
```

### Adım 1: OAST (Out-of-Band Application Security Testing) Entegrasyonu (Öncelik: P0)
* **Ne Yapılacak:** Açık kaynaklı `interactsh-client` veya bağımsız bir DNS/HTTP callback mikroservisi (`services/oast-service`) sisteme dahil edilmeli.
* **Etki:** Kör SSRF, kör XXE, Log4j benzeri kör RCE ve DNS exfiltration bulguları deterministik olarak kanıtlanabilir (`confirmed`) hale gelecektir.

### Adım 2: Banka / SOC Dostu APT Stealth Profili (Öncelik: P1)
* **Ne Yapılacak:** `scan_profiles.py` içerisine yeni bir `stealth_apt` profili eklenmeli:
  * WAF tespit edildiğinde istek aralığı dinamik olarak artırılmalı (1-5 sn rastgele jitter).
  * HTTP istek başlıkları (User-Agent, Accept, Sec-Ch-Ua) gerçek tarayıcı profilleriyle dinamik değiştirilmeli.
  * Evasion katmanı: URL encoding, chunked transfer encoding, JSON unicode kaçışları gibi WAF atlatma teknikleri devreye sokulmalı.

### Adım 3: HTTP/2 Race Condition (Yarış Durumu) Motoru (Öncelik: P1)
* **Ne Yapılacak:** `httpx` veya `curl-cffi` üzerinden HTTP/2 Single-Packet Attack (aynı TCP paketinde birden fazla isteği sunucuya aynı anda teslim etme) probu yazılmalı.
* **Etki:** Finansal API'larda bakiye düşümü, kupon/indirim kullanımı veya limit kontrollerindeki mantık hataları otomatik test edilebilir.

### Adım 4: Dağıtık Görev Mimarisi (Celery + Redis) (Öncelik: P2)
* **Ne Yapılacak:** `scan_pipeline_v2.py` içindeki `asyncio.create_task` çağrıları Redis destekli bir Celery/Temporal görev kuyruğuna devredilmeli.
* **Etki:** Docker veya orchestrator çökse bile tarama kaldığı adımdan devam eder; aynı anda yüzlerce IP/domain paralel taranabilir.

### Adım 5: Port ve Servis Seviyesinde Varlık Delta Takibi (Öncelik: P2)
* **Ne Yapılacak:** `endpoint_diff.py`'nin dosya/URL düzeyinde yaptığı snapshot-diff mantığı, `nmap_service` çıktısındaki port, servis ve banner verileri için de uygulanmalı (`asset_diff.py`).
* **Etki:** Her periyodik taramada *"Son 7 günde hedef bankada yeni açılan 3 port ve değişen 1 SSL sertifikası"* gibi kurumsal ASM raporları üretilebilir.

### Adım 6: Kurumsal Aksiyon Katmanı (Jira & SIEM) (Öncelik: P3)
* **Ne Yapılacak:** `ProofBundle` ile kanıtlanmış `confirmed` bulgular için tek tıkla veya otomatik Jira bileti açan, banka SIEM sistemine (Splunk/QRadar) syslog (CEF/LEEF) basan bir bildirim router'ı eklenmeli.

---

## 5. Nihai Hüküm

Kadim Güvenlik Auto-Scan, sıradan bir "AI tarayıcısı" değil; **savunma grafı (Attack Graph), PoC doğrulayıcıları, Playwright crawler'ı ve IDOR A/B diferansiyeliyle sahada çalışan gerçek bir otonom saldırı motorudur.**

Ancak kurumsal bir **Banka ve Kritik Altyapı Güvenliği** standartlarında değerlendirildiğinde:
1. **OAST (Kör Açıklar) olmaması** backend servislerini görmesini engeller,
2. **Stealth/Evasion eksikliği** banka WAF'ı tarafından erken engellenme riski taşır,
3. **HTTP/2 Race condition yokluğu** finansal iş mantığı açıklarını kaçırır.

Bu üç kritik eksik kapatıldığında, sistem yalnızca bir "tarayıcı" olmaktan çıkıp **gerçek bir Red Team / APT simülatörü** seviyesine ulaşacaktır.
