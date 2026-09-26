"""
Kadim AI Service - Güvenlik Analiz Servisi
Ollama (local) ve Claude (cloud) destekli AI analiz microservice

Türkçe: Bu servis tarama sonuçlarını AI ile analiz eder ve güvenlik önerileri sunar.

v2.0 Güncellemeler:
- Chat history desteği (konuşma bağlamı korunur)
- Geliştirilmiş prompt sistemi
- Context-aware yanıtlar
- Streaming desteği hazırlığı
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import httpx
import os
import re
import json
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

# Yeni modüller
from chat_history import (
    get_conversation, create_conversation, add_message,
    get_context_messages, update_analysis_state, get_conversation_summary,
    clear_conversation, export_conversation, import_conversation,
    build_system_context
)
from prompt_builder import (
    build_enhanced_security_prompt, build_enhanced_chat_prompt,
    build_hash_analysis_prompt, build_vulnerability_analysis_prompt,
    build_osint_analysis_prompt, calculate_risk_score,
    ground_cves_in_narrative,  # narrative halüsinasyon-CVE guard
)

# Merkezi AI Model Konfigürasyonu
from ai_config import (
    VALID_GEMINI_MODELS, GEMINI_MODEL_MAPPING, DEFAULT_GEMINI_MODEL,
    VALID_CLAUDE_MODELS, CLAUDE_MODEL_MAPPING, DEFAULT_CLAUDE_MODEL,
    validate_gemini_model, validate_claude_model, get_all_models
)

# TOON Token Optimization
try:
    from toon_serializer import compress_scan_data, estimate_token_savings, to_toon, TOONSerializer
    TOON_AVAILABLE = True
    print("✅ TOON Token Optimizer yüklendi - %30-60 token tasarrufu aktif")
except ImportError:
    TOON_AVAILABLE = False
    print("⚠️ TOON serializer bulunamadı, standart JSON kullanılacak")

# Multi-Agent System
try:
    from agents import AgentContext, AgentRegistry, get_registry
    from agents.orchestrator_agent import get_orchestrator, run_multi_agent_analysis
    AGENTS_AVAILABLE = True
    print("✅ Multi-Agent System yüklendi")
except ImportError as e:
    AGENTS_AVAILABLE = False
    print(f"⚠️ Multi-Agent System yüklenemedi: {e}")

# AI Report Engine - Nessus'tan 10x daha güçlü
try:
    from report_engine import AIReportEngine, generate_ai_report
    REPORT_ENGINE_AVAILABLE = True
    print("✅ AI Report Engine yüklendi - Attack Chain + Business Impact aktif")
except ImportError as e:
    REPORT_ENGINE_AVAILABLE = False
    print(f"⚠️ AI Report Engine yüklenemedi: {e}")

# 🧠 AI Brain Modülleri
try:
    from brain_router import router as brain_router
    BRAIN_AVAILABLE = True
    print("✅ AI Brain yüklendi - Multi-AI Orchestra aktif")
except ImportError as e:
    BRAIN_AVAILABLE = False
    print(f"⚠️ AI Brain yüklenemedi: {e}")

app = FastAPI(
    title="Kadim AI Service",
    description="Güvenlik tarama sonuçlarını AI ile analiz eden servis (Multi-Agent + TOON + Report Engine + AI Brain 101)",
    version="3.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🧠 AI Brain Router Endpoints
if BRAIN_AVAILABLE:
    app.include_router(brain_router)
    print("✅ AI Brain endpoints aktif: /brain/*")

# Configuration — TEK kaynak: llm_env_config (.env). Tekrarlı os.getenv blokları kaldırıldı.
from llm_env_config import (
    OLLAMA_URL, CLAUDE_API_KEY, GEMINI_API_KEY,
    DEEPSEEK_BASE_URL, DEEPSEEK_API_KEY, DEEPSEEK_MODEL,
    resolve_ai_service_default, VALID_PROVIDERS, provider_default_model,
)

# Rate limiting cache
rate_limit_cache = defaultdict(list)


# ============== Models ==============

class AnalysisRequest(BaseModel):
    scan_data: dict
    provider: Literal["ollama", "deepseek", "claude", "gemini"] = "ollama"
    model: str = "mistral:7b"
    analysis_type: str = "security"  # security, hash, osint, vuln
    use_default: bool = False  # True → provider/model varsayılandan (DB > .env) gelir


# ai-service'in TARİHSEL ollama varsayılan modeli. Otonom motorun ollama modeli (Qwythos)
# rapor/analiz için pull edilmemiş olabilir; bu yüzden ollama'da boş-model → mistral:7b
# (eski davranış) korunur. Cloud sağlayıcılar kendi gerçek varsayılan modellerini kullanır.
AI_SERVICE_OLLAMA_FALLBACK_MODEL = "mistral:7b"


def _provider_fallback_model(provider: str) -> str:
    """Açıkça seçilmiş provider için boş-model fallback'i. ollama'da regresyonu önlemek için
    tarihsel mistral:7b; diğerlerinde sağlayıcının .env varsayılanı."""
    if provider == "ollama":
        return AI_SERVICE_OLLAMA_FALLBACK_MODEL
    return provider_default_model(provider)


def resolve_provider_model(provider: Optional[str], model: Optional[str], use_default: bool):
    """İstekteki provider/model'i AKTİF varsayılana göre çöz (varsayılan: DB > .env).

    use_default=True → her zaman varsayılan (resolve_ai_service_default: DB > .env) kazanır.
    Aksi halde istek açık bir seçim yaptıysa o korunur (regresyon yok); geçersiz/boş provider
    verilmişse varsayılana düşülür.
    """
    default = resolve_ai_service_default()
    # use_default → provider VE model tümüyle varsayılandan gelir. İstek model'i (varsayılan
    # "mistral:7b" gibi truthy olsa bile) YOK SAYILIR — aksi halde ör. varsayılan claude iken
    # provider=claude + model=mistral:7b uyumsuzluğu oluşurdu (bulut API reddeder).
    if use_default:
        return default["provider"], default["model"]
    # Geçersiz/boş provider → varsayılana düş; istek model verdiyse onu koru.
    if not provider or provider.lower() not in VALID_PROVIDERS:
        return default["provider"], (model or default["model"])
    # İstek açık bir provider verdi ama model yok → O SAĞLAYICININ fallback modeli
    # (yanlış-eşleşmiş model olmasın, örn. deepseek'e claude modeli; ollama'da mistral:7b).
    p = provider.lower()
    return p, (model or _provider_fallback_model(p))


class AnalysisResponse(BaseModel):
    provider: str
    model: str
    analysis: str
    risk_score: Optional[int] = None
    recommendations: List[str] = []
    critical_findings: List[str] = []
    technical_details: List[str] = []  # CVE, versiyon, PoC komutları
    next_steps: List[str] = []
    conversation_id: Optional[str] = None  # Chat history için
    message_count: Optional[int] = None  # Konuşmadaki mesaj sayısı


# ============== Rate Limiting ==============

def check_rate_limit(identifier: str, max_requests: int = 20, window_minutes: int = 60):
    """Türkçe: Basit rate limiting (abuse önleme)"""
    now = datetime.now()
    cutoff = now - timedelta(minutes=window_minutes)
    
    # Eski request'leri temizle
    rate_limit_cache[identifier] = [
        ts for ts in rate_limit_cache[identifier] if ts > cutoff
    ]
    
    # Limit kontrolü
    if len(rate_limit_cache[identifier]) >= max_requests:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit aşıldı. {window_minutes} dakikada max {max_requests} istek."
        )
    
    # Yeni request'i kaydet
    rate_limit_cache[identifier].append(now)


# ============== Prompt Building ==============

def build_security_prompt(scan_data: dict, analysis_type: str = "security") -> str:
    """
    Türkçe: Tarama verisinden güvenlik analiz promptu oluştur
    
    v2.0: Geliştirilmiş prompt builder modülünü kullanır
    """
    
    # Farklı analiz türleri için özel promptlar
    if analysis_type == "hash":
        return build_hash_analysis_prompt(scan_data)
    elif analysis_type == "osint":
        return build_osint_analysis_prompt(scan_data)
    elif analysis_type == "vuln":
        return build_vulnerability_analysis_prompt(scan_data)
    elif analysis_type == "redteam":
        return build_redteam_prompt(scan_data)
    elif analysis_type == "path_intel":
        return build_path_intel_prompt(scan_data)
    elif analysis_type == "adaptive_payloads":
        return build_adaptive_payloads_prompt(scan_data)

    # Genel güvenlik tarama analizi - geliştirilmiş prompt kullan
    return build_enhanced_security_prompt(scan_data, analysis_type)


def build_hash_analysis_prompt(scan_data: dict) -> str:
    """Türkçe: Hash kırma sonuçları için prompt"""
    
    hash_value = scan_data.get("hash", "unknown")
    hash_type = scan_data.get("hash_type", "unknown")
    found = scan_data.get("found", False)
    password = scan_data.get("password", None)
    attempts = scan_data.get("attempts", 0)
    elapsed = scan_data.get("elapsed_ms", 0)
    
    prompt = f"""Sen bir siber güvenlik uzmanısın. Hash kırma sonucunu analiz et.

# HASH KRAKİNG SONUCU

**Hash:** `{hash_value}`
**Hash Türü:** {hash_type}
**Sonuç:** {"✅ KIRILDI" if found else "❌ Kırılamadı"}
**Bulunan Şifre:** {password if password else "N/A"}
**Denenen Kombinasyon:** {attempts:,}
**Geçen Süre:** {elapsed/1000:.2f} saniye

# ANALİZ GÖREVLERİ

1. Bu hash türünün güvenlik düzeyini değerlendir
2. {"Bulunan şifrenin gücünü analiz et" if found else "Neden kırılamadığını açıkla"}
3. Güvenlik önerileri sun

# YANIT FORMATI

## Risk Değerlendirmesi
[Hash türü ve sonuç hakkında değerlendirme]

## 🔴 Bulgular
1. [Bulgu 1]
2. [Bulgu 2]

## 💡 Öneriler
1. [Öneri 1]
2. [Öneri 2]

## 🔬 Teknik Analiz & Deliller
1. **Hash Algoritması:** {hash_type}
   - Kırılma yöntemi: [brute-force/dictionary/rainbow-table]
   - Deneme hızı: {attempts/(elapsed/1000):.0f} hash/saniye

## ⏭️ Sonraki Adımlar
- [Aksiyon 1]
- [Aksiyon 2]

Türkçe yanıt ver."""

    return prompt


def build_osint_analysis_prompt(scan_data: dict) -> str:
    """Türkçe: OSINT sonuçları için prompt"""
    
    domain = scan_data.get("domain", scan_data.get("target", "unknown"))
    
    prompt = f"""Sen bir OSINT (Açık Kaynak İstihbarat) uzmanısın.

# OSINT VERİLERİ

**Hedef Domain:** `{domain}`

**TAM VERİ:**
```json
{json.dumps(scan_data, indent=2, ensure_ascii=False, default=str)[:6000]}
```

# ANALİZ GÖREVLERİ

1. Toplanan istihbaratı özetle
2. Potansiyel güvenlik risklerini belirle
3. Social engineering attack yüzeyini değerlendir
4. Sonraki istihbarat toplama adımlarını öner

# YANIT FORMATI

## Risk Skoru: [X/100]
[Genel değerlendirme]

## 🔴 Kritik Bulgular
1. [Bulgu]

## 💡 Öneriler
1. [Öneri]

## 🔬 Teknik Analiz & Deliller
1. **Toplanan Veri Kaynakları:**
   - WHOIS, DNS, Subdomain, Email vs.
   - Her kaynağın güvenilirlik derecesi

## ⏭️ Sonraki Adımlar
- [Aksiyon]

Türkçe yanıt ver."""

    return prompt


def build_redteam_prompt(scan_data: dict) -> str:
    """
    Türkçe: Red Team (saldırgan takım) analiz promptu.
    Hedefin hızlı yüzey snapshot'ını (DNS + HTTP parmak izi + hassas yol bulguları +
    subdomainler) saldırgan gözüyle değerlendirir; "sektörün 5 adım önünde" düşünerek
    saldırı zincirleri ve insan analistin henüz bakmadığı noktaları üretir.
    """

    target = scan_data.get("target", "unknown")
    # Snapshot'ı ham JSON olarak ver — model kendi bağlantılarını kursun
    snapshot_json = json.dumps(scan_data, indent=2, ensure_ascii=False, default=str)[:9000]

    prompt = f"""Sen Kadim Güvenlik'in kıdemli KIRMIZI TAKIM (red team) operatörüsün. Bug bounty
avcılarının "domain/.env açık" gibi basit bulguları raporladığı ortamda, senin görevin
bu basit bulguları BİLE kaçırmamak VE saldırganın 5 adım sonrasını şimdiden görmek.

# HEDEF
`{target}`

# YÜZEY SNAPSHOT'I (canlı toplanmış veri)
```json
{snapshot_json}
```

# DÜŞÜNCE YÖNTEMİN (bunu uygula, yazdırma)
1. Önce snapshot'taki HER veri parçasını bir saldırganın gözünden oku: bu bilgiyle NE yapılır?
2. Basit bulguları zincirle: açık .env → DB kimliği → veri sızıntısı; .git → kaynak kod →
   hardcoded secret → cloud ele geçirme; eksik header → clickjacking → phishing altyapısı.
3. Savunmacının UNUTTUĞU noktaları ara: subdomain'ler, eski yedek dosyalar, debug uçları,
   varsayılan paneller, teknoloji istifine özgü (server/X-Powered-By) bilinen zafiyetler.
4. Her zincir için SOMUT doğrulama adımı yaz (curl komutu, kontrol edilecek yol vb.).

# YANIT FORMATI (kesinlikle bu yapıda, Türkçe)

## Risk Skoru: [0-100]
[Tek paragraf: hedefin genel durumu — en kötü senaryo nedir?]

## 🔴 Kritik Bulgular
1. [Bulgu — kanıtla birlikte (snapshot'taki somut veri)]

## ⚔️ Saldırı Zincirleri (5 Adım Önde) 🔬
1. **[Zincir adı]:** Adım 1 → Adım 2 → Adım 3 → ... (her adımda saldırganın elinde NE olur,
   sonraki adıma NASIL geçer — somut yaz)

## 🕵️ Savunmacının Atladığı Noktalar ve Öneriler
1. [Sektörde çok raporlanan ama az kontrol edilen sınıflar — bu hedefe uyarla]

## ⏭️ Hemen Doğrulanacaklar ve Sonraki Adımlar
1. `[çalıştırılacak komut veya kontrol]` — [neden]

KURALLAR:
- Snapshot'ta OLMAYAN bulguyu uydurma; "doğrulanmalı" olarak işaretle.
- Her iddiayı snapshot verisine dayandır (URL, header, IP, bulgu).
- Jenerik güvenlik tavsiyesi verme — hedefe özgü, uygulanabilir ol.
Türkçe yanıt ver."""

    return prompt


def build_path_intel_prompt(scan_data: dict) -> str:
    """
    Türkçe: PathProbe LLM İstihbarat Subayı promptu (K2). Hedefin parmak izini (server/tech/
    sürüm/gözlenen yollar) verir; modelden YÜKSEK OLASILIKLI ek hassas yol + BEKLENEN İÇERİK
    İMZASI ister. Kritik: çıktı YALNIZ JSON dizisi olmalı (orchestrator deterministik parse eder;
    prosa çıktı elenir). Model 'bulgu' demez, yalnız ADAY üretir — yargı orchestrator'da.
    """
    fp = scan_data.get("path_intel_fingerprint", scan_data)
    fp_json = json.dumps(fp, indent=2, ensure_ascii=False, default=str)[:4000]

    prompt = f"""Sen bir web güvenlik keşif uzmanısın. Aşağıdaki HEDEF PARMAK İZİNE göre, bu
teknoloji istifinde en sık İFŞA olan hassas dosya/dizin yollarını (config, yedek, log, debug,
kimlik, VCS) tahmin et. Amaç: statik listelerin kaçırdığı, HEDEFE ÖZGÜ yüksek-isabetli yolları
önermek.

# HEDEF PARMAK İZİ
```json
{fp_json}
```

# GÖREV
En olası 15-25 hassas yolu öner. Her yol için, o dosya AÇIKSA yanıt gövdesinde bulunması
BEKLENEN benzersiz imzayı da ver (böylece deterministik doğrulanabilir). Genel/jenerik yol
verme (örn. /admin) — teknolojiye özgü, spesifik dosyalar ver.

# ÇIKTI (YALNIZCA JSON DİZİSİ — başka HİÇBİR metin, açıklama, markdown yok)
[
  {{
    "path": "/mutlak/yol",
    "category": "env_exposure|credential_exposure|vcs_exposure|backup_exposure|db_dump|config_exposure|log_exposure|debug_exposure|admin_panel|info_disclosure",
    "severity": "critical|high|medium|low|info",
    "signature": {{
      "must_contain_any": ["dosya AÇIKSA gövdede olması beklenen ayırt edici token(lar)"],
      "must_not_contain": ["<html", "<!doctype"],
      "min_length": 10
    }}
  }}
]

KURALLAR:
- path DAİMA '/' ile başlar, tam URL/host verme (aynı host varsayılır).
- signature.must_contain_any DOLU olmalı (doğrulanamayan öneri işe yaramaz).
- Yanıtın TAMAMI geçerli tek bir JSON dizisi olmalı. Kod bloğu işareti (```) KOYMA."""

    return prompt


def build_adaptive_payloads_prompt(scan_data: dict) -> str:
    """
    Türkçe: T3-A adaptif payload zanaatı promptu. Orchestrator bir enjeksiyon noktasının
    CANLI bağlamını (baseline/bloklanan yanıt snippet'i, WAF, framework, yansıma bağlamı)
    verir; modelden o hedefe/WAF'a ÖZGÜ payload'lar ister. Kritik: model 'bulgu' demez —
    yalnız DENENECEK payload üretir; deterministik imza (SLEEP/marker/dosya/aritmetik)
    orchestrator'da ONAYLAR. Çıktı YALNIZ JSON string dizisi olmalı.

    Payload'lar sınıfın PLACEHOLDER'ını taşımak ZORUNDA (orchestrator deterministik ölçüm
    için doldurur) — bu aynı zamanda tahribatsızlığı yapısal olarak garanti eder:
      sqli → {D} (SLEEP gecikmesi, saniye)   xss → {MARKER} (yansıma nonce'u)
      ssti → {A} ve {B} (aritmetik çarpım)    lfi → passwd/win.ini/php://filter kanaryası
    """
    ctx = scan_data.get("adaptive_payload_context", scan_data)
    vuln_class = str(ctx.get("vuln_class") or "")
    ctx_json = json.dumps(ctx, indent=2, ensure_ascii=False, default=str)[:4000]

    ph = {
        "sqli": "Her payload '{D}' içermeli (SLEEP/pg_sleep/WAITFOR/BENCHMARK gecikmesi; "
                "orchestrator {D}'yi saniyeyle doldurup zamanlar). Sadece ZAMAN-TABANLI; "
                "veri değiştiren (DROP/DELETE/UPDATE/OUTFILE) payload YASAK.",
        "xss": "Her payload '{MARKER}' içermeli (orchestrator benzersiz nonce ile doldurur ve "
               "yanıtta HAM/escape-siz yansımasını arar). Bağlama uygun breakout üret "
               "(attribute/script/HTML). Zararsız yansıma yeterli.",
        "ssti": "Her payload '{A}' ve '{B}' içermeli (orchestrator asal sayılarla doldurup "
                "çarpımın HESAPLANMIŞ yansımasını arar). Şablon motoruna göre sözdizimi üret "
                "(Jinja2/Twig/FreeMarker/ERB...).",
        "lfi": "Her payload bilinen zararsız kanaryayı hedeflemeli: /etc/passwd, win.ini veya "
               "php://filter (kaynak kod base64). Rastgele hassas dosya OKUMA.",
    }.get(vuln_class, "Sınıfa uygun, TAHRİBATSIZ (oku/zamanla/yansıt) payload üret.")

    return f"""Sen ofansif bir güvenlik uzmanısın (yetkili pentest). Aşağıdaki CANLI enjeksiyon
bağlamına göre, '{vuln_class}' sınıfı için hedefe/WAF'a/framework'e ÖZGÜ payload'lar zanaatla.
Statik listeler ve jenerik WAF-bypass'lar zaten DENENDİ ve başarısız oldu — sen baseline ile
bloklanan yanıt farkını okuyup bir sonraki denemeyi UYARLA (insan pentester gibi).

# CANLI ENJEKSİYON BAĞLAMI
```json
{ctx_json}
```

# GÖREV
'{vuln_class}' için 8-12 aday payload üret. {ph}

# ÇIKTI (YALNIZCA JSON STRING DİZİSİ — başka HİÇBİR metin/açıklama/markdown yok)
["payload1", "payload2", "..."]

KURALLAR:
- Yalnız TAHRİBATSIZ payload (oku/zamanla/yansıt). Veri silen/değiştiren, komut çalıştıran,
  dosya yazan, dış ağa istek atan payload ÜRETME (reddedilir).
- Bağlamda 'corpus_examples' varsa: bu sınıfın BİLİNEN formatlarıdır ve bu noktada
  büyük olasılıkla DENENMİŞ/başarısız olmuştur — kütüphane gibi kullan, bağlama (WAF/
  framework/yansıma) ÖZGÜ uyarla; BİREBİR KOPYA üretme (aynı payload'ı tekrar denemek
  israf).
- Yukarıdaki placeholder kuralına UY (yoksa payload orchestrator'da elenir).
- Yanıtın TAMAMI geçerli tek bir JSON string dizisi olmalı. Kod bloğu işareti (```) KOYMA."""


def build_vulnerability_analysis_prompt(scan_data: dict) -> str:
    """Türkçe: Zafiyet listesi analizi için prompt"""
    
    vulnerabilities = scan_data.get("vulnerabilities", [])
    
    prompt = f"""Sen bir zafiyet yönetimi uzmanısın. Aşağıdaki zafiyet listesini analiz et.

# ZAFİYET LİSTESİ

**Toplam Zafiyet:** {len(vulnerabilities)}

```json
{json.dumps(vulnerabilities[:20], indent=2, ensure_ascii=False, default=str)}
```

# ANALİZ GÖREVLERİ

1. Zafiyetleri öncelik sırasına göre sırala
2. En kritik zafiyetleri açıkla
3. Remediation planı öner
4. Patch yönetimi stratejisi öner

# YANIT FORMATI

## Risk Skoru: [X/100]
[Genel değerlendirme]

## 🔴 Kritik Bulgular
1. [En önemli zafiyet]

## 💡 Öneriler
1. [Öneri]

## 🔬 Teknik Analiz & Deliller
1. **CVE-XXXX-XXXX** - [Zafiyet Adı]
   - Etkilenen versiyon: [X.X.X]
   - CVSS Skoru: [X.X]
   - PoC: `[Test komutu]`

## ⏭️ Sonraki Adımlar
- [Aksiyon]

Türkçe yanıt ver."""

    return prompt


# ============== AI Providers ==============

async def analyze_with_ollama(scan_data: dict, model: str, analysis_type: str) -> AnalysisResponse:
    """
    Türkçe: Ollama ile tarama analizi
    
    v2.0: Chat history başlatma ve context-aware analiz
    """
    
    scan_id = scan_data.get("scan_id", "unknown")
    target = scan_data.get("target", scan_data.get("domain", "unknown"))
    
    # Yeni konuşma başlat veya mevcut olanı kullan
    conv = get_conversation(scan_id)
    if conv is None:
        conv = create_conversation(scan_id, target)
    
    prompt = build_security_prompt(scan_data, analysis_type)
    
    # System context ekle
    system_context = build_system_context(scan_data, analysis_type)
    
    async with httpx.AsyncClient(timeout=240.0) as client:
        try:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "system": system_context,  # System prompt ekle
                    "stream": False,
                    "options": {
                        "temperature": 0.2,  # Daha tutarlı yanıtlar
                        "top_p": 0.9,
                        "num_predict": 4096,  # Daha uzun yanıt
                        "num_ctx": 8192  # Context window artır
                    }
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=502, 
                    detail=f"Ollama error: {response.text}"
                )
            
            result = response.json()
            analysis_text = result.get("response", "")
            
            # Yanıtı parse et
            parsed = parse_ai_response(analysis_text)
            
            # Chat history'ye kaydet
            add_message(scan_id, "assistant", analysis_text, {
                "model": model,
                "provider": "ollama",
                "type": "initial_analysis"
            })
            
            # Risk score güncelle
            if parsed.get("risk_score"):
                update_analysis_state(scan_id, parsed["risk_score"])
            
            # Conversation bilgisi ekle
            conv_summary = get_conversation_summary(scan_id)
            
            return AnalysisResponse(
                provider="ollama",
                model=model,
                analysis=analysis_text,
                conversation_id=scan_id,
                message_count=conv_summary.get("message_count", 1),
                **parsed
            )
            
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504, 
                detail="Ollama timeout - model çok yavaş yanıt verdi. Daha küçük bir model deneyin."
            )
        except httpx.ConnectError:
            raise HTTPException(
                status_code=503, 
                detail="Ollama'ya bağlanılamadı. Mac'te 'ollama serve' çalışıyor mu?"
            )


async def analyze_with_deepseek(scan_data: dict, model: str, analysis_type: str) -> AnalysisResponse:
    """
    Türkçe: DeepSeek (OpenAI-uyumlu bulut) ile tarama analizi.

    Otonom motorun _appraise_deepseek deseniyle aynı çağrı biçimi (/chat/completions,
    Authorization: Bearer). Local-güvenli değil (veri bulut sunucuya gider) ama Claude/Gemini'ye
    göre ucuz/hızlı bir OpenAI-uyumlu alternatif. Anahtar yoksa net hata verir.
    """
    if not DEEPSEEK_API_KEY:
        raise HTTPException(
            status_code=400,
            detail="DEEPSEEK_API_KEY tanımlı değil. .env dosyasına DEEPSEEK_API_KEY=sk-... ekleyin."
        )

    scan_id = scan_data.get("scan_id", "unknown")
    target = scan_data.get("target", scan_data.get("domain", "unknown"))
    conv = get_conversation(scan_id)
    if conv is None:
        conv = create_conversation(scan_id, target)

    prompt = build_security_prompt(scan_data, analysis_type)
    system_context = build_system_context(scan_data, analysis_type)
    use_model = model or DEEPSEEK_MODEL

    async with httpx.AsyncClient(timeout=240.0) as client:
        try:
            response = await client.post(
                f"{DEEPSEEK_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": use_model,
                    "messages": [
                        {"role": "system", "content": system_context},
                        {"role": "user", "content": prompt},
                    ],
                    "stream": False,
                    "temperature": 0.2,
                    "max_tokens": 4096,
                    # DeepSeek v4'te thinking varsayılan AÇIK: CoT reasoning_content'e akıp
                    # max_tokens'i tüketir, content boş/truncated döner → boş analiz veya
                    # düşünce metni analiz diye kaydedilir (tutarsız sonuç). Analiz çıktısı
                    # doğrudan istenir; temperature da ancak non-thinking modda geçerlidir.
                    "thinking": {"type": "disabled"},
                },
            )

            if response.status_code != 200:
                if response.status_code in (401, 403):
                    raise HTTPException(status_code=502, detail="DeepSeek API anahtarı geçersiz (401/403). .env → DEEPSEEK_API_KEY yenileyin.")
                raise HTTPException(status_code=502, detail=f"DeepSeek error: {response.text}")

            choices = response.json().get("choices", []) or []
            msg = choices[0].get("message", {}) if choices else {}
            # DeepSeek reasoner tarzı modellerde asıl yanıt `content` yerine boş gelip
            # `reasoning_content`'e düşebilir; content boşsa oraya bak (boş analiz olmasın).
            analysis_text = (msg.get("content") or "").strip() or (msg.get("reasoning_content") or "").strip()

            # CVE GROUNDING: modelin, taramanın kanıtında OLMAYAN CVE uydurmasını ⚠️ ile işaretle.
            analysis_text, _ung = ground_cves_in_narrative(analysis_text, scan_data)
            if _ung:
                print(f"⚠️ [deepseek] {len(_ung)} grounded-olmayan CVE işaretlendi: {_ung}")

            parsed = parse_ai_response(analysis_text)
            add_message(scan_id, "assistant", analysis_text, {
                "model": use_model, "provider": "deepseek", "type": "initial_analysis"
            })
            if parsed.get("risk_score"):
                update_analysis_state(scan_id, parsed["risk_score"])
            conv_summary = get_conversation_summary(scan_id)

            return AnalysisResponse(
                provider="deepseek",
                model=use_model,
                analysis=analysis_text,
                conversation_id=scan_id,
                message_count=conv_summary.get("message_count", 1),
                **parsed
            )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="DeepSeek timeout - yanıt çok uzun sürdü.")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="DeepSeek'e bağlanılamadı. .env'deki DEEPSEEK_BASE_URL doğru mu?")
        except HTTPException:
            raise
        except Exception as e:
            # Geçersiz JSON yanıt vb. — ollama yolundaki gibi net 5xx ver, opak hata sızdırma.
            raise HTTPException(status_code=500, detail=f"DeepSeek analiz hatası: {e}")


async def process_chat_deepseek(prompt: str, model: str, scan_id: str = "unknown") -> AnalysisResponse:
    """Türkçe: DeepSeek ile chat işleme (OpenAI-uyumlu /chat/completions)."""
    if not DEEPSEEK_API_KEY:
        raise HTTPException(status_code=400, detail="DEEPSEEK_API_KEY tanımlı değil.")
    use_model = model or DEEPSEEK_MODEL
    async with httpx.AsyncClient(timeout=240.0) as client:
        try:
            response = await client.post(
                f"{DEEPSEEK_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": use_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "temperature": 0.3,
                    "max_tokens": 4096,
                    # thinking kapalı: v4'te varsayılan açık — CoT token bütçesini yiyip
                    # content'i boş bırakıyordu (bkz. analyze_with_deepseek notu).
                    "thinking": {"type": "disabled"},
                },
            )
            if response.status_code != 200:
                if response.status_code in (401, 403):
                    raise HTTPException(status_code=502, detail="DeepSeek API anahtarı geçersiz (401/403). .env → DEEPSEEK_API_KEY yenileyin.")
                raise HTTPException(status_code=502, detail=f"DeepSeek error: {response.text}")
            choices = response.json().get("choices", []) or []
            msg = choices[0].get("message", {}) if choices else {}
            # content boşsa reasoner çıktısı reasoning_content'te olabilir (bkz. analyze_with_deepseek).
            analysis_text = (msg.get("content") or "").strip() or (msg.get("reasoning_content") or "").strip()

            clean_text = analysis_text
            try:
                json_match = re.search(r'```json\s*(.*?)\s*```', analysis_text, re.DOTALL)
                if json_match:
                    parsed_json = json.loads(json_match.group(1))
                    if "analysis" in parsed_json:
                        clean_text = parsed_json["analysis"]
                else:
                    try:
                        parsed_json = json.loads(analysis_text)
                        if "analysis" in parsed_json:
                            clean_text = parsed_json["analysis"]
                    except Exception:
                        pass
            except Exception:
                pass

            parsed = parse_ai_response(analysis_text)
            add_message(scan_id, "assistant", clean_text, {
                "model": use_model, "provider": "deepseek", "type": "chat_response"
            })
            if parsed.get("risk_score"):
                update_analysis_state(scan_id, parsed["risk_score"])
            conv_summary = get_conversation_summary(scan_id)

            return AnalysisResponse(
                provider="deepseek",
                model=use_model,
                analysis=clean_text,
                conversation_id=scan_id,
                message_count=conv_summary.get("message_count", 0),
                **parsed
            )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="DeepSeek timeout.")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="DeepSeek'e bağlanılamadı.")
        except HTTPException:
            raise
        except Exception as e:
            # Geçersiz JSON yanıt vb. — process_chat_ollama ile tutarlı net 5xx.
            raise HTTPException(status_code=500, detail=f"DeepSeek chat hatası: {e}")


async def analyze_with_claude(scan_data: dict, model: str, analysis_type: str) -> AnalysisResponse:
    """
    Türkçe: Claude API ile tarama analizi
    
    v2.0: Chat history başlatma ve context-aware analiz
    
    Desteklenen Claude modelleri (2025):
    - claude-sonnet-4-20250514: En yeni Sonnet 4
    - claude-opus-4-20250514: En güçlü model
    - claude-3-7-sonnet-20250219: Claude 3.7 Sonnet (hybrid reasoning)
    - claude-3-5-sonnet-latest: Claude 3.5 Sonnet alias
    - claude-3-5-haiku-latest: Claude 3.5 Haiku (hızlı)
    """
    
    if not CLAUDE_API_KEY:
        raise HTTPException(
            status_code=400, 
            detail="CLAUDE_API_KEY tanımlı değil. .env dosyasına CLAUDE_API_KEY=sk-ant-... ekleyin."
        )
    
    # Geçerli Claude model listesi (2025 güncel)
    VALID_CLAUDE_MODELS = [
        "claude-sonnet-4-20250514",
        "claude-opus-4-20250514", 
        "claude-3-7-sonnet-20250219",
        "claude-3-5-sonnet-latest",
        "claude-3-5-haiku-latest",
        # Eski model alias'ları (backward compatibility)
        "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku-20241022",
    ]
    
    # Model adını validate et ve gerekirse düzelt
    original_model = model
    if model not in VALID_CLAUDE_MODELS:
        # Eski model adlarını yeni alias'lara yönlendir
        model_mapping = {
            "claude-3-5-sonnet-20241022": "claude-3-5-sonnet-latest",
            "claude-3-5-haiku-20241022": "claude-3-5-haiku-latest",
            "claude-3-sonnet": "claude-3-5-sonnet-latest",
            "claude-3-opus": "claude-opus-4-20250514",
        }
        if model in model_mapping:
            model = model_mapping[model]
            print(f"⚠️ Model yönlendirmesi: {original_model} → {model}")
        else:
            # Varsayılan olarak en stabil modeli kullan
            model = "claude-3-5-sonnet-latest"
            print(f"⚠️ Bilinmeyen model '{original_model}', varsayılan kullanılıyor: {model}")
    
    from anthropic import Anthropic, APIError, NotFoundError, AuthenticationError
    
    scan_id = scan_data.get("scan_id", "unknown")
    target = scan_data.get("target", scan_data.get("domain", "unknown"))
    
    # Yeni konuşma başlat veya mevcut olanı kullan
    conv = get_conversation(scan_id)
    if conv is None:
        conv = create_conversation(scan_id, target)
    
    client = Anthropic(api_key=CLAUDE_API_KEY)
    prompt = build_security_prompt(scan_data, analysis_type)
    system_context = build_system_context(scan_data, analysis_type)
    
    # Debug: Prompt boyutunu logla
    print(f"📊 Claude'a gönderilen prompt boyutu: {len(prompt)} karakter")
    print(f"📊 System context boyutu: {len(system_context)} karakter")
    print(f"🎯 Analiz tipi: {analysis_type}")
    print(f"🔍 Hedef: {target}")
    
    try:
        message = client.messages.create(
            model=model,
            max_tokens=8192,  # Daha uzun yanıt
            temperature=0.2,  # Daha tutarlı
            system=system_context,  # System prompt ekle
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        
        analysis_text = message.content[0].text
        # CVE GROUNDING (bkz. analyze_with_deepseek): uydurma CVE'yi işaretle.
        analysis_text, _ung = ground_cves_in_narrative(analysis_text, scan_data)
        if _ung:
            print(f"⚠️ [claude] {len(_ung)} grounded-olmayan CVE işaretlendi: {_ung}")
        parsed = parse_ai_response(analysis_text)

        # Chat history'ye kaydet
        add_message(scan_id, "assistant", analysis_text, {
            "model": model,
            "provider": "claude",
            "type": "initial_analysis"
        })
        
        # Risk score güncelle
        if parsed.get("risk_score"):
            update_analysis_state(scan_id, parsed["risk_score"])
        
        # Conversation bilgisi ekle
        conv_summary = get_conversation_summary(scan_id)
        
        return AnalysisResponse(
            provider="claude",
            model=model,
            analysis=analysis_text,
            conversation_id=scan_id,
            message_count=conv_summary.get("message_count", 1),
            **parsed
        )
    
    except NotFoundError as e:
        # Model bulunamadı hatası - detaylı mesaj
        raise HTTPException(
            status_code=404, 
            detail=f"Claude model bulunamadı: '{original_model}'. Geçerli modeller: claude-sonnet-4-20250514, claude-3-5-sonnet-latest, claude-3-5-haiku-latest"
        )
    
    except AuthenticationError as e:
        # API key hatası
        raise HTTPException(
            status_code=401, 
            detail="Claude API key geçersiz. .env dosyasındaki CLAUDE_API_KEY değerini kontrol edin."
        )
    
    except APIError as e:
        # Genel API hatası
        raise HTTPException(
            status_code=502, 
            detail=f"Claude API hatası: {str(e)}"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Claude API error: {str(e)}"
        )


async def analyze_with_gemini(scan_data: dict, model: str, analysis_type: str) -> AnalysisResponse:
    """
    Türkçe: Google Gemini API ile tarama analizi
    
    v3.1: TOON Token Optimizasyonu + Güncel Model Listesi
    
    Desteklenen Gemini modelleri (2026 Güncel):
    - gemini-2.0-flash: GA model (stabil, hızlı)
    - gemini-2.0-flash-lite: Hafif ve ucuz
    - gemini-1.5-pro: 1M context window
    - gemini-1.5-flash: Hızlı günlük kullanım
    """
    
    if not GEMINI_API_KEY:
        raise HTTPException(
            status_code=400, 
            detail="GEMINI_API_KEY tanımlı değil. Dashboard → AI Settings → Gemini API Key girin."
        )
    
    # Model validasyonu - merkezi config kullan
    original_model = model
    model, was_changed = validate_gemini_model(model)
    if was_changed:
        print(f"⚠️ Gemini model yönlendirmesi: {original_model} → {model}")
    
    import google.generativeai as genai
    
    scan_id = scan_data.get("scan_id", "unknown")
    target = scan_data.get("target", scan_data.get("domain", "unknown"))
    
    # Yeni konuşma başlat veya mevcut olanı kullan
    conv = get_conversation(scan_id)
    if conv is None:
        conv = create_conversation(scan_id, target)
    
    # API key ayarla
    genai.configure(api_key=GEMINI_API_KEY)
    
    # 🔥 TOON Token Optimizasyonu - Gemini için de aktif
    if TOON_AVAILABLE:
        try:
            # Token tasarrufunu hesapla ve logla
            savings = estimate_token_savings(scan_data)
            print(f"💰 TOON Token Tasarrufu: %{savings['savings_percent']} (~{savings['estimated_tokens_saved']} token)")
            
            # Kompakt veri ile prompt oluştur
            compressed_data = compress_scan_data(scan_data)
            prompt = build_security_prompt({"toon_data": compressed_data, **scan_data}, analysis_type)
        except Exception as e:
            print(f"⚠️ TOON compression failed, using raw data: {e}")
            prompt = build_security_prompt(scan_data, analysis_type)
    else:
        prompt = build_security_prompt(scan_data, analysis_type)
    
    system_context = build_system_context(scan_data, analysis_type)
    
    # Debug: Prompt boyutunu logla
    print(f"📊 Gemini'ye gönderilen prompt boyutu: {len(prompt)} karakter")
    print(f"📊 System context boyutu: {len(system_context)} karakter")
    print(f"🎯 Analiz tipi: {analysis_type}")
    print(f"🔍 Hedef: {target}")
    print(f"✨ Model: {model}")
    
    try:
        # Gemini model oluştur
        gemini_model = genai.GenerativeModel(
            model_name=model,
            system_instruction=system_context,
            generation_config=genai.GenerationConfig(
                temperature=0.2,  # Tutarlı yanıtlar
                top_p=0.9,
                max_output_tokens=8192,
            )
        )
        
        # Analiz yap
        response = gemini_model.generate_content(prompt)
        
        # Yanıt kontrolü
        if not response.text:
            raise HTTPException(
                status_code=502,
                detail="Gemini boş yanıt döndürdü. Farklı bir model deneyin."
            )
        
        analysis_text = response.text
        # CVE GROUNDING (bkz. analyze_with_deepseek): uydurma CVE'yi işaretle.
        analysis_text, _ung = ground_cves_in_narrative(analysis_text, scan_data)
        if _ung:
            print(f"⚠️ [gemini] {len(_ung)} grounded-olmayan CVE işaretlendi: {_ung}")
        parsed = parse_ai_response(analysis_text)

        # Chat history'ye kaydet
        add_message(scan_id, "assistant", analysis_text, {
            "model": model,
            "provider": "gemini",
            "type": "initial_analysis",
            "toon_optimized": TOON_AVAILABLE
        })
        
        # Risk score güncelle
        if parsed.get("risk_score"):
            update_analysis_state(scan_id, parsed["risk_score"])
        
        # Conversation bilgisi ekle
        conv_summary = get_conversation_summary(scan_id)
        
        print(f"✅ Gemini analizi tamamlandı ({model})")
        
        return AnalysisResponse(
            provider="gemini",
            model=model,
            analysis=analysis_text,
            conversation_id=scan_id,
            message_count=conv_summary.get("message_count", 1),
            **parsed
        )
    
    except Exception as e:
        error_msg = str(e).lower()
        original_error = str(e)
        
        print(f"❌ Gemini API hatası: {original_error}")
        
        # 404 hatası - Model bulunamadı
        if "404" in original_error or "not found" in error_msg:
            valid_models_str = ", ".join(VALID_GEMINI_MODELS[:5]) + "..."
            raise HTTPException(
                status_code=404, 
                detail=f"Gemini model bulunamadı: '{original_model}'. Model adını kontrol edin. Geçerli modeller: {valid_models_str}"
            )
        
        # API key hatası
        if "api_key" in error_msg or "authentication" in error_msg or "invalid" in error_msg:
            raise HTTPException(
                status_code=401, 
                detail="Gemini API key geçersiz. Dashboard → AI Settings → API Key'i kontrol edin."
            )
        
        # Quota/Rate limit hatası
        if "quota" in error_msg or "rate" in error_msg or "limit" in error_msg or "resource" in error_msg:
            raise HTTPException(
                status_code=429, 
                detail="Gemini API kotası aşıldı. Biraz bekleyin veya farklı provider (Ollama/Claude) deneyin."
            )
        
        # Permission hatası
        if "permission" in error_msg or "403" in original_error:
            raise HTTPException(
                status_code=403, 
                detail="Gemini API erişim izni yok. Google Cloud Console'da API'yi etkinleştirdiğinizden emin olun."
            )
        
        # Genel hata - orijinal mesajı göster
        raise HTTPException(
            status_code=500, 
            detail=f"Gemini API error: {original_error}"
        )


def parse_ai_response(text: str) -> dict:
    """Türkçe: AI yanıtından yapılandırılmış veri çıkar"""
    
    result = {
        "risk_score": None,
        "recommendations": [],
        "critical_findings": [],
        "technical_details": [],
        "next_steps": []
    }
    
    # Risk skoru çıkar
    risk_match = re.search(r'[Rr]isk\s*[Ss]koru[:\s]*(\d+)', text)
    if risk_match:
        result["risk_score"] = min(100, int(risk_match.group(1)))
    else:
        # Alternatif format
        risk_match = re.search(r'(\d+)/100', text)
        if risk_match:
            result["risk_score"] = min(100, int(risk_match.group(1)))
    
    # Bölümleri parse et
    lines = text.split('\n')
    current_section = None
    
    for line in lines:
        line = line.strip()
        
        # Bölüm başlıkları
        if "kritik bulgu" in line.lower() or "🔴" in line:
            current_section = "findings"
            continue
        elif "öneri" in line.lower() or "💡" in line:
            current_section = "recommendations"
            continue
        elif "teknik analiz" in line.lower() or "🔬" in line or "delil" in line.lower():
            current_section = "technical"
            continue
        elif "sonraki adım" in line.lower() or "⏭️" in line or "hemen yapılması" in line.lower():
            current_section = "next_steps"
            continue
        
        # Liste elemanı mı?
        if re.match(r'^[\d\-\*\•]+\.?\s', line):
            cleaned = re.sub(r'^[\d\-\*\•]+\.?\s*', '', line).strip()
            if cleaned and len(cleaned) > 5:
                if current_section == "findings":
                    result["critical_findings"].append(cleaned)
                elif current_section == "recommendations":
                    result["recommendations"].append(cleaned)
                elif current_section == "technical":
                    result["technical_details"].append(cleaned)
                elif current_section == "next_steps":
                    result["next_steps"].append(cleaned)
    
    return result


# ============== API Endpoints ==============

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_scan(request: AnalysisRequest):
    """
    Türkçe: Tarama sonuçlarını AI ile analiz et
    
    - **ollama**: Local Ollama (hızlı, ücretsiz, offline)
    - **claude**: Claude API (güçlü, ücretli, online)
    - **gemini**: Google Gemini API (1M context, hızlı, multimodal)
    """
    
    # Rate limit check
    identifier = request.scan_data.get("scan_id", "anonymous")
    check_rate_limit(identifier)

    # Provider/model'i .env (TEK doğruluk kaynağı) ışığında çöz.
    provider, model = resolve_provider_model(request.provider, request.model, request.use_default)

    if provider == "ollama":
        return await analyze_with_ollama(request.scan_data, model, request.analysis_type)
    elif provider == "deepseek":
        return await analyze_with_deepseek(request.scan_data, model, request.analysis_type)
    elif provider == "claude":
        return await analyze_with_claude(request.scan_data, model, request.analysis_type)
    elif provider == "gemini":
        return await analyze_with_gemini(request.scan_data, model, request.analysis_type)
    else:
        raise HTTPException(status_code=400, detail="Geçersiz provider. Desteklenen: ollama, deepseek, claude, gemini")


class ChatRequest(BaseModel):
    scan_data: dict
    current_analysis: dict
    user_message: str
    provider: Literal["ollama", "deepseek", "claude", "gemini"] = "ollama"
    model: str = "mistral:7b"
    analysis_type: str = "security"
    conversation_history: Optional[List[Dict[str, str]]] = None  # Opsiyonel geçmiş
    use_default: bool = False  # True → provider/model varsayılandan (DB > .env) gelir


@app.post("/chat", response_model=AnalysisResponse)
async def chat_with_ai(request: ChatRequest):
    """
    Türkçe: Mevcut analiz üzerine sohbet et ve raporu güncelle
    
    v2.0 Güncellemeler:
    - Konuşma geçmişi korunur (chat history)
    - Context-aware yanıtlar
    - Sliding window ile son N mesaj AI'a gönderilir
    """
    scan_id = request.scan_data.get("scan_id", "unknown")
    identifier = scan_id
    check_rate_limit(identifier)
    
    # Kullanıcı mesajını chat history'ye ekle
    add_message(scan_id, "user", request.user_message)
    
    # Konuşma geçmişini al (sliding window)
    conversation_history = request.conversation_history or get_context_messages(scan_id)
    
    # Geliştirilmiş prompt oluştur
    prompt = build_enhanced_chat_prompt(
        request.scan_data, 
        request.current_analysis, 
        request.user_message,
        conversation_history
    )
    
    # Provider/model'i .env (TEK doğruluk kaynağı) ışığında çöz.
    provider, model = resolve_provider_model(request.provider, request.model, request.use_default)

    # Provider'a göre istek gönder
    if provider == "ollama":
        return await process_chat_ollama(prompt, model, scan_id)
    elif provider == "deepseek":
        return await process_chat_deepseek(prompt, model, scan_id)
    elif provider == "claude":
        return await process_chat_claude(prompt, model, scan_id)
    elif provider == "gemini":
        return await process_chat_gemini(prompt, model, scan_id)
    else:
        raise HTTPException(status_code=400, detail="Geçersiz provider. Desteklenen: ollama, deepseek, claude, gemini")


def build_chat_prompt(scan_data: dict, current_analysis: dict, user_message: str) -> str:
    """
    Türkçe: Chat güncellemesi için prompt oluştur
    
    v2.0: Geliştirilmiş prompt builder modülünü kullanır
    """
    # Yeni modülü kullan (conversation_history olmadan basit versiyon)
    return build_enhanced_chat_prompt(scan_data, current_analysis, user_message, None)


async def process_chat_ollama(prompt: str, model: str, scan_id: str = "unknown") -> AnalysisResponse:
    """
    Türkçe: Ollama ile chat işleme
    
    v2.0: Chat history entegrasyonu
    """
    async with httpx.AsyncClient(timeout=240.0) as client:
        try:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # Chat'te biraz daha esnek
                        "num_predict": 4096,
                        "num_ctx": 8192
                    }
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Ollama error: {response.text}")
            
            result = response.json()
            analysis_text = result.get("response", "")
            
            # JSON bloğu içinden temiz metni çıkar
            clean_text = analysis_text
            try:
                # Markdown JSON bloğunu temizle (```json ... ```)
                json_match = re.search(r'```json\s*(.*?)\s*```', analysis_text, re.DOTALL)
                if json_match:
                    inner_json = json_match.group(1)
                    parsed_json = json.loads(inner_json)
                    if "analysis" in parsed_json:
                        clean_text = parsed_json["analysis"]
                else:
                     # Direkt JSON string olabilir
                    try:
                        parsed_json = json.loads(analysis_text)
                        if "analysis" in parsed_json:
                            clean_text = parsed_json["analysis"]
                    except:
                        pass
            except:
                pass

            parsed = parse_ai_response(analysis_text)
            
            # Chat history'ye AI yanıtını kaydet
            add_message(scan_id, "assistant", clean_text, {
                "model": model,
                "provider": "ollama",
                "type": "chat_response"
            })
            
            # Risk score güncellendiyse state'i güncelle
            if parsed.get("risk_score"):
                update_analysis_state(scan_id, parsed["risk_score"])
            
            # Conversation bilgisi ekle
            conv_summary = get_conversation_summary(scan_id)
            
            return AnalysisResponse(
                provider="ollama",
                model=model,
                analysis=clean_text,
                conversation_id=scan_id,
                message_count=conv_summary.get("message_count", 0),
                **parsed
            )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Ollama timeout - yanıt çok uzun sürdü")
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Ollama'ya bağlanılamadı")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


async def process_chat_claude(prompt: str, model: str, scan_id: str = "unknown") -> AnalysisResponse:
    """
    Türkçe: Claude ile chat işleme
    
    v2.0: Chat history entegrasyonu
    
    Model doğrulama: Eski model adları otomatik olarak güncel alias'lara yönlendirilir
    """
    if not CLAUDE_API_KEY:
        raise HTTPException(status_code=400, detail="CLAUDE_API_KEY eksik. .env dosyasına ekleyin.")
    
    # Model adını validate et ve gerekirse düzelt
    original_model = model
    model_mapping = {
        "claude-3-5-sonnet-20241022": "claude-3-5-sonnet-latest",
        "claude-3-5-haiku-20241022": "claude-3-5-haiku-latest",
    }
    if model in model_mapping:
        model = model_mapping[model]
        print(f"⚠️ Chat model yönlendirmesi: {original_model} → {model}")
        
    from anthropic import Anthropic, APIError, NotFoundError, AuthenticationError
    client = Anthropic(api_key=CLAUDE_API_KEY)
    
    try:
        message = client.messages.create(
            model=model,
            max_tokens=8192,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}]
        )
        
        analysis_text = message.content[0].text
        
        # JSON bloğu içinden temiz metni çıkar
        clean_text = analysis_text
        try:
            json_match = re.search(r'```json\s*(.*?)\s*```', analysis_text, re.DOTALL)
            if json_match:
                inner_json = json_match.group(1)
                parsed_json = json.loads(inner_json)
                if "analysis" in parsed_json:
                    clean_text = parsed_json["analysis"]
            else:
                try:
                    parsed_json = json.loads(analysis_text)
                    if "analysis" in parsed_json:
                        clean_text = parsed_json["analysis"]
                except:
                    pass
        except:
            pass

        parsed = parse_ai_response(analysis_text)
        
        # Chat history'ye AI yanıtını kaydet
        add_message(scan_id, "assistant", clean_text, {
            "model": model,
            "provider": "claude",
            "type": "chat_response"
        })
        
        # Risk score güncellendiyse state'i güncelle
        if parsed.get("risk_score"):
            update_analysis_state(scan_id, parsed["risk_score"])
        
        # Conversation bilgisi ekle
        conv_summary = get_conversation_summary(scan_id)
        
        return AnalysisResponse(
            provider="claude",
            model=model,
            analysis=clean_text,
            conversation_id=scan_id,
            message_count=conv_summary.get("message_count", 0),
            **parsed
        )
    
    except NotFoundError as e:
        raise HTTPException(
            status_code=404, 
            detail=f"Claude model bulunamadı: '{original_model}'. Geçerli modeller: claude-sonnet-4-20250514, claude-3-5-sonnet-latest"
        )
    
    except AuthenticationError as e:
        raise HTTPException(
            status_code=401, 
            detail="Claude API key geçersiz. .env dosyasındaki CLAUDE_API_KEY değerini kontrol edin."
        )
    
    except APIError as e:
        raise HTTPException(
            status_code=502, 
            detail=f"Claude API hatası: {str(e)}"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Claude chat hatası: {str(e)}")


async def process_chat_gemini(prompt: str, model: str, scan_id: str = "unknown") -> AnalysisResponse:
    """
    Türkçe: Gemini ile chat işleme
    
    v3.0: Yeni Gemini chat entegrasyonu
    """
    if not GEMINI_API_KEY:
        raise HTTPException(status_code=400, detail="GEMINI_API_KEY eksik. Dashboard → AI Settings → API Key girin.")
    
    import google.generativeai as genai
    genai.configure(api_key=GEMINI_API_KEY)
    
    # Model validasyonu
    original_model = model
    # Model validasyonu - merkezi config kullan
    model, was_changed = validate_gemini_model(model)
    if was_changed:
        print(f"⚠️ Chat Gemini model yönlendirmesi: {original_model} → {model}")
    
    try:
        gemini_model = genai.GenerativeModel(
            model_name=model,
            generation_config=genai.GenerationConfig(
                temperature=0.3,  # Chat'te biraz daha esnek
                max_output_tokens=8192,
            )
        )
        
        response = gemini_model.generate_content(prompt)
        
        if not response.text:
            raise HTTPException(status_code=502, detail="Gemini boş yanıt döndürdü")
        
        analysis_text = response.text
        
        # JSON bloğu içinden temiz metni çıkar
        clean_text = analysis_text
        try:
            json_match = re.search(r'```json\s*(.*?)\s*```', analysis_text, re.DOTALL)
            if json_match:
                inner_json = json_match.group(1)
                parsed_json = json.loads(inner_json)
                if "analysis" in parsed_json:
                    clean_text = parsed_json["analysis"]
        except:
            pass
        
        parsed = parse_ai_response(analysis_text)
        
        # Chat history'ye AI yanıtını kaydet
        add_message(scan_id, "assistant", clean_text, {
            "model": model,
            "provider": "gemini",
            "type": "chat_response"
        })
        
        # Risk score güncellendiyse state'i güncelle
        if parsed.get("risk_score"):
            update_analysis_state(scan_id, parsed["risk_score"])
        
        # Conversation bilgisi ekle
        conv_summary = get_conversation_summary(scan_id)
        
        return AnalysisResponse(
            provider="gemini",
            model=model,
            analysis=clean_text,
            conversation_id=scan_id,
            message_count=conv_summary.get("message_count", 0),
            **parsed
        )
    
    except Exception as e:
        error_msg = str(e)
        if "API_KEY" in error_msg.upper() or "authentication" in error_msg.lower():
            raise HTTPException(status_code=401, detail="Gemini API key geçersiz.")
        if "quota" in error_msg.lower() or "rate" in error_msg.lower():
            raise HTTPException(status_code=429, detail="Gemini API kotası aşıldı.")
        raise HTTPException(status_code=500, detail=f"Gemini chat hatası: {error_msg}")


@app.get("/health")
async def health():
    """Health check - Ollama, Claude ve Gemini durumunu kontrol et"""
    ollama_status = "unknown"
    ollama_models = []
    
    # Ollama connectivity test
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                ollama_models = [m["name"] for m in models]
                ollama_status = f"connected ({len(models)} models)"
            else:
                ollama_status = "unreachable"
    except httpx.ConnectError:
        ollama_status = "offline"
    except Exception as e:
        ollama_status = f"error: {str(e)}"
    
    # Gemini status check
    gemini_status = "not_configured"
    if GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            # Quick validation test
            gemini_status = "configured"
        except Exception as e:
            gemini_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "providers": {
            "ollama": {
                "status": ollama_status,
                "models": ollama_models[:5],
                "url": OLLAMA_URL
            },
            "claude": {
                "status": "configured" if CLAUDE_API_KEY else "not_configured",
                "api_key_set": bool(CLAUDE_API_KEY)
            },
            "gemini": {
                "status": gemini_status,
                "api_key_set": bool(GEMINI_API_KEY)
            }
        },
        # Backward compatibility
        "ollama": ollama_status,
        "ollama_models": ollama_models[:5],
        "claude": "configured" if CLAUDE_API_KEY else "not_configured",
        "gemini": gemini_status,
        "ollama_url": OLLAMA_URL
    }


@app.get("/models")
async def list_models():
    """
    Türkçe: Kullanılabilir modelleri listele
    
    Model listeleri merkezi ai_config.py dosyasından yönetilir.
    - Claude: Anthropic API geçerli modeller
    - Gemini: Google AI geçerli modeller  
    - Ollama: Dinamik olarak local'den çekilir
    """
    # Merkezi config'den model listelerini al
    models = get_all_models()
    
    # Ollama modellerini dinamik olarak çek
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            if resp.status_code == 200:
                models["ollama"] = [m["name"] for m in resp.json().get("models", [])]
    except:
        pass
    
    return models


# ============== Chat History Endpoints ==============

@app.get("/conversation/{scan_id}")
async def get_conversation_history(scan_id: str):
    """
    Türkçe: Belirli bir tarama için konuşma geçmişini getir
    
    Frontend sayfa yenilendiğinde veya geri geldiğinde
    konuşma geçmişini geri yüklemek için kullanılır.
    """
    conv_data = export_conversation(scan_id)
    
    if conv_data is None:
        return {
            "exists": False,
            "scan_id": scan_id,
            "messages": [],
            "message_count": 0
        }
    
    return {
        "exists": True,
        "scan_id": scan_id,
        "target": conv_data.get("target"),
        "messages": conv_data.get("messages", []),
        "message_count": len(conv_data.get("messages", [])),
        "current_risk_score": conv_data.get("current_risk_score"),
        "analysis_version": conv_data.get("analysis_version", 1),
        "created_at": conv_data.get("created_at"),
        "updated_at": conv_data.get("updated_at")
    }


@app.delete("/conversation/{scan_id}")
async def clear_conversation_history(scan_id: str):
    """
    Türkçe: Konuşma geçmişini temizle (yeni analiz için)
    
    Kullanıcı "Yeniden Analiz" butonuna bastığında çağrılır.
    """
    clear_conversation(scan_id)
    return {
        "success": True,
        "message": f"Konuşma geçmişi temizlendi: {scan_id}"
    }


class ImportConversationRequest(BaseModel):
    """MongoDB'den konuşma import etmek için"""
    conversation_data: Dict[str, Any]


@app.post("/conversation/import")
async def import_conversation_history(request: ImportConversationRequest):
    """
    Türkçe: MongoDB'den konuşma geçmişini import et
    
    Orchestrator, MongoDB'den aldığı konuşma verisini
    AI service'e geri yüklemek için bu endpoint'i kullanır.
    """
    try:
        conv = import_conversation(request.conversation_data)
        return {
            "success": True,
            "scan_id": conv.scan_id,
            "message_count": len(conv.messages),
            "analysis_version": conv.analysis_version
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import hatası: {str(e)}")


@app.get("/conversation/{scan_id}/summary")
async def get_conversation_summary_endpoint(scan_id: str):
    """Türkçe: Konuşma özeti (debugging için)"""
    return get_conversation_summary(scan_id)


@app.get("/")
async def root():
    """API bilgisi"""
    return {
        "service": "Kadim AI Service",
        "version": "2.1.0",
        "features": [
            "Chat History Support",
            "Context-Aware Responses",
            "Enhanced Prompts",
            "Conversation Persistence",
            "TOON Token Optimization" if TOON_AVAILABLE else "TOON (not available)"
        ],
        "toon_enabled": TOON_AVAILABLE,
        "endpoints": {
            "/analyze": "POST - Tarama sonuçlarını AI ile analiz et",
            "/chat": "POST - AI ile sohbet et (context-aware)",
            "/conversation/{scan_id}": "GET - Konuşma geçmişini getir",
            "/conversation/{scan_id}": "DELETE - Konuşma geçmişini temizle",
            "/conversation/import": "POST - Konuşma geçmişini import et",
            "/token-metrics": "POST - Token tasarruf metriklerini hesapla",
            "/health": "GET - Servis ve AI bağlantı durumu",
            "/models": "GET - Kullanılabilir modelleri listele"
        }
    }


# ============== TOON Token Metrics Endpoint ==============

class TokenMetricsRequest(BaseModel):
    scan_data: dict


@app.post("/token-metrics")
async def calculate_token_metrics(request: TokenMetricsRequest):
    """
    Türkçe: TOON vs JSON token tasarrufunu hesapla
    
    Bu endpoint, tarama verisi için TOON formatinin
    sağlayacağı token tasarrufunu gösterir.
    """
    if not TOON_AVAILABLE:
        return {
            "toon_available": False,
            "message": "TOON serializer yüklü değil"
        }
    
    try:
        savings = estimate_token_savings(request.scan_data)
        toon_output = compress_scan_data(request.scan_data)
        
        return {
            "toon_available": True,
            "json_chars": savings["json_chars"],
            "toon_chars": savings["toon_chars"],
            "savings_percent": savings["savings_percent"],
            "estimated_tokens_saved": savings["estimated_tokens_saved"],
            "toon_preview": toon_output[:500] + "..." if len(toon_output) > 500 else toon_output
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token metrikleri hesaplanamadı: {str(e)}")


@app.post("/analyze/stream")
async def analyze_scan_stream(request: AnalysisRequest):
    """
    Türkçe: Streaming AI analizi (deneysel)
    
    Yanit parça parça gelir, daha iyi kullanıcı deneyimi sağlar.
    """
    # TODO: Implement streaming for Ollama and Claude
    # Placeholder for Phase 2
    return {
        "status": "not_implemented",
        "message": "Streaming analiz Faz 2'de eklenecek"
    }


# ============== Multi-Agent System Endpoints ==============

class MultiAgentRequest(BaseModel):
    scan_id: str
    scan_data: dict
    provider: Literal["ollama", "claude"] = "ollama"
    model: str = "mistral:7b"


@app.post("/agents/analyze")
async def multi_agent_analyze(request: MultiAgentRequest):
    """
    Türkçe: Multi-agent güvenlik analizi
    
    Bu endpoint:
    1. OrchestratorAgent'ı başlatır
    2. ReconAgent ve VulnScannerAgent'ları koordine eder
    3. Birleştirilmiş analiz sonucu döner
    
    Avantajlar:
    - Paralel işleme
    - Uzmanlaşmış analiz
    - Kapsamlı rapor
    """
    if not AGENTS_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Multi-Agent System kullanılamıyor. agents/ modülünü kontrol edin."
        )
    
    # Rate limit
    check_rate_limit(request.scan_id)
    
    try:
        target = request.scan_data.get("target", request.scan_data.get("domain", "unknown"))
        
        result = await run_multi_agent_analysis(
            scan_id=request.scan_id,
            target=target,
            scan_data=request.scan_data,
            ai_provider=request.provider,
            model=request.model
        )
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Multi-agent analiz hatası: {str(e)}")


@app.get("/agents/status")
async def get_agents_status():
    """
    Türkçe: Tüm ajanların durumunu getir
    """
    if not AGENTS_AVAILABLE:
        return {
            "available": False,
            "message": "Multi-Agent System yüklenmedi"
        }
    
    registry = get_registry()
    return {
        "available": True,
        **registry.get_status()
    }


@app.post("/agents/init")
async def initialize_agents(
    provider: Literal["ollama", "claude"] = "ollama",
    model: str = "mistral:7b"
):
    """
    Türkçe: Ajanları başlat veya yeniden yükle
    """
    if not AGENTS_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Multi-Agent System kullanılamıyor"
        )
    
    try:
        orchestrator = get_orchestrator(provider, model)
        orchestrator.initialize_agents(provider, model)
        
        registry = get_registry()
        return {
            "status": "initialized",
            "provider": provider,
            "model": model,
            **registry.get_status()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ajan başlatma hatası: {str(e)}")


# ============== AI Report Engine Endpoints ==============

class ReportRequest(BaseModel):
    scan_id: str
    scan_data: Optional[dict] = None
    sector: str = "technology"


@app.post("/report")
async def create_ai_report(request: ReportRequest):
    """
    Türkçe: Devrimci AI güvenlik raporu oluştur
    
    Bu endpoint NESSUS'UN 10 KATI değer sağlar:
    1. Attack Chain Analysis - Saldırı zincirleri
    2. Business Impact Calculator - Finansal risk hesabı
    3. Automated Remediation - Hazır düzeltme komutları
    4. Compliance Mapping - KVKK, PCI-DSS, ISO27001
    """
    if not REPORT_ENGINE_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="AI Report Engine yüklenemedi. report_engine.py kontrol edin."
        )
    
    # Rate limit
    check_rate_limit(request.scan_id)
    
    try:
        # Scan data yoksa fetch et
        scan_data = request.scan_data
        if not scan_data:
            # MongoDB'den çek (orchestrator üzerinden)
            raise HTTPException(
                status_code=400,
                detail="scan_data parametresi gerekli"
            )
        
        # AI Report oluştur
        report = await generate_ai_report(
            scan_id=request.scan_id,
            scan_data=scan_data,
            sector=request.sector
        )
        
        return report
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rapor oluşturma hatası: {str(e)}")


@app.get("/report/features")
async def get_report_features():
    """
    Türkçe: AI Report Engine özelliklerini listele
    """
    return {
        "engine": "Kadim AI Report Engine",
        "version": "1.0.0",
        "features": {
            "attack_chain_analysis": {
                "enabled": REPORT_ENGINE_AVAILABLE,
                "description": "Zafiyetleri birleştirerek saldırı senaryoları oluşturur",
                "mitre_mapping": True
            },
            "business_impact": {
                "enabled": REPORT_ENGINE_AVAILABLE,
                "description": "Finansal risk ve compliance etkisi hesaplar",
                "currencies": ["USD", "TRY"],
                "frameworks": ["PCI-DSS", "KVKK", "ISO27001", "SOC2"]
            },
            "auto_remediation": {
                "enabled": REPORT_ENGINE_AVAILABLE,
                "description": "Kopyala-yapıştır düzeltme komutları",
                "ansible_support": True,
                "verification_steps": True
            },
            "natural_language": {
                "enabled": True,
                "description": "Doğal dil ile güvenlik sorgulama",
                "examples": [
                    "Veritabanına nasıl sızılabilir?",
                    "En kritik 3 zafiyet hangisi?",
                    "Ransomware riski var mı?"
                ]
            }
        },
        "comparison_with_nessus": {
            "attack_chains": "Nessus: ❌ | Kadim: ✅",
            "business_impact": "Nessus: Sınırlı | Kadim: Tam Hesaplama",
            "auto_remediation": "Nessus: Genel Öneriler | Kadim: Hazır Komutlar",
            "ai_query": "Nessus: ❌ | Kadim: ✅",
            "mitre_mapping": "Nessus: Kısmi | Kadim: Tam Entegrasyon"
        }
    }

