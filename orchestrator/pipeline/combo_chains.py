"""
Kadim Güvenlik — Kombinasyon Zincirleri / Sinyal Sentezi (APT doktrini)
======================================================================
Türkçe: APT'lerin tarayıcılardan asıl farkı, tek başına DÜŞÜK değerli bulguları BİRLEŞTİRİP
yüksek-etkili bir saldırı yüzeyi kurmalarıdır. "user-enum var" + "xmlrpc açık" ayrı ayrı
'low/medium'dur; BİRLİKTE = geçerli kullanıcı adlarına karşı system.multicall ile tek istekte
yüzlerce parola denemesi → PRATİK hesap ele geçirme yüzeyi. Motor bu birleşimi görmezse APT'nin
gerisinde kalır.

Bu modül SAF bir kural motorudur (I/O yok → izole test): girdi olarak motorun ZATEN topladığı
CONFIRMED sinyalleri (normalize edilmiş {kind, target, severity, title}) alır, host bazında
gruplar, kural tablosunu uygular ve tetiklenen KOMBİNASYON bulgularını döndürür. Bu bulgular
pipeline'da Evidence olarak grafa yazılır → compose_killchain anlatısına da akar (sentezlenmiş
neden→etki kenarı: A + B → C).

Kurallar cross-tool'dur (wp_probe + idor_probe ...) ve GENİŞLETİLEBİLİR — yeni birleşim eklemek
tek satırlık ComboRule girdisidir. Yalnız CONFIRMED sinyaller birleştirilir (spekülasyon yok;
zincir kanıtlı taşlardan örülür). TAHRİBATSIZ: yeni istek üretmez, var olan kanıtı ilişkilendirir.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# ============================================================
# Sinyal etiketleri (kind) — kanıtın kararlı, tool-bağımsız sınıflaması
# ============================================================
# wp_probe (verification_method → kind):
SIG_WP_USER_ENUM = "wp-user-enum"          # REST /wp-json/wp/v2/users kullanıcı listesi
SIG_WP_AUTHOR_SCAN = "wp-author-scan"      # ?author=1 → kullanıcı adı
SIG_WP_XMLRPC = "wp-xmlrpc-open"           # xmlrpc.php açık
SIG_WP_DEBUG_LOG = "wp-debug-log"          # wp-content/debug.log ifşası
SIG_WP_CORE_VERSION = "wp-core-version"    # çekirdek sürüm ifşası
SIG_WP_INVENTORY = "wp-inventory"          # plugin/tema envanteri (kesin sürüm)
# Genel (tool-bağımsız):
SIG_IDOR_CONFIRMED = "idor-confirmed"      # idor_probe kanıtlı BOLA/IDOR
# AI/LLM red-team (Faz A) — confirmed kanıt sinyalleri (llm_redteam / OAST):
SIG_AI_PROMPT_INJECTION = "ai-prompt-injection"   # doğrudan/indirect PI kanıtlı
SIG_AI_TOOL_ABUSE = "ai-tool-abuse"               # tool/function çağrısı kanıtlı (OAST)
SIG_AI_OUTPUT_SSRF = "ai-output-ssrf"             # çıktı-handling → SSRF kanıtlı (OAST)
SIG_AI_SYSTEM_LEAK = "ai-system-prompt-leak"      # system-prompt ifşası (probable→confirmed değil)
SIG_AI_JAILBREAK = "ai-multiturn-jailbreak"       # çok-tur jailbreak kanıtlı


@dataclass
class Signal:
    """Normalize edilmiş CONFIRMED bulgu — kombinatörün girdisi."""
    kind: str
    target: str
    severity: str = ""
    title: str = ""


@dataclass
class ComboRule:
    """Bir kombinasyon kuralı. groups: her grup = alternatif kind kümesi; kural yalnız HER grup
    en az bir sinyalle karşılandığında tetiklenir (ör. {user-enum VEYA author-scan} VE {xmlrpc}).
    Tek grup varsa tetiklenmez sayılır (kombinasyon ≥2 farklı sinyal sınıfı gerektirir)."""
    name: str
    groups: List[Tuple[str, ...]]
    severity: str
    title: str
    cwe: List[str]
    mitre: str
    rationale: str                 # {sources} yer tutucusu kaynak başlıklarıyla doldurulur
    tier: str = "confirmed"


# ============================================================
# Kural tablosu — küratörlü, GENİŞLETİLEBİLİR (kanon değil)
# ============================================================
COMBO_RULES: List[ComboRule] = [
    # user-enum + xmlrpc = pratik brute-force. Bu birleşimin gücü: geçerli KULLANICI ADLARI
    # (enum) + system.multicall (xmlrpc) → tek HTTP isteğinde yüzlerce parola denemesi, WP
    # login rate-limit'ini baypas. Tek başlarına low/medium; birlikte kanıtlı yüksek yüzey.
    ComboRule(
        name="wp-bruteforce-surface",
        groups=[(SIG_WP_USER_ENUM, SIG_WP_AUTHOR_SCAN), (SIG_WP_XMLRPC,)],
        severity="high", cwe=["CWE-307", "CWE-799"], mitre="T1110.001",
        title="Kanıtlı WordPress Brute-Force / Credential-Stuffing Yüzeyi",
        rationale="Geçerli kullanıcı adları ifşa ({sources}) VE XML-RPC system.multicall açık: "
                  "saldırgan tek istekte çok-parola deneyerek login rate-limit'ini baypas eder → "
                  "pratik hesap ele geçirme. İki kanıtlı düşük bulgunun birleşimi yüksek etki."),
    # user-enum + kanıtlı IDOR = kitlesel kullanıcı verisi sızıntısı. enum id-uzayını verir,
    # IDOR erişimi kanıtlar → sömürü otomatikleştirilebilir (id-yürüyüşüyle tüm hesaplar).
    ComboRule(
        name="wp-mass-user-exfil",
        groups=[(SIG_WP_USER_ENUM, SIG_WP_AUTHOR_SCAN), (SIG_IDOR_CONFIRMED,)],
        severity="high", cwe=["CWE-639", "CWE-200"], mitre="T1213",
        title="Kanıtlı Kitlesel Kullanıcı Verisi Sızıntısı Zinciri",
        rationale="Kullanıcı enümerasyonu ({sources}) geçerli id-uzayını verirken kanıtlı IDOR "
                  "yetkisiz nesne erişimini gösteriyor: id-yürüyüşüyle TÜM kullanıcı kayıtları "
                  "otomatik dökülebilir. Enum + IDOR birleşimi tekil bulgulardan çok daha yüksek etki."),
    # debug.log (mutlak yol ifşası) + kesin bileşen sürümü = hedefli exploit hazırlığı. Yol +
    # sürüm, LFI/deserialization ve sürüm-eşlemeli public exploit seçimini pratikleştirir.
    ComboRule(
        name="wp-targeted-exploit-intel",
        groups=[(SIG_WP_DEBUG_LOG,), (SIG_WP_CORE_VERSION, SIG_WP_INVENTORY)],
        severity="high", cwe=["CWE-200"], mitre="T1592.002",
        title="Hedefli Exploit İstihbaratı Zinciri (yol ifşası + kesin sürüm)",
        rationale="debug.log sunucu mutlak yollarını sızdırırken ({sources}) kesin çekirdek/plugin "
                  "sürümleri biliniyor: saldırgan LFI/path-tabanlı sömürü ve sürüm-eşlemeli public "
                  "exploit'i tahmin yapmadan hedefler. İfşa + sürüm birleşimi exploit'i pratikleştirir."),
    # ===== AI/agentic kombinasyonları (Faz A) — düşük AI sinyallerini yüksek-etkiye bağlar =====
    # PI + tool-abuse = AJAN ELE GEÇİRME. Kanıtlı talimat-ezme + sunucunun saldırgan-verdiği aracı
    # OTOMATİK çalıştırması → SSRF/RCE/veri-exfil. Tek başına high; birlikte kritik.
    ComboRule(
        name="ai-agent-hijack",
        groups=[(SIG_AI_PROMPT_INJECTION,), (SIG_AI_TOOL_ABUSE,)],
        severity="critical", cwe=["CWE-1427", "CWE-1426", "CWE-918"], mitre="AML.T0050",
        title="Kanıtlı AI Ajan Ele Geçirme (prompt injection + tool execution)",
        rationale="Talimat-ezme kanıtlı ({sources}) VE saldırgan-tanımlı araç sunucu tarafında "
                  "OTOMATİK çalıştırıldı (OAST callback): ajan ele geçirilip keyfi adrese istek "
                  "attırılabilir → SSRF/veri-sızdırma/iç-servis erişimi. İki kanıtlı bulgunun "
                  "birleşimi kritik etki (OWASP LLM01+LLM08)."),
    # PI + output-SSRF = VERİ SIZDIRMA ZİNCİRİ. Çıktı aşağı akışta fetch ediliyorsa saldırgan
    # yönlendirmesiyle kanal dışına veri taşınabilir.
    ComboRule(
        name="ai-data-exfil-chain",
        groups=[(SIG_AI_PROMPT_INJECTION, SIG_AI_JAILBREAK), (SIG_AI_OUTPUT_SSRF,)],
        severity="high", cwe=["CWE-1427", "CWE-1426", "CWE-918"], mitre="AML.T0057",
        title="AI Veri Sızdırma Zinciri (injection + çıktı-fetch)",
        rationale="Talimat-ezme/aşındırma kanıtlı ({sources}) ve model çıktısı aşağı akışta "
                  "fetch ediliyor (OAST callback): saldırgan yönlendirmesiyle kanal-dışına veri "
                  "taşınabilir (OWASP LLM02/LLM05)."),
    # PI + çok-tur jailbreak = SAVUNMA AŞILDI: hem tek-tur hem kademeli aşındırma çalışıyor →
    # guardrail'ler güvenilmez; hedefli zincir için serbest yüzey.
    ComboRule(
        name="ai-guardrail-bypass",
        groups=[(SIG_AI_PROMPT_INJECTION,), (SIG_AI_JAILBREAK,)],
        severity="high", cwe=["CWE-1427"], mitre="AML.T0054",
        title="AI Guardrail Aşımı (tek-tur + çok-tur jailbreak)",
        rationale="Hem doğrudan talimat-ezme hem kademeli çok-tur jailbreak kanıtlı ({sources}): "
                  "modelin güvenlik kısıtları birden çok yolla aşılabiliyor — savunma güvenilmez "
                  "(OWASP LLM01)."),
]


def normalize_host(target: str) -> str:
    """Bulgu hedefinden host anahtarını çıkar (SAF). 'https://h/p?x' / 'h:443' / 'h' → 'h'.
    Kombinasyonlar host bazında değerlendirilir (aynı sistemdeki sinyaller birleşir)."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        try:
            netloc = urlsplit(t).netloc
        except Exception:
            netloc = t
        t = netloc or t
    # host:port → host (IPv6 köşeli parantez kaba ele alınır)
    if t.startswith("["):
        return t.split("]", 1)[0] + "]"
    return t.split(":", 1)[0].split("/", 1)[0]


def find_combinations(signals: List[Signal],
                      rules: Optional[List[ComboRule]] = None) -> List[Dict[str, Any]]:
    """CONFIRMED sinyallerden kombinasyon bulguları türet (SAF). Host bazında gruplar; her host
    için her kuralı dener. Döner combo-finding dict listesi (pipeline Evidence'a çevirir)."""
    rule_set = rules if rules is not None else COMBO_RULES
    # Host → {kind → [Signal]}
    by_host: Dict[str, Dict[str, List[Signal]]] = {}
    for s in signals:
        if not s.kind or not s.target:
            continue
        h = normalize_host(s.target)
        by_host.setdefault(h, {}).setdefault(s.kind, []).append(s)

    out: List[Dict[str, Any]] = []
    for host, kinds in by_host.items():
        for rule in rule_set:
            if len(rule.groups) < 2:
                continue  # kombinasyon ≥2 sinyal sınıfı ister
            matched_titles: List[str] = []
            ok = True
            for group in rule.groups:
                hit = next((k for k in group if k in kinds), None)
                if hit is None:
                    ok = False
                    break
                # gruptan tetikleyen ilk sinyalin başlığını kaynak olarak yaz
                matched_titles.append(kinds[hit][0].title or hit)
            if not ok:
                continue
            sources = "; ".join(dict.fromkeys(matched_titles))
            out.append({
                "combo": rule.name,
                "title": f"{rule.title} @ {host}",
                "severity": rule.severity,
                "target": host,
                "proof": rule.rationale.format(sources=sources),
                "confidence_tier": rule.tier,
                "cwe": list(rule.cwe),
                "mitre": rule.mitre,
                "sources": list(dict.fromkeys(matched_titles)),
                "verification_method": f"combo:{rule.name}",
            })
    return out
