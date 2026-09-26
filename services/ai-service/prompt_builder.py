"""
Enhanced Prompt Builder - Kadim AI Service
Türkçe: Daha kaliteli AI yanıtları için geliştirilmiş prompt sistemi

Bu modül:
1. Context-aware prompts oluşturur
2. Tarama türüne göre özelleştirilmiş promptlar sağlar
3. Structured output formatları tanımlar
4. Few-shot examples ile kaliteyi artırır
"""

import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

# TOON Token Optimization - %30-60 token tasarrufu
try:
    from toon_serializer import compress_scan_data, estimate_token_savings, to_toon
    TOON_AVAILABLE = True
except ImportError:
    TOON_AVAILABLE = False
    print("⚠️ TOON serializer bulunamadı, JSON formatı kullanılacak")


# ============== Nuclei Severity Mapping ==============
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪"
}


# ============== Data Extraction Helpers ==============

def extract_nuclei_summary(results: Dict) -> Dict:
    """
    Türkçe: Nuclei sonuçlarından özet bilgi çıkar

    ENHANCED: MongoDB formatını da parse eder
    - findings_summary: orchestrator kayıtları
    - findings: direkt nuclei çıktısı
    - Her iki formatı da destekler
    """
    nuclei_data = results.get("nuclei", {})

    # Findings çeşitli formatlarda olabilir
    findings = nuclei_data.get("findings_summary", nuclei_data.get("findings", []))

    if not findings:
        return {"has_data": False}

    # Severity dağılımı - MongoDB'den veya findings'ten
    severity_counts = nuclei_data.get("severity_counts", {})
    if not severity_counts:
        # Manuel hesapla
        for f in findings:
            # "info" dict içinde olabilir
            sev = f.get("severity")
            if not sev and "info" in f:
                sev = f["info"].get("severity", "info")
            sev = (sev or "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Kritik bulgular (critical + high) - ENHANCED parsing
    critical_findings = []
    for f in findings:
        severity = f.get("severity")
        if not severity and "info" in f:
            severity = f["info"].get("severity", "")

        if severity and severity.lower() in ["critical", "high"]:
            # Template ID ve name farklı yerlerde olabilir
            template_id = f.get("template-id") or f.get("template_id") or f.get("templateID", "unknown")
            name = f.get("name")
            if not name and "info" in f:
                name = f["info"].get("name", template_id)

            critical_findings.append({
                "template_id": template_id,
                "name": name or template_id,
                "severity": severity,
                "matched_at": f.get("matched-at") or f.get("matched_at", ""),
                "description": f.get("description") or (f.get("info", {}).get("description", ""))
            })

    critical_findings = critical_findings[:15]  # İlk 15 kritik bulgu

    # Benzersiz template'ler
    unique_templates = list(set(
        f.get("template-id") or f.get("template_id") or f.get("name", "unknown")
        for f in findings
    ))

    # CVE'ler - çeşitli konumlarda olabilir
    cves = []
    for f in findings:
        cve = f.get("cve_id") or f.get("cve-id")
        if not cve and "info" in f:
            info = f["info"]
            # CVE liste veya tek değer olabilir
            cve_field = info.get("classification", {}).get("cve-id") or info.get("cve_id")
            if isinstance(cve_field, list):
                cves.extend(cve_field)
            elif cve_field:
                cves.append(cve_field)
        elif cve:
            if isinstance(cve, list):
                cves.extend(cve)
            else:
                cves.append(cve)

    cves = list(set(filter(None, cves)))[:20]  # Max 20 CVE

    # Raw logs - farklı key'lerde olabilir
    raw_logs = nuclei_data.get("full_raw_logs") or nuclei_data.get("raw_output") or nuclei_data.get("output", "")

    return {
        "has_data": True,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "critical_findings": critical_findings,
        "unique_templates": unique_templates[:30],
        "cves": cves,
        "raw_logs": str(raw_logs)[:25000]  # Max 25K karakter (AI token limit)
    }


def extract_nmap_summary(results: Dict) -> Dict:
    """
    Türkçe: Nmap sonuçlarından özet bilgi çıkar

    ENHANCED: MongoDB findings_summary ve raw output destekler
    """
    nmap_data = results.get("nmap", {})

    # MongoDB format: findings_summary (orchestrator)
    findings_summary = nmap_data.get("findings_summary", [])

    # Portları çek - önce findings_summary'den
    ports = []
    if findings_summary:
        for f in findings_summary:
            if f.get("port"):
                ports.append({
                    "port": f.get("port"),
                    "protocol": f.get("protocol", "tcp"),
                    "state": f.get("state", "open"),
                    "service": f.get("service"),
                    "product": f.get("product"),
                    "version": f.get("version")
                })

    # Fallback: Raw output parse et
    if not ports:
        output = nmap_data.get("output", "")
        if output:
            port_matches = re.findall(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)', output)
            for match in port_matches:
                port_num, protocol, state, service = match
                if state == "open":
                    ports.append({
                        "port": int(port_num),
                        "protocol": protocol,
                        "state": "open",
                        "service": service
                    })

    if not ports:
        return {"has_data": False}

    # OS detection - raw output'tan
    os_info = None
    output = nmap_data.get("output", "")
    if output:
        os_match = re.search(r'OS details?:\s*(.+)', output)
        if os_match:
            os_info = os_match.group(1).strip()

    # Servis versiyonları - findings_summary'den veya parse
    service_versions = []
    for p in ports:
        if p.get("product") or p.get("version"):
            service_versions.append({
                "port": f"{p['port']}/{p.get('protocol', 'tcp')}",
                "service": p.get("service", "unknown"),
                "product": p.get("product", ""),
                "version": p.get("version", "")
            })

    # Fallback: raw output'tan version parse
    if not service_versions and output:
        versions = re.findall(r'(\d+/tcp)\s+open\s+(\S+)\s+(.+)', output)
        for v in versions[:20]:
            service_versions.append({
                "port": v[0],
                "service": v[1],
                "version": v[2].strip()
            })

    # Kritik portlar - exploitation risk yüksek
    critical_ports = [
        p for p in ports
        if p["port"] in [21, 22, 23, 25, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017]
    ]

    return {
        "has_data": True,
        "open_ports": ports[:50],  # Max 50 port
        "port_count": len(ports),
        "os_info": os_info,
        "service_versions": service_versions[:25],  # Max 25 service
        "critical_ports": critical_ports
    }


def extract_recon_summary(scan_data: Dict) -> Dict:
    """Türkçe: Recon Intelligence sonuçlarından özet çıkar"""
    results = scan_data.get("results", scan_data)
    
    summary = {
        "has_data": False,
        "subdomains": [],
        "technologies": [],
        "dns_records": [],
        "whois_info": {}
    }
    
    # Subdomain'ler
    if "subdomains" in results:
        summary["subdomains"] = results["subdomains"][:50]
        summary["has_data"] = True
    
    # Teknolojiler
    if "technologies" in results:
        summary["technologies"] = results["technologies"]
        summary["has_data"] = True
    
    # DNS kayıtları
    if "dns" in results:
        summary["dns_records"] = results["dns"]
        summary["has_data"] = True
    
    return summary


def calculate_risk_score(scan_data: Dict) -> int:
    """
    Türkçe: Tarama verilerinden risk skoru hesapla (0-100)
    
    Faktörler:
    - Zafiyet sayısı ve şiddeti (ağırlıklı)
    - Kritik port sayısı
    - Güvensiz servis versiyonları
    """
    score = 0
    results = scan_data.get("results", scan_data)
    
    # Nuclei zafiyetleri
    nuclei = extract_nuclei_summary(results)
    if nuclei["has_data"]:
        for severity, count in nuclei.get("severity_counts", {}).items():
            weight = SEVERITY_WEIGHTS.get(severity.lower(), 1)
            score += count * weight
    
    # Nmap kritik portlar
    nmap = extract_nmap_summary(results)
    if nmap["has_data"]:
        score += len(nmap.get("critical_ports", [])) * 5
        score += min(nmap.get("port_count", 0), 20)  # Çok açık port = risk
    
    # 0-100 aralığına normalize et
    return min(100, max(0, score))


def _format_scan_data(scan_data: Dict, max_chars: int = 35000) -> str:
    """
    Türkçe: Tarama verisini AI için optimize edilmiş formata dönüştürür
    
    TOON mevcut ise TOON formatı kullanır (%30-60 token tasarrufu)
    Değilse standart JSON kullanır
    
    Args:
        scan_data: Tarama verisi
        max_chars: Maksimum karakter limiti
        
    Returns:
        Formatlanmış string
    """
    if TOON_AVAILABLE:
        try:
            toon_data = compress_scan_data(scan_data)
            # Token tasarrufunu logla
            savings = estimate_token_savings(scan_data)
            print(f"📊 TOON Token Tasarrufu: {savings['savings_percent']}% ({savings['estimated_tokens_saved']} token)")
            return toon_data[:max_chars]
        except Exception as e:
            print(f"⚠️ TOON serileştirme hatası: {e}, JSON'a düşülüyor")
    
    # Fallback: JSON
    return json.dumps(scan_data, indent=2, ensure_ascii=False, default=str)[:max_chars]


# ============== Main Prompt Builders ==============

def build_enhanced_security_prompt(scan_data: Dict, analysis_type: str = "security") -> str:
    """
    Türkçe: Geliştirilmiş güvenlik analiz promptu

    Bu prompt:
    1. Yapılandırılmış veri özeti içerir
    2. Spesifik görevler tanımlar
    3. Beklenen çıktı formatını belirtir
    4. Few-shot example ile kaliteyi artırır

    ENHANCED: Tarama sonuçlarını daha detaylı parse ediyor
    """

    target = scan_data.get("target", scan_data.get("domain", "unknown"))
    results = scan_data.get("results", scan_data)

    # Veri özetlerini çıkar - ENHANCED parsing
    nuclei = extract_nuclei_summary(results)
    nmap = extract_nmap_summary(results)
    
    # Hesaplanan risk skoru (AI'ın referans alması için)
    calculated_risk = calculate_risk_score(scan_data)
    
    # Nuclei özet metni - ENHANCED with better formatting
    nuclei_section = ""
    if nuclei["has_data"]:
        # Kritik bulguları daha okunabilir formatta göster
        critical_findings_text = ""
        if nuclei['critical_findings']:
            for idx, finding in enumerate(nuclei['critical_findings'][:10], 1):
                severity_emoji = SEVERITY_EMOJI.get(finding.get('severity', 'info').lower(), '⚪')
                critical_findings_text += f"\n{idx}. {severity_emoji} **{finding.get('name', 'Unknown')}**\n"
                critical_findings_text += f"   - Template: `{finding.get('template_id', 'N/A')}`\n"
                critical_findings_text += f"   - Severity: {finding.get('severity', 'N/A').upper()}\n"
                critical_findings_text += f"   - Matched: {finding.get('matched_at', 'N/A')}\n"
                if finding.get('description'):
                    desc = finding['description'][:200]
                    critical_findings_text += f"   - Info: {desc}...\n"

        nuclei_section = f"""
## 📊 NUCLEI ZAFİYET TARAMASI

**Toplam Bulgu:** {nuclei['total_findings']}

**Şiddet Dağılımı:**
{chr(10).join(f"- {SEVERITY_EMOJI.get(k, '⚪')} {k.upper()}: {v}" for k, v in nuclei['severity_counts'].items())}

**Tespit Edilen CVE'ler ({len(nuclei['cves'])} adet):**
{', '.join(nuclei['cves'][:15]) if nuclei['cves'] else 'CVE bulunamadı'}

**Kritik ve Yüksek Şiddetli Bulgular:**
{critical_findings_text or 'Kritik bulgu yok'}

**Benzersiz Template'ler ({len(nuclei['unique_templates'])} adet):**
{', '.join([f'`{t}`' for t in nuclei['unique_templates'][:20]])}
"""

        # Raw logs varsa ekle (ama daha kısa)
        if nuclei['raw_logs'] and len(nuclei['raw_logs']) > 100:
            nuclei_section += f"""
**Ham Tarama Çıktısı (İlk 10K karakter):**
```
{nuclei['raw_logs'][:10000]}
```
"""

    # Nmap özet metni - ENHANCED with attack surface analysis
    nmap_section = ""
    if nmap["has_data"]:
        # Portları kategorize et
        web_ports = [p for p in nmap['open_ports'] if p['port'] in [80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000]]
        db_ports = [p for p in nmap['open_ports'] if p['port'] in [3306, 5432, 1433, 27017, 6379, 9200, 5984]]
        remote_access_ports = [p for p in nmap['open_ports'] if p['port'] in [22, 23, 3389, 5900]]

        # Formatla
        ports_text = ""
        for p in nmap['open_ports'][:30]:
            icon = "🌐" if p['port'] in [80, 443, 8080, 8443] else \
                   "🗄️" if p['port'] in [3306, 5432, 1433, 27017, 6379] else \
                   "🔐" if p['port'] in [22, 23, 3389, 5900] else "📡"
            ports_text += f"- {icon} **{p['port']}/{p.get('protocol', 'tcp')}** → {p.get('service', 'unknown')}"
            if p.get('product'):
                ports_text += f" ({p['product']}"
                if p.get('version'):
                    ports_text += f" {p['version']}"
                ports_text += ")"
            ports_text += "\n"

        # Kritik port analizi
        critical_analysis = ""
        if nmap['critical_ports']:
            critical_analysis = "⚠️ **Yüksek risk portlar tespit edildi:**\n"
            for cp in nmap['critical_ports']:
                risk_reason = {
                    22: "SSH - Brute-force ve credential stuffing riski",
                    23: "Telnet - Şifresiz erişim, cleartext iletişim",
                    21: "FTP - Anonymous login, cleartext credentials",
                    445: "SMB - EternalBlue, ransomware vektörü",
                    3389: "RDP - BlueKeep, brute-force riski",
                    3306: "MySQL - SQL injection, default credentials",
                    5432: "PostgreSQL - Command injection riski",
                    6379: "Redis - Unauthenticated access",
                    27017: "MongoDB - NoSQL injection, public exposure"
                }.get(cp['port'], "Exploitation vektörü")
                critical_analysis += f"- Port {cp['port']}: {risk_reason}\n"

        nmap_section = f"""
## 🔍 NMAP PORT TARAMASI

**Açık Port Sayısı:** {nmap['port_count']}
**İşletim Sistemi:** {nmap['os_info'] or 'Tespit edilemedi'}

**Attack Surface Analizi:**
- 🌐 Web Portları: {len(web_ports)}
- 🗄️ Database Portları: {len(db_ports)}
- 🔐 Remote Access: {len(remote_access_ports)}

{critical_analysis}

**Tespit Edilen Portlar ve Servisler:**
{ports_text}
"""

        # Servis versiyonları - CVE match için önemli
        if nmap['service_versions']:
            versions_text = ""
            for v in nmap['service_versions'][:15]:
                versions_text += f"- **{v['port']}** {v['service']}"
                if v.get('product'):
                    versions_text += f": {v['product']}"
                if v.get('version'):
                    versions_text += f" v{v['version']}"
                versions_text += "\n"

            nmap_section += f"""
**Servis Versiyonları (CVE araştırması için):**
{versions_text}
"""

    prompt = f"""# 🛡️ KADİM GÜVENLİK ANALİZ RAPORU

Sen dünya çapında tanınan bir siber güvenlik uzmanısın. OWASP Top 10, MITRE ATT&CK Framework ve CVE/CWE standartlarına tam hakimsin. Penetrasyon testi raporları yazma konusunda 15+ yıl deneyimin var.

## HEDEF SİSTEM BİLGİLERİ

| Alan | Değer |
|------|-------|
| **Hedef** | `{target}` |
| **Tarama Tarihi** | {datetime.now().strftime("%d/%m/%Y %H:%M")} |
| **Hesaplanan Risk** | {calculated_risk}/100 (referans) |

{nuclei_section}

{nmap_section}

---

## 📦 TAM TARAMA VERİSİ

Aşağıda tüm tarama sonuçlarının optimize edilmiş verisi bulunmaktadır:

```
{_format_scan_data(scan_data)}
```

---

# 🎯 ANALİZ GÖREVLERİN

## Görev 1: Risk Değerlendirmesi
Yukarıdaki verileri değerlendirerek 0-100 arası risk skoru hesapla. Hesaplarken:
- Critical zafiyet: +20-25 puan
- High zafiyet: +10-15 puan
- Medium zafiyet: +5-8 puan
- Kritik port açık (SSH, RDP, SMB): +5-10 puan
- Güncel olmayan yazılım versiyonu: +5 puan

## Görev 2: Kritik Bulguları Özetle
En tehlikeli 3-5 bulguyu listele. Her bulgu için:
- Zafiyet adı ve CVE numarası (varsa)
- Neden tehlikeli olduğunu açıkla
- Exploit edilebilirlik durumu

## Görev 3: Somut Öneriler
Her kritik bulgu için:
- Hemen yapılması gereken aksiyon
- Uzun vadeli çözüm
- Patch/update bilgisi

## Görev 4: Teknik Kanıtlar
Her önemli bulgu için:
- Tespit edilen versiyon bilgisi
- PoC (Proof of Concept) komutu (varsa)
- CVSS skoru ve referans link

## Görev 5: Acil Aksiyon Planı
Güvenlik ekibinin hemen yapması gereken 3-5 adım.

---

# 📝 YANITLAMA FORMATI

Yanıtını **KESİNLİKLE** aşağıdaki formatta ver:

## Risk Skoru: [SKOR]/100

[2-3 cümle genel değerlendirme. Neden bu skoru verdiğini açıkla.]

## 🔴 Kritik Bulgular

1. **[Bulgu Adı]** - [CVE varsa]
   - Açıklama: [Kısa açıklama]
   - Risk: [Neden tehlikeli]

2. **[Bulgu Adı]** - [CVE varsa]
   - Açıklama: [Kısa açıklama]
   - Risk: [Neden tehlikeli]

## 💡 Güvenlik Önerileri

1. **[Öneri Başlığı]**
   - Aksiyon: [Yapılması gereken]
   - Öncelik: [Kritik/Yüksek/Orta]

2. **[Öneri Başlığı]**
   - Aksiyon: [Yapılması gereken]
   - Öncelik: [Kritik/Yüksek/Orta]

## 🔬 Teknik Analiz & Deliller

1. **[Teknoloji/Servis]** - [Versiyon]
   - CVE: [CVE numarası veya N/A]
   - CVSS: [Skor veya N/A]
   - Test: `[PoC komutu]`
   - Referans: [URL]

## ⏭️ Acil Aksiyon Planı

- [ ] [Hemen yapılması gereken 1]
- [ ] [Hemen yapılması gereken 2]
- [ ] [Hemen yapılması gereken 3]

---

**ÖNEMLİ KURALLAR:**
1. Türkçe yanıt ver (teknik terimler İngilizce kalabilir)
2. Spekülatif bilgi verme, sadece tarama verilerini yorumla
3. Güvenlik risklerini asla küçümseme
4. Somut, uygulanabilir öneriler ver
5. CVE numarasını YALNIZ yukarıdaki tarama verisinde AÇIKÇA geçen CVE'lerden al; veride
   OLMAYAN CVE UYDURMA. Emin değilsen "CVE: N/A" yaz. (Otomatik grounding katmanı, tarama
   kanıtında bulunmayan her CVE'yi ⚠️ ile işaretleyip "doğrulanmadı" notu ekler — uydurma
   CVE müşteri raporunu bozar.)
6. Yukarıdaki JSON verisindeki TÜM önemli bulguları analiz et
"""

    return prompt


# ============================================================
# CVE GROUNDING — narrative halüsinasyon guard'ı
# ============================================================
# NEDEN: Deterministik graf CVE'leri NVD/KEV feed'inden GROUNDED gelir; ama narrative rapor
# prompt'u modele "CVE numarası yaz" der → model, taramanın kanıtında OLMAYAN bir CVE'yi kendi
# bilgi tabanından uydurabilir (grounding yok). Müşteri teslimatında uydurma CVE = güven kaybı.
# Bu guard LLM metnindeki her CVE'yi taramanın grounded kümesiyle kesiştirir; kümede olmayanı
# ⚠️ ile işaretler ve dipnot ekler (SİLMEZ — operatör görüp karar versin).
_CVE_TOKEN_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_grounded_cves(scan_data: Any) -> set:
    """Taramanın YAPISAL verisindeki (findings/vulnerabilities/services — feed & tarayıcı
    kaynaklı) tüm CVE'ler. Bu küme 'grounded'dır: pipeline'ın fiilen kaydettiği kanıt.
    LLM'in eklediği ama burada olmayan CVE 'ungrounded' (doğrulanmamış) sayılır."""
    try:
        blob = json.dumps(scan_data, default=str)
    except Exception:
        blob = str(scan_data)
    return {m.group(0).upper() for m in _CVE_TOKEN_RE.finditer(blob)}


def annotate_ungrounded_cves(text: str, grounded: set):
    """LLM narrative'indeki grounded-olmayan CVE'leri ⚠️ ile işaretle + dipnot ekle.
    Döner: (işaretli_metin, ungrounded_listesi). Grounded CVE'lere dokunmaz; hiç
    ungrounded yoksa metni değiştirmeden döner."""
    if not text:
        return text, []
    grounded_up = {str(c).upper() for c in (grounded or set())}
    found = {m.group(0).upper() for m in _CVE_TOKEN_RE.finditer(text)}
    ungrounded = sorted(found - grounded_up)
    if not ungrounded:
        return text, []
    ung = set(ungrounded)
    marked = _CVE_TOKEN_RE.sub(
        lambda m: (m.group(0) + "⚠️") if m.group(0).upper() in ung else m.group(0),
        text,
    )
    footer = (
        "\n\n---\n"
        "⚠️ **CVE DOĞRULAMA NOTU (otomatik grounding):** İşaretli (⚠️) CVE'ler bu taramanın "
        "kanıt/feed verisinde (NVD/KEV/tarayıcı) BULUNMUYOR; modelin bilgi tabanından gelmiştir "
        "ve DOĞRULANMAMIŞTIR — bağımsız teyit edilmeden müşteri raporuna alınmamalıdır.\n"
        f"Doğrulanmamış CVE(ler): {', '.join(ungrounded)}"
    )
    return marked + footer, ungrounded


def ground_cves_in_narrative(text: str, scan_data: Any):
    """Kısayol: scan_data'dan grounded kümeyi çıkar, narrative'i işaretle.
    Döner: (işaretli_metin, ungrounded_listesi)."""
    grounded = extract_grounded_cves(scan_data)
    return annotate_ungrounded_cves(text, grounded)


def build_enhanced_chat_prompt(
    scan_data: Dict, 
    current_analysis: Dict, 
    user_message: str,
    conversation_history: List[Dict] = None
) -> str:
    """
    Türkçe: Context-aware chat promptu oluştur
    
    Bu prompt:
    1. Önceki konuşma geçmişini içerir
    2. Mevcut analizi korur
    3. Kullanıcı isteğine göre güncelleme yapar
    """
    
    target = scan_data.get("target", scan_data.get("domain", "unknown"))
    
    # Konuşma geçmişi formatı
    history_section = ""
    if conversation_history:
        history_lines = []
        for msg in conversation_history[-10:]:  # Son 10 mesaj
            role = "KULLANICI" if msg["role"] == "user" else "ANALİST"
            history_lines.append(f"[{role}]: {msg['content'][:500]}")  # Max 500 karakter
        history_section = f"""
## 💬 ÖNCEKİ KONUŞMA

{chr(10).join(history_lines)}

---
"""

    # Mevcut analiz özeti
    current_risk = current_analysis.get("risk_score", "Belirlenmedi")
    current_findings = current_analysis.get("critical_findings", [])
    current_recommendations = current_analysis.get("recommendations", [])
    
    prompt = f"""# 🤖 KADİM AI ANALİST - İNTERAKTİF MOD

Sen Kadim Security Platform'un kıdemli güvenlik analistisin. Kullanıcı seninle bir güvenlik taramasının sonuçlarını tartışıyor.

## HEDEF
`{target}`

## MEVCUT ANALİZ DURUMU
- **Risk Skoru:** {current_risk}/100
- **Kritik Bulgu Sayısı:** {len(current_findings)}
- **Öneri Sayısı:** {len(current_recommendations)}

{history_section}

## 📨 KULLANICI MESAJI

> {user_message}

---

# 🎯 GÖREVİN

Kullanıcının mesajını değerlendir ve uygun şekilde yanıt ver:

1. **Soru soruyorsa:** Detaylı ve teknik bir cevap ver
2. **İtiraz ediyorsa:** Argümanlarını değerlendir, haklıysa risk skorunu güncelle
3. **Ek bilgi veriyorsa:** Bu bilgiyi analizi güncellemek için kullan
4. **Açıklama istiyorsa:** İlgili bulguyu detaylandır
5. **Rapor güncellemesi istiyorsa:** Güncellenmiş rapor bölümlerini yaz

## YANITLAMA KURALLARI

1. **Doğal ve profesyonel** bir dil kullan
2. Risk skorunu güncellemen gerekiyorsa yeni skoru belirt ve gerekçele
3. Spekülatif bilgi verme, sadece mevcut verilere dayanarak konuş
4. Güvenlik risklerini asla küçümseme
5. Kullanıcı haklıysa kabul et ve analizi güncelle

## YANITINDA ŞU BÖLÜMLER OLABİLİR (gerektiğinde):

- **Yanıt:** [Kullanıcı mesajına doğrudan cevap]
- **Risk Güncellemesi:** [Yeni skor ve gerekçe - değiştiyse]
- **Ek Bilgi:** [Detaylı açıklamalar]
- **Güncellenen Bulgular:** [Varsa]
- **Öneriler:** [Varsa yeni öneriler]

---

**ÖNEMLİ:** Türkçe yanıt ver. Teknik terimler İngilizce kalabilir.
"""

    return prompt


def build_hash_analysis_prompt(scan_data: Dict) -> str:
    """Türkçe: Geliştirilmiş hash kırma analiz promptu"""
    
    hash_value = scan_data.get("hash", "unknown")
    hash_type = scan_data.get("hash_type", "unknown")
    found = scan_data.get("found", False)
    password = scan_data.get("password", None)
    attempts = scan_data.get("attempts", 0)
    elapsed = scan_data.get("elapsed_ms", 0)
    method = scan_data.get("method", "unknown")
    
    prompt = f"""# 🔐 HASH KRAKİNG ANALİZ RAPORU

Sen bir kriptografi ve parola güvenliği uzmanısın.

## HASH BİLGİLERİ

| Alan | Değer |
|------|-------|
| **Hash** | `{hash_value}` |
| **Algoritma** | {hash_type.upper()} |
| **Sonuç** | {"✅ KIRILDI" if found else "❌ Kırılamadı"} |
| **Bulunan Şifre** | `{password if password else "N/A"}` |
| **Deneme Sayısı** | {attempts:,} |
| **Süre** | {elapsed/1000:.2f} saniye |
| **Yöntem** | {method} |

## ANALİZ GÖREVLERİ

1. Hash algoritmasının güvenlik düzeyini değerlendir
2. {"Bulunan şifrenin zayıflıklarını analiz et" if found else "Neden kırılamadığını açıkla"}
3. Parola politikası önerileri sun
4. Alternatif kırma yöntemleri öner (gerekirse)

## YANITLAMA FORMATI

## Risk Skoru: [X]/100

[Hash türü ve sonuç hakkında değerlendirme]

## 🔴 Bulgular

1. [Bulgu 1]
2. [Bulgu 2]

## 💡 Öneriler

1. [Öneri 1]
2. [Öneri 2]

## 🔬 Teknik Detaylar

- **Algoritma Gücü:** [Değerlendirme]
- **Kırılma Hızı:** {attempts/(elapsed/1000) if elapsed > 0 else 0:.0f} hash/saniye
- **Tahmini Brute-force Süresi:** [Hesaplama]

## ⏭️ Sonraki Adımlar

- [Aksiyon 1]
- [Aksiyon 2]

---
**Türkçe yanıt ver.**
"""
    return prompt


def build_vulnerability_analysis_prompt(scan_data: Dict) -> str:
    """Türkçe: Geliştirilmiş zafiyet listesi analiz promptu"""
    
    vulnerabilities = scan_data.get("vulnerabilities", [])
    target = scan_data.get("target", "unknown")
    
    # Şiddet dağılımı
    severity_dist = {}
    for v in vulnerabilities:
        sev = v.get("severity", "unknown").lower()
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
    
    prompt = f"""# 🛡️ ZAFİYET YÖNETİMİ RAPORU

Sen bir zafiyet yönetimi ve patch management uzmanısın.

## HEDEF
`{target}`

## ZAFİYET ÖZETİ

**Toplam Zafiyet:** {len(vulnerabilities)}

**Şiddet Dağılımı:**
{chr(10).join(f"- {SEVERITY_EMOJI.get(k, '⚪')} {k.upper()}: {v}" for k, v in severity_dist.items())}

## ZAFİYET LİSTESİ (İlk 20)

```json
{json.dumps(vulnerabilities[:20], indent=2, ensure_ascii=False, default=str)}
```

## ANALİZ GÖREVLERİ

1. Zafiyetleri öncelik sırasına göre sırala (CVSS + exploit availability)
2. En kritik zafiyetleri detaylı açıkla
3. Remediation planı oluştur
4. Patch yönetimi stratejisi öner

## YANITLAMA FORMATI

## Risk Skoru: [X]/100

[Genel değerlendirme]

## 🔴 Kritik Zafiyetler (Öncelikli)

1. **[CVE-XXXX-XXXX]** - [Zafiyet Adı]
   - CVSS: [Skor]
   - Etki: [Açıklama]
   - Çözüm: [Aksiyon]

## 💡 Remediation Planı

| Öncelik | Zafiyet | Aksiyon | Süre |
|---------|---------|---------|------|
| P1 | [CVE] | [Aksiyon] | [Tahmini süre] |

## ⏭️ Patch Stratejisi

1. [Strateji 1]
2. [Strateji 2]

---
**Türkçe yanıt ver.**
"""
    return prompt


def build_osint_analysis_prompt(scan_data: Dict) -> str:
    """Türkçe: Geliştirilmiş OSINT analiz promptu"""
    
    domain = scan_data.get("domain", scan_data.get("target", "unknown"))
    recon = extract_recon_summary(scan_data)
    
    prompt = f"""# 🔍 OSINT / RECON ANALİZ RAPORU

Sen bir OSINT (Açık Kaynak İstihbarat) ve tehdit istihbaratı uzmanısın.

## HEDEF DOMAIN
`{domain}`

## TOPLANAN VERİLER

**Subdomain Sayısı:** {len(recon.get('subdomains', []))}
**Tespit Edilen Teknolojiler:** {len(recon.get('technologies', []))}

**Subdomain'ler (İlk 30):**
{chr(10).join(['- ' + s for s in recon.get('subdomains', [])[:30]])}

**Teknolojiler:**
{chr(10).join(['- ' + str(t) for t in recon.get('technologies', [])[:20]])}

## TAM VERİ

```json
{json.dumps(scan_data, indent=2, ensure_ascii=False, default=str)[:8000]}
```

## ANALİZ GÖREVLERİ

1. Toplanan istihbaratı değerlendir
2. Attack surface'i analiz et
3. Potansiyel güvenlik risklerini belirle
4. Sonraki istihbarat toplama adımlarını öner

## YANITLAMA FORMATI

## Risk Skoru: [X]/100

[Genel değerlendirme]

## 🔴 Kritik Bulgular

1. [Bulgu]
2. [Bulgu]

## 🌐 Attack Surface Analizi

- **Toplam Subdomain:** [Sayı]
- **Riskli Servisler:** [Liste]
- **Açık Veri:** [Liste]

## 💡 Öneriler

1. [Öneri]

## ⏭️ Sonraki Adımlar

- [Aksiyon]

---
**Türkçe yanıt ver.**
"""
    return prompt
