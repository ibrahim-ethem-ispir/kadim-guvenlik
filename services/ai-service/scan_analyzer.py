"""
Kadim Güvenlik - v2 Scan Analyzer
Türkçe: Pipeline sonuçlarını AI ile analiz eden modül.

Pipeline tamamlandığında orchestrator bu modülü çağırır.
AI Orchestra üzerinden optimal model seçimi yaparak APT-tarzı analiz üretir.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

# §2.3: Sağlam JSON-önce + regex-fallback ayrıştırıcı (izole test edilmiş: test_report_parsing.py)
from report_parsing import parse_ai_analysis

from ai_orchestra import (
    AIOrchestra, get_orchestra,
    SecurityTask, AICapability, TaskPriority, AIResponse
)

# Threat Intelligence Integration
try:
    from threat_intel_engine import match_apt_indicators, get_threat_landscape, APT_GROUPS
    from ioc_matcher import calculate_apt_risk_score, match_iocs
    TI_AVAILABLE = True
except ImportError:
    TI_AVAILABLE = False

logger = logging.getLogger("scan-analyzer")


# ============== Analiz Prompt Şablonları ==============

COMPREHENSIVE_ANALYSIS_PROMPT = """Sen dünya çapında bir APT (Advanced Persistent Threat) analisti ve Red Team liderisinisin. Lazarus Group, APT28 (Fancy Bear), APT29 (Cozy Bear) gibi gelişmiş tehdit aktörlerinin TTP'lerine (Tactics, Techniques, Procedures) hakimsin. MITRE ATT&CK Framework, OWASP Top 10, CWE ve CVE standartlarını bire bir biliyorsun.

## Hedef: {target}
## Tarama Profili: {profile}

## Tarama Sonuçları

{scan_results_formatted}

---

## GÖREVLERİN

Bu tarama sonuçlarını bir **APT threat actor** gibi analiz et. Savunma tarafında çalışan güvenlik ekibine, saldırganın ne göreceğini ve nasıl saldıracağını detaylı şekilde anlat.

### 1. RISK SCORE (0-100)
Risk skorunu 0-100 arasında hesapla:
- Cloudflare/WAF bypass edilebiliyorsa: +15 puan
- Gerçek IP açığa çıkmışsa: +20 puan
- Kritik zafiyet (RCE, SQLi, SSRF): +25 puan
- High zafiyet: +15 puan
- Kritik port açık (SSH, RDP, SMB, DB): +10 puan
- Güncel olmayan yazılım: +10 puan
- Default credentials: +20 puan

### 2. EXECUTIVE SUMMARY
Üst yönetime 3 cümle: Ne bulundu, ne kadar tehlikeli, ne yapılmalı.

### 3. ALTYAPI HARİTASI
- Cloudflare/WAF durumu (bypass edildi mi?)
- Gerçek IP vs CDN IP karşılaştırması
- Tespit edilen teknoloji stack (OS, Web Server, Framework, DB)
- DNS yapılandırması analizi
- SSL/TLS sertifika bilgileri

### 4. SALDIRI YÜZEYİ ANALİZİ (Attack Surface)
Her açık port ve servis için:
- Port/Servis/Versiyon
- Bilinen CVE'ler ve exploit'ler
- Sömürü kolaylık derecesi (Easy/Medium/Hard)
- APT grubunun bu servisi nasıl kullanacağı

### 5. KRİTİK BULGULAR
Her critical/high bulgu için:
- Bulgu adı, CVE, CVSS skoru
- Sömürü senaryosu (PoC komutu dahil)
- MITRE ATT&CK teknik ID'si (örn: T1190 - Exploit Public-Facing Application)
- İş etkisi (veri sızıntısı, sistem ele geçirme, lateral movement)

### 6. APT SALDIRI ZİNCİRİ (Kill Chain)
Adım adım, bir APT aktörünün bu hedefi nasıl ele geçireceğini yaz:

**Aşama 1 - Keşif (Reconnaissance):**
- Hangi veriler toplandı
- Hedef hakkında ne biliniyor

**Aşama 2 - İlk Erişim (Initial Access):**
- En olası giriş noktası
- Kullanılacak exploit/teknik
- MITRE: T1190, T1133, T1078...

**Aşama 3 - Yürütme (Execution):**
- Erişim sonrası ne çalıştırılır
- Reverse shell, web shell senaryoları

**Aşama 4 - Kalıcılık (Persistence):**
- Backdoor yerleştirme yöntemleri
- Cron job, startup script, web shell

**Aşama 5 - Yetki Yükseltme (Privilege Escalation):**
- Kernel exploit, SUID, sudo bypass
- Servis hesapları

**Aşama 6 - Yanal Hareket (Lateral Movement):**
- İç ağda yayılma stratejisi
- Diğer servislere pivoting

**Aşama 7 - Veri Sızdırma (Exfiltration):**
- Veri çıkış kanalları
- DNS tunneling, HTTPS exfil

### 7. SHODAN/OSINT İSTİHBARATI
- Shodan'da görünen servisler
- VirusTotal itibar durumu
- Whois ve DNS istihbaratı
- Geçmiş güvenlik olayları

### 8. SAVUNMA ÖNERİLERİ (Prioritized)

**[P0 - ACİL] Şimdi yapılmalı:**
- ... (her biri somut komut/aksiyon ile)

**[P1 - KRİTİK] 24 saat içinde:**
- ...

**[P2 - YÜKSEK] 1 hafta içinde:**
- ...

**[P3 - ORTA] 1 ay içinde:**
- ...

### 9. WAF/IDS BYPASS NOTU
Eğer WAF/CDN tespit edildiyse:
- Bypass edilebilirlik durumu
- Direkt IP erişimi mümkün mü
- Önerilen WAF kuralları

---

**FORMAT KURALLARI:**
1. Türkçe yanıt ver (teknik terimler İngilizce kalabilir)
2. Her bulgu için SOMUT kanıt göster (port, versiyon, CVE)
3. Spekülatif bilgi verme - sadece tarama verisini yorumla
4. PoC komutları ver (curl, nmap, nuclei, sqlmap örnekleri)
5. MITRE ATT&CK teknik ID'lerini kullan
6. Risk skorunu ASLA küçümseme
"""


def _format_scan_results(results: Dict[str, Any]) -> str:
    """Tarama sonuçlarını okunabilir metin formatına dönüştür"""
    sections = []

    for tool_name, tool_data in results.items():
        if not tool_data:
            continue

        section = f"### {tool_name.upper()} Sonuçları\n"

        if tool_name == "nmap":
            ports = tool_data.get("open_ports", [])
            if isinstance(ports, list) and ports:
                section += f"**Açık Port Sayısı:** {len(ports)}\n"
                section += "**Portlar:**\n"
                for port in ports[:50]:  # Max 50 port
                    if isinstance(port, dict):
                        section += f"- {port.get('port', '?')}/{port.get('protocol', 'tcp')} - {port.get('service', 'unknown')} {port.get('version', '')}\n"
                    else:
                        section += f"- {port}\n"

            os_info = tool_data.get("os_detection")
            if os_info:
                section += f"\n**OS Tespiti:** {os_info}\n"

            services = tool_data.get("services", [])
            if services:
                section += f"\n**Servisler:** {len(services)} servis tespit edildi\n"

        elif tool_name == "nuclei":
            findings_count = tool_data.get("findings_count", 0)
            severity_counts = tool_data.get("severity_counts", {})
            # FALSE-POSITIVE ekseni: kanıt güç kademesi. LLM'e "8 kritik" değil "2 KANITLI
            # kritik, 6 doğrulanmamış (olası FP)" bağlamı verilir ki rapor kritikleri şişirmesin
            # ve doğrulanmamış bulguları "kesin açık" gibi sunmasın.
            confirmed_counts = tool_data.get("confirmed_severity_counts") or {}
            tier_counts = tool_data.get("tier_counts") or {}
            section += f"**Toplam Bulgu:** {findings_count}\n"
            section += f"**Severity Dağılımı (tüm bulgular):** Critical={severity_counts.get('critical', 0)}, High={severity_counts.get('high', 0)}, Medium={severity_counts.get('medium', 0)}, Low={severity_counts.get('low', 0)}\n"
            if tier_counts or confirmed_counts:
                section += (
                    f"**Kanıt Kademesi:** Kanıtlı(confirmed)={tier_counts.get('confirmed', 0)}, "
                    f"Olası(probable)={tier_counts.get('probable', 0)}, "
                    f"Doğrulanmadı(unconfirmed/olası-FP)={tier_counts.get('unconfirmed', 0)}\n"
                )
                section += (
                    f"**MANŞET (yalnız kanıtlı+olası):** Critical={confirmed_counts.get('critical', 0)}, "
                    f"High={confirmed_counts.get('high', 0)}\n"
                )
                section += (
                    "> NOT: 'unconfirmed' bulgular araç iddiasıdır, bağımsız teyit YOKTUR — "
                    "raporda 'kesin açık' değil 'doğrulanması gereken aday' olarak sun; "
                    "kritik sayısını manşetle abartma.\n"
                )

            findings = tool_data.get("findings", [])
            if findings:
                section += "\n**Bulgular:**\n"
                for f in findings[:30]:  # Max 30 bulgu
                    info = f.get("info", {})
                    tier = str(f.get("confidence_tier") or "unconfirmed")
                    tier_lbl = {"confirmed": "KANITLI", "probable": "OLASI",
                                "unconfirmed": "DOĞRULANMADI"}.get(tier, "DOĞRULANMADI")
                    section += (
                        f"- [{info.get('severity', 'unknown').upper()}] "
                        f"[{tier_lbl}] "
                        f"{info.get('name', 'Unknown')} | "
                        f"Template: {f.get('template-id', '?')} | "
                        f"Match: {f.get('matched-at', '?')}\n"
                    )

        elif tool_name == "subfinder":
            subdomains = tool_data.get("subdomains", [])
            sub_count = tool_data.get("subdomains_count", len(subdomains))
            section += f"**Subdomain Sayısı:** {sub_count}\n"
            if subdomains:
                section += "**Subdomainler:**\n"
                for sd in subdomains[:30]:
                    section += f"- {sd}\n"

            source_counts = tool_data.get("source_counts", {})
            if source_counts:
                section += f"\n**Kaynak Dağılımı:** {json.dumps(source_counts, indent=2)}\n"

        elif tool_name == "rustscan":
            ports = tool_data.get("open_ports", [])
            section += f"**Açık Port Sayısı:** {len(ports)}\n"
            if ports:
                section += f"**Portlar:** {', '.join(str(p) for p in ports[:50])}\n"

        elif tool_name == "fuzz":
            fuzz_count = tool_data.get("findings_count", 0)
            section += f"**Dizin/Dosya Bulgusu:** {fuzz_count}\n"
            directories = tool_data.get("directories", [])
            if directories:
                section += "**Bulunan Dizinler:**\n"
                for d in directories[:20]:
                    section += f"- {d}\n"

        elif tool_name == "recon":
            is_cf = tool_data.get("is_cloudflare", False)
            real_ips = tool_data.get("real_ips", [])
            domain_ips = tool_data.get("domain_ips", [])
            technologies = tool_data.get("technologies", [])
            subdomains = tool_data.get("subdomains", [])

            section += f"**Cloudflare/CDN Tespiti:** {'EVET - Cloudflare arkasında' if is_cf else 'HAYIR - Doğrudan erişim'}\n"
            section += f"**Domain IP'leri:** {', '.join(domain_ips) if domain_ips else 'Bulunamadı'}\n"

            if real_ips:
                section += f"\n**GERÇEK IP ADRESLERİ (CF Bypass):** {', '.join(real_ips)}\n"
                section += "**DİKKAT:** Bu IP'ler Cloudflare/WAF arkasından doğrudan erişilebilir!\n"

            if technologies:
                section += f"\n**Tespit Edilen Teknolojiler:** {', '.join(str(t) for t in technologies[:20])}\n"

            if subdomains:
                cf_subs = [s for s in subdomains if isinstance(s, dict) and not s.get("is_cf", True)]
                section += f"\n**Subdomain Sayısı:** {len(subdomains)}\n"
                if cf_subs:
                    section += f"**CF Korumasız Subdomain'ler ({len(cf_subs)} adet):**\n"
                    for sub in cf_subs[:15]:
                        section += f"- {sub.get('name', '?')} → {', '.join(sub.get('ips', []))}\n"

            page_title = tool_data.get("page_title", "")
            if page_title:
                section += f"\n**Sayfa Başlığı:** {page_title}\n"

            headers = tool_data.get("http_headers", {})
            interesting_headers = {
                k: v for k, v in headers.items()
                if k.lower() in ("server", "x-powered-by", "x-aspnet-version",
                                  "x-generator", "x-drupal-cache", "x-varnish",
                                  "via", "x-cache", "x-amz-cf-id")
            }
            if interesting_headers:
                section += "\n**İlginç HTTP Header'ları:**\n"
                for k, v in interesting_headers.items():
                    section += f"- {k}: {v}\n"

        elif tool_name == "osint":
            for lookup_name, lookup_data in tool_data.items():
                if isinstance(lookup_data, dict) and lookup_data.get("error"):
                    continue
                section += f"\n**{lookup_name.upper()} Sonuçları:**\n"
                section += f"```json\n{json.dumps(lookup_data, indent=2, default=str)[:1500]}\n```\n"

        elif tool_name == "origin_discovery":
            is_cdn = tool_data.get("is_behind_cdn", False)
            section += f"**CDN Arkasında:** {'EVET' if is_cdn else 'HAYIR'}\n"
            best = tool_data.get("best_candidate")
            if best:
                section += f"\n**EN İYİ ADAY IP:** {best.get('ip', '?')}\n"
                section += f"  - Güven: %{best.get('confidence', 0)}\n"
                section += f"  - Kaynak: {best.get('source', '?')}\n"
                section += f"  - Doğrulandı: {'EVET ✓' if best.get('verified') else 'HAYIR'}\n"

            candidates = tool_data.get("candidates", [])
            if candidates:
                section += f"\n**Tüm Aday IP'ler ({len(candidates)}):**\n"
                for c in candidates[:10]:
                    verified_mark = " ✓" if c.get("verified") else ""
                    section += f"  - {c.get('ip', '?')} (güven: %{c.get('confidence', 0)}, kaynak: {c.get('source', '?')}){verified_mark}\n"

            techniques = tool_data.get("techniques_used", [])
            if techniques:
                section += f"\n**Kullanılan Teknikler:** {', '.join(techniques)}\n"

            risk = tool_data.get("risk_assessment", "")
            if risk:
                section += f"\n**Risk Değerlendirmesi:** {risk}\n"

        elif tool_name == "adaptive_analysis":
            anomalies = tool_data.get("anomalies", [])
            recommendations = tool_data.get("recommendations", [])

            if anomalies:
                section += f"**Tespit Edilen Anomaliler ({len(anomalies)}):**\n"
                for a in anomalies[:10]:
                    section += f"  - [{a.get('severity', '?').upper()}] {a.get('title', '?')}: {a.get('description', '')[:200]}\n"

            if recommendations:
                section += f"\n**Adaptif Öneriler ({len(recommendations)}):**\n"
                for r in recommendations[:10]:
                    section += f"  - [{r.get('priority', '?').upper()}] {r.get('action', '?')}: {r.get('reason', '')}\n"

            nuclei_tags = tool_data.get("nuclei_tags", [])
            if nuclei_tags:
                section += f"\n**Önerilen Nuclei Tags:** {', '.join(nuclei_tags)}\n"

            section += f"**Risk Modifiyeri:** +{tool_data.get('risk_score_modifier', 0)}\n"
            section += f"**Profil Yükseltme:** {'EVET' if tool_data.get('should_escalate') else 'HAYIR'}\n"

        else:
            section += f"```json\n{json.dumps(tool_data, indent=2, default=str)[:2000]}\n```\n"

        sections.append(section)

    return "\n\n".join(sections) if sections else "Tarama sonucu bulunamadı."


async def analyze_scan_results(
    scan_id: str,
    target: str,
    scan_data: Dict[str, Any],
    preferred_model: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Türkçe: Pipeline sonuçlarını AI ile analiz et.

    Args:
        scan_id: Tarama ID'si
        target: Hedef domain/IP
        scan_data: Pipeline'dan gelen sonuçlar ({"results": {...}, "profile": "..."})
        preferred_model: Kullanıcının tercih ettiği model

    Returns:
        AI analiz sonucu dict
    """
    orchestra = get_orchestra()

    results = scan_data.get("results", {})
    profile = scan_data.get("profile", "normal")

    # ---- Threat Intelligence Analysis (AI'dan önce) ----
    ti_section = ""
    ti_data = {}
    if TI_AVAILABLE:
        try:
            apt_result = match_apt_indicators(results)
            ioc_result = match_iocs(results)
            risk_result = calculate_apt_risk_score(results)

            ti_data = {
                "apt_matches": apt_result.get("apt_matches", []),
                "apt_risk_score": apt_result.get("risk_score", 0),
                "kev_matches": apt_result.get("kev_matches", []),
                "mitre_techniques": apt_result.get("mitre_techniques", []),
                "ioc_patterns": ioc_result.get("port_patterns", []),
                "service_cve_matches": ioc_result.get("service_cve_matches", []),
                "anomalies": ioc_result.get("anomalies", []),
                "calculated_risk": risk_result,
                "recommendations": apt_result.get("recommendations", []),
            }

            # TI bölümünü prompt'a ekle
            ti_lines = ["\n### THREAT INTELLIGENCE ENGINE SONUÇLARI\n"]

            if apt_result["apt_matches"]:
                ti_lines.append(f"**APT Risk Skoru:** {apt_result['risk_score']}/100")
                ti_lines.append(f"**Eşleşen APT Grupları ({len(apt_result['apt_matches'])}):**")
                for m in apt_result["apt_matches"][:5]:
                    ti_lines.append(
                        f"  - **{m['name']}** ({m['origin']}) | "
                        f"Skor: {m['match_score']} | "
                        f"Nedenler: {'; '.join(m['match_reasons'][:3])}"
                    )

            if apt_result["kev_matches"]:
                ti_lines.append(f"\n**CISA KEV Eşleşmeleri ({len(apt_result['kev_matches'])}):**")
                for kev in apt_result["kev_matches"]:
                    ti_lines.append(f"  - 🚨 {kev['cve']} ({kev['name']}): {kev['description']}")

            if ioc_result["port_patterns"]:
                ti_lines.append(f"\n**IOC Port Pattern Eşleşmeleri ({len(ioc_result['port_patterns'])}):**")
                for p in ioc_result["port_patterns"][:5]:
                    ti_lines.append(
                        f"  - {p['name']} | Güven: %{p['confidence']} | "
                        f"Portlar: {p['matched_ports']}"
                    )

            if ioc_result["anomalies"]:
                ti_lines.append(f"\n**Anomaliler ({len(ioc_result['anomalies'])}):**")
                for a in ioc_result["anomalies"]:
                    ti_lines.append(f"  - [{a['severity'].upper()}] {a['description'][:200]}")

            ti_lines.append(f"\n**Hesaplanan Risk Skoru:** {risk_result['score']}/100 ({risk_result['level'].upper()})")
            ti_lines.append(f"**Risk Özeti:** {risk_result['summary']}")

            if apt_result["recommendations"]:
                ti_lines.append(f"\n**TI Önerileri:**")
                for rec in apt_result["recommendations"][:5]:
                    ti_lines.append(f"  - {rec}")

            ti_section = "\n".join(ti_lines)
            logger.info(
                f"TI analysis completed for {scan_id}: "
                f"{len(apt_result['apt_matches'])} APT matches, "
                f"risk={risk_result['score']}/100"
            )

        except Exception as e:
            logger.warning(f"TI analysis failed: {e}")
            ti_section = "\n### THREAT INTELLIGENCE\nTI analizi başarısız oldu.\n"

    # Sonuçları formatla
    formatted = _format_scan_results(results)
    if ti_section:
        formatted = formatted + "\n\n" + ti_section

    # Prompt oluştur
    prompt_text = COMPREHENSIVE_ANALYSIS_PROMPT.format(
        target=target,
        profile=profile,
        scan_results_formatted=formatted,
    )

    # Context tahmini (token)
    context_estimate = len(prompt_text) // 4

    # Task oluştur
    task = SecurityTask(
        task_id=f"scan_analysis_{scan_id}",
        task_type="comprehensive_analysis",
        content={"prompt": prompt_text, "scan_id": scan_id, "target": target},
        requires_privacy=False,
        is_offensive=True,  # APT perspektifi
        context_tokens=context_estimate,
        capabilities_needed=[AICapability.STRATEGY, AICapability.REASONING],
        priority=TaskPriority.HIGH,
        preferred_model=preferred_model,
        allow_fallback=True,  # Bir model çalışmazsa diğerine geç
    )

    try:
        response: AIResponse = await orchestra.route_task(task)

        # Yapılandırılmış veri çıkar
        parsed = _parse_analysis(response.content)

        analysis_result = {
            "scan_id": scan_id,
            "target": target,
            "model_used": response.model,
            "provider": response.provider,
            "analysis_text": response.content,
            "risk_score": parsed.get("risk_score"),
            "executive_summary": parsed.get("executive_summary", ""),
            "critical_findings": parsed.get("critical_findings", []),
            "attack_chain": parsed.get("attack_chain", []),
            "recommendations": parsed.get("recommendations", []),
            "tokens_used": response.tokens_used,
            "cost_estimate": response.cost_estimate,
            "latency_ms": response.latency_ms,
            "analyzed_at": datetime.utcnow().isoformat(),
            # Threat Intelligence data
            "threat_intelligence": ti_data if ti_data else None,
        }

        # TI'dan hesaplanan risk skoru ile AI'ın risk skorunu karşılaştır
        if ti_data and ti_data.get("calculated_risk"):
            ti_score = ti_data["calculated_risk"]["score"]
            ai_score = parsed.get("risk_score", 0) or 0
            # En yüksek skoru kullan (AI küçümseyebilir)
            if ti_score > ai_score:
                analysis_result["risk_score"] = ti_score
                logger.info(
                    f"Risk score overridden: AI={ai_score} → TI={ti_score} "
                    f"(TI daha yüksek risk tespit etti)"
                )

        return analysis_result

    except Exception as e:
        logger.error(f"Scan analysis failed: {scan_id} -> {e}")
        return {
            "scan_id": scan_id,
            "target": target,
            "error": str(e),
            "analysis_text": "",
            "risk_score": None,
            "analyzed_at": datetime.utcnow().isoformat(),
        }


def _parse_analysis(content: str) -> Dict[str, Any]:
    """AI yanıtından yapılandırılmış veri çıkar.

    §2.3: Kırılgan satır-satır regex yerine JSON-önce + sağlam regex fallback'e delege
    edilir (report_parsing.parse_ai_analysis, izole test edilmiş). Eski parser bir cümledeki
    yılı (2026) skor sanabiliyor ya da gerçek skoru kaçırıyor, numaralı listeleri atlıyordu.
    Dönüş anahtar sözleşmesi korunur (risk_score/executive_summary/critical_findings/
    attack_chain/recommendations); ek anahtarlar (technical_details/next_steps) zararsızdır."""
    return parse_ai_analysis(content)
