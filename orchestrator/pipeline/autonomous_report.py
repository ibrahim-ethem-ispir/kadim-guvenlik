"""
Kadim Güvenlik — Otonom rapor sözleşme köprüsü
==============================================
Türkçe: Otonom motorun DÜZ (flat) kanıt+özet çıktısını, AI analiz servisinin
(scan_analyzer._format_scan_results + threat_intel/ioc_matcher) beklediği
`{tool_name: tool_data}` ŞEKLİNE çevirir — yani statik pipeline ile AYNI sözleşme.

NEDEN (kök-neden düzeltmesi)
----------------------------
`_trigger_autonomous_report` bulguları `scan_data` içinde ÜST SEVİYEDE
(vulnerabilities/findings/open_ports) paketliyordu; ama `analyze_scan_results`
`scan_data["results"]`'i okuyor (scan_analyzer.py). "results" anahtarı olmadığı için
motorun bulduğu HER ŞEY düşüyor, AI raporu BOŞ veriyi analiz ediyordu ("tarama sonrası
analizde patlama" şikâyetinin kök nedeni). Bu modül o sözleşmeyi onarır.

SAF ve BAĞIMSIZ: yalnız stdlib. Ağ/servis/DB bağımlılığı yok → izole test edilebilir.
"""

from typing import Any, Dict, List

# _format_scan_results'ın nuclei severity dağılımında okuduğu anahtarlar (scan_analyzer.py).
_SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "info")


def build_autonomous_scan_results(
    evidence: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Otonom kanıt listesi + motor özetini, AI analizcinin beklediği results şekline çevir.

    Args:
        evidence: Evidence.to_dict() listesi (title/severity/target/cve/... alanları).
        summary:  engine.summary() (graph.summary(): technologies/subdomains/real_ip/
                  is_behind_cdn/... anahtarları).

    Returns:
        {tool_name: tool_data} — statik pipeline'ın ürettiğiyle aynı sözleşme.
        Ne kanıt ne bağlam varsa boş dict (formatter "sonuç bulunamadı" der).
    """
    results: Dict[str, Any] = {}

    # ---- Kanıtlar → nuclei bölümü (raporun çekirdeği) ----
    # _format_scan_results nuclei dalı findings[*]{info:{severity,name}, template-id,
    # matched-at} okur; kanıtları TAM bu şekle map'liyoruz ki bulgular rapora ULAŞSIN.
    #
    # FALSE-POSITIVE ekseni: her bulgu bir confidence_tier taşır (confirmed/probable/
    # unconfirmed). `severity_counts` GERİYE-UYUMLU olarak TÜM bulguları sayar (eski okuyucu
    # bozulmasın), ama ek olarak:
    #   - confirmed_severity_counts: yalnız confirmed+probable (rapor MANŞETİ bunu kullanmalı)
    #   - tier_counts: kademe dağılımı (unconfirmed = "incelenmeli" kovası)
    # Böylece "8 kritik!" yerine "2 kanıtlı kritik, 6 doğrulanmamış (incelenmeli)" denebilir.
    if evidence:
        severity_counts = {bucket: 0 for bucket in _SEVERITY_BUCKETS}
        confirmed_severity_counts = {bucket: 0 for bucket in _SEVERITY_BUCKETS}
        tier_counts = {"confirmed": 0, "probable": 0, "unconfirmed": 0}
        findings: List[Dict[str, Any]] = []
        for ev in evidence:
            sev = str(ev.get("severity") or "info").lower()
            if sev not in severity_counts:
                sev = "info"  # bilinmeyen severity motoru patlatmasın (gürültü değil, info)
            tier = str(ev.get("confidence_tier") or "unconfirmed").lower()
            if tier not in tier_counts:
                tier = "unconfirmed"
            severity_counts[sev] += 1
            tier_counts[tier] += 1
            # Manşet sayımı: unconfirmed'ı SAYMA (olası FP → kritik sayısını şişirmesin).
            if tier in ("confirmed", "probable"):
                confirmed_severity_counts[sev] += 1
            findings.append({
                "info": {
                    "severity": sev,
                    "name": ev.get("title") or "Bilinmeyen bulgu",
                },
                # template-id: önce CVE (varsa), yoksa üreten araç — kör "?" yerine anlamlı.
                "template-id": ev.get("cve") or ev.get("tool") or "autonomous",
                "matched-at": ev.get("target") or "",
                # FALSE-POSITIVE eksenini bulguyla birlikte taşı (AI/rapor/frontend okur).
                "confidence_tier": tier,
                "verified": ev.get("verified"),
                "verification_confidence": ev.get("verification_confidence"),
                # P2/P3 anotasyonları: neden şüpheli (fp_reason) + LLM-hakem ikincil görüşü.
                "fp_reason": ev.get("fp_reason"),
                "llm_fp_opinion": ev.get("llm_fp_opinion"),
                # Kanıt Sözleşmesi — HAFİF sinyal (full bundle'ı LLM bağlamına koyma: token
                # israfı). Yalnız "tekrar-koşulabilir ispat var mı + kimliği ne" bilgisi; full
                # paket Evidence.to_dict() ile detay/DB tarafına akar, replay onunla yapılır.
                "replayable": bool(ev.get("proof_bundle")),
                "proof_fingerprint": ev.get("proof_fingerprint"),
            })
        results["nuclei"] = {
            "findings_count": len(findings),
            "severity_counts": severity_counts,
            "confirmed_severity_counts": confirmed_severity_counts,
            "tier_counts": tier_counts,
            "findings": findings,
        }

    # ---- Özet bağlamı → recon bölümü (LLM'e hedef bağlamı) ----
    # Teknoloji/gerçek-IP/CDN/subdomain motorun keşfettiği yüzeydir; formatter recon dalı
    # bunları okur. Yalnız gerçekten bilgi varsa bölüm ekle (boş recon bölümü üretme).
    technologies = summary.get("technologies") or []
    subdomains = summary.get("subdomains") or []
    real_ip = summary.get("real_ip")
    is_cdn = summary.get("is_behind_cdn", False)
    if technologies or subdomains or real_ip or is_cdn:
        results["recon"] = {
            "is_cloudflare": bool(is_cdn),
            "real_ips": [real_ip] if real_ip else [],
            "domain_ips": [],
            "technologies": technologies,
            "subdomains": subdomains,
        }

    return results
