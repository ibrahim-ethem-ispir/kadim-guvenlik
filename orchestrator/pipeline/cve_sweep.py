"""
Kadim Güvenlik — Operatör CVE Süpürmesi (cve_sweep)
===================================================
Türkçe: Mevcut akış 'envanterden CVE'ye' çalışır (hedef tara → sürüm bul → NVD'ye sor →
CVE çıkar). Acil durumda yön TERSTİR: 'CVE'den envantere'. Dün çıkan kritik bir açık için
sorumluluk, kimin etkilendiğini BUGÜN bilmektir — sürüm ifşası beklenemez (expose_php=Off
gibi standart gizlemeler cve_intel'in sürüm hunisini en kritik anda çalıştırmaz).

SÖZLEŞME
--------
Operatör tarama başlatırken CVE id listesi verir:
    POST /api/v2/scan {"target": "...", "profile": "autonomous", "cve_ids": ["CVE-2026-1234"]}

Motor döngüye girmeden ÖNCE her CVE için:
  1. VULNERABILITY düğümü tohumlanır (etiketli, operatör kaynaklı),
  2. kökten düğüme HEDEFLİ nuclei template kenarı eklenir (cve-2026-1234),
  3. vulnx (PDCP) istihbaratından template varlığı/KEV/EPSS okunur; template YOKSA
     dürüst 'advisory' kanıtı yazılır (unconfirmed — manuel triyaj) ve kenar YİNE
     eklenir: template nuclei kütüphanesine sonradan gelirse süpürme kendiliğinden
     çalışır (template güncelleme döngüsü 24 saatte bir tazeler).

Koşum, skor, scope, dedup, kanıt kademesi — hepsi motorun. Bu modül yalnız TOHUMLAR;
determinizmin ve doktrinin (LLM karar vermez) dışına çıkmaz.

SAF: ağ/DB yok. İstihbarat I/O'su wiring katmanında (vulnx_intel.enrich_cves) kalır.
İzole test: test_cve_sweep.py (düz script).
"""

import re
from typing import Any, Dict, List

# 'CVE-2026-1234' veya bare '2026-1234' kabul et; geri kalanı reddet.
_CVE_RE = re.compile(r"^(?:CVE-)?(\d{4}-\d{3,8})$", re.IGNORECASE)


def normalize_cve_ids(raw: Any) -> List[str]:
    """Ham girdiyi kanonik 'CVE-YYYY-NNNN' listesine çevir (SAF).

    Kabul: 'CVE-2026-1234', 'cve-2026-1234', '2026-1234'. Geçersiz öğeler SESSİZCE
    düşer (normalize toleranslıdır); API katmanı katı davranışı isterse validate_cve_ids
    kullanır. Sıra korunur, mükerrer elenir."""
    out: List[str] = []
    for c in (raw or []):
        if isinstance(c, (list, tuple)):
            continue  # iç içe liste anlamsız — düşür
        s = str(c or "").strip().upper()
        m = _CVE_RE.match(s)
        if not m:
            continue
        canon = f"CVE-{m.group(1)}"
        if canon not in out:
            out.append(canon)
    return out


def validate_cve_ids(raw: Any) -> List[str]:
    """API doğrulayıcısı: geçersiz TEK öğe varsa ValueError (sessiz düşürme yok —
    operatör yazım hatasınıFark etmeli; 'cve-20261-23' sessizce yok sayılırsa süpürme
    hiç yapılmamış olur ve operatör bunu bilmez)."""
    raw_list = list(raw or [])
    norm = normalize_cve_ids(raw_list)
    if len(norm) != len(raw_list):
        bad = [str(c) for c in raw_list if str(c or "").strip().upper() not in norm]
        raise ValueError(
            f"cve_ids geçersiz öğe içeriyor: {bad[:3]} — biçim 'CVE-YYYY-NNNN' olmalı")
    return norm


def sweep_plan(cve_ids: List[str], intel_results: Dict[str, Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """CVE listesinden tohumlama planı çıkar (SAF, deterministik).

    intel_results: vulnx enrich_cves 'results' sözlüğü ({cve: slim}). Kayıt YOKSA
    (rate-limit/servis kapalı) konservatif varsayım: template YOK sayılır → advisory
    yazılır; kenar yine eklenir. Bu 'görünür degrade' doktrinidir: sessiz yutma yok,
    ama süpürme de durmaz."""
    intel_results = intel_results or {}
    out: List[Dict[str, Any]] = []
    for cve in (cve_ids or []):
        slim = intel_results.get(cve) or {}
        out.append({
            "cve": cve,
            "template": cve.lower(),                 # nuclei template-id konvansiyonu
            "has_template": bool(slim.get("is_template")),
            "is_kev": bool(slim.get("is_kev")),
            "is_poc": bool(slim.get("is_poc")),
            "severity": (str(slim.get("severity") or "").lower() or "high"),
            "cvss": slim.get("cvss"),
            "epss": slim.get("epss"),
        })
    return out


def advisory_finding(item: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Template'i olmayan CVE için dürüst advisory kanıtı üret (SAF).

    Kademe 'unconfirmed': hedefteki etki HENÜZ kanıtlanmadı; bu kayıt operatörün
    süpürme TALİMATININ ve 'neden otomatik doğrulanamadı'nın kaydıdır. Severity'yi
    istihbarattan (KEV/PoC varsa yükselt) türet — iddia değil, kaynak etiketi."""
    sev = item.get("severity") or "high"
    if item.get("is_kev"):
        sev = "critical"
    elif item.get("is_poc") and sev == "medium":
        sev = "high"
    why = []
    if item.get("is_kev"):
        why.append("CISA KEV üyesi — sahada AKTİF SÖMÜRÜLÜYOR")
    if item.get("is_poc"):
        why.append(f"halka açık PoC mevcut")
    why.append("nuclei template'i henüz kütüphanede yok — otomatik doğrulama yapılamadı")
    return {
        "title": (f"Operatör CVE süpürmesi: {item['cve']} — otomatik doğrulanamadı "
                  f"(template yok){' [KEV]' if item.get('is_kev') else ''}"),
        "severity": sev,
        "cve": item["cve"],
        "target": target,
        "proof": (f"Operatör talimatıyla {item['cve']} kapsam genelinde süpürme istendi. "
                  f"{'; '.join(why)}. Bulgu SÜRÜMDEN ÇIKARILMADI — hedefteki bileşen/sürüm "
                  f"etkileniyor olabileceğinden MANUEL triyaj gerekir (nuclei template'i "
                  f"yayımlandığında tarama kendiliğinden doğrulayacak)."),
        "confidence_tier": "unconfirmed",
        "tool": "cve_sweep",
    }
