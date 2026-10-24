"""
Kadim Güvenlik — cve_sweep İZOLE TEST (düz script, pytest yok — repo konvansiyonu).
SAF çekirdek: normalize/validate/sweep_plan/advisory_finding deterministik doğrulanır.

Çalıştır: python3 orchestrator/pipeline/test_cve_sweep.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.cve_sweep import (  # noqa: E402
    advisory_finding, normalize_cve_ids, sweep_plan, validate_cve_ids,
)

_OK = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _OK, _FAIL
    if cond:
        _OK += 1
        print(f"✓ {name}")
    else:
        _FAIL += 1
        print(f"✗ {name} — {detail}")


# ---------- 1) normalize: biçim toleransı + mükerrer + sıra ----------
check("normalize: kanonik biçim",
      normalize_cve_ids(["CVE-2026-1234"]) == ["CVE-2026-1234"])
check("normalize: küçük harf + önek siz",
      normalize_cve_ids(["cve-2026-1234", "2025-98765"]) == ["CVE-2026-1234", "CVE-2025-98765"])
check("normalize: mükerrer elenir, sıra korunur",
      normalize_cve_ids(["CVE-2026-111", "cve-2026-111", "CVE-2026-222"]) == ["CVE-2026-111", "CVE-2026-222"])
check("normalize: çöp sessizce düşer",
      normalize_cve_ids(["CVE-2026-1234", "selam", "", None, "CVE-x"]) == ["CVE-2026-1234"])
check("normalize: boş/None girdi → boş liste",
      normalize_cve_ids(None) == [] and normalize_cve_ids([]) == [])

# ---------- 2) validate: yazım hatası GÖRÜNÜR olur ----------
try:
    validate_cve_ids(["CVE-2026-1234"])
    check("validate: geçerli liste kabul", True)
except ValueError:
    check("validate: geçerli liste kabul", False)
try:
    validate_cve_ids(["CVE-2026-1234", "cve2026-123"])
    check("validate: geçersiz öğe ValueError (sessiz düşürme YOK)", False)
except ValueError as e:
    check("validate: geçersiz öğe ValueError (sessiz düşürme YOK)",
          "cve2026-123" in str(e), f"hata: {e}")

# ---------- 3) sweep_plan: istihbaratlı/konusuz ----------
plan = sweep_plan(["CVE-2026-1234"], {"CVE-2026-1234": {
    "is_template": True, "is_kev": True, "severity": "critical", "cvss": 9.8}})
check("sweep_plan: template id konvansiyonu (küçük harf)",
      plan[0]["template"] == "cve-2026-1234")
check("sweep_plan: istihbarat aktarılır (template/kev/severity)",
      plan[0]["has_template"] is True and plan[0]["is_kev"] is True
      and plan[0]["severity"] == "critical")

plan = sweep_plan(["CVE-2026-9999"], {})
check("sweep_plan: istihbarat YOKSA konservatif — template yok sayılır, severity default",
      plan[0]["has_template"] is False and plan[0]["severity"] == "high",
      f"plan={plan[0]}")

check("sweep_plan: boş liste → boş plan", sweep_plan([], {}) == [])

# ---------- 4) advisory: dürüst kanıt kademesi ----------
adv = advisory_finding(sweep_plan(["CVE-2026-9999"])[0], "hedef.example.com")
check("advisory: template yok → unconfirmed (iddia değil, talimat kaydı)",
      adv["confidence_tier"] == "unconfirmed")
check("advisory: manuel triyaj talimatı kanıtta",
      "MANUEL" in adv["proof"])
check("advisory: CVE ve hedef taşınır",
      adv["cve"] == "CVE-2026-9999" and adv["target"] == "hedef.example.com")

adv = advisory_finding(sweep_plan(["CVE-2026-1234"],
                                  {"CVE-2026-1234": {"is_template": False,
                                                     "is_kev": True,
                                                     "severity": "high"}})[0],
                       "hedef.example.com")
check("advisory: KEV üyesi template'siz de critical + [KEV] etiketi",
      adv["severity"] == "critical" and "[KEV]" in adv["title"])
check("advisory: kanıt 'AKTİF SÖMÜRÜLÜYOR' uyarısı taşır",
      "AKTİF SÖMÜRÜLÜYOR" in adv["proof"])

# ---------- 5) determinizm ----------
p1 = sweep_plan(["CVE-2026-1", "CVE-2026-2"], {"CVE-2026-1": {"is_template": True}})
p2 = sweep_plan(["CVE-2026-1", "CVE-2026-2"], {"CVE-2026-1": {"is_template": True}})
check("sweep_plan deterministik", p1 == p2)

print()
print(f"{'TÜM TESTLER GEÇTİ' if _FAIL == 0 else 'BAŞARISIZ TEST VAR'} — {_OK} ok, {_FAIL} fail")
sys.exit(1 if _FAIL else 0)
