"""
Türkçe: Uyum & güvence katmanı — SAF fonksiyon testleri (düz script, ağ/DB YOK).
Çalıştır: python3 orchestrator/pipeline/test_compliance_map.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline import compliance_map as C  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


def main():
    print("== map_finding: kanonik eşleme ==")
    pi = C.map_finding({"kind": "prompt_injection", "confidence_tier": "confirmed"})
    check("prompt_injection → LLM01", pi["owasp_llm"] == "LLM01")
    check("LLM01 EU Art.15 taşıyor", any(a["article"] == "Art.15" for a in pi["eu_ai_act"]))
    check("NIST MEASURE 2.7 var", any("MEASURE 2.7" in n for n in pi["nist_ai_rmf"]))

    print("== 2023→2025 numaralandırma düzeltmesi ==")
    # llm_redteam tool_abuse'u eskiden LLM08 damgalıyordu; 2025'te Excessive Agency = LLM06.
    ta = C.map_finding({"kind": "tool_abuse", "owasp_llm": "LLM08", "confidence_tier": "confirmed"})
    check("tool_abuse KANONİK LLM06'ya düzeltildi", ta["owasp_llm"] == "LLM06")
    dow = C.map_finding({"kind": "denial_of_wallet"})
    check("denial_of_wallet → LLM10", dow["owasp_llm"] == "LLM10")
    spl = C.map_finding({"kind": "system_prompt_leak"})
    check("system_prompt_leak → LLM07 (2025 ayrı sınıf)", spl["owasp_llm"] == "LLM07")

    print("== AI-dışı bulgu kapsam dışı (yanlış etiketlemez) ==")
    web = C.map_finding({"kind": "sqli", "severity": "high"})
    check("klasik bulgu owasp_llm=None", web["owasp_llm"] is None)

    print("== attest_coverage: durum ekonomisi ==")
    findings = [
        {"kind": "prompt_injection", "confidence_tier": "confirmed", "title": "PI @ /chat"},
        {"kind": "system_prompt_leak", "confidence_tier": "probable", "title": "leak @ /chat"},
    ]
    # Yoklanan kind'ler: PI + system-prompt-leak + output_handling (temiz çıkmış varsay).
    att = C.attest_coverage(findings, tested_kinds=["prompt_injection", "system_prompt_leak", "output_handling"])
    check("LLM01 confirmed", att["classes"]["LLM01"]["status"] == "confirmed")
    check("LLM07 probable", att["classes"]["LLM07"]["status"] == "probable")
    check("LLM05 tested_clean (yoklandı, temiz)", att["classes"]["LLM05"]["status"] == "tested_clean")
    check("LLM06 not_tested (erişilebilir, yoklanmadı)", att["classes"]["LLM06"]["status"] == "not_tested")
    check("LLM04 not_reachable (white-box)", att["classes"]["LLM04"]["status"] == "not_reachable")

    print("== ters-kapsama dürüstlüğü (asıl fark) ==")
    check("gaps_not_tested LLM06 içerir", "LLM06" in att["eu_ai_act"]["gaps_not_tested"])
    check("gaps_not_reachable LLM04 içerir", "LLM04" in att["eu_ai_act"]["gaps_not_reachable"])
    check("confirmed varken posture=fail", att["eu_ai_act"]["posture"] == "fail")

    print("== confirmed yok, not_tested var → 'geçti' DEME ==")
    att2 = C.attest_coverage(
        [{"kind": "output_handling", "confidence_tier": "confirmed", "title": "x"}],
        tested_kinds=["output_handling"],  # sadece bir sınıf yoklandı
    )
    check("output_handling confirmed → fail", att2["eu_ai_act"]["posture"] == "fail")
    att3 = C.attest_coverage([], tested_kinds=["prompt_injection"])  # hiç bulgu, tek sınıf yoklandı
    check("bulgu yok ama boşluk var → inconclusive (pass değil)",
          att3["eu_ai_act"]["posture"] == "inconclusive")

    print("== AI yüzeyi yoksa erişilebilir sınıf not_applicable ==")
    att4 = C.attest_coverage([], tested_kinds=[], ai_surface=False)
    check("ai_surface=False → LLM01 not_applicable",
          att4["classes"]["LLM01"]["status"] == "not_applicable")

    print(f"\n== SONUÇ: {PASS} ok / {FAIL} fail ==")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
