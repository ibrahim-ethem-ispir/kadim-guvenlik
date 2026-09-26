"""Türkçe: Kapsama Sözleşmesi (coverage_contract) testleri — SAF; ağ YOK.

Kök: motorun 'whack-a-mole' hastalığında bir sınıf sessizce düşüyordu. Bu sözleşme o
sessizliği 'kontrol-edilemedi + neden' olarak GÖRÜNÜR kılar. Testler özellikle kullanıcının
üç şikayetini kanıtlar: (1) JS sessiz-düşüşü (crawl koşmazsa JS girdisiz), (2) K8s if_relevant
kapısı (profil zayıfsa doğrulanamadı), (3) resilience toggle kapalıysa availability hiç ölçülmez.

Çalıştır: python3 orchestrator/pipeline/test_coverage_contract.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.coverage_contract import (  # noqa: E402
    build_coverage, FOUND, CLEAN, NOT_CHECKED,
)


def _status(rep, key):
    for c in rep["classes"]:
        if c["key"] == key:
            return c["status"]
    raise AssertionError(f"sınıf yok: {key}")


def _cls(rep, key):
    for c in rep["classes"]:
        if c["key"] == key:
            return c
    raise AssertionError(f"sınıf yok: {key}")


def test_empty_state_degrade_safe():
    # Boş state → çökmez; her sınıf makul bir 'kontrol-edilemedi' alır; kapsam %0.
    rep = build_coverage({})
    assert rep["total"] == len(rep["classes"]) > 0
    assert rep["found"] == 0 and rep["clean"] == 0
    assert rep["not_checked"] == rep["total"]
    assert rep["coverage_percent"] == 0
    assert len(rep["gaps"]) == rep["total"]


def test_malformed_state_no_crash():
    # Bozuk tipler (None/yanlış tip) çökertmemeli.
    rep = build_coverage({"evidence": None, "meta": "bozuk", "profile": 123,
                          "ran_stages": None, "tried_tools": 5})
    assert rep["total"] > 0


def test_ports_found_vs_clean_vs_notchecked():
    found = build_coverage({"meta": {"open_ports": [80, 443, 22]}})
    assert _status(found, "surface.ports") == FOUND
    clean = build_coverage({"tried_tools": ["nmap"], "meta": {"open_ports": []}})
    assert _status(clean, "surface.ports") == CLEAN
    nc = build_coverage({})
    assert _status(nc, "surface.ports") == NOT_CHECKED


def test_js_secret_silent_drop_is_now_visible():
    # ŞİKAYET 1: crawl koşmadıysa JS girdisiz kalır → 'kontrol-edilemedi', SESSİZ DEĞİL.
    no_crawl = build_coverage({"meta": {"open_ports": [80]}})
    js = _cls(no_crawl, "exposure.js_secrets")
    assert js["status"] == NOT_CHECKED
    assert "girdisiz" in js["reason"] or "hiç incelenmedi" in js["reason"]

    # Crawl koştu, JS sırrı yok → 'temiz' (koştu ama bulmadı — sessiz değil).
    crawl_clean = build_coverage({"ran_stages": ["crawl"], "meta": {"endpoints": ["/a"]}})
    assert _status(crawl_clean, "exposure.js_secrets") == CLEAN

    # JS sırrı bulundu → 'bulundu'.
    js_found = build_coverage({
        "tried_tools": ["crawl"],
        "evidence": [{"tool": "js_secret_scan", "severity": "high", "confidence_tier": "confirmed"}],
    })
    jf = _cls(js_found, "exposure.js_secrets")
    assert jf["status"] == FOUND and jf["confirmed"] is True


def test_kubernetes_if_relevant_gate_reasons():
    # ŞİKAYET 2: K8s tam tespit edilemiyor — nedeni GÖRÜNÜR olmalı.
    # (a) profil hiç K8s dememiş → if_relevant kapalı, doğrulanamadı.
    a = _cls(build_coverage({}), "infra.kubernetes")
    assert a["status"] == NOT_CHECKED and "if_relevant" in a["reason"]

    # (b) profil K8s dedi ama derin prob koşmadı → gecikme/kapı şüphesi (araştır).
    b = _cls(build_coverage({
        "profile": {"facts": {"infra": {"value": "kubernetes", "confidence": 0.9}}},
    }), "infra.kubernetes")
    assert b["status"] == NOT_CHECKED and "araştır" in b["reason"]

    # (c) K8s sinyali zayıf (0.5 < 0.6 eşik) → filtreli port şüphesi.
    c = _cls(build_coverage({
        "profile": {"facts": {"infra": {"value": "kubernetes", "confidence": 0.5}}},
    }), "infra.kubernetes")
    assert c["status"] == NOT_CHECKED and "zayıf" in c["reason"]

    # (d) prob koştu (marker) → temiz.
    d = _cls(build_coverage({"meta": {"k8s_probed": True}}), "infra.kubernetes")
    assert d["status"] == CLEAN

    # (e) kanıt var → bulundu.
    e = _cls(build_coverage({
        "meta": {"k8s_probed": True},
        "evidence": [{"tool": "k8s_probe", "severity": "critical", "confidence_tier": "confirmed"}],
    }), "infra.kubernetes")
    assert e["status"] == FOUND


def test_resilience_toggle_gap_visible():
    # ŞİKAYET (DDoS dersi): toggle kapalıysa availability ekseni HİÇ ölçülmez — görünür olmalı.
    off = _cls(build_coverage({}), "availability.resilience")
    assert off["status"] == NOT_CHECKED and "toggle" in off["reason"]

    on_clean = _cls(build_coverage({"resilience_enabled": True}), "availability.resilience")
    assert on_clean["status"] == CLEAN

    on_found = _cls(build_coverage({
        "resilience_enabled": True,
        "evidence": [{"tool": "resilience_probe", "severity": "medium"}],
    }), "availability.resilience")
    assert on_found["status"] == FOUND


def test_dast_recon_level_vs_no_endpoints():
    recon = _cls(build_coverage({"level": "recon"}), "vuln.dast")
    assert recon["status"] == NOT_CHECKED and "Keşif" in recon["reason"]

    no_eps = _cls(build_coverage({"level": "standard", "meta": {"endpoints": []}}), "vuln.dast")
    assert no_eps["status"] == NOT_CHECKED and "girdisi yok" in no_eps["reason"]

    clean = _cls(build_coverage({"level": "standard", "meta": {"endpoints": ["/x?id=1"]}}), "vuln.dast")
    assert clean["status"] == CLEAN

    found = _cls(build_coverage({
        "level": "deep", "meta": {"endpoints": ["/x?id=1"]},
        "evidence": [{"tool": "poc_verify", "severity": "high", "verified": True}],
    }), "vuln.dast")
    assert found["status"] == FOUND and found["confirmed"] is True


def test_origin_exposure_semantics():
    # CDN arkasında + gerçek IP ifşa → bu bir BULGU (kötü).
    exposed = _cls(build_coverage({"meta": {"is_behind_cdn": True, "real_ip": "1.2.3.4"}}),
                   "surface.origin_exposure")
    assert exposed["status"] == FOUND
    # CDN arkasında + IP gizli → temiz (iyi duruş).
    hidden = _cls(build_coverage({"meta": {"is_behind_cdn": True}}), "surface.origin_exposure")
    assert hidden["status"] == CLEAN


def test_coverage_percent_and_gaps_math():
    rep = build_coverage({
        "meta": {"open_ports": [80], "endpoints": ["/a"], "k8s_probed": True},
        "ran_stages": ["crawl", "nmap"],
        "tried_tools": ["nmap", "crawl", "nuclei"],
    })
    checked = rep["found"] + rep["clean"]
    assert rep["coverage_percent"] == round(checked / rep["total"] * 100)
    assert len(rep["gaps"]) == rep["not_checked"]
    # gaps her zaman neden içerir (eyleme geçirilebilir).
    for g in rep["gaps"]:
        assert g["reason"] and g["label"] and g["key"]


def test_profile_identity_found():
    rep = _cls(build_coverage({
        "profile": {"facts": {"framework": {"value": "wordpress", "confidence": 0.8}},
                    "summary": "framework=wordpress(80%)", "kind": "web"},
    }), "identity.profile")
    assert rep["status"] == FOUND


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
