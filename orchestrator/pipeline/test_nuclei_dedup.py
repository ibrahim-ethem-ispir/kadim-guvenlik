"""
Kadim Güvenlik — akıllı tarama: tekrar nuclei tag-taraması eleme testleri.

Adaptif köprü her observe'de biraz farklı tag setiyle nuclei kenarı seed edebiliyor →
imza-dedup yetmiyor, aynı host (nginx) 4 kez taranıyordu (mantıksız israf). Motor artık
tag'leri o hostta ZATEN taranmış olanlarca TÜMÜYLE kapsanan bir tag-taramasını eler.
Yeni tag getiren kenar çalışmaya devam eder; template/dast/cve_sweep dokunulmaz. Düz script.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.autonomous_engine import AutonomousEngine  # noqa: E402
from pipeline.attack_graph import Edge  # noqa: E402


def _engine():
    # Offline: resolve_autonomous_default env'e düşer, ağ/DB gerektirmez.
    return AutonomousEngine(scan_id="t", target="portal.test", target_is_ip=False)


def _nuclei(tags=None, **opts):
    o = dict(opts)
    if tags is not None:
        o["tags"] = tags
    return Edge(from_id="r", to_id="r", tool="nuclei", options=o)


def test_subset_tag_scan_pruned():
    """nginx zaten tarandıysa, salt-nginx tag-taraması elenir (exhausted)."""
    e = _engine()
    e._record_nuclei_tags({"tags": ["nginx", "php"]})
    dup = _nuclei(tags=["nginx"])
    kept = e._prune_redundant_nuclei_tags([dup])
    assert kept == [], "kapsanan tag-taraması elenmedi"
    assert dup.state == "exhausted"
    print("[OK] test_subset_tag_scan_pruned")


def test_new_tag_scan_survives():
    """Yeni tag getiren tarama (apache) elenmez — gerçek yeni kapsam."""
    e = _engine()
    e._record_nuclei_tags({"tags": ["nginx"]})
    fresh = _nuclei(tags=["nginx", "apache"])
    kept = e._prune_redundant_nuclei_tags([fresh])
    assert kept == [fresh], "yeni tag getiren tarama yanlışlıkla elendi"
    print("[OK] test_new_tag_scan_survives")


def test_template_and_dast_not_pruned():
    """template/dast/cve_sweep kenarları tag mantığından ETKİLENMEZ (spesifik taramalar)."""
    e = _engine()
    e._record_nuclei_tags({"tags": ["nginx"]})
    tmpl = _nuclei(templates=["cve-xxx"])                    # tag yok → dokunma
    dast = _nuclei(tags=["nginx"], dast=True)                # dast → dokunma
    sweep = _nuclei(tags=["nginx"], cve_sweep=True)          # cve_sweep → dokunma
    kept = e._prune_redundant_nuclei_tags([tmpl, dast, sweep])
    assert kept == [tmpl, dast, sweep], "spesifik kenarlar yanlışlıkla elendi"
    print("[OK] test_template_and_dast_not_pruned")


def test_per_host_isolation():
    """Bir hostta taranan tag başka hostu ETKİLEMEZ (scan_target ayrımı)."""
    e = _engine()
    e._record_nuclei_tags({"tags": ["nginx"], "scan_target": "a.test"})
    other = _nuclei(tags=["nginx"], scan_target="b.test")   # b.test'te nginx taranmadı
    kept = e._prune_redundant_nuclei_tags([other])
    assert kept == [other], "farklı host taraması yanlışlıkla elendi"
    print("[OK] test_per_host_isolation")


def test_first_scan_runs():
    """Hiç tarama yapılmamışken ilk tag-taraması ELENMEZ (kapsam boş)."""
    e = _engine()
    first = _nuclei(tags=["nginx"])
    assert e._prune_redundant_nuclei_tags([first]) == [first]
    print("[OK] test_first_scan_runs")


def test_record_only_tag_scans():
    """dast/cve_sweep/template taramaları tag kaydına GİRMEZ (yanlış baskılamayı önler)."""
    e = _engine()
    e._record_nuclei_tags({"tags": ["nginx"], "dast": True})
    e._record_nuclei_tags({"templates": ["x"]})
    assert e._nuclei_scanned_tags == {}, e._nuclei_scanned_tags
    print("[OK] test_record_only_tag_scans")


if __name__ == "__main__":
    test_subset_tag_scan_pruned()
    test_new_tag_scan_survives()
    test_template_and_dast_not_pruned()
    test_per_host_isolation()
    test_first_scan_runs()
    test_record_only_tag_scans()
    print("\nTüm testler geçti.")
