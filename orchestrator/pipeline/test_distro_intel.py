"""Türkçe: Madde 4 — linux_distro_intel testleri. SAF, ağ/DB YOK (statik snapshot repo'da).

Kilit senaryolar:
  • dpkg sürüm kıyası: "4ubuntu0.4" < "4ubuntu0.10" (string kıyası tersini söyler!),
    epoch, '~' ön-sırası.
  • PLANIN BAYRAK VAKASI: os=Ubuntu 20.04 + OpenSSH 8.2p1 (rev 4ubuntu0.4)
    → CVE-2023-48795 (Terrapin) vulnerable, fixed 1:8.2p1-4ubuntu0.10.
  • Yamalı sürüm elemesi (4ubuntu0.10 → Terrapin YOK).
  • release-bilinmez mod: yalnız same-lineage; cross-release FP ÜRETMEMELİ
    (focal banner'ı jammy-only CVE ile eşmemeli).
  • Ubuntu-olmayan hedef → hiç bulgu; snapshot yok → sessiz [].
  • Tier doktrini: revision okunursa 'probable', sadece aday 'unconfirmed'.

Çalıştır: python3 orchestrator/pipeline/test_distro_intel.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.linux_distro_intel import (  # noqa: E402
    analyze_service, analyze_services, build_finding, compare_versions,
    detect_release, resolve_package, banner_revision,
)


def _cve_ids(res):
    return {v["cve"] for v in (res or {}).get("vulnerable", [])}


# ---------------- dpkg sürüm kıyası ----------------

def test_vercmp_revision_sayisal_run():
    """Kalp: '4ubuntu0.4' < '4ubuntu0.10' — string kıyası '>' der (0x34>0x31);
    dpkg run-kıyası sayısal okur. Terrapin tespiti bu satıra bağlı."""
    assert compare_versions("8.2p1-4ubuntu0.4", "8.2p1-4ubuntu0.10") < 0
    assert compare_versions("8.9p1-3ubuntu0.4", "8.9p1-3ubuntu0.10") < 0
    assert compare_versions("1.0-2", "1.0-10") < 0


def test_vercmp_epoch_tilde_esitlik():
    assert compare_versions("2:1.0-1", "1:9.9-1") > 0          # epoch önce
    assert compare_versions("1:8.2p1-4ubuntu0.10", "8.2p1-4ubuntu0.10") > 0  # epoch yok=0
    assert compare_versions("1.0~rc1-1", "1.0-1") < 0          # '~' boştan önce
    assert compare_versions("1.18.0-6ubuntu14.17", "1.18.0-6ubuntu14.17") == 0
    assert compare_versions("1.0", "1.0.1") < 0


# ---------------- çözümleyiciler ----------------

def test_resolve_package_ve_banner():
    assert resolve_package("OpenSSH", "8.2p1") == "openssh"
    assert resolve_package("nginx", "1.18.0") == "nginx"
    assert resolve_package("Apache httpd", "2.4.41") == "apache2"
    assert resolve_package("MySQL", "8.0.35") == "mysql-8.0"
    assert resolve_package("MySQL", "5.7.42") == "mysql-5.7"
    assert resolve_package("PostgreSQL", "12.4") == "postgresql-12"
    assert resolve_package("anything else", "1.0") is None
    assert banner_revision("Ubuntu 4ubuntu0.4") == "4ubuntu0.4"
    assert banner_revision("(Ubuntu)") is None                 # revision yok
    assert banner_revision("protocol 2.0, Ubuntu-4ubuntu0.11") == "4ubuntu0.11"
    assert detect_release("Ubuntu 20.04.6 LTS (GNU/Linux)") == ("focal", "20.04")
    assert detect_release("Windows Server 2019") == (None, None)


# ---------------- planın bayrak vakası: Terrapin ----------------

def test_terrapin_focal_detected():
    """OS=Ubuntu 20.04 + OpenSSH 8.2p1-4ubuntu0.4 → CVE-2023-48795 vulnerable."""
    res = analyze_service("OpenSSH", "8.2p1", "Ubuntu 4ubuntu0.4", "Ubuntu 20.04 LTS")
    assert res is not None
    assert res["release"] == "focal"
    assert "CVE-2023-48795" in _cve_ids(res)
    terr = next(v for v in res["vulnerable"] if v["cve"] == "CVE-2023-48795")
    assert terr["fixed"] == "1:8.2p1-4ubuntu0.10"
    assert terr["status"] == "vulnerable"
    f = build_finding(res, "10.0.0.5:22")
    assert "Ubuntu 20.04" in f["title"] and "CVE-2023-48795" in f["proof"]
    assert "USN" in f["proof"]
    assert f["confidence_tier"] == "probable"      # deterministik kıyas, PoC yok
    assert f["tool"] == "distro_intel"


def test_terrapin_patched_excluded():
    """Kurulu 4ubuntu0.10 == focal fix → Terrapin ARTIK vulnerable değil."""
    res = analyze_service("OpenSSH", "8.2p1", "Ubuntu 4ubuntu0.10", "Ubuntu 20.04 LTS")
    assert "CVE-2023-48795" not in _cve_ids(res)


def test_regresshion_jammy_detected():
    """jammy OpenSSH 8.9p1-3ubuntu0.4 < fix 8.9p1-3ubuntu0.10 → CVE-2024-6387."""
    res = analyze_service("OpenSSH", "8.9p1", "Ubuntu 3ubuntu0.4", "Ubuntu 22.04 LTS")
    assert "CVE-2024-6387" in _cve_ids(res)


# ---------------- release-bilinmez mod: cross-release FP kalkanı ----------------

def test_release_unknown_same_lineage_only():
    """OS yok (default preset'te -O YOK) ama banner 'Ubuntu' taşır:
    same-lineage (8.2p1) CVE yakalanır; jammy/noble-only 8.9p1-hattındaki
    CVE-2024-6387 EŞMEMELİ (cross-release spekülasyon = FP)."""
    res = analyze_service("OpenSSH", "8.2p1", "Ubuntu 4ubuntu0.4", None)
    assert res is not None and res["release"] is None
    assert "CVE-2023-48795" in _cve_ids(res)        # focal hattı, same-lineage ✓
    assert "CVE-2024-6387" not in _cve_ids(res)     # 8.9p1 hattı — eşmemeli


def test_no_revision_release_known_maybe_only():
    """nginx 1.18.0 (Ubuntu), release jammy, revision okunamıyor → SAME-upstream
    kayıtlar 'maybe' (vulnerable DEĞİL) — rapor 'incelenmeli' kovası."""
    res = analyze_service("nginx", "1.18.0", "(Ubuntu)", "Ubuntu 22.04 LTS")
    assert res is not None
    assert res["maybe_count"] >= 15
    # vulnerable yalnız farklı-upstream (cu<0) kayıtlardan gelir; same-lineage girmemeli:
    for v in res["vulnerable"]:
        assert not v["fixed"].startswith("1.18.0"), \
            "revision bilinmezken same-upstream kayıt vulnerable OLAMAZ"


def test_non_ubuntu_and_unknown_product():
    assert analyze_service("OpenSSH", "8.2p1", "Windows", "Windows Server 2019") is None
    assert analyze_service("OpenSSH", "8.2p1", "", None) is None   # Ubuntu işareti yok
    assert analyze_service("WeirdServer", "9.9", "Ubuntu 1.2", "Ubuntu 20.04") is None


def test_analyze_services_batch_and_silence():
    """Toplu giriş: bozuk kayıt atlanır, Ubuntu hedefte bulgu çıkar, target alanı dolar."""
    out = analyze_services(
        [{"product": "OpenSSH", "version": "8.2p1", "extrainfo": "Ubuntu 4ubuntu0.4",
          "port": 22, "host": "10.0.0.5"},
         {"product": "nginx", "version": "1.25.3", "extrainfo": "", "port": 80,
          "host": "10.0.0.5"},
         "bozuk-kayit"],
        "Ubuntu 20.04")
    assert len(out) == 1
    assert out[0]["target"] == "10.0.0.5:22"
    assert out[0]["title"].startswith("Ubuntu 20.04")


def test_snapshot_yok_sağlam_devre():
    """Snapshot boşaltılınca (dosya yok/bozuk simülasyonu) TÜH hatlar sessiz []/None."""
    import pipeline.linux_distro_intel as ldi
    old_cache, old_loaded = ldi._snapshot_cache, ldi._snapshot_loaded
    ldi._snapshot_cache, ldi._snapshot_loaded = {}, True
    try:
        assert analyze_service("OpenSSH", "8.2p1", "Ubuntu 4ubuntu0.4",
                               "Ubuntu 20.04") is None
        assert analyze_services([{"product": "OpenSSH", "version": "8.2p1"}],
                                "Ubuntu 20.04") == []
        assert resolve_package("PostgreSQL", "12.4") is None  # snapshot-siz bilinemez
    finally:
        ldi._snapshot_cache, ldi._snapshot_loaded = old_cache, old_loaded
    # geri yüklendi — plan vakası tekrar çalışır:
    assert "CVE-2023-48795" in _cve_ids(
        analyze_service("OpenSSH", "8.2p1", "Ubuntu 4ubuntu0.4", "Ubuntu 20.04"))


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print(f"\n{len(tests)} test geçti.")


if __name__ == "__main__":
    main()
