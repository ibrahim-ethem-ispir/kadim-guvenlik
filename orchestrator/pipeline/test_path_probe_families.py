"""Türkçe: K1 — yol-ailesi şablon üretimi birim testleri (SAF; I/O yok).

Kök neden: k3 Symfony kombinasyonlarını (apps/frontend/..., apps/backend/...) TEK TEK elle
yazdı — bir hedef için düzeltir, sınıfı için değil. Şablon üretimi {taban}×{app}×{dosya}
kombinasyonunu runtime üretir; kimsenin yazmadığı 'apps/api/...' da kapsanır. Bu testler
şablonun kapsamlı ama sınırlı (bütçe) kaldığını sabitler.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.path_probe import _expand_path_families, PATH_FAMILIES  # noqa: E402


def test_symfony_ailesi_apps_kombinasyonu_uretir():
    rows = _expand_path_families(["symfony 1.4"])   # alt-dize eşleşmesi
    paths = {r[0] for r in rows}
    assert "/symfony/config/databases.yml" in paths
    assert "/config/databases.yml" in paths
    assert "/apps/api/config/databases.yml" in paths       # kimse elle yazmadı
    assert all(r[4]["source"] == "template" for r in rows)  # kaynak etiketi
    assert len(rows) <= 40                                  # aile başına üst sınır


def test_bilinmeyen_tech_bos():
    assert _expand_path_families(["cobol"]) == []
    assert _expand_path_families([]) == []
    assert _expand_path_families(None) == []


def test_kesfedilen_app_eklenir():
    """Kanıttan gelen app adı (crawl/dizin-listeleme) şablona katılır — üretilmiş listeye girmez,
    HEDEFE özel genişler. Kanıt app'leri önce sıralanır (yüksek değer, cap'e kurban gitmez)."""
    rows = _expand_path_families(["symfony"], discovered_apps=["mobil2"])
    paths = {r[0] for r in rows}
    assert "/apps/mobil2/config/databases.yml" in paths


def test_kritik_dosya_cap_altinda_hep_uretilir():
    """Dış döngü DOSYA (severity sırası) → databases.yml TÜM tabanlar için cap'ten önce üretilir."""
    rows = _expand_path_families(["symfony"], per_family_cap=6)
    dbs = [r[0] for r in rows if r[0].endswith("config/databases.yml")]
    # cap=6 küçük olsa bile kritik databases.yml varyantları öncelikli üretilir (en az 6)
    assert len(dbs) >= 5


def test_wordpress_ailesi_yedek_varyantlari():
    rows = _expand_path_families(["WordPress 6.5"])
    paths = {r[0] for r in rows}
    assert "/wp-config.php.bak" in paths


def test_families_hep_5_tuple():
    for fam in PATH_FAMILIES.values():
        for f in fam["files"]:
            assert len(f) == 4  # (file, category, severity, validator) tanımı
    rows = _expand_path_families(["symfony"])
    assert all(len(r) == 5 and isinstance(r[4], dict) for r in rows)


def main():
    tests = [
        test_symfony_ailesi_apps_kombinasyonu_uretir,
        test_bilinmeyen_tech_bos,
        test_kesfedilen_app_eklenir,
        test_kritik_dosya_cap_altinda_hep_uretilir,
        test_wordpress_ailesi_yedek_varyantlari,
        test_families_hep_5_tuple,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"[OK] {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {t.__name__}: {type(e).__name__}: {e}")
    if failed:
        print(f"\n{failed} test BAŞARISIZ.")
        sys.exit(1)
    print("\nTüm şablon testleri geçti.")


if __name__ == "__main__":
    main()
