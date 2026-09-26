"""Türkçe: K3 — öğrenme döngüsü (scan_memories) birim testleri (SAF; sahte koleksiyon,
gerçek Mongo YOK).

Kök derdimiz: "başkası buldu biz bulamadık." Bu döngü, bir kez görülen (motor/LLM/insan)
yolu KALICI hafızaya alır; sonraki her tarama onu proplar. Testler: kirlenme korkulukları
(kör-200 yazılmaz), tech-eşleşme filtreli okuma, manuel giriş, ≥2 hedefte global terfi.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.path_memory import (  # noqa: E402
    load_learned_paths, record_findings, learn_path_manual,
)


class FakeCol:
    """Minimal in-memory Mongo koleksiyonu: eşitlik-tabanlı find/find_one + insert/replace."""
    def __init__(self):
        self.docs = []

    def find(self, query=None):
        query = query or {}
        return [d for d in self.docs if all(d.get(k) == v for k, v in query.items())]

    def find_one(self, query):
        for d in self.docs:
            if all(d.get(k) == v for k, v in query.items()):
                return d
        return None

    def insert_one(self, doc):
        self.docs.append(doc)

    def replace_one(self, filt, doc, upsert=False):
        for i, d in enumerate(self.docs):
            if all(d.get(k) == v for k, v in filt.items()):
                self.docs[i] = doc
                return
        if upsert:
            self.docs.append(doc)


def test_manuel_giris_sonra_yuklenir():
    """Manuel ekip raporu → kalıcı; sonraki taramada yüklenir (databases.yml boşluğunu kapatır)."""
    c = FakeCol()
    learn_path_manual(c, "/symfony/config/databases.yml", "credential_exposure", "critical",
                      signature={"must_contain_any": ["hostspec", "password"]})
    rows = load_learned_paths(c, ["symfony"])
    paths = [r[0] for r in rows]
    assert "/symfony/config/databases.yml" in rows[0][0] or "/symfony/config/databases.yml" in paths
    row = [r for r in rows if r[0] == "/symfony/config/databases.yml"][0]
    assert row[2] == "critical"
    assert row[3] == "signature" and row[4]["source"] == "memory"
    assert row[4]["signature"]["must_contain_any"] == ["hostspec", "password"]


def test_kor_200_yazilmaz():
    """Güçlü validator geçmeyen (generic/kör-200) bulgu hafızaya YAZILMAZ (kirlenme koruması)."""
    c = FakeCol()
    record_findings(c, [{"path": "/x", "validator": "generic", "severity": "low",
                         "category": "info_disclosure"}], "hedef1")
    assert c.docs == []


def test_guclu_bulgu_yazilir_ve_yuklenir():
    c = FakeCol()
    record_findings(c, [{"path": "/.env", "validator": "env_file", "severity": "critical",
                         "category": "env_exposure"}], "hedef1", techs=["laravel"])
    assert len(c.docs) == 1 and c.docs[0]["source"] == "confirmed_finding"
    rows = load_learned_paths(c, ["laravel"])
    assert any(r[0] == "/.env" for r in rows)


def test_tech_eslesmeyince_yuklenmez():
    """tech-özel öğrenilmiş yol, eşleşmeyen teknolojide YÜKLENMEZ (gürültü/bütçe koruması)."""
    c = FakeCol()
    record_findings(c, [{"path": "/wp-config.php.bak", "validator": "php_config",
                         "severity": "critical", "category": "backup_exposure"}],
                    "hedef1", techs=["wordpress"])
    assert load_learned_paths(c, ["spring"]) == []          # eşleşmez
    assert any(r[0] == "/wp-config.php.bak" for r in load_learned_paths(c, ["wordpress"]))


def test_iki_hedefte_global_terfi():
    """≥2 farklı hedefte doğrulanan yol → tech=[] (global): her hedefte aranır."""
    c = FakeCol()
    f = [{"path": "/.git/config", "validator": "git_config", "severity": "high",
          "category": "vcs_exposure"}]
    record_findings(c, f, "hedef1", techs=["php"])
    record_findings(c, f, "hedef2", techs=["php"])
    doc = c.find_one({"path": "/.git/config"})
    assert doc["tech"] == []                                  # global terfi
    assert doc["hit_count"] == 2
    # global olduğu için alakasız tech'te bile yüklenir
    assert any(r[0] == "/.git/config" for r in load_learned_paths(c, ["dotnet"]))


def test_load_cap():
    c = FakeCol()
    for i in range(80):
        learn_path_manual(c, f"/p{i}.conf", "config_exposure", "high",
                          signature={"must_contain_any": ["k"]})
    assert len(load_learned_paths(c, [], cap=50)) == 50


def main():
    tests = [
        test_manuel_giris_sonra_yuklenir,
        test_kor_200_yazilmaz,
        test_guclu_bulgu_yazilir_ve_yuklenir,
        test_tech_eslesmeyince_yuklenmez,
        test_iki_hedefte_global_terfi,
        test_load_cap,
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
    print("\nTüm K3 testleri geçti.")


if __name__ == "__main__":
    main()
