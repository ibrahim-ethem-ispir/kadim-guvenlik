"""
LLM saldırı hipotezi modeli + parser (attack_hypothesis) testleri — Plan B.

NEDEN: LLM'i "araç seçici"den "saldırı fikri üreticisi"ne çıkarıyoruz — ama LLM çıktısı
GÜVENİLMEZ (halüsinasyon + prompt-injection yüzeyi). Bu parser ham hipotezleri SIKI
doğrular: yalnız http(s) URL, yalnız DOĞRULANABİLİR sınıf (verifier'ın kanıtlayabileceği),
sınırlı sayı, tekilleştirilmiş. Geçersiz olan sessizce düşer (motor asla kör hipoteze güvenmez).

Çalıştır: python3 orchestrator/pipeline/test_attack_hypothesis.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.attack_hypothesis import (
    AttackHypothesis, parse_hypotheses, VERIFIABLE_CLASSES,
    seed_hypotheses_from_endpoints,
)


def test_valid_hypothesis_parsed():
    raw = [{"url": "http://x/item?id=1", "param": "id", "vuln_class": "sqli", "why": "sayısal param"}]
    hyps = parse_hypotheses(raw)
    assert len(hyps) == 1
    h = hyps[0]
    assert isinstance(h, AttackHypothesis)
    assert h.url == "http://x/item?id=1"
    assert h.param == "id"
    assert h.vuln_class == "sqli"
    assert "sayısal" in h.rationale


def test_vuln_class_synonyms_normalized():
    raw = [
        {"url": "http://x?q=1", "vuln_class": "SQL-Injection"},
        {"url": "http://x?q=1", "vuln_class": "sql injection"},
    ]
    hyps = parse_hypotheses(raw)
    # ikisi de 'sqli'ye normalize + aynı URL/param → tekilleşir
    assert all(h.vuln_class == "sqli" for h in hyps)


def test_non_http_url_dropped():
    raw = [
        {"url": "javascript:alert(1)", "vuln_class": "sqli"},
        {"url": "file:///etc/passwd", "vuln_class": "sqli"},
        {"url": "ftp://x/y", "vuln_class": "sqli"},
    ]
    assert parse_hypotheses(raw) == []


def test_unverifiable_class_dropped():
    """Verifier'ın KANITLAYAMAYACAĞI sınıf hipotezleri düşer (kör iddia üretme)."""
    raw = [{"url": "http://x?q=1", "vuln_class": "business-logic"},
           {"url": "http://x?q=1", "vuln_class": "info-leak"},
           {"url": "http://x?q=1", "vuln_class": "ssrf"},   # Grup B — OOB kolektör yok
           {"url": "http://x?q=1", "vuln_class": "idor"}]   # Grup C — oturum motoru yok
    assert parse_hypotheses(raw) == []
    assert "sqli" in VERIFIABLE_CLASSES


# ---- Grup A genişlemesi (lfi / open_redirect / ssti) ----

def test_group_a_classes_accepted():
    """Grup A sınıfları artık doğrulanabilir: lfi, open_redirect, ssti kabul edilir."""
    assert {"sqli", "xss", "lfi", "open_redirect", "ssti"} <= set(VERIFIABLE_CLASSES)
    raw = [
        {"url": "http://x/p?file=a", "param": "file", "vuln_class": "lfi"},
        {"url": "http://x/r?next=/", "param": "next", "vuln_class": "open_redirect"},
        {"url": "http://x/t?name=b", "param": "name", "vuln_class": "ssti"},
    ]
    hyps = parse_hypotheses(raw)
    assert {h.vuln_class for h in hyps} == {"lfi", "open_redirect", "ssti"}


def test_group_a_synonyms_normalized():
    """LLM'in kullanabileceği eşanlamlılar kanonik sınıfa iner."""
    raw = [
        {"url": "http://x?a=1", "vuln_class": "path-traversal"},
        {"url": "http://x?a=2", "vuln_class": "Local File Inclusion"},
        {"url": "http://x?a=3", "vuln_class": "open redirect"},
        {"url": "http://x?a=4", "vuln_class": "unvalidated-redirect"},
        {"url": "http://x?a=5", "vuln_class": "template-injection"},
        {"url": "http://x?a=6", "vuln_class": "server-side-template-injection"},
    ]
    hyps = parse_hypotheses(raw)
    got = [h.vuln_class for h in hyps]
    assert got == ["lfi", "lfi", "open_redirect", "open_redirect", "ssti", "ssti"]


# ---- Kural-tohumu (deterministik, LLM'siz hat) ----

def test_seed_param_name_rules():
    """Parametre adı → sınıf kuralları doğru tohum üretir."""
    eps = [
        "http://x/p?file=home",      # → lfi
        "http://x/r?next=/dash",     # → open_redirect
        "http://x/i?id=42",          # → sqli
        "http://x/s?q=test",         # → xss
        "http://x/t?name=bob",       # → ssti
        "http://x/u?zzz=1",          # kural eşleşmez → tohum yok
    ]
    hyps = seed_hypotheses_from_endpoints(eps)
    got = {(h.vuln_class, h.param) for h in hyps}
    assert got == {("lfi", "file"), ("open_redirect", "next"), ("sqli", "id"),
                   ("xss", "q"), ("ssti", "name")}


def test_seed_first_rule_wins_and_dedup():
    """Aynı URL içinde aynı parametre tekilleşir; 'page' gibi çift-anlamlı adlar ilk
    kurala gider (lfi). Farklı URL dizgileri farklı hipotezdir (pipeline dedup'ı ayrı)."""
    eps = ["http://x/p?page=2&page=3", "http://x/p?page=2"]
    hyps = seed_hypotheses_from_endpoints(eps)
    assert len(hyps) == 2  # URL'ler farklı; aynı URL'deki mükerrer 'page' tekile indi
    assert all(h.vuln_class == "lfi" for h in hyps)


def test_seed_skips_non_http_and_caps():
    """Geçersiz URL atlanır; max_items tavanı uygulanır."""
    eps = ["javascript:x", "ftp://y/z?id=1"] + [f"http://x/i?id={i}" for i in range(50)]
    hyps = seed_hypotheses_from_endpoints(eps, max_items=7)
    assert len(hyps) == 7
    assert all(h.url.startswith("http") for h in hyps)
    # Rationale kural-tohumu olduğunu söyler (LLM hipotezinden ayırt edilebilir).
    assert "kural-tohumu" in hyps[0].rationale


def test_malformed_entries_dropped_not_crash():
    raw = ["düz string", {"vuln_class": "sqli"}, {"url": ""}, None, 42,
           {"url": "http://ok?a=1", "vuln_class": "sqli"}]
    hyps = parse_hypotheses(raw)
    assert len(hyps) == 1
    assert hyps[0].url == "http://ok?a=1"


def test_duplicates_collapsed():
    raw = [
        {"url": "http://x?id=1", "param": "id", "vuln_class": "sqli"},
        {"url": "http://x?id=1", "param": "id", "vuln_class": "sqli"},
    ]
    assert len(parse_hypotheses(raw)) == 1


def test_count_capped():
    raw = [{"url": f"http://x?id={i}", "vuln_class": "sqli"} for i in range(50)]
    hyps = parse_hypotheses(raw, max_items=8)
    assert len(hyps) == 8


def test_non_list_input_safe():
    assert parse_hypotheses(None) == []
    assert parse_hypotheses("not a list") == []
    assert parse_hypotheses({}) == []


def main():
    tests = [
        test_valid_hypothesis_parsed, test_vuln_class_synonyms_normalized,
        test_non_http_url_dropped, test_unverifiable_class_dropped,
        test_malformed_entries_dropped_not_crash, test_duplicates_collapsed,
        test_count_capped, test_non_list_input_safe,
        test_group_a_classes_accepted, test_group_a_synonyms_normalized,
        test_seed_param_name_rules, test_seed_first_rule_wins_and_dedup,
        test_seed_skips_non_http_and_caps,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
