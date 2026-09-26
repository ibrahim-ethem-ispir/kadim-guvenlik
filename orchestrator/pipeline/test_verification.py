"""
PoC doğrulama — zaman-tabanlı blind SQLi doğrulayıcı (verification) testleri.

NEDEN: "Tarayıcı"yı "pentester"dan ayıran şey KANITLANMIŞ sömürüdür. nuclei "template
eşleşti" der (tahmin); biz aktif olarak SLEEP(N) enjekte edip yanıt süresinin enjekte
edilen gecikmeyle TUTARLI arttığını ölçeriz → false-positive ölür, bulgu 'verified' olur.
Bu testler zamanlama-karar çekirdeğini pinler (I/O değil — saf, jitter'a dayanıklı olmalı).

Çalıştır: python3 orchestrator/pipeline/test_verification.py
"""

import asyncio
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.verification import (
    TimingSample, confirm_time_based_sqli, looks_like_sqli, build_injected_urls,
    _marker_reflected_unescaped, _reflected_xss_marker,
    detect_lfi_signature, is_open_redirect_location, ssti_arithmetic_evaluated,
    evidence_meta_for, CLASS_EVIDENCE_META, _replace_param_urls,
    detect_sqli_error_signature, confirm_boolean_sqli,
    extract_sqli_error_value, parse_union_extracted,
    verify_error_based_sqli, verify_union_extraction,
)
from pipeline.attack_hypothesis import VERIFIABLE_CLASSES


# ---- confirm_time_based_sqli (zamanlama kararı) ----

def test_clear_sqli_confirmed():
    """Kontrol ~200ms, SLEEP(5) ~5300ms → net gecikme yansıması → DOĞRULANDI."""
    samples = [
        TimingSample(0, 200), TimingSample(0, 220),
        TimingSample(5, 5300), TimingSample(5, 5250),
    ]
    v = confirm_time_based_sqli(samples)
    assert v.verified is True


def test_slow_jittery_server_not_confirmed():
    """Server zaten yavaş/dalgalı (kontrol ~4000ms), gecikme farkı küçük → FALSE POSITIVE ELENİR."""
    samples = [
        TimingSample(0, 4000), TimingSample(0, 4200),
        TimingSample(5, 4300),
    ]
    v = confirm_time_based_sqli(samples)
    assert v.verified is False


def test_partial_delay_sufficient_confirmed():
    """Enjekte 5s'nin ~%64'ü yansımış (3200ms > 3000ms eşik) → DOĞRULANDI."""
    samples = [TimingSample(0, 200), TimingSample(5, 3400)]
    v = confirm_time_based_sqli(samples)
    assert v.verified is True


def test_partial_delay_insufficient_not_confirmed():
    """Enjekte 5s'nin sadece ~%36'sı yansımış (1800ms < 3000ms) → DOĞRULANMAZ (temkinli)."""
    samples = [TimingSample(0, 200), TimingSample(5, 2000)]
    v = confirm_time_based_sqli(samples)
    assert v.verified is False


def test_inconsistent_delayed_samples_not_confirmed():
    """Delayed örneklerden biri gecikmeyi göstermiyorsa TUTARSIZ → doğrulanmaz."""
    samples = [TimingSample(0, 200), TimingSample(5, 5300), TimingSample(5, 900)]
    v = confirm_time_based_sqli(samples)
    assert v.verified is False


def test_insufficient_samples_not_confirmed():
    """Kontrol ya da delayed örnek eksikse doğrulama yapılamaz (yetersiz)."""
    v = confirm_time_based_sqli([TimingSample(0, 200), TimingSample(0, 210)])
    assert v.verified is False


# ---- looks_like_sqli (hangi bulguyu doğrulayacağız?) ----

def test_looks_like_sqli_cwe_and_title():
    assert looks_like_sqli({"cwe": ["CWE-89"], "title": "x"}) is True
    assert looks_like_sqli({"title": "SQL Injection in /login"}) is True
    assert looks_like_sqli({"title": "Blind SQLi on id param"}) is True


def test_looks_like_sqli_negatives():
    assert looks_like_sqli({"title": "Reflected XSS", "cwe": ["CWE-79"]}) is False
    assert looks_like_sqli({"title": "Open redirect"}) is False


# ---- build_injected_urls (payload'u nereye sokacağız?) ----

def test_build_injected_urls_per_param():
    urls = build_injected_urls("http://x/a?id=1&q=2", "PAY")
    assert "http://x/a?id=1PAY&q=2" in urls
    assert "http://x/a?id=1&q=2PAY" in urls
    assert len(urls) == 2


def test_build_injected_urls_no_params_empty():
    """Sorgu parametresi yoksa enjeksiyon noktası tahmin etme — boş dön."""
    assert build_injected_urls("http://x/a", "PAY") == []


# ---- Faz 1f: reflected XSS karar çekirdeği (saf, I/O yok) ----

def test_marker_benzer_her_cagri():
    """Marker her çağrıda farklı olmalı — stale reflection tespiti engellemek için."""
    m1 = _reflected_xss_marker()
    m2 = _reflected_xss_marker()
    assert m1 != m2
    # Her marker güvenli etiket `<x>` içeriyor (tarayıcıda zararsız).
    assert "<x>" in m1 and "<x>" in m2


def test_marker_unescaped_reflection_detected():
    """Sunucu marker'i escape etmeden yansıttı → verified XSS."""
    marker = "Kad1mXssabc123<x>"
    body = f"<html>Merhaba {marker} başka içerik</html>"
    assert _marker_reflected_unescaped(marker, body) is True


def test_marker_escaped_not_detected():
    """Sunucu `<` `>` yerine &lt;&gt; koydu → escape sağlam → DOĞRULANMAZ."""
    marker = "Kad1mXssabc123<x>"
    body = "Merhaba Kad1mXssabc123&lt;x&gt; başka içerik"
    # Türkçe: marker TAM haliyle geçmez (escape edilmiş),escape'li hali geçer → False.
    assert _marker_reflected_unescaped(marker, body) is False


def test_marker_missing_body_not_detected():
    """Marker gövdede hiç geçmiyor → False."""
    assert _marker_reflected_unescaped("Kad1mXssyyy<x>", "hiç alakasız içerik") is False
    assert _marker_reflected_unescaped("x", "") is False


# ---- Grup A: LFI imza çekirdeği (saf, I/O yok) ----

def test_lfi_passwd_signature_detected():
    """/etc/passwd içeriği yansıdı → imza bulunur."""
    body = "<html>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:</html>"
    assert detect_lfi_signature(body) == "etc_passwd"


def test_lfi_win_ini_signature_detected():
    body = "; for 16-bit app support\n[extensions]\n[fonts]\nmci extensions"
    assert detect_lfi_signature(body) == "win_ini"


def test_lfi_php_filter_source_detected():
    """php://filter base64 çıktısı çözülünce <?php içeriyor → kaynak kod ifşası."""
    import base64 as _b64
    blob = _b64.b64encode(b"<?php $db = new PDO('mysql:host=db'); ?>" * 3).decode()
    assert detect_lfi_signature(f"<pre>{blob}</pre>") == "php_filter_source"


def test_lfi_static_page_no_signature():
    """Normal sayfa içeriğinde imza YOK → None (false-positive üretme)."""
    assert detect_lfi_signature("<html><body>Merhaba dünya</body></html>") is None
    assert detect_lfi_signature("") is None
    assert detect_lfi_signature("root kullanıcısı hakkında yazı — imza değil") is None


# ---- Grup A: Open Redirect Location eşleşmesi (saf, I/O yok) ----

def test_open_redirect_sentinel_accepted():
    """Location sentinel host'a çözülüyor → True (tüm varyantlar)."""
    assert is_open_redirect_location("https://kadim-oob.invalid/abc") is True
    assert is_open_redirect_location("//kadim-oob.invalid/abc") is True
    assert is_open_redirect_location("https:kadim-oob.invalid/abc") is True
    assert is_open_redirect_location("http://sub.kadim-oob.invalid/x") is True
    # Tarayıcılar backslash önekini de yetkili gibi işler — normalize edilmeli.
    assert is_open_redirect_location("/\\kadim-oob.invalid/abc") is True
    assert is_open_redirect_location("\\\\kadim-oob.invalid\\abc") is True


def test_open_redirect_non_sentinel_rejected():
    """Hedefin kendi domain'i veya başka harici host → False."""
    assert is_open_redirect_location("/local/path") is False
    assert is_open_redirect_location("https://hedef.com/dashboard") is False
    assert is_open_redirect_location("https://evil.com/kadim-oob.invalid") is False
    assert is_open_redirect_location("https://not-kadim-oob.invalid.evil.com/x") is False
    assert is_open_redirect_location("") is False


# ---- Grup A: SSTI aritmetik çekirdeği (saf, I/O yok) ----

def test_ssti_evaluated_detected():
    """Çarpım VAR, ham ifade YOK → şablon motoru değerlendirdi."""
    body = "<html>Sonuç: 1787569 — teşekkürler</html>"
    assert ssti_arithmetic_evaluated(body, 1787569, "1337*1337") is True


def test_ssti_raw_reflected_not_evaluated():
    """Ham ifade de yansıyorsa sunucu değerlendirmiyor → güvenli."""
    body = "<html>Girdi: {{1337*1337}} olduğu gibi görünüyor 1787569</html>"
    # Ham ifade metni (1337*1337) gövdede → değerlendirme YOK sayılır.
    assert ssti_arithmetic_evaluated(body, 1787569, "1337*1337") is False


def test_ssti_no_product_not_detected():
    assert ssti_arithmetic_evaluated("alakasız içerik", 1787569, "1337*1337") is False
    assert ssti_arithmetic_evaluated("", 1787569, "1337*1337") is False


# ---- Ortak: parametre DEĞİŞTİRME (LFI/redirect payload'u değeri ezer, eklemez) ----

def test_replace_param_urls_replaces_value():
    urls = _replace_param_urls("http://x/a?file=home&q=2", "PAY")
    assert "http://x/a?file=PAY&q=2" in urls
    assert "http://x/a?file=home&q=PAY" in urls


def test_replace_param_urls_only_param():
    """LLM'in hedeflediği parametre verilirse YALNIZ o değiştirilir."""
    urls = _replace_param_urls("http://x/a?file=home&q=2", "PAY", only_param="file")
    assert urls == ["http://x/a?file=PAY&q=2"]


def test_replace_param_urls_touch_cap():
    """Kör taramada mutasyon max_params ile tavanlı — ama URL'nin GERİ KALANI korunur
    (dokunuş bütçesi: payload × parametre istek patlamasın)."""
    url = "http://x/a?" + "&".join(f"p{i}={i}" for i in range(10))
    urls = _replace_param_urls(url, "PAY", max_params=3)
    assert len(urls) == 3
    # 4. parametre hâlâ URL'de (silinmedi), sadece mutasyona uğramadı.
    assert all("p3=3" in u and "p9=9" in u for u in urls)
    # only_param verilirse tavan uygulanmaz (hedefli tek atış).
    urls2 = _replace_param_urls(url, "PAY", only_param="p9")
    assert urls2 == [url.replace("p9=9", "p9=PAY")]


# ---- Madde 3: error-based SQLi imza çekirdeği (saf, I/O yok) ----

def test_sqli_error_mysql_leaks_detected():
    """Veri taşıyan MySQL hataları en yüksek güvenle yakalanır."""
    sig = detect_sqli_error_signature("ERROR 1105 (HY000): XPATH syntax error: '~8.0.32'")
    assert sig and sig[0] == "mysql-xpath-leak" and sig[1] >= 0.9
    sig = detect_sqli_error_signature("Duplicate entry 'kb_users-7' for key 'PRIMARY'")
    assert sig and sig[0] == "mysql-duplicate-leak"
    sig = detect_sqli_error_signature("Unknown column 'usr' in 'field list'")
    assert sig and sig[0] == "mysql-unknown-column"


def test_sqli_error_dialect_families_detected():
    assert detect_sqli_error_signature(
        'pg_query(): ERROR: syntax error at or near "\'" ')[0] == "postgres-syntax"
    assert detect_sqli_error_signature(
        "Msg 156, Level 15, State 1, Line 1")[0] == "mssql-native"
    assert detect_sqli_error_signature(
        "Unclosed quotation mark after the character string '' ")[0] == "mssql-quotation"
    assert detect_sqli_error_signature(
        "Conversion failed when converting the varchar value '8.00.1234' to data type int"
    )[0] == "mssql-conversion-leak"
    assert detect_sqli_error_signature("ORA-01756: quoted string not properly terminated"
                                       )[0] == "oracle-ora"
    assert detect_sqli_error_signature(
        "Warning: SQLite3::query(): Unable to prepare statement: near '\"': syntax error"
    )[0] == "sqlite"
    assert detect_sqli_error_signature(
        "java.sql.SQLSyntaxErrorException: bad grammar")[0] == "generic-sqlstate"


def test_sqli_error_benign_body_no_signature():
    """Sıradan içerik / prose'ta 'sql' kelimesi → imza YOK (FP üretme)."""
    assert detect_sqli_error_signature("<html>Hoş geldiniz — ürünler burada</html>") is None
    assert detect_sqli_error_signature("SQL kursu: kayıt formu doldurun") is None
    assert detect_sqli_error_signature("") is None


def test_boolean_sqli_stable_difference_confirmed():
    t = ["<div>toplam 42 kayıt listelendi</div>"] * 2
    f = ["<div>toplam 0 kayıt listelendi</div>"] * 2
    ok, detail = confirm_boolean_sqli(t, f)
    assert ok and "boolean-based" in detail


def test_boolean_sqli_dynamic_content_not_confirmed():
    """Dinamik içerik (token/timestamp) kararlılığı bozar → FN kabul, FP ASLA."""
    t = ["<div>kayıt token=abc1</div>", "<div>kayıt token=def2</div>"]
    f = ["<div>boş</div>", "<div>boş</div>"]
    ok, _ = confirm_boolean_sqli(t, f)
    assert ok is False


def test_boolean_sqli_identical_bodies_not_confirmed():
    b = ["<div>aynı içerik her durumda</div>"]
    ok, _ = confirm_boolean_sqli(b * 2, b * 2)
    assert ok is False


def test_boolean_sqli_insufficient_measurements():
    assert confirm_boolean_sqli([None, "x"], ["y", "y"])[0] is False
    assert confirm_boolean_sqli(["a"], ["b"])[0] is False


# ---- Madde 3: LFI yeni imzaları (saf) ----

def test_lfi_proc_environ_signature_detected():
    # /proc/self/environ gerçek biçimi: NUL ile ayrılmış KEY=VALUE çiftleri.
    body = "PATH=/usr/local/bin:/usr/bin\x00HOME=/var/www\x00PWD=/srv/app"
    assert detect_lfi_signature(body) == "proc_environ"
    # Tek başına PATH= statik dokümanda da geçer → çift şart FP kırpar:
    assert detect_lfi_signature("Bu makalede PATH= değişkeni anlatılıyor") is None


def test_lfi_access_log_signature_detected():
    body = '10.0.0.5 - - [24/Sep/2026:10:15:32 +0300] "GET /index.php HTTP/1.1" 200 512'
    assert detect_lfi_signature(body) == "access_log"
    assert detect_lfi_signature("dün 10.0.0.5 adresinden giriş oldu") is None


def test_lfi_boot_ini_signature_detected():
    body = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS"
    assert detect_lfi_signature(body) == "boot_ini"


# ---- Sınıf → Evidence metadata tablosu ----

def test_class_evidence_meta_covers_all_verifiable():
    """Doğrulanabilir HER sınıfın metadata'sı olmalı — hardcode SQLi felaketi dönmesin."""
    for vc in VERIFIABLE_CLASSES:
        meta = CLASS_EVIDENCE_META[vc]
        assert "{url}" in meta["title"] and meta["severity"] and meta["cwe"]


def test_evidence_meta_unknown_class_fallback():
    """Bilinmeyen sınıf SQLi etiketi ALMAZ — güvenli varsayılan döner."""
    meta = evidence_meta_for("gelecekteki-sinif")
    assert "{class}" in meta["title"] and meta["cwe"] == []
    assert evidence_meta_for("lfi")["severity"] == "high"
    assert evidence_meta_for("open_redirect")["severity"] == "medium"


# ---- sızan değer çözümlemesi + UNION veri çekimi (kanıt derinliği) ----

def test_sqli_error_value_version_shown_identity_masked():
    v = extract_sqli_error_value(
        "You have an error... Duplicate entry '5.7.44-log' for key 'group_key'")
    assert v and v[1] == "5.7.44-log"          # sürüm → AÇIK (sır değil, kanıt gerekli)
    v2 = extract_sqli_error_value("XPATH syntax error: '~root@db~' near '/'")
    assert v2 and v2[1].startswith("roo") and "***" in v2[1]   # kimlik → MASKELİ
    assert "root@db" not in v2[1]
    assert extract_sqli_error_value("masum metin, hata yok") is None


def test_parse_union_extracted():
    b = "header Kad1mUabcS5.7.44|root@dbKad1mUabcE footer"
    assert parse_union_extracted(b, "Kad1mUabcS", "Kad1mUabcE") == ["5.7.44", "root@db"]
    assert parse_union_extracted("marker yok", "Kad1mUabcS", "Kad1mUabcE") is None
    assert parse_union_extracted("", "a", "b") is None


def test_verify_error_based_sqli_value_in_proof():
    def handler(request):
        from urllib.parse import unquote
        if "EXTRACTVALUE" in unquote(str(request.url)):
            return httpx.Response(500, text="XPATH syntax error: '~5.8.31~' near '/'")
        return httpx.Response(200, text="normal ürün sayfası")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    v = asyncio.run(verify_error_based_sqli("https://h.test/x?id=1", client))
    assert v.verified is True
    assert "5.8.31" in v.detail and "sızan değer" in v.detail   # kanıt derinleşti
    asyncio.run(client.aclose())


def test_verify_union_extraction_reads_data():
    def handler(request):
        from urllib.parse import unquote_plus
        u = unquote_plus(str(request.url))
        if "UNION SELECT" not in u:
            return httpx.Response(200, text="<html>ürün listesi</html>")
        import re as _re
        ms = _re.search(r"(Kad1mU[0-9a-f]+S)", u)
        me = _re.search(r"(Kad1mU[0-9a-f]+E)", u)
        if ms and me:
            return httpx.Response(
                200, text=f"<html>{ms.group(1)}5.7.44-log|root@localhost{me.group(1)}</html>")
        return httpx.Response(200, text="<html>ürün listesi</html>")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    v = asyncio.run(verify_union_extraction("https://h.test/list?id=1", client))
    assert v.verified is True and v.method == "union-data-extraction"
    assert "5.7.44-log" in v.detail                    # sürüm açık kanıt
    assert "root@localhost" not in v.detail            # kimlik maskeli
    assert "roo***" in v.detail
    assert v.confidence >= 0.9
    asyncio.run(client.aclose())


def test_verify_union_extraction_no_marker_not_confirmed():
    def handler(request):
        return httpx.Response(200, text="<html>normal sayfa</html>")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    v = asyncio.run(verify_union_extraction("https://h.test/list?id=1", client))
    assert v.verified is False and v.method == "union-data-extraction"
    asyncio.run(client.aclose())


def main():
    tests = [
        test_clear_sqli_confirmed, test_slow_jittery_server_not_confirmed,
        test_partial_delay_sufficient_confirmed, test_partial_delay_insufficient_not_confirmed,
        test_inconsistent_delayed_samples_not_confirmed, test_insufficient_samples_not_confirmed,
        test_looks_like_sqli_cwe_and_title, test_looks_like_sqli_negatives,
        test_build_injected_urls_per_param, test_build_injected_urls_no_params_empty,
        test_marker_benzer_her_cagri, test_marker_unescaped_reflection_detected,
        test_marker_escaped_not_detected, test_marker_missing_body_not_detected,
        test_lfi_passwd_signature_detected, test_lfi_win_ini_signature_detected,
        test_lfi_php_filter_source_detected, test_lfi_static_page_no_signature,
        test_open_redirect_sentinel_accepted, test_open_redirect_non_sentinel_rejected,
        test_ssti_evaluated_detected, test_ssti_raw_reflected_not_evaluated,
        test_ssti_no_product_not_detected,
        test_replace_param_urls_replaces_value, test_replace_param_urls_only_param,
        test_replace_param_urls_touch_cap,
        test_sqli_error_mysql_leaks_detected, test_sqli_error_dialect_families_detected,
        test_sqli_error_benign_body_no_signature,
        test_boolean_sqli_stable_difference_confirmed,
        test_boolean_sqli_dynamic_content_not_confirmed,
        test_boolean_sqli_identical_bodies_not_confirmed,
        test_boolean_sqli_insufficient_measurements,
        test_lfi_proc_environ_signature_detected, test_lfi_access_log_signature_detected,
        test_lfi_boot_ini_signature_detected,
        test_class_evidence_meta_covers_all_verifiable,
        test_evidence_meta_unknown_class_fallback,
        test_sqli_error_value_version_shown_identity_masked,
        test_parse_union_extracted,
        test_verify_error_based_sqli_value_in_proof,
        test_verify_union_extraction_reads_data,
        test_verify_union_extraction_no_marker_not_confirmed,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
