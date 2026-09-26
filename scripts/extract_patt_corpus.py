#!/usr/bin/env python3
"""
Kadim Güvenlik — PayloadsAllTheThings Corpus Ekstraktörü (tek seferlik, OFFLINE araç)
=====================================================================================
NEDEN: PATT (MIT) zengin payload bilgi tabanıdır ama repo olarak entegre EDİLMEZ:
tahribatlı payload'lar (DROP/OUTFILE/DoS), dış-URL OOB callback'leri (kurumsal ağda
client ağından dışa attacker-infra trafiği = politika ihlali) ve FP seli riski vardır.
Bu script ham markdown'ı bir kez süzer → placeholder-kilitli, tahribatsız, imza-uyumlu
payload'ları `orchestrator/pipeline/data/payloads/<class>.json`'a yazar. Runtime yalnız
SÜZÜLMÜŞ JSON'u okur (pipeline/payload_corpus.py); repoya hiçbir ham PATT dosyası girmez.

Çalıştırma (yalnız geliştirici makinesinde, tarama yığınına bağımlılığı YOK):
    python3 scripts/extract_patt_corpus.py
    python3 scripts/extract_patt_corpus.py --src /yol/patt-klon   # çevrimdışı klon varsa

GÜVENLİK ANTİVİRÜS NOTU: antivirüsler ham PATT klonundaki script-benzeri dosyaları
silebiliyor — bu yüzden VARSAYILAN mod ham dosyaya disk yazmadan, URL'i bellekte
indirip işler. Çıktı yalnız metin JSON'lardır.

Kapı tek kaynak: güvenlik filtresi runtime ile AYNI fonksiyondur
(pipeline.adaptive_payloads._payload_ok — placeholder zorunlu + yıkıcı token reddi).
Script'in ürettiği her girdi runtime'da da aynı kapıdan geçer (savunma derinliği).
"""
import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "orchestrator" / "pipeline" / "data" / "payloads"

# PATT sabit commit — yeniden üretilebilirlik (güncelleme bilinçli olmalı, sessiz değil).
COMMIT = "3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a"
RAW_BASE = f"https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/{COMMIT}/"

sys.path.insert(0, str(ROOT / "orchestrator"))
try:
    # runtime kapısının tek kaynağı — hata-vektör beyazlistesi de AYNI kaynaktan
    # (extractor ile loader/verifier üçgeninde tanım sürüklenmesi olmasın).
    from pipeline.adaptive_payloads import (
        _payload_ok, _SQLI_ERROR_TRIGGERS, _SQLI_ERROR_QUOTES,
    )
except Exception as e:  # pragma: no cover
    print(f"HATA: pipeline.adaptive_payloads import edilemedi: {e}", file=sys.stderr)
    sys.exit(1)

# Bilinen dış OOB/callback domain'leri ve genel egress deseni — XXE/SSRF tarzı harici
# çağrı yapan payload'lar corpus'a ASLA giremez (blanket: payload'da http/https:// yok).
_EXTERNAL_RE = re.compile(r"https?://|//\s*[a-z0-9-]+\.[a-z]", re.I)
_MAX_LEN = 400


# ============================================================
# Kaynak dosyalar (yalnız imzası olan sınıflar — xxe/open_redirect bilinçli dışarıda:
# xxe imzalarımız 3 inline payload'u zaten kapsıyor, PATT türevleri OOB-external istiyor;
# open_redirect'in sentinel-variant listesi sabit, sözlük tüketicisi yok.)
# ============================================================
SQLI_SOURCES = [
    ("mysql", "SQL Injection/MySQL Injection.md"),
    ("postgres", "SQL Injection/PostgreSQL Injection.md"),
    ("mssql", "SQL Injection/MSSQL Injection.md"),
    ("oracle", "SQL Injection/OracleSQL Injection.md"),
    ("generic", "SQL Injection/README.md"),
]
XSS_SOURCES = [
    ("filter-bypass", "XSS Injection/1 - XSS Filter Bypass.md"),
    ("waf-bypass", "XSS Injection/3 - XSS Common WAF Bypass.md"),
    ("polyglot", "XSS Injection/2 - XSS Polyglot.md"),
    ("angular", "XSS Injection/5 - XSS in Angular.md"),
    ("generic", "XSS Injection/README.md"),
]
LFI_SOURCES = [
    ("traversal", "Directory Traversal/README.md"),
    ("inclusion", "File Inclusion/README.md"),
    ("wrappers", "File Inclusion/Wrappers.md"),
]
SQLI_ERROR_SOURCES = [
    # Madde 3: hata-üretici lehçeler — XPATH/duplicate/conversion/quote vektörleri.
    # Bu sınıf ZAMANLAMA İSTEMEZ: kanıt DB hata imzası (verification._SQLI_ERROR_SIGNATURES).
    ("mysql", "SQL Injection/MySQL Injection.md"),
    ("mssql", "SQL Injection/MSSQL Injection.md"),
    ("oracle", "SQL Injection/OracleSQL Injection.md"),
    ("postgres", "SQL Injection/PostgreSQL Injection.md"),
    ("sqlite", "SQL Injection/SQLite Injection.md"),
    ("generic", "SQL Injection/README.md"),
]
SSTI_SOURCES = [
    ("python", "Server Side Template Injection/Python.md"),
    ("java", "Server Side Template Injection/Java.md"),
    ("php", "Server Side Template Injection/PHP.md"),
    ("ruby", "Server Side Template Injection/Ruby.md"),
    ("javascript", "Server Side Template Injection/JavaScript.md"),
    ("asp", "Server Side Template Injection/ASP.md"),
    ("elixir", "Server Side Template Injection/Elixir.md"),
    ("generic", "Server Side Template Injection/README.md"),
]


# ============================================================
# Markdown → aday satırlar (yalnız ``` fence blokları — düz metin/prose elenir)
# ============================================================

_INLINE_CODE_RE = re.compile(r"`([^`\n]{3,})`")


def iter_candidates(md_text: str):
    """Fence blokları (```...```) + fence DIŞINDAKİ satır-üstü `kod` parçaları.
    NEDEN backtick: PATT README'lerde payload'ların bir kısmı prose içine gömülü —
    yalnız fence okumak LFI/SSTI verimini sıfıra yakınsatıyordu."""
    in_block = False
    for line in md_text.splitlines():
        s = line.strip()
        if s.startswith("```"):
            in_block = not in_block
            continue
        if in_block:
            if s:
                yield s
        else:
            for m in _INLINE_CODE_RE.finditer(line):
                c = m.group(1).strip()
                if c:
                    yield c


def dedup_key(payload: str) -> str:
    """İskelet anahtar: tırnaklı içerik ve sayı RUN'ları nötrlenir — DB-adı parmak
    izleme zincirleri (LIKE '___' vs '____') timing-kanıtı açısından AYNI payload'dır;
    iskelet-dedup bütçeyi varyant seliyle şişirmez."""
    k = re.sub(r"'[^']*'", "''", payload)
    k = re.sub(r"\d+", "0", k)
    return re.sub(r"\s+", " ", k).lower()


def fetch_text(rel_path: str, src_dir: Path | None) -> str:
    """Diskten (yerel klon) ya da belleğe indir (varsayılan — ham dosya diske DEĞMEZ)."""
    if src_dir is not None:
        p = src_dir / rel_path
        return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
    from urllib.parse import quote
    url = RAW_BASE + quote(rel_path)
    req = urllib.request.Request(url, headers={"User-Agent": "kadim-corpus-extract"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="replace")


# ============================================================
# Sınıf bazında normalize + filtre
# ============================================================

# sqlmap şablon işaretçileri: [RANDNUM], [INFLECTION], [CHAR...] — BÜYÜK HARF token.
# Madde 3: afaki "[/]" yasağı XSS'i yarı yarıya kırpıyordu (`[document.domain]` gerçek
# payload); yasak yalnız şablon-imza token'larına daraltıldı (allow_brackets).
_SQLMAP_TOKEN_RE = re.compile(r"\[(?:[A-Z][A-Z_]|\d+[,.\-]*)+\]")


def _common_bad(line: str, *, allow_pct: bool = False, allow_brackets: bool = False) -> bool:
    """Sınıf-bağımsız red kuralları: şablon/artifact satırları, egress, uzunluk.
    allow_pct (Madde 3): LFI encoded-variant zenginliği için % afaki olarak reddedilmez —
    içerik zaten sınıf kanarya kontrolünden (_payload_ok lfi) geçmek ZORUNDA, yani %'li
    satır ya passwd/boot.ini/win.ini/proc/self/php://filter taşıyor ya da eleniyor."""
    low = line.lower()
    if len(line) > _MAX_LEN:
        return True
    if allow_brackets:
        if _SQLMAP_TOKEN_RE.search(line):
            return True
    elif "[" in line or "]" in line:
        return True
    if "%" in line and not allow_pct and "php://" not in low:   # url-encode tuzağı (bkz. m_tab_space)
        return True
    if _EXTERNAL_RE.search(line):
        return True
    if any(t in low for t in ("curl ", "sqlmap", "echo ", "import ", "$(", "`python")):
        return True
    return False


_SLEEP_RE = re.compile(r"(?i)\b((?:pg_|dbms_[a-z_]+\.)?sleep)\s*\(\s*(\d+)")
# LAZY ön ek (`[\d:]*?`): greedy olursa '0:0:10' → '0:0:1{D}' kalır (son basamak yemişti).
_WAITFOR_RE = re.compile(r"(?i)(waitfor\s+delay\s*'[\d:]*?)(\d+)(')")
_ORACLE_RE = re.compile(r"(?i)(receive_message\s*\(\s*'[^']*'\s*,\s*)(\d+)")
_QS_PREFIX_RE = re.compile(r"^(?:\?[\w.\[\]-]{1,24}|[A-Za-z][\w.\[\]-]{1,24})=")  # "?id=1 .."/"ProductID=1;.." kalıntısı


def norm_sqli(line: str) -> str | None:
    """Zamanlama argümanını {D}'ye çevir — gecikme runtime'da doldurulur ve İKİNCİ
    ÖLÇEK ORAKLI (2x gecikme) ölçeklenebilsin diye sayı sabiti kabul edilmez."""
    p = line.strip()
    if _common_bad(p) or any(t in p.lower() for t in
                             ("benchmark", "while", "declare", "cursor", "sleep(0)")):
        return None  # benchmark ölçeklenemez (sabit iterasyon); WHILE/DECLARE döngü=DoS
    p = _QS_PREFIX_RE.sub("", p, count=1)
    p2 = _WAITFOR_RE.sub(r"\g<1>{D}\g<3>", p)
    p2 = _ORACLE_RE.sub(r"\g<1>{D}", p2)
    p2 = _SLEEP_RE.sub(lambda m: f"{m.group(1)}({{D}}", p2)
    if "{D}" not in p2 or not _payload_ok(p2, "sqli"):
        return None
    return p2


def norm_sqli_error(line: str) -> str | None:
    """Error-based SQLi normalizatörü (Madde 3): ZAMANLAMA YOK — kanıt DB hata imzası.
    Yalnız BEYAZLİSTE vektörler geçer (XPATH/duplicate/conversion/quote — runtime
    kapısıyla TEK kaynak: adaptive_payloads._SQLI_ERROR_*). Sorgu-ön eki kalıntıları
    temizlenir; {D} normalizasyonu UYGULANMAZ (gecikme yok)."""
    p = line.strip().rstrip(";")
    if _common_bad(p) or "<" in p:
        return None
    p = _QS_PREFIX_RE.sub("", p, count=1).strip()
    low = p.lower()
    if not any(t in low for t in _SQLI_ERROR_TRIGGERS) and p not in _SQLI_ERROR_QUOTES:
        return None
    # Yorum başlangıcı düşür (-- # yorumu payload'un kendisi olabilir; yalnız uzunsа kes).
    if len(p) > 8:
        p = re.split(r"\s+--\s+#|/\*", p, maxsplit=1)[0].strip()
    if not p or not _payload_ok(p, "sqli_error"):
        return None
    return p


_ALERTCALL_RE = re.compile(
    r"(?i)\b(?:top\.|parent\.|window\.)?(?:alert|prompt|confirm|print|eval|atob|fetch)"
    r"(?:\s*\((?:[^()]|\([^()]*\))*\)|\s*`[^`]*`)")
_ALERTWORD_RE = re.compile(r"(?i)\b(?:alert|prompt|confirm)\b(?!\s*[(/`])")


def norm_xss(line: str) -> str | None:
    """JS çalıştırıcı çağrıyı zararsız {MARKER} ile değiştir: vektör ŞEKLİ korunur
    (    WAF/bağlam atlatma değeri orada), yansıma kanıtı zaten marker'ın HAM geçişi."""
    p = line.strip()
    # allow_brackets: XSS sözdizimi köşeli parantez içerir (onerror=[alert]) — afaki
    # yasak yerine yalnız sqlmap-şablon token'ı reddedilir (Madde 3 verim düzeltmesi).
    # Kırpma-bağlamı (breakout): "<" ŞART DEĞİL — tırnak/backtick ile başlayan
    # `" onfocus=... x="` şekilleri PATT filter-bypass'ın ekseriyeti; değerleri bağlam
    # kırma gücü, etiket içermelerinde değil. Marker yansıması yine tek kanıt.
    if _common_bad(p, allow_brackets=True) or len(p) > 300:
        return None
    # `{{` angular gadget'ları ve `javascript:` URI şekilleri de meşru bağlamdır —
    # kanıt her halükarda marker'ın HAM yansıması, vektörün zararsızlığı garantili.
    if "<" not in p and p[0] not in "'\"`{" and not p.lower().startswith("javascript:"):
        return None
    p = _ALERTCALL_RE.sub("{MARKER}", p)
    p = _ALERTWORD_RE.sub("{MARKER}", p)
    if "{MARKER}" not in p or not _payload_ok(p, "xss"):
        return None
    return p


_TRAVERSAL_START = ("../", "..\\", "....//", "..;/", "php://", "/etc/passwd",
                    "etc/passwd", "win.ini", "..\\..",
                    # Madde 3: encoded/alternatif başlangıç token'ları — satır bu
                    # işaretlerden kesilir, prose kalıntısı düşer.
                    "..%2f", "..%252f", "..%5c", "%2e%2e", "%c0%af", "..%c0",
                    "proc/self", "boot.ini", "c:\\", "/var/log")


def norm_lfi(line: str) -> str | None:
    """Satırı ilk traversal/canary token'ından kes — prose/komut kalıntısı düşsün;
    yalnız bilinen zararsız kanaryayı hedefleyen değer kalsın (_payload_ok lfi)."""
    p = line.strip()
    if _common_bad(p, allow_pct=True) or "<" in p or len(p) > 120:
        return None
    low = p.lower()
    idxs = [low.find(t) for t in _TRAVERSAL_START if low.find(t) >= 0]
    if not idxs:
        return None
    val = p[min(idxs):].strip().strip("'\"`")
    if not val or not _payload_ok(val, "lfi"):
        return None
    return val


_SSTI_MUL_RE = re.compile(r"(\d{1,4})\s*\*\s*(\d{1,4})")
_SSTI_ALLOWED = set("{}$#<>%=*[]().! \t~^&|;,-")  # harf/rakam içermeyen saf şablon sözdizimi


_SSTI_DELIMS = ("{{", "${", "#{", "<%", "[[", "[=", "%>", "}}", "}", "]", ">")
# Madde 3: motor-sayfalı PATT satırlarının çoğu çarpımı PROSE içine gömer
# ("Eval: {{7*7}} ve ${7*7} çalışır") — bütün-satırlı red bu derinliği çöpe atıyordu.
# Delim-kavruklu aritmetik TOKEN'ı satırın içinden kazınır; aday yine saf-şablon
# kapısından (_SSTI_ALLOWED) geçer, harf/gadget kalıntısı bulaşamaz.
_SSTI_ARITH_TOKEN_RE = re.compile(
    r"(?:\{\{\{|\{\{|\$\{\{|\$\{|#\{|<%=?|\[\[|\[=)\s*\d{1,4}\s*\*\s*\d{1,4}\s*"
    r"(?:\}\}\}|\}\}|\$\}|%>|\]\]|=])")


def norm_ssti(line: str) -> str | None:
    """Yalnız ARİTMETİK değerlendirmeli saf şablonlar: sayı pairi {A}*{B} olur,
    motoru-kanıtlayan çarpım runtime'da asal sayılarla doldurulur. Harf içeren
    (config dump, gadget) satırları elenir — imza onayı zaten yalnız çarpıma bakar.
    DELIM ZORUNLU: çıplak '7*7' hiçbir motoru kanıtlamaz (salt yansıma FP'si)."""
    p = line.strip()
    if _common_bad(p) or not _SSTI_MUL_RE.search(p):
        return None
    cands = ([p] if len(p) <= 60 else []) + _SSTI_ARITH_TOKEN_RE.findall(p)
    for raw in cands:
        if not any(d in raw for d in _SSTI_DELIMS):
            continue
        cand = _SSTI_MUL_RE.sub("{A}*{B}", raw).strip()
        rest = cand.replace("{A}", "").replace("{B}", "")
        if any(c.isalnum() or (c not in _SSTI_ALLOWED) for c in rest):
            continue
        if not _payload_ok(cand, "ssti"):
            continue
        return cand
    return None


# ============================================================
# Topla → dialct-arası SALLA (interleave) → yaz
# ============================================================
# Interleave NEDEN: runtime merge cap'i listeyi baştan keser; tek dialct öne yığılırsa
# (ör. 30 MySQL satırı) diğer lehçeler hiç denenmez. Dialct sırayla gelirse küçük
# cap'te bile kapsam (mysql+postgres+mssql+oracle) korunur.

_EXTRACTORS = {
    "sqli": (SQLI_SOURCES, norm_sqli, 200),
    "sqli_error": (SQLI_ERROR_SOURCES, norm_sqli_error, 60),
    "xss": (XSS_SOURCES, norm_xss, 350),
    "lfi": (LFI_SOURCES, norm_lfi, 60),
    "ssti": (SSTI_SOURCES, norm_ssti, 30),
}
# Lehçe başına tavan — tek lehçe bütçeyi yutmasın. XSS doğrulayıcıya merge ile GİRMEZ
# (retry/few-shot tüketimi) → geniş; sqli timing hattına girer ama runtime merge
# tavanı (payload_corpus._MERGE_CAPS + PAYLOAD_CORPUS_CAP_*) gerçek keseri yapar —
# corpus derin = çeşitlilik havuzu, tavan dar = dokunuş bütçesi (iki katman ayrı).
_DIALECT_CAPS = {"sqli": 60, "sqli_error": 15, "xss": 120, "lfi": 60, "ssti": 15}

# Madde 3.2 — elle kürateli eklemeler (PATT'te OLMAYAN sınıflar): php://filter zincir
# varyantları, /proc/*, çift-encode/overlong-UTF8 traversal, web log yolları, tırnak
# kırıcılar ve hata-sızıntı oraklları. Kaynak "manual-curated" — yeniden üretimde
# KAYBOLMAZ (build_class bunları ÖNCE yerleştirir, otomatik çıkarım dedup'la süzer).
# expect://, data://, zip:// BİLİNÇLİ YOK: wrapper→RCE sınıfı, tahribatsızlık doktrini.
MANUAL_ADDITIONS: dict[str, list[str]] = {
    "lfi": [
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=.htaccess",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=../../config/database.php",
        "php://filter/resource=/etc/passwd",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/root/etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%25c0%25af..%25c0%25afetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%5c..%5c..%5cboot.ini",
        "..\\..\\..\\boot.ini",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "/var/log/nginx/access.log",
        "....//....//....//var/log/apache2/access.log",
    ],
    "sqli_error": [
        "'", '"', "')", "'-- -", "%27",
        "and extractvalue(1,concat(0x7e,(select database()),0x7e))",
        "and updatexml(1,concat(0x7e,(select user()),0x7e),1)",
        '1" AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@VERSION,FLOOR(RAND(0)*2))x '
        "FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)#",
        "'||dbms_xmlgen.getxml('select user from dual')||'",
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE "
        "ROWNUM=1))-- -",
    ],
}


# Madde 3: bağlam-gramer genişletme. PATT'in zaman/hata tabanlı satır Havuzu GERÇEKTEN
# küçük (iskelet-dedup sonrası ~20); asıl derinlik BAĞLAM X LEHÇE X YORUM çarpımından
# gelir: aynı SLEEP/EXTRACTVALUE vektörü tırnaklı/çift-tırnaklı/parantezli/sayısal bağlamda
# ve farklı yorum-son ekiyle ayrı WAF imzasıdır. Grid deterministiktir (LLM yok), her
# üretim yine runtime kapısından (_payload_ok) geçer.
def _grammar_sqli() -> list[tuple[str, str]]:
    q = "\x27"  # tek tırnak — f-string içinde gömülü tırnak kazası olmasın
    out: list[tuple[str, str]] = []
    for p in (q, '"', ")" + q, ""):
        out += [
            ("mysql", f"{p} AND SLEEP({{D}})-- -"),
            ("mysql", f"{p} AND SLEEP({{D}})#"),
            ("mysql", f"{p} AND SLEEP({{D}})/**/"),
            ("mysql", f"{p} AND (SELECT SLEEP({{D}}))-- -"),
            ("mysql", f"{p} AND SLEEP({{D}})={p}"),
            ("mysql", f"{p} AND (SELECT*FROM(SELECT(SLEEP({{D}})))w)-- -"),
            ("mysql", f"{p} AND SLEEP({{D}})--+-"),
            ("mysql", f"{p} AND SLEEP({{D}})%23"),
        ]
    for p in (q, ""):
        out += [
            ("postgres", f"{p}||pg_sleep({{D}})--"),
            ("postgres", f"{p} AND pg_sleep({{D}})=1 --"),
            ("postgres", f"{p}||pg_sleep({{D}})||{p}"),
            ("postgres", f"{p};SELECT pg_sleep({{D}})--"),
            ("postgres", f"{p} AND (SELECT pg_sleep({{D}}))IS NOT NULL --"),
        ]
    for p in (q, '"', ")" + q, ""):
        out += [
            ("mssql", f"{p}; WAITFOR DELAY {q}0:0:{{D}}{q}--"),
            ("mssql", f"{p} AND 1=1; WAITFOR DELAY {q}0:0:{{D}}{q}--"),
            ("mssql", f"{p}; IF(1=1) WAITFOR DELAY {q}0:0:{{D}}{q}--"),
        ]
    for p in (q, '"', ")" + q, ""):
        out += [
            ("oracle", f"{p} AND DBMS_PIPE.RECEIVE_MESSAGE({q}a{q},{{D}})=1-- "),
            ("oracle", f"{p}||DBMS_PIPE.RECEIVE_MESSAGE({q}a{q},{{D}})||{p}"),
            ("oracle", f"{p} AND (SELECT CASE WHEN (1=1) THEN "
                       f"DBMS_PIPE.RECEIVE_MESSAGE({q}a{q},{{D}}) ELSE 0 END "
                       f"FROM DUAL)=1-- "),
        ]
    return out


def _grammar_sqli_error() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    mysql_exprs = ("VERSION()", "DATABASE()", "USER()")
    for p in ("'", '"'):
        for c in ("-- -", "#"):
            for e in mysql_exprs:
                out.append(("mysql", f"{p} AND EXTRACTVALUE(1,CONCAT(0x7e,{e},0x7e)){c}"))
                out.append(("mysql", f"{p} AND UPDATEXML(1,CONCAT(0x7e,{e},0x7e),1){c}"))
    for p in ("'", '"'):
        out.append(("mssql", f"{p} AND 1=CAST(@@version AS INT)-- -"))
        out.append(("mssql", f"{p} AND 1=CONVERT(INT,DB_NAME())-- -"))
        out.append(("mssql", f"{p} AND 1=CAST(DB_NAME() AS INT)#"))
    return out


def _grammar_ssti() -> list[tuple[str, str]]:
    # Motor delim grid'i — PATT'in motor sayfaları hep AYNI aritmetik shape'i kullanır;
    # gerçek çeşitlilik delim'de. Küme parantezi bolluğu f-string ile DEĞİL, bilinçli
    # birleştirme ile kurulur (okunabilirlik + {A}/{B} bozulmasın).
    ab = "{A}*{B}"
    pairs = [("{{", "}}"), ("{{{", "}}}"), ("${{", "}}"),
             ("${", "}"), ("#{", "}"), ("<%=", "%>"), ("<%", "%>"),
             ("[[", "]]"), ("[=", "=]")]
    return [("engine", open_ + ab + close) for open_, close in pairs]


_GRAMMAR: dict[str, list[tuple[str, str]]] = {
    "sqli": _grammar_sqli(),
    "sqli_error": _grammar_sqli_error(),
    "ssti": _grammar_ssti(),
}


def _manual_ok(p: str, klass: str) -> bool:
    """Manuel girdi korkuluğu: runtime kapısı + egress yasağı (PATT kuralıyla aynı).
    Elle yazılan payload DA aynı süzgeçten geçer — doktrin 'elle dokunuş kapıyı aşmaz'."""
    if not p or len(p) > _MAX_LEN or _EXTERNAL_RE.search(p):
        return False
    return _payload_ok(p, klass)


def build_class(klass: str, src_dir: Path | None):
    sources, normalizer, cap = _EXTRACTORS[klass]
    dialect_cap = _DIALECT_CAPS.get(klass, 10)
    per_dialect: dict[str, list[dict]] = {}
    order: list[str] = []
    for dialect, rel in sources:
        try:
            text = fetch_text(rel, src_dir)
        except Exception as e:
            print(f"UYARI: {rel} okunamadı ({e}) — atlanıyor", file=sys.stderr)
            continue
        bucket = per_dialect.setdefault(dialect, [])
        if dialect not in order:
            order.append(dialect)
        seen_local = set()
        for raw in iter_candidates(text):
            if len(bucket) >= dialect_cap:
                break
            norm = normalizer(raw)
            if not norm:
                continue
            key = dedup_key(norm)
            if key in seen_local:
                continue
            seen_local.add(key)
            bucket.append({"payload": norm, "dialect": dialect, "source": rel})
    out, seen = [], set()
    # Manuel kürateli ÖNCE (kapıdan geçenler): runtime tavanı baştan keserken en
    # deterministik/imza-uyumlu şekiller garanti sıraya girmiş olur.
    for p in MANUAL_ADDITIONS.get(klass, []):
        if _manual_ok(p, klass):
            key = dedup_key(p)
            if key not in seen:
                seen.add(key)
                out.append({"payload": p, "dialect": "manual", "source": "manual-curated"})
    for dialect, p in _GRAMMAR.get(klass, []):
        if _manual_ok(p, klass):
            key = dedup_key(p)
            if key not in seen:
                seen.add(key)
                out.append({"payload": p, "dialect": dialect,
                            "source": "grammar-expanded"})
    i = 0
    while len(out) < cap:
        took = False
        for d in order:
            b = per_dialect.get(d) or []
            if i < len(b):
                e = b[i]
                key = dedup_key(e["payload"])
                if key not in seen:
                    seen.add(key)
                    out.append(e)
                    took = True
        if not took:
            break
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser(description="PATT → süzülmüş payload corpus'u (tek seferlik)")
    ap.add_argument("--src", type=Path, default=None,
                    help="Yerel PATT klonu (varsa); yoksa belleğe indirilir")
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    meta = {"source": "https://github.com/swisskyrepo/PayloadsAllTheThings",
            "commit": COMMIT, "license": "MIT", "extracted": str(date.today()),
            "counts": {}}
    for klass in _EXTRACTORS:
        entries = build_class(klass, args.src)
        if not entries:
            print(f"UYARI: {klass} için payload çıkarılamadı — dosya YAZILMADI",
                  file=sys.stderr)
            continue
        path = OUT_DIR / f"{klass}.json"
        path.write_text(json.dumps({"class": klass, "entries": entries},
                                   ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        meta["counts"][klass] = len(entries)
        print(f"{klass}: {len(entries)} payload → {path.relative_to(ROOT)}")
    (OUT_DIR / "META.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    print("META.json yazıldı.")


if __name__ == "__main__":
    main()
