"""
Kadim Güvenlik — LLM Saldırı Hipotezi Modeli + Sıkı Parser (Plan B)
===================================================================
Türkçe: LLM'i "araç seçici"den "saldırı FİKRİ üreticisi"ne çıkarmanın güvenli yolu.
İstihbarat subayı (DeepSeek) somut, test edilebilir hipotezler önerir ("şu URL'nin `id`
parametresinde SQLi dene"); bunlar deterministik verifier'a verilir ve YALNIZ kanıtlanırsa
Evidence olur → LLM'in halüsinasyonu bile zararsız (hipotez güvenilmez, kanıt zorunlu).

Bu modül LLM'in HAM çıktısını sıkı doğrular: LLM çıktısı düşman girdisidir (halüsinasyon +
prompt-injection). Kural: yalnız http(s) URL + verifier'ın DOĞRULAYABİLECEĞİ sınıf; gerisi
sessizce düşer. SAF ve BAĞIMSIZ (stdlib) → izole test edilebilir (test_attack_hypothesis.py).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, parse_qsl

# Verifier'ın AKTİF olarak kanıtlayabileceği sınıflar. Bir sınıf buraya eklenmeden hipotezi
# kabul edilmez (kanıtlanamayacak şeye "bulgu" demeyiz). Grup A (kendine yeterli — ek altyapı
# gerektirmez): sqli, xss, lfi, open_redirect, ssti, rce (echo-marker in-band kanıt — OOB
# kolektör GEREKTİRMEZ, Grup B'den A'ya indirildi). Grup B (blind RCE/OOB) hâlâ kolektör,
# Grup C (IDOR/auth-bypass) çok-kimlikli oturum motoru ister — onlar gelene dek burada YOK.
VERIFIABLE_CLASSES = frozenset({"sqli", "xss", "lfi", "open_redirect", "ssti", "rce"})

# LLM'in kullanabileceği eşanlamlıları kanonik sınıfa indir.
_CLASS_SYNONYMS = {
    "sqli": "sqli", "sql-injection": "sqli", "sql injection": "sqli",
    "sql_injection": "sqli", "blind-sqli": "sqli", "blind sqli": "sqli",
    "time-based-sqli": "sqli",
    # Türkçe: Faz 1f — reflected XSS teyit yöntemi eklendi.
    "xss": "xss", "cross-site-scripting": "xss", "cross site scripting": "xss",
    "reflected-xss": "xss", "reflected xss": "xss",
    # LFI / path traversal — tek kanonik kova: doğrulayıcı imza-tabanlı (/etc/passwd, win.ini).
    "lfi": "lfi", "local-file-inclusion": "lfi", "local file inclusion": "lfi",
    "path-traversal": "lfi", "path traversal": "lfi",
    "directory-traversal": "lfi", "directory traversal": "lfi",
    # Open redirect — sentinel-host yönlendirmesiyle kanıtlanır.
    "open_redirect": "open_redirect", "open-redirect": "open_redirect",
    "open redirect": "open_redirect", "unvalidated-redirect": "open_redirect",
    # SSTI — aritmetik marker değerlendirmesiyle kanıtlanır (komut YOK, tahribatsız).
    "ssti": "ssti", "template-injection": "ssti", "template injection": "ssti",
    "server-side-template-injection": "ssti",
    # RCE / komut enjeksiyonu — echo-marker yankısıyla in-band kanıtlanır (tahribatsız).
    "rce": "rce", "remote-code-execution": "rce", "remote code execution": "rce",
    "command-injection": "rce", "command injection": "rce",
    "os-command-injection": "rce", "os command injection": "rce",
    "cmd-injection": "rce", "cmd injection": "rce",
}

_MAX_URL_LEN = 2048
_MAX_RATIONALE_LEN = 300

# P0-B: gövde enjeksiyonu desteklenen HTTP metotları. GET sorguda kalır; POST/PUT/
# PATCH gövdeye iner (form veya JSON). DELETE gövdesi nadir olduğundan kapsam dışı.
BODY_METHODS = frozenset({"post", "put", "patch"})
_BODY_PARAM_CAP = 12       # tek hipotezin gövdesinde en fazla bu kadar parametre
_BODY_NAME_LEN = 120
_BODY_VALUE_LEN = 200


@dataclass(frozen=True)
class AttackHypothesis:
    """LLM'in önerdiği tek, somut, test edilebilir saldırı hipotezi.

    P0-B alanları (varsayılanlar geriye-uyumlu): `method` GET ise klasik sorgu
    enjeksiyonu; POST/PUT/PATCH + `body_params` doluysa doğrulayıcı gövdeye enjekte
    eder (gerçek API zafiyetlerinin çoğu gövdede yaşar). `body_kind` gövdenin
    form mu JSON mu olduğunu söyler (OpenAPI/LLM ipucu)."""
    url: str
    vuln_class: str                 # kanonik (VERIFIABLE_CLASSES)
    param: Optional[str] = None     # hedef parametre (varsa)
    rationale: str = ""             # LLM'in gerekçesi (insan-okunur)
    method: str = "get"             # get | post | put | patch
    body_params: Optional[tuple] = None   # ((ad, değer), ...) — gövde parametreleri
    body_kind: str = "form"         # form | json

    def dedup_key(self) -> tuple:
        # Aynı URL+sınıf farklı metotla AYRI hipotezdir (GET temiz, POST gövde —
        # ikisi de denenmeli; dedup yalnız tam aynı kombinasyonu elemeli).
        return (self.url, self.param or "", self.vuln_class,
                (self.method or "get").lower())


def _normalize_class(value: Any) -> Optional[str]:
    key = str(value or "").strip().lower()
    canon = _CLASS_SYNONYMS.get(key)
    if canon and canon in VERIFIABLE_CLASSES:
        return canon
    return None


def _valid_http_url(value: Any) -> Optional[str]:
    url = str(value or "").strip()
    if not url or len(url) > _MAX_URL_LEN:
        return None
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return url


def _canon_host(value: Any) -> str:
    """SAF host kanonikleştirme (stdlib): şema/port/kimlik/path atılır, küçük harf,
    'www.' öneki düşer. attack_graph._canon_host'un BAĞIMSIZ ikizi — bu modül izole ve
    stdlib-only kalmalı (test_attack_hypothesis.py düz script'le koşuyor). Düz hostname
    de ('api.bank.com') URL de ('https://api.bank.com/x') aynı sonucu verir."""
    h = str(value or "").strip().lower()
    if "://" not in h:
        h = "//" + h  # urlsplit netloc'u ayıklayabilsin (aksi halde path sanır)
    host = urlsplit(h).hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host.strip(".")


def _host_in_scope(url: str, allowed_hosts: Optional[frozenset]) -> bool:
    """Hipotez URL'inin host'u engagement kapsamında mı? `allowed_hosts` None/boşsa
    (kapsam verilmediyse) filtre UYGULANMAZ → geriye-uyum (izole testler etkilenmez).
    Verildiğinde: host, izinli host'lardan birine EŞİT ya da onun SUBDOMAIN'i olmalı
    (kök hedef + keşfedilen host'lar); değilse LLM halüsinasyonu/enjeksiyonu sayılıp düşer.
    Bu, dış-kutudan yetkisiz/metadata hedefine GERÇEK istek gitmesini engeller."""
    if not allowed_hosts:
        return True
    host = _canon_host(urlsplit(url).hostname or urlsplit(url).netloc)
    if not host:
        return False
    for a in allowed_hosts:
        if host == a or host.endswith("." + a):
            return True
    return False


def _parse_body_params(raw: Any) -> Optional[tuple]:
    """LLM/OpenAPI'den gelen gövde parametrelerini doğrula: {ad: değer} dict'i →
    ((ad, değer), ...) tuple'ı (frozen dataclass hash'li alan ister). Geçersiz/boş
    girdi → None (hipotez GET hipotezi olarak kalır)."""
    if not isinstance(raw, dict) or not raw:
        return None
    out = []
    for k, v in raw.items():
        name = str(k or "").strip()[:_BODY_NAME_LEN]
        if not name:
            continue
        out.append((name, str(v if v is not None else "1")[:_BODY_VALUE_LEN]))
        if len(out) >= _BODY_PARAM_CAP:
            break
    return tuple(out) if out else None


def parse_hypotheses(raw: Any, *, max_items: int = 10,
                     allowed_hosts: Optional[frozenset] = None) -> List[AttackHypothesis]:
    """LLM'in ham `attack_hypotheses` listesini doğrulanmış hipotezlere çevir.

    Geçersiz her giriş SESSİZCE düşer (motor kör hipoteze asla güvenmez). Sonuç
    tekilleştirilir ve `max_items` ile sınırlanır (maliyet/dokunuş kontrolü).
    P0-B: `method` (post/put/patch) + `body_params` verilirse gövde-hipotezi olur.

    KAPSAM: `allowed_hosts` verilirse (kök hedef + keşfedilen host'lar), host'u kapsam
    dışı hipotezler düşer — LLM'in uydurduğu/enjekte ettiği off-target URL'e (ör. saldırgan
    domaini, 169.254.169.254 metadata) dış-kutudan GERÇEK istek gitmez. None → filtre yok.
    """
    if not isinstance(raw, list):
        return []
    out: List[AttackHypothesis] = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        url = _valid_http_url(item.get("url"))
        if url is None:
            continue
        if not _host_in_scope(url, allowed_hosts):
            continue  # kapsam-dışı host — halüsinasyon/enjeksiyon; sessizce düş
        vuln_class = _normalize_class(item.get("vuln_class") or item.get("class"))
        if vuln_class is None:
            continue
        param = item.get("param")
        param = str(param).strip()[:120] if param else None
        rationale = str(item.get("why") or item.get("rationale") or "").strip()[:_MAX_RATIONALE_LEN]
        # Method/gövde: bilinmeyen metot GET'e düşer (güvenli varsayılan).
        method = str(item.get("method") or "get").strip().lower()
        if method not in ("get", "post", "put", "patch"):
            method = "get"
        body_params = _parse_body_params(item.get("body_params") or item.get("body"))
        if method == "get":
            body_params = None  # GET'te gövde anlamsız — sorgu hattı kullanılır
        if method in BODY_METHODS and not body_params:
            # Gövde metodu ama parametre yok → enjekte edilecek yer yok; GET'e düşürme
            # (endpoint gerçekten POST-only olabilir) ama gövdesiz doğrulama yapılamaz →
            # sessizce düşür (kanıtlanamayacak hipotez kuyruğu şişirmesin).
            continue
        body_kind = str(item.get("body_kind") or "form").strip().lower()
        if body_kind not in ("form", "json"):
            body_kind = "form"
        hyp = AttackHypothesis(url=url, vuln_class=vuln_class, param=param,
                               rationale=rationale, method=method,
                               body_params=body_params, body_kind=body_kind)
        key = hyp.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(hyp)
        if len(out) >= max_items:
            break
    return out


# ============================================================
# Kural-tohumu hipotez üretici (deterministik — LLM'siz de beslenen hat)
# ============================================================
# NEDEN: Doktrin "LLM opsiyonel bir sezgi katmanı, kritik yol değil" der — ama hipotez
# üretimi %100 LLM'e bağlıydı; LLM düşünce 5 doğrulayıcı boşta kalıyordu. Oysa parametre
# ADINDAN sınıf tahmini saf kural işidir: '?file=' → lfi, '?next=' → open_redirect.
# Bu tohumlayıcı LLM'den BAĞIMSIZ çalışır; LLM hipotezleriyle aynı kuyruğa düşer ve aynı
# deterministik verifier'dan geçer (halüsinasyon-güvenli hat değişmez — kanıt yine zorunlu).
#
# İlk eşleşen kural kazanır (sıra = öncelik). Güvenlik notu: tüm sınıflar tahribatsız
# PoC ile doğrulanır; yanlış sınıf tohumu en kötü ihtimalle bütçeden 1 deneme yer ve
# sessizce düşer (verified=False) — bulgu ÜRETMEZ.
_PARAM_CLASS_RULES = [
    (("file", "page", "path", "include", "template", "doc", "folder", "dir",
      "lang", "content", "filename", "download"), "lfi"),
    (("next", "url", "redirect", "redirect_uri", "return", "returnurl", "return_url",
      "goto", "dest", "destination", "continue", "redir", "target", "to"), "open_redirect"),
    (("id", "item", "user", "uid", "product", "prod", "cat", "category", "order",
      "sort", "article", "post", "news", "pid"), "sqli"),
    (("q", "s", "search", "query", "keyword", "term", "filter", "find"), "xss"),
    (("name", "msg", "message", "comment", "title", "greeting", "text"), "ssti"),
]


def _class_for_param_name(pname: str) -> Optional[str]:
    """Parametre adı → sınıf (ilk eşleşen kural kazanır). SAF."""
    pname = pname.strip().lower()
    for names, vuln_class in _PARAM_CLASS_RULES:
        if pname in names:
            return vuln_class
    return None


# Gövde parametreleri için örnek varsayılan değerler — enjeksiyon payload'u bu
# değerin SONUNA eklenir; boş değer bazı framework'lerde 400 döndürüp enjeksiyonu
# hiç çalıştırmaz. Metin çağrışımlı adlara metin, kalanına sayı.
_TEXT_HINTS = ("name", "msg", "message", "comment", "title", "text", "desc", "bio", "note")


def _default_body_value(name: str) -> str:
    n = name.strip().lower()
    if any(h in n for h in _TEXT_HINTS):
        return "kadim"
    if "email" in n or "mail" in n:
        return "kadim@example.com"
    if "url" in n or "link" in n:
        return "https://example.com"
    return "1"


def seed_hypotheses_from_endpoints(endpoints: List[Any], *, max_items: int = 10,
                                   forms: Optional[List[Any]] = None,
                                   api_endpoints: Optional[List[Any]] = None,
                                   ) -> List[AttackHypothesis]:
    """Endpoint URL/form/API matrisinden parametre-adı kurallarıyla hipotez tohumla
    (SAF — I/O yok).

    Üç kaynak (P0-B ile genişletildi):
      1) `endpoints`: parametreli GET URL'leri (klasik sorgu hattı)
      2) `forms`: crawler'ın çıkardığı HTML formlar — POST/PUT method + input adları
         gövde hipotezine dönüşür (gerçek API bug'larının çoğu gövdede)
      3) `api_endpoints`: OpenAPI'den çıkan {url, method, params} matrisi — doküman
         method+parametreyi BEDAVAYA verir; GET'se sorgu, gövde metoduysa body hattı

    Her (url, param, sınıf, method) bir kez üretilir; adı hiçbir kuralla eşleşmeyen
    parametreler sessizce atlanır. Sonuç `max_items` ile sınırlı (bütçe). LLM
    kuyruğuyla aynı tiptir — pipeline ikisini ayırt etmeden doğrular."""
    out: List[AttackHypothesis] = []
    seen = set()

    def _add(hyp: AttackHypothesis) -> bool:
        key = hyp.dedup_key()
        if key in seen:
            return False
        seen.add(key)
        out.append(hyp)
        return len(out) >= max_items

    # 1) GET sorgu hattı (mevcut davranış — değişmedi: URL'nin TÜM eşleşen
    # parametreleri tohumlanır, her (url, param, sınıf) bir kez)
    for raw in endpoints or []:
        url = _valid_http_url(raw)
        if url is None:
            continue
        params = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for k, _v in params:
            vc = _class_for_param_name(k)
            if vc is None:
                continue
            if _add(AttackHypothesis(
                    url=url, vuln_class=vc, param=k,
                    rationale=f"kural-tohumu: '{k}' parametre adı {vc} ipucu")):
                return out

    # 2) HTML formlar → gövde hipotezleri (POST/PUT; GET form zaten 1. adımda URL oldu)
    for form in forms or []:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "get").strip().lower()
        if method not in BODY_METHODS:
            continue
        action = _valid_http_url(form.get("action"))
        inputs = [str(i).strip() for i in (form.get("inputs") or []) if str(i).strip()]
        if action is None or not inputs:
            continue
        for name in inputs:
            vc = _class_for_param_name(name)
            if vc is None:
                continue
            body = tuple((n, _default_body_value(n)) for n in inputs)
            if _add(AttackHypothesis(
                    url=action, vuln_class=vc, param=name, method=method,
                    body_params=body, body_kind="form",
                    rationale=f"kural-tohumu: form '{name}' girdisi {vc} ipucu (gövde/{method})")):
                return out
            break  # form başına tek hipotez (bütçe)

    # 3) OpenAPI matrisi → method+parametre hazır gelir
    for ep in api_endpoints or []:
        if not isinstance(ep, dict):
            continue
        url = _valid_http_url(ep.get("url"))
        if url is None:
            continue
        method = str(ep.get("method") or "get").strip().lower()
        params = [str(p).strip() for p in (ep.get("params") or []) if str(p).strip()]
        if not params:
            continue
        if method in BODY_METHODS:
            for name in params:
                vc = _class_for_param_name(name)
                if vc is None:
                    continue
                body = tuple((n, _default_body_value(n)) for n in params)
                if _add(AttackHypothesis(
                        url=url, vuln_class=vc, param=name, method=method,
                        body_params=body, body_kind="json",
                        rationale=f"kural-tohumu: OpenAPI '{name}' parametresi {vc} ipucu (gövde/{method})")):
                    return out
                break
        else:
            # GET OpenAPI endpoint'i: URL'de sorgu yoksa parametreleri boş değerle kur
            for name in params:
                vc = _class_for_param_name(name)
                if vc is None:
                    continue
                full = url if "?" in url else url + "?" + "&".join(f"{p}=" for p in params)
                if _add(AttackHypothesis(
                        url=full, vuln_class=vc, param=name,
                        rationale=f"kural-tohumu: OpenAPI '{name}' parametresi {vc} ipucu")):
                    return out
                break
    return out
