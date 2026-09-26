"""
Kadim Güvenlik — IDOR / Broken Object-Level Authorization (Bug Bounty T2-A)
===========================================================================
Türkçe: İnsan pentester'ların en çok kazandığı sınıf, otomatik tarayıcıların en kör
olduğu yer: IDOR (Insecure Direct Object Reference) / BOLA. Kaynak kimliğini (`/api/
accounts/1042`, `?order_id=5581`) değiştirerek BAŞKASININ nesnesine erişim. nuclei
template'i bunu göremez çünkü "erişim kontrolü ihlali" bir imza değil, bir DİFERANSİYEL
gözlemdir: aynı istek, farklı kimlik → aynı veri dönüyorsa yetki kontrolü YOK.

Bu modül iki kipte çalışır:

  ┌─ ALTIN KİP (iki-hesap diferansiyel) → **confirmed**
  │   A kendi nesnesini çeker (200, gövde X). B AYNI URL'i çeker. B de X'i alıyorsa
  │   (gövdeler benzer) VE anonim erişim REDDEDİLİYORsa → yetki kontrolü kimliğe
  │   BAKMIYOR. Bu deterministik bir KANITTIR (template tahmini değil): tek değişen
  │   Authorization başlığı, dönen veri aynı.
  │
  └─ GÜMÜŞ KİP (tek-hesap + anon + enumerasyon) → **probable**
      İkinci hesap yoksa: A nesneyi çekebiliyor ama anon REDDEDİLİYOR (kaynak korumalı)
      VE A, id'yi yürüterek (N±1) BAŞKA nesneleri de okuyabiliyor → yatay yetki
      yükseltme ŞÜPHESİ. Sahipliği ikinci hesap olmadan KANITLAYAMAYIZ → probable,
      needs-review. Asla confirmed'a yükselmez (doktrin: FP'yi confirmed'a yazma).

Tasarım (service_probes/fp_signals deseni): karar çekirdeği (`adjudicate_*`, ref
çıkarımı, benzerlik) SAF → izole test; I/O katmanı ince, TAHRİBATSIZ (yalnız GET),
bütçeli, ASLA exception yükseltmez. Doktrin: LLM yok — tamamen deterministik.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

logger = logging.getLogger("idor-probe")

# ---- Eşikler (FP'ye karşı kalibre — iki KARŞIT karşılaştırma, iki AYRI eşik) ----
# (1) "B, A'nın NESNESİNİ mi aldı?" (owner vs cross) → YÜKSEK bar. İki FARKLI kullanıcının
# hesap JSON'u aynı ALANLARı paylaşır (sadece değerler farklı) → ~0.6-0.75 benzeyebilir;
# düşük eşik, güvenli durumu (B kendi nesnesini aldı) yanlışlıkla IDOR sayardı. 0.90 = ancak
# NEREDEYSE-BİREBİR (aynı kayıt) confirmed. SPA-shell id-duyarlılık kalkanıyla birlikte sağlam.
_SIM_CROSS_MATCH = 0.90
# (2) "Kaynak PUBLIC mi?" (owner vs anon) → DÜŞÜK bar (agresif public-eleme; anon owner'a
# kısmen bile benziyorsa public say, FP üretme).
_SIM_PUBLIC = 0.60
# Enumerasyon: komşu id FARKLI bir kayıt mı? Neredeyse-birebir ise (şablon/boş) sinyal zayıf.
_SIM_DISTINCT_MAX = 0.985
# Anlamlı gövde alt sınırı — bu kadar bayttan kısa yanıt "nesne döndü" saymaz.
_MIN_BODY = 24
# Bütçe: kaç aday URL problanır, komşu enumerasyon başına kaç deneme.
_MAX_TARGETS = 12
_MAX_NEIGHBORS = 2
_PER_REQUEST_TIMEOUT = 8.0

# ---- id-benzeri değer sınıflandırıcıları ----
_RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_RE_OBJECTID = re.compile(r"^[0-9a-f]{24}$", re.I)
_RE_HASH = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
_RE_NUMERIC = re.compile(r"^\d{1,15}$")

# Param/segment adı IDOR çağrışımlı mı? (değer id-benzeri değilse bile ipucu)
# REST/CMS koleksiyon isimleri (media/comment/contact/subscriber/company/attachment/lead/entry)
# eklendi: WP /wp-json ve plugin route'larında (Groundhogg contacts, Crater company, form
# entries) sayısal id'li PATH segmentleri artık IDOR adayı sayılır — güncel CVE deseninin ana
# sınıfı. Sayfalama gürültüsü (page/offset) BİLEREK dışarıda (FP kaçınma). Çoğullar `s\b` ile.
_ID_NAME_HINT = re.compile(
    r"(?:^|_|-|\b)(id|uid|uuid|guid|user|users|account|acct|customer|order|orders|"
    r"invoice|doc|document|file|report|ticket|msg|message|record|item|profile|"
    r"member|group|team|org|project|number|no|ref|"
    r"media|comment|contact|subscriber|company|attachment|lead|entry)(?:$|_|-|\b|s\b)", re.I)


def classify_id(value: str) -> Optional[str]:
    """Bir değer id-benzeri mi? kind döndür (numeric|uuid|objectid|hash) yoksa None.
    Sıra önemli: uuid/objectid/hash sayısaldan ÖNCE (24-hex objectid'i hash yeme)."""
    if not isinstance(value, str) or not value:
        return None
    v = value.strip()
    if _RE_UUID.match(v):
        return "uuid"
    if _RE_OBJECTID.match(v):
        return "objectid"
    if _RE_HASH.match(v):
        return "hash"
    if _RE_NUMERIC.match(v):
        return "numeric"
    return None


@dataclass
class ObjectRef:
    """URL içinde değiştirilebilir bir nesne kimliği (enjeksiyon/enumerasyon hedefi)."""
    location: str            # "path" | "query"
    value: str
    kind: str                # numeric | uuid | objectid | hash
    name: Optional[str] = None       # query param adı
    index: Optional[int] = None      # path segment indeksi
    name_hint: bool = False          # adı IDOR-çağrışımlı mı


def extract_object_refs(url: str) -> List[ObjectRef]:
    """URL'den id-benzeri nesne referanslarını çıkar (SAF). Hem query paramları hem
    path segmentleri taranır. Ad-ipucu (user/order/id...) taşıyan refler önceliklidir."""
    refs: List[ObjectRef] = []
    try:
        parts = urlsplit(url)
    except Exception:
        return refs

    # Query paramları
    for name, val in parse_qsl(parts.query, keep_blank_values=True):
        kind = classify_id(val)
        hint = bool(_ID_NAME_HINT.search(name or ""))
        if kind and (hint or kind in ("uuid", "objectid")):
            # numeric değer ancak ad-ipucu varsa alınır (sayfa=2 gibi gürültüyü ele);
            # uuid/objectid tek başına yeterince ayırt edici.
            refs.append(ObjectRef(location="query", value=val, kind=kind,
                                  name=name, name_hint=hint))

    # Path segmentleri
    segs = [s for s in parts.path.split("/")]
    for i, seg in enumerate(segs):
        if not seg:
            continue
        kind = classify_id(seg)
        if not kind:
            continue
        # Önceki segment ad-ipucu mu? (`/users/1042` → users id çağrışımı)
        prev = segs[i - 1] if i > 0 else ""
        hint = bool(_ID_NAME_HINT.search(prev))
        if kind in ("uuid", "objectid") or hint:
            refs.append(ObjectRef(location="path", value=seg, kind=kind,
                                  index=i, name=prev or None, name_hint=hint))

    # Ad-ipuçlu refler öne (daha yüksek IDOR olasılığı)
    refs.sort(key=lambda r: (not r.name_hint, r.kind != "numeric"))
    return refs


def replace_ref(url: str, ref: ObjectRef, new_value: str) -> str:
    """URL'deki ref'in değerini new_value ile değiştir (SAF). Enumerasyon için."""
    parts = urlsplit(url)
    if ref.location == "query":
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        out_pairs = []
        replaced = False
        for name, val in pairs:
            if not replaced and name == ref.name and val == ref.value:
                out_pairs.append((name, new_value))
                replaced = True
            else:
                out_pairs.append((name, val))
        new_q = urlencode(out_pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_q, parts.fragment))
    else:
        segs = parts.path.split("/")
        if ref.index is not None and 0 <= ref.index < len(segs):
            segs[ref.index] = new_value
        new_path = "/".join(segs)
        return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


def neighbor_values(ref: ObjectRef) -> List[str]:
    """Enumerasyon komşuları (SAF). Sayısal id için N-1, N+1... (id-walk). uuid/hash
    için enumerasyon anlamsız (tahmin edilemez) → boş."""
    if ref.kind != "numeric":
        return []
    try:
        n = int(ref.value)
    except Exception:
        return []
    out = []
    for delta in (1, -1, 2):
        m = n + delta
        if m >= 0 and str(m) != ref.value:
            out.append(str(m))
        if len(out) >= _MAX_NEIGHBORS:
            break
    return out


def alt_id_value(ref: ObjectRef) -> Optional[str]:
    """id-duyarlılık testi için FARKLI ama biçim-uyumlu bir değer üret (SAF). Endpoint bu
    değerle owner ile AYNI gövdeyi dönüyorsa → id'ye DUYARSIZ (SPA shell / statik rota),
    IDOR sayılmaz (iki-hesap FP kalkanı). Üretilemezse None."""
    if ref.kind == "numeric":
        nv = neighbor_values(ref)
        return nv[0] if nv else None
    if ref.kind == "uuid":
        z = "00000000-0000-0000-0000-000000000000"
        return z if ref.value.lower() != z else "11111111-1111-1111-1111-111111111111"
    if ref.kind == "objectid":
        return "0" * 24 if set(ref.value) != {"0"} else "1" * 24
    if ref.kind == "hash":
        return "0" * len(ref.value) if set(ref.value) != {"0"} else "1" * len(ref.value)
    return None


def bodies_similar(a: str, b: str) -> float:
    """İki gövde ne kadar benzer (0..1). Uzun gövdeleri kırparak SequenceMatcher ratio.
    'B, A'nın aynı nesnesini mi aldı' sorusunun ölçüsü."""
    if a is None or b is None:
        return 0.0
    a = a[:4000]
    b = b[:4000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


@dataclass
class Measured:
    """Tek bir HTTP ölçümü (I/O katmanından adjudicate'e taşınan SAF veri)."""
    status: int
    body: str
    page_class: Optional[str]   # fp_signals.classify_response_page çıktısı (None=temiz)
    length: int = 0
    content_type: str = ""      # BRONZE kip: JSON/API yanıtını public HTML'den ayırt eder


def _is_substantive(m: Optional[Measured]) -> bool:
    """Ölçüm 'gerçek bir nesne döndü' sayılır mı? 2xx + temiz sayfa (waf/auth/error/
    empty DEĞİL) + anlamlı uzunluk."""
    if m is None:
        return False
    if not (200 <= m.status < 300):
        return False
    if m.page_class in ("waf_block", "auth_wall", "generic_error", "maintenance", "empty"):
        return False
    return m.length >= _MIN_BODY


def _is_denied(m: Optional[Measured]) -> bool:
    """Ölçüm 'erişim reddedildi' sayılır mı? 401/403, auth-duvarı, ya da login'e
    yönlendirme (3xx redirect page_class)."""
    if m is None:
        return True  # ölçülemedi → temkinli: reddedilmiş say (FP üretme)
    if m.status in (401, 403):
        return True
    if 300 <= m.status < 400:
        return True
    if m.page_class in ("auth_wall", "waf_block"):
        return True
    return False


def adjudicate_two_account(owner: Measured, cross: Measured,
                           anon: Optional[Measured]) -> Dict[str, Any]:
    """ALTIN KİP kararı (SAF). owner=A kendi nesnesi, cross=B aynı URL, anon=kimliksiz.

    confirmed IDOR koşulu:
      - owner anlamlı (A gerçekten bir nesne aldı)
      - cross anlamlı VE gövdesi owner'a BENZER (B, A'nın nesnesini aldı)
      - anon REDDEDİLDİ ya da anon gövdesi FARKLI (kaynak public değil — public olsaydı
        IDOR değil, sadece açık veri olurdu)
    """
    none = {"is_idor": False, "tier": None, "reason": None}
    if not _is_substantive(owner):
        return {**none, "reason": "owner_baseline_yok"}
    if not _is_substantive(cross):
        return {**none, "reason": "cross_reddedildi_yetki_calisiyor"}
    sim = bodies_similar(owner.body, cross.body)
    if sim < _SIM_CROSS_MATCH:
        # B, A'nın nesnesini değil KENDİ nesnesini aldı (sunucu id'yi kimliğe göre
        # kapsıyor) → yetki kontrolü ÇALIŞIYOR, IDOR değil. YÜKSEK eşik: iki farklı
        # kullanıcının aynı-yapılı JSON'u kısmen benzer olabilir; ancak NEREDEYSE-BİREBİR
        # aynılık "B, A'nın ta kendisini aldı" der.
        return {**none, "reason": f"cross_farkli_nesne(sim={sim:.2f}<{_SIM_CROSS_MATCH})"}
    # Public mi? anon owner'a benziyorsa (DÜŞÜK eşik, agresif eleme) IDOR değil.
    if anon is not None and _is_substantive(anon):
        anon_sim = bodies_similar(owner.body, anon.body)
        if anon_sim >= _SIM_PUBLIC:
            return {**none, "reason": f"kaynak_public(anon_sim={anon_sim:.2f})"}
    return {
        "is_idor": True,
        "tier": "confirmed",
        "reason": (f"İki-hesap diferansiyel: B (farklı kimlik) A'nın nesnesini aldı "
                   f"(gövde benzerliği {sim:.2f} ≥ {_SIM_CROSS_MATCH}); anon erişim "
                   f"reddedildi/farklı. Yetki kontrolü kimliğe bakmıyor."),
        "similarity": round(sim, 3),
    }


def adjudicate_single_account(owner: Measured, anon: Optional[Measured],
                              neighbors: List[Measured]) -> Dict[str, Any]:
    """GÜMÜŞ KİP kararı (SAF). İkinci hesap yok → sahiplik kanıtlanamaz → en fazla probable.

    probable IDOR koşulu:
      - owner anlamlı (A id N'de bir nesne aldı)
      - anon REDDEDİLDİ (kaynak korumalı — yoksa public veri, IDOR değil)
      - EN AZ BİR komşu id (N±1) anlamlı VE owner'dan FARKLI kayıt (id-walk ile başka
        nesne okundu) → yatay yetki yükseltme şüphesi.
    """
    none = {"is_idor": False, "tier": None, "reason": None}
    if not _is_substantive(owner):
        return {**none, "reason": "owner_baseline_yok"}
    # Korumalı mı? anon reddedilmeli; anon da nesneyi alıyorsa public → IDOR değil.
    if anon is not None and _is_substantive(anon):
        if bodies_similar(owner.body, anon.body) >= _SIM_PUBLIC:
            return {**none, "reason": "kaynak_public_anon_erisebiliyor"}
    if not _is_denied(anon):
        return {**none, "reason": "anon_durumu_belirsiz"}
    walked = 0
    sims: List[float] = []
    for nb in neighbors:
        if not _is_substantive(nb):
            continue
        sim = bodies_similar(owner.body, nb.body)
        # Komşu FARKLI bir kayıt olmalı (birebir kopya = şablon/boş → sinyal değil)
        if sim < _SIM_DISTINCT_MAX:
            walked += 1
            sims.append(sim)
    if walked == 0:
        return {**none, "reason": "komsu_id_farkli_nesne_dondurmedi"}
    return {
        "is_idor": True,
        "tier": "probable",
        "reason": (f"Tek-hesap enumerasyon: kaynak korumalı (anon reddedildi) ama A, "
                   f"id yürüterek {walked} komşu nesneyi daha okudu (farklı kayıtlar). "
                   f"Yatay yetki yükseltme ŞÜPHESİ — sahiplik ikinci hesapla kanıtlanmalı."),
        "walked": walked,
    }


# ============================================================
# I/O katmanı — TAHRİBATSIZ (yalnız GET), bütçeli, korumalı
# ============================================================

def _classify(status: int, body: str) -> Optional[str]:
    """fp_signals.classify_response_page sarmalı (import başarısızsa temkinli None)."""
    try:
        from .fp_signals import classify_response_page
        if 300 <= status < 400:
            return "redirect"
        return classify_response_page(body or "", status)
    except Exception:
        return None


async def _get(client, url: str, headers: Dict[str, str]) -> Optional[Measured]:
    """Tek GET → Measured. Hata → None (adjudicate temkinli davranır)."""
    try:
        r = await client.get(url, headers=headers)
    except Exception:
        return None
    body = ""
    try:
        # İlk 8KB yeter (benzerlik + sayfa sınıfı için)
        body = (r.text or "")[:8192]
    except Exception:
        body = ""
    if 300 <= r.status_code < 400:
        pc = "redirect"
    else:
        pc = _classify(r.status_code, body)
    ctype = ""
    try:
        ctype = str(r.headers.get("content-type", ""))
    except Exception:
        ctype = ""
    return Measured(status=r.status_code, body=body, page_class=pc, length=len(body),
                    content_type=ctype)


async def probe_idor(candidates: List[str], *,
                     auth_a: Dict[str, str],
                     auth_b: Optional[Dict[str, str]] = None,
                     max_targets: int = _MAX_TARGETS) -> List[Dict[str, Any]]:
    """Aday URL'lerde IDOR/BOLA diferansiyel probu (I/O). auth_a zorunlu (A kimliği).
    auth_b verilirse ALTIN kip (confirmed), yoksa GÜMÜŞ kip (probable + enumerasyon).

    Döner: bulgu listesi [{url, ref_kind, ref_name, tier, severity, cwe, mitre, proof,
    verification_method, verification_detail}]. ASLA raise etmez."""
    import httpx
    findings: List[Dict[str, Any]] = []
    if not auth_a:
        return findings  # A kimliği olmadan yetki boşluğu kanıtlanamaz — gürültü üretme

    # Aday URL'lerden nesne referansı taşıyanları seç (dedup + cap)
    seen: set = set()
    targets: List[Tuple[str, ObjectRef]] = []
    for url in candidates:
        if not isinstance(url, str) or url in seen:
            continue
        seen.add(url)
        refs = extract_object_refs(url)
        if refs:
            targets.append((url, refs[0]))  # en olası ref (ad-ipuçlu/uuid önce)
        if len(targets) >= max_targets:
            break
    if not targets:
        return findings

    limits = httpx.Limits(max_connections=6, max_keepalive_connections=6)
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                     timeout=_PER_REQUEST_TIMEOUT, limits=limits) as client:
            for url, ref in targets:
                try:
                    owner = await _get(client, url, auth_a)
                    anon = await _get(client, url, {})
                    if auth_b:
                        cross = await _get(client, url, auth_b)
                        verdict = adjudicate_two_account(owner, cross, anon)
                        method = "idor-two-account-differential"
                        # SPA-shell / statik-rota FP KALKANI: endpoint id'ye DUYARLI mı?
                        # owner(N) ile owner(farklı-id) AYNI anlamlı gövdeyse, sunucu id'ye
                        # bakmadan aynı kabuğu dönüyordur → cross'un "A'nın verisini aldı"
                        # görünmesi yanıltıcı (ikisi de aynı kabuk). Bu durumda confirmed İPTAL.
                        if verdict.get("is_idor"):
                            alt = alt_id_value(ref)
                            if alt is not None:
                                owner_alt = await _get(client, replace_ref(url, ref, alt), auth_a)
                                if _is_substantive(owner_alt) and \
                                        bodies_similar(owner.body, owner_alt.body) >= _SIM_DISTINCT_MAX:
                                    verdict = {"is_idor": False, "tier": None,
                                               "reason": (f"endpoint_id_duyarsiz_muhtemel_spa_"
                                                          f"shell(alt_id_sim>={_SIM_DISTINCT_MAX})")}
                    else:
                        nbs: List[Measured] = []
                        for nv in neighbor_values(ref):
                            m = await _get(client, replace_ref(url, ref, nv), auth_a)
                            if m is not None:
                                nbs.append(m)
                        verdict = adjudicate_single_account(owner, anon, nbs)
                        method = "idor-single-account-enumeration"
                except Exception as e:
                    logger.debug(f"IDOR prob hatası ({url}): {e}")
                    continue

                if not verdict.get("is_idor"):
                    continue
                tier = verdict["tier"]
                sev = "high" if tier == "confirmed" else "medium"
                findings.append({
                    "url": url,
                    "ref_kind": ref.kind,
                    "ref_name": ref.name,
                    "ref_location": ref.location,
                    "tier": tier,
                    "severity": sev,
                    "cwe": ["CWE-639", "CWE-284"],
                    "mitre": "T1190",
                    "title": (f"IDOR / Broken Object-Level Authorization @ {url}"),
                    "proof": verdict["reason"],
                    "verification_method": method,
                    "verification_detail": verdict["reason"][:200],
                    "verification_confidence": 0.85 if tier == "confirmed" else 0.5,
                })
    except Exception as e:
        logger.debug(f"IDOR probu genel hata: {e}")
    return findings


# ============================================================
# BRONZE KİP — kimliksiz nesne ifşası + enumerasyon (auth YOK)
# ============================================================
# NEDEN: Golden/Silver kip A kimliği ister. Ama dıştan yetkili testin ÇOĞU kimliksizdir;
# modern API'lerin en sık gerçek açığı "nesne endpoint'i kimlik DOĞRULAMADAN veri döndürüyor
# + id yürünebiliyor" (n8n/Ni8mare tarzı bilgi ifşası, OWASP API #1/#2). Golden/Silver bu
# vakada HİÇ çalışmaz → path-param yüzeyi keşfedilir/değerlenir ama test EDİLMEZDİ. BRONZE bu
# boşluğu kapatır: tahribatsız (yalnız GET), yalnız SAYISAL + HASSAS-adlı (users/orders/
# invoice...) koleksiyon, JSON/API yanıtı; en fazla PROBABLE (kimliksizken "korunmalıydı"
# NİYETİ ispatlanamaz — asla confirmed'a yükseltme, doktrin: FP'yi confirmed'a yazma).

# Yanıt yapılandırılmış veri (JSON) mı görünüyor? Public HTML sayfayı (blog/ürün) eleyerek
# FP'yi kısan kalkan. Önce content-type, yoksa gövde biçimi.
_JSON_BODY_HINT = re.compile(r'^\s*[\[{]|"\s*:\s*["\[{0-9tfn]')


def _looks_like_data(m: Optional[Measured]) -> bool:
    """Ölçüm bir veri nesnesi (JSON/API) mi? BRONZE FP kalkanı — public HTML sayfaları
    (blog post, ürün sayfası) 'nesne ifşası' sayılmasın. SAF."""
    if m is None or not m.body:
        return False
    ct = (m.content_type or "").lower()
    if "json" in ct or "application/vnd.api" in ct:
        return True
    if "html" in ct:
        return False  # açıkça HTML → veri nesnesi değil
    return bool(_JSON_BODY_HINT.search(m.body[:512]))


def adjudicate_anonymous(owner_anon: Optional[Measured], neighbors: List[Measured],
                         *, ref: ObjectRef) -> Dict[str, Any]:
    """BRONZE KİP kararı (SAF). Kimliksiz istekle nesne endpoint'i veri döndürüyor VE id
    yürünerek FARKLI nesneler okunuyorsa → kimlik-doğrulamasız nesne ifşası ŞÜPHESİ.

    probable koşulu (hepsi):
      - owner_anon anlamlı (kimliksiz GET 2xx + temiz + gövdeli)
      - yanıt JSON/API verisi görünüyor (public HTML sayfa FP kalkanı)
      - EN AZ BİR komşu id (N±1) anlamlı VE owner'dan FARKLI kayıt (statik-shell değil,
        gerçekten id-başına-nesne → enumere edilebilir ifşa)
    Kanıt sınırı: kimliksizken kaynağın 'gizli olması gerektiği' NİYETİ ispatlanamaz →
    asla confirmed değil (bilinçli-public API olabilir; manuel doğrulama şart)."""
    none = {"is_idor": False, "tier": None, "reason": None}
    if not _is_substantive(owner_anon):
        return {**none, "reason": "anon_veri_donmedi_muhtemel_korumali(iyi)"}
    if not _looks_like_data(owner_anon):
        return {**none, "reason": "yanit_veri_nesnesi_gorunmuyor(html/sayfa)"}
    walked = 0
    for nb in neighbors:
        if not _is_substantive(nb):
            continue
        if bodies_similar(owner_anon.body, nb.body) < _SIM_DISTINCT_MAX:
            walked += 1
    if walked == 0:
        return {**none, "reason": "komsu_id_farkli_nesne_dondurmedi(statik_route?)"}
    return {
        "is_idor": True,
        "tier": "probable",
        "reason": (f"Kimliksiz nesne ifşası: '{ref.name}/{ref.value}' endpoint'i AUTH "
                   f"olmadan JSON/API verisi döndürdü ve id yürünerek {walked} farklı nesne "
                   f"daha okundu. Kimlik doğrulaması eksik/zayıf ŞÜPHESİ (OWASP API #2) — "
                   f"kaynağın gizli olması gerekip gerekmediği manuel doğrulanmalı."),
        "walked": walked,
    }


async def probe_object_exposure(candidates: List[str], *,
                                max_targets: int = _MAX_TARGETS) -> List[Dict[str, Any]]:
    """Kimliksiz (anon) nesne-ifşa + enumerasyon probu (I/O). AUTH GEREKMEZ — probe_idor'un
    erken çıktığı kimliksiz vakayı kapsar. Yalnız SAYISAL + HASSAS-adlı (name_hint) ref'ler
    (enumere edilebilir + FP kalkanı). Tahribatsız (yalnız GET), bütçeli, ASLA raise etmez.
    Bulgu şeması probe_idor ile aynı (pipeline ikisini ayırt etmeden emit eder)."""
    import httpx
    findings: List[Dict[str, Any]] = []

    seen: set = set()
    targets: List[Tuple[str, ObjectRef]] = []
    for url in candidates:
        if not isinstance(url, str) or url in seen:
            continue
        seen.add(url)
        for ref in extract_object_refs(url):
            # BRONZE yalnız: sayısal (enumere edilebilir) + hassas-adlı koleksiyon. uuid/hash
            # tahmin edilemez → anon enumerasyon anlamsız; ad-ipucu yoksa FP riski yüksek.
            if ref.kind == "numeric" and ref.name_hint and neighbor_values(ref):
                targets.append((url, ref))
                break
        if len(targets) >= max_targets:
            break
    if not targets:
        return findings

    limits = httpx.Limits(max_connections=6, max_keepalive_connections=6)
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                     timeout=_PER_REQUEST_TIMEOUT, limits=limits) as client:
            for url, ref in targets:
                try:
                    owner_anon = await _get(client, url, {})
                    nbs: List[Measured] = []
                    for nv in neighbor_values(ref):
                        m = await _get(client, replace_ref(url, ref, nv), {})
                        if m is not None:
                            nbs.append(m)
                    verdict = adjudicate_anonymous(owner_anon, nbs, ref=ref)
                except Exception as e:
                    logger.debug(f"Nesne-ifşa prob hatası ({url}): {e}")
                    continue
                if not verdict.get("is_idor"):
                    continue
                findings.append({
                    "url": url,
                    "ref_kind": ref.kind,
                    "ref_name": ref.name,
                    "ref_location": ref.location,
                    "tier": "probable",
                    "severity": "medium",
                    "cwe": ["CWE-639", "CWE-306"],
                    "mitre": "T1190",
                    "title": f"Unauthenticated Object Exposure (BOLA) @ {url}",
                    "proof": verdict["reason"],
                    "verification_method": "idor-anonymous-enumeration",
                    "verification_detail": verdict["reason"][:200],
                    "verification_confidence": 0.5,
                })
    except Exception as e:
        logger.debug(f"Nesne-ifşa probu genel hata: {e}")
    return findings


# ============================================================
# MASS-EXPOSURE — kitlesel nesne ifşası (TEB senaryosu: token'sız Burp ile "tüm
# kullanıcılar sızdı"). BRONZE/GÜMÜŞ "yürünebilir nesne VAR" der ama KAÇ FARKLI
# kullanıcının PII'si döndüğünü SAYMAZ. Asıl kanıt genişliktir: id yürüyüşüyle onlarca
# FARKLI kayıt (email/telefon/tckn/iban) dönüyorsa bu "bilinçli-public tek nesne"
# olamaz → kitlesel yetkisiz ifşa. Tahribatsız (yalnız GET), örnek KAPAKLI, saklanan
# kanıtta ham PII YOK (yalnız sayım + tür). OWASP API #1 (BOLA) / #2 (Broken Auth).
# ============================================================

# Örnekleme + eşik bütçeleri (FP'ye karşı: az kayıt confirmed olmaz).
_MASS_SAMPLE = 24            # id penceresi genişliği (kaç komşu id çekilir)
_MASS_MAX_TARGETS = 6       # kaç aday endpoint kitlesel taranır
_MASS_PII_MIN = 5           # ≥ bu kadar FARKLI PII kaydı → confirmed kitlesel ifşa
_MASS_DATA_MIN = 10         # PII yok ama ≥ bu kadar FARKLI veri kaydı → probable

# ---- PII imzaları (Türkiye bağlamı dahil) ----
_PII_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PII_PHONE_TR = re.compile(r"(?<!\d)(?:\+?90|0)?5\d{9}(?!\d)")
_PII_TCKN = re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)")
_PII_IBAN_TR = re.compile(r"\bTR\d{24}\b")
_PII_KEY = re.compile(
    r'"(email|e_?posta|phone|gsm|telefon|tc|tckn|tc_?no|tc_?kimlik|iban|password|parola|'
    r'sifre|passwd|ssn|credit|card|address|adres|first_?name|last_?name|full_?name|'
    r'birth|dogum)"\s*:', re.I)


def detect_pii(body: str) -> Dict[str, int]:
    """Gövdedeki PII imzalarını say (SAF). Ham değer DÖNDÜRMEZ — yalnız tür→sayım
    (kanıtta PII sızdırmamak için). email/telefon/tckn/iban güçlü; 'pii_alan' JSON
    anahtar sayısıdır (email:/iban: gibi)."""
    counts: Dict[str, int] = {}
    if not body:
        return counts
    for kind, rx in (("email", _PII_EMAIL), ("telefon", _PII_PHONE_TR),
                     ("tckn", _PII_TCKN), ("iban", _PII_IBAN_TR)):
        c = len(rx.findall(body))
        if c:
            counts[kind] = c
    keys = len(_PII_KEY.findall(body))
    if keys:
        counts["pii_alan"] = keys
    return counts


def has_strong_pii(counts: Dict[str, int]) -> bool:
    """Sayım güçlü PII taşıyor mu? (SAF). email/iban tek başına yeterli; telefon/tckn
    tek başına gürültülü (epoch/rakam) → PII-alan bağlamıyla desteklenmeli; ya da ≥2
    farklı PII JSON anahtarı."""
    if counts.get("email") or counts.get("iban"):
        return True
    if counts.get("pii_alan", 0) >= 2:
        return True
    if counts.get("pii_alan", 0) >= 1 and (counts.get("telefon") or counts.get("tckn")):
        return True
    return False


def sample_id_window(ref: ObjectRef, n: int = _MASS_SAMPLE) -> List[str]:
    """Sayısal id çevresinde GENİŞ komşu penceresi (SAF). neighbor_values yalnız ±2
    verir (VAR mı?); kitlesel kanıt için değere yakın n farklı id (ardışık kayıt
    lokalitesi). uuid/hash tahmin edilemez → boş."""
    if ref.kind != "numeric":
        return []
    try:
        base = int(ref.value)
    except Exception:
        return []
    out: List[str] = []
    d = 1
    while len(out) < n and d <= n * 2 + 2:
        for cand in (base + d, base - d):
            s = str(cand)
            if cand >= 0 and s != ref.value and s not in out:
                out.append(s)
                if len(out) >= n:
                    break
        d += 1
    return out[:n]


def count_distinct(measures: List[Measured]) -> int:
    """Anlamlı+veri gövdelerinden KAÇ FARKLI kayıt (SAF). Birbirine neredeyse-birebir
    (şablon/statik-shell) olanlar tek küme sayılır → 'aynı boş kabuk N kez' şişirmesin."""
    reps: List[str] = []
    for m in measures:
        b = m.body or ""
        if any(bodies_similar(b, r) >= _SIM_DISTINCT_MAX for r in reps):
            continue
        reps.append(b)
    return len(reps)


def adjudicate_mass_exposure(samples: List[Measured], *, ref: ObjectRef,
                             unauth: bool) -> Dict[str, Any]:
    """Kitlesel ifşa kararı (SAF). samples = owner + id-penceresi ölçümleri.

    confirmed koşulu: ≥_MASS_PII_MIN FARKLI kayıt GÜÇLÜ PII taşıyor. Gerekçe (doktrine
    rağmen confirmed): id yürüyüşüyle onlarca FARKLI kullanıcının email/iban'ı dönmesi
    'bilinçli-public tek nesne' olamaz — genişliğin kendisi kanıt. probable: PII yok ama
    ≥_MASS_DATA_MIN farklı veri kaydı (public liste OLABİLİR → confirmed değil)."""
    none = {"is_idor": False, "tier": None, "reason": None}
    data = [m for m in samples if _is_substantive(m) and _looks_like_data(m)]
    if len(data) < 3:
        return {**none, "reason": f"yetersiz_veri_ornegi(n={len(data)})"}
    # PII taşıyan kayıtlar + türlerin toplamı (kanıt için — ham değer değil, SAYIM).
    agg: Dict[str, int] = {}
    pii_measures: List[Measured] = []
    for m in data:
        c = detect_pii(m.body)
        if has_strong_pii(c):
            pii_measures.append(m)
            for k, v in c.items():
                agg[k] = agg.get(k, 0) + v
    distinct_all = count_distinct(data)
    distinct_pii = count_distinct(pii_measures)
    scope = "kimliksiz (token yok)" if unauth else "tek düşük-yetki kimlikle"
    if distinct_pii >= _MASS_PII_MIN:
        kinds = ", ".join(f"{k}×{v}" for k, v in sorted(agg.items()))
        return {
            "is_idor": True, "tier": "confirmed",
            "distinct_pii": distinct_pii, "distinct_all": distinct_all,
            "reason": (f"Kitlesel BOLA ({scope}): '{ref.name or ref.kind}' endpoint'inde id "
                       f"yürüyüşüyle {distinct_pii} FARKLI kayıt GÜÇLÜ PII döndürdü "
                       f"({kinds}). Nesne-seviyesi yetki kontrolü YOK — onlarca kullanıcının "
                       f"kişisel verisi çekilebiliyor (CWE-639/CWE-306, OWASP API #1/#2)."),
        }
    if distinct_all >= _MASS_DATA_MIN:
        return {
            "is_idor": True, "tier": "probable",
            "distinct_pii": distinct_pii, "distinct_all": distinct_all,
            "reason": (f"Kitlesel enumerasyon şüphesi ({scope}): id yürüyüşüyle "
                       f"{distinct_all} FARKLI veri kaydı okundu (güçlü PII imzası yok). "
                       f"Public liste olabilir — kaynağın gizli olması gerekip gerekmediği "
                       f"manuel doğrulanmalı."),
        }
    return {**none, "reason": (f"kitlesel_esik_alti(farkli_pii={distinct_pii}<{_MASS_PII_MIN}, "
                               f"farkli_veri={distinct_all}<{_MASS_DATA_MIN})")}


async def probe_mass_exposure(candidates: List[str], *,
                              auth: Optional[Dict[str, str]] = None,
                              sample_size: int = _MASS_SAMPLE,
                              max_targets: int = _MASS_MAX_TARGETS,
                              pacing: float = 0.0) -> List[Dict[str, Any]]:
    """Kitlesel nesne-ifşa probu (I/O). Sayısal+hassas-adlı endpoint'te id-penceresini
    örnekler → KAÇ FARKLI kullanıcının PII'si dönüyor sayar. auth=None → kimliksiz
    (TEB senaryosu); auth verilirse o kimlikle kitlesel çekim. TAHRİBATSIZ (yalnız GET),
    örnek kapaklı, saklanan kanıtta ham PII YOK. ASLA raise etmez."""
    import httpx
    findings: List[Dict[str, Any]] = []
    hdrs = auth or {}
    unauth = not bool(auth)

    seen: set = set()
    targets: List[Tuple[str, ObjectRef]] = []
    for url in candidates:
        if not isinstance(url, str) or url in seen:
            continue
        seen.add(url)
        for ref in extract_object_refs(url):
            if ref.kind == "numeric" and ref.name_hint and sample_id_window(ref, 3):
                targets.append((url, ref))
                break
        if len(targets) >= max_targets:
            break
    if not targets:
        return findings

    limits = httpx.Limits(max_connections=6, max_keepalive_connections=6)
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                     timeout=_PER_REQUEST_TIMEOUT, limits=limits) as client:
            for url, ref in targets:
                try:
                    owner = await _get(client, url, hdrs)
                    # owner hiç veri döndürmüyorsa (korumalı/boş) kitlesel çekim anlamsız.
                    if not (_is_substantive(owner) and _looks_like_data(owner)):
                        continue
                    samples: List[Measured] = [owner]
                    for nv in sample_id_window(ref, sample_size):
                        m = await _get(client, replace_ref(url, ref, nv), hdrs)
                        if m is not None:
                            samples.append(m)
                        if pacing > 0:
                            await asyncio.sleep(pacing)
                    verdict = adjudicate_mass_exposure(samples, ref=ref, unauth=unauth)
                except Exception as e:
                    logger.debug(f"Kitlesel ifşa prob hatası ({url}): {e}")
                    continue
                if not verdict.get("is_idor"):
                    continue
                tier = verdict["tier"]
                sev = "critical" if tier == "confirmed" else "high"
                findings.append({
                    "url": url,
                    "ref_kind": ref.kind,
                    "ref_name": ref.name,
                    "ref_location": ref.location,
                    "tier": tier,
                    "severity": sev,
                    "cwe": ["CWE-639", "CWE-306", "CWE-200"],
                    "mitre": "T1190",
                    "title": (f"Kitlesel Nesne İfşası (Mass BOLA) @ {url}"),
                    "proof": verdict["reason"],
                    "verification_method": "idor-mass-enumeration",
                    "verification_detail": verdict["reason"][:240],
                    "verification_confidence": 0.8 if tier == "confirmed" else 0.5,
                    "distinct_pii": verdict.get("distinct_pii", 0),
                    "distinct_all": verdict.get("distinct_all", 0),
                })
    except Exception as e:
        logger.debug(f"Kitlesel ifşa probu genel hata: {e}")
    return findings
