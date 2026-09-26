"""
Kadim Güvenlik — Endpoint Sürüm-Diff Monitörü (Bug Bounty P0-A)
================================================================
Türkçe: "Bakılacak yer kalmadı" hissinin ilacı. Bug bounty'de para "her yere
bakmak"tan değil, **herkesten ÖNCE YENİ yere bakmak**tan kazanılır: 6 yıldır
açık aranan bir programda bile binlerce endpoint HAFTALIK diff'le izlenir.

Bu modül crawler (endpoint_discovery) çıktısının normalize SNAPSHOT'ini alır,
bir önceki taramanın snapshot'ı ile DIFF'ler ve YENİ yüzeyi (yeni yol / yeni
parametre / yeni form) çıkarır. Zincir:

    scheduled tarama → crawl → snapshot → scan_memories(kind=endpoint_snapshot)
                     → önceki snapshot ile diff → YENİ endpoint'ler kural-tohumu
                       hipotezlerine öncelikli beslenir → doğrulama → bildirim

Tasarım (exploit_memory/path_memory deseni):
- Karar çekirdeği SAF (stdlib only) → izole test edilebilir (test_endpoint_diff.py).
- DB fonksiyonları koleksiyonu DIŞARIDAN alır; hatalar sessizce yutulur
  (diff lüks bir katman — düşerse tarama bozulmaz, doktrin: hafıza kral değil).

Neden path+param-set anahtarı: sorgu DEĞERLERİ uçucudur (CSRF token, timestamp)
ama yol+parametre ADLARI sürüm kimliğidir. Değer üstünden diff her taramada
"yeni" patlaması üretirdi (false-positive); yol+ad üstünden diff gerçek yüzey
değişimini ölçer.
"""

import logging
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, parse_qsl

logger = logging.getLogger("endpoint-diff")

# Snapshot dokümanındaki URL listesi tavanı — Mongo 16MB limiti + anlamsız şişme.
# 500 URL crawler tavanıyla (CRAWL_MAX_URLS) uyumlu.
_SNAPSHOT_URL_CAP = 600
_SNAPSHOT_PARAM_CAP = 300

# Diff çıktısında operatöre gösterilecek YENİ yüzey tavanı (event/rapor okunabilirliği).
_DIFF_REPORT_CAP = 50


# ============================================================
# SAF çekirdek — normalize + diff (I/O yok)
# ============================================================

def _canon_host(host: str) -> str:
    """www farkını normalize et (endpoint_discovery ile aynı kural)."""
    h = (host or "").strip().lower()
    return h[4:] if h.startswith("www.") else h


def url_key(url: str) -> Optional[Tuple[str, str]]:
    """URL'yi (host, path) anahtarına indir. Sorgu değerleri ATILIR — sürüm kimliği
    yol+host'tur. Geçersiz/boş URL → None (diff'e gürültü karışmaz)."""
    s = str(url or "").strip()
    if not s:
        return None
    # Şeması olup '//' olmayan girdiler (mailto:, tel:) URL değildir — http ekleme.
    if "://" not in s:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", s):
            return None
        s = "http://" + s
    try:
        parts = urlsplit(s)
    except ValueError:
        return None
    if not parts.netloc or parts.scheme not in ("http", "https"):
        return None
    path = parts.path or "/"
    return (_canon_host(parts.netloc.split("@")[-1].split(":")[0]), path)


def param_key(url: str) -> Optional[Tuple[str, str, Tuple[str, ...]]]:
    """Parametreli endpoint'i (host, path, param-adları) anahtarına indir.
    Parametresi yoksa None (yalnız yol anahtarı url_key'de kalır)."""
    s = str(url or "").strip()
    if not s:
        return None
    if "://" not in s:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", s):
            return None
        s = "http://" + s
    try:
        parts = urlsplit(s)
    except ValueError:
        return None
    if not parts.netloc or parts.scheme not in ("http", "https"):
        return None
    params = tuple(sorted(dict.fromkeys(
        k for k, _v in parse_qsl(parts.query, keep_blank_values=True) if k)))
    if not params:
        return None
    return (_canon_host(parts.netloc.split("@")[-1].split(":")[0]),
            parts.path or "/", params)


def form_key(form: Dict[str, Any]) -> Optional[Tuple[str, str, str, Tuple[str, ...]]]:
    """Form'u (host, action-path, method, input-adları) anahtarına indir.
    Yeni form = yeni saldırı yüzeyi (özellikle POST — P0-B gövde kapsamı)."""
    action = str((form or {}).get("action") or "").strip()
    if not action:
        return None
    k = url_key(action)
    if k is None:
        return None
    method = str((form or {}).get("method") or "get").strip().lower()
    inputs = tuple(sorted(dict.fromkeys(
        str(i) for i in ((form or {}).get("inputs") or []) if str(i).strip())))
    return (k[0], k[1], method, inputs)


def build_snapshot(
    discovered_urls: List[str],
    parameterized_endpoints: List[Dict[str, Any]],
    forms: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Crawler çıktısından normalize snapshot üret (SAF — I/O yok).

    Şema: {"urls": [host+path anahtarları], "params": {host+path: [param adları]},
           "forms": [form anahtarları], "counts": {...}} — listeler tekilleştirilmiş,
    tavanlı (DB şişmesin). Bu şekil diff'i deterministik yapar: aynı yüzey her
    taramada AYNI snapshot'ı verir (crawl sırası/tesadüf fark etmez)."""
    urls: List[List[str]] = []
    seen_u: Set[Tuple[str, str]] = set()
    for u in discovered_urls or []:
        k = url_key(u)
        if k and k not in seen_u:
            seen_u.add(k)
            urls.append(list(k))
            if len(urls) >= _SNAPSHOT_URL_CAP:
                break

    params: Dict[str, List[str]] = {}
    for ep in parameterized_endpoints or []:
        raw = ep.get("url") if isinstance(ep, dict) else ep
        k = param_key(raw)
        if not k:
            continue
        pk = f"{k[0]}{k[1]}"
        if pk not in params:
            params[pk] = list(k[2])
        if len(params) >= _SNAPSHOT_PARAM_CAP:
            break

    form_keys: List[List[str]] = []
    seen_f: Set[Tuple] = set()
    for f in forms or []:
        fk = form_key(f)
        if fk and fk not in seen_f:
            seen_f.add(fk)
            form_keys.append([fk[0], fk[1], fk[2], list(fk[3])])

    return {
        "urls": urls,
        "params": params,
        "forms": form_keys,
        "counts": {
            "urls": len(urls),
            "params": len(params),
            "forms": len(form_keys),
        },
    }


def diff_snapshots(prev: Optional[Dict[str, Any]], curr: Dict[str, Any]) -> Dict[str, Any]:
    """Önceki snapshot ile şimdikini karşılaştır → YENİ yüzey (SAF — I/O yok).

    prev=None → ilk tarama (baseline): hiçbir şey 'yeni' sayılmaz, yalnız sayılır.
    Çıktı:
      is_first        : baseline mı (önceki snapshot yok)
      new_urls        : ilk kez görülen (host, path) listesi
      new_params      : bilinen ya da yeni yollarda ilk kez görülen parametre setleri
      new_forms       : ilk kez görülen formlar
      removed_url_count: önceki snapshot'ta olup artık görünmeyen yol sayısı
                         (yüzey DARALDI — kapanan endpoint de haberdir)
      unchanged_url_count: iki snapshot'ta ortak yol sayısı
    """
    curr = curr or {}
    curr_urls = {tuple(u) for u in curr.get("urls") or []}
    curr_params = curr.get("params") or {}
    curr_forms = {tuple(tuple(x) if isinstance(x, list) else x for x in f)
                  for f in curr.get("forms") or []}

    if not prev:
        return {
            "is_first": True,
            "new_urls": [], "new_params": [], "new_forms": [],
            "removed_url_count": 0, "unchanged_url_count": 0,
            "counts": curr.get("counts") or {},
        }

    prev_urls = {tuple(u) for u in prev.get("urls") or []}
    prev_params = prev.get("params") or {}
    prev_forms = {tuple(tuple(x) if isinstance(x, list) else x for x in f)
                  for f in prev.get("forms") or []}

    new_urls = sorted(curr_urls - prev_urls)[:_DIFF_REPORT_CAP]
    removed = prev_urls - curr_urls

    # Parametre diff'i iki katmanlı: yol YENİ ise tüm paramları yeni say; yol biliniyorsa
    # yalnız parametre ADI kümesindeki ekler yeni (değer değişimi gürültüsü zaten yok —
    # anahtar ad kümesi).
    new_params: List[Dict[str, Any]] = []
    for pk, plist in curr_params.items():
        before = prev_params.get(pk)
        if before is None:
            new_params.append({"endpoint": pk, "params": list(plist), "kind": "new_endpoint"})
        else:
            added = [p for p in plist if p not in before]
            if added:
                new_params.append({"endpoint": pk, "params": added, "kind": "new_param"})
        if len(new_params) >= _DIFF_REPORT_CAP:
            break

    new_forms = [list(f) for f in sorted(curr_forms - prev_forms)][:_DIFF_REPORT_CAP]

    return {
        "is_first": False,
        "new_urls": [list(u) for u in new_urls],
        "new_params": new_params,
        "new_forms": new_forms,
        "removed_url_count": len(removed),
        "unchanged_url_count": len(curr_urls & prev_urls),
        "counts": curr.get("counts") or {},
    }


def diff_has_news(diff: Dict[str, Any]) -> bool:
    """Diff'te operatöre bildirilecek YENİ yüzey var mı? (ilk tarama 'yeni' sayılmaz —
    baseline'dır; her şey zaten ilk kez görülüyor)."""
    if not diff or diff.get("is_first"):
        return False
    return bool(diff.get("new_urls") or diff.get("new_params") or diff.get("new_forms"))


def diff_headline(diff: Dict[str, Any]) -> str:
    """Diff'in tek satırlık Türkçe özeti (event mesajı + LLM prompt'u için)."""
    if not diff:
        return "Endpoint diff alınamadı."
    if diff.get("is_first"):
        c = diff.get("counts") or {}
        return (f"İl tarama (baseline): {c.get('urls', 0)} yol, "
                f"{c.get('params', 0)} parametreli endpoint, {c.get('forms', 0)} form kaydedildi.")
    nu = len(diff.get("new_urls") or [])
    np = len(diff.get("new_params") or [])
    nf = len(diff.get("new_forms") or [])
    if not (nu or np or nf):
        return ("Yüzey değişmedi — önceki taramadan bu yana yeni yol/parametre/form YOK "
                f"({diff.get('unchanged_url_count', 0)} yol sabit).")
    parts = []
    if nu:
        parts.append(f"{nu} yeni yol")
    if np:
        parts.append(f"{np} yeni parametre/endpoint")
    if nf:
        parts.append(f"{nf} yeni form")
    return "🆕 YENİ YÜZEY: " + ", ".join(parts) + " — taze bug olasılığı en yüksek yer."


def new_surface_urls(diff: Dict[str, Any], *, scheme: str = "https") -> List[str]:
    """Diff'teki YENİ yüzeyi doğrulayıcıların tüketebileceği URL listesine çevir.
    new_params öğeleri zaten tam URL'ye çevrilebilir (path+param adları); new_urls
    parametresiz yollardır (method-matrix/DAST adayı olarak döner)."""
    out: List[str] = []
    seen: Set[str] = set()
    for item in diff.get("new_params") or []:
        ep = str(item.get("endpoint") or "")
        params = item.get("params") or []
        if not ep or not params:
            continue
        # ep biçimi 'host/path' — şema ekle, parametreleri boş değerle kur.
        url = f"{scheme}://{ep}" + "?" + "&".join(f"{p}=" for p in params)
        if url not in seen:
            seen.add(url)
            out.append(url)
    for u in diff.get("new_urls") or []:
        if isinstance(u, (list, tuple)) and len(u) == 2:
            url = f"{scheme}://{u[0]}{u[1]}"
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out[:_DIFF_REPORT_CAP]


# ============================================================
# DB katmanı — scan_memories (kind=endpoint_snapshot)
# ============================================================
# Anahtar: (kind, host). Son snapshot + bir önceki tutulur (diff zinciri).
# no_diff_streak: üst üste kaç taramada yüzey değişmedi — "program bitti" kapanış
# kriterinin ölçülebilir sinyali (≥2 hafta diff'siz = yüzey durağan).

def load_latest_snapshot(collection: Any, host: str) -> Optional[Dict[str, Any]]:
    """Host için son kaydedilmiş snapshot dokümanını getir. Hata → None (tarama düşmez)."""
    h = _canon_host(host)
    if not h:
        return None
    try:
        doc = collection.find_one({"kind": "endpoint_snapshot", "host": h})
        if doc is not None:
            # Kopya üstünden _id düşür — orijinal dokümanı mutasyona uğratma
            # (paylaşılan referans üstünden pop, depolanan kaydın _id'sini silerdi).
            doc = dict(doc)
            doc.pop("_id", None)
        return doc
    except Exception as e:
        logger.warning(f"Endpoint snapshot okunamadı ({h}): {e}")
        return None


def save_snapshot(collection: Any, *, host: str, snapshot: Dict[str, Any],
                  scan_id: str, diff: Optional[Dict[str, Any]] = None) -> bool:
    """Yeni snapshot'ı upsert et; diff sonucunu da dokümana işle (no_diff_streak
    sayacı burada sürer). Best-effort: hata sessizce yutulur, False döner."""
    h = _canon_host(host)
    if not h or not snapshot:
        return False
    now = datetime.utcnow()
    try:
        doc = collection.find_one({"kind": "endpoint_snapshot", "host": h})
        prev_streak = int((doc or {}).get("no_diff_streak", 0) or 0)
        if diff is None or diff.get("is_first"):
            streak = 0
        elif diff_has_news(diff):
            streak = 0
        else:
            streak = prev_streak + 1
        payload = {
            "kind": "endpoint_snapshot",
            "host": h,
            "snapshot": snapshot,
            "scan_id": scan_id,
            "taken_at": now,
            "no_diff_streak": streak,
            "last_changed_at": (doc or {}).get("last_changed_at")
                               if (diff and not diff_has_news(diff)) else now,
            "previous_counts": ((doc or {}).get("snapshot") or {}).get("counts"),
            "last_diff": {
                "new_urls": len((diff or {}).get("new_urls") or []),
                "new_params": len((diff or {}).get("new_params") or []),
                "new_forms": len((diff or {}).get("new_forms") or []),
                "is_first": bool((diff or {}).get("is_first")),
            } if diff else None,
        }
        if doc:
            collection.replace_one({"_id": doc["_id"]}, {**doc, **payload})
        else:
            collection.insert_one({"_id": str(uuid.uuid4()), **payload})
        return True
    except Exception as e:
        logger.warning(f"Endpoint snapshot yazılamadı ({h}): {e}")
        return False
