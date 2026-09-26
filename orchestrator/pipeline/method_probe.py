"""
Kadim Güvenlik — HTTP Method Matrisi (Bug Bounty P0-B keşif ayağı)
===================================================================
Türkçe: Aynı endpoint'e GET/POST/PUT/DELETE atıp durum-kodu matrisi çıkarır. İki
değerli sinyal üretir:

  1) METHOD-SWAP ERİŞİM BOŞLUĞU (CWE-285): GET 401/403 ile korunan bir yol POST/
     PUT ile 2xx dönerse erişim kontrolü YALNIZ GET'e bakıyor demektir — klasik
     bug bounty bulgusu ("GET /admin/users 403, POST /admin/users 200"). Bu,
     TEMPLATE ile bulunamaz; deterministik istek matrisi ister.
  2) GÖVDE YÜZEYİ SİNYALİ: GET 405 + POST 2xx → endpoint yalnız gövdeyle çalışır;
     P0-B doğrulayıcıları için "buraya POST hipotezi tohumla" işaretidir.

Yorum çekirdeği SAF (interpret_method_matrix) → izole test. I/O katmanı
(probe_method_matrix) bütçe dostu: yalnız verilen URL listesi × 4 metot.

GÜVENLİK: DELETE dahil istekler GÖVDESİZ ve zararsızdır (silme denemesi değil,
durum kodu ölçümü); çoğu API gövdesiz DELETE'e 4xx ile cevap verir — ölçüm yine
değerlidir. Kapı: crawl aşaması yalnız 8 URL ile sınırlar (bütçe).
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("method-probe")

PROBED_METHODS = ("GET", "POST", "PUT", "DELETE")

# Erişim boşluğu yorumu için GET'in koruma kodları.
_BLOCKED_CODES = (401, 403)


def interpret_method_matrix(matrix: Dict[str, int]) -> Optional[Dict[str, Any]]:
    """Durum-kodu matrisini yorumla (SAF — I/O yok).

    Döner:
      {"kind": "access_gap", "method": M, "status": S, "blocked_get": G}
          GET 401/403 iken M metodu 2xx → method-swap erişim boşluğu (KANIT değeri).
      {"kind": "body_only", "method": "POST", "status": S}
          GET 405 + POST/PUT 2xx → endpoint gövdeye özel (P0-B tohum sinyali).
      None → yorumlanacak sinyal yok.
    0 durum kodu = istek hatası (ölçüm yok), yorum dışı.
    """
    if not matrix:
        return None
    get_status = matrix.get("GET") or 0

    if get_status in _BLOCKED_CODES:
        for m in ("POST", "PUT", "DELETE", "PATCH"):
            s = matrix.get(m) or 0
            if 200 <= s < 300:
                return {"kind": "access_gap", "method": m, "status": s,
                        "blocked_get": get_status}

    if get_status == 405:
        for m in ("POST", "PUT"):
            s = matrix.get(m) or 0
            if 200 <= s < 300:
                return {"kind": "body_only", "method": m, "status": s}
    return None


async def probe_method_matrix(client, urls: List[str], *,
                              methods=PROBED_METHODS,
                              timeout: float = 10.0) -> List[Dict[str, Any]]:
    """URL listesi üstünde method matrisi koş (bütçe: urls × methods istek).

    Döner: [{"url", "matrix": {method: status}, "interpretation": {...}|None}] —
    interpretation dolu satırlar operatör olayı/kanıt adayıdır. Hata → satırın
    matrix'i 0'larla kalır, yorum None (gürültü üretmez)."""
    out: List[Dict[str, Any]] = []
    for url in urls or []:
        matrix: Dict[str, int] = {}
        for m in methods:
            try:
                r = await client.request(m, url, timeout=timeout, follow_redirects=False)
                matrix[m] = r.status_code
            except Exception:
                matrix[m] = 0
        out.append({
            "url": url,
            "matrix": matrix,
            "interpretation": interpret_method_matrix(matrix),
        })
    return out
