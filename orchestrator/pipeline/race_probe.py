"""
Kadim Güvenlik — Finansal & İş Mantığı Güvenliği: Race Condition (Yarış Durumu) Probu
=====================================================================================
Türkçe: Bankacılık, FinTech ve kurumsal sistemlerde (İşbank İşim / İşim Kolay vb.)
en kritik mantık açıklarından biri eşzamanlılık (concurrency) ve yarış durumudur (CWE-362).
Bakiye düşümü, kupon/indirim kullanımı, limit kontrolü veya para transferi noktalarında
sunucu kilit (mutex / atomic transaction / idempotency key) kullanmazsa, aynı milisaniyede
gönderilen çoklu istekler mükerrer işlem yapabilir (Double-Spending / Limit Bypass).

Tasarım İlkeleri:
1. SAF ÇEKİRDEK: `is_financial_target` ve `adjudicate_concurrency` fonksiyonları
   tamamen saf matematik ve metin karşılaştırmasıdır (izole test edilebilir).
2. TAHRİBATSIZ (Non-Destructive): Gerçek bakiye eksiltme veya sistem bozma yapmaz;
   güvenli keşif parametreleriyle eşzamanlılık kalkanını (idempotency, 429 rate limit, 409 conflict)
   yoklar.
3. KADEME (Confidence Tier):
   - 'confirmed': Sunucu aynı anda atılan 8-10 isteğin hepsine idempotency/kilit olmadan 200/201 döndü ve gövdelerde işlem mükerrerliği kanıtlandı.
   - 'probable': Finansal uçta hız sınırlaması (rate limit) ve anti-replay kalkanı yok.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger("race-probe")

# Finansal / İşlem adayı anahtar kelimeleri
_FINANCIAL_KEYWORDS = re.compile(
    r"(?:^|[/_?&=-])(transfer|pay|payment|odeme|bakiye|balance|limit|coupon|kupon|"
    r"voucher|indirim|discount|redeem|checkout|siparis|order|hesap|account|"
    r"withdraw|deposit|para|credit|kredi|cuzdan|wallet)(?:$|[/_?&=-])",
    re.I
)

# Statik varlık uzantıları (bunlar asla finansal uç olamaz)
_STATIC_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip"
)


def is_financial_target(url: str) -> bool:
    """Verilen URL bir finansal işlem / durum-değiştirici uç adayı mı? (SAF)"""
    if not url or not isinstance(url, str):
        return False
    parts = urlsplit(url)
    path_and_query = f"{parts.path}?{parts.query}"
    if parts.path.lower().endswith(_STATIC_EXT):
        return False
    return bool(_FINANCIAL_KEYWORDS.search(path_and_query))


@dataclass
class ConcurrencyVerdict:
    """Eşzamanlılık testi değerlendirme sonucu."""
    is_vulnerable: bool
    confidence_tier: str       # "confirmed" | "probable" | "clean"
    title: str
    detail: str
    status_codes: List[int] = field(default_factory=list)
    success_count: int = 0
    replay_protection_found: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_vulnerable": self.is_vulnerable,
            "confidence_tier": self.confidence_tier,
            "title": self.title,
            "detail": self.detail,
            "status_codes": self.status_codes,
            "success_count": self.success_count,
            "replay_protection_found": self.replay_protection_found,
        }


def adjudicate_concurrency(
    responses: List[Tuple[int, str, float]],
    target_url: str,
    burst_count: int = 8,
    method: str = "GET",
) -> ConcurrencyVerdict:
    """
    Eşzamanlı istek sonuçlarını değerlendir (SAF — I/O yok).
    responses: [(status_code, body, elapsed_seconds), ...]
    """
    if not responses:
        return ConcurrencyVerdict(
            is_vulnerable=False,
            confidence_tier="clean",
            title="Eşzamanlılık Denetimi Yapılamadı",
            detail="Sunucu yanıtsız kaldı."
        )

    codes = [r[0] for r in responses]
    successes = [r for r in responses if 200 <= r[0] < 300]
    conflict_or_ratelimit = any(c in (409, 423, 429) for c in codes)

    # 1. Eğer 409 (Conflict), 423 (Locked) veya 429 (Too Many Requests) döndüyse sunucu eşzamanlılığı kontrol ediyor
    if conflict_or_ratelimit:
        return ConcurrencyVerdict(
            is_vulnerable=False,
            confidence_tier="clean",
            title="Eşzamanlılık Koruması Aktif",
            detail=f"Sunucu {burst_count} paralel istekte koruma sağladı (Hız limiti / kilit yanıtları görüldü).",
            status_codes=codes,
            success_count=len(successes),
            replay_protection_found=True,
        )

    # 2. İDEMPOTENT METOT KAPISI (FP önleme): GET/HEAD/OPTIONS güvenli+idempotenttir; bunlara
    #    N×2xx dönmesi BEKLENEN davranıştır, race condition KANITI DEĞİL. Idempotent metotta
    #    asla zafiyet işaretleme (aksi halde /my-account, /checkout gibi salt-okunur uçlar
    #    8×200 dönüp yanlış CONFIRMED CWE-362 üretiyordu).
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return ConcurrencyVerdict(
            is_vulnerable=False,
            confidence_tier="clean",
            title="Eşzamanlılık Denetimi (idempotent metot)",
            detail=(f"{method.upper()} idempotenttir; {len(successes)}/{burst_count} 2xx yanıtı "
                    f"beklenen davranıştır — race condition için kanıt değil (durum-değiştirici "
                    f"metot gözlemlenmeden CWE-362 iddia edilmez)."),
            status_codes=codes,
            success_count=len(successes),
            replay_protection_found=False,
        )

    # 3. DURUM-DEĞİŞTİRİCİ metotta (POST/PUT/PATCH) çoğul 2xx → eşzamanlılık koruması GÖZLENMEDİ.
    #    Ama tahribatsız gözlemle gerçek durum-mükerrerliğini (çift harcama) KANITLAYAMAYIZ →
    #    tier en fazla 'probable' (asla 'confirmed'). Gövdeler özdeşse (aynı işlem tekrar tekrar
    #    işlenmiş olabilir) kanıtı güçlendiren not düşülür — bodies artık gerçekten kullanılıyor.
    if len(successes) >= max(3, int(burst_count * 0.75)):
        bodies = [r[1][:500] for r in successes if r[1]]
        identical = len(bodies) >= 2 and len(set(bodies)) == 1
        body_note = (" Başarılı yanıt gövdeleri özdeş — aynı işlemin mükerrer işlenmiş "
                     "olabileceğine işaret." if identical else "")
        return ConcurrencyVerdict(
            is_vulnerable=True,
            confidence_tier="probable",
            title="Olası Eşzamanlılık / Race Condition (CWE-362)",
            detail=(
                f"{method.upper()} durum-değiştirici uçta ({target_url}) eşzamanlı gönderilen "
                f"{len(successes)}/{burst_count} istek 2xx döndü; idempotency-key / atomik kilit "
                f"(429/409/423) yanıtı GÖZLENMEDİ.{body_note} Çift harcama/limit aşımı riski — "
                f"durum gözlemiyle manuel doğrulanmalı (tahribatsız probun kesinleştiremediği)."
            ),
            status_codes=codes,
            success_count=len(successes),
            replay_protection_found=False,
        )

    return ConcurrencyVerdict(
        is_vulnerable=False,
        confidence_tier="clean",
        title="Temiz",
        detail="Belirgin eşzamanlılık anomalisine rastlanmadı.",
        status_codes=codes,
        success_count=len(successes),
        replay_protection_found=False,
    )


async def probe_race_condition(
    url: str,
    client: httpx.AsyncClient,
    *,
    burst_count: int = 8,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET"
) -> ConcurrencyVerdict:
    """
    Finansal hedef uca senkronize paralel istek patlaması gönderir (I/O).
    """
    req_headers = dict(headers or {})
    m = method.upper()

    # İstekleri hazırla
    tasks = []
    for _ in range(burst_count):
        if m == "POST":
            tasks.append(client.post(url, headers=req_headers, timeout=10.0))
        else:
            tasks.append(client.get(url, headers=req_headers, timeout=10.0))

    start_time = time.time()
    raw_resps = await asyncio.gather(*tasks, return_exceptions=True)

    collected: List[Tuple[int, str, float]] = []
    for r in raw_resps:
        if isinstance(r, httpx.Response):
            collected.append((r.status_code, r.text or "", time.time() - start_time))
        else:
            collected.append((0, "", 0.0))

    return adjudicate_concurrency(collected, url, burst_count=burst_count, method=m)
