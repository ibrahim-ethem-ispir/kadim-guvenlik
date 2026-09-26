"""
Kadim Güvenlik — Verifier-Guided Generate-and-Verify (Best-of-N) + Hafıza
=========================================================================
Türkçe: "Zeka modelde değil DOĞRULAYICIDA" ilkesinin algoritması. Her turda N ucuz ADAY üret;
deterministik ORACLE (verifier) hangisinin GERÇEK olduğunu SEÇSİN; kazanan/kaybeden AİLE-bazlı
hafızaya yazılsın (experience replay). Böylece:
  • anında kabiliyet — çok deneme + kanıt-seçim (Best-of-N),
  • otomatik eğitim/tercih verisi — kazanan = kabul, kaybeden = ret (model eğitmeden).

DOKTRİN: karar HEP deterministik verifier'da. Aday üretimi (LLM/korpus/mutasyon) yalnız
ÖNERİDİR; LLM "bu zafiyet var" diyemez — kanıt oracle'dan gelir.

NEDEN (mimari gerekçe): Model eğitmek pahalı, bayat ve projene-bağımlı bilgiyi ağırlığa
gömmeye çalışır (yanlış araç). Elimizdeki ASIL ayrıcalık deterministik oracle'dır (marker
yansıması / OAST callback / zamanlama). Bu modül o oracle'ı ÇARPAN yapar: çok aday → oracle
seçer → hafıza birikir. Küçük model (LoRA/distillation) bu döngü ÇALIŞTIKTAN sonra yalnız
hızlandırıcı olarak gelir.

SAF çekirdek (aday planı + sonuç seçimi + aile istatistiği) + ince async runner. Ağ/DB/LLM
YOK (runner verify_fn'i dışarıdan alır). İzole test: test_verifier_sampling.py.
"""

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple


@dataclass
class Candidate:
    """Bir saldırı/hipotez adayı. `family`: strateji ailesi (builtin/corpus/mutation/llm)."""
    id: str
    family: str
    payload: Any
    prior: float = 0.0                 # yüksek = önce denenir (ör. sahada kanıtlanmış şablon)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    """Bir adayın doğrulama sonucu (oracle çıktısı). finding dolu ise KANITLANDI."""
    verified: bool = False
    confidence: float = 0.0
    detail: str = ""
    finding: Optional[Dict[str, Any]] = None


@dataclass
class SamplingResult:
    """Best-of-N koşusunun özeti (rapor/hafıza için)."""
    winner: Optional[Candidate] = None
    winner_verdict: Optional[Verdict] = None
    results: List[Tuple[Candidate, Verdict]] = field(default_factory=list)
    planned: int = 0
    tried: int = 0
    # Aile → {tried, wins, win_rate} — hangi strateji işe yarıyor (experience replay dersi).
    family_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "winner": self.winner.id if self.winner else None,
            "winner_family": self.winner.family if self.winner else None,
            "verified": bool(self.winner is not None),
            "planned": self.planned,
            "tried": self.tried,
            "family_stats": self.family_stats,
        }


def plan_best_of_n(candidates: List[Candidate], n: int,
                   *, dedup_key: Optional[Callable[[Candidate], Any]] = None) -> List[Candidate]:
    """Adayları AİLE-ÇEŞİTLİLİĞİ gözeterek ilk n'e indir (SAF).

    Round-robin: her turda, prior'ı en yüksek aileden sıradaki adayı al → tek aileye yığılma
    olmaz (farklı strateji = farklı başarı şansı). dedup_key verilirse aynı anahtarlı adaylar
    TEK kez alınır (ör. builtin ile corpus'ta aynı payload tekrar denenmesin — dokunuş bütçesi).
    """
    if n <= 0:
        return []
    seen: set = set()
    by_family: Dict[str, List[Candidate]] = {}
    for c in candidates:
        k = dedup_key(c) if dedup_key else c.id
        if k in seen:
            continue
        seen.add(k)
        by_family.setdefault(c.family, []).append(c)
    for fam in by_family:
        by_family[fam].sort(key=lambda c: c.prior, reverse=True)

    # Aile sırası: en yüksek prior'a sahip aile önce (öncelik korunur).
    fam_prior = {f: max(c.prior for c in lst) for f, lst in by_family.items()}
    order = sorted(by_family.keys(), key=lambda f: fam_prior[f], reverse=True)
    idx = {f: 0 for f in order}
    out: List[Candidate] = []
    while len(out) < n:
        progressed = False
        for fam in order:
            if len(out) >= n:
                break
            i = idx[fam]
            lst = by_family[fam]
            if i < len(lst):
                out.append(lst[i])
                idx[fam] = i + 1
                progressed = True
        if not progressed:
            break
    return out


def select_best(results: List[Tuple[Candidate, Verdict]]) -> Tuple[Optional[Candidate], Optional[Verdict]]:
    """Kanıtlanan (verified) adaylar arasından en iyisini seç (SAF). Yoksa (None, None).

    Sıralama: confidence DESC, sonra prior DESC, sonra tried-sırası (ilk kazanan avantajlı).
    """
    best: Tuple[Optional[Candidate], Optional[Verdict]] = (None, None)
    best_key: Optional[Tuple[float, float]] = None
    for c, v in results:
        if not v.verified:
            continue
        key = (float(v.confidence or 0.0), float(c.prior or 0.0))
        if best_key is None or key > best_key:
            best_key = key
            best = (c, v)
    return best


def outcome_summary(results: List[Tuple[Candidate, Verdict]]) -> Dict[str, Dict[str, Any]]:
    """Aile-bazlı kazanma istatistiği (SAF) → hafıza dersi/replay ağırlığı."""
    stats: Dict[str, Dict[str, Any]] = {}
    for c, v in results:
        s = stats.setdefault(c.family, {"tried": 0, "wins": 0})
        s["tried"] += 1
        if v.verified:
            s["wins"] += 1
    for _fam, s in stats.items():
        s["win_rate"] = round(s["wins"] / s["tried"], 3) if s["tried"] else 0.0
    return stats


async def run_best_of_n(
    candidates: List[Candidate],
    verify_fn: Callable[[Candidate], Awaitable[Verdict]],
    n: int,
    *,
    early_exit: bool = True,
    dedup_key: Optional[Callable[[Candidate], Any]] = None,
) -> SamplingResult:
    """N adayı SIRAYLA doğrula (bütçe-dostu), tüm sonuçları topla; kanıtlananı seç.

    early_exit=True: verifier bir KAZANAN bulur bulmaz dur (kalan adayları harcama — dokunuş
    bütçesi/stealth). Sonuç yine de `select_best` ile en iyi kazananı döndürür (tek kazanan olsa
    da). verify_fn saf-dışı (I/O) katmandır; bu modül onu yalnız çağırır → izole test edilebilir.
    """
    plan = plan_best_of_n(candidates, n, dedup_key=dedup_key)
    res = SamplingResult(planned=len(plan))
    for cand in plan:
        try:
            v = await verify_fn(cand)
        except Exception as e:
            v = Verdict(False, 0.0, f"verify-error: {type(e).__name__}")
        res.results.append((cand, v))
        res.tried += 1
        if early_exit and v.verified:
            break
    res.winner, res.winner_verdict = select_best(res.results)
    res.family_stats = outcome_summary(res.results)
    return res