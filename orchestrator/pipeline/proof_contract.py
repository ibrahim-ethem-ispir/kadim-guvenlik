"""
Kadim Güvenlik — Kanıt Sözleşmesi (Proof Contract) [SPIKE]
==========================================================
Türkçe: Motorun "domine eden" farkı — çıktı bir bulgu LİSTESİ değil, üçüncü bir tarafın
YENİDEN KOŞUP aynı sonucu aldığı, TEKRAR-ÜRETİLEBİLİR bir ispat paketidir.

NEDEN (doktrin):
  Sektör "otonomluk"la yarışıyor ama kanıtlanamaz kara-kutu üretiyor — her koşuda farklı
  sonuç, yüzlerce bulgu, "e ne olmuş?". Biz otonomiyi kara-kutudan çıkarıp bir İSPAT
  motoruna çeviriyoruz. Bu sözleşme üç hastalığı TANIMI GEREĞİ çözer:
    1) Tutarsızlık   -> replay_bundle() mekanik bir tekrar-üretilebilirlik testidir.
    2) False-positive-> "confirmed" olmanın TEK yolu, gözlemlerden TÜRETİLEN karardır;
                        anlatı elle yazılmaz → kanıt ile anlatı ASLA çelişemez.
    3) Hesap verme   -> paket, CISO/regülatöre verilen replay-edilebilir kanıt dosyasıdır.

Bu modül TRANSPORT-BAĞIMSIZ ve SAF'tır (I/O yok). Replay, dışarıdan enjekte edilen bir
`observe(step) -> Observation` çağrılabiliriyle sürülür → tam izole test edilebilir; ve
zincir tipinden bağımsız TEK kere yazılır (bloat yok — her bulgu buraya takılır).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Awaitable, Callable, Dict, List, Optional

# Bir adımın kanıt-yükü olan beklentisi. "informational" = kaydedilir ama KARARA girmez
# (ör. imza-kurcalama negatif kontrolü: hangi zafiyet olduğunu ayırt eder, iddiayı taşımaz).
GATING_EXPECTATIONS = ("must_be_denied", "must_be_substantive")


@dataclass
class Observation:
    """Bir adımın DİSKRİMİNAN gözlemi — ham gövde DEĞİL, kararı belirleyen sınıflandırma.
    Ham dump tutmayız: gizlilik + kararı etkilemeyen gürültüden bağımsız kararlı parmak izi."""
    status: int
    denied: bool
    substantive: bool
    page_class: Optional[str] = None
    length: int = 0


@dataclass
class ProofStep:
    """Tek, tekrar-koşulabilir HTTP adımı: ne istendi + ne beklenmeli + ne gözlendi."""
    role: str                      # anlamsal rol: anon_baseline | forged_escalation | ...
    url: str
    expectation: str               # must_be_denied | must_be_substantive | informational
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)  # replay için AYNEN gerekli
    observed: Optional[Observation] = None


@dataclass
class ProofBundle:
    """Tekrar-üretilebilir ispat paketi — confirmed bir bulgunun TEK kanıt kaynağı."""
    claim: str                     # ne iddia ediliyor (yapısal, insan-okur)
    verdict: str                   # confirmed | refuted (adımlardan TÜRETİLİR)
    adjudication: str              # kararı üreten deterministik gerekçe
    steps: List[ProofStep]
    fingerprint: str               # bulgu kimliği (gözlemden BAĞIMSIZ → koşudan koşuya sabit)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplayResult:
    """Bir ispat paketinin canlı hedefte yeniden koşulmasının sonucu."""
    reproduced: bool
    reason: str
    fresh_fingerprint: str
    diverged_step: Optional[str] = None
    fresh_steps: List[ProofStep] = field(default_factory=list)


def _predicate_holds(expectation: str, obs: Optional[Observation]) -> bool:
    """Bir adımın gözlemi beklentisini karşılıyor mu? (SAF). informational hep geçer."""
    if expectation == "informational":
        return True
    if obs is None:
        return False               # gating adım ölçülemedi → kanıt yok
    if expectation == "must_be_denied":
        return obs.denied
    if expectation == "must_be_substantive":
        return obs.substantive
    return False                   # bilinmeyen beklenti → güvenli taraf: karşılanmadı


def derive_verdict(steps: List[ProofStep]) -> tuple[str, str]:
    """Kararı adımların gözlemlerinden TÜRET (SAF). Kural: TÜM gating adımlar beklentisini
    karşılarsa confirmed; ilk karşılanmayan adımda refuted. informational adımlar karara
    girmez. Bu fonksiyon anlatının 'yalan söyleyememesinin' garantisidir — verdict koda değil,
    ölçülen gözleme bağlıdır."""
    gating = [s for s in steps if s.expectation in GATING_EXPECTATIONS]
    if not gating:
        return "refuted", "gating_kanit_adimi_yok"
    for s in gating:
        if not _predicate_holds(s.expectation, s.observed):
            return "refuted", f"{s.role}:{s.expectation}_saglanmadi"
    return "confirmed", "tum_gating_adimlari_saglandi"


def compute_fingerprint(claim: str, steps: List[ProofStep]) -> str:
    """Bulgu KİMLİĞİ (SAF). Gözlem ve uçucu header (token değeri) HARİÇ — yalnız iddia +
    prosedür (rol/method/url/beklenti). Böylece aynı hedefte aynı zafiyet koşudan koşuya
    AYNI parmak izini verir → tekrar-üretilebilirlik kimlik üzerinden doğrulanabilir."""
    skel = {
        "claim": claim,
        "steps": [[s.role, s.method, s.url, s.expectation] for s in steps],
    }
    raw = json.dumps(skel, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def build_bundle(claim: str, steps: List[ProofStep],
                 meta: Optional[Dict[str, Any]] = None) -> ProofBundle:
    """Kaydedilen adımlardan ispat paketini KUR: verdict + adjudication + fingerprint türetilir."""
    verdict, adjudication = derive_verdict(steps)
    fp = compute_fingerprint(claim, steps)
    return ProofBundle(claim=claim, verdict=verdict, adjudication=adjudication,
                       steps=steps, fingerprint=fp, meta=dict(meta or {}))


def render_narrative(bundle: ProofBundle) -> str:
    """Paketten GENEL anlatı üret (SAF). Bulgu-özel zengin metin çağırana ait; bu, her
    bulgu tipi için çalışan denetlenebilir varsayılan görünüm."""
    lines = [
        f"İDDİA: {bundle.claim}",
        f"KARAR: {bundle.verdict} ({bundle.adjudication})",
        "KANIT ADIMLARI (tekrar-koşulabilir):",
    ]
    for i, s in enumerate(bundle.steps, 1):
        o = s.observed
        if o is None:
            obs = "ölçülemedi"
        elif o.denied:
            obs = f"HTTP {o.status} · REDDEDİLDİ"
        elif o.substantive:
            obs = f"HTTP {o.status} · ANLAMLI-KABUL (len={o.length})"
        else:
            obs = f"HTTP {o.status} · nötr"
        lines.append(f"  {i}. [{s.role}] {s.method} {s.url} → beklenen: {s.expectation}; gözlenen: {obs}")
    lines.append(f"PARMAK İZİ: {bundle.fingerprint}")
    return "\n".join(lines)


async def replay_bundle(
    bundle: ProofBundle,
    observe: Callable[[ProofStep], Awaitable[Observation]],
) -> ReplayResult:
    """Paketi canlı hedefte YENİDEN KOŞ (transport dışarıdan enjekte). Her adımın isteğini
    tekrar gönderir, gözlemi tazeler, kararı yeniden türetir ve orijinalle karşılaştırır.

    reproduced = taze karar da 'confirmed' VE parmak izi aynı (aynı bulgu). Aksi halde,
    beklentisi artık karşılanmayan İLK gating adım 'diverged_step' olarak bildirilir —
    bu, aynı zamanda 'zafiyet yamandı mı?' (regresyon) testidir."""
    fresh_steps: List[ProofStep] = []
    diverged: Optional[str] = None
    for s in bundle.steps:
        try:
            obs = await observe(s)
        except Exception:
            obs = None
        fresh = ProofStep(role=s.role, url=s.url, expectation=s.expectation,
                          method=s.method, headers=dict(s.headers), observed=obs)
        fresh_steps.append(fresh)
        if diverged is None and s.expectation in GATING_EXPECTATIONS \
                and not _predicate_holds(s.expectation, obs):
            diverged = s.role

    fresh_verdict, fresh_adj = derive_verdict(fresh_steps)
    fresh_fp = compute_fingerprint(bundle.claim, fresh_steps)
    reproduced = (fresh_verdict == "confirmed" and bundle.verdict == "confirmed"
                  and fresh_fp == bundle.fingerprint)
    if reproduced:
        reason = "ispat_yeniden_uretildi"
    elif diverged:
        reason = f"sapma:{diverged}_artik_beklentiyi_karsilamiyor(muhtemel_yama)"
    else:
        reason = f"yeniden_uretilemedi:{fresh_adj}"
    return ReplayResult(reproduced=reproduced, reason=reason, fresh_fingerprint=fresh_fp,
                        diverged_step=diverged, fresh_steps=fresh_steps)


# ---------- Serileştirme (bulgu sözlüğüne gömmek + replay için rehidrasyon) ----------

def bundle_to_dict(bundle: ProofBundle) -> Dict[str, Any]:
    """Paketi JSON-uyumlu sözlüğe çevir (bulgu dict'ine / DB'ye gömülür)."""
    return asdict(bundle)


def bundle_from_dict(d: Dict[str, Any]) -> ProofBundle:
    """Sözlükten paketi geri kur (kayıtlı bir bulguyu replay etmek için)."""
    steps = []
    for sd in d.get("steps", []):
        od = sd.get("observed")
        obs = Observation(**od) if od else None
        steps.append(ProofStep(
            role=sd["role"], url=sd["url"], expectation=sd["expectation"],
            method=sd.get("method", "GET"), headers=dict(sd.get("headers", {})),
            observed=obs,
        ))
    return ProofBundle(
        claim=d["claim"], verdict=d["verdict"], adjudication=d["adjudication"],
        steps=steps, fingerprint=d["fingerprint"], meta=dict(d.get("meta", {})),
    )
