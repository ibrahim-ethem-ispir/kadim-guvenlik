"""
Kadim Güvenlik — Kanıt Sözleşmesi (proof_contract) birim testleri [SPIKE]
=========================================================================
Türkçe: Omurgayı transport'suz, ağsız, tam izole doğrular (düz script, pytest yok).
Kanıtlanan sözleşme: karar gözlemden TÜRETİLİR (anlatı yalan söyleyemez), parmak izi
koşudan-koşuya sabit, replay mekanik bir tekrar-üretilebilirlik/regresyon testidir.

Çalıştır: python3 orchestrator/pipeline/test_proof_contract.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.proof_contract import (  # noqa: E402
    Observation, ProofStep, build_bundle, derive_verdict, compute_fingerprint,
    render_narrative, replay_bundle, bundle_to_dict, bundle_from_dict,
)


def _denied():
    return Observation(status=403, denied=True, substantive=False, page_class="auth_wall", length=9)


def _accepted():
    return Observation(status=200, denied=False, substantive=True, page_class=None, length=180)


def _steps_confirmed():
    return [
        ProofStep(role="anon_baseline", url="https://t/admin", expectation="must_be_denied",
                  headers={}, observed=_denied()),
        ProofStep(role="forged_escalation", url="https://t/admin", expectation="must_be_substantive",
                  headers={"Authorization": "Bearer X"}, observed=_accepted()),
        ProofStep(role="signature_tamper_control", url="https://t/admin", expectation="informational",
                  headers={"Authorization": "Bearer garbage"}, observed=_denied()),
    ]


def test_derive_verdict_confirmed():
    v, why = derive_verdict(_steps_confirmed())
    assert v == "confirmed", why


def test_derive_verdict_refuted_gating_dususte():
    steps = _steps_confirmed()
    steps[1].observed = _denied()          # forged artık kabul EDİLMİYOR → gating düşer
    v, why = derive_verdict(steps)
    assert v == "refuted" and "forged_escalation" in why, why


def test_informational_karara_girmez():
    steps = _steps_confirmed()
    steps[2].observed = _accepted()        # tamper kabul edildi ama informational → karar bozulmaz
    v, _ = derive_verdict(steps)
    assert v == "confirmed"


def test_fingerprint_gozlemden_bagimsiz_sabit():
    a = build_bundle("iddia-1", _steps_confirmed())
    steps2 = _steps_confirmed()
    steps2[1].observed = Observation(status=200, denied=False, substantive=True,
                                     page_class=None, length=999)  # farklı gövde uzunluğu
    b = build_bundle("iddia-1", steps2)
    assert a.fingerprint == b.fingerprint       # gözlem değişti, KİMLİK aynı
    c = build_bundle("iddia-2-farkli", _steps_confirmed())
    assert c.fingerprint != a.fingerprint       # iddia değişti → kimlik değişti


def test_render_narrative_paketten_turer():
    b = build_bundle("JWT forge @ /admin", _steps_confirmed())
    txt = render_narrative(b)
    assert b.fingerprint in txt and "confirmed" in txt
    assert "anon_baseline" in txt and "forged_escalation" in txt


def test_serilestirme_roundtrip():
    b = build_bundle("iddia", _steps_confirmed())
    b2 = bundle_from_dict(bundle_to_dict(b))
    assert b2.fingerprint == b.fingerprint and b2.verdict == b.verdict
    assert len(b2.steps) == 3 and b2.steps[0].observed.denied is True


def test_replay_yeniden_uretir():
    b = build_bundle("iddia", _steps_confirmed())
    # Enjekte observe: hedef hâlâ zafiyetli (kayıtlı gözlemleri aynen döndür).
    recorded = {s.role: s.observed for s in b.steps}

    async def observe(step):
        return recorded[step.role]

    res = asyncio.run(replay_bundle(b, observe))
    assert res.reproduced is True and res.diverged_step is None
    assert res.fresh_fingerprint == b.fingerprint


def test_replay_regresyon_yakalar():
    b = build_bundle("iddia", _steps_confirmed())

    async def observe(step):
        # Yama: forged artık reddediliyor (gating adım düşer).
        if step.role == "forged_escalation":
            return _denied()
        return _denied()

    res = asyncio.run(replay_bundle(b, observe))
    assert res.reproduced is False
    assert res.diverged_step == "forged_escalation", res.reason
    assert res.fresh_fingerprint == b.fingerprint   # kimlik sabit → "aynı bulgu, artık geçmiyor"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"✓ {fn.__name__}")
    print(f"\n{len(fns)} test geçti.")
