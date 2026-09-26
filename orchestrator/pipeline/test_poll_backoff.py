"""
Kadim Güvenlik — D2 ölü-hizmet erken vazgeçme testleri (poll_with_backoff)
==========================================================================
Türkçe: poll_with_backoff'un kalıcı-yokluk (dead service) durumunda 600s tavanını yakmadan
erken vazgeçtiğini; buna karşın ARALIKLI hatalarda (başarılı yoklama sayacı sıfırlar) erken
vazgeçmediğini izole doğrular. Sleep'ler minik interval ile hızlandırılır (gerçek ağ yok).

Çalıştır: python3 -m pipeline.test_poll_backoff
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pipeline.scan_pipeline_v2 import poll_with_backoff

# Testlerde sleep'i ihmal edilebilir kıl (backoff_factor=1 → sabit minik interval).
FAST = dict(initial_interval=0.001, max_interval=0.001, backoff_factor=1.0)


async def _run():
    # 1) ÖLÜ HİZMET: check_fn hep patlar → tavanı beklemeden vazgeç, unreachable işaretli.
    calls = {"n": 0}

    async def always_raises():
        calls["n"] += 1
        raise ConnectionError("service down")

    res = await poll_with_backoff(always_raises, max_timeout=9999,
                                  max_consecutive_errors=5, **FAST)
    assert res.get("status") == "timeout", res            # geriye-uyum: çağıranlar 'timeout' işler
    assert res.get("unreachable") is True, res            # ek bilgilendirme bayrağı
    assert calls["n"] == 5, calls                         # tam eşikte kesildi, 600s yakmadı
    print("[OK] test_dead_service_early_giveup")

    # 2) ARALIKLI HATA: 4 patlama arasına başarılı (done=False) yoklamalar → sayaç sıfırlanır,
    #    erken vazgeçme TETİKLENMEZ; sonunda done=True gelince gerçek sonuç döner.
    seq = ["err", "ok", "err", "ok", "err", "ok", "err", "done"]
    idx = {"i": 0}

    async def intermittent():
        step = seq[idx["i"]]
        idx["i"] += 1
        if step == "err":
            raise TimeoutError("hiccup")
        if step == "done":
            return {"done": True, "result": {"status": "completed", "data": {"ok": 1}}}
        return {"done": False}

    res2 = await poll_with_backoff(intermittent, max_timeout=9999,
                                   max_consecutive_errors=3, **FAST)
    assert res2 == {"status": "completed", "data": {"ok": 1}}, res2   # erken vazgeçmedi
    print("[OK] test_intermittent_errors_no_early_giveup")

    # 3) KAPALI (max_consecutive_errors=0): eski davranış — hep tavana kadar, unreachable yok.
    async def raises2():
        raise ConnectionError("down")

    res3 = await poll_with_backoff(raises2, max_timeout=0.005,
                                   max_consecutive_errors=0, **FAST)
    assert res3.get("status") == "timeout", res3
    assert "unreachable" not in res3, res3
    print("[OK] test_disabled_drains_to_timeout")

    # 4) NORMAL: done=True → sonuç aynen döner (regresyon yok).
    async def done_now():
        return {"done": True, "result": {"status": "completed"}}

    res4 = await poll_with_backoff(done_now, max_timeout=9999, **FAST)
    assert res4 == {"status": "completed"}, res4
    print("[OK] test_normal_completion")


if __name__ == "__main__":
    asyncio.run(_run())
    print("\nTüm testler geçti.")
