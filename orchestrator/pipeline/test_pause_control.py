"""
Duraklat/devam kapısı (pause_control.PauseGate) testleri — §2.5.

NEDEN: Otonom motorda gerçek bir pause/resume yoktu; yalnız (geri dönüşsüz) cancel vardı.
'Durdur/devam sıkıntılı' şikâyeti için motorun SIRADAKİ hamleyi bekletebilmesi gerekir.
Bu kapı: paused=False iken bekleme anında geçer; True iken resume gelene kadar bloke eder.

Çalıştır: python3 orchestrator/pipeline/test_pause_control.py
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.pause_control import PauseGate


def test_starts_unpaused():
    g = PauseGate()
    assert g.paused is False


def test_pause_and_resume_toggle():
    g = PauseGate()
    g.pause()
    assert g.paused is True
    g.resume()
    assert g.paused is False


async def _wait_returns_immediately_when_unpaused():
    g = PauseGate()
    # 0.2s içinde dönmezse takılmış demektir → timeout hatası (test kırmızı).
    await asyncio.wait_for(g.wait_while_paused(), timeout=0.2)


async def _wait_blocks_until_resume():
    g = PauseGate()
    g.pause()
    waiter = asyncio.create_task(g.wait_while_paused())
    await asyncio.sleep(0.05)
    assert not waiter.done(), "paused iken beklemeci dönmemeli"
    g.resume()
    await asyncio.wait_for(waiter, timeout=0.2)  # resume'dan sonra geçmeli
    assert waiter.done()


def main():
    test_starts_unpaused()
    print("[OK] starts_unpaused")
    test_pause_and_resume_toggle()
    print("[OK] pause_and_resume_toggle")
    asyncio.run(_wait_returns_immediately_when_unpaused())
    print("[OK] wait_returns_immediately_when_unpaused")
    asyncio.run(_wait_blocks_until_resume())
    print("[OK] wait_blocks_until_resume")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
