#!/usr/bin/env python3
"""Davranış denetimi (loop-guard) testi — düz script (pytest yok, konvansiyon).

Kullanım: python3 orchestrator/pipeline/test_behavior_monitor.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASARISIZ = 0


def kontrol(ad: str, kosul: bool) -> None:
    global BASARISIZ
    durum = "OK " if kosul else "FAIL"
    if not kosul:
        BASARISIZ += 1
    print(f"[{durum}] {ad}")


def main() -> None:
    from behavior_monitor import BehaviorMonitor

    # --- eşik altı: davranış birebir (ceza 1.0, uyarı yok) ---
    m = BehaviorMonitor(enabled=True, ayni_arac_limit=3, ceza_carpani=0.5)
    m.kaydet("nuclei")
    m.kaydet("nuclei")
    kontrol("eşik altı ceza 1.0", m.ceza("nuclei") == 1.0)
    kontrol("eşik altı uyarı yok", m.bekleyen_uyarilar == [])

    # --- eşik anı: ceza + TEK uyarı ---
    m.kaydet("nuclei")
    kontrol("eşikte ceza uygulandı", m.ceza("nuclei") == 0.5)
    kontrol("eşikte 1 uyarı üretildi", len(m.bekleyen_uyarilar) == 1)
    kontrol("diğer araç etkilenmedi", m.ceza("nmap") == 1.0)

    # --- uyarı kuyruğu tek tüketim ---
    uyarilar = m.uyarilari_bosalt()
    kontrol("uyarılar boşaltıldı", len(uyarilar) == 1 and m.bekleyen_uyarilar == [])

    # --- eşik katlarında tekrar uyarı (2x, 3x...) ama arada spam yok ---
    m.kaydet("nuclei")  # 4. koşu — kat değil, uyarı yok
    m.kaydet("nuclei")  # 5. koşu — kat değil
    kontrol("ara koşuda spam yok", m.bekleyen_uyarilar == [])
    m.kaydet("nuclei")  # 6. koşu = 2x eşik → uyarı
    kontrol("eşik katında tekrar uyarı", len(m.bekleyen_uyarilar) == 1)
    m.uyarilari_bosalt()

    # --- başarısız koşular da sayılır (observe her status'ta çağırır) ---
    m2 = BehaviorMonitor(enabled=True, ayni_arac_limit=2, ceza_carpani=0.6)
    m2.kaydet("fuzz")
    m2.kaydet(None)  # araçsız karar (STOP vb.) — patlamamalı, sayılmamalı
    kontrol("None araç güvenle yok sayıldı", m2.ceza(None) == 1.0)
    m2.kaydet("fuzz")
    kontrol("limit=2'de ceza devrede", m2.ceza("fuzz") == 0.6)

    # --- flag kapalı: tamamen no-op ---
    m3 = BehaviorMonitor(enabled=False, ayni_arac_limit=2)
    for _ in range(10):
        m3.kaydet("nuclei")
    kontrol("kapalıyken ceza hep 1.0", m3.ceza("nuclei") == 1.0)
    kontrol("kapalıyken uyarı üretilmez", m3.bekleyen_uyarilar == [])

    # --- parametre kıstırma: ceza [0.1, 0.95], limit >= 2 ---
    m4 = BehaviorMonitor(enabled=True, ayni_arac_limit=1, ceza_carpani=5.0)
    kontrol("ceza üst sınıra kıstırıldı", m4.ceza_carpani == 0.95)
    kontrol("limit alt sınıra kıstırıldı", m4.ayni_arac_limit == 2)
    m5 = BehaviorMonitor(enabled=True, ceza_carpani=-3.0)
    kontrol("ceza alt sınıra kıstırıldı", m5.ceza_carpani == 0.1)

    # --- env çözümü ---
    os.environ["LOOP_GUARD_ENABLED"] = "0"
    os.environ["LOOP_GUARD_SAME_LIMIT"] = "4"
    os.environ["LOOP_GUARD_PENALTY"] = "0.7"
    m6 = BehaviorMonitor()
    kontrol("env: flag kapalı okundu", m6.enabled is False)
    kontrol("env: limit okundu", m6.ayni_arac_limit == 4)
    kontrol("env: ceza okundu", abs(m6.ceza_carpani - 0.7) < 1e-9)
    os.environ["LOOP_GUARD_ENABLED"] = "1"

    # --- durum() dökümü (summary şeffaflığı) ---
    d = m.durum()
    kontrol("durum: cezalı araçlar listelendi", d["cezali_araclar"] == ["nuclei"])
    kontrol("durum: sayaçlar tam", d["arac_sayaclari"]["nuclei"] == 6)

    print()
    if BASARISIZ:
        print(f"{BASARISIZ} test BAŞARISIZ")
        sys.exit(1)
    print("TÜM TESTLER GEÇTİ")


if __name__ == "__main__":
    main()
