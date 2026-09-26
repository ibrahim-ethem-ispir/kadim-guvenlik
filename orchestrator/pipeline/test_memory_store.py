#!/usr/bin/env python3
"""Vektör hafıza testi — düz script (pytest yok, konvansiyon gereği).

Kullanım:
  python3 orchestrator/pipeline/test_memory_store.py            # offline (no-op) testler
  VECTOR_LIVE=1 VECTOR_EMBED_MODEL=... python3 ...              # canlı Qdrant+embedding testi

Offline kol: flag kapalıyken HER çağrı no-op olmalı (motor asla patlamamalı).
Canlı kol: Qdrant + embedding sağlayıcısı gerektirir; yaz→oku round-trip doğrular.
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


def offline_testler() -> None:
    # Flag kapalı → aktif False, tüm çağrılar zararsız no-op.
    os.environ["VECTOR_MEMORY_ENABLED"] = "0"
    from memory_store import VektorHafiza

    h = VektorHafiza()
    kontrol("flag kapalıyken aktif=False", h.aktif is False)
    kontrol("flag kapalıyken kaydet() False döner (patlamaz)", h.kaydet("memory", "deneme") is False)
    kontrol("flag kapalıyken benzer_ara() boş döner", h.benzer_ara("deneme") == [])
    kontrol("flag kapalıyken toplu_kaydet() 0 döner", h.toplu_kaydet("memory", [{"text": "x"}]) == 0)

    # Flag açık ama model tanımsız → yine pasif (embedding maliyeti/kaçamağı yok).
    os.environ["VECTOR_MEMORY_ENABLED"] = "1"
    os.environ.pop("VECTOR_EMBED_MODEL", None)
    h2 = VektorHafiza()
    kontrol("model tanımsızken aktif=False", h2.aktif is False)
    kontrol("model tanımsızken benzer_ara() boş döner", h2.benzer_ara("herhangi") == [])

    # Qdrant erişilemezken (sahte URL) → cooldown'a düşer, exception YOK.
    os.environ["VECTOR_EMBED_MODEL"] = "test-model"
    os.environ["QDRANT_URL"] = "http://127.0.0.1:59999"  # kapalı port
    h3 = VektorHafiza()
    kontrol("qdrant yokken _istemci() None (sessiz degrade)", h3._istemci() is None)
    kontrol("qdrant yokken benzer_ara() boş döner", h3.benzer_ara("herhangi") == [])


def canli_testler() -> None:
    """VECTOR_LIVE=1 + çalışan Qdrant + VECTOR_EMBED_MODEL gerekir."""
    os.environ["VECTOR_MEMORY_ENABLED"] = "1"
    from memory_store import COLLECTION, VektorHafiza, _deterministik_id

    h = VektorHafiza()
    if not h.aktif:
        print("[SKIP] canlı test: VECTOR_EMBED_MODEL tanımsız")
        return
    metin = "wordpress wpbakery 6.x sql injection login formunda doğrulandı"
    yazildi = h.kaydet(
        "evidence",
        metin,
        {"target": "test.local", "tech": "wordpress", "severity": "high"},
    )
    kontrol("canlı: kayıt yazıldı", yazildi)
    sonuc = h.benzer_ara("wp sqli auth sayfası", kind="evidence", limit=3)
    kontrol("canlı: semantik arama sonuç döndürdü", len(sonuc) > 0)
    if sonuc:
        kontrol("canlı: en yakın sonuç doğru kayıt", sonuc[0].get("text", "").startswith("wordpress"))
        kontrol("canlı: filtre çalıştı (tech=wordpress)", sonuc[0].get("tech") == "wordpress")
    # Idempotency: aynı metin ikinci kez → aynı id (upsert ezer, şişmez).
    kontrol(
        "canlı: deterministik id üretimi",
        _deterministik_id(metin, "evidence") == _deterministik_id(metin, "evidence"),
    )
    print(f"      koleksiyon: {COLLECTION}")


if __name__ == "__main__":
    print("--- offline testler ---")
    offline_testler()
    if os.getenv("VECTOR_LIVE") == "1":
        print("--- canlı testler ---")
        canli_testler()
    else:
        print("(canlı test atlandı: VECTOR_LIVE=1 ile çalıştır)")
    print()
    if BASARISIZ:
        print(f"{BASARISIZ} test BAŞARISIZ")
        sys.exit(1)
    print("TÜM TESTLER GEÇTİ")
