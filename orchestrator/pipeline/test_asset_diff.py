"""
Kadim Güvenlik — test_asset_diff.py
Port ve servis varlık envanteri diff motoru birim testi (Düz script).
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.asset_diff import build_asset_snapshot, diff_asset_snapshots


def main():
    print("🧪 [TEST] Asset Diff (Port & Servis Envanteri) testleri başlıyor...")

    # 1. Snapshot oluşturma
    target = "bank.kadim.local"
    raw_ports_1 = [
        {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18"},
        {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18"},
    ]
    snap1 = build_asset_snapshot(target, raw_ports_1, technologies=["nginx", "react"])
    assert "80/tcp" in snap1["ports"]
    assert "443/tcp" in snap1["ports"]
    print("  ✓ build_asset_snapshot normalizasyonu başarılı")

    # 2. İlk tarama (baseline) diff testi
    diff_base = diff_asset_snapshots(None, snap1)
    assert diff_base["is_baseline"] is True
    assert diff_base["has_changes"] is False
    print("  ✓ İlk tarama baseline tespiti başarılı")

    # 3. İkinci tarama (Yeni port açıldı + versiyon güncellendi)
    raw_ports_2 = [
        {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.24"}, # Güncellendi
        {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.24"},
        {"port": 8443, "protocol": "tcp", "service": "https", "product": "Apache Tomcat", "version": "9.0"}, # YENİ AÇILDI!
    ]
    snap2 = build_asset_snapshot(target, raw_ports_2, technologies=["nginx", "react", "tomcat"])
    diff2 = diff_asset_snapshots(snap1, snap2)

    assert diff2["has_changes"] is True
    assert len(diff2["new_ports"]) == 1
    assert diff2["new_ports"][0]["port"] == 8443
    print(f"  ✓ Yeni açılan port başarıyla yakalandı: {diff2['new_ports'][0]['port']}/tcp ({diff2['new_ports'][0]['product']})")

    assert len(diff2["changed_services"]) >= 1
    print(f"  ✓ Değişen servis başarıyla yakalandı: {diff2['changed_services'][0]}")

    assert "tomcat" in diff2["new_technologies"]
    print(f"  ✓ Yeni teknoloji başarıyla yakalandı: {diff2['new_technologies']}")

    # 4. Port kapatılma testi
    raw_ports_3 = [
        {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.24"}
    ]
    snap3 = build_asset_snapshot(target, raw_ports_3)
    diff3 = diff_asset_snapshots(snap2, snap3)
    assert len(diff3["closed_ports"]) == 2 # 80 ve 8443 kapandı
    print(f"  ✓ Kapatılan portlar başarıyla yakalandı ({len(diff3['closed_ports'])} port)")

    print("\n🎉 Tüm Asset Diff testleri BAŞARIYLA GEÇTİ (100% Yeşil)!")


if __name__ == "__main__":
    main()
