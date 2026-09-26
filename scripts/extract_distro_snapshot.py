#!/usr/bin/env python3
"""
Kadim Güvenlik — Ubuntu distro zaafiyet snapshot üreticisi (tek seferlik, OFFLINE araç)
======================================================================================
NEDEN (Madde 4 / T5): banner → CPE → NVD hattı "OpenSSH 8.2p1" bilir ama
"UBUNTU 20.04'te bu sürüm hâlâ CVE-2023-48795 (Terrapin) açık — düzeltme
1:8.2p1-4ubuntu0.8" cümlesini KURAMAZ: LTS backport dünyasında fix sürümü
Debian-revision'da yaşar (8.2p1-4ubuntu0.8), upstream sürüm numarasında değil.
Bu script Ubuntu Security API'sinden (USN'nin resmi kaynağı) öncelikli paketlerin
CVE→release→fixed-version matrisini bir kez indirir, kompakt JSON yapar; runtime
(pipeline/linux_distro_intel.py) yalnız STATİK dosyayı okur — doktrin: offline,
deterministik, ağ istediğinde tarama durmaz.

Çalıştırma (yalnız geliştirici makinesi):
    python3 scripts/extract_distro_snapshot.py

Filtre politikası (veri boyutu = rapor dikkat bütçesi):
  • Yalnız LTS release'ler: bionic/focal/jammy/noble.
  • cvss3 ≥ 5.0 VEYA CISA KEV listesi (KEV = sahada aktif sömürü — skordan
    bağımsız değerli). Ubuntu'nun KENDİ priority alanı kullanılmaz: neredeyse
    her şey "medium" (ölçüldü: openssh ilk 20'nin 19'u medium) — ayırt edici
    değil. Eşik, repo doktrini CVE_INTEL_MIN_CVSS'nin (medium+ değerli)
    bir tık üstü: distro matrisi banner'dan GURULTÜSÜZ konuşmalı.
    (Terrapin CVE-2023-48795 cvss 5.9 ve KEV'de YOK — 7.0 eşiği planın
    bayrak vakasını kaçırırdı; 5.0 bunun ölçülü cevabıdır.)
  • Paket başına MAX 120 kayıt (kritik/ağır + yeni önce) — veri kaynakları
    şişse bile snapshot boyutu deterministik tavanlı.
  • Yalnız "released" durumu = sürülebilir FIXED version var → banner ile
    dpkg-karşılaştırması yapılabilir. "active/needs-triage" (yamalı yok) gürültüsü
    runtime'a yüklenmez; NVD hattı onu zaten ayrı yakalıyor.
Güvenlik ANTİVİRÜS notu: çıktı yalnız JSON — repoya ham API cache'i girmez.
"""
import argparse
import json
import re
import sys
import time
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "orchestrator" / "pipeline" / "data" / "distro"

UBUNTU_API = "https://ubuntu.com/security/cves.json"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

# Banner→source paket ailesi (nmap product alanı runtime tarafında eşlenir).
# postgresql source adı major sürüm içerir → ayrı satırlar; mysql aynı mantık.
PACKAGES = [
    "openssh", "nginx", "apache2", "redis", "vsftpd", "proftpd-dfsg",
    "docker.io", "mysql-8.0", "mysql-5.7",
    "postgresql-10", "postgresql-12", "postgresql-14", "postgresql-16",
]
RELEASES = {"bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04"}
# cvss3 eşiği (KEV bu eşiği AŞAR — skora bakmadan girer). Ubuntu'nun kendi
# priority alanı "medium" çöplüğü (openssh ilk 20'nin 19'u medium) → kullanılmaz;
# NVD cvss3 tek ayırt edici sinyal. 5.0 = medium üstü (Terrapin 5.9 girer, 7.0
# kaçırırdı); banner matrisi gürültüsüz konuşsun diye 4.0 değil.
MIN_CVSS3 = 5.0
PKG_CAP = 120            # paket başına tavan (aşağıdaki sort kritik/yeni önce)
_USN_RE = re.compile(r"USN-\d+-\d+")


def _neg_date(iso: str) -> int:
    """'YYYY-MM-DD' → negatif int (sort'ta YENİ tarih önce gitsin diye)."""
    digits = re.sub(r"\D", "", iso or "")[:8]
    return -int(digits or "19700101")


def _sev_from_cvss(score) -> str:
    s = float(score or 0.0)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "unknown"


def _get_json(url: str, params: dict | None = None, timeout: int = 60) -> dict:
    if params:
        from urllib.parse import urlencode
        url = f"{url}?{urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "kadim-distro-extract"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def fetch_kev_ids() -> set:
    try:
        data = _get_json(KEV_URL)
        ids = {v.get("cveID", "") for v in data.get("vulnerabilities", [])}
        return {c for c in ids if c}
    except Exception as e:
        print(f"UYARI: KEV alınamadı ({e}) — yalnız priority filtresiyle devam", file=sys.stderr)
        return set()


def fetch_package(pkg: str) -> list[dict]:
    """Tek source paketi için tüm CVE'leri sayfalamalı çek (Ubuntu Security API)."""
    out: list[dict] = []
    offset, total = 0, None
    while total is None or offset < total:
        d = _get_json(UBUNTU_API, {"package": pkg, "limit": 20, "offset": offset})
        cves = d.get("cves") or {}
        items = list(cves.values()) if isinstance(cves, dict) else cves
        total = int(d.get("total_results") or 0)
        if not items:
            break
        out.extend(items)
        offset += len(items)
        time.sleep(0.4)  # politeness — kurumsal IP'yi rate-limit'e sokma
    return out


def extract_entry(cve: dict, pkg: str, kev_ids: set) -> dict | None:
    """API CVE kaydı → kompakt snapshot satırı. LTS'lerin hiçbiri için fixed
    sürüm YOKSA None (karşılaştırma malzemesi yok)."""
    prio = (cve.get("priority") or "").lower()
    cid = cve.get("id", "")
    kev = cid in kev_ids
    cvss = float(cve.get("cvss3") or 0.0)
    if not kev and cvss < MIN_CVSS3:
        return None
    fixes: dict[str, str] = {}
    for p in cve.get("packages", []) or []:
        if p.get("name") != pkg:
            continue
        for st in p.get("statuses", []) or []:
            rel = st.get("release_codename", "")
            if rel in RELEASES and st.get("status") == "released":
                ver = (st.get("description") or "").strip()
                if ver:
                    fixes[rel] = ver
    if not fixes:
        return None
    usn = ""
    for ref in cve.get("references", []) or []:
        m = _USN_RE.search(str(ref))
        if m:
            usn = m.group(0)
            break
    desc = re.sub(r"\s+", " ", (cve.get("description") or "").strip())[:200]
    sev = _sev_from_cvss(cvss)
    if kev and sev in ("unknown", "low", "medium"):
        # KEV = sahada aktif sömürü kanıtı: sev'yi taban high'a çek (APT gerçeği,
        # CVSS kağıt değeri — örn. eski ama hâlâ sömürülen CVE'ler).
        sev = "high"
    return {
        "cve": cid,
        "sev": sev,
        "ubuntu_priority": prio,
        "cvss3": cvss,
        "published": (cve.get("published") or "")[:10],
        "usn": usn,
        "kev": kev,
        "desc": desc,
        "fixes": fixes,
    }


def main():
    ap = argparse.ArgumentParser(description="Ubuntu USN/CVE → statik distro snapshot")
    ap.add_argument("--out", type=Path, default=OUT_DIR, help="Çıktı dizini")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    print("KEV listesi indiriliyor...")
    kev_ids = fetch_kev_ids()
    print(f"KEV: {len(kev_ids)} aktif-sömürü CVE'si")

    snapshot: dict[str, list[dict]] = {}
    total = 0
    for pkg in PACKAGES:
        try:
            cves = fetch_package(pkg)
        except Exception as e:
            print(f"UYARI: {pkg} alınamadı ({e}) — atlanıyor", file=sys.stderr)
            continue
        rows, seen = [], set()
        for cve in cves:
            row = extract_entry(cve, pkg, kev_ids)
            if row and row["cve"] not in seen:
                seen.add(row["cve"])
                rows.append(row)
        # Kritik/ağır + KEV + yeni önce — runtime tavan uygularsa bile en değerli
        # kayıt kesilmez (sıralama dosyaya gömülü gelir).
        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        rows.sort(key=lambda r: (0 if r["kev"] else _sev_rank.get(r["sev"], 5),
                                 -float(r["cvss3"] or 0),
                                 # yeni tarih önce: string ters çevirme yerine negatif epoch
                                 _neg_date(r.get("published") or ""),))
        if len(rows) > PKG_CAP:
            dropped = len(rows) - PKG_CAP
            rows = rows[:PKG_CAP]
            print(f"  ({pkg}: tavan {PKG_CAP} — {dropped} düşük-öncelikli kayıt elendi)")
        snapshot[pkg] = rows
        total += len(rows)
        kev_n = sum(1 for r in rows if r["kev"])
        print(f"{pkg}: {len(rows)} CVE ({kev_n} KEV)")

    meta = {
        "source": "https://ubuntu.com/security/cves.json (USN resmi kaynağı)",
        "kev_source": KEV_URL,
        "generated": str(date.today()),
        "releases": RELEASES,
        "filter": (f"cvss3 >= {MIN_CVSS3} OR KEV-listed; status=released (fixed bilinen); "
                   f"LTS: bionic/focal/jammy/noble; kapak: {PKG_CAP}/paket"),
        "counts": {k: len(v) for k, v in snapshot.items()},
        "total": total,
    }
    out = {"meta": meta, "packages": snapshot}
    path = args.out / "ubuntu_distro_cves.json"
    path.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n",
                    encoding="utf-8")
    kb = path.stat().st_size / 1024
    print(f"Yazıldı: {path.relative_to(ROOT)} — {total} kayıt, {kb:.0f} KB")


if __name__ == "__main__":
    main()
