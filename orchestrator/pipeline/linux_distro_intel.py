"""
Kadim Güvenlik — Linux Distro Zaafiyet Matrisi (Madde 4 / T5)
============================================================
Türkçe: "Ubuntu çiçeğini bilmek." Banner + OS tespitinden DISTRO-PAKET zaafiyet
cümlesi kurar:

    "Ubuntu 20.04 üzerinde OpenSSH 8.2p1-4ubuntu0.4 — 12 yamanabilir güvenlik
     açığı (en kötüsü CVE-2024-6387, 8.1); Terrapin CVE-2023-48795 düzeltmesi
     1:8.2p1-4ubuntu0.10 (USN-6560-1) — makine bu güncellemenin GERİSİNDE."

NEDEN mevcut NVD hattından ayrı: upstream CVE dünyası "OpenSSH 8.2p1"i yamalı
sayabilir (upstream 9.6'da kapandı), ama UBUNTU LTS backport evreninde fix
sürümü Debian-revision'da yaşar (8.2p1-4ubuntu0.10). Banner'daki "Ubuntu
4ubuntu0.4" imzası olmadan bu cümle kurulamaz — distro-patch-level istihbaratı
APT gözüyle asıl sinyaldir: kamyon dolusu PoC'u olan CVE'ye yavaş yama.

VERİ: data/distro/ubuntu_distro_cves.json — Ubuntu Security (USN) + CISA KEV
statik snapshot'ı (scripts/extract_distro_snapshot.py, geliştirici makinesinde
üretilir). Runtime'DA AĞ İSTEĞİ YOK — doktrin: offline deterministik; snapshot
yok/bozuk → [] → tarama bundan habersiz devam eder (sıfır regresyon).

TASARIM: SAF çekirdek (ağ/DB/pipeline-import YOK; stdlib-only — path_intel/wp_probe
deseni, izole test). Deterministik tier:
  • revision banner'dan okunabildiyse  → "probable" (dpkg sürüm karşılaştırması,
    tahmin yok; yine de aktif PoC olmadığı için confirmed DEĞİL)
  • aynı-upstream/revision-bilinmez    → "unconfirmed" (aday — rapor "incelenmeli")
Kanıttan çok İSTİHBARAT ürünüdür: engine'in FP ekseni (confidence_tier) bunu
doğru kovaya koyar; KEV kesişimi raporda "sahada sömürülüyor" diye patlar.

Sürüm karşılaştırma Debian dpkg kuralıyla (epoch, ~ ön-sıra, sayısal-run ve
karakter-run sırası) — "4ubuntu0.4" < "4ubuntu0.10" string kıyasıyla YANLIŞ
çıkar (0x34 > 0x31); dpkg-run kıyası şart.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("distro-intel")

_DATA_PATH = Path(__file__).resolve().parent / "data" / "distro" / "ubuntu_distro_cves.json"

# Modül-ömrü önbellek: (payload_dict | None hata-yok → boş dict)
_snapshot_cache: Optional[Dict[str, Any]] = None
_snapshot_loaded = False

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

# ------------------------------------------------------------------
# Snapshot yükleyici (her hata → {} — doktrin: veri yoksa sessiz devre dışı)
# ------------------------------------------------------------------

def _snapshot() -> Dict[str, Any]:
    global _snapshot_cache, _snapshot_loaded
    if _snapshot_loaded:
        return _snapshot_cache or {}
    _snapshot_loaded = True
    try:
        data = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("packages"), dict):
            _snapshot_cache = data
        else:
            _snapshot_cache = {}
    except Exception as e:  # dosya yok / bozuk JSON → devre dışı
        logger.debug(f"distro snapshot yüklenemedi: {e}")
        _snapshot_cache = {}
    return _snapshot_cache


# ------------------------------------------------------------------
# Debian sürüm karşılaştırıcı (dpkg kuralı — SAF)
# ------------------------------------------------------------------

_EPOCH_RE = re.compile(r"^\s*(\d+):")


def _strip_epoch(v: str) -> Tuple[int, str]:
    v = (v or "").strip()
    m = _EPOCH_RE.match(v)
    if m:
        return int(m.group(1)), v[m.end():]
    return 0, v


def _split_debian(v: str) -> Tuple[str, str]:
    """'8.2p1-4ubuntu0.10' → ('8.2p1', '4ubuntu0.10'). Epoch soyulmuş olmalı."""
    up, _, rev = v.partition("-")
    return up, rev


def _char_order(c: Optional[str]) -> int:
    """dpkg sıra: '~' her şeyden (boştan da) ÖNCE; diğer karakterler boştan SONRA."""
    if c is None:
        return 0
    if c == "~":
        return -1
    return ord(c)


def _cmp_nonnum(a: str, b: str) -> int:
    i = 0
    while True:
        ca = a[i] if i < len(a) else None
        cb = b[i] if i < len(b) else None
        oa, ob = _char_order(ca), _char_order(cb)
        if oa != ob:
            return -1 if oa < ob else 1
        if ca is None and cb is None:
            return 0
        i += 1


def _cmp_verstr(a: str, b: str) -> int:
    """Upstream/revision gövdesi kıyası: sayı-run (int) + non-sayı-run karakter sırası."""
    i = j = 0
    while i < len(a) or j < len(b):
        di = re.match(r"\d+", a[i:])
        dj = re.match(r"\d+", b[j:])
        na = int(di.group()) if di else 0
        nb = int(dj.group()) if dj else 0
        if na != nb:
            return -1 if na < nb else 1
        i += len(di.group()) if di else 0
        j += len(dj.group()) if dj else 0
        si = re.match(r"[^\d]+", a[i:])
        sj = re.match(r"[^\d]+", b[j:])
        sa = si.group() if si else ""
        sb = sj.group() if sj else ""
        r = _cmp_nonnum(sa, sb)
        if r:
            return r
        i += len(sa)
        j += len(sb)
    return 0


def compare_versions(a: str, b: str) -> int:
    """Tam Debian sürüm kıyası: -1 a<b, 0 eşit, 1 a>b. Eksik revision = ''."""
    ea, ua = _strip_epoch(a)
    eb, ub = _strip_epoch(b)
    if ea != eb:
        return -1 if ea < eb else 1
    up_a, rev_a = _split_debian(ua)
    up_b, rev_b = _split_debian(ub)
    r = _cmp_verstr(up_a, up_b)
    if r:
        return r
    return _cmp_verstr(rev_a, rev_b)


# ------------------------------------------------------------------
# Banner → source paket çözümlemesi
# ------------------------------------------------------------------

def resolve_package(product: str, version: str) -> Optional[str]:
    """nmap product/version → Ubuntu source paket adı. Bilinmeyen → None."""
    p = (product or "").lower().strip()
    if not p:
        return None
    if "openssh" in p:
        return "openssh"
    if "nginx" in p:
        return "nginx"
    if "apache" in p and ("http" in p or "server" in p or p == "apache"):
        return "apache2"
    if "redis" in p:
        return "redis"
    if "vsftpd" in p:
        return "vsftpd"
    if "proftpd" in p:
        return "proftpd-dfsg"
    v = (version or "").strip()
    if "mysql" in p:
        if v.startswith("8."):
            return "mysql-8.0"
        if v.startswith("5.7"):
            return "mysql-5.7"
        return None
    if "postgres" in p:
        m = re.match(r"(\d+)", v)
        if not m:
            return None
        pkg = f"postgresql-{m.group(1)}"
        return pkg if pkg in (_snapshot().get("packages") or {}) else None
    if p == "docker":
        return "docker.io"
    return None


_UBUNTU_REV_RE = re.compile(r"ubuntu[\s\-]+([0-9][0-9A-Za-z.+~+-]*)", re.I)


def banner_revision(extrainfo: str, version: str = "") -> Optional[str]:
    """Banner Debian-revision'ı: nmap extrainfo 'Ubuntu 4ubuntu0.4' → '4ubuntu0.4'.
    Yoksa None (revision-bilinmez modu)."""
    for src in (extrainfo, version):
        m = _UBUNTU_REV_RE.search(src or "")
        if m:
            return m.group(1)
    return None


_OS_VER_RE = re.compile(r"\b(18|20|22|24)\.04\b")


def detect_release(os_detection: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """OS stringi → (codename, '20.04'). Ubuntu değilse/numara yoksa (None, None)
    — revision-bilinmez modda yalnız same-lineage eşleme yapılır (release tavanı yok)."""
    b = (os_detection or "").lower()
    if "ubuntu" not in b:
        return None, None
    m = _OS_VER_RE.search(b)
    if not m:
        return None, None
    ver = m.group(0)
    snap = _snapshot()
    releases = (snap.get("meta") or {}).get("releases") or {}
    for code, v in releases.items():
        if v == ver:
            return code, ver
    return None, ver


# ------------------------------------------------------------------
# Matris eşleme (SAF çekirdek)
# ------------------------------------------------------------------

def _match_package(pkg: str, installed_up: str, installed_rev: Optional[str],
                   release: Optional[str]) -> Tuple[List[Dict[str, Any]], int]:
    """Paket satırları → (vulnerable-listesi, maybe_sayısı).

    Karar kuralları (deterministik, muhafazakar):
      • release BİLİNİYOR → yalnız o release'in fix satırları değerlendirilir.
        sürüm < fixed → vulnerable; ==/> → patched (elem).
      • release BİLİNMİYOR → yalnız SAME-LINEAGE (fixed-upstream == banner-upstream)
        ve revision banner'dan okunabiliyorsa karar verilir. Farklı release'in
        farklı upstream'ine bakıp "vulnerable" demek FP üretirdi (focal banner'ı
        jammy fix'iyle kıyaslanmaz). Revision okunamıyorsA → karar yok.
      • same-upstream + revision yok + release var → 'maybe' (aday, unconfirmed).
    """
    snap = _snapshot()
    rows = (snap.get("packages") or {}).get(pkg) or []
    vulnerable: List[Dict[str, Any]] = []
    maybe = 0
    for row in rows:
        fixes = row.get("fixes") or {}
        statuses = []
        for rel, fixed in fixes.items():
            if release and rel != release:
                continue
            e_f, fixed_clean = _strip_epoch(fixed)
            f_up, f_rev = _split_debian(fixed_clean)
            cu = _cmp_verstr(installed_up, f_up)
            if cu < 0:
                # Banner upstream'i fix upstream'inden ESKİ hat — yalnız release
                # BİLİNİYORSA hüküm verilir (release-bilinmez cross-release kıyas
                # FP üretir: focal banner'ı jammy fix'iyle kıyaslanmaz).
                if release:
                    statuses.append(("vulnerable", rel, fixed))
                continue
            if cu > 0:
                continue  # daha yeni upstream hattı — bu CVE'nin fix'inden ileri
            # same lineage: revision kıyası
            if installed_rev is not None:
                cr = _cmp_verstr(installed_rev, f_rev)
                if cr < 0:
                    statuses.append(("vulnerable", rel, fixed))
            elif release:
                statuses.append(("maybe", rel, fixed))
        if not statuses:
            continue
        vul = [s for s in statuses if s[0] == "vulnerable"]
        if vul:
            _, rel, fixed = vul[0]
            item = dict(row)
            item["release"] = rel
            item["fixed"] = fixed
            item["status"] = "vulnerable"
            vulnerable.append(item)
        else:
            maybe += 1
    return vulnerable, maybe


def _sort_key(row: Dict[str, Any]):
    return (0 if row.get("kev") else _SEV_RANK.get(row.get("sev"), 5),
            -float(row.get("cvss3") or 0))


def analyze_service(product: str, version: str, extrainfo: Optional[str],
                    os_detection: Optional[str],
                    release_override: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Tek servis banner'ı → distro-matris bulgusu (SAF). Uygun paket/eşleme
    yoksa None. os_detection'dan bağımsız Ubuntu işareti banner'dan da gelir
    (nmap -O default preset'te YOK — banner 'Ubuntu' imzası tek güvenilir iz)."""
    snap = _snapshot()
    if not snap:
        return None
    pkg = resolve_package(product, version)
    if not pkg or pkg not in (snap.get("packages") or {}):
        return None
    ubuntu_marker = ("ubuntu" in (extrainfo or "").lower()
                     or "ubuntu" in (version or "").lower()
                     or "ubuntu" in (os_detection or "").lower())
    if not ubuntu_marker:
        return None  # paket Ubuntu'suz ortamlarda da var — matris Ubuntu-only, spekülasyon yok
    release, release_ver = detect_release(os_detection)
    if release_override and not release:
        release = release_override
    up, rev = _split_debian(_strip_epoch(version or "")[1])
    if not up:
        return None
    rev_banner = banner_revision(extrainfo)
    vulnerable, maybe = _match_package(pkg, up, rev_banner, release)
    if not vulnerable and not maybe:
        return None
    vulnerable.sort(key=_sort_key)
    return {
        "pkg": pkg,
        "product": product,
        "version": version,
        "extrainfo": extrainfo or "",
        "installed": f"{up}-{rev_banner}" if rev_banner else up,
        "release": release,
        "release_version": release_ver,
        "vulnerable": vulnerable,
        "vulnerable_count": len(vulnerable),
        "maybe_count": maybe,
    }


def _release_label(res: Dict[str, Any]) -> str:
    if res.get("release_version"):
        return f"Ubuntu {res['release_version']}"
    return "Ubuntu"


def build_finding(res: Dict[str, Any], target: str,
                  proof_top: int = 10) -> Dict[str, Any]:
    """SAF: analyze_service çıktısından Evidence-ready bulgu sözü (title/proof
    TÜRKÇE tam cümle — rapora ham CVE listesi değil 'makine bu güncellemenin
    gerisinde' istihbaratı girer)."""
    rel_label = _release_label(res)
    vul = res["vulnerable"]
    maybe_n = res.get("maybe_count") or 0
    kev = [v for v in vul if v.get("kev")]
    worst = vul[0] if vul else None
    sev = "medium"
    cve = None
    if worst:
        sev = "high" if (worst.get("kev") and worst.get("sev") in ("low", "unknown", "medium")) \
            else worst.get("sev") or "medium"
        cve = worst.get("cve")

    if vul:
        title = (f"{rel_label} üzerinde {res['product']} {res['installed']} — "
                 f"{res['vulnerable_count']} yamanabilir güvenlik açığı"
                 + (f" (en kötüsü {cve}, CVSS {worst.get('cvss3')})" if cve else ""))
    else:
        title = (f"{rel_label} üzerinde {res['product']} {res['installed']} — "
                 f"{maybe_n} potansiyel açık (yama düzeltmesi belirsiz)")

    lines = [
        f"{rel_label} · {res['pkg']} · kurulu: {res['installed']} · "
        f"veri: Ubuntu Security (USN) statik snapshot"
    ]
    for v in vul[:proof_top]:
        kev_tag = " ⚡CISA-KEV (sahada aktif sömürü)" if v.get("kev") else ""
        usn = f" · {v['usn']}" if v.get("usn") else ""
        lines.append(f"{v['cve']} [{v.get('sev')}/{v.get('cvss3')}] — düzeltme "
                     f"{v.get('fixed')} ({v.get('release')}){usn}{kev_tag}")
    if len(vul) > proof_top:
        lines.append(f"… +{len(vul) - proof_top} CVE daha (tam liste snapshot'ta)")
    if maybe_n:
        lines.append(f"Not: {maybe_n} CVE aynı-upstream hattında ama kurulu "
                     f"Debian-revision'ı banner'dan okunamadı — ADAY (yama durumu "
                     f"işletim sistemi paketiyle doğrulanmalı).")
    tier = "probable" if vul else "unconfirmed"
    return {
        "title": title,
        "severity": sev if vul else "medium",
        "cve": cve,
        "target": target,
        "proof": "\n".join(lines),
        "tool": "distro_intel",
        "confidence_tier": tier,
        "cvss_v3": worst.get("cvss3") if worst and isinstance(worst.get("cvss3"), (int, float)) else None,
        "kev": [v["cve"] for v in kev],
        "cve_count": len(vul),
        "pkg": res["pkg"],
        "installed": res["installed"],
        "release": res.get("release"),
    }


def analyze_services(services: List[Dict[str, Any]],
                     os_detection: Optional[str]) -> List[Dict[str, Any]]:
    """Servis listesi (nmap findings özdeş alanları: product/version/extrainfo) →
    bulgu listesi. Tek servis hatası diğerini düşürmez (best-effort SAF)."""
    out: List[Dict[str, Any]] = []
    for svc in services or []:
        if not isinstance(svc, dict):
            continue
        try:
            res = analyze_service(
                str(svc.get("product") or ""),
                str(svc.get("version") or ""),
                svc.get("extrainfo"),
                os_detection,
            )
        except Exception as e:  # SAF'ın SAF'ı — tek bozuk banner matrisi düşürmez
            logger.debug(f"distro-intel servis hatası: {e}")
            continue
        if not res:
            continue
        port = svc.get("port")
        target = f"{svc.get('host') or ''}:{port}" if port else (svc.get("host") or "")
        out.append(build_finding(res, target or "host"))
    return out
