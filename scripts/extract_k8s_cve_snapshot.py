#!/usr/bin/env python3
"""
Kadim Güvenlik — Kubernetes resmî CVE snapshot üreticisi (tek seferlik, OFFLINE araç)
=====================================================================================
NEDEN (Madde 5 / T4): k8s_probe apiserver/kubelet SÜRÜMÜNÜ çıkarıyor (gitVersion) ama
sürüm→CVE cümlesi kurulamıyordu — NVD hattı network'e bağımlı ve yavaş; RKE2/k3s
damgaları NVD'de CPE olarak zayıf eşleşir. Bu script Kubernetes'in RESMÎ CVE feed'ini
(github.com/kubernetes/kubernetes, label:official-cve-feed — Security Response
Committee'nin duyurduğu her CVE burada) bir kez indirir, "hangi bileşen hangi minor'da
hangi patch'te düzeltildi" matrisini kompakt JSON yapar; runtime
(pipeline/k8s_probe.py match_k8s_cves) yalnız STATİK dosyayı okur — doktrin:
offline, deterministik, ağ istediğinde tarama durmaz.

Çalıştırma (yalnız geliştirici makinesi):
    python3 scripts/extract_k8s_cve_snapshot.py            # GitHub API'den çeker
    python3 scripts/extract_k8s_cve_snapshot.py --in feed.json   # lokal ham feed

Filtre politikası (veri boyutu = rapor dikkat bütçesi):
  • Yalnız "Fixed Versions" bölümü PARÇALANABİLEN kayıtlar (fixed_in haritasız kayıt
    deterministik eşlenemez → NVD hattına kalır). Feed'de fixed bölümü olmayan
    (kapatılmamış/devam eden) kayıtlar bilinçli girmez.
  • Bileşen çözülemeyen kayıt girmez: matcher'ımız bileşen kimliğiyle eşleşir,
    "belki kubernetes" kaydı FP üretir.
  • ingress-nginx / CSI sürücüleri gibi core-dışı kayıtlar DA girer — bileşen adı
    kesinse veri zarar vermez; runtime'da yalnız eldeki bileşen eşleşir.
Feed formatı yıllara göre değişiyor (üç format ailesi ölçüldü: "kubelet: >= v1.34.12",
"kubelet v1.28.4 - fixed by #PR", componentsiz "v1.32.1" satırları) — parser üçünü de
işler; componentsiz satırlarda bileşen başlık/gövdeden çıkarılır (ör. "Windows nodes ...
/logs" → kubelet).
Güvenlik ANTİVİRÜS notu: çıktı yalnız JSON — repoya ham API cache'i girmez.
"""
import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "orchestrator" / "pipeline" / "data" / "k8s"
OUT_FILE = OUT_DIR / "k8s_cves.json"

FEED_URL = ("https://api.github.com/search/issues"
            "?q=repo:kubernetes/kubernetes+label:official-cve-feed&per_page=100")

# Core bileşenler + bilinen yan-bileşenler. Bölüm satırında bileşen adı yoksa
# başlık/gövde metninden İLK geçen bileşen kimliği alınır (sıra = öncelik).
KNOWN_COMPONENTS = ["kube-apiserver", "kube-controller-manager", "kube-scheduler",
                    "kube-proxy", "kubelet", "kubectl", "ingress-nginx"]
# Gövdede geçen serbest-metin ipuçları → bileşen (componentsiz satırlar için).
_COMPONENT_HINTS = [
    (re.compile(r"kube-apiserver|apiserver|API server", re.I), "kube-apiserver"),
    (re.compile(r"kube-controller-manager|controller manager", re.I), "kube-controller-manager"),
    (re.compile(r"kube-scheduler", re.I), "kube-scheduler"),
    (re.compile(r"kube-proxy", re.I), "kube-proxy"),
    (re.compile(r"kubelet", re.I), "kubelet"),
    (re.compile(r"kubectl", re.I), "kubectl"),
    (re.compile(r"ingress-nginx|ingress nginx", re.I), "ingress-nginx"),
]

# CVSS: iki resmî format ailesi — eski "High (8.8)" ve yeni "rated High (...link...) (score: 8.1)"
_SEC_RE = re.compile(r"(Critical|High|Medium|Low)\s*\(\s*(\d+(?:\.\d+)?)\s*\)", re.I)
_RATED_RE = re.compile(r"rated\s+(Critical|High|Medium|Low)", re.I)
_SCORE_RE = re.compile(r"score[:：]?\s*(\d+(?:\.\d+)?)", re.I)
_VER_RE = r"v?(\d+\.\d+\.\d+)"
# SATIR-SONU DİSİPLİNİ: `\s*`/`.*` yeni-satırı da yediği için finditer satırları İKİŞER
# yutuyordu (ölçüldü: 4 fix satırından 2'si kayboluyordu) — satır-içi boşluk `[ \t]*`,
# satır-içi kuyruk `[^\n]*` zorunlu.
# "kubelet: <= v1.34.11" / "- ingress-nginx: < v1.12.5" / "kubelet: >= v1.34.12"
_LINE_OP_RE = re.compile(
    r"(?m)^[ \t]*[-*]?[ \t]*`?([\w][\w.-]*)`?[ \t]*[:：]??[ \t]*(<=|>=|<|>|=)[ \t]*" + _VER_RE)
# "kubelet v1.28.4 - fixed by #121882" / "- kubelet v1.23.11" / "kube-controller-manager v1.18.1+"
# / "Kubernetes kube-apiserver v1.25.4" / "kubelet master/v1.31.0 - fixed by"
_LINE_PLAIN_RE = re.compile(
    r"(?m)^[ \t]*[-*]?[ \t]*(?:Kubernetes[ \t]+)?(kube[\w-]*|ingress-nginx)[ \t]+"
    r"(?:master/)?v?(\d+\.\d+\.\d+)\+?(?:[ \t]*[-–—][^\n]*)?$")
# Componentsiz satırlar (CVE-2024-9042 tarzı): "v1.32.1" / "v1.31.0 to v1.31.4" / "<=v1.29.12"
_LINE_BARE_RE = re.compile(
    r"(?m)^[ \t]*[-*]?[ \t]*(?:<=|>=|<|>|=)?[ \t]*" + _VER_RE
    + r"(?:[ \t]+to[ \t]+" + _VER_RE + r")?[ \t]*$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")

# Feed'in EN ESKİ kayıtları (2018-2019) "Fixed Versions" başlığı kullanmıyor ("is fixed in
# the following releases" + markdown link listesi) → parser bunları göremez. Distrolar
# extractor'daki MANUAL_ADDITIONS deseni: yeniden üretimde kaybolmaz, kaynak URL sabit.
MANUAL_ADDITIONS = [
    {
        "cve": "CVE-2018-1002105",
        "title": "proxy request handling in kube-apiserver can leave vulnerable TCP connections",
        "components": ["kube-apiserver"],
        "severity": "critical", "cvss3": 9.8, "windows_only": False,
        "fixed_in": {"1.13": "1.13.0", "1.12": "1.12.3", "1.11": "1.11.5", "1.10": "1.10.11"},
        "affected": ["kube-apiserver <= v1.12.2", "kube-apiserver v1.11.0 - v1.11.4",
                     "kube-apiserver v1.10.0 - v1.10.10", "kube-apiserver <= v1.9.x (fix almadı)"],
        "url": "https://github.com/kubernetes/kubernetes/issues/73476",
    },
    {
        "cve": "CVE-2019-11253",
        "title": "Kubernetes API Server JSON/YAML parsing vulnerable to resource exhaustion attack",
        "components": ["kube-apiserver"],
        "severity": "high", "cvss3": 7.5, "windows_only": False,
        "fixed_in": {"1.16": "1.16.2", "1.15": "1.15.5", "1.14": "1.14.8", "1.13": "1.13.12"},
        "affected": ["kube-apiserver v1.16.0 - v1.16.1", "kube-apiserver v1.15.0 - v1.15.4",
                     "kube-apiserver v1.14.0 - v1.14.7", "kube-apiserver <= v1.12.x (fix almadı)"],
        "url": "https://github.com/kubernetes/kubernetes/issues/83261",
    },
]


def _section(body: str, name: str) -> str:
    """'#### Affected Versions' bölüm metni (sonraki başlığa kadar)."""
    m = re.search(r"#+\s*" + name + r"\s*\n(.*?)(?=\n#+\s|\nHow do I mitigate|\nTo upgrade|\Z)",
                  body, re.S | re.I)
    return m.group(1).strip() if m else ""


def _parse_version_lines(text: str):
    """Bölüm metni → [(component|None, op|None, version, range_end|None)] ham satırlar."""
    out = []
    for m in _LINE_OP_RE.finditer(text):
        out.append((m.group(1), m.group(2), m.group(3), None))
    for m in _LINE_PLAIN_RE.finditer(text):
        out.append((m.group(1), None, m.group(2), None))
    for m in _LINE_BARE_RE.finditer(text):
        out.append((None, None, m.group(1), m.group(2)))
    return out


def _guess_component(title: str, body: str):
    """Bileşensiz format: başlık+gövdeden ilk core bileşen kimliğini çıkar."""
    haystack = (title or "") + "\n" + (body or "")
    for rx, comp in _COMPONENT_HINTS:
        if rx.search(haystack):
            return comp
    return None


def _sev_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def parse_feed(items) -> list:
    entries = []
    seen = set()
    for it in items:
        title = (it.get("title") or "").strip()
        # Feed GitHub API'sinden CRLF geliyor; `$` (multiline) `\r`'den önce eşleşmez →
        # satırların TAMAMI düşer (ölçüldü: yalnız string-sonu satırı kalıyordu).
        body = (it.get("body") or "").replace("\r\n", "\n").replace("\r", "\n")
        cve_m = _CVE_RE.search(title)
        if not cve_m:
            continue
        cve = cve_m.group(0)
        if cve in seen:
            continue
        fixed_txt = _section(body, "Fixed Versions")
        if not fixed_txt:
            continue
        fixed_lines = _parse_version_lines(fixed_txt)
        if not fixed_lines:
            continue
        comp_guess = None
        fixed_in: dict = {}
        for comp, _op, ver, _rng in fixed_lines:
            if comp is None:
                if comp_guess is None:
                    comp_guess = _guess_component(title, body)
                comp = comp_guess
            if comp not in KNOWN_COMPONENTS:
                continue
            minor = ".".join(ver.split(".")[:2])
            # Aynı minor için en DÜŞÜK fix sürümü kalsın ("master/v1.31.0" + cherry-pick
            # karışıklığında katı eşik yanlış hüküm vermesin).
            if minor not in fixed_in or _ver_tuple(ver) < _ver_tuple(fixed_in[minor]):
                fixed_in[minor] = ver
        if not fixed_in:
            continue
        seen.add(cve)
        affected_txt = _section(body, "Affected Versions")
        affected = [ln.strip(" -*\t") for ln in affected_txt.splitlines()
                    if ln.strip(" -*\t") and len(ln.strip(" -*\t")) < 120][:12]
        sec_m = _SEC_RE.search(body)
        rated_m = _RATED_RE.search(body)
        score_m = _SCORE_RE.search(body)
        if sec_m:
            severity, cvss = sec_m.group(1).lower(), float(sec_m.group(2))
        else:
            severity = (rated_m.group(1).lower() if rated_m
                        else (score_m and _sev_from_cvss(float(score_m.group(1))) or None))
            cvss = float(score_m.group(1)) if score_m else None
        low = (title + body).lower()
        entries.append({
            "cve": cve,
            "title": title.split(":", 1)[1].strip() if ":" in title else title,
            "components": sorted({c for c, _op, _v, _r in fixed_lines
                                  if c in KNOWN_COMPONENTS}
                                 | ({comp_guess} if comp_guess else set())),
            "severity": (severity or "medium"),
            "cvss3": cvss,
            "windows_only": "windows" in low,
            "fixed_in": fixed_in,
            "affected": affected,
            "url": it.get("html_url") or "",
        })
    # Yeni CVE önce (tarama raporunda güncel tehdit manşette) + manuel eklemeler
    entries.extend(MANUAL_ADDITIONS)
    entries.sort(key=lambda e: e["cve"], reverse=True)
    return entries


def _ver_tuple(v: str):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0, 0, 0)


def main():
    ap = argparse.ArgumentParser(description="K8s resmî CVE feed → statik snapshot")
    ap.add_argument("--in", dest="infile", help="lokal ham feed JSON (default: GitHub API)")
    ap.add_argument("--out", dest="outfile", default=str(OUT_FILE))
    args = ap.parse_args()

    if args.infile:
        data = json.loads(Path(args.infile).read_text())
        items = data.get("items", data if isinstance(data, list) else [])
    else:
        req = urllib.request.Request(FEED_URL, headers={
            "User-Agent": "kadim-k8s-cve-extract", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            items = json.loads(r.read().decode()).get("items", [])

    entries = parse_feed(items)
    snapshot = {
        "generated_at": date.today().isoformat(),
        "source": ("Kubernetes resmî CVE feed'i — github.com/kubernetes/kubernetes "
                   "issue'ları label:official-cve-feed (Security Response Committee "
                   "duyuruları). Üretim: scripts/extract_k8s_cve_snapshot.py"),
        "match_semantics": ("fixed_in: {minor: fixed_version}. Eşleşen minor'da "
                            "version < fixed → zaafiyetli; minor > en büyük fixed minor → "
                            "yamalı; minor < en küçük fixed minor → zaafiyetli (fix "
                            "penceresi öncesi dal, danışmanın 'affected' listesiyle "
                            "çapraz kontrol edilmeli)."),
        "entries": entries,
    }
    out = Path(args.outfile)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, ensure_ascii=False, indent=1) + "\n")
    comps: dict = {}
    for e in entries:
        for c in e["components"]:
            comps[c] = comps.get(c, 0) + 1
    print(f"OK: {len(entries)} kayıt → {out}")
    print(f"    bileşen dağılımı: {comps}")
    skipped = len(items) - len(entries)
    print(f"    atlanan (fixed bölümü parçalanamayan/bileşensiz): {skipped}")


if __name__ == "__main__":
    main()
