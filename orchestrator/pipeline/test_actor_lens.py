"""
Kadim Güvenlik — actor_lens İZOLE TEST (düz script, pytest yok — repo konvansiyonu).
SAF çekirdek: ağ/DB/LLM yok, sentetik yüzeylerle deterministik davranış doğrulanır.

Çalıştır: python3 orchestrator/pipeline/test_actor_lens.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.actor_lens import (  # noqa: E402
    ACTORS, THREAT_VECTORS, assess_actor_surface, surface_from_graph,
)

_OK = 0
_FAIL = 0


def check(name: str, cond: bool, detail: str = ""):
    global _OK, _FAIL
    if cond:
        _OK += 1
        print(f"✓ {name}")
    else:
        _FAIL += 1
        print(f"✗ {name} — {detail}")


def _surface(**kw):
    base = {"hosts": [], "technologies": [], "evidence": [], "executed_tools": []}
    base.update(kw)
    return base


# ---------- 1) .env ifşası kanıtı → hacktivist için KAPI AÇIK ----------
res = assess_actor_surface(_surface(
    evidence=[{"tool": "pathprobe", "title": ".env ifşası (env_file)", "severity": "critical"}],
    executed_tools=["pathprobe", "nmap"],
))
hv = res["actors"]["hacktivist"]
door_ids = [d["id"] for d in hv["doors"]]
check("env kanıtı → hacktivist secret_leak kapısı AÇIK",
      "secret_leak" in door_ids, f"doors={door_ids}")
check("env kapısı 'kanıt eşleşti' gerekçesiyle açıldı",
      any(d["why"] == "kanıt eşleşti" for d in hv["doors"] if d["id"] == "secret_leak"))

# ---------- 2) pathprobe KOŞMADI ama .env hiç aranmadıysa → kapsam açığı değil, n/a ----------
res = assess_actor_surface(_surface(executed_tools=["nmap"]))
hv = res["actors"]["hacktivist"]
check("sinyal+kanıt yokken secret_leak n/a (uydurma gap üretme)",
      all(d["id"] != "secret_leak" for d in hv["gaps"]))

# ---------- 3) 3389 açık → ransomware için DOĞRUDAN kapı (sinyal=kanıt) ----------
res = assess_actor_surface(_surface(
    hosts=[{"host": "1.2.3.4", "ports": {3389: {"service": "ms-wbt-server",
                                                "product": "Microsoft Terminal Services",
                                                "version": ""}}}],
    executed_tools=["nmap"],
))
rw = res["actors"]["ransomware"]
door_ids = [d["id"] for d in rw["doors"]]
check("3389 açık → rdp_exposed kapısı AÇIK (confirm_on_signal)",
      "rdp_exposed" in door_ids, f"doors={door_ids}")

# ---------- 4) 6379 (Redis) açık, nuclei koşmadı → GAP (doğrulanmadı, iddia da edilmedi) ----------
res = assess_actor_surface(_surface(
    hosts=[{"host": "1.2.3.4", "ports": {6379: {"service": "redis", "product": "Redis",
                                                "version": ""}}}],
    executed_tools=["nmap"],
))
rw = res["actors"]["ransomware"]
gap_ids = [g["id"] for g in rw["gaps"]]
door_ids = [d["id"] for d in rw["doors"]]
check("Redis açık + nuclei yok → unauth_datastore GAP'te",
      "unauth_datastore" in gap_ids, f"gaps={gap_ids}")
check("Redis açık tek başına 'kapı AÇIK' İLAN EDİLMEZ (kimliksizlik kanıtlanmadı)",
      "unauth_datastore" not in door_ids)

# ---------- 5) Redis açık + nuclei KOŞTU + bulgu yok → TEMİZ ----------
res = assess_actor_surface(_surface(
    hosts=[{"host": "1.2.3.4", "ports": {6379: {"service": "redis", "product": "Redis",
                                                "version": ""}}}],
    executed_tools=["nmap", "nuclei"],
))
rw = res["actors"]["ransomware"]
check("Redis + nuclei koştu → unauth_datastore TEMİZ",
      "unauth_datastore" in rw["clean"])
check("coverage=100% (tek uygun vektör kontrol edildi)",
      rw["coverage"]["pct"] == 100.0, f"cov={rw['coverage']}")

# ---------- 6) Jenkins sinyali, CI kapsamı yok → lazarus GAP'i ----------
res = assess_actor_surface(_surface(
    technologies=["jenkins", "nginx"],
    executed_tools=["nmap", "subfinder"],
))
lz = res["actors"]["lazarus"]
gap_ids = [g["id"] for g in lz["gaps"]]
check("Jenkins sinyali + doğrulayıcı yok → cicd_exposed GAP",
      "cicd_exposed" in gap_ids, f"gaps={gap_ids}")

# ---------- 7) subdomain keşfi koşmadı → takeover 'değerlendirilemedi' gap'i ----------
res = assess_actor_surface(_surface(executed_tools=["nmap"]))
hv = res["actors"]["hacktivist"]
gap_ids = [g["id"] for g in hv["gaps"]]
check("subfinder koşmadı → subdomain_takeover kapsam-dışı gap'i",
      "subdomain_takeover" in gap_ids, f"gaps={gap_ids}")

# ---------- 8) keşif koştu, takeover kontrolü de koştu, bulgu yok → TEMİZ ----------
res = assess_actor_surface(_surface(
    executed_tools=["nmap", "subfinder", "takeover"],
))
hv = res["actors"]["hacktivist"]
check("subfinder+takeover koştu → subdomain_takeover TEMİZ",
      "subdomain_takeover" in hv["clean"])

# ---------- 9) Boş yüzey → hiçbir aktörde kapı yok; yalnız keşif-ön-koşullu vektör gap ----------
res = assess_actor_surface(_surface())
check("boş yüzey → doors_total=0", res["doors_total"] == 0)
check("boş yüzey → hiçbir aktörde açık kapı yok",
      all(not a["doors"] for a in res["actors"].values()))
check("boş yüzey → keşif koşmadığı için takeover gap'i görünür (uydurma değil, gerçek kapsamış açığı)",
      any(g["id"] == "subdomain_takeover" for g in res["actors"]["hacktivist"]["gaps"]))
check("boş yüzey → keşif-ön-koşulsuz vektörler uydurma gap ÜRETMEZ",
      all(g["id"] != "secret_leak" and g["id"] != "rdp_exposed"
          for a in res["actors"].values() for g in a["gaps"]))

# ---------- 10) Determinizm: aynı girdi → aynı çıktı ----------
r1 = assess_actor_surface(_surface(
    evidence=[{"tool": "nuclei", "title": "CVE-2026-1234 KEV", "cve": "CVE-2026-1234"}],
))
r2 = assess_actor_surface(_surface(
    evidence=[{"tool": "nuclei", "title": "CVE-2026-1234 KEV", "cve": "CVE-2026-1234"}],
))
check("deterministik çıktı", r1 == r2)

# ---------- 11) KEV kanıtı → üç aktörde de kapı AÇIK ----------
res = r1
for a in ("hacktivist", "ransomware", "lazarus"):
    check(f"KEV kanıtı → {a} kev_active kapısı AÇIK",
          any(d["id"] == "kev_active" for d in res["actors"][a]["doors"]))

# ---------- 12) surface_from_graph: sahte graf → host/teknoloji/araç çıkarma ----------


class _N:  # minimal düğüm taklidi (attribute erişimi yeterli)
    def __init__(self, meta):
        self.meta = meta


class _E:  # minimal kenar taklidi
    def __init__(self, tool):
        self.tool = tool


class _Ev:  # minimal kanıt taklidi
    def __init__(self, tool, title):
        self.tool, self.title, self.severity, self.cve = tool, title, "critical", None


class _G:  # minimal graf taklidi
    def __init__(self):
        self.target = "hedef.example.com"
        self.root_id = "root"
        self.nodes = {
            "root": _N({"open_ports": [{"port": 443, "service": "https",
                                        "product": "", "version": ""}],
                        "technologies": [{"name": "WordPress"}]}),
            "svc:ssh@1.2.3.4": _N({"host": "1.2.3.4", "port": 22,
                                   "product": "OpenSSH", "version": "9.6",
                                   "matched_service": "ssh"}),
        }
        self.edges = {("a", "b", "k"): _E("nmap")}
        self.evidence = [_Ev("pathprobe", ".env ifşası (env_file)")]


sf = surface_from_graph(_G())
check("graf → 2 host çıkarıldı (root target + SERVICE düğümü)",
      {h["host"] for h in sf["hosts"]} == {"hedef.example.com", "1.2.3.4"},
      f"hosts={[h['host'] for h in sf['hosts']]}")
check("graf → SSH portu envantere girdi",
      any(22 in h["ports"] for h in sf["hosts"]))
check("graf → teknoloji normalize (dict→str)",
      "wordpress" in sf["technologies"], f"tech={sf['technologies']}")
check("graf → executed_tools kenar+kanıt araçlarını birleştirdi",
      set(sf["executed_tools"]) >= {"nmap", "pathprobe"})

# Graf yüzeyiyle uçtan uca: .env kanıtı + WordPress → hacktivist'te 2 kapı
res = assess_actor_surface(sf)
hv = res["actors"]["hacktivist"]
check("graf yüzeyi → secret_leak kapısı AÇIK",
      any(d["id"] == "secret_leak" for d in hv["doors"]))
check("graf yüzeyi → WordPress sinyali + wp probu koşmadı → cms_wordpress GAP",
      any(g["id"] == "cms_wordpress" for g in hv["gaps"]))

# ---------- 13) Kütüphane bütünlüğü: her vektörde zorunlu alanlar ----------
_required = ("id", "name", "actors", "severity", "mitre")
_bad = [v.get("id", "?") for v in THREAT_VECTORS
        if any(not v.get(f) for f in _required) or not v["actors"]]
check(f"kütüphane: {len(THREAT_VECTORS)} vektör, zorunlu alanlar tam",
      not _bad, f"eksik: {_bad}")
_all_actor_keys = {a for v in THREAT_VECTORS for a in v["actors"]}
check("kütüphane: her aktör en az bir vektüre bağlı",
      _all_actor_keys == set(ACTORS.keys()),
      f"fark: {_all_actor_keys ^ set(ACTORS.keys())}")

# ---------- 14) gap_sweep_plan: gap'ler hedefli süpürme planına döner ----------
from pipeline.actor_lens import gap_sweep_plan  # noqa: E402

res = assess_actor_surface(_surface(
    hosts=[{"host": "1.2.3.4", "ports": {6379: {"service": "redis", "product": "Redis", "version": ""}}}],
    technologies=["jenkins"],
    executed_tools=["nmap"],
))
plan = gap_sweep_plan(res, base_target="hedef.example.com")
plan_ids = [p["vector_id"] for p in plan]
check("köprü planı: Redis gap'i süpürme planında (redis/mongodb/es tag'leriyle)",
      "unauth_datastore" in plan_ids and
      set(plan[plan_ids.index("unauth_datastore")]["tags"]) >= {"redis"},
      f"plan={[(p['vector_id'], p['tags']) for p in plan]}")
check("köprü planı: Jenkins gap'i teknoloji sinyalinden kök hedefle çözüldü",
      "cicd_exposed" in plan_ids and
      plan[plan_ids.index("cicd_exposed")]["hosts"] == ["hedef.example.com"])
check("köprü planı: port sinyali host'u taşıdı (1.2.3.4)",
      "1.2.3.4" in plan[plan_ids.index("unauth_datastore")]["hosts"])
check("köprü planı: aktör atfı korundu (ransomware Redis gap'inde)",
      "ransomware" in plan[plan_ids.index("unauth_datastore")]["actors"])

# medium gap köprülenmez (gürültü disiplini)
res = assess_actor_surface(_surface(technologies=["wordpress"], executed_tools=["nmap"]))
plan = gap_sweep_plan(res, base_target="x.example.com")
check("köprü planı: medium (cms_wordpress) gap köprülenMEZ",
      all(p["vector_id"] != "cms_wordpress" for p in plan))

# gap yoksa plan boş
res = assess_actor_surface(_surface(executed_tools=["nmap", "nuclei", "subfinder", "takeover"]))
check("köprü planı: gap yoksa plan boş", gap_sweep_plan(res) == [])

print()
print(f"{'TÜM TESTLER GEÇTİ' if _FAIL == 0 else 'BAŞARISIZ TEST VAR'} — {_OK} ok, {_FAIL} fail")
sys.exit(1 if _FAIL else 0)
