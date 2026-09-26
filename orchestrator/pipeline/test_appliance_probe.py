"""
Appliance auth-bypass / missing-auth probu — izole düz-script testleri (pytest gerekmez).
Kapsam: identify_appliance + classify_appliance_response + probe_appliance (sahte client) +
playbook _is_appliance gating.

Çalıştırma:
    PYTHONPATH=orchestrator python3 orchestrator/pipeline/test_appliance_probe.py
"""
import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pipeline.appliance_probe import (
    identify_appliance, classify_appliance_response, probe_appliance,
)
from pipeline.target_profile import fingerprint
from pipeline.playbook import select_playbook

_fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        _fails.append(name)


# ---------------- Sahte httpx client ----------------
class _Resp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _FakeClient:
    """url→(status,text,headers) haritasından yanıt döndürür. Kök '/' zorunlu."""
    def __init__(self, routes):
        self.routes = routes

    async def get(self, url, timeout=10.0, follow_redirects=False):
        # tam eşleşme, yoksa path-suffix eşleşmesi
        if url in self.routes:
            return _Resp(*self._norm(self.routes[url]))
        for k, v in self.routes.items():
            if url.endswith(k):
                return _Resp(*self._norm(v))
        return _Resp(404, "not found")

    @staticmethod
    def _norm(v):
        if len(v) == 2:
            return (v[0], v[1], {})
        return v


print("== identify_appliance ==")
fam, ev = identify_appliance("<a href='/remote/login'>FortiGate</a>", {})
check("fortinet tanındı", fam == "fortinet" and ev)
fam, _ = identify_appliance("<div>GlobalProtect Portal</div>", {})
check("panos tanındı", fam == "panos")
fam, _ = identify_appliance("<a href='/dana-na/auth/url_default/welcome.cgi'>Pulse</a>", {})
check("ivanti tanındı", fam == "ivanti")
fam, _ = identify_appliance("<title>Citrix NetScaler Gateway</title>", {})
check("citrix tanındı", fam == "citrix_netscaler")
fam, _ = identify_appliance("<html><title>Welcome to nginx</title></html>", {})
check("negatif: sıradan sayfa None", fam is None)

print("== classify_appliance_response ==")
# auth-gate imzası → None (kapı çalışıyor)
c = classify_appliance_response("unauth_api", 200, "Please sign in to continue",
                                re.compile(r"system\s*status", re.I))
check("auth-gate imzası → bulgu yok", c is None)
# unauth_api ayrıcalıklı içerik, kapı yok → bulgu
c = classify_appliance_response("unauth_api", 200, '{"version":"7.4.1","serial":"FG100"}',
                                re.compile(r'"version"\s*:', re.I))
check("unauth_api ayrıcalıklı içerik → bulgu", c and c["kind"] == "unauth_api")
# version çıkarımı
c = classify_appliance_response("version", 200, '{"version":"22.7R2.3"}',
                                re.compile(r'"version"\s*:\s*"([0-9][0-9A-Za-z.\-]+)"'))
check("version çıkarıldı=22.7R2.3", c and c.get("version") == "22.7R2.3")
# 401 → None
c = classify_appliance_response("unauth_api", 401, "unauthorized",
                                re.compile(r"x", re.I))
check("401 → bulgu yok", c is None)

print("== probe_appliance uçtan uca (sahte client) ==")
# FortiWeb: kök fortinet imzası + /api/v2/cmdb/system/status kimliksiz version JSON döndürür
routes = {
    "https://fw.example.com/": (200, "<html><a href='/remote/login'>FortiGate</a></html>", {}),
    "https://fw.example.com/api/v2/cmdb/system/status": (200, '{"version":"7.4.0","build":"1234"}', {}),
    "https://fw.example.com/migadmin/": (200, "Please login", {}),  # kapı çalışıyor → bulgu yok
}
res = asyncio.run(probe_appliance("fw.example.com", _FakeClient(routes)))
check("aile=fortinet", res["family"] == "fortinet")
titles = [f["title"] for f in res["findings"]]
check("missing-auth bulgusu üretildi",
      any("Eksik Kimlik Doğrulama" in t for t in titles))
check("kapalı endpoint bulgu üretmedi (migadmin login)",
      not any("migadmin" in t for t in titles))
crit = [f for f in res["findings"] if f["severity"] == "critical"]
check("missing-auth critical + CWE-306",
      crit and "CWE-306" in (crit[0].get("cwe") or []))
check("tahribatsız kanıt metni (GET/exploit çalıştırılmadı)",
      any("exploit tekniği/komut çalıştırılmadı" in f["proof"] for f in res["findings"]))

# Çift kapı: imza YOKSA (kök jenerik) → BOŞ (profil yanılsa bile FP yok)
routes_noimg = {
    "https://x.example.com/": (200, "<html><title>Welcome</title></html>", {}),
    "https://x.example.com/api/v2/cmdb/system/status": (200, '{"version":"7.4.0"}', {}),
}
res2 = asyncio.run(probe_appliance("x.example.com", _FakeClient(routes_noimg)))
check("çift kapı: canlı imza yoksa BOŞ", res2["family"] is None and res2["findings"] == [])

print("== playbook _is_appliance gating ==")
# fortinet fingerprint → appliance_probe run=True
p = fingerprint(headers={}, cookies=[], body="<a href='/remote/login'>fortigate</a>")
pb = select_playbook(p)
check("profil framework=fortinet", p.is_("framework", "fortinet", 0.5))
check("playbook: appliance_probe ÇALIŞIR", pb.allowed("appliance_probe", default=False))
# Sıradan WordPress → appliance_probe run=False (gate kapalı)
p2 = fingerprint(headers={}, cookies=["wordpress_logged_in"], body="wp-content/")
pb2 = select_playbook(p2)
check("WP hedefte appliance_probe ÇALIŞMAZ", not pb2.allowed("appliance_probe", default=False))

print()
if _fails:
    print(f"TOPLAM {len(_fails)} BAŞARISIZ: {_fails}")
    sys.exit(1)
print("TÜM TESTLER GEÇTİ ✔")
