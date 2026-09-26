"""
2026 yüzeyi tespit zinciri — izole düz-script testleri (pytest gerekmez).
Kapsam: path_probe._detect_modern_stack + target_profile.fingerprint +
cve_intel._cpe_product_variants + adaptive_scanner haritası + kev_intel._product_keys.

Çalıştırma:
    PYTHONPATH=orchestrator python3 orchestrator/pipeline/test_modern_stack_2026.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pipeline.path_probe import _detect_modern_stack, _MODERN_STACK_SIGNATURES
from pipeline.target_profile import fingerprint
from pipeline.cve_intel import _cpe_product_variants
from pipeline.adaptive_scanner import SERVICE_VULNERABILITY_MAP
from pipeline.kev_intel import _product_keys

_fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        _fails.append(name)


def _collect(hdr_blob, body):
    """_detect_modern_stack'i çağırıp {ürün: sürüm} topla."""
    out = {}
    _detect_modern_stack(hdr_blob, body, lambda p, v, s: out.setdefault(p, v))
    return out


print("== path_probe._detect_modern_stack ==")
# Langflow (title imzası, sürümsüz)
d = _collect("", "<html><head><title>Langflow</title></head><body></body></html>")
check("langflow title tespit", "langflow" in d)

# n8n (title)
d = _collect("", "<title>n8n - Workflow Automation</title>")
check("n8n title tespit", "n8n" in d)

# Metabase (çerez header + bootstrap gövde)
d = _collect("set-cookie: metabase.session=abc; path=/", "<div>window.MetabaseBootstrap={}</div>")
check("metabase çerez+bootstrap tespit", "metabase" in d)

# TeamCity — sürüm yakalama
d = _collect("x-teamcity-node-id: MAIN_SERVER", "<h1>TeamCity 2024.12</h1>")
check("teamcity tespit", "teamcity" in d)
check("teamcity sürüm yakalandı=2024.12", d.get("teamcity") == "2024.12")

# Ollama (düz metin kök yanıt)
d = _collect("content-type: text/plain", "Ollama is running")
check("ollama tespit", "ollama" in d)

# ColdFusion (CFID çerezi)
d = _collect("set-cookie: cfid=1234; set-cookie: cftoken=abc", "<html></html>")
check("coldfusion çerez tespit", "coldfusion" in d)

# Grafana (bootdata + sürüm)
d = _collect("", '<script>window.grafanaBootData={settings:{"version":"11.2.0"}}</script>')
check("grafana tespit", "grafana" in d)
check("grafana sürüm=11.2.0", d.get("grafana") == "11.2.0")

# Negatif: sıradan nginx sayfası hiçbir modern-stack imzası vermemeli (FP kapısı)
d = _collect("server: nginx", "<html><head><title>Welcome</title></head><body>hello</body></html>")
check("negatif: temiz sayfa boş döner", d == {})

print("== target_profile.fingerprint (framework boyutu) ==")
p = fingerprint(headers={}, cookies=["metabase.SESSION"], body="")
check("profil: metabase çerezinden framework", p.is_("framework", "metabase", 0.5))

p = fingerprint(headers={"X-Jenkins": "2.440"}, cookies=[], body="")
check("profil: jenkins header'dan framework", p.is_("framework", "jenkins", 0.5))

p = fingerprint(headers={}, cookies=[], body="<title>Langflow</title>")
check("profil: langflow gövdeden framework", p.is_("framework", "langflow", 0.5))
check("profil: langflow → kind=web", p.kind() == "web")

print("== cve_intel._cpe_product_variants (NVD alias) ==")
check("metabase alias", "metabase" in _cpe_product_variants("metabase"))
check("panos → pan-os alias", "pan-os" in _cpe_product_variants("panos"))
check("sharepoint → sharepoint_server", "sharepoint_server" in _cpe_product_variants("sharepoint"))
check("fortinet → fortiweb", "fortiweb" in _cpe_product_variants("fortinet"))

print("== adaptive_scanner.SERVICE_VULNERABILITY_MAP (nuclei tag) ==")
for prod in ("langflow", "n8n", "metabase", "teamcity", "coldfusion", "ollama",
             "gitlab", "grafana", "jenkins", "sharepoint", "loadmaster", "simplehelp"):
    info = SERVICE_VULNERABILITY_MAP.get(prod)
    check(f"map[{prod}] var + nuclei_tags dolu",
          bool(info) and bool(info.get("nuclei_tags")))

print("== kev_intel._product_keys (KEV ürün eşleme) ==")
check("kev: langflow anahtarı", "langflow" in _product_keys("langflow"))
check("kev: panos → panos", "panos" in _product_keys("PAN-OS"))
check("kev: simplehelp", "simplehelp" in _product_keys("SimpleHelp"))
check("kev: sharepoint → sharepointserver", "sharepointserver" in _product_keys("SharePoint"))

print("== her fingerprint ürünü haritada karşılığı var mı (zincir bütünlüğü) ==")
# path_probe'un ürettiği HER ürün adı SERVICE_VULNERABILITY_MAP'te olmalı — aksi halde
# tespit edilir ama nuclei tag'e dönmez (kopuk zincir). confluence/kibana zaten haritada
# ya da klasik CVE ailesinde; kontrol et.
for prod, *_ in _MODERN_STACK_SIGNATURES:
    check(f"zincir: {prod} haritada", prod in SERVICE_VULNERABILITY_MAP)

print()
if _fails:
    print(f"TOPLAM {len(_fails)} BAŞARISIZ: {_fails}")
    sys.exit(1)
print("TÜM TESTLER GEÇTİ ✔")
