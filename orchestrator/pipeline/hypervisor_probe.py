"""
Kadim Güvenlik — Hypervisor / Sanallaştırma Yönetim-Arayüzü İfşa Probu (TAHRİBATSIZ)

NEDEN: Kullanıcı "taradığım sunucunun ana makinesini (ESXi/Proxmox) görebilir miyim?" dedi.
DÜRÜST GERÇEK: bir VM'in fiziksel host IP'si DIŞARIDAN tespit edilemez (mgmt ağı ayrı/firewall
arkası). AMA gerçekten değerli ve YAPILABİLİR olan şudur: hedefin KENDİSİ bir hypervisor/host
yönetim arayüzünü (ESXi Host Client, vCenter, Proxmox VE/PBS, Cockpit, oVirt) internete AÇIK
mı veriyor? Bu, tüm sanallaştırma host'unun saldırı yüzeyidir (ESXi ransomware kampanyaları
tam buradan girer) → mgmt-plane ifşası = yüksek/kritik bulgu.

DOKTRIN: TAHRİBATSIZ. Yalnız GET + banner/başlık/sürüm okuması; KİMLİK DENENMEZ, exploit YOK.
Proxmox `/api2/json/version` gibi kimliksiz sürüm uçları yalnızca OKUNUR (ifşanın kanıtı).

TASARIM: SAF `classify_hypervisor_response(...)` (imza→bulgu, I/O yok, test edilebilir) +
ince `probe_hypervisor(host, open_ports, client)` (yalnız GET). Katı imzalar → normal HTTPS
sitesinde FP üretmez (yalnız açık hypervisor imzasında tetiklenir).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

# Sanallaştırma yönetim portları (nmap sık kaçırır → hedefli yoklanır).
HYPERVISOR_PORTS: Set[int] = {
    443,    # ESXi Host Client / vCenter / oVirt (HTTPS)
    8006,   # Proxmox VE web UI
    8007,   # Proxmox Backup Server
    9090,   # Cockpit (Linux/host web console)
    5989,   # VMware CIM (WBEM/SSL)
}

# (port, path) → hangi mgmt yüzeyi denenecek. 443'te birden çok yol (ESXi farklı imzalar).
_PROBE_TARGETS = [
    (8006, "/api2/json/version"),   # Proxmox VE — kimliksiz sürüm (en güçlü kanıt)
    (8006, "/"),                    # Proxmox VE login
    (8007, "/api2/json/version"),   # Proxmox Backup Server
    (8007, "/"),
    (443, "/ui/"),                  # ESXi Host Client / vCenter
    (443, "/mob/"),                 # ESXi Managed Object Browser (asla internete açık olmamalı)
    (443, "/ovirt-engine/"),        # oVirt / RHV
    (443, "/"),                     # ESXi/vCenter kök (welcome/redirect imzası)
    (9090, "/"),                    # Cockpit
]


def _sev_tier(strong: bool) -> Dict[str, str]:
    """İmza gücüne göre kademe. Güçlü imza = confirmed (ifşa deterministik gözlendi)."""
    return {"confidence_tier": "confirmed" if strong else "probable",
            "severity": "high"}


def classify_hypervisor_response(
    port: int, path: str, status: int,
    headers: Optional[Dict[str, str]] = None,
    body: str = "",
    json_obj: Any = None,
) -> Optional[Dict[str, Any]]:
    """SAF: tek bir HTTP yanıtından hypervisor mgmt ifşası imzası çıkar (I/O yok).

    Katı imza → normal site FP'si yok. Döner: bulgu dict'i ya da None."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    b = (body or "")
    bl = b.lower()
    server = h.get("server", "")
    setcookie = h.get("set-cookie", "")

    def _find(product: str, proof: str, strong: bool, extra: str = "") -> Dict[str, Any]:
        st = _sev_tier(strong)
        return {
            "title": f"Hypervisor yönetim arayüzü internete açık: {product}"
                     + (f" ({extra})" if extra else ""),
            "product": product,
            "severity": st["severity"],
            "confidence_tier": st["confidence_tier"],
            "cwe": ["CWE-284"],           # Improper Access Control (mgmt-plane ifşası)
            "mitre": "T1133",             # External Remote Services
            "proof": proof[:400],
            "port": port,
            "path": path,
        }

    # --- Proxmox VE / Backup Server ---
    if port in (8006, 8007):
        # Kimliksiz sürüm ucu: {"data":{"version":"8.2.2","release":...}} → en güçlü kanıt.
        if path.endswith("/version") and isinstance(json_obj, dict):
            data = json_obj.get("data") if isinstance(json_obj.get("data"), dict) else None
            if data and (data.get("version") or data.get("release")):
                ver = str(data.get("version") or data.get("release"))
                prod = "Proxmox Backup Server" if port == 8007 else "Proxmox VE"
                return _find(prod, f"Kimliksiz {path} sürüm ifşası: {ver}", True, f"v{ver}")
        if "proxmox" in bl or "pveauthcookie" in setcookie or "pbsauthcookie" in setcookie:
            prod = "Proxmox Backup Server" if port == 8007 else "Proxmox VE"
            return _find(prod, f"Proxmox login/UI imzası (port {port})", True)

    # --- Cockpit (host/Linux web konsolu) ---
    if port == 9090:
        if "cockpit" in bl or "cockpit" in server or "x-cockpit" in h or "cockpit" in setcookie:
            return _find("Cockpit (host web konsolu)",
                         f"Cockpit imzası (port 9090): {status}", True)

    # --- ESXi / vCenter / oVirt (443) ---
    if port == 443 or port == 5989:
        # ESXi Host Client / vCenter kesin imzaları.
        if "vmware esxi" in bl:
            m = re.search(r"vmware esxi[^<]{0,40}", bl)
            return _find("VMware ESXi", f"ESXi imzası: {m.group(0) if m else 'VMware ESXi'}", True)
        if "esxi" in bl and ("host client" in bl or "/ui/" in path):
            return _find("VMware ESXi", "ESXi Host Client arayüzü", True)
        if "vsphere" in bl or "websso" in bl or ("vcenter" in bl):
            return _find("VMware vCenter / vSphere", "vSphere/vCenter arayüz imzası", True)
        if path.startswith("/mob") and status == 200 and ("managed object" in bl or "vim25" in bl):
            return _find("VMware ESXi/vCenter (MOB)",
                         "Managed Object Browser internete açık (asla olmamalı)", True)
        # oVirt / RHV — YALNIZ gerçek gövde/cookie imzasıyla. Path tek başına KANIT DEĞİL:
        # _PROBE_TARGETS daima /ovirt-engine/ yokladığı için path.startswith hep True olur →
        # her catch-all/SPA sunucu (index.html=200 ya da login redirect=302) yanlışça
        # "oVirt ifşası" (CRITICAL) damgalanıyordu. İmza olmadan işaretleme.
        if ("ovirt" in bl or "ovirt" in setcookie) and status in (200, 302, 401):
            return _find("oVirt / RHV", f"oVirt engine imzası (status {status})", True)
        if "vmware" in server:
            return _find("VMware (ESXi/vCenter)", f"Server başlığı: {server}", False)

    return None


async def probe_hypervisor(host: str, open_ports: List[int], client) -> List[Dict[str, Any]]:
    """İnce I/O: hedefin mgmt portlarında yalnız GET ile hypervisor ifşasını yokla (TAHRİBATSIZ).

    Yalnız `engine.target` (kullanıcının host'u) için çağrılır — co-hosted sızıntısı yok.
    Denenecek portlar: açık portlar ∩ HYPERVISOR_PORTS ∪ {8006,8007,9090} (nmap bunları kaçırır).
    Bağlantı kurulamayan port sessizce atlanır. Ürün başına tek bulgu (dedup)."""
    from urllib.parse import urlsplit

    bare = host
    if "://" in host:
        bare = urlsplit(host).netloc or host
    bare = bare.split("/")[0].split(":")[0]

    openset = {int(p) for p in (open_ports or []) if str(p).isdigit()}
    # 8006/8007/9090'ı nmap kaçırdığı için açık listede olmasa da dener (hedefli, az sayıda).
    candidate_ports = (openset & HYPERVISOR_PORTS) | {8006, 8007, 9090}

    findings: List[Dict[str, Any]] = []
    seen_products: Set[str] = set()

    for port, path in _PROBE_TARGETS:
        if port not in candidate_ports:
            continue
        url = f"https://{bare}:{port}{path}"
        try:
            resp = await client.get(url, timeout=6.0,
                                    headers={"User-Agent": "KadimGuvenlik/1.0"})
        except Exception:
            continue  # port kapalı/erişilemez → sessizce atla (gürültü yok)
        body = ""
        try:
            body = resp.text[:8192]
        except Exception:
            body = ""
        json_obj = None
        ct = str(resp.headers.get("content-type", "")).lower()
        if "json" in ct:
            try:
                json_obj = resp.json()
            except Exception:
                json_obj = None
        f = classify_hypervisor_response(
            port, path, resp.status_code, dict(resp.headers), body, json_obj)
        if f and f["product"] not in seen_products:
            f["target"] = f"{bare}:{port}"
            seen_products.add(f["product"])
            findings.append(f)
    return findings
