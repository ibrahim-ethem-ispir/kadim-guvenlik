"""
Kadim Güvenlik — TLS / Sertifika + IP İstihbaratı (orchestrator-yerli)
======================================================================
Türkçe: Hedefin TLS sertifikasından KİMLİK ve SALDIRI YÜZEYİ sinyali çıkarır — yeni servis
gerektirmez (tlsx bir Go binary'si; ama sertifika+SAN+IP işi stdlib `ssl` ile daha temiz ve
test edilebilir). Neden değerli:

  - **SAN domainleri**: sertifikadaki alternatif adlar = ek saldırı yüzeyi (çoğu zaman
    aynı origin'e bağlı başka vhost/servis). [[reverse-ip-cohosted-dns-dogrulama]] için de
    same-cert doğrulama sinyali.
  - **Sunucu grubu (IP'ler) + ana sunucu IP'si**: hedef adı hangi IP'lere çözülüyor →
    operatöre "bu sistemin sunucu grubu / ana IP'si" olarak gösterilir.
  - **CDN farkındalığı**: ana IP CDN edge'i olabilir (gerçek origin gizli) → dürüst uyarı.

TAHRİBATSIZ: yalnız TLS handshake + DNS çözümleme (okuma). Degrade-safe: hata/erişilemezlik
sessizce kısmi/boş sonuç döner.
"""

import asyncio
import ipaddress
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# Ana IP / reverse-DNS / issuer'da bu imzalar geçerse "CDN arkasında" say (gerçek origin gizli).
_CDN_HINTS = (
    "cloudflare", "akamai", "fastly", "incapsula", "imperva", "sucuri", "stackpath",
    "cloudfront", "amazonaws", "edgecast", "azureedge", "azure", "llnwd", "cdn77",
    "gcore", "bunnycdn", "keycdn", "netlify", "vercel",
)

# IP-aralığı bazlı CDN tespiti — PTR/issuer imzası olmasa bile Cloudflare vb. yakalanır
# (Cloudflare PTR koymaz, sertifikayı Google Trust Services'ten alır → imza-tabanlı kaçar).
# Bu yüzden ana IP'nin AĞ BLOĞUNA bakarız: origin-gizleme tespitinin en güvenilir sinyali.
_CDN_CIDRS: Dict[str, List[str]] = {
    "Cloudflare": ["104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
                   "173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18",
                   "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
                   "198.41.128.0/17", "131.0.72.0/22"],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "Akamai": ["23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"],
    "Amazon CloudFront": ["13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16",
                          "54.192.0.0/16", "99.84.0.0/16", "205.251.192.0/19"],
}
_CDN_NETS: List[Tuple[str, "ipaddress._BaseNetwork"]] = [
    (name, ipaddress.ip_network(cidr)) for name, cidrs in _CDN_CIDRS.items() for cidr in cidrs
]


def _cdn_for_ip(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return None
    for name, net in _CDN_NETS:
        if addr.version == net.version and addr in net:
            return name
    return None


def _host_port(target: str) -> Tuple[str, int]:
    t = (target or "").strip()
    if "://" not in t:
        t = "https://" + t
    u = urlsplit(t)
    return (u.hostname or "").strip().lower(), (u.port or 443)


def _resolve_ips(host: str) -> List[str]:
    """Hedefi tüm A/AAAA kayıtlarına çöz (sunucu grubu). IPv4 önce."""
    ips = set()
    try:
        for r in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            ips.add(r[4][0])
    except Exception:
        pass
    return sorted(ips, key=lambda ip: (":" in ip, ip))


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _flatten_name(rdns) -> Dict[str, str]:
    """getpeercert()'in subject/issuer'ı iç-içe tuple; düz dict'e çevir."""
    out: Dict[str, str] = {}
    for rdn in rdns or ():
        for pair in rdn:
            try:
                k, v = pair
                out[k] = v
            except Exception:
                continue
    return out


def _grab_cert(host: str, port: int, timeout: float) -> Tuple[Optional[Dict[str, Any]], bool]:
    """(cert, verified) döndürür. Önce DOĞRULANMIŞ bağlantı → getpeercert() dict (SAN/issuer/
    tarih, stdlib, cryptography GEREKMEZ). Doğrulama patlarsa (self-signed) doğrulamasız
    bağlanıp binary sertifikayı cryptography ile (varsa) ayrıştırır."""
    # 1) Doğrulanmış — çoğu gerçek hedef buradan geçer (stdlib-only).
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ss.getpeercert(), True
    except Exception:
        pass
    # 2) Doğrulamasız (self-signed/isim uyuşmazlığı) — binary al, cryptography ile ayrıştır.
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            c = x509.load_der_x509_certificate(der, default_backend())
            san: List[str] = []
            try:
                ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass
            return {
                "subjectAltName": [("DNS", d) for d in san],
                "issuer_str": c.issuer.rfc4514_string(),
                "notAfter": c.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT"),
            }, False
        except Exception:
            # cryptography yok → en azından "TLS var ama doğrulanamadı" sinyali.
            return {"unverified": True}, False
    except Exception:
        return None, False


async def grab_tls_intel(target: str, *, timeout: float = 8.0) -> Dict[str, Any]:
    """Hedef için TLS/IP istihbaratı topla. Bloklayan çağrılar thread'e taşınır (event-loop
    tıkanmasın). Her alan best-effort; hata → o alan boş kalır, sonuç yine döner."""
    host, port = _host_port(target)
    out: Dict[str, Any] = {
        "host": host, "port": port, "main_ip": None, "ips": [], "reverse_dns": {},
        "san_domains": [], "cert": None, "behind_cdn": None, "cdn": None, "note": "ok",
    }
    if not host:
        return {**out, "note": "gecersiz_hedef"}

    ips = await asyncio.to_thread(_resolve_ips, host)
    out["ips"] = ips
    out["main_ip"] = ips[0] if ips else None

    cert, verified = await asyncio.to_thread(_grab_cert, host, port, timeout)
    san: List[str] = []
    if cert:
        for typ, val in cert.get("subjectAltName", []) or []:
            if typ == "DNS" and val:
                san.append(val)
        issuer = cert.get("issuer_str")
        if not issuer:
            iss = _flatten_name(cert.get("issuer"))
            issuer = iss.get("organizationName") or iss.get("commonName")
        subj = _flatten_name(cert.get("subject"))
        out["cert"] = {
            "issuer": issuer,
            "subject_cn": subj.get("commonName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "verified": verified,
        }
    out["san_domains"] = sorted({d.lstrip("*.").lower() for d in san if d})

    rdns: Dict[str, str] = {}
    for ip in ips[:4]:
        r = await asyncio.to_thread(_reverse_dns, ip)
        if r:
            rdns[ip] = r
    out["reverse_dns"] = rdns

    # CDN tespiti: ÖNCE IP-bloğu (en güvenilir — Cloudflare vb. imza koymadan yakalanır),
    # SONRA host/reverse-DNS/issuer imzaları. Bulunan CDN adı UI'da "X arkasında" gösterilir.
    # behind_cdn True → ana IP muhtemelen CDN edge'i, GERÇEK origin gizli (UI bunu belirtir).
    cdn_name = next((c for ip in ips if (c := _cdn_for_ip(ip))), None)
    if not cdn_name:
        blob = " ".join([host, *rdns.values(), str((out["cert"] or {}).get("issuer") or "")]).lower()
        cdn_name = next((h.title() for h in _CDN_HINTS if h in blob), None)
    out["cdn"] = cdn_name
    out["behind_cdn"] = True if cdn_name else None
    return out
