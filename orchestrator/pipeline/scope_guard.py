"""
Kadim Güvenlik — Kapsam Kapısı (Scope Guard)
============================================
Türkçe: "Önce yetki, sonra tarama." Bu ürün DIŞ bir sunucudan, saldırgan-perspektifiyle
tarama yapıyor — yani yanlış/kapsam-dışı bir hedef girilirse motor, yetkimiz olmayan bir
sisteme GERÇEK istek gönderir (TCK 243/244 yetkisiz erişim + engagement-kapsamı ihlali).
Bu modül tarama BAŞLAMADAN iki deterministik kapı uygular:

  1) Yetki allowlist'i (AUTHORIZED_TARGETS): hedef host, operatörün tanımladığı engagement
     kapsamında (domain / subdomain / IP / CIDR) mı? Allowlist BOŞSA zorlanmaz (geriye-uyum)
     — ama uyarı loglanır; bankacılık konuşlanmasında MUTLAKA doldurulmalı.
  2) SSRF / iç-ağ koruması: IP-literal hedef loopback / link-local / private (RFC1918) /
     reserved ya da bulut-metadata (169.254.169.254, fd00:ec2::254) ise reddedilir. İç-ağ
     angajmanı için operatör ALLOW_PRIVATE_TARGETS=true ile BİLİNÇLİ açar; metadata adresi
     iç-ağ modunda bile yasaktır (SSRF-ile-kimlik-hırsızlığı klasiği).

SAF ve BAĞIMSIZ (stdlib). Bilinçli DNS I/O YOK: pydantic validator hızlı/deterministik
kalsın ve domain→private-IP (DNS-rebinding) koruması gerçek-istek katmanına bırakılsın.
Bu modül IP-literal hedefteki en yaygın SSRF vakasını + allowlist'i kapsar.
"""
import ipaddress
import os
from typing import List, Optional

# Bulut-metadata uçları: iç-ağ modu açık olsa bile yasak (kimlik/kredensiyel hırsızlığı yüzeyi).
_METADATA_IPS = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254")
)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on", "evet")


def _authorized_entries() -> List[str]:
    """AUTHORIZED_TARGETS'i parçala. Boş → allowlist zorlanmıyor demektir."""
    raw = os.getenv("AUTHORIZED_TARGETS", "") or ""
    return [e.strip().lower() for e in raw.replace("\n", ",").split(",") if e.strip()]


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def authorized_hosts_configured() -> bool:
    return bool(_authorized_entries())


def ip_scope_reason(host: str) -> Optional[str]:
    """IP-literal host için 'neden reddedildi' gerekçesi; host IP değilse/temizse None.
    ALLOW_PRIVATE_TARGETS=true iç-ağ adreslerini serbest bırakır (bilinçli açık) ama
    metadata uçlarını ASLA."""
    ip = _as_ip(host)
    if ip is None:
        return None  # domain — IP-guard burada uygulanmaz (bkz. modül başlığı)
    if ip in _METADATA_IPS:
        return "bulut-metadata adresi (kimlik hırsızlığı yüzeyi) — iç-ağ modunda bile yasak"
    if _env_flag("ALLOW_PRIVATE_TARGETS", False):
        return None  # iç-ağ angajmanı bilinçli açıldı
    if ip.is_loopback:
        return "loopback (127.0.0.0/8) kapsam dışı"
    if ip.is_link_local:
        return "link-local (169.254.0.0/16) kapsam dışı"
    if ip.is_private:
        return "özel/iç-ağ adresi (RFC1918) — iç angajman için ALLOW_PRIVATE_TARGETS=true"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "ayrılmış/multicast/tanımsız adres kapsam dışı"
    return None


def _host_matches_entry(host: str, entry: str) -> bool:
    host = host.strip().lower().rstrip(".")
    entry = entry.strip().lower().rstrip(".")
    if not host or not entry:
        return False
    if "/" in entry:  # CIDR
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
        ip = _as_ip(host)
        return ip is not None and ip in net
    entry_ip = _as_ip(entry)
    if entry_ip is not None:  # düz IP girdisi
        host_ip = _as_ip(host)
        return host_ip is not None and host_ip == entry_ip
    # Domain girdisi: tam eşleşme veya subdomain (api.bank.com ⊂ bank.com)
    return host == entry or host.endswith("." + entry)


def is_authorized(host: str) -> bool:
    """Hedef host allowlist kapsamında mı? Allowlist boşsa (zorlanmıyorsa) True döner."""
    entries = _authorized_entries()
    if not entries:
        return True
    return any(_host_matches_entry(host, e) for e in entries)


def enforce_target_scope(host: str) -> None:
    """Tarama BAŞLAMADAN çağrılır. Kapsam ihlalinde ValueError fırlatır (pydantic → 422).
    Sıra: önce SSRF/IP-guard (mutlak), sonra yetki-allowlist'i."""
    reason = ip_scope_reason(host)
    if reason:
        raise ValueError(f"Hedef kapsam dışı: {reason}")
    if not is_authorized(host):
        raise ValueError(
            "Hedef, yetki-allowlist'inde (AUTHORIZED_TARGETS) değil — engagement kapsamı dışı. "
            "Yetkili hedefi allowlist'e ekleyin ya da operatörle kapsamı doğrulayın."
        )
