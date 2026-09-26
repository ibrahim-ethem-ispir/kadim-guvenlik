"""
Kadim Güvenlik - Origin Discovery Engine
Türkçe: Cloudflare/WAF arkasındaki gerçek IP'yi bulmak için çoklu vektör keşif motoru.

Gerçek dünya senaryosu:
    Bir domain Cloudflare arkasında, nginx ile 80/443 açık.
    Saldırgan gerçek IP'yi buldu ve direkt port scan yaptı.
    Bu modül aynı teknikleri SAVUNMA AMAÇLI uygular:
    "Saldırgan bunu nasıl buldu?" sorusuna cevap verir.

Teknikler:
    1. Certificate Transparency (crt.sh) - SSL sertifika logları
    2. DNS History - Geçmiş A/AAAA kayıtları  
    3. MX Record analizi - Mail sunucu IP'si genellikle gerçek IP
    4. SPF Record analizi - SPF'te gerçek IP olabilir
    5. Subdomain IP karşılaştırma - CF olmayan subdomain'ler
    6. IPv6 bypass - IPv6 genellikle CDN arkasında değil
    7. HTTP header sızıntıları - X-Forwarded-For, Server header
    8. Favicon hash - Shodan ile favicon hash eşleştirme
    9. HTML body hash - Aynı body hash'e sahip IP'ler

Entegrasyon:
    Pipeline'da "origin_discovery" tool olarak çağrılır.
    Bulunan IP'ler discovered_data'ya kaydedilir.
    Sonraki stage'ler (nmap_real_ip) bu IP'leri kullanır.
"""

import asyncio
import hashlib
import logging
import re
import struct
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger("origin-discovery")

# ============== Known CDN/Proxy IP Ranges ==============
# Cloudflare IP aralıkları (güncel tutulmalı)
CF_IPV4_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# Diğer bilinen CDN sağlayıcıları
KNOWN_CDN_HEADERS = [
    "cf-ray", "cf-cache-status",               # Cloudflare
    "x-served-by", "x-cache",                   # Fastly / Varnish
    "x-amz-cf-id", "x-amz-cf-pop",             # AWS CloudFront
    "x-azure-ref",                              # Azure CDN
    "server: cloudflare",                       # CF server header
    "server: AkamaiGHost",                      # Akamai
]

# Tipik origin port'ları (CDN bypass sonrası taranacak)
ORIGIN_SCAN_PORTS = [
    80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000,
    2083, 2087, 2096, 2053,  # cPanel / CF alternatif portlar
    4443, 9443,  # Atypik HTTPS portları
    22, 21, 25, 587, 993, 995,  # Servis portları
]


@dataclass
class OriginCandidate:
    """Bulunan potansiyel origin IP"""
    ip: str
    source: str           # Hangi teknikle bulundu
    confidence: int       # 0-100 güven skoru
    evidence: str         # Kanıt detayı
    ports_open: List[int] = field(default_factory=list)
    verified: bool = False


@dataclass
class OriginDiscoveryResult:
    """Origin discovery sonucu"""
    domain: str
    is_behind_cdn: bool
    cdn_provider: str
    candidates: List[OriginCandidate]
    best_candidate: Optional[OriginCandidate]
    techniques_used: List[str]
    techniques_failed: List[str]
    risk_assessment: str
    total_duration_seconds: float = 0


def _ip_in_range(ip: str, cidr: str) -> bool:
    """IP'nin CIDR aralığında olup olmadığını kontrol et"""
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        network, bits = cidr.split("/")
        net_int = struct.unpack("!I", socket.inet_aton(network))[0]
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
        return (ip_int & mask) == (net_int & mask)
    except Exception:
        return False


def is_cdn_ip(ip: str) -> bool:
    """IP'nin bilinen bir CDN aralığında olup olmadığını kontrol et"""
    for cidr in CF_IPV4_RANGES:
        if _ip_in_range(ip, cidr):
            return True
    return False


class OriginDiscovery:
    """
    Çoklu vektör origin IP keşif motoru.

    Kullanım:
        discovery = OriginDiscovery("example.com")
        result = await discovery.run()
        if result.best_candidate:
            print(f"Gerçek IP: {result.best_candidate.ip}")
    """

    def __init__(self, domain: str, timeout: int = 10):
        self.domain = domain.strip().lower()
        # www. varsa kaldır
        if self.domain.startswith("www."):
            self.domain = self.domain[4:]
        self.timeout = timeout
        self.candidates: List[OriginCandidate] = []
        self.techniques_used: List[str] = []
        self.techniques_failed: List[str] = []
        self._seen_ips: Set[str] = set()

    def _add_candidate(self, ip: str, source: str, confidence: int, evidence: str):
        """Aday IP ekle (duplicate kontrolü ile)"""
        if not ip or ip in self._seen_ips:
            # Aynı IP başka teknikten de geldiyse confidence'ı artır
            for c in self.candidates:
                if c.ip == ip:
                    c.confidence = min(100, c.confidence + 10)
                    c.evidence += f" | {source}: {evidence}"
            return
        if is_cdn_ip(ip):
            return  # CDN IP'lerini atla
        self._seen_ips.add(ip)
        self.candidates.append(OriginCandidate(
            ip=ip, source=source, confidence=confidence, evidence=evidence
        ))

    async def run(self) -> OriginDiscoveryResult:
        """Tüm teknikleri çalıştır ve sonuç döndür"""
        import time
        start = time.time()

        # Önce CDN arkasında mı kontrol et
        cdn_info = await self._check_cdn()
        is_behind_cdn = cdn_info["is_cdn"]
        cdn_provider = cdn_info["provider"]

        if not is_behind_cdn:
            # CDN arkasında değilse, direkt DNS IP'sini döndür
            dns_ips = cdn_info.get("ips", [])
            for ip in dns_ips:
                self._add_candidate(ip, "direct_dns", 95, "Domain CDN arkasında değil, direkt IP")

            return OriginDiscoveryResult(
                domain=self.domain,
                is_behind_cdn=False,
                cdn_provider="none",
                candidates=self.candidates,
                best_candidate=self.candidates[0] if self.candidates else None,
                techniques_used=["cdn_check"],
                techniques_failed=[],
                risk_assessment="Domain CDN arkasında değil - IP doğrudan erişilebilir",
                total_duration_seconds=time.time() - start,
            )

        # CDN arkasındaysa tüm teknikleri paralel çalıştır
        techniques = [
            ("crt_sh", self._technique_crt_sh()),
            ("dns_history", self._technique_dns_records()),
            ("mx_records", self._technique_mx_records()),
            ("spf_records", self._technique_spf_records()),
            ("ipv6_check", self._technique_ipv6_check()),
            ("http_headers", self._technique_http_headers()),
            ("favicon_hash", self._technique_favicon_hash()),
            ("common_subdomains", self._technique_common_subdomains()),
        ]

        results = await asyncio.gather(
            *[t[1] for t in techniques],
            return_exceptions=True,
        )

        for (name, _), result in zip(techniques, results):
            if isinstance(result, Exception):
                self.techniques_failed.append(f"{name}: {str(result)[:80]}")
                logger.debug(f"Technique failed: {name} -> {result}")
            else:
                self.techniques_used.append(name)

        # Adayları doğrula (en yüksek confidence'lıları)
        top_candidates = sorted(self.candidates, key=lambda c: c.confidence, reverse=True)[:5]
        if top_candidates:
            await self._verify_candidates(top_candidates)

        # En iyi adayı seç
        verified = [c for c in self.candidates if c.verified]
        best = None
        if verified:
            best = max(verified, key=lambda c: c.confidence)
        elif self.candidates:
            best = max(self.candidates, key=lambda c: c.confidence)

        # Risk değerlendirmesi
        risk = self._assess_risk(is_behind_cdn, best)

        return OriginDiscoveryResult(
            domain=self.domain,
            is_behind_cdn=is_behind_cdn,
            cdn_provider=cdn_provider,
            candidates=sorted(self.candidates, key=lambda c: c.confidence, reverse=True),
            best_candidate=best,
            techniques_used=self.techniques_used,
            techniques_failed=self.techniques_failed,
            risk_assessment=risk,
            total_duration_seconds=time.time() - start,
        )

    # ============ CDN Detection ============

    async def _check_cdn(self) -> dict:
        """Domain'in CDN arkasında olup olmadığını kontrol et"""
        result = {"is_cdn": False, "provider": "none", "ips": []}

        try:
            # DNS çözümleme
            loop = asyncio.get_event_loop()
            ips = await loop.run_in_executor(None, lambda: socket.getaddrinfo(
                self.domain, None, socket.AF_INET
            ))
            ip_list = list(set(addr[4][0] for addr in ips))
            result["ips"] = ip_list

            # IP'ler CF aralığında mı?
            for ip in ip_list:
                if is_cdn_ip(ip):
                    result["is_cdn"] = True
                    result["provider"] = "cloudflare"
                    break

            if not result["is_cdn"]:
                # HTTP header kontrolü
                async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                    try:
                        resp = await client.get(f"https://{self.domain}", timeout=self.timeout)
                        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

                        if "cf-ray" in headers_lower or headers_lower.get("server", "") == "cloudflare":
                            result["is_cdn"] = True
                            result["provider"] = "cloudflare"
                        elif "x-served-by" in headers_lower:
                            result["is_cdn"] = True
                            result["provider"] = "fastly"
                        elif "x-amz-cf-id" in headers_lower:
                            result["is_cdn"] = True
                            result["provider"] = "aws_cloudfront"
                        elif "x-azure-ref" in headers_lower:
                            result["is_cdn"] = True
                            result["provider"] = "azure_cdn"
                        elif headers_lower.get("server", "").startswith("akamaighost"):
                            result["is_cdn"] = True
                            result["provider"] = "akamai"
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"CDN check error: {e}")

        return result

    # ============ Technique 1: Certificate Transparency ============

    async def _technique_crt_sh(self):
        """
        crt.sh'den SSL sertifika loglarını sorgular.
        Sertifika genellikle gerçek sunucudan alındığı için
        historical IP'ler ortaya çıkabilir.
        Ayrıca gizli subdomain'ler bulunur.
        """
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15.0,
            )
            if resp.status_code != 200:
                return

            entries = resp.json()
            subdomains: Set[str] = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{self.domain}") or line == self.domain:
                        subdomains.add(line)

            # Subdomain'leri DNS ile çöz ve CDN olmayan IP'leri bul
            for sub in list(subdomains)[:30]:  # İlk 30 subdomain
                try:
                    loop = asyncio.get_event_loop()
                    ips = await loop.run_in_executor(None, lambda s=sub: [
                        addr[4][0] for addr in socket.getaddrinfo(s, None, socket.AF_INET)
                    ])
                    for ip in set(ips):
                        if not is_cdn_ip(ip):
                            self._add_candidate(
                                ip, "crt_sh",
                                confidence=65,
                                evidence=f"CT log subdomain: {sub} -> {ip}",
                            )
                except Exception:
                    continue

    # ============ Technique 2: DNS Records ============

    async def _technique_dns_records(self):
        """
        Farklı DNS kayıt tiplerini kontrol et.
        A, AAAA, NS, TXT kayıtlarında bilgi sızıntısı olabilir.
        """
        import subprocess

        records_to_check = ["A", "AAAA", "NS", "TXT", "SOA"]
        loop = asyncio.get_event_loop()

        for rtype in records_to_check:
            try:
                result = await loop.run_in_executor(None, lambda rt=rtype: subprocess.run(
                    ["dig", "+short", self.domain, rt],
                    capture_output=True, text=True, timeout=5,
                ))
                output = result.stdout.strip()
                if not output:
                    continue

                if rtype in ("A", "AAAA"):
                    for line in output.split("\n"):
                        ip = line.strip()
                        if ip and not is_cdn_ip(ip):
                            self._add_candidate(
                                ip, "dns_records",
                                confidence=40,
                                evidence=f"DNS {rtype} record: {ip}",
                            )
                elif rtype == "SOA":
                    # SOA kaydından nameserver IP'si
                    parts = output.split()
                    if len(parts) >= 1:
                        ns = parts[0].rstrip(".")
                        try:
                            ns_ips = await loop.run_in_executor(None, lambda n=ns: [
                                addr[4][0] for addr in socket.getaddrinfo(n, None, socket.AF_INET)
                            ])
                            for ip in set(ns_ips):
                                if not is_cdn_ip(ip):
                                    self._add_candidate(
                                        ip, "dns_soa",
                                        confidence=25,
                                        evidence=f"SOA nameserver: {ns} -> {ip}",
                                    )
                        except Exception:
                            pass
                elif rtype == "TXT":
                    # TXT'te IP sızıntısı
                    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
                    for match in ip_pattern.finditer(output):
                        ip = match.group(1)
                        if not is_cdn_ip(ip):
                            self._add_candidate(
                                ip, "dns_txt",
                                confidence=35,
                                evidence=f"TXT record IP sızıntısı: {ip}",
                            )
            except Exception:
                continue

    # ============ Technique 3: MX Records ============

    async def _technique_mx_records(self):
        """
        MX kayıtlarından gerçek IP bulma.
        Mail sunucusu genellikle CDN arkasında değildir.
        Aynı sunucuda web + mail çalışıyorsa gerçek IP bulunur.
        """
        import subprocess

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, lambda: subprocess.run(
                ["dig", "+short", self.domain, "MX"],
                capture_output=True, text=True, timeout=5,
            ))
            mx_records = result.stdout.strip().split("\n")

            for record in mx_records:
                parts = record.strip().split()
                if len(parts) >= 2:
                    mx_host = parts[1].rstrip(".")

                    # Üçüncü parti mail servisi mi kontrol et
                    third_party = ["google", "outlook", "protonmail", "zoho",
                                   "mimecast", "barracuda", "forcepoint"]
                    if any(tp in mx_host.lower() for tp in third_party):
                        continue

                    # Kendi domain'inin MX'i ise gerçek IP olma ihtimali yüksek
                    if self.domain in mx_host or mx_host.endswith(f".{self.domain}"):
                        try:
                            mx_ips = await loop.run_in_executor(None, lambda h=mx_host: [
                                addr[4][0] for addr in socket.getaddrinfo(h, None, socket.AF_INET)
                            ])
                            for ip in set(mx_ips):
                                if not is_cdn_ip(ip):
                                    self._add_candidate(
                                        ip, "mx_records",
                                        confidence=75,
                                        evidence=f"MX record: {mx_host} -> {ip} (self-hosted mail)",
                                    )
                        except Exception:
                            pass
                    else:
                        # Farklı domain MX - yine de IP'yi al
                        try:
                            mx_ips = await loop.run_in_executor(None, lambda h=mx_host: [
                                addr[4][0] for addr in socket.getaddrinfo(h, None, socket.AF_INET)
                            ])
                            for ip in set(mx_ips):
                                if not is_cdn_ip(ip):
                                    self._add_candidate(
                                        ip, "mx_records",
                                        confidence=45,
                                        evidence=f"MX record: {mx_host} -> {ip}",
                                    )
                        except Exception:
                            pass
        except Exception:
            pass

    # ============ Technique 4: SPF Records ============

    async def _technique_spf_records(self):
        """
        SPF kaydından IP aralıkları çıkar.
        SPF'te 'ip4:x.x.x.x' şeklinde gerçek IP'ler olabilir.
        """
        import subprocess

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, lambda: subprocess.run(
                ["dig", "+short", self.domain, "TXT"],
                capture_output=True, text=True, timeout=5,
            ))

            for line in result.stdout.strip().split("\n"):
                line = line.strip().strip('"')
                if "v=spf1" not in line.lower():
                    continue

                # ip4: ve ip6: direktifleri
                ip4_pattern = re.compile(r'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d+)?')
                for match in ip4_pattern.finditer(line):
                    ip = match.group(1)
                    if not is_cdn_ip(ip):
                        self._add_candidate(
                            ip, "spf_records",
                            confidence=70,
                            evidence=f"SPF ip4 direktifi: {ip}",
                        )

                # include: içinden başka domain'lerin SPF'ini takip et
                include_pattern = re.compile(r'include:(\S+)')
                for match in include_pattern.finditer(line):
                    included = match.group(1)
                    # Ana domain'le ilişkili include ise
                    if self.domain in included:
                        try:
                            inc_result = await loop.run_in_executor(None, lambda d=included: subprocess.run(
                                ["dig", "+short", d, "TXT"],
                                capture_output=True, text=True, timeout=5,
                            ))
                            for inc_line in inc_result.stdout.strip().split("\n"):
                                for ip_match in ip4_pattern.finditer(inc_line):
                                    ip = ip_match.group(1)
                                    if not is_cdn_ip(ip):
                                        self._add_candidate(
                                            ip, "spf_include",
                                            confidence=60,
                                            evidence=f"SPF include ({included}): {ip}",
                                        )
                        except Exception:
                            pass

        except Exception:
            pass

    # ============ Technique 5: IPv6 Check ============

    async def _technique_ipv6_check(self):
        """
        IPv6 adresi kontrol et.
        Birçok site IPv4'ü CDN'e yönlendirirken IPv6'yı yapılandırmaz
        veya IPv6 doğrudan sunucuya işaret eder.
        """
        import subprocess

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, lambda: subprocess.run(
                ["dig", "+short", self.domain, "AAAA"],
                capture_output=True, text=True, timeout=5,
            ))
            ipv6_records = result.stdout.strip().split("\n")

            for ipv6 in ipv6_records:
                ipv6 = ipv6.strip()
                if not ipv6 or ":" not in ipv6:
                    continue

                # CF IPv6 aralıkları: 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2405:8100::/32
                cf_ipv6_prefixes = ["2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:"]
                is_cf_v6 = any(ipv6.startswith(prefix) for prefix in cf_ipv6_prefixes)

                if not is_cf_v6:
                    self._add_candidate(
                        ipv6, "ipv6_bypass",
                        confidence=55,
                        evidence=f"IPv6 CDN dışında: {ipv6}",
                    )

        except Exception:
            pass

    # ============ Technique 6: HTTP Header Leaks ============

    async def _technique_http_headers(self):
        """
        HTTP header'lardan bilgi sızıntısı kontrolü.
        CSP, CORS, Set-Cookie, Link header'larında
        origin IP veya internal hostname sızabilir.
        """
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            urls = [
                f"https://{self.domain}",
                f"http://{self.domain}",
                f"https://{self.domain}/robots.txt",
                f"https://{self.domain}/.well-known/security.txt",
            ]

            for url in urls:
                try:
                    resp = await client.get(url, timeout=self.timeout)
                    headers = dict(resp.headers)

                    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

                    # Tüm header'larda IP ara
                    for key, value in headers.items():
                        key_lower = key.lower()
                        # İlginç header'lar
                        interesting = [
                            "x-forwarded-for", "x-real-ip", "x-originating-ip",
                            "x-remote-addr", "x-host", "x-backend",
                            "content-security-policy", "access-control-allow-origin",
                            "link", "location",
                        ]
                        if key_lower in interesting or "origin" in key_lower or "backend" in key_lower:
                            for match in ip_pattern.finditer(value):
                                ip = match.group(1)
                                if not is_cdn_ip(ip) and not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168."):
                                    self._add_candidate(
                                        ip, "http_headers",
                                        confidence=80,
                                        evidence=f"Header sızıntısı: {key}: {ip} (URL: {url})",
                                    )

                    # Body'de IP aranması (hata sayfaları, debug bilgisi)
                    body = resp.text[:5000]
                    for match in ip_pattern.finditer(body):
                        ip = match.group(1)
                        if (not is_cdn_ip(ip) and not ip.startswith("127.")
                                and not ip.startswith("10.") and not ip.startswith("192.168.")
                                and not ip.startswith("0.")):
                            self._add_candidate(
                                ip, "http_body_leak",
                                confidence=30,
                                evidence=f"Sayfa gövdesinde IP: {ip} (URL: {url})",
                            )

                except Exception:
                    continue

    # ============ Technique 7: Favicon Hash ============

    async def _technique_favicon_hash(self):
        """
        Favicon hash ile Shodan eşleştirme.
        Aynı favicon hash'ine sahip IP'ler gerçek origin olabilir.
        (Not: Shodan API anahtarı gerektirir, yoksa sadece hash hesaplar)
        """
        import os
        import mmh3
        import codecs

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            favicon_urls = [
                f"https://{self.domain}/favicon.ico",
                f"http://{self.domain}/favicon.ico",
            ]

            for url in favicon_urls:
                try:
                    resp = await client.get(url, timeout=self.timeout)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        # Shodan favicon hash formatı
                        favicon_b64 = codecs.encode(resp.content, "base64")
                        fav_hash = mmh3.hash(favicon_b64)

                        # Shodan API ile sorgu (OSINT service üzerinden)
                        osint_url = os.getenv("OSINT_SERVICE_URL", "http://osint-service:8005")
                        try:
                            shodan_resp = await client.post(
                                f"{osint_url}/lookup/shodan",
                                json={"query": f"http.favicon.hash:{fav_hash}"},
                                timeout=15.0,
                            )
                            if shodan_resp.status_code == 200:
                                shodan_data = shodan_resp.json()
                                matches = shodan_data.get("matches", shodan_data.get("data", []))
                                if isinstance(matches, list):
                                    for match in matches[:10]:
                                        ip = match.get("ip_str", match.get("ip", ""))
                                        if ip and not is_cdn_ip(ip):
                                            self._add_candidate(
                                                ip, "favicon_hash",
                                                confidence=70,
                                                evidence=f"Shodan favicon hash eşleşmesi: hash={fav_hash}, IP={ip}",
                                            )
                        except Exception:
                            # Shodan API yoksa sadece hash'i logla
                            logger.info(f"Favicon hash: {fav_hash} (Shodan sorgusu başarısız)")
                        break
                except Exception:
                    continue

    # ============ Technique 8: Common Subdomains ============

    async def _technique_common_subdomains(self):
        """
        Yaygın subdomain'leri kontrol et.
        mail., ftp., cpanel., webmail., direct., origin. gibi
        subdomain'ler genellikle CDN arkasında değildir.
        """
        common_subs = [
            "mail", "webmail", "ftp", "cpanel", "whm", "direct",
            "origin", "server", "host", "ns1", "ns2",
            "smtp", "pop", "imap", "mx", "relay",
            "dev", "staging", "stage", "test", "beta",
            "api", "backend", "admin", "panel",
            "vpn", "remote", "ssh", "rdp",
            "db", "database", "mysql", "postgres",
            "old", "legacy", "backup", "bak",
            "monitor", "status", "grafana", "kibana",
        ]

        loop = asyncio.get_event_loop()
        tasks = []

        sem = asyncio.Semaphore(20)  # Aynı anda max 20 DNS sorgusu

        async def check_sub(sub: str):
            async with sem:
                fqdn = f"{sub}.{self.domain}"
                try:
                    ips = await loop.run_in_executor(None, lambda f=fqdn: [
                        addr[4][0] for addr in socket.getaddrinfo(f, None, socket.AF_INET)
                    ])
                    for ip in set(ips):
                        if not is_cdn_ip(ip):
                            # Yüksek güven subdomain'ler
                            high_conf = ["mail", "ftp", "cpanel", "direct", "origin",
                                         "server", "smtp", "vpn", "old"]
                            conf = 75 if sub in high_conf else 50
                            self._add_candidate(
                                ip, "common_subdomains",
                                confidence=conf,
                                evidence=f"Subdomain: {fqdn} -> {ip} (CDN dışı)",
                            )
                except Exception:
                    pass

        await asyncio.gather(*[check_sub(s) for s in common_subs])

    # ============ Verification ============

    async def _verify_candidates(self, candidates: List[OriginCandidate]):
        """
        Aday IP'lerin gerçekten hedef domain'in sunucusu olduğunu doğrula.
        IP'ye direkt HTTP isteği atarak aynı sitenin döndüğünü kontrol et.
        """
        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            for candidate in candidates:
                try:
                    # IP'ye direkt HTTP isteği (Host header ile)
                    resp = await client.get(
                        f"https://{candidate.ip}",
                        headers={"Host": self.domain},
                        timeout=self.timeout,
                    )

                    # Yanıt geldi = port açık
                    candidate.ports_open.append(443)

                    # Domain ile eşleşme kontrolü
                    body = resp.text[:2000].lower()
                    if (self.domain in body or
                            resp.status_code in (200, 301, 302, 403) and len(resp.text) > 100):
                        candidate.verified = True
                        candidate.confidence = min(100, candidate.confidence + 20)
                        candidate.evidence += " | ✅ HTTP doğrulama başarılı"

                except Exception:
                    # HTTPS başarısız, HTTP dene
                    try:
                        resp = await client.get(
                            f"http://{candidate.ip}",
                            headers={"Host": self.domain},
                            timeout=self.timeout,
                        )
                        candidate.ports_open.append(80)
                        if self.domain in resp.text[:2000].lower():
                            candidate.verified = True
                            candidate.confidence = min(100, candidate.confidence + 15)
                            candidate.evidence += " | ✅ HTTP doğrulama başarılı (80)"
                    except Exception:
                        pass

    # ============ Risk Assessment ============

    def _assess_risk(self, is_behind_cdn: bool, best: Optional[OriginCandidate]) -> str:
        """Risk değerlendirmesi oluştur"""
        if not is_behind_cdn:
            return (
                "⚠️ KRİTİK: Domain CDN/WAF koruması altında değil. "
                "Gerçek IP doğrudan erişilebilir. "
                "DDoS ve direkt saldırılara açık."
            )

        if best and best.verified:
            return (
                f"🔴 YÜKSEK RİSK: CDN ({self._get_cdn_name()}) arkasındaki gerçek IP bulundu: {best.ip}. "
                f"Teknik: {best.source}. Güven: %{best.confidence}. "
                f"Saldırgan bu IP üzerinden CDN'i bypass edebilir. "
                f"ÖNERİ: Firewall'da sadece CDN IP aralıklarına izin verin, "
                f"gerçek IP üzerinden gelen trafiği engelleyin."
            )

        if best and best.confidence >= 60:
            return (
                f"🟠 ORTA RİSK: Potansiyel gerçek IP tespit edildi: {best.ip}. "
                f"Güven: %{best.confidence}. HTTP doğrulama yapılamadı. "
                f"ÖNERİ: IP'nin gerçek sunucu olduğunu manuel doğrulayın."
            )

        if self.candidates:
            return (
                f"🟡 DÜŞÜK RİSK: {len(self.candidates)} aday IP bulundu, "
                f"ancak yüksek güvenle doğrulanamadı. "
                f"CDN koruması muhtemelen iyi yapılandırılmış."
            )

        return (
            "🟢 İYİ: CDN arkasından gerçek IP bulunamadı. "
            "CDN/WAF koruması düzgün yapılandırılmış görünüyor."
        )

    def _get_cdn_name(self) -> str:
        return "Cloudflare"  # Genişletilebilir

    # ============ Serialization ============

    def to_dict(self, result: OriginDiscoveryResult) -> dict:
        """Sonucu JSON-serileştirilebilir dict'e dönüştür"""
        return {
            "domain": result.domain,
            "is_behind_cdn": result.is_behind_cdn,
            "cdn_provider": result.cdn_provider,
            "candidates": [
                {
                    "ip": c.ip,
                    "source": c.source,
                    "confidence": c.confidence,
                    "evidence": c.evidence,
                    "ports_open": c.ports_open,
                    "verified": c.verified,
                }
                for c in result.candidates
            ],
            "best_candidate": {
                "ip": result.best_candidate.ip,
                "source": result.best_candidate.source,
                "confidence": result.best_candidate.confidence,
                "evidence": result.best_candidate.evidence,
                "verified": result.best_candidate.verified,
            } if result.best_candidate else None,
            "techniques_used": result.techniques_used,
            "techniques_failed": result.techniques_failed,
            "risk_assessment": result.risk_assessment,
            "total_duration_seconds": result.total_duration_seconds,
            "total_candidates": len(result.candidates),
        }


# ============ Standalone Test ============

if __name__ == "__main__":
    import sys

    async def main():
        target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
        print(f"🎯 Origin Discovery: {target}")
        print("=" * 60)

        discovery = OriginDiscovery(target)
        result = await discovery.run()

        print(f"\n📊 Sonuç:")
        print(f"  CDN: {result.cdn_provider}")
        print(f"  Aday sayısı: {len(result.candidates)}")
        print(f"  Kullanılan teknikler: {', '.join(result.techniques_used)}")
        if result.best_candidate:
            print(f"  🎯 En iyi aday: {result.best_candidate.ip} "
                  f"(güven: %{result.best_candidate.confidence}, "
                  f"teknik: {result.best_candidate.source})")
        print(f"\n{result.risk_assessment}")

    asyncio.run(main())
