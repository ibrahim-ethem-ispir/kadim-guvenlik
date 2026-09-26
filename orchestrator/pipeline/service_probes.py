"""
Kadim Güvenlik — Servis-Özel Aktif Derin-Dalış (Faz 3, APT)
============================================================
Türkçe: nmap açık portları bulur ama mail/DNS yüzeyi hiç sömürülmezdi. Gerçek bir APT
her servisi kimlik+zayıflık için yoklar. Bu modül mail (SMTP/IMAP/POP3) ve DNS servisleri
için DETERMİNİSTİK, TAHRİBATSIZ (yalnız-okuma) kontroller yapar:

  SMTP: banner/sürüm, STARTTLS var mı (cleartext kimlik riski), VRFY/EXPN (kullanıcı enum)
  DNS:  AXFR zone-transfer açık mı (misconfig — tüm kayıtlar sızar), version.bind

Hiçbir e-posta GÖNDERİLMEZ, hiçbir kayıt DEĞİŞTİRİLMEZ — yalnız yetenek/yapılandırma okuması.
Tasarım: SAF analiz çekirdeği (analyze_*) + ince I/O katmanı (probe_*). İzole test edilebilir
(test_service_probes.py). Bulgular confidence_tier taşır → FP sistemine oturur.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("service-probes")


# ============================================================
# SAF analiz çekirdeği (I/O yok — TDD)
# ============================================================

def analyze_smtp(banner: str, ehlo_caps: List[str], *, host: str = "", port: Any = 25) -> List[Dict[str, Any]]:
    """SMTP banner + EHLO yeteneklerinden zafiyet/yapılandırma bulgularını türet (SAF).

    Kural: STARTTLS yoksa → cleartext kimlik riski (medium, confirmed — deterministik gözlem);
    VRFY/EXPN varsa → kullanıcı enumerasyonu (low, confirmed); banner sürüm ifşası (info)."""
    findings: List[Dict[str, Any]] = []
    tgt = f"{host}:{port}" if host else str(port)
    caps_up = {c.upper() for c in ehlo_caps}
    banner = (banner or "").strip()

    # STARTTLS yok → cleartext kimlik doğrulama mümkün (MITM ile kimlik çalınabilir)
    if ehlo_caps and "STARTTLS" not in caps_up:
        findings.append({
            "title": f"SMTP STARTTLS yok — cleartext kimlik riski @ {tgt}",
            "severity": "medium", "confidence_tier": "confirmed",
            "proof": f"EHLO yanıtı STARTTLS yeteneği İÇERMİYOR (yetenekler: {', '.join(sorted(caps_up)) or 'yok'}). "
                     f"Kimlik doğrulama düz metin taşınabilir; ağ dinleyicisi kimlik çalabilir.",
            "cwe": ["CWE-319"], "mitre": "T1040",
        })
    # VRFY / EXPN → kullanıcı hesabı enumerasyonu (oltalama/spray ön koşulu)
    if "VRFY" in caps_up or "EXPN" in caps_up:
        findings.append({
            "title": f"SMTP VRFY/EXPN açık — kullanıcı enumerasyonu @ {tgt}",
            "severity": "low", "confidence_tier": "confirmed",
            "proof": f"EHLO {'VRFY' if 'VRFY' in caps_up else 'EXPN'} yeteneğini duyuruyor — "
                     f"geçerli kullanıcı hesapları enumerasyonu mümkün (oltalama/parola-spray hedefi).",
            "cwe": ["CWE-200"], "mitre": "T1087",
        })
    # Banner sürüm ifşası (aday — cve_intel derinleştirir)
    if banner:
        soft = banner.split("ESMTP")[0].strip() if "ESMTP" in banner else banner
        findings.append({
            "title": f"SMTP banner sürüm ifşası @ {tgt}",
            "severity": "info", "confidence_tier": "unconfirmed",
            "proof": f"SMTP banner: {banner[:200]}",
            "cwe": ["CWE-200"], "mitre": "T1592",
        })
    return findings


def analyze_dns(axfr_records: Optional[List[str]], version_bind: Optional[str],
                *, host: str = "", port: Any = 53) -> List[Dict[str, Any]]:
    """DNS AXFR + version.bind sonuçlarından bulgu türet (SAF).

    AXFR kayıt döndüyse → zone-transfer AÇIK (yüksek; tüm iç DNS kayıtları sızar, keşif
    altın madeni). version.bind → sürüm ifşası (info/aday)."""
    findings: List[Dict[str, Any]] = []
    tgt = f"{host}:{port}" if host else str(port)
    if axfr_records:
        findings.append({
            "title": f"DNS zone-transfer (AXFR) açık @ {tgt}",
            "severity": "high", "confidence_tier": "confirmed",
            "proof": f"AXFR başarılı — {len(axfr_records)} kayıt sızdı (ilk örnekler: "
                     f"{', '.join(str(r)[:60] for r in axfr_records[:5])}). Tüm iç DNS haritası "
                     f"ifşa; APT keşfi için altyapı haritası. Yapılandırma hatası (allow-transfer).",
            "cwe": ["CWE-200"], "mitre": "T1590.002",
        })
    if version_bind:
        findings.append({
            "title": f"DNS sürüm ifşası (version.bind) @ {tgt}",
            "severity": "info", "confidence_tier": "unconfirmed",
            "proof": f"version.bind CHAOS TXT: {str(version_bind)[:120]} — sürümden bilinen "
                     f"CVE'ler türetilebilir.",
            "cwe": ["CWE-200"], "mitre": "T1592",
        })
    return findings


# ============================================================
# I/O katmanı (ince — soket/dnspython)
# ============================================================

async def probe_smtp(host: str, port: int, *, timeout: float = 8.0) -> Dict[str, Any]:
    """SMTP servisine bağlan, banner + EHLO yeteneklerini oku (TAHRİBATSIZ — yalnız EHLO/QUIT).
    Hiçbir mail gönderilmez. Hata → boş findings."""
    banner, caps = "", []
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            banner = (await asyncio.wait_for(reader.readline(), timeout=timeout)).decode("utf-8", "replace").strip()
            writer.write(b"EHLO kadim-scanner.local\r\n")
            await writer.drain()
            # 250- çok satırlı yanıtı topla
            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if not line:
                    break
                text = line.decode("utf-8", "replace").strip()
                # "250-STARTTLS" / "250 SIZE ..." → yetenek adını çıkar
                if text[:3].isdigit():
                    cap = text[4:].split()[0] if len(text) > 4 and text[4:].strip() else ""
                    if cap:
                        caps.append(cap)
                    if text[3:4] == " ":  # son satır (250␠)
                        break
            try:
                writer.write(b"QUIT\r\n"); await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"SMTP probe hatası ({host}:{port}): {e}")
        return {"findings": []}
    return {"banner": banner, "ehlo": caps,
            "findings": analyze_smtp(banner, caps, host=host, port=port)}


async def probe_dns(host: str, domain: str, port: int = 53, *, timeout: float = 8.0) -> Dict[str, Any]:
    """DNS: AXFR zone-transfer denemesi + version.bind (dnspython, thread'de — sync API).
    AXFR yalnız OKUMA; hiçbir kayıt değiştirilmez. Hata/red → boş."""
    def _sync() -> Dict[str, Any]:
        records: List[str] = []
        version_bind: Optional[str] = None
        try:
            import dns.query, dns.zone, dns.resolver, dns.rdataclass, dns.rdatatype, dns.message
            # 1) AXFR — domain zorunlu (host'un yetkili olduğu zone)
            if domain:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(host, domain, timeout=timeout, port=port))
                    for name, node in list(z.nodes.items())[:200]:
                        records.append(f"{name} {node.to_text(name)[:80]}")
                except Exception:
                    records = []
            # 2) version.bind CHAOS TXT
            try:
                q = dns.message.make_query("version.bind", dns.rdatatype.TXT, dns.rdataclass.CH)
                r = dns.query.udp(q, host, timeout=timeout, port=port)
                for ans in r.answer:
                    version_bind = ans.to_text()
                    break
            except Exception:
                version_bind = None
        except Exception as e:
            logger.debug(f"DNS probe import/exec hatası: {e}")
        return {"records": records, "version_bind": version_bind}

    try:
        res = await asyncio.to_thread(_sync)
    except Exception as e:
        logger.debug(f"DNS probe hatası ({host}): {e}")
        return {"findings": []}
    return {"axfr_records": res["records"], "version_bind": res["version_bind"],
            "findings": analyze_dns(res["records"], res["version_bind"], host=host, port=port)}
