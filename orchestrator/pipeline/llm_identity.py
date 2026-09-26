"""
Kadim Güvenlik — LLM Son-Çare Kimlik Çıkarımı (Tier 3: uzun kuyruk)
==================================================================
Türkçe: Kimlik çözümleyicinin 3. katmanı. Tier 1 (yerel tablo) + Tier 2 (nmap/Shodan CPE)
hedefi tanıyamadığında devreye girer. Fikir: pfSense, RKE2, hatta niş "Spective" gibi
ürünleri LLM ZATEN bilir (interneti okudu) — biz elle imza yazmak yerine HAM KANITI (header,
banner, title, port, servis) LLM'e verip "bu nedir?" diye soruyoruz. Çıktı bir HİPOTEZDİR →
düşük güvenle profile işlenir (deterministik CPE/tablo baskın kalır) ve asla tahribata yol
açmaz (yalnız KİMLİK/çerçeve; doktrin: LLM önerir, deterministik çekirdek karar verir).

Bu modül SAF'tır (I/O yok): prompt üretir, ham cevabı SIKI parse eder, target_profile
`extra` sinyallerine çevirir. LLM CPE döndürürse cpe_intel ile AYNI normalizasyondan geçer
(tek doğruluk kaynağı), ama güven LLM olduğu için DÜŞÜRÜLÜR. Kanıt saldırgan-kontrollüdür
(header/body) → prompt-injection'a karşı her alan sanitize edilir.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .cpe_intel import cpe_to_signals, os_string_to_signal


IDENTITY_SYSTEM = (
    "Sen bir sistem/servis parmak-izi (fingerprint) uzmanısın. Sana bir hedefin HAM kanıtı "
    "verilir (HTTP header, banner, sayfa başlığı, açık portlar, servis sürümleri). Görevin: "
    "bu sistemde HANGİ ürün/yığın çalıştığını ve rolünü SÖYLEMEK.\n\n"
    "SADECE şu JSON şemasıyla cevap ver, başka metin yazma:\n"
    '{"products":[{"name":"pfSense","cpe":"cpe:2.3:a:netgate:pfsense:2.7:*:*:*:*:*:*:*",'
    '"confidence":0.0-1.0}], "os":"ubuntu|debian|windows|...", '
    '"role":"web-app|server|firewall|appliance|load-balancer|gateway|database|unknown", '
    '"why":"kısa gerekçe"}\n'
    "KURALLAR: yalnız kanıtın DESTEKLEDİĞİ ürünü yaz; emin değilsen products BOŞ bırak. "
    "cpe alanını biliyorsan doldur (CPE 2.3), bilmiyorsan atla. CVE UYDURMA, sürüm UYDURMA. "
    "role'ü kanıta göre seç (yönetim paneli/blok sayfası → firewall/appliance; sadece SSH+OS "
    "→ server; web uygulaması → web-app). Bu bir TAHMİN; abartma, temkinli ol."
)


@dataclass
class IdentityResult:
    products: List[Dict[str, Any]] = field(default_factory=list)  # [{name, cpe?, confidence}]
    os: Optional[str] = None
    role: Optional[str] = None
    why: str = ""


# ---- prompt-injection kalkanı (kanıt saldırgan-kontrollü) ----
def _san(text: Any, limit: int = 240) -> str:
    s = str(text) if text is not None else ""
    for ch in ("\n", "\r", "`", "\x00"):
        s = s.replace(ch, " ")
    s = re.sub(r"(?i)\b(ignore|disregard|forget)\b[^.]{0,40}\b(above|previous|instruction|prompt|system)\b",
               "[filtrelenmis]", s)
    s = s.strip()
    return s[:limit]


def build_identity_prompt(evidence: Dict[str, Any]) -> str:
    """Ham kanıttan (sanitize edilmiş) kimlik sorusu prompt'u üret (SAF)."""
    lines = ["# HEDEF KANITI — bu sistem nedir?", ""]
    title = evidence.get("title")
    if title:
        lines.append(f"Sayfa başlığı: {_san(title, 160)}")
    headers = evidence.get("headers") or {}
    if headers:
        lines.append("HTTP header'ları:")
        for k, v in list(headers.items())[:20]:
            lines.append(f"  {_san(k, 40)}: {_san(v, 120)}")
    cookies = evidence.get("cookies") or []
    if cookies:
        lines.append(f"Çerez adları: {', '.join(_san(c, 40) for c in cookies[:12])}")
    services = evidence.get("services") or []
    if services:
        lines.append("Açık servisler (port/servis ürün sürüm):")
        for s in services[:25]:
            lines.append(f"  {_san(s, 80)}")
    ports = evidence.get("ports") or []
    if ports:
        lines.append(f"Açık portlar: {', '.join(str(int(p)) for p in ports[:40] if str(p).strip().isdigit())}")
    body = evidence.get("body_snippet")
    if body:
        lines.append(f"Sayfa gövdesi (parça): {_san(body, 700)}")
    lines.append("")
    lines.append("Şemaya UYGUN JSON ver. Kanıt zayıfsa products boş bırak.")
    return "\n".join(lines)


def _coerce_conf(v: Any, default: float = 0.5) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, f))


def parse_identity(raw: Any) -> Optional[IdentityResult]:
    """LLM ham cevabını SIKI parse et (SAF). Geçersiz → None. Markdown fence soyulur."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = re.sub(r"^```(?:json)?\s*", "", raw.strip())
    s = re.sub(r"\s*```$", "", s).strip()
    # İlk dengeli { .. } nesnesini al (danışma parser'ıyla aynı temkin).
    start = s.find("{")
    if start < 0:
        return None
    try:
        obj = json.loads(s[start:])
    except Exception:
        # kaba onarım: son } ye kadar
        end = s.rfind("}")
        if end <= start:
            return None
        try:
            obj = json.loads(s[start:end + 1])
        except Exception:
            return None
    if not isinstance(obj, dict):
        return None
    products: List[Dict[str, Any]] = []
    for p in (obj.get("products") or [])[:10]:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip()[:80]
        if not name:
            continue
        item: Dict[str, Any] = {"name": name, "confidence": _coerce_conf(p.get("confidence"))}
        cpe = p.get("cpe")
        if isinstance(cpe, str) and cpe.lower().startswith("cpe:"):
            item["cpe"] = cpe.strip()[:200]
        products.append(item)
    os_v = obj.get("os")
    os_v = str(os_v).strip()[:40] if os_v else None
    role = obj.get("role")
    role = str(role).strip().lower()[:30] if role else None
    why = str(obj.get("why") or "").strip()[:200]
    if not products and not os_v and not role:
        return None
    return IdentityResult(products=products, os=os_v, role=role, why=why)


# LLM kimlik güven TAVANI. 0.6 = has_web_signal/servis eşiğine TAM yeter (LLM "web/apache"
# derse motor buna göre davransın) ama deterministik CPE/tablo (0.75+) baskın kalsın diye
# onun ALTINDA. Yani LLM boşluğu doldurur, çeliştiğinde deterministik kazanır.
_LLM_MAX_WEIGHT = 0.6
_DEFENSE_ROLES = {"firewall", "appliance", "waf", "ips", "ids", "load-balancer",
                  "loadbalancer", "gateway", "proxy"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9_.\-]", "", (s or "").lower())


def identity_to_signals(result: IdentityResult) -> Tuple[List[Tuple[str, str, float, str]], List[str]]:
    """IdentityResult → target_profile `extra` sinyalleri (DÜŞÜK güven) + ürün listesi.
    LLM CPE verirse cpe_intel ile aynı normalizasyondan geçer ama ağırlık _LLM_MAX_WEIGHT'e
    kırpılır (deterministik kaynak baskın). CPE yoksa os/role kaba ipuçlarına düşer."""
    extra: List[Tuple[str, str, float, str]] = []
    products_out: List[str] = []
    cpes: List[str] = []
    for p in result.products:
        products_out.append(f"{p['name']} (LLM~{p.get('confidence', 0.5):.0%})")
        if p.get("cpe"):
            cpes.append(p["cpe"])
    if cpes:
        cpe_sig, _ = cpe_to_signals(cpes)
        for (d, v, w, e) in cpe_sig:
            extra.append((d, v, min(_LLM_MAX_WEIGHT, w), f"llm:{e}"))
    if result.os:
        os_sig = os_string_to_signal(result.os)
        if os_sig:
            extra.append((os_sig[0], os_sig[1], _LLM_MAX_WEIGHT, f"llm-os:{_san(result.os, 30)}"))
    if result.role in _DEFENSE_ROLES:
        label = _norm(result.products[0]["name"]) if result.products else result.role
        extra.append(("waf", label or result.role, _LLM_MAX_WEIGHT, f"llm-role:{result.role}"))
    return extra, products_out
