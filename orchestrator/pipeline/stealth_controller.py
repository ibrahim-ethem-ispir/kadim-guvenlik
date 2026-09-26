"""
Kadim Güvenlik — APT Stealth & Adaptive WAF Jitter Controller
==============================================================
Türkçe: Akamai Kona, Cloudflare Enterprise, Imperva, F5 BIG-IP ASM gibi
kurumsal bankacılık WAF ve SOC sistemlerine yakalanmadan tarama yürütebilmek
için dinamik gecikme (jitter), başlık maskeleme ve hız denetimi sağlayan motor.

Doktrin:
1. GÜRÜLTÜSÜZ KUŞATMA: WAF tespit edildiğinde veya kurumsal banka profili devredeyse
   istekler arası dinamik matematiksel gecikme (adaptive jitter) enjekte edilir.
2. GERÇEK TARAYICI MASKELEMESİ (Browser Impersonation): Standart Python-httpx
   imzaları yerine modern tarayıcıların Sec-Ch-Ua ve Accept başlıkları rotasyona sokulur.
3. TAHRİBATSIZ: Tarayıcıyı durdurmaz, sadece tempo verir.
"""

import asyncio
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("stealth-controller")

# Bankacılık / Kurumsal WAF listesi
ENTERPRISE_WAF_VENDORS = {
    "akamai", "imperva", "cloudflare", "f5_asm", "fortiweb", "fortiguard", "aws_waf"
}

_BROWSER_PROFILES = [
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "platform": '"Windows"',
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "platform": '"macOS"',
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "sec_ch_ua": None,
        "platform": '"Windows"',
    },
]


class StealthController:
    """APT gizlilik ve adaptif gecikme yöneticisi."""

    def __init__(
        self,
        waf_vendor: Optional[str] = None,
        min_delay_s: float = 0.5,
        max_delay_s: float = 2.0,
        forced_stealth: bool = False,
    ):
        self.waf_vendor = (waf_vendor or "").lower()
        self.min_delay_s = min_delay_s
        self.max_delay_s = max_delay_s
        self.forced_stealth = forced_stealth

        # WAF kurumsal bir vendor ise otomatik olarak aktifleşir
        self.is_active = forced_stealth or (self.waf_vendor in ENTERPRISE_WAF_VENDORS)
        self.total_paced_requests = 0
        self.total_delay_time = 0.0

    def update_waf_vendor(self, vendor: str, blocked_probe: bool = False):
        """Tarama sırasında WAF parmak izi keşfedilirse durumu günceller."""
        if not vendor:
            return
        self.waf_vendor = vendor.lower()
        if self.waf_vendor in ENTERPRISE_WAF_VENDORS or blocked_probe:
            self.is_active = True
            logger.info(f"🛡️ APT Stealth Controller aktifleşti: WAF={self.waf_vendor} (blocked={blocked_probe})")

    def get_stealth_headers(self, base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Gerçek tarayıcı başlıkları üretir / zenginleştirir."""
        headers = dict(base_headers or {})
        profile = random.choice(_BROWSER_PROFILES)

        headers["User-Agent"] = profile["user_agent"]
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        headers["Accept-Language"] = "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "same-origin"
        headers["Sec-Fetch-User"] = "?1"
        headers["Upgrade-Insecure-Requests"] = "1"

        if profile["sec_ch_ua"]:
            headers["Sec-Ch-Ua"] = profile["sec_ch_ua"]
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = profile["platform"]

        return headers

    def compute_jitter(self) -> float:
        """İki istek arasında beklemesi gereken rastgele gecikme süresini hesaplar."""
        if not self.is_active:
            return 0.0
        # Düzgün dağılım + mikro varyasyon (insan davranışı)
        delay = random.uniform(self.min_delay_s, self.max_delay_s)
        return round(delay, 3)

    async def pace(self) -> float:
        """Gerekiyorsa asenkron olarak bekler ve beklenen süreyi döner."""
        delay = self.compute_jitter()
        if delay > 0:
            self.total_paced_requests += 1
            self.total_delay_time += delay
            await asyncio.sleep(delay)
        return delay

    def summary(self) -> Dict[str, Any]:
        """Operatör ve rapor için gizlilik metrikleri."""
        return {
            "stealth_active": self.is_active,
            "waf_vendor": self.waf_vendor or "none",
            "jitter_range": f"{self.min_delay_s}s - {self.max_delay_s}s" if self.is_active else "disabled",
            "total_paced_requests": self.total_paced_requests,
            "total_delay_seconds": round(self.total_delay_time, 2),
        }
