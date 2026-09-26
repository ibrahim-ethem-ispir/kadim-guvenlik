"""
🔍 NVD CVE Lookup - Servis versiyonlarını CVE ile eşleştir
Türkçe: Ücretsiz NVD API kullanarak CVE araması

API Limitleri:
- Anonim: 5 istek / 30 saniye
- API Key ile: 50 istek / 30 saniye

Kullanım:
```python
from cve_lookup import lookup_cves, lookup_cves_for_product

# Tek ürün araması
cves = await lookup_cves("apache", "2.4.49")

# Birden fazla servis için
services = [{"product": "OpenSSH", "version": "7.4"}]
results = await lookup_cves_for_services(services)
```
"""

import os
import asyncio
import httpx
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # Opsiyonel, rate limit artırır

# Rate limiting
_last_request_time: Optional[datetime] = None
_request_count = 0
_rate_limit_window = timedelta(seconds=30)
_max_requests_per_window = 5 if not NVD_API_KEY else 50


@dataclass
class CVEInfo:
    """CVE bilgisi"""
    cve_id: str
    description: str
    severity: str = "unknown"
    cvss_score: float = 0.0
    cvss_version: str = ""
    published_date: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "published_date": self.published_date,
            "references": self.references[:3]  # İlk 3 referans
        }


async def _rate_limit():
    """NVD API rate limiting"""
    global _last_request_time, _request_count
    
    now = datetime.now()
    
    if _last_request_time is None:
        _last_request_time = now
        _request_count = 1
        return
    
    # Window sıfırlanmalı mı?
    if now - _last_request_time > _rate_limit_window:
        _last_request_time = now
        _request_count = 1
        return
    
    # Limit aşıldı mı?
    if _request_count >= _max_requests_per_window:
        wait_time = (_rate_limit_window - (now - _last_request_time)).total_seconds()
        if wait_time > 0:
            print(f"⏳ NVD rate limit, {wait_time:.0f}s bekleniyor...")
            await asyncio.sleep(wait_time + 1)
            _last_request_time = datetime.now()
            _request_count = 1
            return
    
    _request_count += 1


async def lookup_cves(
    keyword: str,
    version: str = None,
    max_results: int = 10
) -> List[CVEInfo]:
    """
    NVD'den CVE ara
    
    Args:
        keyword: Ürün adı (örn: "apache", "openssh")
        version: Versiyon (opsiyonel, örn: "2.4.49")
        max_results: Maximum sonuç sayısı
        
    Returns:
        CVEInfo listesi
    """
    await _rate_limit()
    
    # Query oluştur
    search_term = keyword
    if version:
        search_term = f"{keyword} {version}"
    
    params = {
        "keywordSearch": search_term,
        "resultsPerPage": min(max_results, 20)  # NVD max 2000, biz 20 ile sınırlıyoruz
    }
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(NVD_API_URL, params=params, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                results = []
                for vuln in vulnerabilities[:max_results]:
                    cve_data = vuln.get("cve", {})
                    
                    # Description
                    descriptions = cve_data.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")[:500]
                            break
                    
                    # CVSS Score
                    metrics = cve_data.get("metrics", {})
                    cvss_score = 0.0
                    cvss_version = ""
                    severity = "unknown"
                    
                    # CVSS 3.1 öncelikli
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        cvss_version = "3.1"
                        severity = cvss_data.get("baseSeverity", "").lower()
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        cvss_version = "3.0"
                        severity = cvss_data.get("baseSeverity", "").lower()
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0.0)
                        cvss_version = "2.0"
                        # CVSS 2.0 severity mapping
                        if cvss_score >= 7.0:
                            severity = "high"
                        elif cvss_score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                    
                    # References
                    references = []
                    for ref in cve_data.get("references", [])[:3]:
                        references.append(ref.get("url", ""))
                    
                    cve_info = CVEInfo(
                        cve_id=cve_data.get("id", ""),
                        description=description,
                        severity=severity,
                        cvss_score=cvss_score,
                        cvss_version=cvss_version,
                        published_date=cve_data.get("published"),
                        references=references
                    )
                    results.append(cve_info)
                
                print(f"✅ NVD: {len(results)} CVE bulundu - {search_term}")
                return results
                
            elif response.status_code == 403:
                print("⚠️ NVD API rate limit aşıldı")
                return []
            else:
                print(f"⚠️ NVD API hatası: {response.status_code}")
                return []
                
    except Exception as e:
        print(f"⚠️ NVD lookup error: {e}")
        return []


async def lookup_cves_for_services(
    services: List[Dict[str, str]],
    max_per_service: int = 5
) -> Dict[str, List[CVEInfo]]:
    """
    Birden fazla servis için CVE ara
    
    Args:
        services: [{"product": "apache", "version": "2.4.49"}, ...]
        max_per_service: Her servis için max CVE sayısı
        
    Returns:
        {"apache 2.4.49": [CVEInfo, ...], ...}
    """
    results = {}
    
    for service in services:
        product = service.get("product", "")
        version = service.get("version", "")
        
        if not product:
            continue
        
        key = f"{product} {version}".strip()
        cves = await lookup_cves(product, version, max_per_service)
        
        if cves:
            results[key] = cves
        
        # Rate limit için küçük gecikme
        await asyncio.sleep(0.5)
    
    return results


def get_severity_priority(severity: str) -> int:
    """Severity öncelik sıralaması (düşük = daha kritik)"""
    priority_map = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "unknown": 4
    }
    return priority_map.get(severity.lower(), 5)


async def get_critical_cves(
    services: List[Dict[str, str]],
    min_cvss: float = 7.0
) -> List[CVEInfo]:
    """
    Sadece kritik/yüksek CVE'leri getir
    
    Args:
        services: Servis listesi
        min_cvss: Minimum CVSS skoru (default: 7.0 = High)
        
    Returns:
        Kritik CVE listesi
    """
    all_cves = await lookup_cves_for_services(services)
    
    critical = []
    for service, cves in all_cves.items():
        for cve in cves:
            if cve.cvss_score >= min_cvss:
                critical.append(cve)
    
    # CVSS skoruna göre sırala (yüksekten düşüğe)
    critical.sort(key=lambda x: x.cvss_score, reverse=True)
    
    return critical
