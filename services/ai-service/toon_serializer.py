"""
TOON Serializer - Token-Oriented Object Notation
Türkçe: AI API çağrıları için token tasarrufu sağlayan veri serileştirme modülü

TOON Avantajları:
- %30-60 daha az token kullanımı
- JSON'dan daha kompakt format
- LLM-friendly yapı (parsing için guardrails)
- Semantic meaning korunurken gereksiz karakterler azaltılır

Format Özellikleri:
- Minimal syntax (tırnak ve parantez azaltma)
- Indentation-based nesting
- Array length prefix (parsing güvenliği)
- Field headers (LLM güvenilirliği)
"""

import json
import re
from typing import Any, Dict, List, Optional, Union
from datetime import datetime


class TOONSerializer:
    """
    Türkçe: TOON formatında veri serileştirme sınıfı
    
    Kullanım:
        serializer = TOONSerializer()
        toon_data = serializer.to_toon(json_data)
        json_data = serializer.from_toon(toon_data)
    """
    
    def __init__(self, indent: int = 2, max_depth: int = 5):
        self.indent = indent
        self.max_depth = max_depth
        self._depth = 0
    
    def to_toon(self, data: Any, compact: bool = False) -> str:
        """
        Türkçe: Python objesini TOON formatına dönüştürür
        
        Args:
            data: Dönüştürülecek Python objesi (dict, list, str, int, etc.)
            compact: True ise tek satır formatı kullanır
            
        Returns:
            TOON formatında string
        """
        self._depth = 0
        return self._serialize(data, compact)
    
    def _serialize(self, data: Any, compact: bool = False) -> str:
        """Türkçe: Recursive serileştirme"""
        
        if data is None:
            return "~"  # TOON null representation
        
        if isinstance(data, bool):
            return "+" if data else "-"  # TOON boolean
        
        if isinstance(data, (int, float)):
            return str(data)
        
        if isinstance(data, str):
            # Basit stringler tırnak olmadan
            if self._is_simple_string(data):
                return data
            # Karmaşık stringler tek tırnak ile
            return f"'{self._escape_string(data)}'"
        
        if isinstance(data, datetime):
            return data.isoformat()
        
        if isinstance(data, list):
            return self._serialize_list(data, compact)
        
        if isinstance(data, dict):
            return self._serialize_dict(data, compact)
        
        # Fallback: str representation
        return str(data)
    
    def _serialize_list(self, data: List, compact: bool) -> str:
        """Türkçe: Liste serileştirme - length prefix ile"""
        
        if not data:
            return "[]"
        
        if compact or self._depth >= self.max_depth:
            items = ", ".join(self._serialize(item, True) for item in data)
            return f"[{len(data)}| {items}]"
        
        self._depth += 1
        indent_str = " " * (self.indent * self._depth)
        
        lines = [f"[{len(data)}|"]  # Length prefix for LLM parsing
        for item in data:
            serialized = self._serialize(item, False)
            if "\n" in serialized:
                # Multi-line item
                lines.append(f"{indent_str}- {serialized.split(chr(10))[0]}")
                for line in serialized.split("\n")[1:]:
                    lines.append(f"{indent_str}  {line}")
            else:
                lines.append(f"{indent_str}- {serialized}")
        lines.append(f"{' ' * (self.indent * (self._depth - 1))}]")
        
        self._depth -= 1
        return "\n".join(lines)
    
    def _serialize_dict(self, data: Dict, compact: bool) -> str:
        """Türkçe: Dict serileştirme - field headers ile"""
        
        if not data:
            return "{}"
        
        if compact or self._depth >= self.max_depth:
            items = ", ".join(f"{k}:{self._serialize(v, True)}" for k, v in data.items())
            return f"{{{items}}}"
        
        self._depth += 1
        indent_str = " " * (self.indent * self._depth)
        
        lines = []
        for key, value in data.items():
            serialized = self._serialize(value, False)
            if "\n" in serialized:
                # Multi-line value
                lines.append(f"{indent_str}{key}:")
                for line in serialized.split("\n"):
                    lines.append(f"{indent_str}  {line}")
            else:
                lines.append(f"{indent_str}{key}: {serialized}")
        
        self._depth -= 1
        return "\n".join(lines)
    
    def _is_simple_string(self, s: str) -> bool:
        """Türkçe: String tırnak gerektiriyor mu kontrol et"""
        if not s:
            return False
        # Alfanumerik, tire, nokta, slash içeren basit stringler
        return bool(re.match(r'^[a-zA-Z0-9_\-./]+$', s)) and len(s) < 100
    
    def _escape_string(self, s: str) -> str:
        """Türkçe: String escape işlemi"""
        return s.replace("'", "\\'").replace("\n", "\\n")
    
    def from_toon(self, toon_str: str) -> Any:
        """
        Türkçe: TOON formatından Python objesine dönüştürür
        
        Args:
            toon_str: TOON formatında string
            
        Returns:
            Python objesi
        """
        # Basit parse - production için daha robust parser gerekebilir
        toon_str = toon_str.strip()
        
        if toon_str == "~":
            return None
        if toon_str == "+":
            return True
        if toon_str == "-":
            return False
        if toon_str == "{}":
            return {}
        if toon_str == "[]":
            return []
        
        # Number check
        try:
            if "." in toon_str:
                return float(toon_str)
            return int(toon_str)
        except ValueError:
            pass
        
        # Quoted string
        if toon_str.startswith("'") and toon_str.endswith("'"):
            return toon_str[1:-1].replace("\\'", "'").replace("\\n", "\n")
        
        # Simple string
        return toon_str


def compress_scan_data(scan_data: Dict) -> str:
    """
    Türkçe: Tarama verilerini TOON formatında sıkıştırır
    AI promptları için optimize edilmiş çıktı üretir
    
    Özellikler:
    - Gereksiz alanları filtreler
    - Büyük listleri truncate eder
    - Kritik bilgileri öne çıkarır
    
    Args:
        scan_data: Ham tarama verisi (dict)
        
    Returns:
        TOON formatında kompakt string
    """
    serializer = TOONSerializer(indent=2, max_depth=4)
    
    # Optimize edilecek veri yapısı
    optimized = _extract_critical_data(scan_data)
    
    return serializer.to_toon(optimized)


def _extract_critical_data(scan_data: Dict) -> Dict:
    """
    Türkçe: Tarama verisinden kritik bilgileri çıkarır
    Gereksiz detayları atar, AI analizi için önemli olanları tutar
    """
    
    result = {
        "target": scan_data.get("target", scan_data.get("domain", "unknown")),
        "scan_id": scan_data.get("scan_id", ""),
        "timestamp": scan_data.get("created_at", datetime.now().isoformat()),
    }
    
    # Results veya direkt data
    results = scan_data.get("results", scan_data)
    
    # Nuclei Findings - En kritik
    if "nuclei" in results:
        nuclei_data = results["nuclei"]
        findings = nuclei_data.get("findings", [])
        
        # Severity bazlı gruplama
        severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_groups and len(severity_groups[sev]) < 10:
                severity_groups[sev].append({
                    "name": f.get("name", f.get("template_id", "unknown")),
                    "matched": f.get("matched_at", f.get("host", "")),
                    "cve": f.get("cve_id", f.get("info", {}).get("cve_id", "")),
                })
        
        result["nuclei"] = {
            "total": len(findings),
            "critical": len([f for f in findings if f.get("severity", "").lower() == "critical"]),
            "high": len([f for f in findings if f.get("severity", "").lower() == "high"]),
            "medium": len([f for f in findings if f.get("severity", "").lower() == "medium"]),
            "top_findings": severity_groups["critical"][:5] + severity_groups["high"][:5],
        }
    
    # Nmap Ports - Açık portlar özeti
    if "nmap" in results:
        nmap_data = results["nmap"]
        output = nmap_data.get("output", "")
        
        # Port parsing
        ports = []
        for match in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', output):
            ports.append({
                "port": int(match.group(1)),
                "proto": match.group(2),
                "service": match.group(3)
            })
        
        result["nmap"] = {
            "open_ports": len(ports),
            "critical_ports": [p for p in ports if p["port"] in [21, 22, 23, 25, 445, 3389, 5900]],
            "ports": ports[:15],  # İlk 15 port
        }
    
    # Subdomains - Sayı ve örnek
    if "subdomains" in results:
        subdomains = results["subdomains"]
        if isinstance(subdomains, list):
            result["subdomains"] = {
                "count": len(subdomains),
                "samples": subdomains[:20],
            }
    
    # RustScan
    if "rustscan" in results:
        rustscan = results["rustscan"]
        result["rustscan"] = {
            "open_ports": rustscan.get("open_ports", [])[:30],
            "count": len(rustscan.get("open_ports", []))
        }
    
    return result


def estimate_token_savings(json_data: Dict) -> Dict:
    """
    Türkçe: JSON vs TOON token tasarrufunu hesaplar
    
    Returns:
        {
            "json_chars": int,
            "toon_chars": int,
            "savings_percent": float,
            "estimated_tokens_saved": int
        }
    """
    json_str = json.dumps(json_data, indent=2, ensure_ascii=False, default=str)
    toon_str = compress_scan_data(json_data)
    
    json_chars = len(json_str)
    toon_chars = len(toon_str)
    
    # Yaklaşık token hesabı (4 karakter = 1 token)
    json_tokens = json_chars // 4
    toon_tokens = toon_chars // 4
    
    savings = ((json_chars - toon_chars) / json_chars) * 100 if json_chars > 0 else 0
    
    return {
        "json_chars": json_chars,
        "toon_chars": toon_chars,
        "savings_percent": round(savings, 2),
        "estimated_tokens_saved": json_tokens - toon_tokens
    }


# Convenience functions
def to_toon(data: Any, compact: bool = False) -> str:
    """Türkçe: Hızlı TOON dönüşümü"""
    return TOONSerializer().to_toon(data, compact)


def from_toon(toon_str: str) -> Any:
    """Türkçe: Hızlı TOON parse"""
    return TOONSerializer().from_toon(toon_str)


# Test
if __name__ == "__main__":
    # Test verisi
    test_data = {
        "target": "example.com",
        "scan_id": "abc123",
        "nuclei": {
            "findings": [
                {"name": "SQL Injection", "severity": "critical", "cve_id": "CVE-2024-1234"},
                {"name": "XSS", "severity": "high", "cve_id": None},
            ]
        },
        "nmap": {
            "output": "22/tcp open ssh\n80/tcp open http\n443/tcp open https"
        }
    }
    
    # TOON dönüşümü
    toon = compress_scan_data(test_data)
    print("=== TOON Output ===")
    print(toon)
    print()
    
    # Token tasarrufu
    savings = estimate_token_savings(test_data)
    print("=== Token Savings ===")
    print(f"JSON: {savings['json_chars']} chars")
    print(f"TOON: {savings['toon_chars']} chars")
    print(f"Savings: {savings['savings_percent']}%")
    print(f"Tokens saved: ~{savings['estimated_tokens_saved']}")
