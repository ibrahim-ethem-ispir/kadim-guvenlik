"""
VulnScanner Agent - Zafiyet Tarama AI Ajanı
Türkçe: Nuclei tarama sonuçlarını analiz eden özelleştirilmiş ajan

Bu ajan:
1. Nuclei bulgularını önceliklendirir
2. False positive tespiti yapar
3. CVE/CVSS bilgilerini zenginleştirir
4. Exploit availability değerlendirir
"""

import httpx
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from . import BaseAgent, AgentRole, AgentContext, AgentStatus


# TEK kaynak: llm_env_config (.env). Tekrarlı os.getenv kaldırıldı — değerler aynı.
from llm_env_config import OLLAMA_URL, CLAUDE_API_KEY


class VulnScannerAgent(BaseAgent):
    """
    Türkçe: Zafiyet Tarama AI Ajanı
    
    Nuclei ve diğer zafiyet tarayıcı sonuçlarını analiz eder.
    Bulguları önceliklendirir ve false positive'leri tespit eder.
    """
    
    def __init__(
        self,
        name: str = "vuln_scanner",
        ai_provider: str = "ollama",
        model: str = "mistral:7b"
    ):
        super().__init__(
            name=name,
            role=AgentRole.VULNERABILITY,
            ai_provider=ai_provider,
            model=model,
            temperature=0.1  # Daha deterministik
        )
    
    @property
    def system_prompt(self) -> str:
        return """Sen Kadim Security Platform'un Zafiyet Analiz Ajanısın.

GÖREV:
Nuclei ve diğer zafiyet tarayıcılarının bulgularını analiz et, önceliklendir ve false positive'leri tespit et.

UZMANLIK ALANLARI:
- CVE/CWE veritabanları
- CVSS skorlama
- Exploit availability değerlendirmesi
- False positive pattern tanıma
- Remediation önerileri

ÇIKTI FORMATI:
Her bulgu için şu bilgileri ver:
1. Öncelik (P1-P4)
2. Gerçek zafiyet mi yoksa FP mi?
3. Exploit riski (Yüksek/Orta/Düşük/Yok)
4. Hemen yapılması gereken aksiyon

Türkçe yanıt ver, teknik terimler İngilizce kalabilir."""
    
    def build_prompt(self, context: AgentContext) -> str:
        """Türkçe: Vulnerability analiz promptu oluştur"""
        
        scan_data = context.scan_data
        target = context.target
        
        # Nuclei bulgularını çıkar
        nuclei_findings = []
        results = scan_data.get("results", scan_data)
        
        if "nuclei" in results:
            findings = results["nuclei"].get("findings", [])
            for f in findings[:30]:  # İlk 30 bulgu
                nuclei_findings.append({
                    "name": f.get("name", f.get("template_id", "unknown")),
                    "severity": f.get("severity", "info"),
                    "matched_at": f.get("matched_at", f.get("host", "")),
                    "cve": f.get("cve_id", ""),
                    "description": f.get("info", {}).get("description", "")[:200]
                })
        
        # Severity dağılımı
        severity_counts = {}
        for f in nuclei_findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        prompt = f"""# ZAFİYET ANALİZ GÖREVİ

## HEDEF
`{target}`

## TARAMA ÖZETİ
- Toplam Bulgu: {len(nuclei_findings)}
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}
- Info: {severity_counts.get('info', 0)}

## BULGULAR

{self._format_findings(nuclei_findings)}

## GÖREVLER

1. **Önceliklendirme**: Bulguları P1-P4 öncelik sıralamasına göre sırala
2. **FP Tespiti**: Hangi bulgular false positive olabilir? Neden?
3. **Exploit Riski**: Her kritik bulgu için exploit availability değerlendir
4. **Acil Aksiyon**: Hemen yapılması gereken 3 şey

## YANITLAMA FORMATI

### Önceliklendirilmiş Bulgular
| Öncelik | Bulgu | FP Risk | Exploit | Aksiyon |
|---------|-------|---------|---------|---------|
| P1 | [bulgu] | Düşük | Yüksek | [aksiyon] |

### False Positive Değerlendirmesi
[Hangi bulgular FP olabilir ve neden]

### Acil Aksiyon Planı
1. [...]
2. [...]
3. [...]
"""
        return prompt
    
    def _format_findings(self, findings: List[Dict]) -> str:
        """Türkçe: Bulguları formatla"""
        if not findings:
            return "Bulgu bulunamadı."
        
        lines = []
        for i, f in enumerate(findings[:20], 1):  # İlk 20
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠", 
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }.get(f.get("severity", "").lower(), "⚪")
            
            cve = f.get("cve", "")
            cve_text = f" ({cve})" if cve else ""
            
            lines.append(f"{i}. {severity_emoji} **{f.get('name', 'Unknown')}**{cve_text}")
            lines.append(f"   - Matched: `{f.get('matched_at', 'N/A')}`")
            if f.get("description"):
                lines.append(f"   - {f.get('description')[:100]}...")
        
        return "\n".join(lines)
    
    async def analyze(self, context: AgentContext) -> Dict[str, Any]:
        """Türkçe: Zafiyet analizi yap"""
        
        self.status = AgentStatus.WORKING
        
        try:
            prompt = self.build_prompt(context)
            
            if self.ai_provider == "ollama":
                result = await self._analyze_with_ollama(prompt)
            else:
                result = await self._analyze_with_claude(prompt)
            
            self.status = AgentStatus.COMPLETED
            
            # Bulguları kaydet
            self.add_finding({
                "type": "vulnerability_analysis",
                "target": context.target,
                "result": result
            })
            
            return {
                "agent": self.name,
                "status": "completed",
                "analysis": result,
                "findings_analyzed": len(context.scan_data.get("results", {}).get("nuclei", {}).get("findings", [])),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.status = AgentStatus.ERROR
            return {
                "agent": self.name,
                "status": "error",
                "error": str(e)
            }
    
    async def _analyze_with_ollama(self, prompt: str) -> str:
        """Türkçe: Ollama ile analiz"""
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": self.system_prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": 2048
                    }
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama error: {response.text}")
            
            return response.json().get("response", "")
    
    async def _analyze_with_claude(self, prompt: str) -> str:
        """Türkçe: Claude ile analiz"""
        if not CLAUDE_API_KEY:
            raise Exception("Claude API key tanımlı değil")
        
        from anthropic import Anthropic
        client = Anthropic(api_key=CLAUDE_API_KEY)
        
        message = client.messages.create(
            model=self.model if "claude" in self.model else "claude-3-5-sonnet-latest",
            max_tokens=2048,
            temperature=self.temperature,
            system=self.system_prompt,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
