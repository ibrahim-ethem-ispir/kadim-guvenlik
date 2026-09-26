"""
ReconAgent - Keşif AI Ajanı
Türkçe: Subdomain, teknoloji ve attack surface analizi yapan ajan

Bu ajan:
1. Subdomain keşif sonuçlarını değerlendirir
2. Teknoloji stack'ini analiz eder
3. Attack surface haritası çıkarır
4. Shadow IT ve exposed service tespiti yapar
"""

import httpx
import os
from typing import Dict, List, Any
from datetime import datetime

from . import BaseAgent, AgentRole, AgentContext, AgentStatus

# TEK kaynak: llm_env_config (.env). Tekrarlı os.getenv kaldırıldı — değerler aynı.
from llm_env_config import OLLAMA_URL, CLAUDE_API_KEY


class ReconAgent(BaseAgent):
    """
    Türkçe: Keşif AI Ajanı
    
    Subdomain, DNS, teknoloji keşif sonuçlarını analiz eder.
    Attack surface'i haritalandırır ve risk değerlendirmesi yapar.
    """
    
    def __init__(
        self,
        name: str = "recon_agent",
        ai_provider: str = "ollama",
        model: str = "mistral:7b"
    ):
        super().__init__(
            name=name,
            role=AgentRole.RECON,
            ai_provider=ai_provider,
            model=model,
            temperature=0.2
        )
    
    @property
    def system_prompt(self) -> str:
        return """Sen Kadim Security Platform'un Keşif (Recon) Ajanısın.

GÖREV:
Subdomain keşfi, teknoloji tespiti ve attack surface analizi yap.

UZMANLIK ALANLARI:
- Subdomain enumeration sonuçları
- DNS record analizi
- Web teknoloji fingerprinting
- Shadow IT tespiti
- Exposed service keşfi
- Attack surface mapping

ÇIKTI FORMATI:
1. Attack Surface Özeti
2. Kritik Keşifler (exposed services, shadow IT)
3. Teknoloji Stack Analizi
4. Sonraki Tarama Önerileri

Türkçe yanıt ver, domain/IP bilgileri olduğu gibi kalabilir."""
    
    def build_prompt(self, context: AgentContext) -> str:
        """Türkçe: Recon analiz promptu oluştur"""
        
        scan_data = context.scan_data
        target = context.target
        results = scan_data.get("results", scan_data)
        
        # Subdomain bilgileri
        subdomains = results.get("subdomains", [])
        if isinstance(subdomains, dict):
            subdomains = subdomains.get("subdomains", [])
        
        # Nmap port bilgileri
        open_ports = []
        if "nmap" in results:
            nmap_output = results["nmap"].get("output", "")
            # Basit port parsing
            import re
            for match in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', nmap_output):
                open_ports.append({
                    "port": match.group(1),
                    "service": match.group(3)
                })
        
        # RustScan portları
        if "rustscan" in results:
            rustscan_ports = results["rustscan"].get("open_ports", [])
            for p in rustscan_ports[:30]:
                if not any(op.get("port") == str(p) for op in open_ports):
                    open_ports.append({"port": str(p), "service": "unknown"})
        
        prompt = f"""# KEŞİF ANALİZ GÖREVİ

## HEDEF DOMAIN
`{target}`

## KEŞİF SONUÇLARI

### Subdomain'ler ({len(subdomains)} adet)
{self._format_subdomains(subdomains)}

### Açık Portlar ({len(open_ports)} adet)
{self._format_ports(open_ports)}

## GÖREVLER

1. **Attack Surface Haritası**: Toplam saldırı yüzeyini değerlendir
2. **Kritik Servisler**: Dışa açık kritik servisleri tespit et (DB, admin panel, vb.)
3. **Shadow IT**: Beklenmedik veya unutulmuş servisler var mı?
4. **Teknoloji Stack**: Tespit edilen teknolojileri listele
5. **Sonraki Adımlar**: Derinlemesine tarama için öneriler

## YANITLAMA FORMATI

### 🌐 Attack Surface Özeti
[Toplam subdomain, port, exposed servis sayısı ve risk değerlendirmesi]

### 🔴 Kritik Keşifler
1. [Kritik servis/port]
2. [Shadow IT bulgusu]

### 🛠️ Teknoloji Stack
| Teknoloji | Versiyon | Risk |
|-----------|----------|------|
| [tech] | [ver] | [risk] |

### ⏭️ Önerilen Sonraki Taramalar
1. [Öneri]
2. [Öneri]
"""
        return prompt
    
    def _format_subdomains(self, subdomains: List) -> str:
        """Türkçe: Subdomain'leri formatla"""
        if not subdomains:
            return "Subdomain bulunamadı."
        
        # İlk 30 subdomain
        sample = subdomains[:30]
        lines = [f"- `{s}`" for s in sample]
        
        if len(subdomains) > 30:
            lines.append(f"... ve {len(subdomains) - 30} adet daha")
        
        return "\n".join(lines)
    
    def _format_ports(self, ports: List[Dict]) -> str:
        """Türkçe: Portları formatla"""
        if not ports:
            return "Açık port bulunamadı."
        
        lines = []
        for p in ports[:25]:
            port_num = p.get("port", "?")
            service = p.get("service", "unknown")
            
            # Kritik port işaretleme
            critical_ports = ["21", "22", "23", "25", "445", "3306", "3389", "5432", "5900", "6379", "27017"]
            marker = "🔴" if port_num in critical_ports else "🟢"
            
            lines.append(f"{marker} `{port_num}` - {service}")
        
        return "\n".join(lines)
    
    async def analyze(self, context: AgentContext) -> Dict[str, Any]:
        """Türkçe: Keşif analizi yap"""
        
        self.status = AgentStatus.WORKING
        
        try:
            prompt = self.build_prompt(context)
            
            if self.ai_provider == "ollama":
                result = await self._analyze_with_ollama(prompt)
            else:
                result = await self._analyze_with_claude(prompt)
            
            self.status = AgentStatus.COMPLETED
            
            # Bulgu kaydet
            results = context.scan_data.get("results", context.scan_data)
            subdomains = results.get("subdomains", [])
            if isinstance(subdomains, dict):
                subdomains = subdomains.get("subdomains", [])
            
            self.add_finding({
                "type": "recon_analysis",
                "target": context.target,
                "subdomain_count": len(subdomains),
                "result": result
            })
            
            return {
                "agent": self.name,
                "status": "completed",
                "analysis": result,
                "subdomains_analyzed": len(subdomains),
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
        async with httpx.AsyncClient(timeout=120.0) as client:
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
            model=self.model if "claude" in self.model else "claude-3-5-haiku-latest",
            max_tokens=2048,
            temperature=self.temperature,
            system=self.system_prompt,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
