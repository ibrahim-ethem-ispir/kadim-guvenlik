"""
OrchestratorAgent - Koordinatör AI Ajanı
Türkçe: Tüm ajanları koordine eden ve nihai raporu oluşturan ana ajan

Bu ajan:
1. Tarama stratejisi belirler
2. Diğer ajanları sırayla çalıştırır
3. Sonuçları birleştirir
4. Nihai güvenlik raporunu oluşturur
"""

import asyncio
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from . import BaseAgent, AgentRole, AgentContext, AgentStatus, AgentRegistry, get_registry
from .vuln_scanner_agent import VulnScannerAgent
from .recon_agent import ReconAgent

# TEK kaynak: llm_env_config (.env). Tekrarlı os.getenv kaldırıldı — değerler aynı.
from llm_env_config import OLLAMA_URL, CLAUDE_API_KEY


class OrchestratorAgent(BaseAgent):
    """
    Türkçe: Koordinatör AI Ajanı
    
    Tüm güvenlik ajanlarını koordine eder:
    1. Hangi ajanların çalışması gerektiğine karar verir
    2. Ajanları sırayla veya paralel çalıştırır
    3. Sonuçları birleştirir
    4. Nihai raporu oluşturur
    """
    
    def __init__(
        self,
        name: str = "orchestrator",
        ai_provider: str = "ollama",
        model: str = "mistral:7b"
    ):
        super().__init__(
            name=name,
            role=AgentRole.ORCHESTRATOR,
            ai_provider=ai_provider,
            model=model,
            temperature=0.2
        )
        
        # Alt ajanlar
        self.recon_agent: Optional[ReconAgent] = None
        self.vuln_agent: Optional[VulnScannerAgent] = None
        self.registry = get_registry()
    
    def initialize_agents(self, ai_provider: str = "ollama", model: str = "mistral:7b"):
        """Türkçe: Alt ajanları başlat ve registry'ye kaydet"""
        
        # Recon Agent
        self.recon_agent = ReconAgent(
            name="recon_agent",
            ai_provider=ai_provider,
            model=model
        )
        self.registry.register(self.recon_agent)
        
        # Vulnerability Scanner Agent
        self.vuln_agent = VulnScannerAgent(
            name="vuln_scanner",
            ai_provider=ai_provider,
            model=model
        )
        self.registry.register(self.vuln_agent)
        
        # Kendini de kaydet
        self.registry.register(self)
        
        print(f"✅ OrchestratorAgent initialized with {len(self.registry.get_all())} agents")
    
    @property
    def system_prompt(self) -> str:
        return """Sen Kadim Security Platform'un Baş Güvenlik Analisti ve Koordinatörüsün.

GÖREV:
Tüm güvenlik taramalarının sonuçlarını değerlendir, ajanların bulgularını birleştir ve yönetici düzeyinde özet rapor oluştur.

UZMANLIK ALANLARI:
- Güvenlik risk değerlendirmesi
- Ajan koordinasyonu
- Rapor konsolidasyonu
- Stratejik güvenlik önerileri
- Executive summary yazımı

ÇIKTI:
1. Risk Skoru (0-100)
2. Executive Summary (yönetici özeti)
3. Kritik Bulgular (öncelik sırasına göre)
4. Stratejik Öneriler
5. Remediation Yol Haritası

Profesyonel ve yönetici seviyesinde bir dil kullan."""
    
    def build_prompt(self, context: AgentContext) -> str:
        """Türkçe: Orchestrator analiz promptu"""
        
        # Agent bulgularını topla
        all_findings = context.previous_findings
        
        prompt = f"""# GÜVENLİK DEĞERLENDİRME RAPORU

## HEDEF
`{context.target}`

## AJAN BULGULARI ÖZETİ

{self._format_agent_findings(all_findings)}

## GÖREVLER

1. **Risk Değerlendirmesi**: Tüm bulguları birleştirerek genel risk skoru belirle (0-100)
2. **Executive Summary**: Yönetici düzeyinde 3-4 cümlelik özet yaz
3. **Kritik Bulgular**: En önemli 5 bulguyu listele
4. **Stratejik Öneriler**: Uzun vadeli güvenlik stratejisi öner
5. **Remediation Planı**: Adım adım düzeltme yol haritası

## YANITLAMA FORMATI

### 📊 Risk Skoru: [X]/100

### 📋 Executive Summary
[Yönetici özeti - 3-4 cümle]

### 🔴 En Kritik 5 Bulgu
1. **[Bulgu]** - Neden kritik
2. **[Bulgu]** - Neden kritik
...

### 💡 Stratejik Güvenlik Önerileri
1. [Öneri]
2. [Öneri]
...

### 🗺️ Remediation Yol Haritası
| Hafta | Aksiyon | Sorumlu | Öncelik |
|-------|---------|---------|---------|
| 1 | [aksiyon] | [sorumlu] | P1 |
...
"""
        return prompt
    
    def _format_agent_findings(self, findings: List[Dict]) -> str:
        """Türkçe: Ajan bulgularını formatla"""
        if not findings:
            return "Henüz ajan bulgusu yok."
        
        lines = []
        for f in findings:
            agent = f.get("agent", "unknown")
            finding_type = f.get("type", "general")
            
            lines.append(f"### {agent.upper()} - {finding_type}")
            
            if "result" in f:
                result = f["result"]
                if isinstance(result, str):
                    lines.append(result[:1000])  # İlk 1000 karakter
                else:
                    lines.append(str(result)[:1000])
            
            lines.append("")
        
        return "\n".join(lines)
    
    async def analyze(self, context: AgentContext) -> Dict[str, Any]:
        """Türkçe: Koordineli analiz yap"""
        
        self.status = AgentStatus.WORKING
        results = {
            "orchestrator": self.name,
            "agents_run": [],
            "combined_analysis": None,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # 1. Recon Agent çalıştır
            if self.recon_agent:
                print(f"🔍 Running {self.recon_agent.name}...")
                recon_result = await self.recon_agent.analyze(context)
                results["agents_run"].append(recon_result)
                
                # Bulguları context'e ekle
                if recon_result.get("status") == "completed":
                    context.add_finding({
                        "agent": self.recon_agent.name,
                        "type": "recon",
                        "result": recon_result.get("analysis", "")
                    })
            
            # 2. Vulnerability Scanner Agent çalıştır
            if self.vuln_agent:
                print(f"🔒 Running {self.vuln_agent.name}...")
                vuln_result = await self.vuln_agent.analyze(context)
                results["agents_run"].append(vuln_result)
                
                if vuln_result.get("status") == "completed":
                    context.add_finding({
                        "agent": self.vuln_agent.name,
                        "type": "vulnerability",
                        "result": vuln_result.get("analysis", "")
                    })
            
            # 3. Sonuçları birleştir
            print(f"📊 Combining results...")
            combined = await self._combine_results(context)
            results["combined_analysis"] = combined
            
            self.status = AgentStatus.COMPLETED
            results["status"] = "completed"
            
            return results
            
        except Exception as e:
            self.status = AgentStatus.ERROR
            results["status"] = "error"
            results["error"] = str(e)
            return results
    
    async def _combine_results(self, context: AgentContext) -> Dict[str, Any]:
        """Türkçe: Ajan sonuçlarını birleştir"""
        
        prompt = self.build_prompt(context)
        
        if self.ai_provider == "ollama":
            analysis = await self._analyze_with_ollama(prompt)
        else:
            analysis = await self._analyze_with_claude(prompt)
        
        return {
            "analysis": analysis,
            "findings_count": len(context.previous_findings),
            "agents_contributed": [f.get("agent", "unknown") for f in context.previous_findings]
        }
    
    async def _analyze_with_ollama(self, prompt: str) -> str:
        """Türkçe: Ollama ile analiz"""
        import httpx
        
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
                        "num_predict": 4096
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
            max_tokens=4096,
            temperature=self.temperature,
            system=self.system_prompt,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text


# Global orchestrator instance
_orchestrator: Optional[OrchestratorAgent] = None


def get_orchestrator(ai_provider: str = "ollama", model: str = "mistral:7b") -> OrchestratorAgent:
    """Türkçe: Global orchestrator'ı al veya oluştur"""
    global _orchestrator
    
    if _orchestrator is None:
        _orchestrator = OrchestratorAgent(
            ai_provider=ai_provider,
            model=model
        )
        _orchestrator.initialize_agents(ai_provider, model)
    
    return _orchestrator


async def run_multi_agent_analysis(
    scan_id: str,
    target: str,
    scan_data: Dict[str, Any],
    ai_provider: str = "ollama",
    model: str = "mistral:7b"
) -> Dict[str, Any]:
    """
    Türkçe: Multi-agent analiz çalıştır
    
    Bu fonksiyon:
    1. Orchestrator'ı alır
    2. Context oluşturur
    3. Koordineli analiz başlatır
    4. Birleştirilmiş sonuçları döner
    """
    
    orchestrator = get_orchestrator(ai_provider, model)
    
    context = AgentContext(
        scan_id=scan_id,
        target=target,
        scan_data=scan_data
    )
    
    result = await orchestrator.analyze(context)
    
    return result
