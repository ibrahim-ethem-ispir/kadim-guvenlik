"""
Kadim AI Agents - Multi-Agent Security Analysis System
Türkçe: Çoklu ajan tabanlı güvenlik analiz sistemi

Bu modül:
1. BaseAgent: Tüm ajanların temel sınıfı
2. Ortak interface ve iletişim protokolü
3. Agent registry ve discovery
4. Inter-agent messaging
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Literal
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import asyncio


class AgentRole(Enum):
    """Türkçe: Ajan rolleri"""
    RECON = "recon"                    # Keşif ajanı
    VULNERABILITY = "vulnerability"    # Zafiyet tarama ajanı
    EXPLOIT = "exploit"                # Exploit analiz ajanı
    REPORT = "report"                  # Rapor oluşturma ajanı
    ORCHESTRATOR = "orchestrator"      # Koordinatör ajan


class AgentStatus(Enum):
    """Türkçe: Ajan durumları"""
    IDLE = "idle"
    WORKING = "working"
    WAITING = "waiting"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class AgentMessage:
    """Türkçe: Ajanlar arası mesaj formatı"""
    from_agent: str
    to_agent: str
    content: Dict[str, Any]
    message_type: Literal["request", "response", "broadcast", "error"]
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "from": self.from_agent,
            "to": self.to_agent,
            "type": self.message_type,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id
        }


@dataclass
class AgentContext:
    """Türkçe: Ajan çalışma bağlamı"""
    scan_id: str
    target: str
    scan_data: Dict[str, Any]
    previous_findings: List[Dict] = field(default_factory=list)
    shared_state: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Dict):
        """Türkçe: Yeni bulgu ekle"""
        finding["added_at"] = datetime.now().isoformat()
        self.previous_findings.append(finding)
    
    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Türkçe: Belirli şiddetteki bulguları getir"""
        return [f for f in self.previous_findings 
                if f.get("severity", "").lower() == severity.lower()]


class BaseAgent(ABC):
    """
    Türkçe: Tüm AI ajanlarının temel sınıfı
    
    Her ajan şu özelliklere sahiptir:
    - Benzersiz isim ve rol
    - AI provider seçimi (ollama/claude)
    - Özelleştirilmiş system prompt
    - Analiz ve yanıt üretme yetenekleri
    """
    
    def __init__(
        self,
        name: str,
        role: AgentRole,
        ai_provider: Literal["ollama", "claude"] = "ollama",
        model: str = "mistral:7b",
        temperature: float = 0.2
    ):
        self.name = name
        self.role = role
        self.ai_provider = ai_provider
        self.model = model
        self.temperature = temperature
        self.status = AgentStatus.IDLE
        self.message_queue: List[AgentMessage] = []
        self.findings: List[Dict] = []
        self._created_at = datetime.now()
    
    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Türkçe: Ajanın özelleştirilmiş system prompt'u"""
        pass
    
    @abstractmethod
    async def analyze(self, context: AgentContext) -> Dict[str, Any]:
        """
        Türkçe: Ana analiz metodu
        
        Args:
            context: Analiz bağlamı (tarama verisi, önceki bulgular, vb.)
            
        Returns:
            Analiz sonuçları dictionary'si
        """
        pass
    
    @abstractmethod
    def build_prompt(self, context: AgentContext) -> str:
        """Türkçe: Context'e göre analiz promptu oluştur"""
        pass
    
    async def send_message(self, to_agent: str, content: Dict, msg_type: str = "request") -> AgentMessage:
        """Türkçe: Başka bir ajana mesaj gönder"""
        message = AgentMessage(
            from_agent=self.name,
            to_agent=to_agent,
            content=content,
            message_type=msg_type
        )
        # Registry üzerinden mesaj iletilecek
        return message
    
    def receive_message(self, message: AgentMessage):
        """Türkçe: Gelen mesajı kuyruğa ekle"""
        self.message_queue.append(message)
    
    def get_pending_messages(self) -> List[AgentMessage]:
        """Türkçe: Bekleyen mesajları al ve kuyruğu temizle"""
        messages = self.message_queue.copy()
        self.message_queue.clear()
        return messages
    
    def add_finding(self, finding: Dict):
        """Türkçe: Bulgu ekle"""
        finding["agent"] = self.name
        finding["found_at"] = datetime.now().isoformat()
        self.findings.append(finding)
    
    def get_status(self) -> Dict:
        """Türkçe: Ajan durum bilgisi"""
        return {
            "name": self.name,
            "role": self.role.value,
            "status": self.status.value,
            "provider": self.ai_provider,
            "model": self.model,
            "findings_count": len(self.findings),
            "pending_messages": len(self.message_queue),
            "created_at": self._created_at.isoformat()
        }
    
    def __repr__(self):
        return f"<{self.__class__.__name__} name='{self.name}' role={self.role.value}>"


class AgentRegistry:
    """
    Türkçe: Ajan kayıt ve keşif sistemi
    
    Tüm aktif ajanları takip eder ve ajanlar arası iletişimi yönetir.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._agents: Dict[str, BaseAgent] = {}
        return cls._instance
    
    def register(self, agent: BaseAgent):
        """Türkçe: Yeni ajan kaydet"""
        self._agents[agent.name] = agent
        print(f"✅ Agent registered: {agent.name} ({agent.role.value})")
    
    def unregister(self, agent_name: str):
        """Türkçe: Ajan kaydını sil"""
        if agent_name in self._agents:
            del self._agents[agent_name]
            print(f"🗑️ Agent unregistered: {agent_name}")
    
    def get(self, agent_name: str) -> Optional[BaseAgent]:
        """Türkçe: İsme göre ajan getir"""
        return self._agents.get(agent_name)
    
    def get_by_role(self, role: AgentRole) -> List[BaseAgent]:
        """Türkçe: Role göre ajanları getir"""
        return [a for a in self._agents.values() if a.role == role]
    
    def get_all(self) -> List[BaseAgent]:
        """Türkçe: Tüm ajanları listele"""
        return list(self._agents.values())
    
    def send_message(self, message: AgentMessage) -> bool:
        """Türkçe: Mesajı hedef ajana ilet"""
        target = self._agents.get(message.to_agent)
        if target:
            target.receive_message(message)
            return True
        return False
    
    def broadcast(self, from_agent: str, content: Dict):
        """Türkçe: Tüm ajanlara mesaj gönder"""
        for agent in self._agents.values():
            if agent.name != from_agent:
                message = AgentMessage(
                    from_agent=from_agent,
                    to_agent=agent.name,
                    content=content,
                    message_type="broadcast"
                )
                agent.receive_message(message)
    
    def get_status(self) -> Dict:
        """Türkçe: Tüm ajanların durumu"""
        return {
            "total_agents": len(self._agents),
            "agents": [a.get_status() for a in self._agents.values()]
        }


# Global registry instance
registry = AgentRegistry()


def get_registry() -> AgentRegistry:
    """Türkçe: Global registry'yi al"""
    return registry
