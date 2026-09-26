"""
Chat History Manager - Kadim AI Service
Türkçe: Konuşma geçmişini yöneten ve context-aware chat sağlayan modül

Bu modül:
1. Chat mesajlarını bellekte ve MongoDB'de tutar
2. Conversation context'i korur (sliding window)
3. Önceki mesajları AI'a aktararak tutarlı yanıtlar sağlar
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from collections import defaultdict
import json

# ============== Models ==============

class ChatMessage(BaseModel):
    """Türkçe: Tek bir chat mesajı"""
    role: str  # 'user', 'assistant', 'system'
    content: str
    timestamp: datetime = None
    metadata: Optional[Dict[str, Any]] = None  # Ek bilgiler (model, provider vs.)
    
    def __init__(self, **data):
        if data.get('timestamp') is None:
            data['timestamp'] = datetime.utcnow()
        super().__init__(**data)


class ConversationContext(BaseModel):
    """Türkçe: Bir tarama/scan için tüm konuşma bağlamı"""
    scan_id: str
    target: Optional[str] = None
    messages: List[ChatMessage] = []
    created_at: datetime = None
    updated_at: datetime = None
    
    # Analiz state
    current_risk_score: Optional[int] = None
    analysis_version: int = 1  # Her güncelleme +1
    
    def __init__(self, **data):
        now = datetime.utcnow()
        if data.get('created_at') is None:
            data['created_at'] = now
        if data.get('updated_at') is None:
            data['updated_at'] = now
        super().__init__(**data)


# ============== In-Memory Store ==============
# Türkçe: Hızlı erişim için bellek cache'i (MongoDB ile senkronize edilir)

_conversation_cache: Dict[str, ConversationContext] = {}

# Sliding window boyutu - Son N mesajı AI'a gönder
MAX_CONTEXT_MESSAGES = 20


def get_conversation(scan_id: str) -> Optional[ConversationContext]:
    """Türkçe: Bellek cache'inden konuşma getir"""
    return _conversation_cache.get(scan_id)


def create_conversation(scan_id: str, target: Optional[str] = None) -> ConversationContext:
    """Türkçe: Yeni konuşma bağlamı oluştur"""
    conv = ConversationContext(
        scan_id=scan_id,
        target=target
    )
    _conversation_cache[scan_id] = conv
    return conv


def add_message(
    scan_id: str, 
    role: str, 
    content: str, 
    metadata: Optional[Dict] = None
) -> ChatMessage:
    """
    Türkçe: Konuşmaya yeni mesaj ekle
    
    Args:
        scan_id: Tarama ID'si
        role: 'user' veya 'assistant'
        content: Mesaj içeriği
        metadata: Opsiyonel ek bilgiler (model, provider vs.)
    """
    conv = get_conversation(scan_id)
    if conv is None:
        conv = create_conversation(scan_id)
    
    message = ChatMessage(
        role=role,
        content=content,
        metadata=metadata
    )
    
    conv.messages.append(message)
    conv.updated_at = datetime.utcnow()
    
    return message


def get_context_messages(scan_id: str, max_messages: int = MAX_CONTEXT_MESSAGES) -> List[Dict]:
    """
    Türkçe: AI'a gönderilecek context mesajlarını getir (sliding window)
    
    Son N mesajı döndürür, role ve content formatında.
    Bu format Ollama ve Claude API'leri ile uyumludur.
    """
    conv = get_conversation(scan_id)
    if conv is None:
        return []
    
    # Son N mesajı al
    recent_messages = conv.messages[-max_messages:]
    
    # API formatına dönüştür
    return [
        {
            "role": msg.role,
            "content": msg.content
        }
        for msg in recent_messages
    ]


def update_analysis_state(scan_id: str, risk_score: Optional[int] = None):
    """Türkçe: Analiz state'ini güncelle (versiyon artır)"""
    conv = get_conversation(scan_id)
    if conv:
        if risk_score is not None:
            conv.current_risk_score = risk_score
        conv.analysis_version += 1
        conv.updated_at = datetime.utcnow()


def get_conversation_summary(scan_id: str) -> Dict:
    """Türkçe: Konuşma özeti (debugging/logging için)"""
    conv = get_conversation(scan_id)
    if conv is None:
        return {"exists": False}
    
    return {
        "exists": True,
        "scan_id": scan_id,
        "target": conv.target,
        "message_count": len(conv.messages),
        "current_risk_score": conv.current_risk_score,
        "analysis_version": conv.analysis_version,
        "created_at": conv.created_at.isoformat() if conv.created_at else None,
        "updated_at": conv.updated_at.isoformat() if conv.updated_at else None
    }


def clear_conversation(scan_id: str):
    """Türkçe: Konuşmayı temizle (yeni analiz için)"""
    if scan_id in _conversation_cache:
        del _conversation_cache[scan_id]


def export_conversation(scan_id: str) -> Optional[Dict]:
    """
    Türkçe: Konuşmayı export et (MongoDB persistence için)
    
    Bu fonksiyon orchestrator tarafından çağrılarak 
    konuşma MongoDB'ye kaydedilebilir.
    """
    conv = get_conversation(scan_id)
    if conv is None:
        return None
    
    return {
        "scan_id": conv.scan_id,
        "target": conv.target,
        "messages": [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat() if msg.timestamp else None,
                "metadata": msg.metadata
            }
            for msg in conv.messages
        ],
        "current_risk_score": conv.current_risk_score,
        "analysis_version": conv.analysis_version,
        "created_at": conv.created_at.isoformat() if conv.created_at else None,
        "updated_at": conv.updated_at.isoformat() if conv.updated_at else None
    }


def import_conversation(data: Dict) -> ConversationContext:
    """
    Türkçe: MongoDB'den konuşmayı import et
    
    Sayfa yenilendiğinde veya servis restart olduğunda
    konuşma geçmişini geri yükler.
    """
    messages = []
    for msg_data in data.get("messages", []):
        msg = ChatMessage(
            role=msg_data["role"],
            content=msg_data["content"],
            timestamp=datetime.fromisoformat(msg_data["timestamp"]) if msg_data.get("timestamp") else datetime.utcnow(),
            metadata=msg_data.get("metadata")
        )
        messages.append(msg)
    
    conv = ConversationContext(
        scan_id=data["scan_id"],
        target=data.get("target"),
        messages=messages,
        current_risk_score=data.get("current_risk_score"),
        analysis_version=data.get("analysis_version", 1),
        created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.utcnow(),
        updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.utcnow()
    )
    
    _conversation_cache[data["scan_id"]] = conv
    return conv


# ============== Context Building Helpers ==============

def build_system_context(scan_data: Dict, analysis_type: str = "security") -> str:
    """
    Türkçe: Sistem context mesajı oluştur
    
    Bu mesaj her konuşmanın başında AI'a gönderilir ve
    rolünü, görevini ve bağlamı tanımlar.
    """
    target = scan_data.get("target", scan_data.get("domain", "unknown"))
    
    system_prompt = f"""Sen Kadim Security Platform'un kıdemli siber güvenlik analistisin.

## ROLÜN
- OWASP Top 10, MITRE ATT&CK, CVE/CWE standartlarına hakimsin
- Penetrasyon testi ve zafiyet değerlendirmesi konusunda 10+ yıl deneyimin var
- Türkçe iletişim kurarsın, teknik terimler İngilizce kalabilir

## GÖREV BAĞLAMI
- Hedef Sistem: `{target}`
- Analiz Türü: {analysis_type}
- Kullanıcı seninle bir güvenlik taramasının sonuçlarını tartışıyor

## KURALLAR
1. Her zaman profesyonel ve teknik bir dil kullan
2. Güvenlik risklerini asla küçümseme
3. Kullanıcı itiraz ederse mantıklı argümanlar sun ama güvenliği riske atma
4. Somut, uygulanabilir öneriler ver
5. CVE numarası, CVSS skoru gibi referanslar ekle (varsa)
6. Risk skorunu güncellerken gerekçe belirt

## YANITLAMA FORMATI
Yanıtlarında şu bölümleri kullan (gerektiğinde):
- **Risk Değerlendirmesi**: Güncel risk skoru ve gerekçesi
- **Kritik Bulgular**: En önemli güvenlik açıkları
- **Öneriler**: Somut çözüm adımları
- **Teknik Detaylar**: CVE, versiyon, PoC bilgileri
"""
    return system_prompt
