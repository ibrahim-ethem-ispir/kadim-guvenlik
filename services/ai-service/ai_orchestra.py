"""
🧠 AI Orchestra - Multi-AI Router System
Türkçe: Çoklu AI modeli orkestrasyon sistemi

AI Brain Farkı:
- Tek AI yerine Multi-AI Orchestra
- Her task için optimal model seçimi
- Privacy-aware routing (local vs cloud)
- Cost optimization
- Capability-based routing

Desteklenen Modeller:
- Gemini 2.0 Flash (Fast strategy, huge context)
- Claude 3.5 Sonnet (Best code generation)
- Ollama/Dolphin (Uncensored, private)
- GPT-4o (Multimodal)
"""

import os
import asyncio
import httpx
from typing import Dict, Any, List, Optional, Literal, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json

# Merkezi model konfigürasyonu
from ai_config import (
    VALID_GEMINI_MODELS, GEMINI_MODEL_MAPPING, DEFAULT_GEMINI_MODEL,
    VALID_CLAUDE_MODELS, CLAUDE_MODEL_MAPPING, DEFAULT_CLAUDE_MODEL,
    validate_gemini_model, validate_claude_model
)


class AICapability(Enum):
    """AI yetenekleri"""
    STRATEGY = "strategy"           # Strateji ve planlama
    CODE_GEN = "code_generation"    # Kod üretimi (exploit, tools)
    OFFENSIVE = "offensive"         # Saldırı odaklı (uncensored)
    RAPID = "rapid"                 # Hızlı batch işlemler
    VISUAL = "visual"               # Görsel analiz
    REASONING = "reasoning"         # Derin düşünme
    LARGE_CONTEXT = "large_context" # Büyük context (1M+ token)


class TaskPriority(Enum):
    """Task öncelikleri"""
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class SecurityTask:
    """Güvenlik task'ı tanımı"""
    task_id: str
    task_type: str
    content: Dict[str, Any]
    requires_privacy: bool = False
    is_offensive: bool = False
    context_tokens: int = 0
    priority: TaskPriority = TaskPriority.NORMAL
    capabilities_needed: List[AICapability] = field(default_factory=list)
    preferred_model: Optional[str] = None  # User's selected model from AI Settings
    allow_fallback: bool = False  # False = kullanıcının seçtiği model çalışmazsa HATA ver
    

@dataclass
class AIResponse:
    """AI yanıt formatı"""
    model: str
    provider: str
    content: str
    tokens_used: int
    latency_ms: float
    cost_estimate: float
    raw_response: Optional[Dict] = None


@dataclass
class ModelConfig:
    """Model konfigürasyonu"""
    name: str
    provider: str
    capabilities: List[AICapability]
    max_context: int
    cost_per_1k_tokens: float
    avg_latency_ms: int
    is_local: bool = False
    is_uncensored: bool = False


# Model Konfigürasyonları
MODEL_CONFIGS: Dict[str, ModelConfig] = {
    # Gemini 3 Series (EN YENİ!)
    "gemini-3-pro-preview": ModelConfig(
        name="gemini-3-pro-preview",
        provider="gemini",
        capabilities=[AICapability.REASONING, AICapability.STRATEGY, AICapability.VISUAL, AICapability.LARGE_CONTEXT, AICapability.CODE_GEN, AICapability.OFFENSIVE],
        max_context=2000000,
        cost_per_1k_tokens=0.0005,
        avg_latency_ms=2500
    ),
    "gemini-3-flash-preview": ModelConfig(
        name="gemini-3-flash-preview",
        provider="gemini",
        capabilities=[AICapability.STRATEGY, AICapability.RAPID, AICapability.VISUAL, AICapability.LARGE_CONTEXT, AICapability.CODE_GEN, AICapability.OFFENSIVE],
        max_context=2000000,
        cost_per_1k_tokens=0.0003,
        avg_latency_ms=600
    ),
    # Gemini 2 Series
    "gemini-2.0-flash": ModelConfig(
        name="gemini-2.0-flash",
        provider="gemini",
        capabilities=[AICapability.STRATEGY, AICapability.RAPID, AICapability.VISUAL, AICapability.LARGE_CONTEXT, AICapability.CODE_GEN, AICapability.OFFENSIVE],
        max_context=1000000,
        cost_per_1k_tokens=0.00015,
        avg_latency_ms=500
    ),
    "gemini-2.5-pro": ModelConfig(
        name="gemini-2.5-pro",  # Correct model name from API
        provider="gemini",
        capabilities=[AICapability.REASONING, AICapability.STRATEGY, AICapability.LARGE_CONTEXT, AICapability.CODE_GEN, AICapability.OFFENSIVE],
        max_context=1000000,
        cost_per_1k_tokens=0.0003,
        avg_latency_ms=2000
    ),
    "gemini-2.5-flash": ModelConfig(
        name="gemini-2.5-flash",  # Correct model name from API
        provider="gemini",
        capabilities=[AICapability.STRATEGY, AICapability.RAPID, AICapability.LARGE_CONTEXT, AICapability.CODE_GEN, AICapability.OFFENSIVE],
        max_context=1000000,
        cost_per_1k_tokens=0.0002,
        avg_latency_ms=800
    ),
    "gemini-1.5-pro": ModelConfig(
        name="gemini-1.5-pro-latest",  # Using -latest suffix for API compatibility
        provider="gemini",
        capabilities=[AICapability.STRATEGY, AICapability.REASONING, AICapability.LARGE_CONTEXT, AICapability.CODE_GEN, AICapability.OFFENSIVE],
        max_context=2000000,
        cost_per_1k_tokens=0.00125,
        avg_latency_ms=1500
    ),
    
    # Claude Models
    "claude-3.5-sonnet": ModelConfig(
        name="claude-3-5-sonnet-latest",
        provider="claude",
        capabilities=[AICapability.CODE_GEN, AICapability.REASONING, AICapability.STRATEGY],
        max_context=200000,
        cost_per_1k_tokens=0.003,
        avg_latency_ms=1000
    ),
    "claude-sonnet-4": ModelConfig(
        name="claude-sonnet-4-20250514",
        provider="claude",
        capabilities=[AICapability.CODE_GEN, AICapability.REASONING, AICapability.STRATEGY],
        max_context=200000,
        cost_per_1k_tokens=0.003,
        avg_latency_ms=1000
    ),
    
    # Local Models (Ollama)
    "dolphin-mixtral": ModelConfig(
        name="dolphin-mixtral:8x7b",
        provider="ollama",
        capabilities=[AICapability.OFFENSIVE, AICapability.CODE_GEN],
        max_context=32000,
        cost_per_1k_tokens=0.0,
        avg_latency_ms=2000,
        is_local=True,
        is_uncensored=True
    ),
    "mistral": ModelConfig(
        name="mistral:7b",
        provider="ollama",
        capabilities=[AICapability.RAPID, AICapability.CODE_GEN],
        max_context=32000,
        cost_per_1k_tokens=0.0,
        avg_latency_ms=800,
        is_local=True
    ),
    "codestral": ModelConfig(
        name="codestral:latest",
        provider="ollama",
        capabilities=[AICapability.CODE_GEN, AICapability.RAPID],
        max_context=32000,
        cost_per_1k_tokens=0.0,
        avg_latency_ms=1000,
        is_local=True
    ),
    "qwen2.5-coder": ModelConfig(
        name="qwen2.5-coder:latest",
        provider="ollama",
        capabilities=[AICapability.CODE_GEN, AICapability.RAPID],
        max_context=128000,
        cost_per_1k_tokens=0.0,
        avg_latency_ms=900,
        is_local=True
    ),
}


class AIOrchestra:
    """
    🎭 Multi-AI Orchestra
    
    Türkçe: Her task için optimal AI modelini seçen ve yönlendiren akıllı router.
    
    Seçim Kriterleri:
    1. Privacy requirement → Local model (Ollama)
    2. Offensive content → Uncensored model (Dolphin)
    3. Code generation → Claude Sonnet
    4. Large context → Gemini
    5. Rapid processing → Flash Lite
    6. Deep reasoning → Thinking model
    """
    
    def __init__(self):
        # TEK kaynak: llm_env_config (.env). Tekrarlı os.getenv kaldırıldı — değerler aynı.
        from llm_env_config import OLLAMA_URL, CLAUDE_API_KEY, GEMINI_API_KEY
        self.ollama_url = OLLAMA_URL
        self.claude_api_key = CLAUDE_API_KEY
        self.gemini_api_key = GEMINI_API_KEY
        
        # API Key durum loglaması
        print(f"🎭 AI Orchestra initialized:")
        print(f"   - Ollama URL: {self.ollama_url}")
        print(f"   - Claude API Key: {'✅ Set' if self.claude_api_key else '❌ Missing'}")
        print(f"   - Gemini API Key: {'✅ Set' if self.gemini_api_key else '❌ Missing'}")
        
        self.usage_stats: Dict[str, Dict] = {}
        self.routing_history: List[Dict] = []
        
    async def route_task(self, task: SecurityTask) -> AIResponse:
        """
        Task'ı kullanıcının seçtiği AI modeline yönlendir.

        Routing Logic:
        1. Kullanıcının preferred_model'i varsa → ONU KULLAN
        2. Yoksa optimal model seç
        3. allow_fallback=False ise → Model çalışmazsa NET HATA VER
        4. allow_fallback=True ise → Fallback dene (eski davranış)
        """

        start_time = datetime.now()

        # 1. Model seçimi
        selected_model = self._select_optimal_model(task)
        print(f"   🎯 Selected model: {selected_model} (preferred: {task.preferred_model}, fallback: {task.allow_fallback})")

        # 2. Prompt hazırlama
        prompt = self._prepare_prompt(task)

        # 3. Model'e göre çağrı
        if selected_model not in MODEL_CONFIGS:
            # Dinamik model ekleme (kullanıcı yeni model seçmiş olabilir)
            config = self._create_dynamic_config(selected_model)
            if config:
                MODEL_CONFIGS[selected_model] = config
            else:
                error_msg = f"❌ Model bulunamadı: {selected_model}. Lütfen geçerli bir model seçin."
                print(error_msg)
                return AIResponse(
                    model=selected_model,
                    provider="unknown",
                    content=error_msg,
                    tokens_used=0,
                    latency_ms=0,
                    cost_estimate=0,
                    raw_response={"error": True, "message": error_msg}
                )

        config = MODEL_CONFIGS[selected_model]
        response = await self._call_model(config, prompt)

        # 4. HATA KONTROLÜ
        if self._is_error_response(response):
            error_content = response.get("content", "Bilinmeyen hata")

            # allow_fallback=False → Kullanıcının seçtiği model çalışmadı, NET HATA VER
            if not task.allow_fallback:
                error_msg = f"❌ Model hatası [{selected_model}]: {error_content}\n\n" \
                           f"💡 Çözüm önerileri:\n" \
                           f"  - Ollama: 'ollama serve' çalışıyor mu?\n" \
                           f"  - Claude: API key geçerli mi? Kredi var mı?\n" \
                           f"  - Gemini: API key geçerli mi? Quota aşıldı mı?\n\n" \
                           f"Farklı bir model seçerek tekrar deneyin."
                print(f"   ❌ Model failed, NO FALLBACK (user choice): {error_content}")

                return AIResponse(
                    model=config.name,
                    provider=config.provider,
                    content=error_msg,
                    tokens_used=0,
                    latency_ms=(datetime.now() - start_time).total_seconds() * 1000,
                    cost_estimate=0,
                    raw_response={"error": True, "message": error_msg, "original_error": error_content}
                )

            # allow_fallback=True → Eski davranış, fallback dene
            print(f"   ⚠️ Primary model {selected_model} failed, trying fallback (allowed)...")

            # Fallback priority: Local first, then cloud
            fallback_models = ["mistral", "qwen2.5-coder", "gemini-2.0-flash", "gemini-1.5-pro"]

            for fallback_name in fallback_models:
                if fallback_name == selected_model:
                    continue

                if fallback_name not in MODEL_CONFIGS:
                    continue

                fallback_config = MODEL_CONFIGS[fallback_name]
                print(f"   🔄 Retrying with {fallback_name}...")

                response = await self._call_model(fallback_config, prompt)

                if not self._is_error_response(response):
                    selected_model = fallback_name
                    config = fallback_config
                    print(f"   ✅ Fallback to {fallback_name} successful")
                    break

        # 5. Metrikleri kaydet
        latency = (datetime.now() - start_time).total_seconds() * 1000

        self._record_usage(selected_model, task, latency)

        return AIResponse(
            model=config.name,
            provider=config.provider,
            content=response.get("content", ""),
            tokens_used=response.get("tokens", 0),
            latency_ms=latency,
            cost_estimate=self._calculate_cost(config, response.get("tokens", 0)),
            raw_response=response
        )

    def _create_dynamic_config(self, model_name: str) -> Optional[ModelConfig]:
        """Kullanıcının seçtiği model için dinamik config oluştur"""
        model_lower = model_name.lower()

        # Gemini modelleri
        if "gemini" in model_lower:
            validated, _ = validate_gemini_model(model_name)
            return ModelConfig(
                name=validated,
                provider="gemini",
                capabilities=[AICapability.STRATEGY, AICapability.CODE_GEN, AICapability.LARGE_CONTEXT],
                max_context=1000000,
                cost_per_1k_tokens=0.0002,
                avg_latency_ms=1000
            )

        # Claude modelleri
        if "claude" in model_lower:
            validated, _ = validate_claude_model(model_name)
            return ModelConfig(
                name=validated,
                provider="claude",
                capabilities=[AICapability.CODE_GEN, AICapability.REASONING, AICapability.STRATEGY],
                max_context=200000,
                cost_per_1k_tokens=0.003,
                avg_latency_ms=1000
            )

        # Ollama modelleri (local)
        return ModelConfig(
            name=model_name,
            provider="ollama",
            capabilities=[AICapability.CODE_GEN, AICapability.RAPID],
            max_context=32000,
            cost_per_1k_tokens=0.0,
            avg_latency_ms=1000,
            is_local=True
        )
    
    async def _call_model(self, config: ModelConfig, prompt: str) -> Dict:
        """Call the appropriate model based on provider"""
        if config.provider == "ollama":
            return await self._call_ollama(config.name, prompt)
        elif config.provider == "claude":
            return await self._call_claude(config.name, prompt)
        elif config.provider == "gemini":
            return await self._call_gemini(config.name, prompt)
        else:
            return {"content": f"Unknown provider: {config.provider}", "tokens": 0, "error": True}
    
    def _is_error_response(self, response: Dict) -> bool:
        """Check if response indicates an error"""
        content = response.get("content", "")
        if response.get("error"):
            return True
        if "error:" in content.lower() or "error " in content.lower():
            return True
        if "401" in content or "403" in content or "429" in content:
            return True
        if "not configured" in content.lower():
            return True
        return False
    
    def _select_optimal_model(self, task: SecurityTask) -> str:
        """
        Task için optimal modeli seç.
        
        Öncelik sırası:
        0. User's preferred_model (AI Settings'ten) → ALWAYS FIRST
        1. Privacy/Offline → Local
        2. Offensive → Uncensored
        3. Code → Claude
        4. Large context → Gemini
        5. Rapid → Flash
        """
        
        # 🎯 PRIORITY #0: User's preferred model from AI Settings
        if task.preferred_model:
            # Try to find in MODEL_CONFIGS
            if task.preferred_model in MODEL_CONFIGS:
                print(f"   🎯 Using user's preferred model: {task.preferred_model}")
                return task.preferred_model
            
            # Check if it's a model name (not key)
            for key, config in MODEL_CONFIGS.items():
                if config.name == task.preferred_model or task.preferred_model in config.name:
                    print(f"   🎯 Using user's preferred model: {key} ({config.name})")
                    return key
            
            # Model not in configs - add it dynamically for gemini
            if "gemini" in task.preferred_model.lower():
                print(f"   🎯 Using user's custom Gemini model: {task.preferred_model}")
                # Add to configs dynamically
                MODEL_CONFIGS[task.preferred_model] = ModelConfig(
                    name=task.preferred_model,
                    provider="gemini",
                    capabilities=[AICapability.STRATEGY, AICapability.CODE_GEN, AICapability.OFFENSIVE, AICapability.LARGE_CONTEXT],
                    max_context=1000000,
                    cost_per_1k_tokens=0.0002,
                    avg_latency_ms=1000
                )
                return task.preferred_model
        
        candidates: List[tuple] = []  # (model_name, score)
        
        for model_name, config in MODEL_CONFIGS.items():
            score = 0
            
            # Privacy requirement
            if task.requires_privacy:
                if config.is_local:
                    score += 100
                else:
                    continue  # Skip cloud models
            
            # Offensive content
            if task.is_offensive:
                if config.is_uncensored:
                    score += 100
                elif not config.is_local:
                    score -= 50  # Cloud models may refuse
            
            # Context size
            if task.context_tokens > config.max_context:
                continue  # Model can't handle
            
            # Capability match
            for needed in task.capabilities_needed:
                if needed in config.capabilities:
                    score += 20
            
            # Cost optimization (prefer cheaper)
            score -= config.cost_per_1k_tokens * 10
            
            # Latency (prefer faster for high priority)
            if task.priority == TaskPriority.CRITICAL:
                score -= config.avg_latency_ms / 100
            
            candidates.append((model_name, score))
        
        if not candidates:
            # Fallback to default
            return "mistral"
        
        # En yüksek skorlu modeli seç
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]
    
    def _prepare_prompt(self, task: SecurityTask) -> str:
        """Task içeriğinden prompt oluştur"""
        
        base_prompt = f"""
Sen bir siber güvenlik uzmanısın. Aşağıdaki görevi analiz et ve yanıtla.

## Görev Tipi: {task.task_type}

## İçerik:
{json.dumps(task.content, indent=2, ensure_ascii=False)}

## Beklenen Çıktı:
- Yapılandırılmış analiz
- Teknik detaylar
- Aksiyon önerileri
- Risk değerlendirmesi
"""
        return base_prompt
    
    async def _call_ollama(self, model: str, prompt: str) -> Dict:
        """Ollama API çağrısı"""
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.2,
                            "num_predict": 4096
                        }
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "content": data.get("response", ""),
                        "tokens": data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
                    }
                else:
                    return {"content": f"Ollama error: {response.status_code}", "tokens": 0}
                    
        except Exception as e:
            return {"content": f"Ollama connection error: {str(e)}", "tokens": 0}
    
    async def _call_claude(self, model: str, prompt: str) -> Dict:
        """Claude API çağrısı"""
        if not self.claude_api_key:
            return {"content": "Claude API key not configured", "tokens": 0}
        
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.claude_api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    },
                    json={
                        "model": model,
                        "max_tokens": 4096,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.2
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    content = ""
                    if data.get("content"):
                        content = data["content"][0].get("text", "")
                    
                    usage = data.get("usage", {})
                    tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                    
                    return {"content": content, "tokens": tokens}
                else:
                    return {"content": f"Claude error: {response.status_code}", "tokens": 0}
                    
        except Exception as e:
            return {"content": f"Claude connection error: {str(e)}", "tokens": 0}
    
    async def _call_gemini(self, model: str, prompt: str) -> Dict:
        """Gemini API çağrısı - geliştirilmiş hata yönetimi"""
        if not self.gemini_api_key:
            error_msg = "❌ GEMINI_API_KEY tanımlı değil. Dashboard → AI Settings → Gemini API Key girin."
            print(error_msg)
            return {"content": error_msg, "tokens": 0, "error": True, "error_type": "missing_api_key"}
        
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    params={"key": self.gemini_api_key},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.2,
                            "maxOutputTokens": 8192
                        }
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    content = ""
                    
                    if data.get("candidates"):
                        candidate = data["candidates"][0]
                        # Safety filter check
                        if candidate.get("finishReason") == "SAFETY":
                            print("⚠️ Gemini: İçerik güvenlik filtresine takıldı")
                            return {"content": "⚠️ İçerik güvenlik filtresine takıldı", "tokens": 0, "error": True}
                        if candidate.get("content", {}).get("parts"):
                            content = candidate["content"]["parts"][0].get("text", "")
                    
                    if not content:
                        print(f"⚠️ Gemini boş yanıt döndü: {data}")
                        return {"content": "Gemini boş yanıt döndü - model yanıt üretemedi", "tokens": 0, "error": True}
                    
                    usage = data.get("usageMetadata", {})
                    tokens = usage.get("totalTokenCount", 0)
                    
                    return {"content": content, "tokens": tokens}
                elif response.status_code == 400:
                    error_detail = response.json().get("error", {}).get("message", "Bilinmeyen hata")
                    print(f"❌ Gemini 400 hatası: {error_detail}")
                    return {"content": f"Gemini API hatası: {error_detail}", "tokens": 0, "error": True}
                elif response.status_code == 403:
                    print("❌ Gemini 403: API Key geçersiz veya yetkisiz")
                    return {"content": "❌ Gemini API Key geçersiz veya yetkisiz", "tokens": 0, "error": True}
                elif response.status_code == 429:
                    print("⚠️ Gemini 429: Rate limit aşıldı")
                    return {"content": "⚠️ Rate limit aşıldı, lütfen bekleyin", "tokens": 0, "error": True}
                else:
                    print(f"❌ Gemini HTTP {response.status_code}: {response.text[:200]}")
                    return {"content": f"Gemini error: {response.status_code}", "tokens": 0, "error": True}
                    
        except httpx.TimeoutException:
            print("⏱️ Gemini timeout (120s)")
            return {"content": "⏱️ Gemini yanıt zaman aşımı (120s)", "tokens": 0, "error": True}
        except Exception as e:
            print(f"❌ Gemini bağlantı hatası: {str(e)}")
            return {"content": f"Gemini connection error: {str(e)}", "tokens": 0, "error": True}
    
    def _calculate_cost(self, config: ModelConfig, tokens: int) -> float:
        """Maliyet hesapla"""
        return (tokens / 1000) * config.cost_per_1k_tokens
    
    def _record_usage(self, model: str, task: SecurityTask, latency: float):
        """Kullanım istatistiklerini kaydet"""
        if model not in self.usage_stats:
            self.usage_stats[model] = {
                "calls": 0,
                "total_latency": 0,
                "tasks": []
            }
        
        self.usage_stats[model]["calls"] += 1
        self.usage_stats[model]["total_latency"] += latency
        self.usage_stats[model]["tasks"].append(task.task_type)
        
        self.routing_history.append({
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "task_type": task.task_type,
            "latency_ms": latency
        })
    
    def get_stats(self) -> Dict:
        """Kullanım istatistiklerini döndür - API durum bilgisi ile"""
        return {
            "usage_by_model": self.usage_stats,
            "total_routing_decisions": len(self.routing_history),
            "recent_routings": self.routing_history[-10:],
            "api_status": {
                "gemini_configured": bool(self.gemini_api_key),
                "claude_configured": bool(self.claude_api_key),
                "ollama_url": self.ollama_url
            }
        }


# ============== Specialized Routers ==============

class StrategyRouter(AIOrchestra):
    """Strateji ve planlama için özelleştirilmiş router"""
    
    async def get_attack_strategy(self, target_info: Dict) -> AIResponse:
        """Hedef için saldırı stratejisi oluştur"""
        task = SecurityTask(
            task_id=f"strategy_{datetime.now().timestamp()}",
            task_type="attack_strategy",
            content=target_info,
            capabilities_needed=[AICapability.STRATEGY, AICapability.REASONING],
            priority=TaskPriority.HIGH
        )
        return await self.route_task(task)


class ExploitRouter(AIOrchestra):
    """Exploit geliştirme için özelleştirilmiş router"""
    
    async def generate_exploit(self, vulnerability: Dict) -> AIResponse:
        """Zafiyet için exploit kodu üret"""
        task = SecurityTask(
            task_id=f"exploit_{datetime.now().timestamp()}",
            task_type="exploit_generation",
            content=vulnerability,
            is_offensive=True,
            requires_privacy=True,  # Exploit kodları local'de kalsın
            capabilities_needed=[AICapability.CODE_GEN, AICapability.OFFENSIVE],
            priority=TaskPriority.HIGH
        )
        return await self.route_task(task)


class AnalysisRouter(AIOrchestra):
    """Analiz ve rapor için özelleştirilmiş router"""
    
    async def analyze_scan_results(self, scan_data: Dict) -> AIResponse:
        """Tarama sonuçlarını analiz et"""
        # Context size tahmini
        context_estimate = len(json.dumps(scan_data)) // 4  # Rough token estimate
        
        task = SecurityTask(
            task_id=f"analysis_{datetime.now().timestamp()}",
            task_type="scan_analysis",
            content=scan_data,
            context_tokens=context_estimate,
            capabilities_needed=[AICapability.STRATEGY, AICapability.LARGE_CONTEXT],
            priority=TaskPriority.NORMAL
        )
        return await self.route_task(task)


# Global Orchestra instance
_orchestra: Optional[AIOrchestra] = None


def get_orchestra() -> AIOrchestra:
    """Global orchestra instance'ı al"""
    global _orchestra
    if _orchestra is None:
        _orchestra = AIOrchestra()
    return _orchestra


def get_strategy_router() -> StrategyRouter:
    """Strategy router al"""
    return StrategyRouter()


def get_exploit_router() -> ExploitRouter:
    """Exploit router al"""
    return ExploitRouter()


def get_analysis_router() -> AnalysisRouter:
    """Analysis router al"""
    return AnalysisRouter()
