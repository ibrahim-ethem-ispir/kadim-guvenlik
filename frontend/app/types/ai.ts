/**
 * AI Analysis Types - v2.0
 * Türkçe: Ollama ve Claude destekli AI analiz tipleri
 * 
 * v2.0 Güncellemeler:
 * - Chat history types
 * - Technical details field
 * - Conversation tracking
 */

export type AIProvider = 'ollama' | 'deepseek' | 'claude' | 'gemini';

export type AnalysisType = 'security' | 'hash' | 'osint' | 'vuln';

export interface AIAnalysisRequest {
    scan_id?: string;
    scan_data?: Record<string, unknown>;
    provider: AIProvider;
    model: string;
    analysis_type: AnalysisType;
}

export interface AIAnalysisResponse {
    provider: string;
    model: string;
    analysis: string;
    risk_score: number | null;
    recommendations: string[];
    critical_findings: string[];
    technical_details?: string[];  // v2.0: Teknik detaylar
    next_steps: string[];
    conversation_id?: string;  // v2.0: Chat history için
    message_count?: number;  // v2.0: Konuşmadaki mesaj sayısı
}

export interface AIChatRequest {
    scan_id: string;
    current_analysis: AIAnalysisResponse;
    user_message: string;
    provider: AIProvider;
    model: string;
    analysis_type: AnalysisType;
    conversation_history?: ChatMessage[];  // v2.0: Geçmiş mesajlar
}

export interface ChatMessage {
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp?: string;
    metadata?: Record<string, unknown>;
}

export interface ChatHistoryResponse {
    exists: boolean;
    scan_id: string;
    target?: string;
    messages: ChatMessage[];
    message_count: number;
    current_risk_score?: number;
    last_updated?: string;
}

export interface AIHealthResponse {
    status: string;
    ollama: string;
    ollama_models?: string[];
    claude: string;
    ollama_url?: string;
}

export interface AIModelsResponse {
    ollama: string[];
    deepseek?: string[];
    claude: string[];
    gemini?: string[];
    error?: string;
}

// DeepSeek Model Listesi (2026) - resmi API'daki geçerli isimler
export const DEEPSEEK_MODELS = [
    { value: 'deepseek-v4-flash', label: 'DeepSeek V4 Flash', description: 'Hızlı & ekonomik (önerilen)' },
    { value: 'deepseek-v4-pro', label: 'DeepSeek V4 Pro', description: 'En güçlü, kompleks görevler' },
    { value: 'deepseek-chat', label: 'DeepSeek Chat', description: 'Legacy alias (v4-flash non-thinking)' },
    { value: 'deepseek-reasoner', label: 'DeepSeek Reasoner', description: 'Reasoning (thinking modu)' },
];

// Model seçenekleri
export const OLLAMA_MODELS = [
    { value: 'mistral:7b', label: 'Mistral 7B', description: 'Hızlı ve dengeli' },
    { value: 'llama3.2:latest', label: 'Llama 3.2', description: 'Meta\'nın en yeni modeli' },
    { value: 'qwen2.5-coder:latest', label: 'Qwen 2.5 Coder', description: 'Kod analizi için optimize' },
    { value: 'deepseek-coder:latest', label: 'DeepSeek Coder', description: 'Güvenlik analizi' },
    { value: 'codellama:latest', label: 'CodeLlama', description: 'Meta kod modeli' },
];

// Güncel Claude Model Listesi (2025) - Anthropic API'da geçerli isimler
export const CLAUDE_MODELS = [
    { value: 'claude-sonnet-4-20250514', label: 'Claude Sonnet 4', description: 'En yeni, dengeli performans' },
    { value: 'claude-opus-4-20250514', label: 'Claude Opus 4', description: 'En güçlü, kompleks görevler' },
    { value: 'claude-3-7-sonnet-20250219', label: 'Claude 3.7 Sonnet', description: 'Hybrid reasoning' },
    { value: 'claude-3-5-sonnet-latest', label: 'Claude 3.5 Sonnet', description: 'Stabil, alias' },
    { value: 'claude-3-5-haiku-latest', label: 'Claude 3.5 Haiku', description: 'Hızlı & ekonomik' },
];

// Güncel Gemini Model Listesi (2025) - Tüm mevcut modeller
export const GEMINI_MODELS = [
    // Gemini 3 Series (En Yeni - Aralık 2025)
    { value: 'gemini-3-pro', label: 'Gemini 3 Pro', description: 'En güçlü, kompleks görevler' },
    { value: 'gemini-3-flash', label: 'Gemini 3 Flash', description: 'Hızlı, genel kullanım' },
    { value: 'gemini-3-deep-think', label: 'Gemini 3 Deep Think', description: 'Derin düşünme, reasoning' },

    // Gemini 2.5 Series (Haziran 2025)
    { value: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro', description: 'Kompleks reasoning, coding' },
    { value: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash', description: 'Hızlı, varsayılan model' },
    { value: 'gemini-2.5-flash-lite', label: 'Gemini 2.5 Flash Lite', description: 'Ekonomik, yüsek concurrency' },

    // Gemini 2.0 Series (Şubat 2025)
    { value: 'gemini-2.0-pro-exp-02-05', label: 'Gemini 2.0 Pro', description: 'Deneysel pro model' },
    { value: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash', description: 'GA, 1M context, hızlı' },
    { value: 'gemini-2.0-flash-exp', label: 'Gemini 2.0 Flash Exp', description: 'Deneysel flash' },
    { value: 'gemini-2.0-flash-lite', label: 'Gemini 2.0 Flash Lite', description: 'Ekonomik versiyon' },
    { value: 'gemini-2.0-flash-thinking-exp', label: 'Gemini 2.0 Thinking', description: 'Derin reasoning' },
    { value: 'gemini-2.0-flash-live-001', label: 'Gemini 2.0 Live', description: 'Canlı/ses API' },

    // Gemini 1.5 Series (Legacy)
    { value: 'gemini-1.5-pro', label: 'Gemini 1.5 Pro', description: '1M context window' },
    { value: 'gemini-1.5-pro-latest', label: 'Gemini 1.5 Pro Latest', description: 'Güncel alias' },
    { value: 'gemini-1.5-flash', label: 'Gemini 1.5 Flash', description: 'Hızlı, ucuz' },
    { value: 'gemini-1.5-flash-latest', label: 'Gemini 1.5 Flash Latest', description: 'Güncel alias' },
];
