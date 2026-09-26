/**
 * AIModelSelector Component
 * Türkçe: Reusable AI model seçici - tüm sayfalarda kullanılabilir
 */

import { useState, useEffect } from 'react';
import { Bot, ChevronDown, Server, Sparkles, Zap, CloudCog } from 'lucide-react';
import { api } from '../services/api';

interface AIModelSelectorProps {
    provider: 'ollama' | 'deepseek' | 'claude' | 'gemini';
    model: string;
    onProviderChange: (provider: 'ollama' | 'deepseek' | 'claude' | 'gemini') => void;
    onModelChange: (model: string) => void;
    compact?: boolean; // Küçük dropdown modu
}

interface ModelInfo {
    id: string;
    name: string;
    description: string;
}

const providerInfo = {
    ollama: {
        name: 'Ollama',
        icon: Server,
        color: 'text-slate-500',
        bg: 'bg-slate-100 dark:bg-slate-800',
    },
    deepseek: {
        name: 'DeepSeek',
        icon: CloudCog,
        color: 'text-indigo-500',
        bg: 'bg-indigo-100 dark:bg-indigo-900/30',
    },
    claude: {
        name: 'Claude',
        icon: Sparkles,
        color: 'text-orange-500',
        bg: 'bg-orange-100 dark:bg-orange-900/30',
    },
    gemini: {
        name: 'Gemini',
        icon: Zap,
        color: 'text-blue-500',
        bg: 'bg-blue-100 dark:bg-blue-900/30',
    },
};

export function AIModelSelector({
    provider,
    model,
    onProviderChange,
    onModelChange,
    compact = false,
}: AIModelSelectorProps) {
    const [isOpen, setIsOpen] = useState(false);
    const [models, setModels] = useState<{
        ollama: ModelInfo[];
        deepseek: ModelInfo[];
        claude: ModelInfo[];
        gemini: ModelInfo[];
    }>({ ollama: [], deepseek: [], claude: [], gemini: [] });

    useEffect(() => {
        const loadModels = async () => {
            try {
                const res = await api.get<{
                    ollama: ModelInfo[];
                    deepseek: ModelInfo[];
                    claude: ModelInfo[];
                    gemini: ModelInfo[];
                }>('/api/settings/ai/models');
                setModels({
                    ollama: res.ollama ?? [],
                    deepseek: res.deepseek ?? [],
                    claude: res.claude ?? [],
                    gemini: res.gemini ?? [],
                });
            } catch (err) {
                console.error('Failed to load AI models:', err);
            }
        };
        loadModels();
    }, []);

    const currentProvider = providerInfo[provider];
    const Icon = currentProvider.icon;
    const availableModels = models[provider] || [];

    if (compact) {
        return (
            <div className="relative inline-flex">
                <button
                    onClick={() => setIsOpen(!isOpen)}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 ${currentProvider.bg} hover:opacity-80 transition-opacity`}
                >
                    <Icon className={`w-4 h-4 ${currentProvider.color}`} />
                    <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                        {currentProvider.name}
                    </span>
                    <ChevronDown className="w-3 h-3 text-slate-400" />
                </button>

                {isOpen && (
                    <>
                        <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
                        <div className="absolute top-full right-0 mt-1 w-48 bg-white dark:bg-slate-800 rounded-lg shadow-xl border border-slate-200 dark:border-slate-700 z-50 overflow-hidden">
                            {(['ollama', 'deepseek', 'claude', 'gemini'] as const).map((p) => {
                                const info = providerInfo[p];
                                const PIcon = info.icon;
                                return (
                                    <button
                                        key={p}
                                        onClick={() => {
                                            onProviderChange(p);
                                            // Auto-select first model of new provider
                                            if (models[p]?.length > 0) {
                                                onModelChange(models[p][0].id);
                                            }
                                            setIsOpen(false);
                                        }}
                                        className={`w-full flex items-center gap-2 px-3 py-2 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors ${provider === p ? 'bg-emerald-50 dark:bg-emerald-900/20' : ''
                                            }`}
                                    >
                                        <PIcon className={`w-4 h-4 ${info.color}`} />
                                        <span className="text-sm text-slate-700 dark:text-slate-300">{info.name}</span>
                                        {provider === p && (
                                            <span className="ml-auto text-emerald-500 text-xs">✓</span>
                                        )}
                                    </button>
                                );
                            })}
                        </div>
                    </>
                )}
            </div>
        );
    }

    // Full panel mode
    return (
        <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2 mb-2">
                <Bot className="w-4 h-4 text-emerald-500" />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">AI Analiz</span>
            </div>

            {/* Provider Selection */}
            <div className="flex gap-2">
                {(['ollama', 'deepseek', 'claude', 'gemini'] as const).map((p) => {
                    const info = providerInfo[p];
                    const PIcon = info.icon;
                    const isSelected = provider === p;
                    return (
                        <button
                            key={p}
                            onClick={() => {
                                onProviderChange(p);
                                if (models[p]?.length > 0) {
                                    onModelChange(models[p][0].id);
                                }
                            }}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg border transition-all ${isSelected
                                    ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20'
                                    : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600'
                                }`}
                        >
                            <PIcon className={`w-4 h-4 ${isSelected ? 'text-emerald-500' : info.color}`} />
                            <span
                                className={`text-sm font-medium ${isSelected ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-600 dark:text-slate-400'
                                    }`}
                            >
                                {info.name}
                            </span>
                        </button>
                    );
                })}
            </div>

            {/* Model Selection */}
            <select
                value={model}
                onChange={(e) => onModelChange(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm"
            >
                {availableModels.length > 0 ? (
                    availableModels.map((m) => (
                        <option key={m.id} value={m.id}>
                            {m.name}
                        </option>
                    ))
                ) : (
                    <option value={model}>{model}</option>
                )}
            </select>
        </div>
    );
}

// Hook for default AI settings — artık `.env` TEK doğruluk kaynağı (DB değil).
// AI-service (rapor/analiz) varsayılan sağlayıcı+modelini /ai/env-status'tan okur.
// Not: ai-service artık deepseek'i de destekliyor → tip 4 sağlayıcıyı kapsar (aksi halde
// env-status 'deepseek' döndürünce union'a zorla-cast edilir ve consumer'lar şaşırır).
export type DefaultAIProvider = 'ollama' | 'deepseek' | 'claude' | 'gemini';
const DEFAULT_AI_PROVIDERS: DefaultAIProvider[] = ['ollama', 'deepseek', 'claude', 'gemini'];

export function useDefaultAI() {
    const [defaultProvider, setDefaultProvider] = useState<DefaultAIProvider>('ollama');
    const [defaultModel, setDefaultModel] = useState('mistral:7b');

    useEffect(() => {
        const loadDefaults = async () => {
            try {
                const status = await api.get<{ ai_service_provider: string; ai_service_model: string }>(
                    '/api/settings/ai/env-status'
                );
                // Yalnız bilinen bir sağlayıcıysa uygula (beklenmedik değeri sessizce yok say).
                if (DEFAULT_AI_PROVIDERS.includes(status.ai_service_provider as DefaultAIProvider)) {
                    setDefaultProvider(status.ai_service_provider as DefaultAIProvider);
                }
                if (status.ai_service_model) {
                    setDefaultModel(status.ai_service_model);
                }
            } catch {
                // Hata durumunda derlenmiş varsayılanları kullan
            }
        };
        loadDefaults();
    }, []);

    return { defaultProvider, defaultModel };
}
