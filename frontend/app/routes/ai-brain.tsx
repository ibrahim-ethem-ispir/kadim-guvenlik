/**
 * AI Brain Dashboard - Minimal v2
 * Sadece calisan endpoint'ler:
 * - /brain/status
 * - /brain/healthcheck/model|ollama|claude|gemini
 * - /brain/models/available
 * - /brain/analyze (smart analysis)
 * - /brain/analyze/v2 (pipeline analysis)
 *
 * Kaldirilan (backend silindi): phantom, zeroday, tools, chains, memory
 */

import { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
    Brain, Shield, AlertTriangle,
    Loader2, CheckCircle, XCircle,
    Activity, Cpu, Bot, Server,
    RefreshCw, Zap
} from 'lucide-react';

// ============== Types ==============

interface BrainStatus {
    status: string;
    components: Record<string, string>;
    capabilities: string[];
    model_stats: any;
}

interface ModelInfo {
    id: string;
    name: string;
}

interface ModelsResponse {
    gemini: ModelInfo[];
    claude: ModelInfo[];
    ollama: ModelInfo[];
    ollama_status: string;
}

interface HealthResult {
    available: boolean;
    model: string;
    provider: string;
    error?: string;
    latency_ms?: number;
}

// ============== Component ==============

export default function AIBrain() {
    const [brainStatus, setBrainStatus] = useState<BrainStatus | null>(null);
    const [models, setModels] = useState<ModelsResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Healthcheck
    const [selectedModel, setSelectedModel] = useState('');
    const [healthLoading, setHealthLoading] = useState(false);
    const [healthResult, setHealthResult] = useState<HealthResult | null>(null);

    // Smart Analysis
    const [analysisInput, setAnalysisInput] = useState('');
    const [analysisLoading, setAnalysisLoading] = useState(false);
    const [analysisResult, setAnalysisResult] = useState<any>(null);

    useEffect(() => {
        Promise.all([loadBrainStatus(), loadModels()]).finally(() => setLoading(false));
    }, []);

    const loadBrainStatus = async () => {
        try {
            const data = await api.get<BrainStatus>('/api/ai/brain/status');
            setBrainStatus(data);
        } catch (e) {
            console.error('Brain status yuklenemedi:', e);
            setError('Brain servisine baglanamadi');
        }
    };

    const loadModels = async () => {
        try {
            const data = await api.get<ModelsResponse>('/api/ai/brain/models/available');
            setModels(data);
            // Auto-select first model
            if (!selectedModel) {
                if (data.ollama_status === 'online' && data.ollama.length > 0) {
                    setSelectedModel(data.ollama[0].id);
                } else if (data.gemini.length > 0) {
                    setSelectedModel(data.gemini[0].id);
                } else if (data.claude.length > 0) {
                    setSelectedModel(data.claude[0].id);
                }
            }
        } catch (e) {
            console.error('Model listesi yuklenemedi:', e);
        }
    };

    const testModel = async () => {
        if (!selectedModel) return;
        setHealthLoading(true);
        setHealthResult(null);
        try {
            const result = await api.post<HealthResult>('/api/ai/brain/healthcheck/model', { model: selectedModel });
            setHealthResult(result);
        } catch (e: any) {
            setHealthResult({ available: false, model: selectedModel, provider: 'unknown', error: e.message });
        } finally {
            setHealthLoading(false);
        }
    };

    const runAnalysis = async () => {
        if (!analysisInput.trim()) return;
        setAnalysisLoading(true);
        setAnalysisResult(null);
        try {
            let scanData: any;
            try {
                scanData = JSON.parse(analysisInput);
            } catch {
                scanData = { raw_text: analysisInput, type: 'freeform' };
            }
            const result = await api.post<any>('/api/ai/brain/analyze', {
                scan_data: scanData,
                analysis_type: 'comprehensive',
                preferred_model: selectedModel || undefined,
            });
            setAnalysisResult(result);
        } catch (e: any) {
            setError(e.message || 'Analiz basarisiz');
        } finally {
            setAnalysisLoading(false);
        }
    };

    const totalModels = (models?.gemini.length || 0) + (models?.claude.length || 0) + (models?.ollama.length || 0);

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[400px]">
                <Loader2 className="w-8 h-8 animate-spin text-purple-500" />
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h1 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Brain className="w-7 h-7 text-purple-500" />
                        AI Brain
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1 text-sm">
                        Multi-AI Orchestra | Model Healthcheck | Smart Analysis
                    </p>
                </div>

                <div className="flex items-center gap-3">
                    <button
                        onClick={() => { loadBrainStatus(); loadModels(); }}
                        className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                        title="Yenile"
                    >
                        <RefreshCw className="w-4 h-4 text-slate-500" />
                    </button>
                    <div className={`px-4 py-2 rounded-lg border flex items-center gap-2 ${
                        brainStatus?.status === 'operational'
                            ? 'bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30 text-emerald-700 dark:text-emerald-400'
                            : brainStatus?.status === 'limited'
                                ? 'bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/30 text-amber-700 dark:text-amber-400'
                                : 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-400'
                    }`}>
                        {brainStatus?.status === 'operational' ? <CheckCircle className="w-4 h-4" /> :
                         brainStatus?.status === 'limited' ? <AlertTriangle className="w-4 h-4" /> :
                         <XCircle className="w-4 h-4" />}
                        <span className="text-sm font-medium">
                            {brainStatus?.status === 'operational' ? 'Aktif' :
                             brainStatus?.status === 'limited' ? 'Sinirli' : 'Kapali'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Error Banner */}
            {error && (
                <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-4 flex items-center gap-3">
                    <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0" />
                    <p className="text-red-700 dark:text-red-400 text-sm flex-1">{error}</p>
                    <button onClick={() => setError(null)} className="p-1 hover:bg-red-100 dark:hover:bg-red-500/20 rounded">
                        <XCircle className="w-4 h-4 text-red-500" />
                    </button>
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Brain Status */}
                <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-6">
                    <h3 className="font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                        <Cpu className="w-5 h-5 text-purple-500" />
                        Bilesenler
                    </h3>
                    <div className="space-y-3">
                        {brainStatus?.components && Object.entries(brainStatus.components).map(([name, status]) => (
                            <div key={name} className="flex items-center justify-between">
                                <span className="text-sm text-slate-600 dark:text-slate-400 capitalize">
                                    {name.replace(/_/g, ' ')}
                                </span>
                                <span className={`text-xs px-2 py-1 rounded-full ${
                                    status === 'active'
                                        ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400'
                                        : 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400'
                                }`}>
                                    {status}
                                </span>
                            </div>
                        ))}
                    </div>

                    {/* Capabilities */}
                    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800">
                        <p className="text-xs text-slate-500 mb-2">Yetenekler</p>
                        <div className="flex flex-wrap gap-1.5">
                            {brainStatus?.capabilities?.map(cap => (
                                <span key={cap} className="text-xs px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 rounded-full">
                                    {cap.replace(/_/g, ' ')}
                                </span>
                            ))}
                        </div>
                    </div>

                    {/* API Stats */}
                    {brainStatus?.model_stats?.api_status && (
                        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800">
                            <p className="text-xs text-slate-500 mb-2">API Durumu</p>
                            <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-slate-600 dark:text-slate-400">Gemini</span>
                                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                                        brainStatus.model_stats.api_status.gemini_configured
                                            ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400'
                                            : 'bg-slate-100 dark:bg-slate-800 text-slate-500'
                                    }`}>
                                        {brainStatus.model_stats.api_status.gemini_configured ? 'Yapilandi' : 'Yok'}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-slate-600 dark:text-slate-400">Claude</span>
                                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                                        brainStatus.model_stats.api_status.claude_configured
                                            ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400'
                                            : 'bg-slate-100 dark:bg-slate-800 text-slate-500'
                                    }`}>
                                        {brainStatus.model_stats.api_status.claude_configured ? 'Yapilandi' : 'Yok'}
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Model Healthcheck */}
                <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-6">
                    <h3 className="font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                        <Bot className="w-5 h-5 text-blue-500" />
                        Model Healthcheck
                    </h3>

                    <div className="space-y-4">
                        {/* Model Select */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Model ({totalModels} mevcut)
                            </label>
                            <select
                                value={selectedModel}
                                onChange={(e) => { setSelectedModel(e.target.value); setHealthResult(null); }}
                                className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white text-sm"
                            >
                                {models?.ollama && models.ollama.length > 0 && (
                                    <optgroup label="Ollama (Local)">
                                        {models.ollama.map(m => (
                                            <option key={m.id} value={m.id}>{m.name}</option>
                                        ))}
                                    </optgroup>
                                )}
                                {models?.gemini && models.gemini.length > 0 && (
                                    <optgroup label="Gemini">
                                        {models.gemini.map(m => (
                                            <option key={m.id} value={m.id}>{m.name}</option>
                                        ))}
                                    </optgroup>
                                )}
                                {models?.claude && models.claude.length > 0 && (
                                    <optgroup label="Claude">
                                        {models.claude.map(m => (
                                            <option key={m.id} value={m.id}>{m.name}</option>
                                        ))}
                                    </optgroup>
                                )}
                            </select>
                        </div>

                        {/* Ollama Status */}
                        {models && (
                            <div className="flex items-center gap-2 text-xs">
                                <Server className="w-3.5 h-3.5" />
                                <span className="text-slate-500">Ollama:</span>
                                <span className={models.ollama_status === 'online'
                                    ? 'text-emerald-600 dark:text-emerald-400 font-medium'
                                    : 'text-amber-600 dark:text-amber-400'}>
                                    {models.ollama_status === 'online'
                                        ? `Online (${models.ollama.length} model)`
                                        : 'Offline'}
                                </span>
                            </div>
                        )}

                        {/* Test Button */}
                        <button
                            onClick={testModel}
                            disabled={!selectedModel || healthLoading}
                            className="w-full py-2.5 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg flex items-center justify-center gap-2 text-sm transition-colors"
                        >
                            {healthLoading ? (
                                <><Loader2 className="w-4 h-4 animate-spin" /> Test ediliyor...</>
                            ) : (
                                <><Activity className="w-4 h-4" /> Model Test</>
                            )}
                        </button>

                        {/* Health Result */}
                        {healthResult && (
                            <div className={`p-4 rounded-lg border ${
                                healthResult.available
                                    ? 'bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30'
                                    : 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30'
                            }`}>
                                <div className="flex items-center gap-2 mb-2">
                                    {healthResult.available
                                        ? <CheckCircle className="w-4 h-4 text-emerald-500" />
                                        : <XCircle className="w-4 h-4 text-red-500" />}
                                    <span className={`text-sm font-medium ${
                                        healthResult.available
                                            ? 'text-emerald-700 dark:text-emerald-400'
                                            : 'text-red-700 dark:text-red-400'
                                    }`}>
                                        {healthResult.available ? 'Erisilebilir' : 'Erisilemez'}
                                    </span>
                                </div>
                                <div className="space-y-1 text-xs text-slate-600 dark:text-slate-400">
                                    <p>Model: <span className="font-mono">{healthResult.model}</span></p>
                                    <p>Provider: {healthResult.provider}</p>
                                    {healthResult.latency_ms && <p>Gecikme: {healthResult.latency_ms.toFixed(0)}ms</p>}
                                    {healthResult.error && <p className="text-red-600 dark:text-red-400 mt-1">{healthResult.error}</p>}
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Smart Analysis */}
                <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-6">
                    <h3 className="font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                        <Zap className="w-5 h-5 text-amber-500" />
                        Smart Analysis
                    </h3>

                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Analiz Verisi (JSON veya metin)
                            </label>
                            <textarea
                                value={analysisInput}
                                onChange={(e) => setAnalysisInput(e.target.value)}
                                placeholder={`Tarama sonuclarini veya serbest metin yapistiriniz...\n\nOrnek JSON:\n{"ports": [22, 80, 443], "services": ["ssh", "http", "https"]}`}
                                rows={5}
                                className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white text-sm font-mono resize-none"
                            />
                        </div>

                        <button
                            onClick={runAnalysis}
                            disabled={!analysisInput.trim() || analysisLoading}
                            className="w-full py-2.5 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg flex items-center justify-center gap-2 text-sm transition-colors"
                        >
                            {analysisLoading ? (
                                <><Loader2 className="w-4 h-4 animate-spin" /> Analiz ediliyor...</>
                            ) : (
                                <><Brain className="w-4 h-4" /> Analiz Et</>
                            )}
                        </button>

                        {/* Analysis Result */}
                        {analysisResult && (
                            <div className="space-y-3">
                                {/* Meta */}
                                <div className="flex items-center gap-2 text-xs text-slate-500">
                                    <span className="px-2 py-0.5 bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-400 rounded-full">
                                        {analysisResult.model_used}
                                    </span>
                                    <span>{analysisResult.latency_ms?.toFixed(0)}ms</span>
                                    {analysisResult.risk_score && (
                                        <span className={`px-2 py-0.5 rounded-full font-medium ${
                                            analysisResult.risk_score >= 80 ? 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400' :
                                            analysisResult.risk_score >= 50 ? 'bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400' :
                                            'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400'
                                        }`}>
                                            Risk: {analysisResult.risk_score}/100
                                        </span>
                                    )}
                                </div>

                                {/* Content */}
                                <div className="p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700 max-h-[300px] overflow-y-auto">
                                    <pre className="text-xs text-slate-700 dark:text-slate-300 whitespace-pre-wrap font-mono leading-relaxed">
                                        {analysisResult.analysis}
                                    </pre>
                                </div>

                                {/* Recommendations */}
                                {analysisResult.recommendations?.length > 0 && (
                                    <div>
                                        <p className="text-xs text-slate-500 mb-1 font-medium">Oneriler</p>
                                        <ul className="space-y-1">
                                            {analysisResult.recommendations.map((rec: string, i: number) => (
                                                <li key={i} className="text-xs text-slate-600 dark:text-slate-400 flex items-start gap-1.5">
                                                    <Shield className="w-3 h-3 mt-0.5 text-amber-500 flex-shrink-0" />
                                                    {rec}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}

                                {/* Critical Findings */}
                                {analysisResult.critical_findings?.length > 0 && (
                                    <div>
                                        <p className="text-xs text-slate-500 mb-1 font-medium">Kritik Bulgular</p>
                                        <ul className="space-y-1">
                                            {analysisResult.critical_findings.map((f: string, i: number) => (
                                                <li key={i} className="text-xs text-red-600 dark:text-red-400 flex items-start gap-1.5">
                                                    <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                                    {f}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
