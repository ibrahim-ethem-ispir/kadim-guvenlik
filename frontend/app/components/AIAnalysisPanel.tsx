/**
 * AI Analysis Panel Component - v2.0
 * Türkçe: Tüm sonuç sayfalarında kullanılabilecek premium AI analiz paneli
 * 
 * v2.0 Güncellemeler:
 * - Chat history persistence (sayfa yenilendiğinde korunur)
 * - Technical details gösterimi
 * - Geliştirilmiş markdown rendering
 */

import { useRef, useState, useEffect } from 'react';
import { Brain, Loader2, AlertCircle, Sparkles, Shield, ListChecks, ArrowRight, FileText, MessageSquare, Trash2, RefreshCcw, Code } from 'lucide-react';
import AIChatModal from './AIChatModal';
import { api } from '../services/api';
import type { AIAnalysisResponse, AnalysisType } from '../types/ai';
import { generateAIAnalysisReport } from '../libs/report-generator';

interface ChatHistoryResponse {
    exists: boolean;
    messages: { role: 'user' | 'assistant'; content: string; timestamp?: string }[];
    message_count: number;
}

interface AIAnalysisPanelProps {
    scanId?: string;
    scanData?: Record<string, unknown>;
    analysisType?: AnalysisType;
    title?: string;
    className?: string;
}

// 4 sağlayıcı için görünen etiket (deepseek eksikti → Gemini gibi görünüyordu).
function providerLabel(p?: string): string {
    switch ((p || '').toLowerCase()) {
        case 'ollama': return '🦙 Ollama';
        case 'deepseek': return '🐋 DeepSeek';
        case 'claude': return '☁️ Claude';
        case 'gemini': return '✨ Gemini';
        default: return p || 'AI';
    }
}

export default function AIAnalysisPanel({
    scanId,
    scanData,
    analysisType = 'security',
    title = 'AI Güvenlik Analizi',
    className = ''
}: AIAnalysisPanelProps) {
    const [analysis, setAnalysis] = useState<AIAnalysisResponse | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    // Provider/model artık burada SEÇİLMEZ. Analiz/rapor/chat motoru AI Ayarları'ndaki
    // aktif varsayılanı (DB > .env) kullanır → istekte use_default:true gönderilir. Panel bu
    // varsayılanı yalnızca BİLGİ olarak gösterir (kullanıcı nereden değiştireceğini bilsin).
    const [activeDefault, setActiveDefault] = useState<{ provider: string; model: string } | null>(null);


    // Chat State - v2.0: timestamp destekli
    const [isChatOpen, setIsChatOpen] = useState(false);
    const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'assistant', content: string, timestamp?: string }[]>([]);
    const [chatLoading, setChatLoading] = useState(false);
    const [historyLoaded, setHistoryLoaded] = useState(false);

    // v2.0: Sayfa yüklendiğinde chat history'yi MongoDB'den çek
    useEffect(() => {
        const loadChatHistory = async () => {
            if (!scanId || historyLoaded) return;

            try {
                const history = await api.get<ChatHistoryResponse>(`/api/ai/conversation/${scanId}`);
                if (history.exists && history.messages.length > 0) {
                    console.log(`✅ Chat history yüklendi: ${history.message_count} mesaj`);
                    setChatMessages(history.messages);
                }
            } catch (e) {
                console.log('Chat history bulunamadı (normal durum)');
            } finally {
                setHistoryLoaded(true);
            }
        };

        loadChatHistory();
    }, [scanId, historyLoaded]);

    // Persistence Check - mevcut analiz
    useEffect(() => {
        if (scanData && scanData.ai_analysis) {
            console.log('Loading persisted AI analysis');
            setAnalysis(scanData.ai_analysis as AIAnalysisResponse);
        }
    }, [scanData]);

    // AI Ayarları'ndaki aktif varsayılan sağlayıcı+modeli oku (sadece bilgi göstermek için —
    // analiz her zaman use_default ile bu varsayılanı kullanır, burada seçim yapılmaz).
    useEffect(() => {
        api.get<{ ai_service_provider?: string; ai_service_model?: string }>('/api/settings/ai/env-status')
            .then((s) => setActiveDefault({
                provider: s.ai_service_provider || 'ollama',
                model: s.ai_service_model || '',
            }))
            .catch(() => { /* sessiz — bilgi satırı opsiyonel, analizi etkilemez */ });
    }, []);

    const analyzeWithAI = async () => {
        if (!scanId && !scanData) {
            setError('Analiz için scan_id veya scan_data gerekli');
            return;
        }

        setLoading(true);
        setError(null);
        setAnalysis(null);

        try {
            const response = await api.post<AIAnalysisResponse>('/api/ai/analyze', {
                scan_id: scanId,
                scan_data: scanData,
                analysis_type: analysisType,
                use_default: true,   // provider/model AI Ayarları varsayılanından (DB > .env) gelsin
            });
            setAnalysis(response);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'AI analizi başarısız oldu');
        } finally {
            setLoading(false);
        }
    };

    const handleChat = async (message: string) => {
        if (!analysis || !scanId) return;

        const timestamp = new Date().toISOString();

        // Add user message with timestamp
        const newMessages = [...chatMessages, { role: 'user' as const, content: message, timestamp }];
        setChatMessages(newMessages);
        setChatLoading(true);

        try {
            const response = await api.post<AIAnalysisResponse>('/api/ai/chat', {
                scan_id: scanId,
                current_analysis: analysis,
                user_message: message,
                analysis_type: analysisType,
                use_default: true,   // analiz ile aynı: aktif varsayılan sağlayıcı/model
            });

            // Update analysis with new version
            setAnalysis(response);

            // Add AI response message with timestamp
            setChatMessages([
                ...newMessages,
                {
                    role: 'assistant',
                    content: response.analysis || 'Rapor güncellendi.',
                    timestamp: new Date().toISOString()
                }
            ]);

        } catch (e) {
            setChatMessages([
                ...newMessages,
                {
                    role: 'assistant',
                    content: 'Üzgünüm, bir hata oluştu: ' + (e instanceof Error ? e.message : 'Bilinmeyen hata'),
                    timestamp: new Date().toISOString()
                }
            ]);
        } finally {
            setChatLoading(false);
        }
    };

    // v2.0: Chat history temizleme
    const handleClearHistory = async () => {
        if (!scanId) return;

        if (!confirm('Konuşma geçmişini temizlemek istediğinizden emin misiniz? Bu işlem geri alınamaz.')) {
            return;
        }

        try {
            await api.delete(`/api/ai/conversation/${scanId}`);
            setChatMessages([]);
            setAnalysis(null);
            console.log('✅ Chat history temizlendi');
        } catch (e) {
            console.error('Chat history temizlenemedi:', e);
        }
    };

    // v2.0: Chat history export
    const handleExportHistory = async () => {
        if (!scanId) return;

        try {
            const exportData = await api.get<any>(`/api/ai/conversation/${scanId}/export`);

            // JSON olarak indir
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ai-analysis-${scanId}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            console.log('✅ Chat history export edildi');
        } catch (e) {
            console.error('Export hatası:', e);
        }
    };

    const getRiskColor = (score: number | null) => {
        if (score === null) return 'text-slate-400';
        if (score >= 80) return 'text-red-400';
        if (score >= 60) return 'text-orange-400';
        if (score >= 40) return 'text-yellow-400';
        if (score >= 20) return 'text-blue-400';
        return 'text-emerald-400';
    };

    const getRiskBg = (score: number | null) => {
        if (score === null) return 'from-slate-500/20 to-slate-600/20';
        if (score >= 80) return 'from-red-500/20 to-red-600/20';
        if (score >= 60) return 'from-orange-500/20 to-orange-600/20';
        if (score >= 40) return 'from-yellow-500/20 to-yellow-600/20';
        if (score >= 20) return 'from-blue-500/20 to-blue-600/20';
        return 'from-emerald-500/20 to-emerald-600/20';
    };

    return (
        <div className={`rounded-2xl overflow-hidden ${className}`}>
            {/* Başlangıç Durumu - Henüz analiz yapılmadı */}
            {!analysis && !loading && !error && (
                <div className="bg-slate-500/10 border border-emerald-500/30 rounded-2xl p-6">
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <div className="p-2.5 bg-emerald-500/20 rounded-xl">
                                <Brain className="w-6 h-6 text-emerald-400" />
                            </div>
                            <div>
                                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{title}</h3>
                                <p className="text-sm text-slate-600 dark:text-emerald-300/80">Sonuçları AI ile değerlendir</p>
                            </div>
                        </div>

                    </div>

                    {/* Aktif sağlayıcı bilgisi — seçim BURADA yapılmaz; AI Ayarları'ndaki
                        aktif varsayılan (DB > .env) kullanılır. Değiştirmek için Admin → AI Ayarları. */}
                    {activeDefault && (
                        <div className="mb-4 p-3 bg-white/60 dark:bg-slate-900/50 rounded-xl border border-slate-300 dark:border-slate-700/50 flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                            <Sparkles className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                            <span>
                                Aktif model:{' '}
                                <strong className="text-slate-800 dark:text-slate-200">
                                    {activeDefault.provider}{activeDefault.model ? ` / ${activeDefault.model}` : ''}
                                </strong>
                                {' '}— değiştirmek için <em>Admin → AI Ayarları</em>.
                            </span>
                        </div>
                    )}

                    {/* Analiz Butonu */}
                    <button
                        onClick={analyzeWithAI}
                        disabled={loading}
                        className="w-full py-3.5 px-6 bg-gradient-to-r from-emerald-600 to-emerald-500 text-white rounded-xl font-medium hover:from-emerald-500 hover:to-emerald-400 transition-all shadow-lg shadow-emerald-500/25 hover:shadow-emerald-500/40 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        <Brain className="w-5 h-5" />
                        🤖 AI ile Değerlendir
                    </button>
                </div>
            )}

            {/* Yükleniyor */}
            {loading && (
                <div className="bg-gradient-to-br from-emerald-900/10 via-slate-900/40 to-emerald-900/20 border border-emerald-500/30 rounded-2xl p-8">
                    <div className="flex flex-col items-center justify-center">
                        <div className="relative">
                            <div className="absolute inset-0 rounded-full bg-emerald-500/20 animate-ping" />
                            <div className="relative p-4 bg-emerald-500/20 rounded-full">
                                <Loader2 className="w-8 h-8 text-emerald-400 animate-spin" />
                            </div>
                        </div>
                        <h3 className="mt-4 text-lg font-semibold text-slate-900 dark:text-white">AI Analiz Ediyor</h3>
                        <p className="mt-2 text-sm text-emerald-600 dark:text-emerald-300/80 text-center">
                            {providerLabel(activeDefault?.provider)} • {activeDefault?.model || 'aktif varsayılan'}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">Bu işlem 30-60 saniye sürebilir...</p>
                    </div>
                </div>
            )}

            {/* Hata */}
            {error && (
                <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-2xl p-6">
                    <div className="flex items-start gap-4">
                        <div className="p-2 bg-red-100 dark:bg-red-500/20 rounded-lg shrink-0">
                            <AlertCircle className="w-6 h-6 text-red-500 dark:text-red-400" />
                        </div>
                        <div className="flex-1">
                            <h4 className="text-red-600 dark:text-red-400 font-semibold mb-1">AI Analizi Başarısız</h4>
                            <p className="text-sm text-slate-600 dark:text-slate-400">{error}</p>
                            {activeDefault?.provider === 'ollama' && error.includes('bağlanılamadı') && (
                                <p className="mt-2 text-xs text-slate-500 dark:text-slate-500">
                                    💡 Ollama servisinin çalıştığından emin olun: <code className="bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 rounded">ollama serve</code>
                                </p>
                            )}
                        </div>
                    </div>
                    <button
                        onClick={() => setError(null)}
                        className="mt-4 w-full py-2 px-4 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors text-sm"
                    >
                        Tekrar Dene
                    </button>
                </div>
            )}

            {/* Analiz Sonucu */}
            {analysis && (
                <div className={`bg-gradient-to-br ${getRiskBg(analysis.risk_score)} border border-emerald-500/30 dark:border-emerald-500/30 rounded-2xl overflow-hidden`}>
                    {/* Header */}
                    <div className="bg-emerald-100/50 dark:bg-emerald-900/40 px-6 py-4 border-b border-emerald-200 dark:border-emerald-500/30">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-emerald-500/20 rounded-lg">
                                    <Brain className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                                </div>
                                <div>
                                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{title}</h3>
                                    <p className="text-xs text-emerald-700 dark:text-emerald-300">
                                        {providerLabel(analysis.provider)} • {analysis.model}
                                    </p>
                                </div>
                            </div>

                            <div className="flex items-center gap-4">
                                {/* Export Button */}
                                <button
                                    onClick={() => generateAIAnalysisReport(analysis, { scanId: scanId, target: scanData?.target as string })}
                                    className="p-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-600 dark:text-emerald-300 rounded-lg transition-colors group"
                                    title="PDF Rapor İndir"
                                >
                                    <FileText className="w-5 h-5 group-hover:scale-110 transition-transform" />
                                </button>

                                {/* Chat Button */}
                                <button
                                    onClick={() => setIsChatOpen(true)}
                                    className="p-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 rounded-lg transition-colors group flex items-center gap-2"
                                    title="AI ile Sohbet Et / İtiraz Et"
                                >
                                    <MessageSquare className="w-5 h-5 group-hover:scale-110 transition-transform" />
                                    <span className="text-sm font-medium">Asistan</span>
                                </button>

                                {/* Risk Skoru */}
                                {analysis.risk_score !== null && (
                                    <div className="text-right">
                                        <div className={`text-3xl font-bold ${getRiskColor(analysis.risk_score)}`}>
                                            {analysis.risk_score}
                                        </div>
                                        <div className="text-xs text-emerald-700 dark:text-emerald-300">Risk Skoru</div>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Content */}
                    <div className="p-6 space-y-6">
                        {/* Ana Analiz Metni */}
                        <div className="prose dark:prose-invert prose-sm max-w-none">
                            <div className="text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed text-sm">
                                {analysis.analysis}
                            </div>
                        </div>

                        {/* Kritik Bulgular */}
                        {analysis.critical_findings && analysis.critical_findings.length > 0 && (
                            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-xl p-4">
                                <h4 className="text-red-600 dark:text-red-400 font-semibold mb-3 flex items-center gap-2">
                                    <Shield className="w-4 h-4" />
                                    Kritik Bulgular
                                </h4>
                                <ul className="space-y-2">
                                    {analysis.critical_findings.map((finding, idx) => (
                                        <li key={idx} className="text-slate-700 dark:text-slate-300 text-sm flex items-start gap-2">
                                            <span className="text-red-500 dark:text-red-400 mt-0.5">•</span>
                                            {finding}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        {/* Öneriler */}
                        {analysis.recommendations && analysis.recommendations.length > 0 && (
                            <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-xl p-4">
                                <h4 className="text-emerald-600 dark:text-emerald-400 font-semibold mb-3 flex items-center gap-2">
                                    <Sparkles className="w-4 h-4" />
                                    Öneriler
                                </h4>
                                <ul className="space-y-2">
                                    {analysis.recommendations.map((rec, idx) => (
                                        <li key={idx} className="text-slate-700 dark:text-slate-300 text-sm flex items-start gap-2">
                                            <span className="text-emerald-600 dark:text-emerald-400 font-medium">{idx + 1}.</span>
                                            {rec}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        {/* v2.0: Teknik Detaylar */}
                        {analysis.technical_details && analysis.technical_details.length > 0 && (
                            <div className="bg-purple-50 dark:bg-purple-500/10 border border-purple-200 dark:border-purple-500/30 rounded-xl p-4">
                                <h4 className="text-purple-600 dark:text-purple-400 font-semibold mb-3 flex items-center gap-2">
                                    <Code className="w-4 h-4" />
                                    Teknik Detaylar
                                </h4>
                                <ul className="space-y-2">
                                    {analysis.technical_details.map((detail, idx) => (
                                        <li key={idx} className="text-slate-700 dark:text-slate-300 text-sm font-mono bg-slate-100 dark:bg-slate-900/50 p-2 rounded">
                                            {detail}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        {/* Sonraki Adımlar */}
                        {analysis.next_steps && analysis.next_steps.length > 0 && (
                            <div className="bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/30 rounded-xl p-4">
                                <h4 className="text-blue-600 dark:text-blue-400 font-semibold mb-3 flex items-center gap-2">
                                    <ListChecks className="w-4 h-4" />
                                    Sonraki Adımlar
                                </h4>
                                <ul className="space-y-2">
                                    {analysis.next_steps.map((step, idx) => (
                                        <li key={idx} className="text-slate-700 dark:text-slate-300 text-sm flex items-start gap-2">
                                            <ArrowRight className="w-4 h-4 text-blue-500 dark:text-blue-400 mt-0.5 shrink-0" />
                                            {step}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        {/* Yeniden Analiz Butonu */}
                        <div className="flex gap-3">
                            <button
                                onClick={analyzeWithAI}
                                className="flex-1 py-2.5 px-4 bg-slate-100 dark:bg-slate-800/50 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700/50 transition-colors text-sm flex items-center justify-center gap-2"
                            >
                                <RefreshCcw className="w-4 h-4" />
                                Yeniden Analiz Et
                            </button>
                            {chatMessages.length > 0 && (
                                <button
                                    onClick={handleClearHistory}
                                    className="py-2.5 px-4 bg-orange-500/10 text-orange-400 rounded-lg hover:bg-orange-500/20 transition-colors text-sm flex items-center justify-center gap-2"
                                    title="Konuşma geçmişini temizle"
                                >
                                    <Trash2 className="w-4 h-4" />
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}
            {/* Chat Modal - v2.0 */}
            <AIChatModal
                isOpen={isChatOpen}
                onClose={() => setIsChatOpen(false)}
                messages={chatMessages}
                onSendMessage={handleChat}
                loading={chatLoading}
                analysisContext={{
                    target: scanData?.target as string,
                    riskScore: analysis?.risk_score,
                    scanId: scanId
                }}
                onClearHistory={handleClearHistory}
                onExportHistory={handleExportHistory}
            />
        </div>

    );
}
