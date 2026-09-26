/**
 * AI Chat Modal Component - v3.0
 * Türkçe: Gelişmiş AI sohbet modal - Canlı tarama tetikleme desteği
 * 
 * v3.0 Güncellemeler:
 * - URL algılama ve canlı tarama başlatma
 * - Daha fazla quick action
 * - Gelişmiş markdown rendering
 * - Premium terminal tasarımı
 */

import { useRef, useEffect, useState } from 'react';
import { X, Send, Terminal, Cpu, ChevronRight, RotateCcw, Download, Trash2, MessageSquare, Zap, Target, Shield, ExternalLink, Play, AlertTriangle, Loader2, Sparkles, Code } from 'lucide-react';
import { api } from '../services/api';
import { Link } from 'react-router';

interface ChatMessage {
    role: 'user' | 'assistant';
    content: string;
    timestamp?: string;
}

interface AIChatModalProps {
    isOpen: boolean;
    onClose: () => void;
    messages: ChatMessage[];
    onSendMessage: (message: string) => void;
    loading: boolean;
    analysisContext: {
        target?: string;
        riskScore?: number | null;
        scanId?: string;
    };
    onClearHistory?: () => void;
    onExportHistory?: () => void;
}

// Geliştirilmiş hızlı aksiyon önerileri
const QUICK_ACTIONS = [
    {
        label: "🔍 Riski Açıkla",
        message: "Bu risk skorunu nasıl hesapladın? Her faktörü detaylı açıklar mısın?",
        category: "analysis"
    },
    {
        label: "⚡ Öncelikleri Belirle",
        message: "Bu bulgular arasında hangilerine öncelik vermeliyim ve neden? Acil olanları listele.",
        category: "priority"
    },
    {
        label: "🛠️ Teknik PoC",
        message: "En kritik zafiyet için teknik detayları, PoC komutlarını ve exploit senaryosunu paylaş.",
        category: "technical"
    },
    {
        label: "📋 Remediation Planı",
        message: "Tüm zafiyetleri gidermek için öncelik sırasına göre adım adım bir düzeltme planı oluştur.",
        category: "remediation"
    },
    {
        label: "🎯 MITRE Haritalama",
        message: "Bu bulgulari MITRE ATT&CK framework'üne göre haritala. Hangi taktik ve teknikler kullanılabilir?",
        category: "analysis"
    },
    {
        label: "💰 İş Etkisi",
        message: "Bu zafiyetlerin potansiyel iş etkisini (finansal, itibar, yasal) analiz et.",
        category: "impact"
    },
    {
        label: "🔗 Attack Chain",
        message: "Bu zafiyetleri birleştirerek oluşturulabilecek saldırı zincirlerini açıkla.",
        category: "analysis"
    },
    {
        label: "📖 Öğrenme Kaynakları",
        message: "Bu tip zafiyetler hakkında daha fazla bilgi edinmek için kaynaklar öner.",
        category: "learning"
    },
];

// URL extraction regex
const URL_REGEX = /(https?:\/\/[^\s]+)|((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})/g;

export default function AIChatModal({
    isOpen,
    onClose,
    messages,
    onSendMessage,
    loading,
    analysisContext,
    onClearHistory,
    onExportHistory
}: AIChatModalProps) {
    const [input, setInput] = useState('');
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);
    const [showQuickActions, setShowQuickActions] = useState(true);
    const [activeCategory, setActiveCategory] = useState<string | null>(null);

    // URL Scan State
    const [detectedUrls, setDetectedUrls] = useState<string[]>([]);
    const [scanningUrl, setScanningUrl] = useState<string | null>(null);
    const [scanResult, setScanResult] = useState<{ url: string; scanId: string } | null>(null);

    // Auto-scroll to bottom
    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
        if (messages.length > 2) {
            setShowQuickActions(false);
        }

        // Extract URLs from last AI message
        if (messages.length > 0) {
            const lastMessage = messages[messages.length - 1];
            if (lastMessage.role === 'assistant') {
                const urls = lastMessage.content.match(URL_REGEX) || [];
                // Filter out common non-target URLs
                const targetUrls = urls.filter(url =>
                    !url.includes('github.com') &&
                    !url.includes('owasp.org') &&
                    !url.includes('cve.org') &&
                    !url.includes('nist.gov')
                );
                setDetectedUrls([...new Set(targetUrls)].slice(0, 3));
            }
        }
    }, [messages, loading]);

    // Focus input on open
    useEffect(() => {
        if (isOpen) {
            setTimeout(() => inputRef.current?.focus(), 100);
        }
    }, [isOpen]);

    if (!isOpen) return null;

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (input.trim() && !loading) {
            onSendMessage(input.trim());
            setInput('');
            setShowQuickActions(false);
        }
    };

    const handleQuickAction = (message: string) => {
        onSendMessage(message);
        setShowQuickActions(false);
    };

    // Canlı tarama başlat
    const handleQuickScan = async (url: string) => {
        setScanningUrl(url);
        try {
            // Basit Nuclei taraması başlat
            const response = await api.post<{ scan_id: string }>('/api/scan', {
                target: url,
                scan_types: ['nuclei'],
                nuclei_options: {
                    severity: ['critical', 'high'],
                    rate_limit: 50
                }
            });

            setScanResult({ url, scanId: response.scan_id });

            // AI'a bildir
            onSendMessage(`Ben "${url}" için hızlı bir Nuclei taraması başlattım. Tarama ID: ${response.scan_id}. Tarama tamamlanınca sonuçları analiz edebilirsin.`);

        } catch (e) {
            console.error('Tarama başlatılamadı:', e);
        } finally {
            setScanningUrl(null);
        }
    };

    // Markdown formatını basit HTML'e çevir
    const formatMessage = (content: string) => {
        return content
            // Bold
            .replace(/\*\*(.*?)\*\*/g, '<strong class="text-emerald-300 font-semibold">$1</strong>')
            // Headers
            .replace(/^### (.*?)$/gm, '<h4 class="text-base font-bold text-emerald-400 mt-4 mb-2 flex items-center gap-2">$1</h4>')
            .replace(/^## (.*?)$/gm, '<h3 class="text-lg font-bold text-emerald-400 mt-4 mb-2">$1</h3>')
            .replace(/^# (.*?)$/gm, '<h2 class="text-xl font-bold text-emerald-300 mt-4 mb-2">$1</h2>')
            // Code blocks
            .replace(/```([a-z]*)\n([\s\S]*?)```/g, '<pre class="bg-black/70 p-3 rounded-lg my-3 text-xs overflow-x-auto border border-emerald-900/50 font-mono"><code class="text-emerald-300">$2</code></pre>')
            .replace(/```([\s\S]*?)```/g, '<pre class="bg-black/70 p-3 rounded-lg my-3 text-xs overflow-x-auto border border-emerald-900/50 font-mono"><code class="text-emerald-300">$1</code></pre>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code class="bg-black/50 px-1.5 py-0.5 rounded text-xs text-emerald-300 font-mono">$1</code>')
            // Lists
            .replace(/^- (.*?)$/gm, '<li class="ml-4 list-disc text-slate-300 my-1">$1</li>')
            .replace(/^\d+\. (.*?)$/gm, '<li class="ml-4 list-decimal text-slate-300 my-1">$1</li>')
            // URLs - make clickable
            .replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" class="text-blue-400 hover:underline">$1</a>')
            // Newlines
            .replace(/\n/g, '<br/>');
    };

    const filteredActions = activeCategory
        ? QUICK_ACTIONS.filter(a => a.category === activeCategory)
        : QUICK_ACTIONS;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <div className="w-full max-w-6xl h-[90vh] bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 border border-emerald-500/30 rounded-2xl shadow-2xl shadow-emerald-500/10 flex flex-col overflow-hidden font-mono mx-4">

                {/* Header (Terminal Bar) */}
                <div className="bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border-b border-emerald-500/20 px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="flex gap-2">
                            <div className="w-3 h-3 rounded-full bg-red-500/80 hover:bg-red-400 cursor-pointer transition-colors" onClick={onClose} />
                            <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                            <div className="w-3 h-3 rounded-full bg-green-500/80" />
                        </div>
                        <div className="flex items-center gap-2 text-emerald-400 text-sm opacity-80 pl-2 border-l border-emerald-500/20 ml-2">
                            <Terminal className="w-4 h-4" />
                            <span className="hidden sm:inline">kadim_ai@{analysisContext.target || 'security'}:~$</span>
                            <span className="text-emerald-300 font-semibold">interactive_mode</span>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        {/* Mesaj sayısı */}
                        <span className="text-xs text-emerald-500/50 flex items-center gap-1 bg-emerald-500/10 px-2 py-1 rounded">
                            <MessageSquare className="w-3 h-3" />
                            {messages.length}
                        </span>

                        {onExportHistory && messages.length > 0 && (
                            <button
                                onClick={onExportHistory}
                                className="text-emerald-500/60 hover:text-emerald-400 hover:bg-emerald-500/10 p-1.5 rounded transition-colors"
                                title="Konuşmayı Dışa Aktar"
                            >
                                <Download className="w-4 h-4" />
                            </button>
                        )}

                        {onClearHistory && messages.length > 0 && (
                            <button
                                onClick={onClearHistory}
                                className="text-orange-500/60 hover:text-orange-400 hover:bg-orange-500/10 p-1.5 rounded transition-colors"
                                title="Konuşmayı Temizle"
                            >
                                <Trash2 className="w-4 h-4" />
                            </button>
                        )}

                        <button
                            onClick={onClose}
                            className="text-emerald-500/60 hover:text-emerald-400 hover:bg-emerald-500/10 p-2 rounded transition-colors"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>
                </div>

                {/* Messages Area */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-emerald-900 scrollbar-track-transparent">
                    {/* Welcome Message */}
                    <div className="flex gap-4 p-4 bg-gradient-to-r from-emerald-950/40 to-transparent border border-emerald-500/20 rounded-xl text-emerald-400/90 text-sm">
                        <div className="p-2 bg-emerald-500/20 rounded-lg h-fit">
                            <Cpu className="w-5 h-5" />
                        </div>
                        <div>
                            <p className="font-bold mb-1 text-emerald-300">🤖 KADIM AI ANALYST v3.0</p>
                            <p>Hedef: <span className="font-bold text-white">{analysisContext.target}</span> | Risk Skoru: <span className="font-bold text-emerald-300">{analysisContext.riskScore ?? 'N/A'}</span></p>
                            <p className="mt-2 opacity-80 border-l-2 border-emerald-500/30 pl-3 text-slate-400">
                                Soru sorabilir, itiraz edebilir, ek bağlam ekleyebilir veya <span className="text-emerald-400">canlı tarama</span> başlatabilirsiniz.
                                <br />
                                <span className="text-emerald-500/70">💡 Konuşma geçmişiniz otomatik kaydedilir.</span>
                            </p>
                        </div>
                    </div>

                    {/* Quick Actions - Kategori bazlı */}
                    {showQuickActions && messages.length <= 1 && (
                        <div className="space-y-3">
                            {/* Kategori Filtreleri */}
                            <div className="flex gap-2 flex-wrap">
                                <button
                                    onClick={() => setActiveCategory(null)}
                                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${!activeCategory
                                            ? 'bg-emerald-500 text-white'
                                            : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                                        }`}
                                >
                                    Tümü
                                </button>
                                {['analysis', 'priority', 'technical', 'remediation', 'impact'].map(cat => (
                                    <button
                                        key={cat}
                                        onClick={() => setActiveCategory(cat)}
                                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors capitalize ${activeCategory === cat
                                                ? 'bg-emerald-500 text-white'
                                                : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                                            }`}
                                    >
                                        {cat}
                                    </button>
                                ))}
                            </div>

                            {/* Actions Grid */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                {filteredActions.map((action, idx) => (
                                    <button
                                        key={idx}
                                        onClick={() => handleQuickAction(action.message)}
                                        disabled={loading}
                                        className="p-3 text-left text-sm bg-slate-900/80 border border-emerald-500/20 rounded-xl text-emerald-400/80 hover:bg-emerald-500/10 hover:border-emerald-500/40 transition-all disabled:opacity-50 group"
                                    >
                                        <span className="group-hover:scale-110 inline-block transition-transform">{action.label}</span>
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* URL Scan Trigger - AI yanıtında URL varsa göster */}
                    {detectedUrls.length > 0 && !loading && (
                        <div className="p-4 bg-gradient-to-r from-blue-950/40 to-transparent border border-blue-500/30 rounded-xl">
                            <div className="flex items-center gap-2 text-blue-400 font-semibold mb-3">
                                <Target className="w-4 h-4" />
                                Tespit Edilen Hedefler - Hızlı Tarama
                            </div>
                            <div className="flex flex-wrap gap-2">
                                {detectedUrls.map((url, idx) => (
                                    <div key={idx} className="flex items-center gap-2 bg-slate-900/80 rounded-lg p-2 border border-slate-700">
                                        <code className="text-xs text-blue-300 truncate max-w-[200px]">{url}</code>
                                        {scanningUrl === url ? (
                                            <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
                                        ) : scanResult?.url === url ? (
                                            <Link
                                                to={`/results?id=${scanResult.scanId}`}
                                                className="flex items-center gap-1 text-xs text-emerald-400 hover:underline"
                                            >
                                                <ExternalLink className="w-3 h-3" />
                                                Sonuçlar
                                            </Link>
                                        ) : (
                                            <button
                                                onClick={() => handleQuickScan(url)}
                                                className="flex items-center gap-1 px-2 py-1 bg-blue-600 hover:bg-blue-500 text-white text-xs rounded transition-colors"
                                            >
                                                <Play className="w-3 h-3" />
                                                Tara
                                            </button>
                                        )}
                                    </div>
                                ))}
                            </div>
                            <p className="text-xs text-slate-500 mt-2">
                                💡 Hızlı taramalar critical/high seviye zafiyetleri kontrol eder
                            </p>
                        </div>
                    )}

                    {/* Messages */}
                    {messages.map((msg, idx) => (
                        <div
                            key={idx}
                            className={`flex gap-4 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                        >
                            <div
                                className={`
                                    max-w-[85%] rounded-xl p-4 text-sm leading-relaxed border
                                    ${msg.role === 'user'
                                        ? 'bg-slate-800/80 border-slate-700 text-slate-200'
                                        : 'bg-gradient-to-br from-black to-slate-900 border-emerald-500/30 text-emerald-100 shadow-lg shadow-emerald-500/5'
                                    }
                                `}
                            >
                                <div className="flex items-center gap-2 mb-2 opacity-50 text-xs uppercase tracking-wider font-bold">
                                    {msg.role === 'user' ? (
                                        <>USER <ChevronRight className="w-3 h-3" /></>
                                    ) : (
                                        <><Sparkles className="w-3 h-3 text-emerald-400" /> AI ANALYST</>
                                    )}
                                    {msg.timestamp && (
                                        <span className="ml-auto opacity-50 font-normal normal-case">
                                            {new Date(msg.timestamp).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}
                                        </span>
                                    )}
                                </div>
                                <div
                                    className="whitespace-pre-wrap prose prose-invert prose-sm max-w-none"
                                    dangerouslySetInnerHTML={{ __html: formatMessage(msg.content) }}
                                />
                            </div>
                        </div>
                    ))}

                    {loading && (
                        <div className="flex gap-4 justify-start">
                            <div className="bg-gradient-to-br from-black to-slate-900 border border-emerald-500/30 rounded-xl p-4 text-emerald-500 text-sm flex items-center gap-3">
                                <div className="relative">
                                    <div className="absolute inset-0 rounded-full bg-emerald-500/30 animate-ping" />
                                    <Loader2 className="w-5 h-5 animate-spin relative" />
                                </div>
                                <div>
                                    <span className="font-semibold">AI Düşünüyor...</span>
                                    <span className="ml-2 text-xs opacity-50">(30-60 saniye sürebilir)</span>
                                </div>
                            </div>
                        </div>
                    )}

                    <div ref={messagesEndRef} />
                </div>

                {/* Input Area */}
                <div className="p-4 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border-t border-emerald-500/20">
                    <form onSubmit={handleSubmit} className="flex gap-3 max-w-5xl mx-auto">
                        <div className="relative flex-1 group">
                            <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none text-emerald-500/50 group-focus-within:text-emerald-400 transition-colors">
                                <ChevronRight className="w-5 h-5" />
                            </div>
                            <input
                                ref={inputRef}
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                placeholder="Soru sor, itiraz et, URL paylaş veya tarama iste..."
                                className="w-full bg-slate-950 text-emerald-100 placeholder-emerald-800/50 border border-emerald-900/50 rounded-xl pl-10 pr-4 py-3.5 focus:outline-none focus:border-emerald-500/50 focus:ring-2 focus:ring-emerald-500/20 transition-all font-mono"
                                disabled={loading}
                            />
                        </div>
                        <button
                            type="submit"
                            disabled={!input.trim() || loading}
                            className="bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-white px-6 rounded-xl font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 shadow-lg shadow-emerald-500/25"
                        >
                            <Send className="w-4 h-4" />
                            <span className="hidden sm:inline">GÖNDER</span>
                        </button>
                    </form>
                    <p className="text-center text-xs text-emerald-500/30 mt-3">
                        Kadim Security AI v3.0 • Chat History Enabled • URL Scan Support
                    </p>
                </div>
            </div>
        </div>
    );
}
