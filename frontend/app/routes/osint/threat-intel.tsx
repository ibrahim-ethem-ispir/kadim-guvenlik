/**
 * Türkçe: Threat Intelligence Sayfası
 * Shodan, VirusTotal ve AbuseIPDB entegrasyonları ile IP/Domain analizi
 * Professional UI/UX Enhancement
 */
import React, { useState } from 'react';
import {
    Search,
    Shield,
    AlertTriangle,
    CheckCircle,
    Server,
    Globe,
    Eye,
    AlertOctagon,
    Skull,
    Activity,
    ExternalLink,
    RefreshCw,
    Info,
    Lock,
    Clock
} from 'lucide-react';
import { api } from '../../services/api';
import { TipBox } from '../../components/osint/ui-components';

// Türkçe: Tip tanımları (Mevcut tipler aynen kalacak)
interface ShodanResult {
    ip: string;
    ports: number[];
    hostnames: string[];
    country: string | null;
    city: string | null;
    org: string | null;
    isp: string | null;
    asn: string | null;
    services: {
        port: number;
        transport: string;
        product: string | null;
        version: string | null;
    }[];
    vulns: string[];
    tags: string[];
}

interface VirusTotalResult {
    target: string;
    target_type: string;
    malicious_count: number;
    suspicious_count: number;
    harmless_count: number;
    reputation: number;
    categories: string[];
    tags: string[];
}

interface AbuseIPDBResult {
    ip: string;
    abuse_confidence_score: number;
    country_name: string | null;
    isp: string | null;
    usage_type: string | null;
    total_reports: number;
    last_reported_at: string | null;
}

interface ReputationResult {
    target: string;
    target_type: string;
    overall_score: number;
    risk_level: string;
    sources: {
        source: string;
        score: number;
        details: string | null;
        available: boolean;
    }[];
}

// Türkçe: Sorgu geçmişi tipi
interface QueryHistoryItem {
    target: string;
    timestamp: string;
    reputation: ReputationResult | null;
    shodan: ShodanResult | null;
    virustotal: VirusTotalResult | null;
    abuseipdb: AbuseIPDBResult | null;
}

const STORAGE_KEY = 'kadim_threat_intel_history';
const MAX_HISTORY = 10;

export default function ThreatIntel() {
    const [target, setTarget] = useState('');
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState<'reputation' | 'shodan' | 'virustotal' | 'abuseipdb'>('reputation');

    // Sonuçlar
    const [reputation, setReputation] = useState<ReputationResult | null>(null);
    const [shodan, setShodan] = useState<ShodanResult | null>(null);
    const [virustotal, setVirusTotal] = useState<VirusTotalResult | null>(null);
    const [abuseipdb, setAbuseIPDB] = useState<AbuseIPDBResult | null>(null);
    const [error, setError] = useState<string | null>(null);

    // Türkçe: Sorgu geçmişi
    const [queryHistory, setQueryHistory] = useState<QueryHistoryItem[]>([]);

    // Türkçe: Sayfa yüklendiğinde localStorage'dan geçmişi yükle
    React.useEffect(() => {
        try {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved) {
                const parsed = JSON.parse(saved) as QueryHistoryItem[];
                setQueryHistory(parsed);
                // Son sorguyu otomatik yükle
                if (parsed.length > 0) {
                    const last = parsed[0];
                    setTarget(last.target);
                    setReputation(last.reputation);
                    setShodan(last.shodan);
                    setVirusTotal(last.virustotal);
                    setAbuseIPDB(last.abuseipdb);
                }
            }
        } catch (e) {
            console.error('Failed to load query history:', e);
        }
    }, []);

    // Türkçe: Sonuçları localStorage'a kaydet
    const saveToHistory = (newItem: QueryHistoryItem) => {
        setQueryHistory(prev => {
            // Aynı target varsa güncelle, yoksa başa ekle
            const filtered = prev.filter(item => item.target !== newItem.target);
            const updated = [newItem, ...filtered].slice(0, MAX_HISTORY);
            try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
            } catch (e) {
                console.error('Failed to save query history:', e);
            }
            return updated;
        });
    };

    // Türkçe: Geçmişten bir sorguyu yükle
    const loadFromHistory = (item: QueryHistoryItem) => {
        setTarget(item.target);
        setReputation(item.reputation);
        setShodan(item.shodan);
        setVirusTotal(item.virustotal);
        setAbuseIPDB(item.abuseipdb);
        setError(null);
        setActiveTab('reputation');
    };

    // Türkçe: Geçmişi temizle
    const clearHistory = () => {
        setQueryHistory([]);
        localStorage.removeItem(STORAGE_KEY);
    };

    // Türkçe: Hedef tipini belirle
    const isIP = (value: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(value);

    // Türkçe: Tüm kaynaklardan sorgula
    const queryAll = async () => {
        if (!target.trim()) return;

        setLoading(true);
        setError(null);
        // Türkçe: Önceki sonuçları KORUYARAK yeni sorgu yap (eğer aynı target değilse temizle)
        const currentTarget = target.trim();
        if (reputation?.target !== currentTarget) {
            setReputation(null);
            setShodan(null);
            setVirusTotal(null);
            setAbuseIPDB(null);
        }
        setActiveTab('reputation');

        try {
            // Reputation (aggregate) - Paralel istekler için Promise.all kullanılabilir ama hata yönetimi için ayrı try-catch daha güvenli
            const repPromise = api.post<any>('/api/osint/lookup/reputation', { target: currentTarget });

            // Diğer servisler
            const vtPromise = api.post<any>('/api/osint/lookup/virustotal', { target: currentTarget });

            let shodanPromise = Promise.resolve({ success: false, data: null });
            let abusePromise = Promise.resolve({ success: false, data: null });

            if (isIP(currentTarget)) {
                shodanPromise = api.post<any>('/api/osint/lookup/shodan', { ip: currentTarget });
                abusePromise = api.post<any>('/api/osint/lookup/abuseipdb', { ip: currentTarget });
            }

            // Türkçe: Tüm sonuçları topla
            let repResult: ReputationResult | null = null;
            let vtResult: VirusTotalResult | null = null;
            let shodanResult: ShodanResult | null = null;
            let abuseResult: AbuseIPDBResult | null = null;

            // Ana reputation verisini bekle
            try {
                const repData = await repPromise;
                if (repData.success) {
                    repResult = repData.data;
                    setReputation(repData.data);
                }
            } catch (e: any) {
                console.error("Reputation error:", e);
                // En azından reputation gelmeli, yoksa kritik hata
                throw new Error("Sunucu yanıt vermiyor. Lütfen target'ı kontrol edin.");
            }

            // Diğer verileri arka planda tamamla (UI güncellemeleri)
            vtPromise.then(res => {
                if (res.success) {
                    vtResult = res.data;
                    setVirusTotal(res.data);
                }
            }).catch((err) => { console.error('VirusTotal error:', err); });

            shodanPromise.then(res => {
                if (res.success) {
                    shodanResult = res.data;
                    setShodan(res.data);
                }
            }).catch((err) => { console.error('Shodan error:', err); });

            abusePromise.then(res => {
                if (res.success) {
                    abuseResult = res.data;
                    setAbuseIPDB(res.data);
                }
            }).catch((err) => { console.error('AbuseIPDB error:', err); });

            // Türkçe: Tüm promise'lar tamamlandığında kaydet (3 saniye sonra)
            setTimeout(() => {
                saveToHistory({
                    target: currentTarget,
                    timestamp: new Date().toISOString(),
                    reputation: repResult,
                    shodan: shodanResult,
                    virustotal: vtResult,
                    abuseipdb: abuseResult
                });
            }, 3000);

        } catch (e: any) {
            setError(e.message || 'Sorgu başarısız');
        } finally {
            setLoading(false);
        }
    };

    // Türkçe: Risk seviyesine göre renk
    const getRiskColor = (level: string) => {
        switch (level) {
            case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/30 ring-red-500/20';
            case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/30 ring-orange-500/20';
            case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30 ring-yellow-500/20';
            default: return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30 ring-emerald-500/20';
        }
    };

    const getScoreColor = (score: number) => {
        if (score >= 75) return 'text-red-500';
        if (score >= 50) return 'text-orange-500';
        if (score >= 25) return 'text-yellow-500';
        return 'text-emerald-500';
    };

    return (
        <div className="space-y-6 pb-12 animate-in fade-in duration-500">
            {/* Header / Search Section */}
            <div className="bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-800 rounded-xl p-8 relative overflow-hidden shadow-2xl">
                <div className="absolute top-0 right-0 p-8 opacity-5">
                    <Skull className="w-64 h-64" />
                </div>

                <div className="relative z-10">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-8">
                        <div>
                            <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-3">
                                <Activity className="w-8 h-8 text-purple-500" />
                                Threat Intelligence
                            </h1>
                            <p className="text-slate-600 dark:text-slate-400 max-w-xl">
                                Advanced threat analysis using Shodan, VirusTotal, and AbuseIPDB.
                                Aggregate risk scoring for domains and IP addresses.
                            </p>
                        </div>
                    </div>

                    <div className="flex gap-3 max-w-3xl">
                        <div className="flex-1 relative group">
                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <Search className="w-5 h-5 text-slate-500 dark:text-slate-500 group-focus-within:text-purple-500 transition-colors" />
                            </div>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && queryAll()}
                                placeholder="Enter IP address (e.g., 8.8.8.8) or Domain (e.g., example.com)"
                                className="w-full pl-12 pr-4 py-4 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded-xl text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500 transition-all shadow-inner"
                            />
                        </div>
                        <button
                            onClick={queryAll}
                            disabled={loading || !target.trim()}
                            className="flex items-center gap-2 px-8 py-4 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-300 dark:disabled:bg-slate-800 disabled:text-slate-500 dark:disabled:text-slate-500 disabled:cursor-not-allowed text-white rounded-xl transition-all font-medium shadow-lg shadow-purple-900/20 hover:shadow-purple-900/40 transform hover:-translate-y-0.5 active:translate-y-0"
                        >
                            {loading ? (
                                <>
                                    <RefreshCw className="w-5 h-5 animate-spin" />
                                    Analyzing...
                                </>
                            ) : (
                                <>
                                    <Shield className="w-5 h-5" />
                                    Analyze Target
                                </>
                            )}
                        </button>
                    </div>
                </div>
            </div>

            {/* Query History Section */}
            {queryHistory.length > 0 && (
                <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-3">
                        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                            <Clock className="w-4 h-4 text-purple-400" />
                            Son Sorgular
                        </h3>
                        <button
                            onClick={clearHistory}
                            className="text-xs text-slate-400 hover:text-red-400 transition-colors"
                        >
                            Temizle
                        </button>
                    </div>
                    <div className="flex flex-wrap gap-2">
                        {queryHistory.map((item, idx) => (
                            <button
                                key={idx}
                                onClick={() => loadFromHistory(item)}
                                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${target === item.target
                                    ? 'bg-purple-600 text-white'
                                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-purple-100 dark:hover:bg-purple-900/30 hover:text-purple-600 dark:hover:text-purple-400'
                                    }`}
                            >
                                {item.target}
                                {item.reputation && (
                                    <span className={`ml-2 text-xs ${getScoreColor(item.reputation.overall_score)}`}>
                                        ({item.reputation.overall_score.toFixed(0)})
                                    </span>
                                )}
                            </button>
                        ))}
                    </div>
                </div>
            )}

            {error && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-4 text-red-400 animate-in slide-in-from-top-4">
                    <div className="p-2 bg-red-500/20 rounded-lg">
                        <AlertTriangle className="w-6 h-6" />
                    </div>
                    <div>
                        <div className="font-semibold text-red-300">Analysis Failed</div>
                        <div className="text-sm opacity-90">{error}</div>
                    </div>
                </div>
            )}

            {loading && !reputation && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-pulse">
                    <div className="col-span-3 h-48 bg-slate-100 dark:bg-slate-900 rounded-xl border border-slate-300 dark:border-slate-800"></div>
                    <div className="h-64 bg-slate-100 dark:bg-slate-900 rounded-xl border border-slate-300 dark:border-slate-800"></div>
                    <div className="h-64 bg-slate-100 dark:bg-slate-900 rounded-xl border border-slate-300 dark:border-slate-800"></div>
                    <div className="h-64 bg-slate-100 dark:bg-slate-900 rounded-xl border border-slate-300 dark:border-slate-800"></div>
                </div>
            )}

            {reputation && (
                <div className="space-y-6 animate-in slide-in-from-bottom-8 duration-700">
                    {/* Summary Card */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <div className="lg:col-span-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-800 rounded-xl p-8 relative overflow-hidden">
                            <div className="flex items-start justify-between relative z-10">
                                <div className="space-y-4">
                                    <div className="flex items-center gap-3">
                                        <h2 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight">{reputation.target}</h2>
                                        <span className="px-2 py-1 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-400 text-xs rounded uppercase font-bold tracking-wider">
                                            {reputation.target_type}
                                        </span>
                                    </div>

                                    <div className="flex items-center gap-4">
                                        <div className={`px-4 py-2 rounded-lg border flex items-center gap-2 ${getRiskColor(reputation.risk_level)}`}>
                                            {reputation.risk_level === 'critical' || reputation.risk_level === 'high' ? (
                                                <AlertOctagon className="w-5 h-5" />
                                            ) : (
                                                <CheckCircle className="w-5 h-5" />
                                            )}
                                            <span className="font-bold uppercase tracking-wide">{reputation.risk_level} RISK</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="text-right">
                                    <div className="text-sm text-slate-600 dark:text-slate-400 uppercase tracking-widest mb-1 font-semibold">Aggregate Score</div>
                                    <div className="flex items-baseline justify-end gap-1">
                                        <span className={`text-6xl font-black ${getScoreColor(reputation.overall_score)} tracking-tighter`}>
                                            {reputation.overall_score.toFixed(0)}
                                        </span>
                                        <span className="text-xl text-slate-400 dark:text-slate-600 font-medium">/100</span>
                                    </div>
                                </div>
                            </div>

                            {/* Source Availability */}
                            <div className="mt-8 pt-6 border-t border-slate-300 dark:border-slate-800 grid grid-cols-3 gap-4">
                                {reputation.sources.map(source => (
                                    <div key={source.source} className="flex items-center gap-3">
                                        <div className={`w-2 h-2 rounded-full ${source.available ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-slate-400 dark:bg-slate-700'}`}></div>
                                        <span className={`text-sm font-medium ${source.available ? 'text-slate-700 dark:text-slate-300' : 'text-slate-400 dark:text-slate-600 line-through'}`}>
                                            {source.source.toUpperCase()}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Quick Tips */}
                        <div className="lg:col-span-1">
                            <TipBox title="Analyst Note" variant="info">
                                {reputation.risk_level === 'critical'
                                    ? "Immediate action required. High-risk indicators detected across multiple sources. Consider isolating this asset."
                                    : "Monitor this asset. Periodic scans are recommended to detect changes in threat landscape."
                                }
                            </TipBox>
                        </div>
                    </div>

                    {/* Tabs */}
                    <div className="flex gap-1 bg-slate-200 dark:bg-slate-900/50 p-1 rounded-xl w-fit border border-slate-300 dark:border-slate-800">
                        {[
                            { id: 'reputation', icon: Activity, label: 'Overview' },
                            ...(shodan ? [{ id: 'shodan', icon: Eye, label: 'Shodan' }] : []),
                            ...(virustotal ? [{ id: 'virustotal', icon: Shield, label: 'VirusTotal' }] : []),
                            ...(abuseipdb ? [{ id: 'abuseipdb', icon: AlertTriangle, label: 'AbuseIPDB' }] : []),
                        ].map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id as any)}
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${activeTab === tab.id
                                    ? 'bg-purple-600 text-white shadow-lg'
                                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-300 dark:hover:bg-slate-800'
                                    }`}
                            >
                                <tab.icon className="w-4 h-4" />
                                {tab.label}
                            </button>
                        ))}
                    </div>

                    {/* Content Area */}
                    <div className="bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-800 rounded-xl p-6 min-h-[400px]">

                        {/* Shodan Content */}
                        {activeTab === 'shodan' && shodan && (
                            <div className="space-y-8 animate-in fade-in slide-in-from-left-4">
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    {[
                                        { label: 'Organization', value: shodan.org },
                                        { label: 'ASN', value: shodan.asn },
                                        { label: 'ISP', value: shodan.isp },
                                        { label: 'Location', value: `${shodan.city || ''}, ${shodan.country || ''}` }
                                    ].map((item, i) => (
                                        <div key={i} className="bg-slate-100 dark:bg-slate-950 p-4 rounded-lg border border-slate-200 dark:border-slate-800">
                                            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">{item.label}</div>
                                            <div className="text-slate-700 dark:text-slate-200 font-medium truncate" title={item.value || ''}>{item.value || 'N/A'}</div>
                                        </div>
                                    ))}
                                </div>

                                <div>
                                    <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                                        <Server className="w-5 h-5 text-orange-400" />
                                        Open Ports & Services
                                    </h3>
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                        {shodan.services.map((svc, i) => (
                                            <div key={i} className="bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-4 hover:border-orange-500/30 transition-colors group">
                                                <div className="flex items-center justify-between mb-2">
                                                    <span className="text-2xl font-mono font-bold text-orange-400">{svc.port}</span>
                                                    <span className="px-2 py-1 bg-slate-200 dark:bg-slate-900 rounded text-xs text-slate-600 dark:text-slate-500 uppercase">{svc.transport}</span>
                                                </div>
                                                <div className="text-slate-700 dark:text-slate-300 font-medium mb-1">{svc.product || 'Unknown Service'}</div>
                                                <div className="text-xs text-slate-500 group-hover:text-slate-400">{svc.version || ''}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* VirusTotal Content */}
                        {activeTab === 'virustotal' && virustotal && (
                            <div className="space-y-8 animate-in fade-in slide-in-from-left-4">
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                                    <div className="text-center p-6 bg-slate-100 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800">
                                        <div className="text-4xl font-bold text-red-500 mb-2">{virustotal.malicious_count}</div>
                                        <div className="text-sm text-red-400/80 font-medium uppercase tracking-wider">Malicious</div>
                                    </div>
                                    <div className="text-center p-6 bg-slate-100 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800">
                                        <div className="text-4xl font-bold text-yellow-500 mb-2">{virustotal.suspicious_count}</div>
                                        <div className="text-sm text-yellow-400/80 font-medium uppercase tracking-wider">Suspicious</div>
                                    </div>
                                    <div className="text-center p-6 bg-slate-100 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800">
                                        <div className="text-4xl font-bold text-green-500 mb-2">{virustotal.harmless_count}</div>
                                        <div className="text-sm text-green-400/80 font-medium uppercase tracking-wider">Harmless</div>
                                    </div>
                                    <div className="bg-slate-200 dark:bg-slate-700/50 border border-slate-300 dark:border-slate-600 p-4 rounded-lg text-center">
                                        <div className="text-3xl font-bold text-slate-700 dark:text-slate-300">{virustotal.reputation}</div>
                                        <div className="text-xs text-slate-400 mt-1">Reputation</div>
                                    </div>
                                </div>

                                {virustotal.tags.length > 0 && (
                                    <div>
                                        <h3 className="text-sm font-medium text-slate-400 mb-3 uppercase tracking-wider">Tags</h3>
                                        <div className="flex flex-wrap gap-2">
                                            {virustotal.tags.map((tag, i) => (
                                                <span key={i} className="px-3 py-1.5 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg text-sm border border-slate-300 dark:border-slate-700">
                                                    #{tag}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* AbuseIPDB Content */}
                        {activeTab === 'abuseipdb' && abuseipdb && (
                            <div className="space-y-8 animate-in fade-in slide-in-from-left-4">
                                <div className="flex items-center gap-8 bg-slate-100 dark:bg-slate-950 p-8 rounded-xl border border-slate-200 dark:border-slate-800">
                                    <div className="relative">
                                        <svg className="w-32 h-32 transform -rotate-90">
                                            <circle
                                                className="text-slate-200 dark:text-slate-800"
                                                strokeWidth="8"
                                                stroke="currentColor"
                                                fill="transparent"
                                                r="58"
                                                cx="64"
                                                cy="64"
                                            />
                                            <circle
                                                className={`${getScoreColor(abuseipdb.abuse_confidence_score)}`}
                                                strokeWidth="8"
                                                strokeDasharray={365}
                                                strokeDashoffset={365 - (365 * abuseipdb.abuse_confidence_score) / 100}
                                                strokeLinecap="round"
                                                stroke="currentColor"
                                                fill="transparent"
                                                r="58"
                                                cx="64"
                                                cy="64"
                                            />
                                        </svg>
                                        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-center">
                                            <span className={`text-3xl font-bold ${getScoreColor(abuseipdb.abuse_confidence_score)}`}>{abuseipdb.abuse_confidence_score}%</span>
                                        </div>
                                    </div>
                                    <div>
                                        <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">Abuse Confidence Score</h3>
                                        <p className="text-slate-400 max-w-md">
                                            Probability that this IP address is involved in malicious activity based on reports.
                                        </p>
                                    </div>
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div className="bg-slate-100 dark:bg-slate-950 p-4 rounded-lg border border-slate-200 dark:border-slate-800 flex justify-between items-center">
                                        <span className="text-slate-400">Total Reports</span>
                                        <span className="text-xl font-bold text-slate-900 dark:text-white">{abuseipdb.total_reports}</span>
                                    </div>
                                    <div className="bg-slate-100 dark:bg-slate-950 p-4 rounded-lg border border-slate-200 dark:border-slate-800 flex justify-between items-center">
                                        <span className="text-slate-400">Usage Type</span>
                                        <span className="text-xl font-bold text-slate-900 dark:text-white">{abuseipdb.usage_type || 'Unknown'}</span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Overview Tab Default Content */}
                        {activeTab === 'reputation' && (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in fade-in slide-in-from-left-4">
                                {reputation.sources.map(source => (
                                    <div key={source.source} className={`relative p-6 rounded-xl border transition-all ${source.available
                                        ? 'bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                                        : 'bg-slate-100 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800/50 opacity-60'
                                        }`}>
                                        {!source.available && (
                                            <div className="absolute top-3 right-3 text-slate-600">
                                                <Lock className="w-4 h-4" />
                                            </div>
                                        )}

                                        <div className="flex items-center justify-between mb-4">
                                            <span className="text-lg font-bold text-slate-900 dark:text-white uppercase">{source.source}</span>
                                            {source.available && (
                                                <span className={`text-2xl font-bold ${getScoreColor(source.score)}`}>
                                                    {source.score.toFixed(0)}
                                                </span>
                                            )}
                                        </div>

                                        <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden mb-3">
                                            <div
                                                className={`h-full ${getRiskColor(source.score > 50 ? 'high' : 'low').split(' ')[0].replace('text-', 'bg-')}`}
                                                style={{ width: `${source.score}%` }}
                                            ></div>
                                        </div>

                                        <p className="text-sm text-slate-500">
                                            {source.available ? source.details : "API configuration required"}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
