import { useState, useEffect, useRef } from 'react';
import { Form } from 'react-router';
import { api } from '../services/api';

interface SubdomainInfo {
    subdomain: string;
    ip: string;
    is_cf: boolean;
}

interface AnalysisResult {
    domain: string;
    dns: {
        is_cf: boolean;
        ips: string[];
    };
    http: {
        headers: Record<string, string>;
        found_cf: boolean;
    };
    subdomains: {
        found: SubdomainInfo[];
    };
}

interface ScanStatus {
    id: string;
    state: 'Pending' | 'Running' | 'Completed' | 'Failed' | 'Cancelled';
    progress: number;
    current_step: string;
    total_subdomains: number;
    scanned_subdomains: number;
    logs: string[];
    result: AnalysisResult | null;
    error: string | null;
    // Analytical Metrics
    start_time: number;
    scan_rate: number;
    estimated_time_remaining: number;
    current_wordlist: string;
    total_wordlists: number;
    processed_wordlists: number;
    // Cancellation flag
    cancelled: boolean;
}

export default function CloudflareAnalyzer() {
    const [domain, setDomain] = useState('');
    const [wordlist, setWordlist] = useState('files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt');
    const [wordlists, setWordlists] = useState<any[]>([]);

    // Advanced Config
    const [concurrency, setConcurrency] = useState(50);
    const [delay, setDelay] = useState(0);
    const [timeout, setTimeoutVal] = useState(10);
    const [showAdvanced, setShowAdvanced] = useState(false);

    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [scanId, setScanId] = useState<string | null>(null);
    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
    const [error, setError] = useState<string | null>(null);
    const logsEndRef = useRef<HTMLDivElement>(null);

    // Fetch available wordlists on component mount
    useEffect(() => {
        api.get<any>('/api/cf-analyzer/wordlists')
            .then(data => setWordlists(data.wordlists || []))
            .catch(err => console.error('Failed to load wordlists:', err));
    }, []);

    // Auto-scroll logs
    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [scanStatus?.logs]);

    // Polling logic
    useEffect(() => {
        let interval: any;

        if (isAnalyzing && scanId) {
            interval = setInterval(async () => {
                try {
                    const status = await api.get<ScanStatus>(`/api/cf-analyzer/analyze/${scanId}`);
                    setScanStatus(status);

                    if (status.state === 'Completed' || status.state === 'Failed' || status.state === 'Cancelled') {
                        setIsAnalyzing(false);
                        if (status.state === 'Failed') {
                            setError(status.error || 'Scan failed');
                        }
                    }
                } catch (err) {
                    console.error("Polling error:", err);
                }
            }, 1000);
        }

        return () => clearInterval(interval);
    }, [isAnalyzing, scanId]);

    const handleAnalyze = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsAnalyzing(true);
        setScanStatus(null);
        setError(null);

        try {
            const data = await api.post<any>('/api/cf-analyzer/analyze', {
                domain,
                wordlist,
                concurrency: Number(concurrency),
                delay_ms: Number(delay),
                timeout_minutes: Number(timeout)
            });

            setScanId(data.scan_id);
        } catch (err: any) {
            setError(err.message || 'Analiz başlatılamadı');
            setIsAnalyzing(false);
        }
    };

    // Taramayı iptal etmek için fonksiyon - Durdur butonu
    const handleCancel = async () => {
        if (!scanId) return;

        try {
            const data = await api.post<any>(`/api/cf-analyzer/analyze/${scanId}/cancel`, {});

            if (data.success) {
                // Tarama iptal edildi, polling devam edecek ve Cancelled durumunu alacak
                console.log('Tarama iptal edildi');
            }
        } catch (err) {
            console.error('İptal hatası:', err);
        }
    };

    // Helper to format seconds
    const formatTime = (seconds: number) => {
        if (seconds < 60) return `${seconds}s`;
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m}m ${s}s`;
    };

    // Helper to format file size
    const formatFileSize = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    return (
        <div className="min-h-screen bg-slate-950 text-white p-8 font-sans">
            <div className="max-w-7xl mx-auto">
                <header className="mb-12 text-center">
                    <h1 className="text-5xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-orange-400 to-red-600 mb-4">
                        Cloudflare Analyzer
                    </h1>
                    <p className="text-slate-400 text-lg">
                        Gelişmiş DNS Analizi, Subdomain Keşfi ve Gerçek IP Tespiti
                    </p>
                </header>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
                    {/* Sol Panel: Kontrol */}
                    <div className="lg:col-span-1 bg-slate-900/50 p-6 rounded-2xl border border-slate-800 backdrop-blur-sm shadow-xl h-fit">
                        <h2 className="text-xl font-bold mb-6 text-orange-400 flex items-center gap-2">
                            <span className="w-2 h-2 bg-orange-500 rounded-full animate-pulse"></span>
                            Hedef Tanımla
                        </h2>

                        <Form onSubmit={handleAnalyze} className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-slate-400 mb-1">Domain Adresi</label>
                                <input
                                    type="text"
                                    placeholder="example.com"
                                    value={domain}
                                    onChange={(e) => setDomain(e.target.value)}
                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-white focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-all outline-none"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-slate-400 mb-1">Wordlist Seçimi</label>
                                <select
                                    value={wordlist}
                                    onChange={(e) => setWordlist(e.target.value)}
                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-white focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-all outline-none cursor-pointer"
                                >
                                    <option value="all" className="font-bold text-orange-400">⚡ TÜM LİSTELERİ TARA (Maksimum Kapsam)</option>
                                    <option disabled>──────────────────────────</option>

                                    {wordlists.length > 0 ? (
                                        <>
                                            {/* Quick Scans */}
                                            <option disabled className="font-bold">🚀 HIZLI TARAMALAR</option>
                                            {wordlists.filter(wl => wl.size_bytes < 100000).map((wl) => (
                                                <option key={wl.path} value={wl.path}>
                                                    {wl.description} - {formatFileSize(wl.size_bytes)}
                                                </option>
                                            ))}

                                            <option disabled>──────────────────────────</option>

                                            {/* Standard Scans */}
                                            <option disabled className="font-bold">📊 STANDART TARAMALAR</option>
                                            {wordlists.filter(wl => wl.size_bytes >= 100000 && wl.size_bytes < 2000000).map((wl) => (
                                                <option key={wl.path} value={wl.path}>
                                                    {wl.description} - {formatFileSize(wl.size_bytes)}
                                                </option>
                                            ))}

                                            <option disabled>──────────────────────────</option>

                                            {/* Comprehensive Scans */}
                                            <option disabled className="font-bold">🔥 KAPSAMLI TARAMALAR</option>
                                            {wordlists.filter(wl => wl.size_bytes >= 2000000 && wl.size_bytes < 30000000).map((wl) => (
                                                <option key={wl.path} value={wl.path}>
                                                    {wl.description} - {formatFileSize(wl.size_bytes)}
                                                </option>
                                            ))}

                                            <option disabled>──────────────────────────</option>

                                            {/* Massive Scans */}
                                            <option disabled className="font-bold">💎 DEV TARAMALAR (Uzun Süre)</option>
                                            {wordlists.filter(wl => wl.size_bytes >= 30000000).map((wl) => (
                                                <option key={wl.path} value={wl.path}>
                                                    {wl.description} - {formatFileSize(wl.size_bytes)}
                                                </option>
                                            ))}
                                        </>
                                    ) : (
                                        <option disabled>Yükleniyor...</option>
                                    )}
                                </select>
                                {wordlists.length === 0 && (
                                    <p className="text-xs text-slate-500 mt-1">Wordlist'ler yükleniyor...</p>
                                )}
                            </div>

                            <div className="border-t border-slate-800 pt-4">
                                <button
                                    type="button"
                                    onClick={() => setShowAdvanced(!showAdvanced)}
                                    className="text-sm text-slate-400 hover:text-white flex items-center gap-2 transition-colors"
                                >
                                    {showAdvanced ? '▼' : '▶'} Gelişmiş Ayarlar
                                </button>

                                {showAdvanced && (
                                    <div className="mt-4 space-y-4 animate-fade-in">
                                        <div>
                                            <label className="block text-xs font-medium text-slate-500 mb-1">Eşzamanlılık (Concurrency)</label>
                                            <input
                                                type="number"
                                                value={concurrency}
                                                onChange={(e) => setConcurrency(Number(e.target.value))}
                                                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs font-medium text-slate-500 mb-1">Gecikme (ms)</label>
                                            <input
                                                type="number"
                                                value={delay}
                                                onChange={(e) => setDelay(Number(e.target.value))}
                                                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs font-medium text-slate-500 mb-1">Zaman Aşımı (dk)</label>
                                            <input
                                                type="number"
                                                value={timeout}
                                                onChange={(e) => setTimeoutVal(Number(e.target.value))}
                                                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm"
                                            />
                                        </div>
                                    </div>
                                )}
                            </div>

                            <button
                                type="submit"
                                disabled={isAnalyzing || !domain}
                                className={`w-full py-3 rounded-lg font-bold text-lg transition-all ${isAnalyzing
                                    ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                                    : 'bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-500 hover:to-red-500 text-white shadow-lg shadow-orange-900/20'
                                    }`}
                            >
                                {isAnalyzing ? 'Analiz Ediliyor...' : 'Taramayı Başlat'}
                            </button>

                            {/* Durdur Butonu - Tarama devam ederken görünür */}
                            {isAnalyzing && (
                                <button
                                    type="button"
                                    onClick={handleCancel}
                                    className="w-full mt-2 py-3 rounded-lg font-bold text-lg transition-all bg-red-900/50 hover:bg-red-800/70 text-red-300 border border-red-700"
                                >
                                    ⛔ Taramayı Durdur
                                </button>
                            )}
                        </Form>

                        {error && (
                            <div className="mt-4 p-4 bg-red-900/20 border border-red-900/50 rounded-lg">
                                <p className="text-red-400 text-sm">{error}</p>
                            </div>
                        )}

                        {/* İptal durumu gösterimi */}
                        {scanStatus?.state === 'Cancelled' && (
                            <div className="mt-4 p-4 bg-yellow-900/20 border border-yellow-900/50 rounded-lg">
                                <p className="text-yellow-400 text-sm">⛔ Tarama kullanıcı tarafından iptal edildi</p>
                            </div>
                        )}
                    </div>

                    {/* Sağ Panel: Terminal / Loglar */}
                    <div className="lg:col-span-2 flex flex-col gap-4">
                        {/* Başlangıç Durumu - scanStatus henüz gelmeden önce */}
                        {isAnalyzing && !scanStatus && (
                            <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800 animate-pulse">
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-3 h-3 bg-orange-500 rounded-full animate-ping"></div>
                                    <span className="text-slate-300">Tarama başlatılıyor...</span>
                                </div>
                                <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                                    <div className="bg-gradient-to-r from-orange-500 to-red-600 h-2.5 rounded-full w-1/4 animate-pulse"></div>
                                </div>
                                <p className="text-xs text-slate-500 mt-2">Backend'e bağlanılıyor ve tarama hazırlanıyor...</p>
                            </div>
                        )}

                        {/* Progress Bar & Metrics */}
                        {scanStatus && (
                            <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                                <div className="flex justify-between text-sm mb-2">
                                    <div className="flex items-center gap-2">
                                        {/* Durum göstergesi */}
                                        {scanStatus.state === 'Running' && (
                                            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                                        )}
                                        {scanStatus.state === 'Pending' && (
                                            <span className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></span>
                                        )}
                                        {scanStatus.state === 'Completed' && (
                                            <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                                        )}
                                        {scanStatus.state === 'Failed' && (
                                            <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                                        )}
                                        {scanStatus.state === 'Cancelled' && (
                                            <span className="w-2 h-2 bg-orange-500 rounded-full"></span>
                                        )}
                                        <span className="text-slate-300">{scanStatus.current_step}</span>
                                    </div>
                                    <span className="text-orange-400 font-mono">{scanStatus.progress.toFixed(1)}%</span>
                                </div>
                                <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden mb-4">
                                    <div
                                        className={`h-2.5 rounded-full transition-all duration-500 ${scanStatus.state === 'Cancelled'
                                            ? 'bg-gradient-to-r from-orange-700 to-red-800'
                                            : 'bg-gradient-to-r from-orange-500 to-red-600'
                                            }`}
                                        style={{ width: `${scanStatus.progress}%` }}
                                    ></div>
                                </div>

                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                                    <div className="bg-slate-950 p-2 rounded border border-slate-800">
                                        <div className="text-slate-500 mb-1">Durum</div>
                                        <div className={`font-mono font-bold ${scanStatus.state === 'Running' ? 'text-green-400' :
                                            scanStatus.state === 'Pending' ? 'text-yellow-400' :
                                                scanStatus.state === 'Completed' ? 'text-blue-400' :
                                                    scanStatus.state === 'Cancelled' ? 'text-orange-400' :
                                                        'text-red-400'
                                            }`}>
                                            {scanStatus.state === 'Running' ? '🔄 Çalışıyor' :
                                                scanStatus.state === 'Pending' ? '⏳ Bekliyor' :
                                                    scanStatus.state === 'Completed' ? '✅ Tamamlandı' :
                                                        scanStatus.state === 'Cancelled' ? '⛔ İptal Edildi' :
                                                            '❌ Hata'}
                                        </div>
                                    </div>
                                    <div className="bg-slate-900 p-2 rounded border border-slate-800">
                                        <div className="text-slate-500 mb-1">Hız</div>
                                        <div className="text-cyan-400 font-mono">{scanStatus.scan_rate.toFixed(1)} sub/s</div>
                                    </div>
                                    <div className="bg-slate-950 p-2 rounded border border-slate-800">
                                        <div className="text-slate-500 mb-1">Tahmini Süre</div>
                                        <div className="text-yellow-400 font-mono">{formatTime(scanStatus.estimated_time_remaining)}</div>
                                    </div>
                                    <div className="bg-slate-900 p-2 rounded border border-slate-800">
                                        <div className="text-slate-500 mb-1">Taranan</div>
                                        <div className="text-green-400 font-mono">{scanStatus.scanned_subdomains} / {scanStatus.total_subdomains}</div>
                                    </div>
                                    <div className="bg-slate-900 p-2 rounded border border-slate-800">
                                        <div className="text-slate-500 mb-1">Wordlist</div>
                                        <div className="text-purple-400 font-mono truncate" title={scanStatus.current_wordlist}>
                                            {scanStatus.current_wordlist || '-'}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        <div className="bg-black rounded-2xl border border-slate-800 shadow-2xl overflow-hidden flex flex-col h-[500px]">
                            <div className="bg-slate-900 px-4 py-2 border-b border-slate-800 flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <div className={`w-3 h-3 rounded-full ${isAnalyzing ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
                                    <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                                </div>
                                <div className="flex items-center gap-4">
                                    {/* Canlı durum göstergesi */}
                                    {isAnalyzing && (
                                        <div className="flex items-center gap-2 text-xs">
                                            <span className="w-2 h-2 bg-green-500 rounded-full animate-ping"></span>
                                            <span className="text-green-400">CANLI</span>
                                        </div>
                                    )}
                                    <div className="text-xs text-slate-500 font-mono">root@kadim-guvenlik:~</div>
                                </div>
                            </div>

                            <div className="flex-1 p-6 font-mono text-sm overflow-y-auto space-y-2 custom-scrollbar">
                                <div className="text-slate-500"># Sistem hazır. Analiz bekleniyor...</div>

                                {/* Tarama başladı ama henüz log gelmedi */}
                                {isAnalyzing && !scanStatus && (
                                    <div className="animate-fade-in">
                                        <span className="text-green-500 mr-2">➜</span>
                                        <span className="text-cyan-400">Backend'e bağlanılıyor...</span>
                                    </div>
                                )}

                                {/* Tarama başladı, scan ID alındı ama log henüz yok */}
                                {isAnalyzing && scanId && (!scanStatus?.logs || scanStatus.logs.length === 0) && (
                                    <div className="animate-fade-in">
                                        <span className="text-green-500 mr-2">➜</span>
                                        <span className="text-yellow-400">Tarama ID: {scanId}</span>
                                    </div>
                                )}

                                {scanStatus?.logs.map((log, index) => (
                                    <div key={index} className="animate-fade-in">
                                        <span className="text-green-500 mr-2">➜</span>
                                        <span className={
                                            log.includes('⚠️') || log.includes('❌') ? 'text-yellow-400' :
                                                log.includes('✔') || log.includes('✅') || log.includes('🛡️') ? 'text-green-400' :
                                                    log.includes('⛔') ? 'text-red-400' :
                                                        log.includes('🚀') || log.includes('🔍') || log.includes('📡') ? 'text-cyan-400' :
                                                            log.includes('⚡') ? 'text-purple-400' :
                                                                'text-slate-300'
                                        }>
                                            {log}
                                        </span>
                                    </div>
                                ))}
                                <div ref={logsEndRef} />
                                {isAnalyzing && (
                                    <div className="animate-pulse text-orange-500">_</div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Results Section */}
                {scanStatus?.result && (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in-up">
                        {/* DNS Analysis */}
                        <div className="bg-slate-900/50 p-6 rounded-2xl border border-slate-800">
                            <h3 className="text-lg font-bold mb-4 text-blue-400 flex items-center gap-2">
                                <span>🌐</span> DNS Analizi
                            </h3>
                            <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-400 text-sm">Cloudflare Tespit:</span>
                                    <span className={`font-bold ${scanStatus.result.dns.is_cf ? 'text-orange-400' : 'text-green-400'}`}>
                                        {scanStatus.result.dns.is_cf ? '✓ Evet' : '✗ Hayır'}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-slate-400 text-sm block mb-2">IP Adresleri:</span>
                                    <div className="space-y-1">
                                        {scanStatus.result.dns.ips.map((ip, i) => (
                                            <div key={i} className="text-xs bg-slate-950 px-3 py-2 rounded font-mono text-cyan-400">
                                                {ip}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* HTTP Analysis */}
                        <div className="bg-slate-900/50 p-6 rounded-2xl border border-slate-800">
                            <h3 className="text-lg font-bold mb-4 text-purple-400 flex items-center gap-2">
                                <span>📡</span> HTTP Analizi
                            </h3>
                            <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-400 text-sm">CF Header Tespit:</span>
                                    <span className={`font-bold ${scanStatus.result.http.found_cf ? 'text-orange-400' : 'text-green-400'}`}>
                                        {scanStatus.result.http.found_cf ? '✓ Evet' : '✗ Hayır'}
                                    </span>
                                </div>
                                <div>
                                    <span className="text-slate-400 text-sm block mb-2">Önemli Header'lar:</span>
                                    <div className="max-h-32 overflow-y-auto space-y-1">
                                        {Object.entries(scanStatus.result.http.headers).slice(0, 5).map(([key, value], i) => (
                                            <div key={i} className="text-xs bg-slate-950 px-3 py-1 rounded">
                                                <span className="text-slate-500">{key}:</span>
                                                <span className="text-slate-300 ml-2">{value.substring(0, 30)}{value.length > 30 ? '...' : ''}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Subdomain Stats */}
                        <div className="bg-slate-900/50 p-6 rounded-2xl border border-slate-800">
                            <h3 className="text-lg font-bold mb-4 text-green-400 flex items-center gap-2">
                                <span>🔍</span> Subdomain İstatistikleri
                            </h3>
                            <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-400 text-sm">Toplam Bulunan:</span>
                                    <span className="font-bold text-green-400 text-2xl">{scanStatus.result.subdomains.found.length}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-400 text-sm">CF Arkasında:</span>
                                    <span className="font-bold text-orange-400 text-2xl">
                                        {scanStatus.result.subdomains.found.filter(s => s.is_cf).length}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-slate-400 text-sm">Gerçek IP:</span>
                                    <span className="font-bold text-cyan-400 text-2xl">
                                        {scanStatus.result.subdomains.found.filter(s => !s.is_cf).length}
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* Subdomain List */}
                        {scanStatus.result.subdomains.found.length > 0 && (
                            <div className="lg:col-span-3 bg-slate-900/50 p-6 rounded-2xl border border-slate-800">
                                <h3 className="text-lg font-bold mb-4 text-cyan-400 flex items-center gap-2">
                                    <span>📋</span> Bulunan Subdomain'ler
                                </h3>
                                <div className="overflow-x-auto">
                                    <table className="w-full text-sm">
                                        <thead>
                                            <tr className="border-b border-slate-700">
                                                <th className="text-left py-2 px-4 text-slate-400 font-medium">Subdomain</th>
                                                <th className="text-left py-2 px-4 text-slate-400 font-medium">IP Adresi</th>
                                                <th className="text-center py-2 px-4 text-slate-400 font-medium">Cloudflare</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {scanStatus.result.subdomains.found.map((sub, i) => (
                                                <tr key={i} className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                                                    <td className="py-3 px-4 font-mono text-cyan-400">{sub.subdomain}</td>
                                                    <td className="py-3 px-4 font-mono text-slate-300">{sub.ip}</td>
                                                    <td className="py-3 px-4 text-center">
                                                        {sub.is_cf ? (
                                                            <span className="inline-block px-3 py-1 bg-orange-900/30 text-orange-400 rounded-full text-xs font-bold">
                                                                🛡️ CF
                                                            </span>
                                                        ) : (
                                                            <span className="inline-block px-3 py-1 bg-green-900/30 text-green-400 rounded-full text-xs font-bold">
                                                                ✓ Gerçek IP
                                                            </span>
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

