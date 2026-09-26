import { useState, useEffect, useRef } from 'react';
import { Form } from 'react-router';
import Tooltip from '../components/Tooltip';
import AIAnalysisPanel from '../components/AIAnalysisPanel';
import { api } from '../services/api';
import { generateHashCrackerReport } from '../libs/report-generator';

// ============================================================================
// TYPES
// ============================================================================

interface AlgorithmInfo {
    id: string;
    name: string;
    category: string;
    length: number;
    description: string;
    security_level: string;
    speed: string;
    use_cases: string[];
    emoji: string;
}

interface HashInfo {
    hash_type: string;
    confidence: number;
    description: string;
    security_level: string;
    crack_difficulty: string;
    example_tools: string[];
    warning?: string;        // HMAC veya özel durumlar için uyarı
    is_crackable?: boolean;  // Secret key gerektiren hash'ler için false
}

interface WordlistEntry {
    path: string;
    name: string;
    description: string;
    size_bytes: number;
    line_count: number | null;
    category: string;
    emoji: string;
}

interface CrackJob {
    id: string;
    state: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
    hash: string;
    hash_type: string;
    attack_mode: string;
    progress: {
        attempts: number;
        rate: number;
        elapsed_ms: number;
        percent: number;
    };
    result: {
        found: boolean;
        password: string | null;
        attempts: number;
        elapsed_ms: number;
        rate: number;
    } | null;
    logs: string[];
    created_at: number;
}

interface ScanHistoryEntry {
    id: string;
    hash: string;
    hash_type: string;
    attack_mode: string;
    found: boolean;
    password: string | null;
    attempts: number;
    elapsed_ms: number;
    timestamp: number;
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function HashCracker() {
    // State
    const [hash, setHash] = useState('');
    const [hashInfo, setHashInfo] = useState<HashInfo | null>(null);
    const [attackMode, setAttackMode] = useState('dictionary');
    const [selectedWordlist, setSelectedWordlist] = useState('');
    const [wordlists, setWordlists] = useState<WordlistEntry[]>([]);
    const [algorithms, setAlgorithms] = useState<AlgorithmInfo[]>([]);
    const [jobId, setJobId] = useState<string | null>(null);
    const [job, setJob] = useState<CrackJob | null>(null);
    const [isProcessing, setIsProcessing] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [usageModalOpen, setUsageModalOpen] = useState(false);

    // Brute force options
    const [charset, setCharset] = useState('abcdefghijklmnopqrstuvwxyz0123456789');
    const [minLength, setMinLength] = useState(1);
    const [maxLength, setMaxLength] = useState(6);

    // Hybrid options
    const [selectedRules, setSelectedRules] = useState<string[]>(['capitalize', 'append_year']);

    // Scan history
    const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);

    const [historyPanelOpen, setHistoryPanelOpen] = useState(false);

    // New Features State
    const [exportTried, setExportTried] = useState(false);
    const [advancedModalOpen, setAdvancedModalOpen] = useState(false);
    const [genTab, setGenTab] = useState<'generate' | 'upload'>('generate');
    const [genName, setGenName] = useState('');
    const [genBase, setGenBase] = useState('');
    const [genPattern, setGenPattern] = useState('');
    const [genMin, setGenMin] = useState(1);
    const [genMax, setGenMax] = useState(6);
    const [uploadFile, setUploadFile] = useState<File | null>(null);

    // Salt Options
    const [salt, setSalt] = useState('');
    const [saltPosition, setSaltPosition] = useState('suffix');

    // Crack Mode
    const [crackMode, setCrackMode] = useState<'text' | 'file'>('text');
    const [fileProcessing, setFileProcessing] = useState(false);

    const logsEndRef = useRef<HTMLDivElement>(null);

    // Load scan history from localStorage on mount
    useEffect(() => {
        try {
            const saved = localStorage.getItem('hash-cracker-history');
            if (saved) {
                setScanHistory(JSON.parse(saved));
            }
        } catch (e) {
            console.error('Failed to load scan history:', e);
        }
    }, []);

    // Save scan history to localStorage when it changes
    useEffect(() => {
        if (scanHistory.length > 0) {
            localStorage.setItem('hash-cracker-history', JSON.stringify(scanHistory.slice(0, 50))); // Keep last 50
        }
    }, [scanHistory]);

    // Scroll logs to bottom - Sadece yeni log geldiğinde
    useEffect(() => {
        if (job?.logs && job.logs.length > 0) {
            logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        }
    }, [job?.logs?.length]);

    // Load algorithms on mount
    useEffect(() => {
        fetchAlgorithms();
        fetchWordlists();
    }, []);

    // Detect hash type on input change
    useEffect(() => {
        if (hash.length >= 32) {
            detectHash();
        } else {
            setHashInfo(null);
        }
    }, [hash]);

    // Poll job status - Her 100ms'de bir güncelle (mobil için hızlı feedback)
    useEffect(() => {
        let interval: any;
        if (isProcessing && jobId) {
            interval = setInterval(async () => {
                try {
                    const status = await api.get<CrackJob>(`/api/hash/crack/${jobId}`);
                    setJob(status);

                    if (status.state === 'completed' || status.state === 'failed' || status.state === 'cancelled') {
                        setIsProcessing(false);

                        // Save to history when completed
                        if (status.state === 'completed' && status.result) {
                            const historyEntry: ScanHistoryEntry = {
                                id: status.id,
                                hash: status.hash,
                                hash_type: status.hash_type,
                                attack_mode: status.attack_mode,
                                found: status.result.found,
                                password: status.result.password,
                                attempts: status.result.attempts,
                                elapsed_ms: status.result.elapsed_ms,
                                timestamp: Date.now(),
                            };
                            setScanHistory(prev => [historyEntry, ...prev]);
                        }
                    }
                } catch (err) {
                    console.error('Polling error:', err);
                }
            }, 100); // 100ms - mobil için hızlı güncelleme
        }
        return () => {
            if (interval) clearInterval(interval);
        };
    }, [isProcessing, jobId]);

    // API Functions
    const fetchAlgorithms = async () => {
        try {
            const data = await api.get<AlgorithmInfo[]>('/api/hash/algorithms');
            setAlgorithms(data);
        } catch (err) {
            console.error('Failed to fetch algorithms:', err);
        }
    };

    const fetchWordlists = async () => {
        try {
            const data = await api.get<WordlistEntry[]>('/api/hash/wordlists');
            setWordlists(data);
            if (data.length > 0) {
                setSelectedWordlist(data[0].path);
            }
        } catch (err) {
            console.error('Failed to fetch wordlists:', err);
        }
    };

    const detectHash = async () => {
        try {
            const data = await api.get<HashInfo>(`/api/hash/detect?hash=${encodeURIComponent(hash)}`);
            setHashInfo(data);
        } catch (err) {
            console.error('Hash detection error:', err);
        }
    };

    const startCrack = async (e: React.FormEvent) => {
        e.preventDefault();

        // State'i temizle - 2. tarama için
        setIsProcessing(true);
        setJob(null);
        setJobId(null);
        setError(null);

        try {
            const body: any = {
                hash,
                attack_mode: attackMode,
                export_tried: exportTried,
                salt: salt || undefined,
                salt_position: salt ? saltPosition : undefined,
            };

            if (attackMode === 'dictionary' || attackMode === 'hybrid' || attackMode === 'combinator') {
                body.wordlist = selectedWordlist;
            }
            if (attackMode === 'bruteforce') {
                body.charset = charset;
                body.min_length = minLength;
                body.max_length = maxLength;
            }
            if (attackMode === 'hybrid') {
                body.rules = selectedRules;
            }

            const data = await api.post<any>('/api/hash/crack', body);
            setJobId(data.job_id);
        } catch (err: any) {
            setError(err.message);
            setIsProcessing(false);
        }
    };

    const cancelJob = async () => {
        if (!jobId) return;
        try {
            await api.post(`/api/hash/crack/${jobId}/cancel`, {});
            setIsProcessing(false);
        } catch (err) {
            console.error('Cancel failed:', err);
        }
    };

    const handleGenerateWordlist = async () => {
        if (!genName) {
            setError('Lütfen wordlist adı girin');
            return;
        }
        setIsProcessing(true);
        try {
            const data = await api.post<any>('/api/hash-cracker/wordlist/generate', {
                name: genName,
                base_word: genBase || undefined,
                pattern: genPattern || undefined,
                min_length: !genPattern ? genMin : undefined,
                max_length: !genPattern ? genMax : undefined,
            });

            if (data.success) {
                setAdvancedModalOpen(false);
                fetchWordlists(); // Refresh list
                alert(`Wordlist oluşturuldu: ${data.result.count} kelime`);
            } else {
                setError(data.error);
            }
        } catch (e: any) {
            setError(e.message);
        }
        setIsProcessing(false);
    };

    const handleUploadWordlist = async () => {
        if (!uploadFile) return;
        const formData = new FormData();
        formData.append('file', uploadFile);

        setIsProcessing(true);
        try {
            const data = await api.upload<any>('/api/hash-cracker/wordlist/upload', formData);

            if (data.success) {
                setAdvancedModalOpen(false);
                fetchWordlists();
                alert('Dosya yüklendi!');
            } else {
                setError(data.error);
            }
        } catch (e: any) {
            setError(e.message);
        }
        setIsProcessing(false);
    };

    const handleFileCrack = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setFileProcessing(true);
        const formData = new FormData();
        formData.append('file', file);

        try {
            const data = await api.upload<any>('/api/hash/crack/file', formData);
            if (data.success) {
                setHash(data.hash);
                setCrackMode('text'); // Switch to text mode to show hash
                alert(`Dosyadan hash çıkarıldı: ${data.filename}\nHash ilgili alana dolduruldu.`);
            } else {
                setError(data.error);
            }
        } catch (err: any) {
            setError(err.message);
        }
        setFileProcessing(false);
    };

    const handleDownloadSelectedWordlist = () => {
        if (!selectedWordlist || selectedWordlist === '__ALL__') return;
        // Extract filename from path
        const filename = selectedWordlist.split('/').pop();
        if (filename) {
            window.open(`/api/hash-cracker/wordlist/${filename}/download`);
        }
    };

    const handleDownloadTried = () => {
        if (job?.id) {
            window.open(`/api/hash-cracker/crack/${job.id}/tried`);
        }
    };

    // Format file size
    const formatSize = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    };

    // Format rate
    const formatRate = (rate: number) => {
        if (rate < 1000) return `${rate.toFixed(0)} H/s`;
        if (rate < 1000000) return `${(rate / 1000).toFixed(1)} KH/s`;
        return `${(rate / 1000000).toFixed(1)} MH/s`;
    };

    const attackModes = [
        { id: 'dictionary', name: '📚 Sözlük Saldırısı', desc: 'Wordlist kullanarak hızlı kırma', icon: '📚' },
        { id: 'bruteforce', name: '💪 Brute Force', desc: 'Tüm kombinasyonları dene', icon: '💪' },
        { id: 'hybrid', name: '🔀 Hibrit Saldırı', desc: 'Wordlist + Kurallar (leet, suffix)', icon: '🔀' },
        { id: 'combinator', name: '🔗 Birleştirici', desc: 'İki kelime birleştir', icon: '🔗' },
    ];

    const availableRules = [
        { id: 'capitalize', name: 'Baş Harf Büyük', example: 'password → Password' },
        { id: 'uppercase', name: 'Tümü Büyük', example: 'password → PASSWORD' },
        { id: 'lowercase', name: 'Tümü Küçük', example: 'PASSWORD → password' },
        { id: 'reverse', name: 'Ters Çevir', example: 'password → drowssap' },
        { id: 'leet', name: 'Leet Speak', example: 'password → p4ssw0rd' },
        { id: 'duplicate', name: 'Tekrarla', example: 'pass → passpass' },
        { id: 'append_year', name: 'Yıl Ekle', example: 'pass → pass2024' },
        { id: 'append_special', name: 'Özel Karakter', example: 'pass → pass!' },
    ];

    const getSecurityColor = (level: string) => {
        switch (level?.toLowerCase()) {
            case 'broken': return 'text-red-500 bg-red-500/20';
            case 'weak': return 'text-orange-500 bg-orange-500/20';
            case 'moderate': return 'text-yellow-500 bg-yellow-500/20';
            case 'strong': return 'text-emerald-500 bg-emerald-500/20';
            case 'hardened': return 'text-purple-500 bg-purple-500/20';
            default: return 'text-slate-500 bg-slate-500/20';
        }
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex-1">
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-3">
                        <span className="text-4xl">🔓</span>
                        HASH KIRICI
                        <Tooltip content="Modern hash kırma aracı. Dictionary, Brute Force, Hybrid saldırıları destekler. MD5, SHA1, SHA256, bcrypt, Argon2 ve daha fazlası." position="bottom">
                            <div className="w-5 h-5 rounded-full bg-purple-500/20 hover:bg-purple-500/30 flex items-center justify-center cursor-help transition-colors border border-purple-500/40">
                                <span className="text-xs text-purple-300 font-bold">i</span>
                            </div>
                        </Tooltip>
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400">Yüksek performanslı paralel hash kırma motoru</p>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={() => setHistoryPanelOpen(true)}
                        className="px-4 py-2 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-900 dark:text-white rounded-lg font-semibold text-sm transition-all flex items-center gap-2 border border-slate-300 dark:border-slate-700"
                    >
                        <span>📋</span>
                        Geçmiş
                        {scanHistory.length > 0 && (
                            <span className="bg-purple-600 text-white text-xs px-2 py-0.5 rounded-full">
                                {scanHistory.length}
                            </span>
                        )}
                    </button>
                    <button
                        onClick={() => setUsageModalOpen(true)}
                        className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-semibold text-sm transition-all flex items-center gap-2 shadow-lg hover:scale-105"
                    >
                        <span>📚</span>
                        Nasıl Kullanılır?
                    </button>
                    <button
                        onClick={() => setAdvancedModalOpen(true)}
                        className="px-4 py-2 bg-pink-600 hover:bg-pink-500 text-white rounded-lg font-semibold text-sm transition-all flex items-center gap-2 shadow-lg hover:scale-105"
                    >
                        <span>⚙️</span>
                        Wordlist Yöneticisi
                    </button>
                    <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 px-4 py-2 rounded-full border border-emerald-500/20">
                        <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
                        SYSTEM ONLINE
                    </div>
                </div>
            </div>

            {/* Algorithm Info Cards */}
            <div className="bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
                <h2 className="text-lg font-bold text-purple-400 mb-4 flex items-center gap-2">
                    <span>🔐</span> Desteklenen Hash Algoritmaları
                </h2>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
                    {algorithms.map((algo) => (
                        <div
                            key={algo.id}
                            className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl p-3 hover:border-purple-500/50 transition-all group cursor-pointer"
                        >
                            <div className="flex items-center gap-2 mb-2">
                                <span className="text-2xl">{algo.emoji}</span>
                                <div className="font-bold text-slate-900 dark:text-white text-sm group-hover:text-purple-400 transition-colors">
                                    {algo.name}
                                </div>
                            </div>
                            <div className={`text-xs px-2 py-0.5 rounded inline-block ${getSecurityColor(algo.security_level)}`}>
                                {algo.security_level}
                            </div>
                            <p className="text-xs text-slate-500 mt-2 line-clamp-2">{algo.description}</p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Left: Configuration */}
                <div className="lg:col-span-5 space-y-6">
                    <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
                        <h2 className="text-lg font-bold mb-4 text-purple-400 flex items-center gap-2">
                            <span>⚡</span> Kırma Ayarları
                        </h2>

                        <Form onSubmit={startCrack} className="space-y-6">

                            {/* Mode Selection Tabs */}
                            <div className="flex p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
                                <button
                                    type="button"
                                    onClick={() => setCrackMode('text')}
                                    className={`flex-1 py-2 text-sm font-bold rounded-md transition-all ${crackMode === 'text'
                                        ? 'bg-white dark:bg-slate-700 shadow text-purple-600 dark:text-purple-400'
                                        : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                                        }`}
                                >
                                    📝 Hash Metni
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setCrackMode('file')}
                                    className={`flex-1 py-2 text-sm font-bold rounded-md transition-all ${crackMode === 'file'
                                        ? 'bg-white dark:bg-slate-700 shadow text-purple-600 dark:text-purple-400'
                                        : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                                        }`}
                                >
                                    📁 Dosyadan (Zip/PDF)
                                </button>
                            </div>

                            {/* File Upload Area */}
                            {crackMode === 'file' && (
                                <div className="p-8 border-2 border-dashed border-slate-300 dark:border-slate-700 rounded-xl hover:border-purple-500/50 transition-colors bg-slate-50 dark:bg-slate-900/50 text-center">
                                    <div className="text-4xl mb-3">📂</div>
                                    <h3 className="text-lg font-bold text-slate-700 dark:text-slate-300 mb-2">
                                        Şifreli Dosyayı Yükle
                                    </h3>
                                    <p className="text-sm text-slate-500 mb-6 max-w-xs mx-auto">
                                        Zip, PDF, Office vb. şifreli dosyaları yükleyin. Sistem otomatik olarak hash değerini çıkarıp kırmaya hazırlayacaktır.
                                    </p>

                                    <label className={`inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-bold cursor-pointer transition-all ${fileProcessing ? 'opacity-70 cursor-wait' : ''}`}>
                                        {fileProcessing ? (
                                            <>
                                                <span className="animate-spin">⌛</span> Çıkarılıyor...
                                            </>
                                        ) : (
                                            <>
                                                <span>⬆️</span> Dosya Seç
                                            </>
                                        )}
                                        <input
                                            type="file"
                                            className="hidden"
                                            onChange={handleFileCrack}
                                            disabled={fileProcessing}
                                        />
                                    </label>
                                </div>
                            )}

                            {/* Hash Input (Only in text mode) */}
                            {crackMode === 'text' && (
                                <div>
                                    <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                                        Hash Değeri
                                        <Tooltip content="Kırmak istediğiniz hash değerini yapıştırın. Otomatik olarak türü tespit edilecektir." position="right" />
                                    </label>
                                    <textarea
                                        value={hash}
                                        onChange={(e) => setHash(e.target.value)}
                                        placeholder="5d41402abc4b2a76b9719d911017c592"
                                        rows={3}
                                        className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:ring-2 focus:ring-purple-500 focus:border-transparent outline-none font-mono text-sm resize-none"
                                    />
                                    {hashInfo && (
                                        <div className="mt-2 p-3 bg-slate-100 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700">
                                            <div className="flex items-center justify-between">
                                                <span className="text-sm font-bold text-slate-900 dark:text-white">{hashInfo.hash_type}</span>
                                                <span className={`text-xs px-2 py-1 rounded ${getSecurityColor(hashInfo.security_level)}`}>
                                                    {hashInfo.security_level}
                                                </span>
                                            </div>
                                            <p className="text-xs text-slate-400 mt-1">{hashInfo.description}</p>

                                            {/* HMAC / Secret Key Uyarısı */}
                                            {hashInfo.warning && (
                                                <div className="mt-2 p-2 bg-amber-900/30 border border-amber-600/50 rounded-lg">
                                                    <p className="text-xs text-amber-300 leading-relaxed">
                                                        {hashInfo.warning}
                                                    </p>
                                                    <p className="text-xs text-amber-400/70 mt-1">
                                                        💡 <strong>HMAC nedir?</strong> HMAC (Hash-based Message Authentication Code),
                                                        secret key ile oluşturulan bir hash türüdür. Secret key bilinmeden
                                                        bu hash kırılamaz. API token'ları ve authentication sistemlerinde yaygındır.
                                                    </p>
                                                </div>
                                            )}

                                            <div className="flex items-center gap-2 mt-2">
                                                <span className="text-xs text-slate-500">Güven:</span>
                                                <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                                                    <div
                                                        className="h-full bg-purple-500 rounded-full transition-all"
                                                        style={{ width: `${hashInfo.confidence}%` }}
                                                    />
                                                </div>
                                                <span className="text-xs text-purple-400 font-mono">{hashInfo.confidence}%</span>
                                            </div>
                                        </div>
                                    )}
                                    {/* Salt Input */}
                                    <div className="mt-4 flex gap-4">
                                        <div className="flex-1">
                                            <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                                                Salt (Opsiyonel)
                                                <Tooltip content="Eğer hash saltlanmışsa buraya girin. Genellikle veritabanı sızıntılarında 'hash:salt' formatında olur." position="right" />
                                            </label>
                                            <input
                                                type="text"
                                                value={salt}
                                                onChange={(e) => setSalt(e.target.value)}
                                                placeholder="tuz123"
                                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 font-mono text-sm outline-none focus:ring-2 focus:ring-purple-500"
                                            />
                                        </div>
                                        <div className="w-1/3">
                                            <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                                                Pozisyon
                                            </label>
                                            <select
                                                value={saltPosition}
                                                onChange={(e) => setSaltPosition(e.target.value)}
                                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white font-mono text-sm outline-none focus:ring-2 focus:ring-purple-500"
                                            >
                                                <option value="suffix">Son (Suffix)</option>
                                                <option value="prefix">Baş (Prefix)</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Attack Mode */}
                            <div>
                                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                    Saldırı Modu
                                    <Tooltip content="Dictionary: Hızlı wordlist tarama. Brute Force: Tüm kombinasyonlar. Hybrid: Wordlist + kurallar. Combinator: Kelime birleştirme." position="right" />
                                </label>
                                <div className="grid grid-cols-2 gap-2">
                                    {attackModes.map((mode) => (
                                        <button
                                            key={mode.id}
                                            type="button"
                                            onClick={() => setAttackMode(mode.id)}
                                            className={`p-3 rounded-lg text-left transition-all ${attackMode === mode.id
                                                ? 'bg-purple-600 border-2 border-purple-400 text-white'
                                                : 'bg-slate-100 dark:bg-slate-800/50 border border-slate-300 dark:border-slate-700 hover:border-purple-500/50'
                                                }`}
                                        >
                                            <div className="font-bold text-slate-900 dark:text-white text-sm">{mode.name}</div>
                                            <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">{mode.desc}</div>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Wordlist Selection */}
                            {(attackMode === 'dictionary' || attackMode === 'hybrid' || attackMode === 'combinator') && (
                                <div>
                                    <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                                        Wordlist Seç
                                        <Tooltip content="SecLists koleksiyonundan hazır wordlist'ler. 'Tümünü Birleştir' seçeneği tüm listeleri tek seferde tarar." position="right" />
                                    </label>
                                    <div className="flex gap-2">
                                        <select
                                            value={selectedWordlist}
                                            onChange={(e) => setSelectedWordlist(e.target.value)}
                                            className="flex-1 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent outline-none"
                                        >
                                            <option value="__ALL__" className="bg-gradient-to-r from-purple-600 to-pink-600">
                                                🔥 TÜM WORDLIST'LERİ BİRLEŞTİR (Kapsamlı Tarama)
                                            </option>
                                            <option disabled>──────────────</option>
                                            {wordlists.map((wl) => (
                                                <option key={wl.path} value={wl.path}>
                                                    {wl.emoji} {wl.description} ({formatSize(wl.size_bytes)})
                                                </option>
                                            ))}
                                        </select>
                                        <button
                                            type="button"
                                            onClick={handleDownloadSelectedWordlist}
                                            disabled={selectedWordlist === '__ALL__' || !selectedWordlist}
                                            className="px-3 bg-slate-200 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg hover:bg-slate-300 dark:hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed text-xl"
                                            title="Seçili Wordlist'i İndir"
                                        >
                                            📥
                                        </button>
                                    </div>
                                    {selectedWordlist === '__ALL__' && (
                                        <div className="mt-2 p-2 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                                            <p className="text-xs text-purple-300">
                                                ⚡ Tüm wordlist'ler birleştirilip tekli olmayan şifreler taranacak. Bu işlem daha uzun sürebilir ancak kapsamlı sonuç verir.
                                            </p>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Brute Force Options */}
                            {attackMode === 'bruteforce' && (
                                <div className="space-y-4 p-4 bg-slate-100 dark:bg-slate-800/30 rounded-lg border border-slate-200 dark:border-slate-700">
                                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">Brute Force Ayarları</h3>
                                    <div>
                                        <label className="block text-xs text-slate-400 mb-1">Karakter Seti</label>
                                        <input
                                            type="text"
                                            value={charset}
                                            onChange={(e) => setCharset(e.target.value)}
                                            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white text-sm font-mono"
                                        />
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs text-slate-400 mb-1">Min Uzunluk</label>
                                            <input
                                                type="number"
                                                min="1"
                                                max="12"
                                                value={minLength}
                                                onChange={(e) => setMinLength(parseInt(e.target.value) || 1)}
                                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white text-sm"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs text-slate-400 mb-1">Max Uzunluk</label>
                                            <input
                                                type="number"
                                                min="1"
                                                max="12"
                                                value={maxLength}
                                                onChange={(e) => setMaxLength(parseInt(e.target.value) || 6)}
                                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white text-sm"
                                            />
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Hybrid Rules */}
                            {attackMode === 'hybrid' && (
                                <div className="space-y-3 p-4 bg-slate-100 dark:bg-slate-800/30 rounded-lg border border-slate-200 dark:border-slate-700">
                                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">Dönüşüm Kuralları</h3>
                                    <div className="grid grid-cols-2 gap-2">
                                        {availableRules.map((rule) => (
                                            <label
                                                key={rule.id}
                                                className={`flex items-center gap-2 p-2 rounded cursor-pointer transition-colors ${selectedRules.includes(rule.id)
                                                    ? 'bg-purple-600/30 border border-purple-500/50'
                                                    : 'bg-slate-100 dark:bg-slate-800/50 border border-slate-300 dark:border-slate-700 hover:border-purple-500/30'
                                                    }`}
                                            >
                                                <input
                                                    type="checkbox"
                                                    checked={selectedRules.includes(rule.id)}
                                                    onChange={(e) => {
                                                        if (e.target.checked) {
                                                            setSelectedRules([...selectedRules, rule.id]);
                                                        } else {
                                                            setSelectedRules(selectedRules.filter((r) => r !== rule.id));
                                                        }
                                                    }}
                                                    className="rounded bg-slate-800 border-slate-600"
                                                />
                                                <div>
                                                    <div className="text-xs font-semibold text-slate-900 dark:text-white">{rule.name}</div>
                                                    <div className="text-xs text-slate-600 dark:text-slate-500 font-mono">{rule.example}</div>
                                                </div>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                            )}


                            {/* Export Options */}
                            <div className="p-4 bg-slate-100 dark:bg-slate-800/30 rounded-lg border border-slate-200 dark:border-slate-700">
                                <label className="flex items-center gap-3 cursor-pointer">
                                    <div className="relative">
                                        <input
                                            type="checkbox"
                                            checked={exportTried}
                                            onChange={(e) => setExportTried(e.target.checked)}
                                            className="hidden peer"
                                        />
                                        <div className="w-10 h-6 bg-slate-700 rounded-full peer-checked:bg-purple-600 transition-colors"></div>
                                        <div className="absolute top-1 left-1 w-4 h-4 bg-white rounded-full peer-checked:translate-x-4 transition-transform"></div>
                                    </div>
                                    <div>
                                        <div className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                            Denenen Şifreleri Kaydet
                                            <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded">YAVAŞLATIR</span>
                                        </div>
                                        <div className="text-xs text-slate-500">
                                            Kırılmasa bile denenmiş tüm kombinasyonları dosyaya yazar (.txt). Analiz için kullanılır.
                                        </div>
                                    </div>
                                </label>
                            </div>

                            {/* Submit Button */}
                            <button
                                type="submit"
                                disabled={isProcessing || !hash}
                                className={`w-full py-4 rounded-xl font-bold text-lg tracking-wide transition-all ${isProcessing || !hash
                                    ? 'bg-slate-300 dark:bg-slate-800 text-slate-500 cursor-not-allowed'
                                    : 'bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white shadow-lg hover:scale-[1.02]'
                                    }`}
                            >
                                {isProcessing ? 'KIRILIYOR...' : '🔓 HASH\'İ KIR'}
                            </button>

                            {isProcessing && (
                                <button
                                    type="button"
                                    onClick={cancelJob}
                                    className="w-full py-3 rounded-xl font-semibold bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30 transition-all"
                                >
                                    ⛔ İptal Et
                                </button>
                            )}
                        </Form>
                    </div>

                    {/* Result Card */}
                    {job?.result && (
                        <div className={`bg-white dark:bg-slate-900/50 border rounded-2xl p-6 ${job.result.found ? 'border-emerald-500/30' : 'border-red-500/30'}`}>
                            <div className="flex items-start justify-between mb-4">
                                <h3 className={`text-lg font-bold flex items-center gap-2 ${job.result.found ? 'text-emerald-400' : 'text-red-400'}`}>
                                    <span>{job.result.found ? '✅' : '❌'}</span>
                                    {job.result.found ? 'Şifre Bulundu!' : 'Şifre Bulunamadı'}
                                </h3>
                                <button
                                    onClick={() => {
                                        const report = {
                                            job_id: job.id,
                                            timestamp: new Date().toISOString(),
                                            hash: job.hash,
                                            hash_type: job.hash_type,
                                            attack_mode: job.attack_mode,
                                            result: {
                                                found: job.result?.found,
                                                password: job.result?.password,
                                                attempts: job.result?.attempts,
                                                rate: job.result?.rate,
                                                elapsed_ms: job.result?.elapsed_ms,
                                            },
                                            logs: job.logs,
                                        };
                                        generateHashCrackerReport(report);
                                    }}
                                    className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-semibold flex items-center gap-2 transition-all"
                                >
                                    📥 PDF Rapor İndir
                                </button>
                                {exportTried && (
                                    <button
                                        onClick={handleDownloadTried}
                                        className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm font-semibold flex items-center gap-2 transition-all ml-2 border border-slate-600"
                                    >
                                        💾 Denenenleri İndir
                                    </button>
                                )}
                            </div>

                            {/* Hash Info */}
                            <div className="bg-slate-100 dark:bg-black/30 p-3 rounded-lg mb-4 font-mono text-xs">
                                <div className="text-slate-500 mb-1">Hash ({job.hash_type}):</div>
                                <div className="text-slate-700 dark:text-slate-300 break-all">{job.hash}</div>
                            </div>

                            {job.result.found && job.result.password && (
                                <div className="bg-emerald-50 dark:bg-black/50 p-4 rounded-lg border border-emerald-500/30 mb-4">
                                    <div className="text-xs text-slate-500 uppercase mb-1">Bulunan Şifre</div>
                                    <div className="text-2xl font-mono text-emerald-400 font-bold break-all">{job.result.password}</div>
                                </div>
                            )}

                            <div className="grid grid-cols-3 gap-3 text-center">
                                <div className="bg-slate-100 dark:bg-black/30 p-3 rounded-lg">
                                    <div className="text-xs text-slate-500 uppercase">Deneme</div>
                                    <div className="text-lg font-bold text-slate-900 dark:text-white font-mono">{job.result.attempts.toLocaleString()}</div>
                                </div>
                                <div className="bg-slate-100 dark:bg-black/30 p-3 rounded-lg">
                                    <div className="text-xs text-slate-500 uppercase">Hız</div>
                                    <div className="text-lg font-bold text-slate-900 dark:text-white font-mono">{formatRate(job.result.rate)}</div>
                                </div>
                                <div className="bg-slate-100 dark:bg-black/30 p-3 rounded-lg">
                                    <div className="text-xs text-slate-500 uppercase">Süre</div>
                                    <div className="text-lg font-bold text-slate-900 dark:text-white font-mono">{(job.result.elapsed_ms / 1000).toFixed(2)}s</div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* AI Hash Analizi - Sonuç geldiğinde göster */}
                    {job?.result && (
                        <AIAnalysisPanel
                            scanData={{
                                hash: job.hash,
                                hash_type: job.hash_type,
                                attack_mode: job.attack_mode,
                                found: job.result.found,
                                password: job.result.password,
                                attempts: job.result.attempts,
                                elapsed_ms: job.result.elapsed_ms,
                                rate: job.result.rate
                            }}
                            analysisType="hash"
                            title="🤖 AI Hash Analizi"
                        />
                    )}
                </div>

                {/* Right: Terminal */}
                <div className="lg:col-span-7 flex flex-col gap-6">
                    {/* Mobile Loading Overlay - Birleştirme/Hazırlık Aşaması */}
                    {isProcessing && !job && (
                        <div className="bg-gradient-to-r from-purple-900/30 to-pink-900/30 border border-purple-500/40 rounded-xl p-6 animate-pulse">
                            <div className="flex items-center gap-4">
                                <div className="relative">
                                    <div className="w-12 h-12 rounded-full border-4 border-purple-500/30 border-t-purple-500 animate-spin"></div>
                                    <div className="absolute inset-0 flex items-center justify-center">
                                        <span className="text-2xl">🔀</span>
                                    </div>
                                </div>
                                <div className="flex-1">
                                    <h3 className="text-lg font-bold text-purple-400">Wordlist Birleştiriliyor...</h3>
                                    <p className="text-sm text-slate-400">
                                        Tüm wordlist dosyaları birleştiriliyor ve unique şifreler filtreleniyor.
                                        Bu işlem ilk seferde ~60 saniye sürebilir.
                                    </p>
                                    <div className="flex items-center gap-2 mt-2 text-xs text-slate-500">
                                        <span className="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></span>
                                        <span>SecLists + Özel wordlist'ler taranıyor...</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Progress Bar - İşlem Sırasında */}
                    {job && isProcessing && (
                        <div className="bg-slate-100 dark:bg-slate-900/50 border border-purple-500/30 rounded-xl p-4 shadow-lg shadow-purple-500/10">
                            {/* Mobil: Kompakt görünüm */}
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                                <div className="flex items-center gap-3">
                                    <div className="relative">
                                        <div className="w-8 h-8 rounded-full border-2 border-purple-500/30 border-t-purple-500 animate-spin"></div>
                                    </div>
                                    <div>
                                        <span className="text-sm text-slate-400 block sm:inline">İlerleme: </span>
                                        <span className="text-xl sm:text-lg font-bold text-purple-400">{job.progress.percent.toFixed(1)}%</span>
                                    </div>
                                </div>
                                <div className="flex flex-wrap items-center gap-2 sm:gap-4 text-xs sm:text-sm font-mono">
                                    <span className="bg-purple-500/20 text-purple-400 px-2 py-1 rounded">{formatRate(job.progress.rate)}</span>
                                    <span className="text-slate-900 dark:text-white">{job.progress.attempts.toLocaleString()} deneme</span>
                                    <span className="bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded">{(job.progress.elapsed_ms / 1000).toFixed(1)}s</span>
                                </div>
                            </div>
                            {/* Progress Bar - Daha belirgin */}
                            <div className="h-4 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden shadow-inner">
                                <div
                                    className="h-full bg-gradient-to-r from-purple-600 via-pink-500 to-purple-600 rounded-full transition-all duration-300 animate-pulse"
                                    style={{
                                        width: `${Math.max(2, job.progress.percent)}%`,
                                        backgroundSize: '200% 100%',
                                        animation: 'gradient-shift 2s linear infinite, pulse 2s ease-in-out infinite'
                                    }}
                                />
                            </div>
                            {/* ETA ve Durum */}
                            <div className="flex justify-between mt-2 text-xs text-slate-500">
                                <span>⚡ Paralel tarama aktif</span>
                                <span>
                                    {job.progress.percent > 0 && job.progress.percent < 100 ?
                                        `~${Math.ceil((100 - job.progress.percent) / (job.progress.percent / (job.progress.elapsed_ms / 1000)))}s kaldı`
                                        : 'Hesaplanıyor...'
                                    }
                                </span>
                            </div>
                        </div>
                    )}

                    {/* Terminal */}
                    <div className="bg-slate-900 dark:bg-black border border-slate-300 dark:border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col h-[500px]">
                        <div className="bg-slate-900/50 px-4 py-2 border-b border-slate-800 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50"></div>
                                <div className="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50"></div>
                                <div className="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/50"></div>
                            </div>
                            <div className="text-xs font-mono text-slate-500">hash-cracker v1.0</div>
                        </div>
                        <div className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1">
                            {!job && (
                                <div className="text-slate-600"># Hash değeri girin ve kırma işlemini başlatın...</div>
                            )}
                            {job?.logs.map((log, i) => (
                                <div key={i} className="break-all">
                                    <span className={
                                        log.includes('✅') ? 'text-emerald-400 font-bold' :
                                            log.includes('❌') ? 'text-red-400' :
                                                log.includes('⛔') ? 'text-orange-400' :
                                                    log.includes('🔓') || log.includes('🔧') ? 'text-purple-400' :
                                                        log.includes('📊') ? 'text-cyan-400' :
                                                            'text-slate-300'
                                    }>{log}</span>
                                </div>
                            ))}
                            <div ref={logsEndRef} />
                            {isProcessing && <div className="animate-pulse text-purple-500">_</div>}
                        </div>
                    </div>
                </div>
            </div >

            {/* Usage Modal */}
            {
                usageModalOpen && (
                    <div className="fixed inset-0 bg-black/90 backdrop-blur-md flex items-center justify-center z-50 p-4 overflow-y-auto">
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-5xl shadow-2xl my-8">
                            <div className="sticky top-0 bg-white dark:bg-slate-900 p-6 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center rounded-t-2xl z-10">
                                <h2 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                                    <span className="text-3xl">📚</span>
                                    Hash Kırıcı - Kullanım Rehberi
                                </h2>
                                <button
                                    onClick={() => setUsageModalOpen(false)}
                                    className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors text-2xl"
                                >
                                    ✕
                                </button>
                            </div>

                            <div className="p-6 space-y-8 max-h-[calc(100vh-200px)] overflow-y-auto">
                                {/* About */}
                                <div className="bg-gradient-to-r from-purple-900/20 to-pink-900/20 border border-purple-500/30 rounded-xl p-6">
                                    <h3 className="text-xl font-bold text-purple-400 mb-3 flex items-center gap-2">
                                        <span>🎯</span> Modül Hakkında
                                    </h3>
                                    <p className="text-slate-300 leading-relaxed">
                                        Yüksek performanslı hash kırma aracı. <strong className="text-white">Rust</strong> ile yazılmış,
                                        <strong className="text-white"> paralel işleme</strong> desteği ile saniyede milyonlarca hash deneyebilir.
                                        Modern algoritmaları (Argon2, BLAKE3, SHA-3) ve eski algoritmaları (MD5, SHA1, NTLM) destekler.
                                    </p>
                                </div>

                                {/* Attack Modes */}
                                <div>
                                    <h3 className="text-xl font-bold text-emerald-400 mb-4 flex items-center gap-2">
                                        <span>⚔️</span> Saldırı Modları
                                    </h3>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
                                            <h4 className="font-bold text-slate-900 dark:text-white mb-2">📚 Sözlük Saldırısı</h4>
                                            <p className="text-sm text-slate-400 mb-2">Hazır wordlist kullanarak hızlı tarama yapar. En çok kullanılan şifreleri dakikalar içinde bulabilir.</p>
                                            <div className="text-xs text-emerald-400">✅ Önerilen: RockYou, Top 10K, Darkc0de</div>
                                        </div>
                                        <div className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
                                            <h4 className="font-bold text-slate-900 dark:text-white mb-2">💪 Brute Force</h4>
                                            <p className="text-sm text-slate-400 mb-2">Belirtilen karakter setiyle tüm olasılıkları dener. Kısa şifreler için etkili.</p>
                                            <div className="text-xs text-yellow-400">⚠️ Dikkat: 6+ karakterde çok uzun sürer</div>
                                        </div>
                                        <div className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
                                            <h4 className="font-bold text-slate-900 dark:text-white mb-2">🔀 Hibrit Saldırı</h4>
                                            <p className="text-sm text-slate-400 mb-2">Wordlist + dönüşüm kuralları. "password" → "P4ssw0rd123!" gibi varyasyonlar üretir.</p>
                                            <div className="text-xs text-purple-400">💡 Profesyonel kullanım için ideal</div>
                                        </div>
                                        <div className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
                                            <h4 className="font-bold text-slate-900 dark:text-white mb-2">🔗 Birleştirici</h4>
                                            <p className="text-sm text-slate-400 mb-2">İki kelimeyi birleştirir: "admin" + "123" = "admin123"</p>
                                            <div className="text-xs text-cyan-400">🔗 Basit kombinasyonlar için</div>
                                        </div>
                                    </div>
                                </div>

                                {/* Security Levels */}
                                <div>
                                    <h3 className="text-xl font-bold text-orange-400 mb-4 flex items-center gap-2">
                                        <span>🛡️</span> Güvenlik Seviyeleri
                                    </h3>
                                    <table className="w-full border-collapse text-sm">
                                        <thead>
                                            <tr className="bg-slate-800 border-b border-slate-700">
                                                <th className="text-left p-3 text-slate-300">Seviye</th>
                                                <th className="text-left p-3 text-slate-300">Algoritmalar</th>
                                                <th className="text-left p-3 text-slate-300">Kırılma Süresi</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr className="border-b border-slate-800">
                                                <td className="p-3"><span className="text-red-400">💀 Broken</span></td>
                                                <td className="p-3 text-slate-400">MD5, SHA1, LM</td>
                                                <td className="p-3 text-red-400">Saniyeler</td>
                                            </tr>
                                            <tr className="border-b border-slate-800">
                                                <td className="p-3"><span className="text-orange-400">⚠️ Weak</span></td>
                                                <td className="p-3 text-slate-400">NTLM, MySQL5</td>
                                                <td className="p-3 text-orange-400">Dakikalar</td>
                                            </tr>
                                            <tr className="border-b border-slate-800">
                                                <td className="p-3"><span className="text-yellow-400">🔓 Moderate</span></td>
                                                <td className="p-3 text-slate-400">SHA256, SHA512</td>
                                                <td className="p-3 text-yellow-400">Saatler</td>
                                            </tr>
                                            <tr className="border-b border-slate-800">
                                                <td className="p-3"><span className="text-emerald-400">🔐 Strong</span></td>
                                                <td className="p-3 text-slate-400">SHA3, BLAKE2/3</td>
                                                <td className="p-3 text-emerald-400">Günler</td>
                                            </tr>
                                            <tr>
                                                <td className="p-3"><span className="text-purple-400">🏰 Hardened</span></td>
                                                <td className="p-3 text-slate-400">bcrypt, Argon2, scrypt</td>
                                                <td className="p-3 text-purple-400">Yıllar / İmkansız</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>

                                {/* Legal Notice */}
                                <div className="bg-red-900/20 border border-red-500/30 rounded-xl p-4">
                                    <h3 className="text-lg font-bold text-red-400 mb-2 flex items-center gap-2">
                                        <span>⚖️</span> Yasal Uyarı
                                    </h3>
                                    <p className="text-sm text-slate-300">
                                        Bu araç <strong>yalnızca</strong> yetkili penetrasyon testleri, güvenlik denetimleri ve
                                        kendi hash değerlerinizi test etmek için kullanılmalıdır. Başkalarının şifrelerini izinsiz
                                        kırmaya çalışmak <strong>yasadışıdır</strong>.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                )
            }

            {/* History Panel Modal */}
            {
                historyPanelOpen && (
                    <div className="fixed inset-0 bg-black/90 backdrop-blur-md flex items-center justify-center z-50 p-4 overflow-y-auto">
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-4xl shadow-2xl my-8">
                            <div className="sticky top-0 bg-white dark:bg-slate-900 p-6 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center rounded-t-2xl z-10">
                                <h2 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                                    <span className="text-3xl">📋</span>
                                    Tarama Geçmişi
                                    <span className="text-sm font-normal text-slate-400">({scanHistory.length} kayıt)</span>
                                </h2>
                                <div className="flex items-center gap-3">
                                    {scanHistory.length > 0 && (
                                        <>
                                            <button
                                                onClick={() => {
                                                    if (confirm('Tüm tarama geçmişini silmek istediğinize emin misiniz?')) {
                                                        setScanHistory([]);
                                                        localStorage.removeItem('hash-cracker-history');
                                                    }
                                                }}
                                                className="text-red-400 hover:text-red-300 text-sm px-3 py-1 rounded border border-red-500/30 hover:bg-red-500/10 transition-colors"
                                            >
                                                🗑️ Temizle
                                            </button>
                                            <button
                                                onClick={() => {
                                                    const report = {
                                                        exported_at: new Date().toISOString(),
                                                        total_scans: scanHistory.length,
                                                        history: scanHistory,
                                                    };
                                                    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
                                                    const url = URL.createObjectURL(blob);
                                                    const a = document.createElement('a');
                                                    a.href = url;
                                                    a.download = `hash-cracker-history-${new Date().toISOString().slice(0, 10)}.json`;
                                                    a.click();
                                                    URL.revokeObjectURL(url);
                                                }}
                                                className="text-purple-400 hover:text-purple-300 text-sm px-3 py-1 rounded border border-purple-500/30 hover:bg-purple-500/10 transition-colors"
                                            >
                                                📥 Tümünü İndir
                                            </button>
                                        </>
                                    )}
                                    <button
                                        onClick={() => setHistoryPanelOpen(false)}
                                        className="text-slate-400 hover:text-white transition-colors text-2xl"
                                    >
                                        ✕
                                    </button>
                                </div>
                            </div>

                            <div className="p-6 max-h-[calc(100vh-200px)] overflow-y-auto">
                                {scanHistory.length === 0 ? (
                                    <div className="text-center py-12">
                                        <div className="text-6xl mb-4">📭</div>
                                        <p className="text-slate-400">Henüz tarama geçmişi yok</p>
                                        <p className="text-sm text-slate-500 mt-2">Tarama yaptığınızda sonuçlar burada görünecek</p>
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        {scanHistory.map((entry) => (
                                            <div
                                                key={entry.id}
                                                className={`bg-slate-100 dark:bg-slate-800/50 border rounded-xl p-4 ${entry.found ? 'border-emerald-500/30' : 'border-red-500/30'
                                                    }`}
                                            >
                                                <div className="flex items-start justify-between gap-4">
                                                    <div className="flex-1 min-w-0">
                                                        <div className="flex items-center gap-2 mb-2">
                                                            <span className={entry.found ? 'text-emerald-400' : 'text-red-400'}>
                                                                {entry.found ? '✅' : '❌'}
                                                            </span>
                                                            <span className="text-slate-900 dark:text-white font-bold">
                                                                {entry.found ? 'Şifre Bulundu' : 'Şifre Bulunamadı'}
                                                            </span>
                                                            <span className="text-xs bg-slate-700 px-2 py-0.5 rounded text-slate-300">
                                                                {entry.hash_type}
                                                            </span>
                                                            <span className="text-xs bg-purple-500/20 px-2 py-0.5 rounded text-purple-300">
                                                                {entry.attack_mode}
                                                            </span>
                                                        </div>
                                                        <div className="font-mono text-xs text-slate-400 truncate mb-2">
                                                            {entry.hash}
                                                        </div>
                                                        {entry.found && entry.password && (
                                                            <div className="bg-black/50 px-3 py-1.5 rounded border border-emerald-500/30 inline-block">
                                                                <span className="text-xs text-slate-500 mr-2">Şifre:</span>
                                                                <span className="font-mono text-emerald-400 font-bold">{entry.password}</span>
                                                            </div>
                                                        )}
                                                    </div>
                                                    <div className="text-right text-xs text-slate-500 shrink-0">
                                                        <div>{new Date(entry.timestamp).toLocaleDateString('tr-TR')}</div>
                                                        <div>{new Date(entry.timestamp).toLocaleTimeString('tr-TR')}</div>
                                                        <div className="mt-2 text-purple-400">
                                                            {entry.attempts.toLocaleString()} deneme
                                                        </div>
                                                        <div className="text-cyan-400">
                                                            {(entry.elapsed_ms / 1000).toFixed(2)}s
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                )
            }
            {/* Advanced Wordlist Modal */}
            {
                advancedModalOpen && (
                    <div className="fixed inset-0 bg-black/90 backdrop-blur-md flex items-center justify-center z-50 p-4">
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-2xl shadow-2xl">
                            <div className="flex border-b border-slate-800">
                                <button
                                    onClick={() => setGenTab('generate')}
                                    className={`flex-1 py-4 font-bold text-sm transition-colors ${genTab === 'generate' ? 'bg-purple-600/20 text-purple-400 border-b-2 border-purple-500' : 'text-slate-500 hover:text-slate-300'}`}
                                >
                                    ⚡ Özel Wordlist Oluştur
                                </button>
                                <button
                                    onClick={() => setGenTab('upload')}
                                    className={`flex-1 py-4 font-bold text-sm transition-colors ${genTab === 'upload' ? 'bg-purple-600/20 text-purple-400 border-b-2 border-purple-500' : 'text-slate-500 hover:text-slate-300'}`}
                                >
                                    📤 Wordlist Yükle
                                </button>
                            </div>

                            <div className="p-6">
                                {genTab === 'generate' ? (
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-xs font-bold text-slate-400 mb-1">Dosya Adı</label>
                                            <input
                                                type="text"
                                                value={genName}
                                                onChange={(e) => setGenName(e.target.value)}
                                                placeholder="my_custom_list.txt"
                                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-slate-900 dark:text-white"
                                            />
                                        </div>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div>
                                                <label className="block text-xs font-bold text-slate-400 mb-1">Baz Kelime (Opsiyonel)</label>
                                                <input
                                                    type="text"
                                                    value={genBase}
                                                    onChange={(e) => setGenBase(e.target.value)}
                                                    placeholder="password"
                                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                                                />
                                            </div>
                                            <div>
                                                <label className="block text-xs font-bold text-slate-400 mb-1">Pattern (Opsiyonel)</label>
                                                <input
                                                    type="text"
                                                    value={genPattern}
                                                    onChange={(e) => setGenPattern(e.target.value)}
                                                    placeholder="?d?d?d?s"
                                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono"
                                                />
                                                <div className="text-[10px] text-slate-500 mt-1">
                                                    ?d=0-9, ?l=a-z, ?u=A-Z, ?s=sembol, ?a=tümü
                                                </div>
                                            </div>
                                        </div>

                                        {!genPattern && (
                                            <div className="grid grid-cols-2 gap-4 border-t border-slate-800 pt-4">
                                                <div>
                                                    <label className="block text-xs font-bold text-slate-400 mb-1">Min Uzunluk</label>
                                                    <input
                                                        type="number"
                                                        value={genMin}
                                                        onChange={(e) => setGenMin(Number(e.target.value))}
                                                        className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-xs font-bold text-slate-400 mb-1">Max Uzunluk</label>
                                                    <input
                                                        type="number"
                                                        value={genMax}
                                                        onChange={(e) => setGenMax(Number(e.target.value))}
                                                        className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                                                    />
                                                </div>
                                            </div>
                                        )}

                                        <button
                                            onClick={handleGenerateWordlist}
                                            disabled={isProcessing}
                                            className="w-full py-3 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-bold mt-4"
                                        >
                                            {isProcessing ? 'Oluşturuluyor...' : '🚀 Oluştur'}
                                        </button>
                                    </div>
                                ) : (
                                    <div className="space-y-4">
                                        <div className="border-2 border-dashed border-slate-700 rounded-xl p-8 text-center hover:border-purple-500/50 transition-colors">
                                            <input
                                                type="file"
                                                onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                                                className="block w-full text-sm text-slate-500
                                                file:mr-4 file:py-2 file:px-4
                                                file:rounded-full file:border-0
                                                file:text-sm file:font-semibold
                                                file:bg-purple-500/10 file:text-purple-400
                                                hover:file:bg-purple-500/20"
                                                accept=".txt"
                                            />
                                            <p className="text-xs text-slate-500 mt-2">Sadece .txt dosyaları (satır satır)</p>
                                        </div>
                                        <button
                                            onClick={handleUploadWordlist}
                                            disabled={isProcessing || !uploadFile}
                                            className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold"
                                        >
                                            {isProcessing ? 'Yükleniyor...' : '📤 Yükle'}
                                        </button>
                                    </div>
                                )}

                                {error && (
                                    <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                                        {error}
                                    </div>
                                )}

                                <button
                                    onClick={() => setAdvancedModalOpen(false)}
                                    className="mt-4 w-full py-2 text-slate-400 hover:text-white"
                                >
                                    İptal
                                </button>
                            </div>
                        </div>
                    </div>
                )
            }

            {/* Mobile Fixed Bottom Loading Bar - İşlem sırasında her zaman görünür */}
            {isProcessing && (
                <div className="fixed bottom-0 left-0 right-0 z-50 bg-slate-900/95 backdrop-blur-lg border-t border-purple-500/30 p-3 sm:p-4 shadow-2xl shadow-purple-500/20 lg:hidden">
                    <div className="max-w-screen-xl mx-auto">
                        <div className="flex items-center gap-3">
                            <div className="relative flex-shrink-0">
                                <div className="w-10 h-10 rounded-full border-3 border-purple-500/30 border-t-purple-500 animate-spin"></div>
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <span className="text-lg">{job ? '🔓' : '🔀'}</span>
                                </div>
                            </div>
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between mb-1">
                                    <span className="text-sm font-bold text-white truncate">
                                        {job ? 'Hash Kırılıyor...' : 'Wordlist Hazırlanıyor...'}
                                    </span>
                                    {job && (
                                        <span className="text-lg font-bold text-purple-400 ml-2">
                                            {job.progress.percent.toFixed(0)}%
                                        </span>
                                    )}
                                </div>
                                {job ? (
                                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-gradient-to-r from-purple-600 to-pink-600 rounded-full transition-all duration-150"
                                            style={{ width: `${Math.max(2, job.progress.percent)}%` }}
                                        />
                                    </div>
                                ) : (
                                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                                        <div className="h-full w-full bg-gradient-to-r from-purple-600 via-pink-600 to-purple-600 animate-pulse rounded-full"
                                            style={{ backgroundSize: '200% 100%' }} />
                                    </div>
                                )}
                                <div className="flex justify-between mt-1 text-xs text-slate-400">
                                    {job ? (
                                        <>
                                            <span>{job.progress.attempts.toLocaleString()} deneme</span>
                                            <span>{formatRate(job.progress.rate)}</span>
                                        </>
                                    ) : (
                                        <span className="animate-pulse">Lütfen bekleyin...</span>
                                    )}
                                </div>
                            </div>
                            <button
                                onClick={cancelJob}
                                className="flex-shrink-0 px-3 py-2 bg-red-600/20 text-red-400 rounded-lg text-sm font-semibold border border-red-600/30"
                            >
                                ⛔
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div >
    );
}
