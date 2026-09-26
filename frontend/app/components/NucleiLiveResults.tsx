
/**
 * Türkçe: Nuclei Canlı Tarama Sonuçları Componenti
 * WebSocket üzerinden real-time tarama durumu, progress ve bulgular gösterir
 */
import { useEffect, useRef, useState } from 'react';
import { Shield, AlertTriangle, Terminal, Activity, CheckCircle, XCircle, Clock, Zap, Target, ExternalLink, BarChart3, Info, BookOpen, ArrowRight, ThumbsDown, ThumbsUp, AlertCircle } from 'lucide-react';
import { api } from '../services/api';

interface NucleiLiveResultsProps {
    scanId: string;
    initialStatus?: string;
    initialFindings?: Finding[];
}

interface Finding {
    template_id: string;
    name: string;
    severity: string;
    matched_at: string;
    timestamp: string;
    info?: any;
    is_potential_fp?: boolean;
    fp_analysis?: {
        fp_score: number;
        risk_level: 'low' | 'medium' | 'high' | 'very_high';
        is_potential_fp: boolean;
        reasons: string[];
        template_reliability: number;
        historical_fp_rate?: number;
    };
}

interface ScanProgress {
    templates_done?: number;
    templates_total?: number;
    progress_percent?: number;
    rps?: number;
    matched?: number;
    errors?: number;
    requests_done?: number;
    requests_total?: number;
    hosts?: number;
    duration?: string;
    eta?: string;
}

export default function NucleiLiveResults({ scanId, initialStatus, initialFindings }: NucleiLiveResultsProps) {
    const [findings, setFindings] = useState<Finding[]>(Array.isArray(initialFindings) ? initialFindings : []);
    const [logs, setLogs] = useState<string[]>([]);

    // Status normalization: map API status to component status
    const mapStatus = (s?: string) => {
        if (!s) return 'connecting';
        if (['completed', 'failed', 'cancelled', 'timeout'].includes(s)) return 'completed';
        return 'connected'; // Assume running/connected
    };

    const [status, setStatus] = useState<'connecting' | 'connected' | 'completed' | 'error'>(mapStatus(initialStatus));
    const [showTerminal, setShowTerminal] = useState(true);
    const [progress, setProgress] = useState<ScanProgress>({});
    const wsRef = useRef<WebSocket | null>(null);
    const terminalRef = useRef<HTMLDivElement>(null);
    const [markedFPs, setMarkedFPs] = useState<Set<string>>(new Set());

    // Türkçe: FP/TP işaretleme fonksiyonu
    const markAsFP = async (templateId: string) => {
        try {
            await api.post('/api/nuclei/mark-fp', { template_id: templateId });
            setMarkedFPs(prev => new Set([...prev, templateId]));
            setLogs(prev => [...prev, `⚠️ ${templateId} False Positive olarak işaretlendi`]);
        } catch (e) {
            console.error('FP işaretleme hatası:', e);
        }
    };

    const markAsTP = async (templateId: string) => {
        try {
            await api.post('/api/nuclei/mark-tp', { template_id: templateId });
            setLogs(prev => [...prev, `✅ ${templateId} Gerçek Zafiyet olarak doğrulandı`]);
        } catch (e) {
            console.error('TP işaretleme hatası:', e);
        }
    };

    // Türkçe: FP risk seviyesi rengini döndür
    const getFPRiskColor = (riskLevel?: string) => {
        switch (riskLevel) {
            case 'very_high': return 'text-red-400 bg-red-500/10 border-red-500/30';
            case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
            case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
            default: return 'text-green-400 bg-green-500/10 border-green-500/30';
        }
    };

    useEffect(() => {
        if (!scanId) return;

        // Static Mode: If scan is already done, don't connect to WS
        if (initialStatus && ['completed', 'failed', 'cancelled', 'timeout'].includes(initialStatus)) {
            setStatus('completed');
            setFindings(Array.isArray(initialFindings) ? initialFindings : []);

            // Try to fetch full logs from backend
            const fetchLogs = async () => {
                try {
                    const result = await api.get<{ log_content?: string; logs?: string[] }>(`/api/nuclei/logs/${scanId}`);
                    if (result && result.log_content) {
                        const logLines = result.log_content.split('\n').filter((line: string) => line.trim());
                        setLogs(logLines);
                    } else if (result && result.logs && Array.isArray(result.logs) && result.logs.length > 0) {
                        setLogs(result.logs);
                    } else {
                        // Fallback to synthetic logs if no full log is available
                        generateSyntheticLogs();
                    }
                } catch (e) {
                    // Fallback to synthetic logs on error
                    generateSyntheticLogs();
                }
            };

            const generateSyntheticLogs = () => {
                if (Array.isArray(initialFindings) && initialFindings.length > 0) {
                    const syntheticLogs = initialFindings.map(f =>
                        `🔴 [BULGU] ${f.severity.toUpperCase()}: ${f.name}`
                    );
                    syntheticLogs.push(`✅ [GEÇMİŞ] Tarama tamamlandı (${initialFindings.length} bulgu)`);
                    setLogs(syntheticLogs);
                } else {
                    setLogs(['ℹ️ [GEÇMİŞ] Tarama tamamlandı - Zafiyet bulunamadı']);
                }
            };

            fetchLogs();
            return;
        }

        // Live Mode: Connect to WS
        setFindings([]);
        setLogs([]);
        setProgress({
            requests_done: 0,
            requests_total: 0,
            progress_percent: 0,
            eta: '',
            rps: 0
        });
        setStatus('connecting');

        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/api/nuclei/ws/monitor/${scanId}`;

        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
            setStatus('connected');
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);

                if (data.type === 'finding') {
                    setFindings(prev => [...prev, data]);
                    setLogs(prev => [...prev, `🔴 [BULGU] ${data.severity.toUpperCase()}: ${data.name}`]);
                } else if (data.type === 'progress') {
                    // Türkçe: Progress bilgisini güncelle
                    setProgress(prev => ({ ...prev, ...data }));
                } else if (data.type === 'log') {
                    setLogs(prev => [...prev, data.message]);
                } else if (data.type === 'info') {
                    setLogs(prev => [...prev, `ℹ️ ${data.message}`]);
                } else if (data.type === 'status') {
                    setLogs(prev => [...prev, `✅ ${data.message}`]);
                } else if (data.type === 'completed') {
                    setStatus('completed');
                    setLogs(prev => [...prev, `✅ ${data.message || 'Tarama tamamlandı'}`]);
                } else if (data.type === 'error') {
                    setLogs(prev => [...prev, `❌ Hata: ${data.message}`]);
                }
            } catch (e) {
                console.error('WebSocket mesaj parse hatası:', e);
            }
        };

        ws.onclose = () => {
            if (status !== 'completed') {
                setStatus('completed');
            }
        };

        ws.onerror = () => {
            setStatus('error');
        };

        return () => {
            ws.close();
        };
    }, [scanId]);

    useEffect(() => {
        if (showTerminal && terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [logs, showTerminal]);

    const severityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/20';
            case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
            case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
            case 'low': return 'text-green-400 bg-green-500/10 border-green-500/20';
            default: return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
        }
    };

    const getStatusText = () => {
        switch (status) {
            case 'connected': return 'Tarama devam ediyor...';
            case 'connecting': return 'Bağlanıyor...';
            case 'completed': return 'Tarama tamamlandı';
            case 'error': return 'Bağlantı hatası';
        }
    };

    const getStatusColor = () => {
        switch (status) {
            case 'connected': return 'text-emerald-400';
            case 'connecting': return 'text-yellow-400';
            case 'completed': return 'text-blue-400';
            case 'error': return 'text-red-400';
        }
    };

    // Türkçe: Akıllı Rehberlik Sistemi
    const getGuidance = (finding: Finding) => {
        const id = finding.template_id.toLowerCase();
        const name = finding.name.toLowerCase();
        const severity = finding.severity.toLowerCase();

        if (severity === 'critical' || severity === 'high') {
            if (id.includes('cve-')) {
                return {
                    title: "Kritik CVE Zafiyeti",
                    action: "Acil Yama Gerektirir",
                    steps: [
                        "İlgili CVE kodunu (ör: CVE-2023-XXXX) araştırın.",
                        "Sistem versiyonunu kontrol edin ve zafiyetli olup olmadığını doğrulayın.",
                        "Vendor tarafından yayınlanan yamayı veya workaround'u uygulayın.",
                        "Geçici olarak ilgili servisi dış dünyaya kapatmayı değerlendirin."
                    ]
                };
            }
            if (name.includes('sql') || id.includes('sqli')) {
                return {
                    title: "SQL Injection",
                    action: "Veritabanı Güvenliği",
                    steps: [
                        "Girdi validasyonlarını kontrol edin.",
                        "Parametreli sorgular (Prepared Statements) kullanın.",
                        "sqlmap aracı ile zafiyeti doğrulayın: `sqlmap -u <URL>`",
                        "WAF kurallarını güncelleyin."
                    ]
                };
            }
            if (name.includes('xss') || id.includes('xss')) {
                return {
                    title: "Cross-Site Scripting (XSS)",
                    action: "Frontend Güvenliği",
                    steps: [
                        "Kullanıcı girdilerini encode edin (HTML Entity Encoding).",
                        "Content Security Policy (CSP) başlıklarını sıkılaştırın.",
                        "Tarayıcıda alert(1) payload'ı ile manuel doğrulama yapın.",
                        "HttpOnly cookie flag'ini aktif edin."
                    ]
                };
            }
            if (name.includes('lfi') || name.includes('local file')) {
                return {
                    title: "Local File Inclusion (LFI)",
                    action: "Dosya Erişim Kontrolü",
                    steps: [
                        "Dosya yolu girdilerini sanitize edin.",
                        "Kullanıcının erişebileceği dizinleri whitelist ile sınırlayın.",
                        "Etkilenen parametre ile `/etc/passwd` okumayı deneyin."
                    ]
                };
            }
        }

        if (severity === 'medium') {
            if (name.includes('ssl') || name.includes('tls')) {
                return {
                    title: "SSL/TLS Yapılandırması",
                    action: "Şifreleme Güvenliği",
                    steps: [
                        "Zayıf şifreleme algoritmalarını (RC4, 3DES) devre dışı bırakın.",
                        "TLS 1.2 veya 1.3 kullanmaya zorlayın.",
                        "Sertifika geçerlilik sürelerini kontrol edin."
                    ]
                };
            }
        }

        if (name.includes('panel') || name.includes('login')) {
            return {
                title: "Açık Yönetim Paneli",
                action: "Erişim Kısıtlaması",
                steps: [
                    "Admin panellerini halka açık ağlardan gizleyin.",
                    "IP kısıtlaması veya VPN zorunluluğu getirin.",
                    "Güçlü parola politikaları ve MFA (Çok Faktörlü Doğrulama) uygulayın.",
                    "Varsayılan (default) parolaları değiştirin."
                ]
            };
        }

        return null;
    };

    const getNextSteps = () => {
        const criticalCount = findings.filter(f => f?.severity === 'critical').length;
        const highCount = findings.filter(f => f?.severity === 'high').length;
        const webVulns = findings.filter(f => f?.name?.toLowerCase().includes('xss') || f?.name?.toLowerCase().includes('sql')).length;
        const networkVulns = findings.filter(f => f?.template_id?.includes('cve')).length;

        const steps = [];

        if (criticalCount > 0) {
            steps.push({
                icon: <AlertTriangle className="w-4 h-4 text-red-500" />,
                text: "Kritik zafiyetler tespit edildi. Acil durum planını devreye sokun ve sistem yöneticilerini bilgilendirin."
            });
        }

        if (webVulns > 0) {
            steps.push({
                icon: <Zap className="w-4 h-4 text-orange-500" />,
                text: "Web uygulama zafiyetleri bulundu. Detaylı analiz için 'Burp Suite' veya 'OWASP ZAP' taraması başlatın."
            });
        }

        if (networkVulns > 0) {
            steps.push({
                icon: <Target className="w-4 h-4 text-blue-500" />,
                text: "Ağ tabanlı CVE'ler bulundu. Servis versiyonlarını doğrulamak için 'Nmap -sV' taraması yapın."
            });
        }

        if (steps.length === 0 && findings.length > 0) {
            steps.push({
                icon: <BookOpen className="w-4 h-4 text-emerald-500" />,
                text: "Bulguları raporlayın ve düşük riskli yapılandırma hatalarını planlı bakımda giderin."
            });
        }

        return steps;
    };

    return (
        <div className="space-y-6">
            {/* Türkçe: Progress Bar ve İstatistikler */}
            {(progress.progress_percent !== undefined || progress.templates_total) && (
                <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-6 space-y-4">
                    {/* Progress Bar */}
                    <div className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-slate-400">Tarama İlerlemesi</span>
                            <span className="text-emerald-400 font-mono">
                                {progress.progress_percent?.toFixed(1) || 0}%
                            </span>
                        </div>
                        <div className="h-3 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 rounded-full transition-all duration-500"
                                style={{ width: `${progress.progress_percent || 0}%` }}
                            />
                        </div>
                        {progress.templates_total && (
                            <p className="text-xs text-slate-500 text-right">
                                {progress.templates_done || 0} / {progress.templates_total} template tarandı
                            </p>
                        )}
                    </div>

                    {/* İstatistik Kartları */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {/* RPS - Requests Per Second */}
                        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                            <div className="flex items-center gap-2 mb-1">
                                <Zap className="w-4 h-4 text-yellow-500" />
                                <span className="text-xs text-slate-400">RPS</span>
                            </div>
                            <p className="text-lg font-bold text-white font-mono">
                                {progress.rps || 0}
                            </p>
                            <p className="text-xs text-slate-500">istek/sn</p>
                        </div>

                        {/* Requests */}
                        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                            <div className="flex items-center gap-2 mb-1">
                                <BarChart3 className="w-4 h-4 text-blue-500" />
                                <span className="text-xs text-slate-400">İstekler</span>
                            </div>
                            <p className="text-lg font-bold text-white font-mono">
                                {progress.requests_done || 0}
                            </p>
                            <p className="text-xs text-slate-500">
                                / {progress.requests_total || '∞'}
                            </p>
                        </div>

                        {/* Duration */}
                        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                            <div className="flex items-center gap-2 mb-1">
                                <Clock className="w-4 h-4 text-purple-500" />
                                <span className="text-xs text-slate-400">Süre</span>
                            </div>
                            <p className="text-lg font-bold text-white font-mono">
                                {progress.duration || '00:00'}
                            </p>
                            <p className="text-xs text-slate-500">geçen</p>
                        </div>

                        {/* ETA - Estimated Time */}
                        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                            <div className="flex items-center gap-2 mb-1">
                                <Target className="w-4 h-4 text-emerald-500" />
                                <span className="text-xs text-slate-400">Kalan</span>
                            </div>
                            <p className="text-lg font-bold text-white font-mono">
                                {progress.eta || '--:--'}
                            </p>
                            <p className="text-xs text-slate-500">tahmini</p>
                        </div>
                    </div>

                    {/* Errors Warning */}
                    {progress.errors && progress.errors > 0 && (
                        <div className="flex items-center gap-2 text-yellow-500 text-sm bg-yellow-500/10 rounded-lg px-3 py-2">
                            <AlertTriangle className="w-4 h-4" />
                            <span>{progress.errors} hata oluştu (bazı template'ler çalışmamış olabilir)</span>
                        </div>
                    )}
                </div>
            )}

            {/* Status Header */}
            <div className="flex items-center justify-between bg-slate-400/10 p-4 rounded-xl border border-slate-800">
                <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${status === 'connected' ? 'bg-emerald-500/10' : status === 'completed' ? 'bg-blue-500/10' : 'bg-slate-800'}`}>
                        {status === 'completed' ? (
                            <CheckCircle className="w-5 h-5 text-blue-500" />
                        ) : (
                            <Activity className={`w-5 h-5 ${status === 'connected' ? 'text-emerald-500 animate-pulse' : 'text-slate-400'}`} />
                        )}
                    </div>
                    <div>
                        <h3 className="font-semibold text-black dark:text-white">Canlı Tarama Durumu</h3>
                        <p className={`text-xs ${getStatusColor()}`}>
                            {getStatusText()}
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-4">
                    <div className="text-right">
                        <div className="text-2xl font-bold text-emerald-500 dark:text-red-700">{findings.length}</div>
                        <div className="text-xs text-slate-700 dark:text-slate-400">Bulgu</div>
                    </div>
                    <button
                        onClick={() => setShowTerminal(!showTerminal)}
                        className={`p-2 rounded-lg border transition-colors ${showTerminal
                            ? 'bg-slate-800 border-slate-700 text-white'
                            : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                            }`}
                    >
                        <Terminal className="w-5 h-5" />
                    </button>
                </div>
            </div>

            {/* Terminal View */}
            {showTerminal && (
                <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden animate-in fade-in slide-in-from-top-2">
                    <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800">
                        <span className="text-xs font-mono text-slate-400">Terminal Output</span>
                        <span className="text-xs text-slate-500">{logs.length} satır</span>
                    </div>
                    <div
                        ref={terminalRef}
                        className="h-64 overflow-y-auto p-4 font-mono text-xs text-slate-300 space-y-1"
                    >
                        {logs.map((log, i) => (
                            <div key={i} className="break-all hover:bg-slate-900/50 px-1 -mx-1 rounded">
                                {log}
                            </div>
                        ))}
                        {logs.length === 0 && <span className="text-slate-600 italic">Henüz log yok...</span>}
                    </div>
                </div>
            )}

            {/* Findings Grid */}
            {findings.length > 0 && (
                <div className="space-y-6">
                    <div>
                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                            <Shield className="w-5 h-5 text-purple-500" />
                            Bulunan Zafiyetler ({findings.length})
                        </h3>
                        <div className="grid grid-cols-1 gap-4">
                            {findings.map((finding, idx) => {
                                const guidance = getGuidance(finding);
                                return (
                                    <div key={idx} className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all group animate-in fade-in slide-in-from-bottom-2">
                                        <div className="flex items-start justify-between mb-3">
                                            <div className="flex items-center gap-3">
                                                <div className={`p-2 rounded-lg ${severityColor(finding.severity)} bg-opacity-10`}>
                                                    <Shield className="w-5 h-5" />
                                                </div>
                                                <div>
                                                    <h4 className="font-bold text-white text-lg group-hover:text-purple-400 transition-colors">
                                                        {finding.name || finding.template_id}
                                                    </h4>
                                                    <span className="font-mono text-xs text-slate-500">{finding.template_id}</span>
                                                </div>
                                            </div>
                                            <span className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider border ${severityColor(finding.severity)}`}>
                                                {finding.severity}
                                            </span>
                                        </div>

                                        <div className="mt-4 p-3 bg-slate-950/50 rounded-lg border border-slate-800/50 flex items-center justify-between group-hover:border-purple-500/30 transition-colors">
                                            <code className="text-xs sm:text-sm text-emerald-400 font-mono break-all">
                                                {finding.matched_at}
                                            </code>
                                            <a
                                                href={finding.matched_at}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="ml-4 p-2 bg-slate-800 hover:bg-emerald-600/20 hover:text-emerald-400 text-slate-400 rounded-lg transition-all"
                                                title="Bağlantıyı Aç"
                                            >
                                                <ExternalLink className="w-4 h-4" />
                                            </a>
                                        </div>

                                        {/* Türkçe: FP Analiz Göstergesi */}
                                        {finding.fp_analysis && (
                                            <div className={`mt-3 p-3 rounded-lg border ${getFPRiskColor(finding.fp_analysis.risk_level)}`}>
                                                <div className="flex items-center justify-between mb-2">
                                                    <div className="flex items-center gap-2">
                                                        <AlertCircle className="w-4 h-4" />
                                                        <span className="text-sm font-medium">
                                                            FP Risk: {(finding.fp_analysis.fp_score * 100).toFixed(0)}%
                                                        </span>
                                                        {finding.fp_analysis.is_potential_fp && (
                                                            <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded">
                                                                Muhtemel FP
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className="flex items-center gap-1">
                                                        {!markedFPs.has(finding.template_id) ? (
                                                            <>
                                                                <button
                                                                    onClick={() => markAsFP(finding.template_id)}
                                                                    className="p-1.5 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors"
                                                                    title="False Positive Olarak İşaretle"
                                                                >
                                                                    <ThumbsDown className="w-3.5 h-3.5" />
                                                                </button>
                                                                <button
                                                                    onClick={() => markAsTP(finding.template_id)}
                                                                    className="p-1.5 rounded bg-green-500/10 hover:bg-green-500/20 text-green-400 transition-colors"
                                                                    title="Gerçek Zafiyet Olarak Onayla"
                                                                >
                                                                    <ThumbsUp className="w-3.5 h-3.5" />
                                                                </button>
                                                            </>
                                                        ) : (
                                                            <span className="text-xs text-slate-500">İşaretlendi</span>
                                                        )}
                                                    </div>
                                                </div>
                                                {finding.fp_analysis.reasons && finding.fp_analysis.reasons.length > 0 && (
                                                    <div className="text-xs text-slate-400 space-y-0.5">
                                                        {finding.fp_analysis.reasons.slice(0, 2).map((reason, i) => (
                                                            <div key={i} className="flex items-center gap-1">
                                                                <span className="text-slate-600">•</span>
                                                                {reason}
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                                {finding.fp_analysis.historical_fp_rate !== undefined && finding.fp_analysis.historical_fp_rate > 0 && (
                                                    <div className="text-xs text-slate-500 mt-1">
                                                        📊 Geçmiş FP oranı: %{(finding.fp_analysis.historical_fp_rate * 100).toFixed(0)}
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* Guidance Section */}
                                        {guidance && (
                                            <div className="mt-4 bg-blue-500/5 border border-blue-500/10 rounded-lg p-4">
                                                <div className="flex items-center gap-2 mb-2 text-blue-400">
                                                    <Info className="w-4 h-4" />
                                                    <h5 className="font-semibold text-sm">{guidance.title} - Aksiyon Planı</h5>
                                                </div>
                                                <p className="text-sm text-slate-300 mb-3 font-medium">{guidance.action}</p>
                                                <ul className="space-y-1">
                                                    {guidance.steps?.map((step, i) => (
                                                        <li key={i} className="text-xs text-slate-400 flex items-start gap-2">
                                                            <span className="text-blue-500/50 mt-0.5">•</span>
                                                            {step}
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                        )}

                                        <div className="flex items-center justify-end mt-4 pt-2 border-t border-slate-800/50">
                                            <span className="text-xs text-slate-500 flex items-center gap-1">
                                                <Clock className="w-3 h-3" />
                                                {new Date(finding.timestamp).toLocaleTimeString()}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Next Steps Recommendations */}
                    {status === 'completed' && findings.length > 0 && (
                        <div className="bg-gradient-to-br from-slate-900 to-slate-900/50 border border-slate-800 rounded-xl p-6">
                            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                                <BookOpen className="w-5 h-5 text-emerald-500" />
                                Önerilen Sonraki Adımlar
                            </h3>
                            <div className="grid gap-3">
                                {getNextSteps().map((step, i) => (
                                    <div key={i} className="flex items-start gap-3 p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                                        <div className="mt-1">{step.icon}</div>
                                        <p className="text-sm text-slate-300">{step.text}</p>
                                        <ArrowRight className="w-4 h-4 text-slate-600 ml-auto mt-1" />
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {findings.length === 0 && status === 'connected' && (
                <div className="py-12 text-center border-2 border-dashed border-slate-800 rounded-xl">
                    <div className="w-12 h-12 bg-slate-800/50 rounded-full flex items-center justify-center mx-auto mb-4">
                        <Activity className="w-6 h-6 text-slate-500 animate-pulse" />
                    </div>
                    <p className="text-slate-400">Tarama devam ediyor, bulgular bekleniyor...</p>
                    <p className="text-xs text-slate-500 mt-2">Yavaş tarama ile tespit edilmeden ilerliyorsunuz</p>
                </div>
            )}

            {findings.length === 0 && status === 'completed' && (
                <div className="py-12 text-center border-2 border-dashed border-gray-500/50 rounded-xl bg-gray-500/5">
                    <div className="w-12 h-12 bg-emerald-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                        <CheckCircle className="w-6 h-6 text-emerald-500" />
                    </div>
                    <p className="text-emerald-400">Tarama tamamlandı - Zafiyet bulunamadı</p>
                    <p className="text-xs text-slate-500 mt-2">
                        Hedef güvenli görünüyor. Eğer sonuç bekliyorsanız 'Info' seviyesini açmayı deneyin
                        veya daha fazla template seçin.
                    </p>
                </div>
            )}
        </div>
    );
}
