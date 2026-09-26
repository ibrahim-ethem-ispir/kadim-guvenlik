import React, { useState, useEffect, useRef } from 'react';
import { Wifi, Shield, Lock, Unlock, AlertTriangle, Info, RefreshCw, Terminal, Radio, X, Signal, Activity, Globe, Upload, CheckCircle, XCircle, Clock, FileText, Zap, Eye, Trash2, Download } from 'lucide-react';
import Tooltip from '../components/Tooltip';
import { api } from '../services/api';

// --- Types ---
interface Network {
    ssid: string;
    bssid: string;
    signal: number;
    security: string;
    channel: number;
    clients: number;
    vendor?: string;
    firstSeen?: string;
    lastSeen?: string;
}

interface CrackJob {
    id: string;
    ssid: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    progress: number;
    result?: string;
    startedAt: string;
}

interface ScanHistory {
    id: string;
    timestamp: string;
    networkCount: number;
    mode: 'demo' | 'real';
}

type ConnectionStatus = 'checking' | 'connected' | 'disconnected' | 'demo';

// --- Components ---
const Modal = ({ isOpen, onClose, title, children }: { isOpen: boolean; onClose: () => void; title: string; children: React.ReactNode }) => {
    if (!isOpen) return null;
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 dark:bg-black/80 backdrop-blur-sm overflow-y-auto">
            <div className="bg-white dark:bg-slate-900 border border-emerald-500/30 rounded-xl max-w-4xl w-full shadow-2xl shadow-emerald-500/20 dark:shadow-emerald-500/10 animate-in fade-in zoom-in duration-200 my-8">
                <div className="sticky top-0 bg-white dark:bg-slate-900 p-6 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center rounded-t-xl z-10">
                    <h3 className="text-xl font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-2">
                        <Info className="w-6 h-6" /> {title}
                    </h3>
                    <button onClick={onClose} className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-6 h-6" />
                    </button>
                </div>
                <div className="p-6 text-slate-700 dark:text-slate-300 space-y-6">{children}</div>
            </div>
        </div>
    );
};

// Connection Status Badge
const ConnectionBadge = ({ status }: { status: ConnectionStatus }) => {
    const configs = {
        checking: { bg: 'bg-yellow-100 dark:bg-yellow-500/20', text: 'text-yellow-700 dark:text-yellow-400', border: 'border-yellow-300 dark:border-yellow-500/30', label: 'Kontrol ediliyor...', icon: RefreshCw },
        connected: { bg: 'bg-emerald-100 dark:bg-emerald-500/20', text: 'text-emerald-700 dark:text-emerald-400', border: 'border-emerald-300 dark:border-emerald-500/30', label: 'Bağlı (Gerçek Mod)', icon: CheckCircle },
        disconnected: { bg: 'bg-red-100 dark:bg-red-500/20', text: 'text-red-700 dark:text-red-400', border: 'border-red-300 dark:border-red-500/30', label: 'Bağlantı Yok', icon: XCircle },
        demo: { bg: 'bg-blue-100 dark:bg-blue-500/20', text: 'text-blue-700 dark:text-blue-400', border: 'border-blue-300 dark:border-blue-500/30', label: 'Demo Modu', icon: Info }
    };
    const config = configs[status];
    const Icon = config.icon;

    return (
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium ${config.bg} ${config.border} border`}>
            <Icon className={`w-3 h-3 ${config.text} ${status === 'checking' ? 'animate-spin' : ''}`} />
            <span className={config.text}>{config.label}</span>
        </div>
    );
};

// Progress Bar
const ProgressBar = ({ progress, label }: { progress: number; label?: string }) => (
    <div className="w-full">
        {label && <div className="text-xs text-slate-600 dark:text-slate-400 mb-1">{label}</div>}
        <div className="h-2 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
            <div
                className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all duration-300"
                style={{ width: `${progress}%` }}
            />
        </div>
        <div className="text-xs text-slate-500 mt-1 text-right">{progress}%</div>
    </div>
);

export default function WiFiAudit() {
    const [networks, setNetworks] = useState<Network[]>([]);
    const [scanning, setScanning] = useState(false);
    const [selectedNetwork, setSelectedNetwork] = useState<Network | null>(null);
    const [showIntro, setShowIntro] = useState(true);
    const [showNetworkDetail, setShowNetworkDetail] = useState(false);
    const [logs, setLogs] = useState<string[]>([]);
    const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('checking');
    const [crackJobs, setCrackJobs] = useState<CrackJob[]>([]);
    const [scanHistory, setScanHistory] = useState<ScanHistory[]>([]);
    const [uploadedFile, setUploadedFile] = useState<File | null>(null);
    const [crackStrategy, setCrackStrategy] = useState('wordlist');
    const fileInputRef = useRef<HTMLInputElement>(null);

    // Check backend connection on mount
    useEffect(() => {
        checkConnection();
        loadScanHistory();
    }, []);

    const checkConnection = async () => {
        setConnectionStatus('checking');
        try {
            await api.get('/api/wifi/health');
            setConnectionStatus('connected');
            addLog('✅ WiFi servisi bağlantısı başarılı');
        } catch {
            setConnectionStatus('demo');
            addLog('ℹ️ WiFi servisi erişilemez - Demo modunda çalışılıyor');
        }
    };

    const loadScanHistory = () => {
        const saved = localStorage.getItem('wifi_scan_history');
        if (saved) setScanHistory(JSON.parse(saved));
    };

    const saveScanToHistory = (count: number, mode: 'demo' | 'real') => {
        const entry: ScanHistory = {
            id: Date.now().toString(),
            timestamp: new Date().toISOString(),
            networkCount: count,
            mode
        };
        const updated = [entry, ...scanHistory].slice(0, 10);
        setScanHistory(updated);
        localStorage.setItem('wifi_scan_history', JSON.stringify(updated));
    };

    const startScan = async () => {
        setScanning(true);
        setNetworks([]);
        addLog("Kablosuz arayüz başlatılıyor...");

        try {
            const data = await api.post<any>('/api/wifi/scan/start', {});
            if (data.networks?.length > 0) {
                const enrichedNetworks = data.networks.map((n: Network) => ({
                    ...n,
                    vendor: getVendorFromBssid(n.bssid),
                    firstSeen: new Date().toISOString(),
                    lastSeen: new Date().toISOString()
                }));
                setNetworks(enrichedNetworks);
                addLog(`✅ Tarama tamamlandı. ${data.networks.length} ağ bulundu.`);
                saveScanToHistory(data.networks.length, 'real');
                setConnectionStatus('connected');
            } else {
                loadDemoData();
            }
        } catch {
            loadDemoData();
        } finally {
            setScanning(false);
        }
    };

    const loadDemoData = () => {
        addLog("⚠️ Backend erişilemez - Demo moduna geçiliyor...");
        const demoNetworks: Network[] = [
            { ssid: "[DEMO] SuperOnline_WiFi_42", bssid: "E8:9F:80:1A:2B:3C", signal: -42, security: "WPA2/WPA3", channel: 6, clients: 3, vendor: "TP-Link" },
            { ssid: "[DEMO] TurkTelekom_Z581", bssid: "00:1A:2B:3C:4D:5E", signal: -58, security: "WPA2", channel: 1, clients: 5, vendor: "ZyXEL" },
            { ssid: "[DEMO] Misafir_Agi", bssid: "AA:BB:CC:11:22:33", signal: -65, security: "Open", channel: 11, clients: 12, vendor: "Unknown" },
            { ssid: "[DEMO] Vodafone_Net_Premium", bssid: "DC:EF:09:12:34:56", signal: -55, security: "WPA3", channel: 36, clients: 8, vendor: "Huawei" },
        ];
        setNetworks(demoNetworks);
        saveScanToHistory(demoNetworks.length, 'demo');
        setConnectionStatus('demo');
        addLog("Demo verisi yüklendi.");
    };

    const getVendorFromBssid = (bssid: string): string => {
        const oui = bssid.substring(0, 8).toUpperCase();
        const vendors: Record<string, string> = {
            'E8:9F:80': 'TP-Link', '00:1A:2B': 'ZyXEL', 'DC:EF:09': 'Huawei',
            'F4:EC:38': 'TP-Link', '74:DA:88': 'TP-Link', 'AC:84:C6': 'TP-Link'
        };
        return vendors[oui] || 'Unknown';
    };

    const addLog = (msg: string) => {
        setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev].slice(0, 100));
    };

    const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            setUploadedFile(file);
            addLog(`📁 Dosya yüklendi: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
        }
    };

    const startCracking = async () => {
        if (!uploadedFile && !selectedNetwork) {
            addLog("⚠️ Kırma işlemi için bir ağ seçin veya handshake dosyası yükleyin");
            return;
        }

        const jobId = Date.now().toString();
        const newJob: CrackJob = {
            id: jobId,
            ssid: selectedNetwork?.ssid || uploadedFile?.name || 'Unknown',
            status: 'running',
            progress: 0,
            startedAt: new Date().toISOString()
        };
        setCrackJobs(prev => [newJob, ...prev]);
        addLog(`🔓 Şifre kırma başlatıldı: ${newJob.ssid} (${crackStrategy})`);

        // Simulate progress
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress >= 100) {
                progress = 100;
                clearInterval(interval);
                setCrackJobs(prev => prev.map(j => 
                    j.id === jobId ? { ...j, status: 'completed', progress: 100, result: 'Demo: password123' } : j
                ));
                addLog(`✅ Kırma tamamlandı: ${newJob.ssid}`);
            } else {
                setCrackJobs(prev => prev.map(j => 
                    j.id === jobId ? { ...j, progress: Math.min(progress, 99) } : j
                ));
            }
        }, 500);
    };

    const handleAttack = (type: string) => {
        if (!selectedNetwork) return;
        if (connectionStatus === 'demo') {
            addLog(`⚠️ Demo modunda ${type} saldırısı simüle ediliyor...`);
        }
        if (type === 'Deauth') {
            addLog(`🎯 ${selectedNetwork.ssid} ağına Deauth saldırısı...`);
            setTimeout(() => addLog(`> İstemciler düşürülüyor...`), 1000);
            setTimeout(() => addLog(`> Handshake bekleniyor...`), 2000);
        } else if (type === 'Handshake') {
            addLog(`📡 ${selectedNetwork.ssid} için Handshake yakalama aktif...`);
            setTimeout(() => {
                addLog(`> [BAŞARILI] WPA Handshake yakalandı!`);
                addLog(`> Dosya: captures/${selectedNetwork.ssid}_handshake.cap`);
            }, 3000);
        }
    };

    return (
        <div className="space-y-6 pb-12">
            {/* Header with Connection Status */}
            <div className="flex items-center justify-between flex-wrap gap-4">
                <div>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
                        <Radio className="w-8 h-8 text-emerald-500 animate-pulse" />
                        WI-FI SENTINEL
                        <Tooltip content="Gelişmiş kablosuz ağ denetim aracı" position="bottom" />
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1">Kablosuz Ağ Güvenlik Denetimi & Analizi</p>
                </div>
                <div className="flex items-center gap-3">
                    <ConnectionBadge status={connectionStatus} />
                    <button onClick={() => setShowIntro(true)} className="px-4 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-emerald-600 dark:text-emerald-400 rounded-lg border border-emerald-500/30 transition-all flex items-center gap-2">
                        <Info className="w-4 h-4" /> Rehber
                    </button>
                    <button onClick={startScan} disabled={scanning} className={`px-6 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-lg shadow-emerald-500/20 transition-all flex items-center gap-2 ${scanning ? 'opacity-50 cursor-not-allowed' : ''}`}>
                        <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
                        {scanning ? 'Tarıyor...' : 'Taramayı Başlat'}
                    </button>
                </div>
            </div>

            {/* Demo Mode Banner */}
            {connectionStatus === 'demo' && (
                <div className="bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/30 rounded-xl p-4 flex items-center gap-4">
                    <Info className="w-6 h-6 text-blue-500 dark:text-blue-400 shrink-0" />
                    <div>
                        <h4 className="font-bold text-blue-600 dark:text-blue-400">Demo Modu Aktif</h4>
                        <p className="text-sm text-blue-600/70 dark:text-blue-300/70">WiFi servisi Docker içinde çalıştığı için gerçek tarama yapılamıyor. Simüle edilmiş veriler gösteriliyor.</p>
                    </div>
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Network List */}
                <div className="lg:col-span-2 space-y-4">
                    <div className="bg-white/80 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm shadow-lg dark:shadow-none">
                        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-900/80">
                            <h2 className="font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-2">
                                <Wifi className="w-5 h-5" /> Tespit Edilen Ağlar
                            </h2>
                            <span className="text-xs text-slate-600 dark:text-slate-500 font-mono px-2 py-1 bg-slate-200 dark:bg-slate-800 rounded border border-slate-300 dark:border-slate-700">{networks.length} AP</span>
                        </div>

                        {networks.length === 0 ? (
                            <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center h-64">
                                <Radio className="w-12 h-12 opacity-20 mb-4" />
                                <p className="text-lg font-medium text-slate-500 dark:text-slate-400">Henüz ağ tespit edilmedi</p>
                                <p className="text-sm mt-2">Taramayı başlatın</p>
                            </div>
                        ) : (
                            <div className="divide-y divide-slate-200 dark:divide-slate-800 max-h-96 overflow-y-auto">
                                {networks.map((net, idx) => (
                                    <div key={idx} onClick={() => { setSelectedNetwork(net); setShowNetworkDetail(true); }}
                                        className={`p-4 cursor-pointer transition-all hover:bg-slate-100 dark:hover:bg-slate-800/50 flex items-center justify-between group ${selectedNetwork?.bssid === net.bssid ? 'bg-emerald-50 dark:bg-emerald-500/10 border-l-4 border-emerald-500' : 'border-l-4 border-transparent'}`}>
                                        <div className="flex items-center gap-4">
                                            <div className={`p-2.5 rounded-full ${net.signal > -50 ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400' : net.signal > -70 ? 'bg-yellow-100 dark:bg-yellow-500/20 text-yellow-600 dark:text-yellow-400' : 'bg-red-100 dark:bg-red-500/20 text-red-600 dark:text-red-400'}`}>
                                                <Wifi className="w-5 h-5" />
                                            </div>
                                            <div>
                                                <h3 className="font-bold text-slate-900 dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-300 transition-colors">{net.ssid}</h3>
                                                <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                                                    <span className="font-mono">{net.bssid}</span>
                                                    <span>CH {net.channel}</span>
                                                    <span>{net.clients} İstemci</span>
                                                </div>
                                            </div>
                                        </div>
                                        <div className="flex flex-col items-end gap-2">
                                            <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${net.security.includes('Open') ? 'bg-red-100 dark:bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-500/30' : net.security.includes('WPA3') ? 'bg-purple-100 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-200 dark:border-purple-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700'}`}>
                                                {net.security}
                                            </span>
                                            <span className="text-xs font-mono text-slate-500">{net.signal} dBm</span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Scan History */}
                    {scanHistory.length > 0 && (
                        <div className="bg-white/80 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-lg dark:shadow-none">
                            <h3 className="font-semibold text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2"><Clock className="w-4 h-4" /> Son Taramalar</h3>
                            <div className="flex flex-wrap gap-2">
                                {scanHistory.slice(0, 5).map(h => (
                                    <div key={h.id} className="px-3 py-1.5 bg-slate-100 dark:bg-slate-800 rounded-lg text-xs flex items-center gap-2">
                                        <span className={`w-2 h-2 rounded-full ${h.mode === 'real' ? 'bg-emerald-500' : 'bg-blue-500'}`} />
                                        <span className="text-slate-500 dark:text-slate-400">{new Date(h.timestamp).toLocaleTimeString()}</span>
                                        <span className="text-slate-700 dark:text-slate-300">{h.networkCount} AP</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                {/* Action Panel */}
                <div className="space-y-6">
                    {/* Upload Handshake */}
                    <div className="bg-white/80 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-lg dark:shadow-none">
                        <h3 className="font-semibold text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2"><Upload className="w-4 h-4" /> Handshake Yükle</h3>
                        <input ref={fileInputRef} type="file" accept=".cap,.pcap,.hccapx,.hc22000" onChange={handleFileUpload} className="hidden" />
                        <button onClick={() => fileInputRef.current?.click()} className="w-full py-3 border-2 border-dashed border-slate-300 dark:border-slate-700 hover:border-emerald-500 rounded-lg text-slate-500 dark:text-slate-400 hover:text-emerald-600 dark:hover:text-emerald-400 transition-all text-sm">
                            {uploadedFile ? `📁 ${uploadedFile.name}` : 'Dosya seç (.cap, .pcap, .hccapx)'}
                        </button>
                    </div>

                    {/* Target Actions */}
                    <div className="bg-white/80 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-6 shadow-lg dark:shadow-none">
                        <h2 className="font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-4">
                            <Terminal className="w-5 h-5 text-emerald-600 dark:text-emerald-400" /> Hedef İşlemleri
                        </h2>
                        {selectedNetwork ? (
                            <div className="space-y-4">
                                <div className="p-3 bg-slate-100 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-emerald-600 dark:text-emerald-400 font-mono font-bold truncate">{selectedNetwork.ssid}</div>
                                    <div className="text-slate-500 text-xs font-mono mt-1">{selectedNetwork.bssid}</div>
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                    <button onClick={() => handleAttack('Deauth')} className="p-3 bg-red-50 dark:bg-red-500/10 hover:bg-red-100 dark:hover:bg-red-500/20 border border-red-200 dark:border-red-500/30 text-red-600 dark:text-red-400 rounded-lg text-xs font-bold flex flex-col items-center gap-1">
                                        <AlertTriangle className="w-5 h-5" /> Deauth
                                    </button>
                                    <button onClick={() => handleAttack('Handshake')} className="p-3 bg-blue-50 dark:bg-blue-500/10 hover:bg-blue-100 dark:hover:bg-blue-500/20 border border-blue-200 dark:border-blue-500/30 text-blue-600 dark:text-blue-400 rounded-lg text-xs font-bold flex flex-col items-center gap-1">
                                        <Lock className="w-5 h-5" /> Capture HS
                                    </button>
                                </div>
                                <select value={crackStrategy} onChange={e => setCrackStrategy(e.target.value)} className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-sm text-slate-700 dark:text-slate-300">
                                    <option value="wordlist">Wordlist (rockyou.txt)</option>
                                    <option value="brute">Brute Force</option>
                                    <option value="pmkid">PMKID Attack</option>
                                </select>
                                <button onClick={startCracking} className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-bold shadow-lg shadow-emerald-500/20">
                                    Kırma Başlat
                                </button>
                            </div>
                        ) : (
                            <div className="text-center py-8 text-slate-500 text-sm border-2 border-dashed border-slate-300 dark:border-slate-800 rounded-xl">
                                Listeden ağ seçin
                            </div>
                        )}
                    </div>

                    {/* Crack Jobs */}
                    {crackJobs.length > 0 && (
                        <div className="bg-white/80 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-lg dark:shadow-none">
                            <h3 className="font-semibold text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2"><Zap className="w-4 h-4" /> Aktif İşlemler</h3>
                            <div className="space-y-3">
                                {crackJobs.slice(0, 3).map(job => (
                                    <div key={job.id} className="p-3 bg-slate-100 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="text-xs text-slate-700 dark:text-slate-300 font-mono truncate">{job.ssid}</span>
                                            <span className={`text-xs px-2 py-0.5 rounded ${job.status === 'completed' ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400' : job.status === 'running' ? 'bg-yellow-100 dark:bg-yellow-500/20 text-yellow-600 dark:text-yellow-400' : 'bg-red-100 dark:bg-red-500/20 text-red-600 dark:text-red-400'}`}>
                                                {job.status}
                                            </span>
                                        </div>
                                        <ProgressBar progress={Math.round(job.progress)} />
                                        {job.result && <div className="mt-2 text-xs text-emerald-600 dark:text-emerald-400 font-mono">🔑 {job.result}</div>}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Logs */}
                    <div className="bg-slate-900 dark:bg-black border border-slate-700 dark:border-slate-800 rounded-xl p-4 h-48 overflow-hidden flex flex-col shadow-lg">
                        <div className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2 flex items-center justify-between border-b border-slate-700 dark:border-slate-800 pb-2">
                            <span className="font-bold flex items-center gap-2"><Terminal className="w-3 h-3" /> Konsol</span>
                            <span className="flex items-center gap-1.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                                <span className="text-[10px]">CANLI</span>
                            </span>
                        </div>
                        <div className="flex-1 overflow-y-auto font-mono text-xs space-y-1">
                            {logs.length === 0 && <span className="text-slate-600 dark:text-slate-700 italic">Sistem hazır...</span>}
                            {logs.map((log, i) => (
                                <div key={i} className="text-emerald-400 dark:text-emerald-500/90 border-l-2 border-emerald-500/20 pl-2">{log}</div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Network Detail Modal */}
            <Modal isOpen={showNetworkDetail} onClose={() => setShowNetworkDetail(false)} title="Ağ Detayları">
                {selectedNetwork && (
                    <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg"><div className="text-xs text-slate-500 mb-1">SSID</div><div className="text-emerald-600 dark:text-emerald-400 font-mono">{selectedNetwork.ssid}</div></div>
                            <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg"><div className="text-xs text-slate-500 mb-1">BSSID</div><div className="text-slate-700 dark:text-slate-300 font-mono">{selectedNetwork.bssid}</div></div>
                            <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg"><div className="text-xs text-slate-500 mb-1">Güvenlik</div><div className="text-slate-700 dark:text-slate-300">{selectedNetwork.security}</div></div>
                            <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg"><div className="text-xs text-slate-500 mb-1">Kanal</div><div className="text-slate-700 dark:text-slate-300">{selectedNetwork.channel}</div></div>
                            <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg"><div className="text-xs text-slate-500 mb-1">Sinyal</div><div className="text-slate-700 dark:text-slate-300">{selectedNetwork.signal} dBm</div></div>
                            <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg"><div className="text-xs text-slate-500 mb-1">Üretici</div><div className="text-slate-700 dark:text-slate-300">{selectedNetwork.vendor || 'Bilinmiyor'}</div></div>
                        </div>
                    </div>
                )}
            </Modal>

            {/* Intro Modal */}
            <Modal isOpen={showIntro} onClose={() => setShowIntro(false)} title="Wi-Fi Sentinel - Kullanım Rehberi">
                <div className="space-y-6">
                    <div className="bg-gradient-to-r from-emerald-100 to-cyan-100 dark:from-emerald-900/20 dark:to-cyan-900/20 border border-emerald-300 dark:border-emerald-500/30 rounded-xl p-6">
                        <h4 className="text-lg font-bold text-emerald-600 dark:text-emerald-400 mb-3">🛡️ Modül Hakkında</h4>
                        <p className="text-sm text-slate-600 dark:text-slate-300">Wi-Fi Sentinel, kablosuz ağ güvenliği testleri için geliştirilmiş kapsamlı bir araçtır. WPA2/WPA3 protokollerindeki zafiyetleri tespit eder.</p>
                    </div>
                    <div className="bg-yellow-50 dark:bg-yellow-900/10 border border-yellow-300 dark:border-yellow-500/20 rounded-xl p-4 flex gap-4">
                        <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-500 shrink-0" />
                        <div>
                            <h4 className="font-bold text-yellow-600 dark:text-yellow-500 mb-1">Yasal Uyarı</h4>
                            <p className="text-xs text-yellow-700/80 dark:text-yellow-200/70">Bu araç sadece yetkili güvenlik testleri için kullanılmalıdır. İzinsiz kullanım yasaktır.</p>
                        </div>
                    </div>
                </div>
            </Modal>
        </div>
    );
}
