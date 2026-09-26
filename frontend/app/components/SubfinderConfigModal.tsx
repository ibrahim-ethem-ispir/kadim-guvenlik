import { useState, useEffect } from "react";
import { X, Save, Globe, Zap, Search, RefreshCw, CheckCircle2 } from "lucide-react";
import { api } from "../services/api";

interface SubfinderConfigModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSave: (options: any) => void;
    initialOptions: any;
}

// Popüler subdomain kaynakları
const POPULAR_SOURCES = [
    { id: "crtsh", name: "crt.sh", description: "Certificate Transparency logs" },
    { id: "hackertarget", name: "HackerTarget", description: "Subdomain enumeration API" },
    { id: "threatcrowd", name: "ThreatCrowd", description: "Threat intelligence" },
    { id: "dnsdumpster", name: "DNSDumpster", description: "DNS recon & research" },
    { id: "virustotal", name: "VirusTotal", description: "Domain analysis (API key gerekli)" },
    { id: "shodan", name: "Shodan", description: "Internet-wide scanning (API key gerekli)" },
    { id: "censys", name: "Censys", description: "Internet asset discovery" },
    { id: "bufferover", name: "BufferOver", description: "DNS enumeration" },
    { id: "chaos", name: "ProjectDiscovery Chaos", description: "PD public subdomain data" },
    { id: "alienvault", name: "AlienVault OTX", description: "Open Threat Exchange" },
];

export default function SubfinderConfigModal({ isOpen, onClose, onSave, initialOptions }: SubfinderConfigModalProps) {
    const [options, setOptions] = useState<any>(initialOptions || {
        sources: [],
        all_sources: false,
        recursive: false,
        timeout: 30,
        rate_limit: 0
    });

    const [availableSources, setAvailableSources] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (isOpen) {
            setLoading(true);
            api.get<any>('/api/subfinder/config')
                .then(data => {
                    if (data.available_sources) {
                        setAvailableSources(data.available_sources);
                    }
                })
                .catch(err => console.error('Subfinder config fetch error:', err))
                .finally(() => setLoading(false));
        }
    }, [isOpen]);

    if (!isOpen) return null;

    const handleSave = () => {
        onSave(options);
        onClose();
    };

    const toggleSource = (sourceId: string) => {
        const current = options.sources || [];
        if (current.includes(sourceId)) {
            setOptions({ ...options, sources: current.filter((s: string) => s !== sourceId) });
        } else {
            setOptions({ ...options, sources: [...current, sourceId] });
        }
    };

    return (
        <div className="fixed inset-0 !z-[9999] flex items-center justify-center bg-slate-950/40 backdrop-blur-md p-4 animate-in fade-in duration-300">
            <div className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl shadow-cyan-900/20 animate-in zoom-in-95 duration-200">

                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-10 rounded-t-2xl">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-cyan-500/10 rounded-xl border border-cyan-500/20 shadow-lg shadow-cyan-900/20">
                            <Globe className="w-6 h-6 text-cyan-500" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white tracking-tight">Subfinder Yapılandırması</h2>
                            <p className="text-sm text-slate-400">Subdomain keşif parametreleri</p>
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-all hover:rotate-90 duration-300"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar">

                    {/* Quick Options */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <button
                            onClick={() => setOptions({ ...options, all_sources: !options.all_sources })}
                            className={`group p-4 rounded-xl border text-left transition-all duration-300 ${options.all_sources
                                ? 'bg-cyan-500/10 border-cyan-500/50 shadow-lg shadow-cyan-900/10'
                                : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                                }`}
                        >
                            <div className="flex items-center gap-3">
                                <div className={`p-2 rounded-lg transition-colors ${options.all_sources ? 'bg-cyan-500/20' : 'bg-slate-800 group-hover:bg-slate-700'}`}>
                                    <Search className={`w-5 h-5 ${options.all_sources ? 'text-cyan-400' : 'text-slate-400'}`} />
                                </div>
                                <div className="flex-1">
                                    <div className={`font-semibold ${options.all_sources ? 'text-white' : 'text-slate-300'}`}>
                                        Tüm Kaynaklar
                                    </div>
                                    <p className="text-xs text-slate-500 mt-0.5">Mevcut tüm kaynakları kullan (yavaş)</p>
                                </div>
                                {options.all_sources && <CheckCircle2 className="w-5 h-5 text-cyan-400 ml-auto animate-in zoom-in duration-200" />}
                            </div>
                        </button>

                        <button
                            onClick={() => setOptions({ ...options, recursive: !options.recursive })}
                            className={`group p-4 rounded-xl border text-left transition-all duration-300 ${options.recursive
                                ? 'bg-cyan-500/10 border-cyan-500/50 shadow-lg shadow-cyan-900/10'
                                : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
                                }`}
                        >
                            <div className="flex items-center gap-3">
                                <div className={`p-2 rounded-lg transition-colors ${options.recursive ? 'bg-cyan-500/20' : 'bg-slate-800 group-hover:bg-slate-700'}`}>
                                    <RefreshCw className={`w-5 h-5 ${options.recursive ? 'text-cyan-400' : 'text-slate-400'}`} />
                                </div>
                                <div className="flex-1">
                                    <div className={`font-semibold ${options.recursive ? 'text-white' : 'text-slate-300'}`}>
                                        Recursive Keşif
                                    </div>
                                    <p className="text-xs text-slate-500 mt-0.5">Alt subdomain'leri de tara</p>
                                </div>
                                {options.recursive && <CheckCircle2 className="w-5 h-5 text-cyan-400 ml-auto animate-in zoom-in duration-200" />}
                            </div>
                        </button>
                    </div>

                    {/* Timeout ve Rate Limit */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                        <div className="space-y-2">
                            <label className="text-sm font-medium text-slate-300 ml-1">Timeout (saniye)</label>
                            <div className="relative">
                                <input
                                    type="number"
                                    value={options.timeout}
                                    onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) || 30 })}
                                    className="w-full bg-slate-900/50 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all placeholder-slate-600"
                                />
                                <div className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500 pointer-events-none">
                                    sn
                                </div>
                            </div>
                            <p className="text-xs text-slate-500 ml-1">İstek başına bekleme süresi (Varsayılan: 30)</p>
                        </div>
                        <div className="space-y-2">
                            <label className="text-sm font-medium text-slate-300 ml-1">Rate Limit</label>
                            <div className="relative">
                                <input
                                    type="number"
                                    value={options.rate_limit}
                                    onChange={(e) => setOptions({ ...options, rate_limit: parseInt(e.target.value) || 0 })}
                                    className="w-full bg-slate-900/50 border border-slate-800 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all placeholder-slate-600"
                                />
                                <div className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500 pointer-events-none">
                                    req/s
                                </div>
                            </div>
                            <p className="text-xs text-slate-500 ml-1">Saniyedeki istek sayısı (0 = Sınırsız)</p>
                        </div>
                    </div>

                    {/* Sources Selection */}
                    {!options.all_sources && (
                        <div className="space-y-4 pt-2">
                            <div className="flex items-center justify-between">
                                <label className="text-sm font-medium text-slate-300 border-l-2 border-cyan-500 pl-3">
                                    Kaynaklar (Opsiyonel)
                                </label>
                                {options.sources?.length > 0 && (
                                    <span className="text-xs font-bold px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded-full border border-cyan-500/20">
                                        {options.sources.length} seçili
                                    </span>
                                )}
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-60 overflow-y-auto pr-2 custom-scrollbar bg-slate-900/30 p-2 rounded-xl border border-slate-800/50">
                                {POPULAR_SOURCES.map((source) => (
                                    <button
                                        key={source.id}
                                        onClick={() => toggleSource(source.id)}
                                        className={`group p-3 rounded-lg border text-left transition-all ${options.sources?.includes(source.id)
                                            ? 'bg-cyan-500/10 border-cyan-500/50'
                                            : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-800'
                                            }`}
                                    >
                                        <div className="flex items-center justify-between mb-1">
                                            <span className={`text-sm font-medium ${options.sources?.includes(source.id) ? 'text-white' : 'text-slate-300'
                                                }`}>
                                                {source.name}
                                            </span>
                                            {options.sources?.includes(source.id) && (
                                                <CheckCircle2 className="w-4 h-4 text-cyan-400 animate-in zoom-in duration-200" />
                                            )}
                                        </div>
                                        <p className="text-[10px] text-slate-500 line-clamp-1 group-hover:text-slate-400 transition-colors">{source.description}</p>
                                    </button>
                                ))}
                            </div>
                            <p className="text-xs text-slate-500 pl-1">
                                * Seçim yapmazsanız varsayılan kaynaklar kullanılır.
                            </p>
                        </div>
                    )}

                    {/* Info Box */}
                    <div className="p-4 rounded-xl bg-gradient-to-br from-slate-900 to-slate-800/50 border border-slate-700/50 shadow-inner">
                        <div className="flex items-start gap-3">
                            <div className="p-2 bg-slate-800 rounded-lg shrink-0">
                                <Zap className="w-4 h-4 text-cyan-400" />
                            </div>
                            <div className="text-sm text-slate-400 leading-relaxed">
                                <p className="font-medium text-slate-300 mb-1">Nasıl Çalışır?</p>
                                <p>
                                    Subfinder, <strong>tamamen pasif</strong> kaynaklardan veri toplar. Hedef sunucuya
                                    doğrudan paket göndermez, bu sayede WAF veya IPS tarafından engellenmez.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Footer */}
                <div className="p-6 border-t border-slate-800 bg-slate-900/50 backdrop-blur-md rounded-b-2xl flex flex-col sm:flex-row justify-between items-center gap-4">
                    <div className="text-sm text-slate-500 font-medium hidden sm:block">
                        {options.all_sources
                            ? "🚀 Tüm kaynaklar aktif"
                            : options.sources?.length > 0
                                ? `✨ ${options.sources.length} özel kaynak`
                                : "⚡ Varsayılan konfigürasyon"
                        }
                    </div>
                    <div className="flex w-full sm:w-auto gap-3">
                        <button
                            onClick={onClose}
                            className="flex-1 sm:flex-none px-6 py-2.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-xl transition-colors font-medium border border-transparent hover:border-slate-700"
                        >
                            İptal
                        </button>
                        <button
                            onClick={handleSave}
                            className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-8 py-2.5 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white font-medium rounded-xl transition-all shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 transform hover:-translate-y-0.5 active:translate-y-0"
                        >
                            <Save className="w-4 h-4" />
                            Kaydet
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
