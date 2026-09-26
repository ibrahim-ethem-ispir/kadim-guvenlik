import React from 'react';
import { useNavigate } from 'react-router';
import { Search, Globe, Shield, Server, Activity, ArrowRight, Database, X, Loader2, Lock, Mail, FileText, ChevronDown } from 'lucide-react';
import { TipBox, InfoCard } from '../../components/osint/ui-components';
import { api } from '../../services/api';

// Types for quick lookup responses
interface DnsRecord {
    type: string;
    value: string;
    ttl?: number;
}

interface WhoisData {
    domain: string;
    registrar: string | null;
    created_date: string | null;
    expiry_date: string | null;
    updated_date: string | null;
    name_servers: string[];
    status: string[];
}

interface SslData {
    host: string;
    issuer: string;
    subject: string;
    not_before: string;
    not_after: string;
    valid: boolean;
    days_left: number;
}

type QuickTool = 'dns' | 'whois' | 'ssl' | null;

export default function OsintDashboard() {
    const navigate = useNavigate();
    const [target, setTarget] = React.useState("");

    // Quick Tool States
    const [activeTool, setActiveTool] = React.useState<QuickTool>(null);
    const [toolInput, setToolInput] = React.useState("");
    const [toolLoading, setToolLoading] = React.useState(false);
    const [toolError, setToolError] = React.useState<string | null>(null);
    const [dnsResult, setDnsResult] = React.useState<DnsRecord[] | null>(null);
    const [whoisResult, setWhoisResult] = React.useState<WhoisData | null>(null);
    const [sslResult, setSslResult] = React.useState<SslData | null>(null);

    const [stats, setStats] = React.useState<{
        scans24h: number;
        totalEntities: number | string;
        trackedDomains: number;
        vulnerabilities: number;
    }>({
        scans24h: 0,
        totalEntities: 0,
        trackedDomains: 0,
        vulnerabilities: 0
    });

    React.useEffect(() => {
        const fetchStats = async () => {
            try {
                const data = await api.get<any>('/api/stats');
                setStats({
                    scans24h: data.daily_stats?.length || 0,
                    totalEntities: data.services_health?.mongodb?.status === 'healthy' ? 'Active' : 'Offline',
                    trackedDomains: data.total_scans || 0,
                    vulnerabilities: data.vulnerabilities_found || 0
                });
            } catch (e) {
                console.error("Stats fetch error", e);
            }
        };
        fetchStats();
    }, []);

    const handleSearch = (e: React.FormEvent) => {
        e.preventDefault();
        if (target) {
            navigate(`/osint/investigate?target=${encodeURIComponent(target)}`);
        }
    };

    const handleToolClick = (tool: QuickTool) => {
        if (activeTool === tool) {
            setActiveTool(null);
        } else {
            setActiveTool(tool);
            setToolError(null);
            // Reset results when switching tools
            setDnsResult(null);
            setWhoisResult(null);
            setSslResult(null);
        }
    };

    const runQuickLookup = async () => {
        if (!toolInput.trim() || !activeTool) return;

        setToolLoading(true);
        setToolError(null);

        try {
            if (activeTool === 'dns') {
                const res = await api.post<any>('/api/osint/lookup/dns', { domain: toolInput.trim() });
                if (res.success && res.data) {
                    setDnsResult(res.data.records || []);
                } else {
                    setToolError(res.error || 'DNS sorgusu başarısız');
                }
            } else if (activeTool === 'whois') {
                const res = await api.post<any>('/api/osint/lookup/whois', { domain: toolInput.trim() });
                if (res.success && res.data) {
                    setWhoisResult(res.data);
                } else {
                    setToolError(res.error || 'WHOIS sorgusu başarısız');
                }
            } else if (activeTool === 'ssl') {
                const res = await api.post<any>('/api/osint/lookup/ssl', { host: toolInput.trim(), port: 443 });
                if (res.success && res.data) {
                    setSslResult(res.data);
                } else {
                    setToolError(res.error || 'SSL sorgusu başarısız');
                }
            }
        } catch (e: any) {
            setToolError(e.message || 'Sorgu sırasında hata oluştu');
        } finally {
            setToolLoading(false);
        }
    };

    const tools = [
        { id: 'dns' as QuickTool, label: 'Quick DNS Lookup', icon: Globe, description: 'A, MX, NS, TXT kayıtları' },
        { id: 'whois' as QuickTool, label: 'WHOIS Check', icon: FileText, description: 'Domain kayıt bilgileri' },
        { id: 'ssl' as QuickTool, label: 'SSL Analyzer', icon: Lock, description: 'Sertifika geçerliliği' },
    ];

    return (
        <div className="space-y-8">
            {/* Hero Section */}
            <div className="text-center py-12 px-4 relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-100 via-slate-50 to-blue-50 dark:from-slate-900 dark:via-slate-900 dark:to-blue-950 border border-slate-200 dark:border-slate-800">
                <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20"></div>
                <div className="relative z-10 max-w-2xl mx-auto">
                    <h2 className="text-4xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-slate-900 to-slate-600 dark:from-white dark:to-slate-400">
                        Intelligence Gathering
                    </h2>
                    <p className="text-slate-600 dark:text-slate-400 mb-8 text-lg">
                        Reconnaissance platform for domains, IP addresses, and digital footprints.
                        Uncover hidden relationships and infrastructure.
                    </p>

                    <form onSubmit={handleSearch} className="relative max-w-lg mx-auto">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <Search className="h-5 w-5 text-slate-500" />
                        </div>
                        <input
                            type="text"
                            className="block w-full pl-10 pr-24 py-4 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-xl"
                            placeholder="Enter domain, IP, or email..."
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                        />
                        <button
                            type="submit"
                            className="absolute inset-y-2 right-2 px-4 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                        >
                            Analyze <ArrowRight className="w-4 h-4" />
                        </button>
                    </form>

                    <div className="mt-4 flex flex-wrap justify-center gap-2 text-xs text-slate-500">
                        <span className="bg-slate-200 dark:bg-slate-800/50 px-2 py-1 rounded">domain.com</span>
                        <span className="bg-slate-200 dark:bg-slate-800/50 px-2 py-1 rounded">1.2.3.4</span>
                        <span className="bg-slate-200 dark:bg-slate-800/50 px-2 py-1 rounded">email@example.com</span>
                    </div>
                </div>
            </div>

            {/* Info Boxes */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <TipBox title="What is OSINT?" variant="info">
                    Open Source Intelligence (OSINT) is the practice of collecting and analyzing information
                    from publicly available sources. Kadim OSINT automates this process to build a
                    comprehensive map of your target's digital assets.
                </TipBox>
                <TipBox title="Modules Available" variant="tip">
                    Currently active modules: <strong>DNS Intelligence</strong> (A, MX, NS, TXT),
                    <strong>WHOIS Lookup</strong> (Registrar info),
                    and <strong>Subdomain Discovery</strong> (Brute-force).
                    More modules like IP Intelligence coming in Phase 2.
                </TipBox>
            </div>

            {/* Stats Grid */}
            <div>
                <h3 className="text-xl font-semibold mb-4 flex items-center gap-2 text-slate-900 dark:text-white">
                    <Activity className="w-5 h-5 text-blue-400" />
                    Platform Activity
                </h3>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    <InfoCard
                        label="Scans (24h)"
                        value={stats.scans24h}
                        icon={Search}
                        subtext="+3 from yesterday"
                    />
                    <InfoCard
                        label="Total Entities"
                        value={stats.totalEntities}
                        icon={Database}
                        subtext="Across all investigations"
                    />
                    <InfoCard
                        label="Tracked Domains"
                        value={stats.trackedDomains}
                        icon={Globe}
                        subtext="Monitoring active"
                    />
                    <InfoCard
                        label="Critical Findings"
                        value={stats.vulnerabilities}
                        icon={Shield}
                        subtext="Requires attention"
                    />
                </div>
            </div>

            {/* Quick Tools Grid */}
            <div className="space-y-4">
                <h3 className="text-xl font-semibold flex items-center gap-2 text-slate-900 dark:text-white">
                    <Server className="w-5 h-5 text-emerald-400" />
                    Quick Tools
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {tools.map((tool) => (
                        <button
                            key={tool.id}
                            onClick={() => handleToolClick(tool.id)}
                            className={`bg-white dark:bg-slate-900 border p-4 rounded-lg flex items-center justify-between transition-all group text-left w-full ${activeTool === tool.id
                                    ? 'border-blue-500 ring-2 ring-blue-500/20'
                                    : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800'
                                }`}
                        >
                            <div className="flex items-center gap-3">
                                <div className={`p-2 rounded-lg ${activeTool === tool.id ? 'bg-blue-500/10' : 'bg-slate-100 dark:bg-slate-800'}`}>
                                    <tool.icon className={`w-5 h-5 ${activeTool === tool.id ? 'text-blue-500' : 'text-slate-500 dark:text-slate-400'}`} />
                                </div>
                                <div>
                                    <span className="font-medium text-slate-900 dark:text-white block">{tool.label}</span>
                                    <span className="text-xs text-slate-500">{tool.description}</span>
                                </div>
                            </div>
                            <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform ${activeTool === tool.id ? 'rotate-180' : ''}`} />
                        </button>
                    ))}
                </div>

                {/* Expandable Tool Panel */}
                {activeTool && (
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 animate-in slide-in-from-top-4 duration-300">
                        <div className="flex items-center justify-between mb-4">
                            <h4 className="text-lg font-semibold text-slate-900 dark:text-white">
                                {activeTool === 'dns' && 'DNS Lookup'}
                                {activeTool === 'whois' && 'WHOIS Lookup'}
                                {activeTool === 'ssl' && 'SSL Certificate Check'}
                            </h4>
                            <button onClick={() => setActiveTool(null)} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded">
                                <X className="w-5 h-5 text-slate-500" />
                            </button>
                        </div>

                        <div className="flex gap-3 mb-4">
                            <input
                                type="text"
                                value={toolInput}
                                onChange={(e) => setToolInput(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && runQuickLookup()}
                                placeholder={activeTool === 'ssl' ? 'Hostname girin (örn: example.com)' : 'Domain girin (örn: example.com)'}
                                className="flex-1 px-4 py-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            />
                            <button
                                onClick={runQuickLookup}
                                disabled={toolLoading || !toolInput.trim()}
                                className="px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-300 dark:disabled:bg-slate-700 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                            >
                                {toolLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                                Sorgula
                            </button>
                        </div>

                        {toolError && (
                            <div className="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 rounded-lg text-red-600 dark:text-red-400 text-sm mb-4">
                                {toolError}
                            </div>
                        )}

                        {/* DNS Results */}
                        {activeTool === 'dns' && dnsResult && (
                            <div className="space-y-2">
                                <div className="text-sm font-medium text-slate-600 dark:text-slate-400 mb-2">
                                    {dnsResult.length} kayıt bulundu
                                </div>
                                <div className="max-h-64 overflow-y-auto space-y-2">
                                    {dnsResult.map((record, i) => (
                                        <div key={i} className="flex items-center gap-3 p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                            <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 text-xs font-mono rounded">{record.type}</span>
                                            <span className="text-slate-700 dark:text-slate-300 font-mono text-sm flex-1 truncate">{record.value}</span>
                                            {record.ttl && <span className="text-xs text-slate-400">TTL: {record.ttl}</span>}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* WHOIS Results */}
                        {activeTool === 'whois' && whoisResult && (
                            <div className="grid grid-cols-2 gap-4">
                                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-xs text-slate-500 mb-1">Domain</div>
                                    <div className="text-slate-900 dark:text-white font-medium">{whoisResult.domain}</div>
                                </div>
                                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-xs text-slate-500 mb-1">Registrar</div>
                                    <div className="text-slate-900 dark:text-white font-medium">{whoisResult.registrar || 'N/A'}</div>
                                </div>
                                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-xs text-slate-500 mb-1">Kayıt Tarihi</div>
                                    <div className="text-slate-900 dark:text-white font-medium">{whoisResult.created_date || 'N/A'}</div>
                                </div>
                                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                    <div className="text-xs text-slate-500 mb-1">Bitiş Tarihi</div>
                                    <div className="text-slate-900 dark:text-white font-medium">{whoisResult.expiry_date || 'N/A'}</div>
                                </div>
                                {whoisResult.name_servers?.length > 0 && (
                                    <div className="col-span-2 p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                        <div className="text-xs text-slate-500 mb-2">Name Servers</div>
                                        <div className="flex flex-wrap gap-2">
                                            {whoisResult.name_servers.map((ns, i) => (
                                                <span key={i} className="px-2 py-1 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-mono rounded">{ns}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* SSL Results */}
                        {activeTool === 'ssl' && sslResult && (
                            <div className="space-y-4">
                                <div className="flex items-center gap-3 p-4 rounded-lg border ${sslResult.valid ? 'bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-900' : 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900'}">
                                    <div className={`p-2 rounded-full ${sslResult.valid ? 'bg-emerald-100 dark:bg-emerald-900/50' : 'bg-red-100 dark:bg-red-900/50'}`}>
                                        {sslResult.valid ? (
                                            <Shield className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
                                        ) : (
                                            <X className="w-6 h-6 text-red-600 dark:text-red-400" />
                                        )}
                                    </div>
                                    <div>
                                        <div className={`font-semibold ${sslResult.valid ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                                            {sslResult.valid ? 'Sertifika Geçerli' : 'Sertifika Geçersiz'}
                                        </div>
                                        <div className="text-sm text-slate-500">{sslResult.days_left} gün kaldı</div>
                                    </div>
                                </div>
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                        <div className="text-xs text-slate-500 mb-1">Issuer</div>
                                        <div className="text-slate-900 dark:text-white font-medium text-sm truncate">{sslResult.issuer}</div>
                                    </div>
                                    <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                        <div className="text-xs text-slate-500 mb-1">Subject</div>
                                        <div className="text-slate-900 dark:text-white font-medium text-sm truncate">{sslResult.subject}</div>
                                    </div>
                                    <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                        <div className="text-xs text-slate-500 mb-1">Başlangıç</div>
                                        <div className="text-slate-900 dark:text-white font-medium text-sm">{sslResult.not_before}</div>
                                    </div>
                                    <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                                        <div className="text-xs text-slate-500 mb-1">Bitiş</div>
                                        <div className="text-slate-900 dark:text-white font-medium text-sm">{sslResult.not_after}</div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
