import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router';
import {
    Network,
    Shield,
    Activity,
    Clock,
    AlertTriangle,
    CheckCircle,
    Server,
    Globe,
    Cpu,
    Calendar,
    ArrowRight,
    Download
} from 'lucide-react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip as RechartsTooltip,
    ResponsiveContainer,
    AreaChart,
    Area,
    PieChart,
    Pie,
    Cell
} from 'recharts';
import { format } from 'date-fns';
import { TipBox, InfoCard } from '../../components/osint/ui-components';
import { generateOSINTReport } from '../../libs/report-generator';
import { api } from '../../services/api';

interface DomainProfile {
    target: string;
    first_seen: string | null;
    last_scanned: string | null;
    total_scans: number;
    scan_history: {
        scan_id: string;
        date: string;
        scan_types: string[];
        findings_count: number;
        risk_score: number;
    }[];
    entities: {
        subdomains: string[];
        ip_addresses: string[];
        open_ports: number[];
        technologies: string[];
        ssl_info: any;
        whois_data: any;
    };
    vulnerability_trend: {
        date: string;
        critical: number;
        high: number;
        medium: number;
        low: number;
    }[];
    risk_score: number;
    risk_factors: string[];
    services: {
        port: number;
        protocol: string;
        service: string;
        version: string;
        state: string;
    }[];
    // New Professional Stats
    geo_distribution: Record<string, number>;
    asn_info: {
        asn: string;
        org: string;
        count: number;
    }[];
    ssl_health: {
        issuer: string;
        valid_from: string;
        valid_until: string;
        days_left: number;
        is_valid: boolean;
        issues: string[];
    } | null;
}

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

export default function OsintInvestigate() {
    const [searchParams] = useSearchParams();
    const target = searchParams.get('target');
    const [loading, setLoading] = useState(false);
    const [profile, setProfile] = useState<DomainProfile | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (target) {
            fetchProfile(target);
        }
    }, [target]);

    const fetchProfile = async (targetVal: string) => {
        setLoading(true);
        setError(null);
        try {
            // Note: In production, ensure this points to Orchestrator API
            const data = await api.get<DomainProfile>(`/api/osint/profile/${targetVal}`);
            setProfile(data);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    if (!target) {
        return (
            <div className="flex items-center justify-center h-full text-slate-500 dark:text-slate-500">
                <p>Please enter a target in the search bar to view profile.</p>
            </div>
        );
    }

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center h-full gap-4">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
                <p className="text-slate-600 dark:text-slate-400">Analyzing target profile...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="p-8 text-center">
                <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
                <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">Analysis Failed</h2>
                <p className="text-red-500 dark:text-red-400">{error}</p>
                <button
                    onClick={() => fetchProfile(target)}
                    className="mt-4 px-4 py-2 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 rounded text-slate-900 dark:text-white"
                >
                    Retry
                </button>
            </div>
        );
    }

    if (!profile) return null;

    return (
        <div className="space-y-6 pb-12">
            {/* Header / Profile Summary */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <div className="bg-blue-500/10 p-2 rounded-lg">
                                <Globe className="w-6 h-6 text-blue-500 dark:text-blue-400" />
                            </div>
                            <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight">{profile.target}</h1>
                        </div>
                        <div className="flex flex-wrap gap-4 text-sm text-slate-600 dark:text-slate-400">
                            <span className="flex items-center gap-1">
                                <Calendar className="w-4 h-4" /> First Seen: {profile.first_seen ? format(new Date(profile.first_seen), 'MMM d, yyyy') : 'N/A'}
                            </span>
                            <span className="flex items-center gap-1">
                                <Clock className="w-4 h-4" /> Last Scan: {profile.last_scanned ? format(new Date(profile.last_scanned), 'MMM d, HH:mm') : 'N/A'}
                            </span>
                            <span className="flex items-center gap-1">
                                <Activity className="w-4 h-4" /> Total Scans: {profile.total_scans ?? 0}
                            </span>
                        </div>
                    </div>

                    <div className="flex items-center gap-6">
                        {/* Actions */}
                        <button
                            onClick={() => profile && generateOSINTReport(profile)}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm font-medium"
                        >
                            <Download className="w-4 h-4" />
                            Rapor Al
                        </button>

                        {/* Risk Score Card */}
                        <div className="flex flex-col items-end">
                            <span className="text-slate-600 dark:text-slate-400 text-sm mb-1">Risk Score</span>
                            <div className="flex items-center gap-3">
                                <div className="text-right">
                                    <div className={`text-4xl font-bold ${(profile.risk_score ?? 0) > 70 ? 'text-red-500' :
                                        (profile.risk_score ?? 0) > 40 ? 'text-orange-500' : 'text-green-500'
                                        }`}>
                                        {profile.risk_score ?? 0}
                                    </div>
                                    <div className="text-xs text-slate-500 font-medium">/ 100</div>
                                </div>
                                <div className="h-16 w-2 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                                    <div
                                        className={`w-full transition-all duration-1000 ${(profile.risk_score ?? 0) > 70 ? 'bg-red-500' :
                                            (profile.risk_score ?? 0) > 40 ? 'bg-orange-500' : 'bg-green-500'
                                            }`}
                                        style={{ height: `${profile.risk_score ?? 0}%`, marginTop: `${100 - (profile.risk_score ?? 0)}%` }}
                                    ></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left Column: Stats & Trends */}
                <div className="col-span-1 lg:col-span-2 space-y-6">

                    {/* Vulnerability Trend Chart */}
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6">
                        <h3 className="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
                            <Activity className="w-5 h-5 text-blue-500 dark:text-blue-400" /> Vulnerability Trend
                        </h3>
                        <div className="h-[300px] w-full">
                            {(profile.vulnerability_trend || []).length > 0 ? (
                                <ResponsiveContainer width="100%" height="100%">
                                    <AreaChart data={profile.vulnerability_trend || []}>
                                        <defs>
                                            <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                                                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                                            </linearGradient>
                                        </defs>
                                        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" className="dark:stroke-slate-800" />
                                        <XAxis dataKey="date" stroke="#64748b" fontSize={12} tickFormatter={(str) => format(new Date(str), 'MM/dd')} />
                                        <YAxis stroke="#64748b" fontSize={12} />
                                        <RechartsTooltip
                                            contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }}
                                            itemStyle={{ color: '#e2e8f0' }}
                                        />
                                        <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="url(#colorCritical)" />
                                        <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" />
                                        <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" />
                                    </AreaChart>
                                </ResponsiveContainer>
                            ) : (
                                <div className="h-full flex items-center justify-center text-slate-500 bg-slate-100 dark:bg-slate-950/50 rounded-lg">
                                    No historical data available yet.
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Entities Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6">
                            <h3 className="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
                                <Globe className="w-5 h-5 text-indigo-500 dark:text-indigo-400" /> Subdomains
                                <span className="bg-slate-200 dark:bg-slate-800 text-xs px-2 py-0.5 rounded ml-auto text-slate-600 dark:text-slate-400">{(profile.entities?.subdomains || []).length}</span>
                            </h3>
                            <div className="h-[200px] overflow-y-auto space-y-2 pr-2 custom-scrollbar">
                                {(profile.entities?.subdomains || []).length > 0 ? (
                                    (profile.entities?.subdomains || []).map((sub, i) => (
                                        <div key={i} className="bg-slate-100 dark:bg-slate-950/50 p-2 rounded text-sm text-slate-700 dark:text-slate-300 font-mono flex items-center justify-between group">
                                            {sub}
                                            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 text-slate-500" />
                                        </div>
                                    ))
                                ) : (
                                    <div className="text-center text-slate-500 pt-8">No subdomains found.</div>
                                )}
                            </div>
                        </div>

                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6">
                            <h3 className="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
                                <Cpu className="w-5 h-5 text-emerald-500 dark:text-emerald-400" /> Technologies
                                <span className="bg-slate-200 dark:bg-slate-800 text-xs px-2 py-0.5 rounded ml-auto text-slate-600 dark:text-slate-400">{(profile.entities?.technologies || []).length}</span>
                            </h3>
                            <div className="flex flex-wrap gap-2">
                                {(profile.entities?.technologies || []).length > 0 ? (
                                    (profile.entities?.technologies || []).map((tech, i) => (
                                        <span key={i} className="px-2 py-1 bg-emerald-100 dark:bg-emerald-950/30 border border-emerald-300 dark:border-emerald-900/50 text-emerald-600 dark:text-emerald-400 text-xs rounded-md">
                                            {tech}
                                        </span>
                                    ))
                                ) : (
                                    <div className="text-center text-slate-500 w-full pt-8">No technologies detected.</div>
                                )}
                            </div>
                        </div>
                    </div>

                </div>

                {/* Right Column: Timeline & Meta */}
                <div className="space-y-6">
                    {/* Scan History Timeline */}
                    <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 rounded-xl p-6">
                        <h3 className="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
                            <Clock className="w-5 h-5 text-slate-500 dark:text-slate-400" /> Scan History
                        </h3>
                        <div className="relative pl-4 space-y-6 border-l border-slate-300 dark:border-slate-800">
                            {(profile.scan_history || []).map((scan, i) => (
                                <div key={i} className="relative group">
                                    <div className="absolute -left-[21px] w-3 h-3 rounded-full bg-slate-200 dark:bg-slate-800 border border-slate-400 dark:border-slate-600 group-hover:bg-blue-500 group-hover:border-blue-400 transition-colors"></div>
                                    <div className="flex flex-col gap-1">
                                        <span className="text-xs text-slate-500">{format(new Date(scan.date), 'MMM d, HH:mm')}</span>
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                                                {(scan.scan_types || []).join(', ').toUpperCase()} Scan
                                            </span>
                                            {(scan.risk_score ?? 0) > 0 &&
                                                <span className={`text-xs px-1.5 rounded ${(scan.risk_score ?? 0) > 50 ? 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' : 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400'
                                                    }`}>
                                                    Risk: {scan.risk_score}
                                                </span>
                                            }
                                        </div>
                                        {(scan.findings_count ?? 0) > 0 && <span className="text-xs text-orange-500 dark:text-orange-400">{scan.findings_count} Findings</span>}
                                    </div>
                                </div>
                            ))}
                            {(profile.scan_history || []).length === 0 && (
                                <div className="text-sm text-slate-500 italic px-2">No scan history</div>
                            )}
                        </div>
                    </div>

                    {/* SSL Health Card (Professional) */}
                    {profile.ssl_health && (
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6">
                            <h3 className="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
                                <Shield className="w-5 h-5 text-emerald-500 dark:text-emerald-400" /> SSL Certificate
                            </h3>
                            <div className="space-y-3">
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-600 dark:text-slate-400 text-sm">Status</span>
                                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${profile.ssl_health.is_valid ? 'bg-emerald-100 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400' : 'bg-red-100 dark:bg-red-950/50 text-red-600 dark:text-red-400'}`}>
                                        {profile.ssl_health.is_valid ? 'Valid' : 'Invalid'}
                                    </span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-600 dark:text-slate-400 text-sm">Issuer</span>
                                    <span className="text-slate-800 dark:text-slate-200 text-sm truncate max-w-[150px]">{profile.ssl_health.issuer}</span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-slate-600 dark:text-slate-400 text-sm">Expires In</span>
                                    <span className={`text-sm ${profile.ssl_health.days_left < 30 ? 'text-orange-500 dark:text-orange-400' : 'text-slate-800 dark:text-slate-200'}`}>
                                        {profile.ssl_health.days_left} days
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* ASN / Network Info (Professional) */}
                    {profile.asn_info && profile.asn_info.length > 0 && (
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6">
                            <h3 className="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
                                <Network className="w-5 h-5 text-blue-500 dark:text-blue-400" /> Network / ASN
                            </h3>
                            <div className="space-y-2">
                                {profile.asn_info.map((asn, i) => (
                                    <div key={i} className="flex justify-between items-start text-sm border-b border-slate-200 dark:border-slate-800 pb-2 last:border-0">
                                        <div>
                                            <div className="text-slate-800 dark:text-slate-200 font-medium">{asn.asn}</div>
                                            <div className="text-slate-500 text-xs">{asn.org}</div>
                                        </div>
                                        <div className="bg-slate-200 dark:bg-slate-800 px-2 py-1 rounded text-xs text-slate-600 dark:text-slate-400">
                                            {asn.count} IPs
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    <InfoCard
                        label="Infrastructure"
                        value={`${(profile.entities?.ip_addresses || []).length} IPs`}
                        icon={Server}
                        subtext="Discovered Assets"
                    />

                    <TipBox title="Analysis Tip" variant="tip">
                        Run a <strong>Nuclei Scan</strong> with "Critical" severity filter to prioritize high-risk vulnerabilities on newly discovered subdomains.
                    </TipBox>
                </div>

                {/* Network Services Table (Full Width) */}
                <div className="col-span-1 lg:col-span-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6">
                    <h3 className="text-lg font-semibold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2">
                        <Server className="w-5 h-5 text-emerald-500 dark:text-emerald-400" /> Network Services
                    </h3>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 text-sm">
                                    <th className="pb-3 pl-2">Port</th>
                                    <th className="pb-3">Protocol</th>
                                    <th className="pb-3">Service</th>
                                    <th className="pb-3">Version</th>
                                    <th className="pb-3">State</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                {(profile.services || []).length > 0 ? (
                                    (profile.services || []).map((svc, i) => (
                                        <tr key={i} className="text-slate-700 dark:text-slate-300 text-sm hover:bg-slate-100 dark:hover:bg-slate-800/50 transition-colors">
                                            <td className="py-3 pl-2 font-mono text-emerald-600 dark:text-emerald-400">{svc.port}</td>
                                            <td className="py-3 uppercase text-xs text-slate-500">{svc.protocol}</td>
                                            <td className="py-3 font-medium text-slate-800 dark:text-slate-200">{svc.service}</td>
                                            <td className="py-3 text-slate-500">{svc.version || '-'}</td>
                                            <td className="py-3">
                                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${svc.state === 'open' ? 'bg-emerald-100 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-900/50' :
                                                    svc.state === 'closed' ? 'bg-red-100 dark:bg-red-950/50 text-red-600 dark:text-red-400 border border-red-300 dark:border-red-900/50' :
                                                        'bg-yellow-100 dark:bg-yellow-950/50 text-yellow-600 dark:text-yellow-400 border border-yellow-300 dark:border-yellow-900/50'
                                                    }`}>
                                                    {svc.state?.toUpperCase() || 'UNKNOWN'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan={5} className="text-center text-slate-500 py-8">
                                            No open ports or services detected yet.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
}
