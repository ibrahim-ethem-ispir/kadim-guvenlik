import {
    Bug,
    AlertTriangle,
    Shield,
    Filter,
    Download,
    Eye,
    ExternalLink,
    RefreshCw,
    Target,
    Calendar,
    ChevronDown
} from 'lucide-react';
import { Fragment, useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { api } from '../services/api';
import AIAnalysisPanel from '../components/AIAnalysisPanel';
// Kademe rozeti ortak bileşeni (FAQ 4.1) — TIER_STYLE ikiz kopyası buraya göçtü.
import TierBadge from '../components/TierBadge';

interface Vulnerability {
    scan_id: string;
    target: string;
    template_id: string;
    name: string;
    severity: string;
    matched_at: string;
    discovered_at: string;
    // KANIT — otonom bulgularda (js_secret/cve_intel/pathprobe) en eyleme-dönüşür alan.
    proof?: string | null;
    tool?: string | null;
    cve?: string | null;
    // FALSE-POSITIVE ekseni — kanıt güç kademesi (severity'den bağımsız).
    confidence_tier?: string;
    verified?: boolean | null;
    verification_confidence?: number | null;
    fp_reason?: string | null;
    llm_fp_opinion?: { verdict?: string; confidence?: number | null; reason?: string } | null;
}

const FP_REASON_LABEL: Record<string, string> = {
    waf_block: '🛡️ WAF engel', auth_wall: '🔒 Giriş duvarı', generic_error: '❓ Genel hata',
    maintenance: '🚧 Bakım', empty: '␀ Boş yanıt', catchall_host: '🌀 Catch-all host',
};

// Tier-farkında MANŞET sayımları — backend'in TEK doğruluk kaynağı (aggregate, sayfalanan
// pencere DEĞİL). Kart sayıları bunu okur ki auto-scan özetiyle ("2 kanıtlı kritik") birebir
// aynı olsun. Alanlar opsiyonel: eski backend stats göndermezse client-side fallback devreye girer.
interface VulnStats {
    severity_counts?: Record<string, number>;
    confirmed_severity_counts?: Record<string, number>;
    tier_counts?: { confirmed?: number; probable?: number; unconfirmed?: number };
}

interface VulnsResponse {
    vulnerabilities: Vulnerability[];
    total: number;
    stats?: VulnStats;
}

export default function Vulnerabilities() {
    const [vulns, setVulns] = useState<Vulnerability[]>([]);
    const [total, setTotal] = useState(0);
    const [stats, setStats] = useState<VulnStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [severityFilter, setSeverityFilter] = useState<string>('');
    const [tierFilter, setTierFilter] = useState<string>('');
    const [limit, setLimit] = useState(50);
    // Kanıt/kanıt-detail satırını aç-kapa (index bazlı); proof varsa satır tıklanabilir.
    const [expanded, setExpanded] = useState<number | null>(null);
    // TEK-TARAMA scope'u: ?scan_id=... ile gelinirse liste O taramaya daralır → auto-scan
    // özet kartıyla AYNI kümeyi gösterir ("2 kritik dedi ama listede yok" tutarsızlığını bitirir).
    const [searchParams] = useSearchParams();
    const scanId = searchParams.get('scan_id') || '';

    useEffect(() => {
        fetchVulns();
    }, [severityFilter, tierFilter, limit, scanId]);

    const fetchVulns = async () => {
        setLoading(true);
        try {
            let url = `/api/vulnerabilities?limit=${limit}`;
            if (scanId) {
                url += `&scan_id=${encodeURIComponent(scanId)}`;
            }
            if (severityFilter) {
                url += `&severity=${severityFilter}`;
            }
            if (tierFilter) {
                url += `&confidence_tier=${tierFilter}`;
            }
            const data = await api.get<VulnsResponse>(url);
            setVulns(data.vulnerabilities);
            setTotal(data.total);
            setStats(data.stats ?? null);
        } catch (err) {
            console.error("Failed to fetch vulnerabilities", err);
        } finally {
            setLoading(false);
        }
    };

    const getSeverityBadge = (severity: string) => {
        const styles: Record<string, string> = {
            critical: 'bg-red-100 dark:bg-red-600/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-500/30 ring-1 ring-red-500/50',
            high: 'bg-orange-100 dark:bg-orange-500/20 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-500/30',
            medium: 'bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30',
            low: 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-500/30',
            info: 'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-500/30',
            unknown: 'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-500/30',
        };
        const icons: Record<string, any> = {
            critical: AlertTriangle,
            high: AlertTriangle,
            medium: Shield,
            low: Shield,
            info: Bug,
            unknown: Bug,
        };
        const labels: Record<string, string> = {
            critical: 'Kritik',
            high: 'Yüksek',
            medium: 'Orta',
            low: 'Düşük',
            info: 'Bilgi',
            unknown: 'Bilinmiyor',
        };

        const Icon = icons[severity] || Bug;

        return (
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${styles[severity] || styles.unknown}`}>
                <Icon className="w-3 h-3" />
                {labels[severity] || severity}
            </span>
        );
    };

    const formatDate = (dateStr: string) => {
        if (!dateStr) return '-';
        const date = new Date(dateStr);
        return date.toLocaleString('tr-TR', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    // MANŞET SAYIMLARI — tier-farkında ve OTORİTER (backend aggregate; sayfalanan pencere değil).
    // Kritik/Yüksek yalnız confirmed+probable sayar (unconfirmed = "incelenecek" kovası) →
    // motorun confirmed_critical_count'u ile AYNI kural. Böylece "sürü ifşa ama teyit yok"
    // yerine "2 kanıtlı kritik, N incelenecek" dürüst tablosu çıkar; auto-scan kartıyla tutar.
    // FALLBACK: backend stats göndermezse getirilen satırlardan hesapla (eski davranış, kırılmaz).
    const confirmedSev = stats?.confirmed_severity_counts;
    const allSev = stats?.severity_counts;
    const criticalCount = confirmedSev
        ? (confirmedSev.critical ?? 0)
        : vulns.filter(v => v.severity === 'critical' && v.confidence_tier !== 'unconfirmed').length;
    const highCount = confirmedSev
        ? (confirmedSev.high ?? 0)
        : vulns.filter(v => v.severity === 'high' && v.confidence_tier !== 'unconfirmed').length;
    const mediumCount = allSev
        ? (allSev.medium ?? 0)
        : vulns.filter(v => v.severity === 'medium').length;
    // İncelenecek: doğrulanmamış (olası FP) — manşeti şişirmez, ayrı kovada görünür.
    const reviewCount = stats?.tier_counts?.unconfirmed
        ?? vulns.filter(v => (v.confidence_tier ?? 'unconfirmed') === 'unconfirmed').length;

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h1 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <Bug className="w-6 h-6 md:w-7 md:h-7 text-red-500" />
                        Bulunan Zafiyetler
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1 text-sm md:text-base">Nuclei taramalarından tespit edilen güvenlik açıkları.</p>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-sm text-slate-500">Toplam: {total} zafiyet</span>
                    <button
                        onClick={fetchVulns}
                        className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                        title="Yenile"
                    >
                        <RefreshCw className={`w-4 h-4 text-slate-500 dark:text-slate-400 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 md:gap-4">
                <div className="bg-red-50 dark:bg-red-950/30 border border-red-100 dark:border-red-900/50 rounded-xl p-3 md:p-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-red-600 dark:text-red-400 text-xs md:text-sm font-medium">Kanıtlı Kritik</p>
                            <p className="text-2xl md:text-3xl font-bold text-red-700 dark:text-red-300">{criticalCount}</p>
                        </div>
                        <AlertTriangle className="w-6 h-6 md:w-8 md:h-8 text-red-500/50" />
                    </div>
                </div>
                <div className="bg-orange-50 dark:bg-orange-950/30 border border-orange-100 dark:border-orange-900/50 rounded-xl p-3 md:p-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-orange-600 dark:text-orange-400 text-xs md:text-sm font-medium">Kanıtlı Yüksek</p>
                            <p className="text-2xl md:text-3xl font-bold text-orange-700 dark:text-orange-300">{highCount}</p>
                        </div>
                        <AlertTriangle className="w-6 h-6 md:w-8 md:h-8 text-orange-500/50" />
                    </div>
                </div>
                <div className="bg-amber-50 dark:bg-amber-950/30 border border-amber-100 dark:border-amber-900/50 rounded-xl p-3 md:p-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-amber-600 dark:text-amber-400 text-xs md:text-sm font-medium">Orta</p>
                            <p className="text-2xl md:text-3xl font-bold text-amber-700 dark:text-amber-300">{mediumCount}</p>
                        </div>
                        <Shield className="w-6 h-6 md:w-8 md:h-8 text-amber-500/50" />
                    </div>
                </div>
                {/* İNCELENECEK: doğrulanmamış bulgular (olası FP). Ayrı kova — manşeti şişirmez,
                    ama gizlenmez ("sürü ifşa" hissini dürüstçe açıklar: bunlar kanıtlanmadı). */}
                <div className="bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-700/60 rounded-xl p-3 md:p-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-slate-500 dark:text-slate-400 text-xs md:text-sm font-medium">İncelenecek</p>
                            <p className="text-2xl md:text-3xl font-bold text-slate-700 dark:text-slate-300">{reviewCount}</p>
                            <p className="text-[10px] md:text-xs text-slate-400 dark:text-slate-500 mt-0.5">doğrulanmadı · olası FP</p>
                        </div>
                        <Eye className="w-6 h-6 md:w-8 md:h-8 text-slate-400/50" />
                    </div>
                </div>
            </div>

            {/* Filters */}
            <div className="flex flex-wrap items-center gap-4 p-4 bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm dark:shadow-none">
                <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-slate-500" />
                    <select
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:border-red-500 transition-colors"
                    >
                        <option value="">Tüm Seviyeler</option>
                        <option value="critical">Kritik</option>
                        <option value="high">Yüksek</option>
                        <option value="medium">Orta</option>
                        <option value="low">Düşük</option>
                        <option value="info">Bilgi</option>
                    </select>
                </div>

                {/* Kanıt kademesi filtresi — "yalnız kanıtlı" ile false-positive gürültüsü elenir. */}
                <select
                    value={tierFilter}
                    onChange={(e) => setTierFilter(e.target.value)}
                    className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:border-red-500 transition-colors"
                >
                    <option value="">Tüm Kanıt Kademeleri</option>
                    <option value="confirmed">✅ Kanıtlı</option>
                    <option value="probable">◐ Olası</option>
                    <option value="unconfirmed">⚠️ Doğrulanmadı (olası FP)</option>
                </select>

                <select
                    value={limit}
                    onChange={(e) => setLimit(Number(e.target.value))}
                    className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:border-red-500 transition-colors"
                >
                    <option value={25}>25 kayıt</option>
                    <option value={50}>50 kayıt</option>
                    <option value={100}>100 kayıt</option>
                </select>

                <button className="ml-auto flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors">
                    <Download className="w-4 h-4" />
                    Rapor İndir
                </button>
            </div>

            {/* Table */}
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm dark:shadow-none">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
                                <th className="text-left px-6 py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Seviye</th>
                                <th className="text-left px-6 py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Zafiyet</th>
                                <th className="text-left px-6 py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                                    <div className="flex items-center gap-2">
                                        <Target className="w-4 h-4" />
                                        Hedef
                                    </div>
                                </th>
                                <th className="text-left px-6 py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Eşleşen URL</th>
                                <th className="text-left px-6 py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                                    <div className="flex items-center gap-2">
                                        <Calendar className="w-4 h-4" />
                                        Keşif Tarihi
                                    </div>
                                </th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                            {loading ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-12 text-center">
                                        <RefreshCw className="w-8 h-8 text-slate-400 dark:text-slate-600 animate-spin mx-auto mb-2" />
                                        <p className="text-slate-500">Yükleniyor...</p>
                                    </td>
                                </tr>
                            ) : vulns.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-12 text-center">
                                        <Shield className="w-12 h-12 text-emerald-700 mx-auto mb-3" />
                                        <p className="text-emerald-500 font-medium">Harika! Zafiyet bulunamadı.</p>
                                        <p className="text-slate-500 text-sm mt-1">Nuclei taraması yaparak zafiyetleri tespit edebilirsiniz.</p>
                                        <Link
                                            to="/scan"
                                            className="inline-block mt-3 px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-500 transition-colors"
                                        >
                                            Nuclei Taraması Başlat
                                        </Link>
                                    </td>
                                </tr>
                            ) : (
                                vulns.map((vuln, index) => (
                                    <Fragment key={`${vuln.scan_id}-${index}`}>
                                    <tr
                                        onClick={() => vuln.proof && setExpanded(expanded === index ? null : index)}
                                        className={`transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/30 ${vuln.proof ? 'cursor-pointer' : ''}`}
                                    >
                                        <td className="px-6 py-4">
                                            <div className="flex items-center gap-1.5">
                                                {getSeverityBadge(vuln.severity)}
                                                {vuln.proof && (
                                                    <ChevronDown
                                                        title="Kanitı göster/gizle"
                                                        className={`w-3.5 h-3.5 text-slate-400 transition-transform ${expanded === index ? 'rotate-180' : ''}`}
                                                    />
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div>
                                                <div className="flex items-center gap-2 flex-wrap">
                                                    <p className="text-slate-900 dark:text-white font-medium">{vuln.name}</p>
                                                    {(() => {
                                                        return (
                                                            <TierBadge
                                                                tier={vuln.confidence_tier}
                                                                confidence={vuln.verification_confidence}
                                                                bordered={true}
                                                                title={vuln.confidence_tier === 'unconfirmed' ? 'Araç iddia etti, bağımsız teyit yok — olası false-positive' : ''}
                                                            />
                                                        );
                                                    })()}
                                                    {vuln.fp_reason && (
                                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30">
                                                            {FP_REASON_LABEL[String(vuln.fp_reason)] || String(vuln.fp_reason)}
                                                        </span>
                                                    )}
                                                    {vuln.llm_fp_opinion?.verdict === 'false_positive' && (
                                                        <span title={vuln.llm_fp_opinion.reason || ''} className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30">
                                                            🧠 LLM: olası FP
                                                        </span>
                                                    )}
                                                </div>
                                                <p className="text-xs text-slate-500 font-mono mt-0.5">{vuln.template_id}</p>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className="text-slate-700 dark:text-slate-300">{vuln.target}</span>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="flex items-center gap-2 max-w-xs">
                                                <span className="text-slate-400 text-sm truncate">{vuln.matched_at}</span>
                                                {vuln.matched_at && (
                                                    <a
                                                        href={vuln.matched_at}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                                    >
                                                        <ExternalLink className="w-3 h-3" />
                                                    </a>
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400">
                                            {formatDate(vuln.discovered_at)}
                                        </td>
                                    </tr>
                                    {/* KANIT detay satırı — proof varsa satır tıklanınca açılır. */}
                                    {expanded === index && vuln.proof && (
                                        <tr className="bg-slate-50/70 dark:bg-slate-800/40">
                                            <td colSpan={5} className="px-6 py-4">
                                                <div className="flex items-center gap-2 mb-1.5">
                                                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Kanıt</span>
                                                    {vuln.tool && (
                                                        <span className="px-1.5 py-0.5 rounded bg-black/5 dark:bg-white/10 font-mono text-[10px] text-slate-500 dark:text-slate-400">🔧 {vuln.tool}</span>
                                                    )}
                                                    {vuln.cve && (
                                                        <span className="px-1.5 py-0.5 rounded bg-black/5 dark:bg-white/10 font-mono text-[10px] text-slate-500 dark:text-slate-400">CVE · {vuln.cve}</span>
                                                    )}
                                                </div>
                                                <div className="font-mono text-xs text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 rounded-lg p-3 max-h-48 overflow-y-auto">
                                                    {vuln.proof}
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                    </Fragment>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* AI Zafiyet Analizi */}
            {vulns.length > 0 && (
                <AIAnalysisPanel
                    scanData={{ vulnerabilities: vulns, total }}
                    analysisType="vuln"
                    title="🤖 AI Zafiyet Analizi"
                />
            )}

            {/* Footer */}
            {vulns.length > 0 && (
                <div className="flex items-center justify-between text-sm text-slate-500">
                    <p>Gösterilen: {vulns.length} / {total} zafiyet</p>
                    <p>Veriler MongoDB'den alınmaktadır</p>
                </div>
            )}
        </div>
    );
}
