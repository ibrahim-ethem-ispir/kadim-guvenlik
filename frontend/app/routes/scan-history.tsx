import {
    History,
    Search,
    Filter,
    Download,
    Eye,
    Clock,
    CheckCircle,
    XCircle,
    Activity,
    ChevronLeft,
    ChevronRight,
    RefreshCw,
    Target,
    Calendar
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { api } from '../services/api';

interface Scan {
    scan_id: string;
    target: string;
    scan_types: string[];
    status: string;
    created_at: string;
    completed_at: string | null;
}

interface ScansResponse {
    scans: Scan[];
    total: number;
}

export default function ScanHistory() {
    const [scans, setScans] = useState<Scan[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [statusFilter, setStatusFilter] = useState<string>('');
    const [searchQuery, setSearchQuery] = useState('');
    const [limit, setLimit] = useState(25);
    useEffect(() => {
        fetchScans();
    }, [statusFilter, limit]);

    const fetchScans = async () => {
        setLoading(true);
        try {
            let url = `/api/scans?limit=${limit}`;
            if (statusFilter) {
                url += `&status=${statusFilter}`;
            }
            const data = await api.get<ScansResponse>(url);
            setScans(data.scans);
            setTotal(data.total);
        } catch (err) {
            console.error("Failed to fetch scans", err);
        } finally {
            setLoading(false);
        }
    };

    const filteredScans = scans.filter(scan =>
        searchQuery === '' ||
        scan.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.scan_id.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const getStatusBadge = (status: string) => {
        const grayStyle = 'bg-slate-100 dark:bg-slate-500/20 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-500/30';
        const styles: Record<string, string> = {
            running: 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-500/30',
            completed: 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30',
            failed: 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-500/30',
            // Otonom taramalar completed/failed dışında cancelled/stale ile de bitebilir;
            // bunlar 'running' mavisine düşmesin (yanlışlıkla aktif görünürlerdi).
            cancelled: grayStyle,
            stale: grayStyle,
            pending: grayStyle,
        };
        const icons: Record<string, any> = {
            running: Activity,
            completed: CheckCircle,
            failed: XCircle,
            cancelled: XCircle,
            stale: Clock,
            pending: Clock,
        };
        const labels: Record<string, string> = {
            running: 'Çalışıyor',
            completed: 'Tamamlandı',
            failed: 'Başarısız',
            cancelled: 'İptal edildi',
            stale: 'Takıldı',
            pending: 'Bekliyor',
        };

        const Icon = icons[status] || Activity;

        return (
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${styles[status] || grayStyle}`}>
                <Icon className="w-3 h-3" />
                {labels[status] || status}
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

    const getScanTypeBadges = (types: string[]) => {
        const colors: Record<string, string> = {
            nmap: 'bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-400',
            nuclei: 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400',
            rustscan: 'bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400',
            subfinder: 'bg-cyan-100 dark:bg-cyan-500/20 text-cyan-700 dark:text-cyan-400',
        };

        return types.map(type => (
            <span
                key={type}
                className={`px-2 py-0.5 rounded text-xs font-medium ${colors[type] || 'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-400'}`}
            >
                {type}
            </span>
        ));
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h1 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <History className="w-6 h-6 md:w-7 md:h-7 text-purple-500" />
                        Tarama Geçmişi
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1 text-sm">Tüm taramalar MongoDB'de kalıcı olarak saklanmaktadır.</p>
                </div>
                <div className="flex items-center gap-3">
                    <span className="text-sm text-slate-500">Toplam: {total} tarama</span>
                    <button
                        onClick={fetchScans}
                        className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                        title="Yenile"
                    >
                        <RefreshCw className={`w-4 h-4 text-slate-500 dark:text-slate-400 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                </div>
            </div>

            {/* Filters */}
            <div className="flex flex-wrap items-center gap-4 p-4 bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm dark:shadow-none">
                <div className="flex-1 min-w-[200px]">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500" />
                        <input
                            type="text"
                            placeholder="Hedef veya ID ile ara..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-purple-500"
                        />
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-slate-400 dark:text-slate-500" />
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:border-purple-500"
                    >
                        <option value="">Tüm Durumlar</option>
                        <option value="completed">Tamamlanan</option>
                        <option value="running">Çalışan</option>
                        <option value="failed">Başarısız</option>
                    </select>
                </div>

                <select
                    value={limit}
                    onChange={(e) => setLimit(Number(e.target.value))}
                    className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:border-purple-500"
                >
                    <option value={25}>25 kayıt</option>
                    <option value={50}>50 kayıt</option>
                    <option value={100}>100 kayıt</option>
                </select>
            </div>

            {/* Table */}
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm dark:shadow-none">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
                                <th className="text-left px-4 md:px-6 py-3 md:py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                                    <div className="flex items-center gap-2">
                                        <Target className="w-4 h-4" />
                                        Hedef
                                    </div>
                                </th>
                                <th className="text-left px-4 md:px-6 py-3 md:py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Tarama Tipleri</th>
                                <th className="text-left px-4 md:px-6 py-3 md:py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Durum</th>
                                <th className="text-left px-4 md:px-6 py-3 md:py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider hidden md:table-cell">
                                    <div className="flex items-center gap-2">
                                        <Calendar className="w-4 h-4" />
                                        Başlangıç
                                    </div>
                                </th>
                                <th className="text-left px-4 md:px-6 py-3 md:py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider hidden lg:table-cell">Bitiş</th>
                                <th className="text-right px-4 md:px-6 py-3 md:py-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">İşlemler</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                            {loading ? (
                                <tr>
                                    <td colSpan={6} className="px-6 py-12 text-center">
                                        <RefreshCw className="w-8 h-8 text-slate-400 dark:text-slate-600 animate-spin mx-auto mb-2" />
                                        <p className="text-slate-500">Yükleniyor...</p>
                                    </td>
                                </tr>
                            ) : filteredScans.length === 0 ? (
                                <tr>
                                    <td colSpan={6} className="px-6 py-12 text-center">
                                        <History className="w-12 h-12 text-slate-300 dark:text-slate-700 mx-auto mb-3" />
                                        <p className="text-slate-500">Henüz tarama kaydı bulunmuyor.</p>
                                        <Link
                                            to="/scan"
                                            className="inline-block mt-3 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-500 transition-colors"
                                        >
                                            İlk Taramayı Başlat
                                        </Link>
                                    </td>
                                </tr>
                            ) : (
                                filteredScans.map((scan) => (
                                    <tr key={scan.scan_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                                        <td className="px-4 md:px-6 py-3 md:py-4">
                                            <div>
                                                <p className="text-slate-900 dark:text-white font-medium text-sm">{scan.target}</p>
                                                <p className="text-xs text-slate-500 font-mono mt-0.5">{scan.scan_id.slice(0, 8)}...</p>
                                            </div>
                                        </td>
                                        <td className="px-4 md:px-6 py-3 md:py-4">
                                            <div className="flex flex-wrap gap-1">
                                                {getScanTypeBadges(scan.scan_types)}
                                            </div>
                                        </td>
                                        <td className="px-4 md:px-6 py-3 md:py-4">
                                            {getStatusBadge(scan.status)}
                                        </td>
                                        <td className="px-4 md:px-6 py-3 md:py-4 text-sm text-slate-700 dark:text-slate-400 hidden md:table-cell">
                                            {formatDate(scan.created_at)}
                                        </td>
                                        <td className="px-4 md:px-6 py-3 md:py-4 text-sm text-slate-700 dark:text-slate-400 hidden lg:table-cell">
                                            {formatDate(scan.completed_at || '')}
                                        </td>
                                        <td className="px-4 md:px-6 py-3 md:py-4 text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                <Link
                                                    to={`/results?id=${scan.scan_id}`}
                                                    className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                                                    title="Sonuçları Görüntüle"
                                                >
                                                    <Eye className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                                                </Link>
                                                <button
                                                    className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                                                    title="Rapor İndir"
                                                >
                                                    <Download className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Pagination Info */}
            {filteredScans.length > 0 && (
                <div className="flex items-center justify-between text-sm text-slate-500">
                    <p>Gösterilen: {filteredScans.length} / {total} tarama</p>
                    <p>Veriler MongoDB'den alınmaktadır</p>
                </div>
            )}
        </div>
    );
}
