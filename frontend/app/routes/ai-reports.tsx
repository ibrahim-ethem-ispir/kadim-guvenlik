/**
 * AI Security Reports Page
 * Türkçe: AI Güvenlik Raporları - Mevcut AIAnalysisPanel'i kullanarak
 * 
 * Bu sayfa mevcut çalışan AI sistemini kullanır:
 * - AIAnalysisPanel component
 * - /api/ai/analyze endpoint
 * - Model seçimi ve chat
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router';
import { api } from '../services/api';
import AIAnalysisPanel from '../components/AIAnalysisPanel';
import {
    Brain, Shield, AlertTriangle, RefreshCw, Target,
    History, CheckCircle, Clock, ChevronRight, Eye,
    Loader2, FileText, Download
} from 'lucide-react';

interface Scan {
    scan_id: string;
    target: string;
    scan_types: string[];
    status: string;
    created_at: string;
    completed_at: string | null;
    results?: any;
}

export default function AIReports() {
    const [scans, setScans] = useState<Scan[]>([]);
    const [scansLoading, setScansLoading] = useState(true);
    const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
    const [loadingScanData, setLoadingScanData] = useState(false);

    // Tamamlanmış taramaları yükle
    useEffect(() => {
        const fetchScans = async () => {
            setScansLoading(true);
            try {
                const data = await api.get<{ scans: Scan[], total: number }>('/api/scans?limit=50&status=completed');
                setScans(data.scans || []);
            } catch (e) {
                console.error('Tarama listesi yüklenemedi:', e);
            } finally {
                setScansLoading(false);
            }
        };
        fetchScans();
    }, []);

    // Tarama seçilince detay verisi çek
    const handleSelectScan = async (scan: Scan) => {
        setLoadingScanData(true);
        try {
            const fullData = await api.get<any>(`/api/scan/${scan.scan_id}`);
            setSelectedScan({ ...scan, results: fullData.results });
        } catch (e) {
            console.error('Tarama verisi alınamadı:', e);
            // Yine de seç, AI analiz deneyebilir
            setSelectedScan(scan);
        } finally {
            setLoadingScanData(false);
        }
    };

    // Format date
    const formatDate = (dateStr: string | null) => {
        if (!dateStr) return '-';
        return new Date(dateStr).toLocaleString('tr-TR', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    // Scan type badges
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
                        <Brain className="w-6 h-6 md:w-7 md:h-7 text-emerald-500" />
                        AI Security Reports
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400 mt-1 text-sm">
                        Tarama seçin ve AI analiz başlatın
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Sol: Tarama Listesi */}
                <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-800/50">
                        <h2 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                            <History className="w-5 h-5 text-purple-500" />
                            Tamamlanan Taramalar
                        </h2>
                        <span className="text-xs text-slate-500">{scans.length} tarama</span>
                    </div>

                    <div className="max-h-[600px] overflow-y-auto">
                        {scansLoading ? (
                            <div className="p-8 text-center">
                                <RefreshCw className="w-8 h-8 animate-spin text-slate-400 mx-auto mb-2" />
                                <p className="text-slate-500">Taramalar yükleniyor...</p>
                            </div>
                        ) : scans.length === 0 ? (
                            <div className="p-8 text-center">
                                <History className="w-12 h-12 text-slate-300 dark:text-slate-700 mx-auto mb-3" />
                                <p className="text-slate-500 mb-3">Tamamlanmış tarama bulunamadı</p>
                                <Link
                                    to="/scan"
                                    className="inline-block px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-500 transition-colors text-sm"
                                >
                                    Yeni Tarama Başlat
                                </Link>
                            </div>
                        ) : (
                            <div className="divide-y divide-slate-200 dark:divide-slate-800">
                                {scans.map((scan) => (
                                    <button
                                        key={scan.scan_id}
                                        onClick={() => handleSelectScan(scan)}
                                        className={`w-full p-4 text-left hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors ${selectedScan?.scan_id === scan.scan_id
                                                ? 'bg-emerald-50 dark:bg-emerald-500/10 border-l-4 border-emerald-500'
                                                : ''
                                            }`}
                                    >
                                        <div className="flex items-start justify-between gap-4">
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2 mb-1">
                                                    <Target className="w-4 h-4 text-slate-400 shrink-0" />
                                                    <p className="font-medium text-slate-900 dark:text-white truncate">
                                                        {scan.target}
                                                    </p>
                                                </div>
                                                <div className="flex flex-wrap gap-1 mb-2">
                                                    {getScanTypeBadges(scan.scan_types)}
                                                </div>
                                                <div className="flex items-center gap-4 text-xs text-slate-500">
                                                    <span className="flex items-center gap-1">
                                                        <Clock className="w-3 h-3" />
                                                        {formatDate(scan.created_at)}
                                                    </span>
                                                </div>
                                            </div>
                                            <ChevronRight className={`w-5 h-5 text-slate-400 transition-transform ${selectedScan?.scan_id === scan.scan_id ? 'text-emerald-500' : ''
                                                }`} />
                                        </div>
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                {/* Sağ: AI Analiz Paneli */}
                <div>
                    {loadingScanData ? (
                        <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-8 text-center">
                            <Loader2 className="w-8 h-8 animate-spin text-emerald-500 mx-auto mb-4" />
                            <p className="text-slate-600 dark:text-slate-400">Tarama verisi yükleniyor...</p>
                        </div>
                    ) : selectedScan ? (
                        <div className="space-y-4">
                            {/* Seçili Tarama Bilgisi */}
                            <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 rounded-xl p-4">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <p className="text-sm text-emerald-600 dark:text-emerald-400 font-medium">
                                            Seçilen Tarama
                                        </p>
                                        <p className="text-lg font-bold text-emerald-800 dark:text-emerald-200">
                                            {selectedScan.target}
                                        </p>
                                    </div>
                                    <Link
                                        to={`/results?id=${selectedScan.scan_id}`}
                                        className="flex items-center gap-1 text-sm text-emerald-600 dark:text-emerald-400 hover:underline"
                                    >
                                        <Eye className="w-4 h-4" />
                                        Detaylar
                                    </Link>
                                </div>
                            </div>

                            {/* AI Analysis Panel - Mevcut Çalışan Component */}
                            <AIAnalysisPanel
                                scanId={selectedScan.scan_id}
                                scanData={selectedScan.results ? {
                                    target: selectedScan.target,
                                    scan_id: selectedScan.scan_id,
                                    results: selectedScan.results
                                } : undefined}
                                analysisType="security"
                                title="AI Güvenlik Analizi"
                            />
                        </div>
                    ) : (
                        <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-12 text-center">
                            <Brain className="w-16 h-16 text-slate-300 dark:text-slate-700 mx-auto mb-4" />
                            <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-2">
                                Tarama Seçin
                            </h3>
                            <p className="text-slate-500 dark:text-slate-400 text-sm max-w-sm mx-auto">
                                Sol taraftan bir tarama seçerek AI güvenlik analizi başlatabilirsiniz
                            </p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
