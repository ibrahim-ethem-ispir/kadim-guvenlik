/**
 * Türkçe: Aktif Taramalar Sayfası
 * Tüm çalışan taramaları listeler ve izleme imkanı sağlar
 */
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Activity, RefreshCw, StopCircle, Eye, Clock, Target, Shield, AlertTriangle, Trash2, XCircle, Sparkles } from 'lucide-react';
import { api } from '../services/api';

interface ActiveScan {
  scan_id: string;
  target: string;
  scan_types: string[];
  status: string;
  created_at?: string;
  pid?: number;
}

export default function ActiveScans() {
  const [scans, setScans] = useState<ActiveScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [cleanupLoading, setCleanupLoading] = useState(false);


  // Türkçe: Aktif taramaları API'den çek
  const fetchActiveScans = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      const data = await api.get<any>('/api/active-scans');
      setScans(data.active_scans || []);
    } catch (error) {
      console.error('Aktif taramalar alınamadı:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  // Türkçe: Taramayı iptal et (silmeden)
  const cancelScan = async (scanId: string) => {
    setActionLoading(scanId);
    try {
      await api.post(`/api/scan/${scanId}/cancel`, {});
      await fetchActiveScans();
    } catch (error) {
      console.error('Tarama iptal edilemedi:', error);
    } finally {
      setActionLoading(null);
    }
  };

  // Türkçe: Taramayı zorla sil
  const deleteScan = async (scanId: string) => {
    if (!confirm('Bu taramayı tamamen silmek istediğinizden emin misiniz? Bu işlem geri alınamaz.')) {
      return;
    }
    setActionLoading(scanId);
    try {
      await api.delete(`/api/scan/${scanId}`);
      await fetchActiveScans();
    } catch (error) {
      console.error('Tarama silinemedi:', error);
    } finally {
      setActionLoading(null);
    }
  };

  // Türkçe: Tüm takılı taramaları temizle
  const cleanupStaleScans = async () => {
    setCleanupLoading(true);
    try {
      const result = await api.post<any>('/api/scans/cleanup-stale', {});
      alert(`${result.cleaned_count || 0} takılı tarama temizlendi.`);
      await fetchActiveScans();
    } catch (error) {
      console.error('Temizleme hatası:', error);
    } finally {
      setCleanupLoading(false);
    }
  };

  // Türkçe: Sayfa yüklendiğinde ve her 5 saniyede bir güncelle
  useEffect(() => {
    fetchActiveScans();
    const interval = setInterval(() => fetchActiveScans(), 5000);
    return () => clearInterval(interval);
  }, []);

  // Türkçe: Tarama tipi için renk ve ikon (tema-duyarlı: açık modda -600, koyu modda -400)
  const getScanTypeStyle = (type: string) => {
    switch (type) {
      case 'nmap':
        return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
      case 'nuclei':
        return 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30';
      case 'rustscan':
        return 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30';
      case 'subfinder':
        return 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30';
    }
  };

  // Türkçe: Status için renk ve metin (tema-duyarlı)
  const getStatusStyle = (status: string) => {
    switch (status) {
      case 'running':
        return { color: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30', text: 'ÇALIŞIYOR', icon: Activity };
      case 'stale':
        return { color: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/30', text: 'TAKILI', icon: AlertTriangle };
      case 'pending':
        return { color: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30', text: 'BEKLEMEDE', icon: Clock };
      case 'cancelled':
        return { color: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30', text: 'İPTAL', icon: XCircle };
      default:
        return { color: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30', text: status.toUpperCase(), icon: Activity };
    }
  };

  return (
    <div className="space-y-6 md:space-y-8">
      {/* Türkçe: Sayfa başlığı */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-3">
            <Activity className="w-7 h-7 md:w-8 md:h-8 text-emerald-500" />
            Aktif Taramalar
          </h1>
          <p className="text-slate-600 dark:text-slate-400">Çalışan tüm güvenlik taramalarını izleyin ve yönetin.</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Türkçe: Toplu temizleme butonu */}
          <button
            onClick={cleanupStaleScans}
            disabled={cleanupLoading}
            className="flex items-center gap-2 px-3 md:px-4 py-2 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-600 dark:text-yellow-400 border border-yellow-500/30 rounded-lg transition-colors disabled:opacity-50 text-sm"
            title="30 dakikadan eski takılı taramaları temizle"
          >
            <Sparkles className={`w-4 h-4 ${cleanupLoading ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">Takılıları Temizle</span>
          </button>

          <button
            onClick={() => fetchActiveScans(true)}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 md:px-4 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg transition-colors disabled:opacity-50 text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Yenile
          </button>
        </div>
      </div>

      {/* Türkçe: İstatistik kartları */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 md:gap-4">
        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 md:p-6 shadow-sm dark:shadow-none">
          <div className="flex items-center gap-3 md:gap-4">
            <div className="p-2 md:p-3 bg-emerald-500/10 rounded-lg">
              <Activity className="w-5 h-5 md:w-6 md:h-6 text-emerald-500" />
            </div>
            <div>
              <p className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white">{scans.length}</p>
              <p className="text-xs md:text-sm text-slate-500 dark:text-slate-400">Toplam Tarama</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 md:p-6 shadow-sm dark:shadow-none">
          <div className="flex items-center gap-3 md:gap-4">
            <div className="p-2 md:p-3 bg-blue-500/10 rounded-lg">
              <Activity className="w-5 h-5 md:w-6 md:h-6 text-blue-500" />
            </div>
            <div>
              <p className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white">
                {scans.filter(s => s.status === 'running').length}
              </p>
              <p className="text-xs md:text-sm text-slate-500 dark:text-slate-400">Çalışıyor</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 md:p-6 shadow-sm dark:shadow-none">
          <div className="flex items-center gap-3 md:gap-4">
            <div className="p-2 md:p-3 bg-yellow-500/10 rounded-lg">
              <AlertTriangle className="w-5 h-5 md:w-6 md:h-6 text-yellow-500" />
            </div>
            <div>
              <p className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white">
                {scans.filter(s => s.status === 'stale' || s.status === 'pending').length}
              </p>
              <p className="text-xs md:text-sm text-slate-500 dark:text-slate-400">Takılı/Beklemede</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 md:p-6 shadow-sm dark:shadow-none">
          <div className="flex items-center gap-3 md:gap-4">
            <div className="p-2 md:p-3 bg-purple-500/10 rounded-lg">
              <Shield className="w-5 h-5 md:w-6 md:h-6 text-purple-500" />
            </div>
            <div>
              <p className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white">
                {scans.filter(s => s.scan_types?.includes('nuclei')).length}
              </p>
              <p className="text-xs md:text-sm text-slate-500 dark:text-slate-400">Nuclei Tarama</p>
            </div>
          </div>
        </div>
      </div>

      {/* Türkçe: Tarama listesi */}
      {loading ? (
        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-12 text-center">
          <Activity className="w-10 h-10 text-emerald-500 animate-spin mx-auto mb-4" />
          <p className="text-slate-600 dark:text-slate-400">Aktif taramalar yükleniyor...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-12 text-center">
          <div className="w-20 h-20 bg-slate-100 dark:bg-slate-800/50 rounded-full flex items-center justify-center mx-auto mb-6">
            <Clock className="w-10 h-10 text-slate-500 dark:text-slate-400" />
          </div>
          <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-2">Aktif Tarama Yok</h3>
          <p className="text-slate-500 dark:text-slate-400 mb-6">Şu anda çalışan herhangi bir tarama bulunmuyor.</p>
          <Link
            to="/scan"
            className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-600/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/50 rounded-lg hover:bg-emerald-600/30 transition-all"
          >
            <Shield className="w-4 h-4" />
            Yeni Tarama Başlat
          </Link>
        </div>
      ) : (
        <div className="space-y-4">
          {scans.map((scan) => {
            const statusInfo = getStatusStyle(scan.status);
            const StatusIcon = statusInfo.icon;
            const isStale = scan.status === 'stale' || scan.status === 'pending';

            return (
              <div
                key={scan.scan_id}
                className={`bg-white dark:bg-slate-900/50 border rounded-xl p-6 hover:border-slate-300 dark:hover:border-slate-700 transition-all ${isStale ? 'border-yellow-500/30' : 'border-slate-200 dark:border-slate-800'
                  }`}
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-3">
                    {/* Türkçe: Hedef bilgisi */}
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${isStale ? 'bg-yellow-500/10' : 'bg-emerald-500/10'}`}>
                        <Target className={`w-5 h-5 ${isStale ? 'text-yellow-500' : 'text-emerald-500'}`} />
                      </div>
                      <div>
                        <p className="text-lg font-semibold text-slate-900 dark:text-white font-mono">{scan.target}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">ID: {scan.scan_id}</p>
                      </div>
                    </div>

                    {/* Türkçe: Tarama tipleri ve durum */}
                    <div className="flex flex-wrap gap-2">
                      {scan.scan_types?.map((type) => (
                        <span
                          key={type}
                          className={`px-3 py-1 text-xs font-medium rounded-full border ${getScanTypeStyle(type)}`}
                        >
                          {type.toUpperCase()}
                        </span>
                      ))}

                      {/* Türkçe: Durum göstergesi */}
                      <span className={`px-3 py-1 text-xs font-medium rounded-full border flex items-center gap-1 ${statusInfo.color}`}>
                        <StatusIcon className={`w-3 h-3 ${scan.status === 'running' ? 'animate-pulse' : ''}`} />
                        {statusInfo.text}
                      </span>
                    </div>
                  </div>

                  {/* Türkçe: Aksiyon butonları */}
                  <div className="flex items-center gap-2">
                    <Link
                      to={`/results?id=${scan.scan_id}`}
                      className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 rounded-lg hover:bg-emerald-500/20 transition-colors"
                    >
                      <Eye className="w-4 h-4" />
                      İzle
                    </Link>

                    {/* Türkçe: İptal butonu */}
                    <button
                      onClick={() => cancelScan(scan.scan_id)}
                      disabled={actionLoading === scan.scan_id}
                      className="flex items-center gap-2 px-4 py-2 bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/30 rounded-lg hover:bg-orange-500/20 transition-colors disabled:opacity-50"
                      title="Taramayı iptal et (kayıtlar silinmez)"
                    >
                      <StopCircle className={`w-4 h-4 ${actionLoading === scan.scan_id ? 'animate-spin' : ''}`} />
                      İptal
                    </button>

                    {/* Türkçe: Sil butonu */}
                    <button
                      onClick={() => deleteScan(scan.scan_id)}
                      disabled={actionLoading === scan.scan_id}
                      className="flex items-center gap-2 px-4 py-2 bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/20 transition-colors disabled:opacity-50"
                      title="Taramayı tamamen sil"
                    >
                      <Trash2 className={`w-4 h-4 ${actionLoading === scan.scan_id ? 'animate-spin' : ''}`} />
                      Sil
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Türkçe: Uyarı mesajı */}
      {scans.length > 0 && (
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-yellow-800 dark:text-yellow-200">
              <strong>Not:</strong> Taramalar arka planda çalışmaya devam eder.
              "İptal" butonu taramayı durdurur ama kayıtları saklar. "Sil" butonu her şeyi tamamen kaldırır.
              Takılı taramaları temizlemek için <strong>"Takılıları Temizle"</strong> butonunu kullanabilirsiniz.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
