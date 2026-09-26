// Türkçe: Recon Intelligence - Tarama Geçmişi Component
import { useState, useEffect } from "react";
import { Link } from "react-router";
import { format } from "date-fns";
import { api } from "../services/api";

interface ScanHistoryItem {
  scan_id: string;
  target_domain: string;
  timestamp: string;
  status: string;
  total_subdomains: number;
  total_live_assets: number;
  scan_duration_seconds: number;
}

interface Props {
  onLoadScan: (scanId: string) => void;
}

export default function ScanHistory({ onLoadScan }: Props) {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    loadHistory();
    // Auto-refresh every 30 seconds
    const interval = setInterval(loadHistory, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadHistory = async () => {
    try {
      // Don't set loading to true on background refreshes if we already have data
      if (history.length === 0) {
        setLoading(true);
      }
      const data = await api.get<{ scans: ScanHistoryItem[] }>("/api/recon/history");
      if (data.scans) {
        setHistory(data.scans);
      }
    } catch (error) {
      console.error("Geçmiş yükleme hatası:", error);
    } finally {
      if (history.length === 0) {
        setLoading(false);
      }
    }
  };

  const filteredHistory = history.filter((scan) =>
    scan.target_domain.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  if (loading && history.length === 0) {
    return (
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-8 border border-slate-700 text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto"></div>
        <p className="text-slate-400 mt-4">Tarama geçmişi yükleniyor...</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-5 border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold text-white">📜 Tarama Geçmişi</h2>
        <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 hidden sm:inline-block">Otomatik yenilenir (30sn)</span>
            <button
            onClick={loadHistory}
            className="px-3 py-1 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 rounded text-sm transition-colors"
            >
            🔄 Yenile
            </button>
        </div>
      </div>

      <input
        type="text"
        placeholder="Domain ara..."
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 mb-4"
      />

      {filteredHistory.length === 0 ? (
        <div className="text-center py-8">
          <p className="text-slate-400">
            {searchTerm ? "Sonuç bulunamadı" : "Henüz tarama yapılmadı"}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-xs text-slate-400 uppercase bg-slate-900/50">
              <tr>
                <th className="px-4 py-3 text-left">Domain</th>
                <th className="px-4 py-3 text-left">Tarih</th>
                <th className="px-4 py-3 text-center">Subdomain</th>
                <th className="px-4 py-3 text-center">Canlı</th>
                <th className="px-4 py-3 text-center">Süre</th>
                <th className="px-4 py-3 text-center">Durum</th>
                <th className="px-4 py-3 text-center">İşlem</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {filteredHistory.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-slate-900/30">
                  <td className="px-4 py-3 text-white font-medium">
                    {scan.target_domain}
                  </td>
                  <td className="px-4 py-3 text-slate-400">
                    {format(new Date(scan.timestamp), "dd MMM yyyy HH:mm")}
                  </td>
                  <td className="px-4 py-3 text-center text-cyan-400">
                    {scan.total_subdomains}
                  </td>
                  <td className="px-4 py-3 text-center text-green-400">
                    {scan.total_live_assets}
                  </td>
                  <td className="px-4 py-3 text-center text-slate-400">
                    {formatDuration(scan.scan_duration_seconds)}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span
                      className={`px-2 py-1 rounded-full text-xs ${scan.status === "completed"
                        ? "bg-green-500/20 text-green-300"
                        : scan.status === "failed"
                        ? "bg-red-500/20 text-red-300"
                        : "bg-blue-500/20 text-blue-300 animate-pulse"
                        }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={() => onLoadScan(scan.scan_id)}
                      className="px-3 py-1 bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 rounded text-xs transition-colors"
                    >
                      Detayları Gör
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 text-sm text-slate-400 text-center">
        Toplam {filteredHistory.length} tarama kaydı
      </div>
    </div>
  );
}
