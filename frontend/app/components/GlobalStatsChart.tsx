// Türkçe: Global İstatistikler ve Analitik Dashboard Component
import { useState, useEffect } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
} from "recharts";
import { api } from "../services/api";

interface TechnologyStats {
  name: string;
  count: number;
}

interface InfrastructureStats {
  provider: string;
  count: number;
}

interface GlobalStats {
  total_scans: number;
  total_domains: number;
  total_subdomains: number;
  total_live_assets: number;
  top_technologies: TechnologyStats[];
  infrastructure_breakdown: InfrastructureStats[];
}

const COLORS = [
  "#0088FE",
  "#00C49F",
  "#FFBB28",
  "#FF8042",
  "#8884d8",
  "#82ca9d",
  "#ffc658",
  "#ff7c7c",
];

export default function GlobalStatsChart() {
  const [stats, setStats] = useState<GlobalStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const data = await api.get<GlobalStats>("/api/recon/stats");
      // @ts-ignore
      if (!data.error) {
        setStats(data);
      }
    } catch (error) {
      console.error("İstatistik yükleme hatası:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-8 border border-slate-700 text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto"></div>
        <p className="text-slate-400 mt-4">İstatistikler yükleniyor...</p>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-8 border border-slate-700 text-center">
        <p className="text-slate-400">İstatistik verisi bulunamadı</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Özet Kartlar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-xl p-5 border border-cyan-500/30">
          <div className="text-3xl font-bold text-cyan-400">
            {stats.total_scans}
          </div>
          <div className="text-sm text-slate-300 mt-1">Toplam Tarama</div>
        </div>
        <div className="bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-xl p-5 border border-purple-500/30">
          <div className="text-3xl font-bold text-purple-400">
            {stats.total_domains}
          </div>
          <div className="text-sm text-slate-300 mt-1">Taranan Domain</div>
        </div>
        <div className="bg-gradient-to-br from-green-500/20 to-emerald-500/20 rounded-xl p-5 border border-green-500/30">
          <div className="text-3xl font-bold text-green-400">
            {stats.total_subdomains.toLocaleString()}
          </div>
          <div className="text-sm text-slate-300 mt-1">Bulunan Subdomain</div>
        </div>
        <div className="bg-gradient-to-br from-orange-500/20 to-red-500/20 rounded-xl p-5 border border-orange-500/30">
          <div className="text-3xl font-bold text-orange-400">
            {stats.total_live_assets.toLocaleString()}
          </div>
          <div className="text-sm text-slate-300 mt-1">Canlı Varlık</div>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* En Çok Kullanılan Teknolojiler */}
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-5 border border-slate-700">
          <h3 className="text-lg font-semibold text-white mb-4">
            🔥 En Popüler Teknolojiler
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats.top_technologies.slice(0, 10)}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="name"
                angle={-45}
                textAnchor="end"
                height={100}
                stroke="#94a3b8"
              />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1e293b",
                  border: "1px solid #475569",
                  borderRadius: "8px",
                }}
              />
              <Bar dataKey="count" fill="#06b6d4" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Altyapı Dağılımı */}
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-5 border border-slate-700">
          <h3 className="text-lg font-semibold text-white mb-4">
            ☁️ Altyapı Dağılımı
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={stats.infrastructure_breakdown}
                dataKey="count"
                nameKey="provider"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label={(entry) => `${entry.provider}: ${entry.count}`}
              >
                {stats.infrastructure_breakdown.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={COLORS[index % COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1e293b",
                  border: "1px solid #475569",
                  borderRadius: "8px",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Teknoloji Detay Listesi */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-5 border border-slate-700">
        <h3 className="text-lg font-semibold text-white mb-4">
          📊 Teknoloji Kullanım Detayları
        </h3>
        <div className="grid md:grid-cols-2 gap-3">
          {stats.top_technologies.slice(0, 20).map((tech, index) => (
            <div
              key={tech.name}
              className="flex items-center justify-between bg-slate-900/50 rounded-lg p-3"
            >
              <div className="flex items-center gap-3">
                <span className="text-cyan-400 font-mono text-sm">
                  #{index + 1}
                </span>
                <span className="text-white font-medium">{tech.name}</span>
              </div>
              <span className="text-slate-400">{tech.count} site</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
