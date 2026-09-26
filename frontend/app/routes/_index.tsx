import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Server,
  Globe,
  Shield,
  Clock,
  Zap,
  Database,
  Wifi,
  Search,
  XCircle,
  RefreshCw,
  ChevronRight,
  Bug,
  Sun,
  Moon
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { api } from '../services/api';

// ============== Types ==============
interface Stats {
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  failed_scans: number;
  vulnerabilities_found: number;
  recent_activities: Activity[];
  services_health: Record<string, ServiceHealth>;
}

interface Activity {
  type: string;
  target: string;
  message: string;
  severity: string;
  timestamp: string;
}

interface ServiceHealth {
  status: 'healthy' | 'unhealthy';
  latency_ms?: number;
  error?: string;
}

// ============== Components ==============

const StatCard = ({
  title,
  value,
  icon: Icon,
  color,
  subtext,
  trend
}: {
  title: string;
  value: string;
  icon: any;
  color: string;
  subtext: string;
  trend?: 'up' | 'down' | 'neutral';
}) => {
  const colorClasses: Record<string, { bg: string; text: string; border: string; icon: string }> = {
    blue: { bg: 'bg-blue-500/10', text: 'text-blue-500 dark:text-blue-400', border: 'border-blue-500/30', icon: 'text-blue-500' },
    purple: { bg: 'bg-purple-500/10', text: 'text-purple-500 dark:text-purple-400', border: 'border-purple-500/30', icon: 'text-purple-500' },
    emerald: { bg: 'bg-emerald-500/10', text: 'text-emerald-500 dark:text-emerald-400', border: 'border-emerald-500/30', icon: 'text-emerald-500' },
    red: { bg: 'bg-red-500/10', text: 'text-red-500 dark:text-red-400', border: 'border-red-500/30', icon: 'text-red-500' },
    amber: { bg: 'bg-amber-500/10', text: 'text-amber-500 dark:text-amber-400', border: 'border-amber-500/30', icon: 'text-amber-500' },
    cyan: { bg: 'bg-cyan-500/10', text: 'text-cyan-500 dark:text-cyan-400', border: 'border-cyan-500/30', icon: 'text-cyan-500' },
  };

  const c = colorClasses[color] || colorClasses.blue;

  return (
    <div className={`bg-white dark:bg-slate-900/50 p-5 md:p-6 rounded-xl border border-slate-200 dark:border-slate-800 backdrop-blur-sm hover:border-slate-300 dark:hover:border-slate-700 transition-all duration-300 group shadow-sm dark:shadow-none`}>
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{title}</h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">{subtext}</p>
        </div>
        <div className={`p-3 rounded-lg bg-slate-100 dark:bg-slate-800/50 group-hover:${c.bg} transition-colors`}>
          <Icon className={`w-5 h-5 md:w-6 md:h-6 ${c.icon}`} />
        </div>
      </div>
      <div className="flex items-baseline space-x-2">
        <p className="text-2xl md:text-3xl font-bold text-slate-900 dark:text-white">{value}</p>
        <span className={`text-xs font-medium ${c.text}`}>Güncel</span>
      </div>
    </div>
  );
};

const ServiceStatusCard = ({
  name,
  health,
  icon: Icon
}: {
  name: string;
  health?: ServiceHealth;
  icon: any;
}) => {
  const isHealthy = health?.status === 'healthy';

  return (
    <div className="flex items-center justify-between p-3 bg-slate-100 dark:bg-slate-800/30 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition-colors">
      <div className="flex items-center gap-3">
        <div className={`w-2 h-2 rounded-full ${isHealthy ? 'bg-emerald-500' : 'bg-red-500'} ${isHealthy ? 'animate-pulse' : ''}`} />
        <Icon className={`w-4 h-4 ${isHealthy ? 'text-slate-500 dark:text-slate-400' : 'text-red-400'}`} />
        <span className="text-sm text-slate-700 dark:text-slate-300">{name}</span>
      </div>
      <div className="flex items-center gap-2">
        {health?.latency_ms && (
          <span className="text-xs text-slate-500">{health.latency_ms}ms</span>
        )}
        <span className={`text-xs px-2 py-1 rounded ${isHealthy
          ? 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10'
          : 'text-red-600 dark:text-red-400 bg-red-500/10'
          }`}>
          {isHealthy ? 'Aktif' : 'Kapalı'}
        </span>
      </div>
    </div>
  );
};

const ActivityItem = ({ activity }: { activity: Activity }) => {
  const severityColors: Record<string, string> = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/30',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    info: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
  };

  const typeIcons: Record<string, any> = {
    scan_started: Activity,
    scan_completed: CheckCircle,
    scan_failed: XCircle,
    vulnerability_found: Bug,
  };

  const Icon = typeIcons[activity.type] || Activity;
  const colorClass = severityColors[activity.severity] || severityColors.info;

  const formatTime = (timestamp: string) => {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);

    if (minutes < 1) return 'Az önce';
    if (minutes < 60) return `${minutes} dk önce`;
    if (hours < 24) return `${hours} saat önce`;
    return date.toLocaleDateString('tr-TR');
  };

  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border ${colorClass} transition-all hover:scale-[1.02]`}>
      <div className="mt-0.5">
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-slate-800 dark:text-white truncate">{activity.message}</p>
        <div className="flex items-center gap-2 mt-1">
          <span className="text-xs text-slate-500">{activity.target}</span>
          <span className="text-xs text-slate-400 dark:text-slate-600">•</span>
          <span className="text-xs text-slate-500">{formatTime(activity.timestamp)}</span>
        </div>
      </div>
    </div>
  );
};

const QuickActionCard = ({
  title,
  description,
  icon: Icon,
  to,
  color
}: {
  title: string;
  description: string;
  icon: any;
  to: string;
  color: string;
}) => {
  const colorClasses: Record<string, string> = {
    blue: 'from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600',
    purple: 'from-purple-600 to-purple-700 hover:from-purple-500 hover:to-purple-600',
    emerald: 'from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600',
    amber: 'from-amber-600 to-amber-700 hover:from-amber-500 hover:to-amber-600',
    cyan: 'from-cyan-600 to-cyan-700 hover:from-cyan-500 hover:to-cyan-600',
    red: 'from-red-600 to-red-700 hover:from-red-500 hover:to-red-600',
  };

  return (
    <Link
      to={to}
      className={`block p-4 rounded-xl bg-gradient-to-br ${colorClasses[color]} transition-all duration-300 hover:scale-[1.02] hover:shadow-lg group`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-white/10 rounded-lg">
            <Icon className="w-5 h-5 text-white" />
          </div>
          <div>
            <h4 className="font-semibold text-white">{title}</h4>
            <p className="text-xs text-white/70">{description}</p>
          </div>
        </div>
        <ChevronRight className="w-5 h-5 text-white/50 group-hover:text-white group-hover:translate-x-1 transition-all" />
      </div>
    </Link>
  );
};

// ============== Main Dashboard ==============

import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useNavigate } from 'react-router';

// ... (previous imports)

export default function Dashboard() {
  const { token, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [stats, setStats] = useState<Stats>({
    total_scans: 0,
    active_scans: 0,
    completed_scans: 0,
    failed_scans: 0,
    vulnerabilities_found: 0,
    recent_activities: [],
    services_health: {}
  });
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  useEffect(() => {
    // If no token, redirect to login immediately
    if (!token) {
      navigate('/login');
      return;
    }

    const fetchStats = async () => {
      try {
        // api.get automatically adds the token handling
        const data = await api.get<any>('/api/stats');

        // Ensure data structure is safe before setting state
        setStats({
          total_scans: data.total_scans || 0,
          active_scans: data.active_scans || 0,
          completed_scans: data.completed_scans || 0,
          failed_scans: data.failed_scans || 0,
          vulnerabilities_found: data.vulnerabilities_found || 0,
          recent_activities: Array.isArray(data.recent_activities) ? data.recent_activities : [],
          services_health: data.services_health || {}
        });
        setLastUpdate(new Date());
      } catch (err) {
        console.error("Failed to fetch stats", err);
        // Keep existing safe state or show error
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [token, navigate, logout]);

  const servicesList = [
    { key: 'nmap', name: 'Nmap Tarayıcı', icon: Search },
    { key: 'nuclei', name: 'Nuclei Zafiyet', icon: Bug },
    { key: 'rustscan', name: 'RustScan', icon: Zap },
    { key: 'subfinder', name: 'Subfinder', icon: Globe },
    { key: 'mongodb', name: 'MongoDB', icon: Database },
  ];

  const healthyCount = Object.values(stats.services_health).filter(s => s.status === 'healthy').length;
  const totalServices = servicesList.length;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-black dark:text-white mb-2 flex items-center gap-3">
            <Shield className="text-black dark:text-white w-7 h-7 md:w-8 md:h-8 text-emerald-500" />
            Güvenlik Merkezi
          </h1>
          <p className="text-slate-600 dark:text-slate-400 text-sm md:text-base">Sistem durumu, tarama istatistikleri ve zafiyet analizi genel bakış.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3 md:gap-4">
          {/* Theme Toggle Button */}
          <button
            onClick={toggleTheme}
            className="group relative flex items-center gap-2 px-3 py-2 md:px-4 md:py-2.5 rounded-xl transition-all duration-300
                       bg-slate-100 dark:bg-slate-800/50 
                       border border-slate-200 dark:border-slate-700
                       hover:border-emerald-500/50 hover:shadow-lg hover:shadow-emerald-500/10"
            title={theme === 'dark' ? 'Açık Tema' : 'Koyu Tema'}
          >
            <div className="relative w-5 h-5">
              <Sun className={`absolute inset-0 w-5 h-5 text-amber-500 transition-all duration-300 ${theme === 'dark' ? 'opacity-100 rotate-0' : 'opacity-0 -rotate-90'}`} />
              <Moon className={`absolute inset-0 w-5 h-5 text-slate-600 dark:text-slate-400 transition-all duration-300 ${theme === 'dark' ? 'opacity-0 rotate-90' : 'opacity-100 rotate-0'}`} />
            </div>
            <span className="text-xs font-medium text-slate-600 dark:text-slate-400 hidden sm:inline">
              {theme === 'dark' ? 'Açık' : 'Koyu'}
            </span>
          </button>

          <div className="hidden md:block text-right">
            <p className="text-xs text-slate-500 dark:text-slate-500">Son güncelleme</p>
            <p className="text-sm text-slate-600 dark:text-slate-400">{lastUpdate.toLocaleTimeString('tr-TR')}</p>
          </div>
          <div className={`flex items-center space-x-2 text-xs md:text-sm px-3 md:px-4 py-2 rounded-full border ${healthyCount === totalServices
            ? 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
            : 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/20'
            }`}>
            <span className="relative flex h-2 w-2">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${healthyCount === totalServices ? 'bg-emerald-400' : 'bg-amber-400'
                }`}></span>
              <span className={`relative inline-flex rounded-full h-2 w-2 ${healthyCount === totalServices ? 'bg-emerald-500' : 'bg-amber-500'
                }`}></span>
            </span>
            <span>{healthyCount}/{totalServices} Servis Aktif</span>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Aktif Taramalar"
          value={stats.active_scans.toString()}
          icon={Activity}
          color="blue"
          subtext="Şu an çalışan işlemler"
        />
        <StatCard
          title="Toplam Taramalar"
          value={stats.total_scans.toString()}
          icon={Server}
          color="purple"
          subtext="Veritabanında kayıtlı"
        />
        <StatCard
          title="Tamamlanan"
          value={stats.completed_scans.toString()}
          icon={CheckCircle}
          color="emerald"
          subtext="Başarıyla tamamlanan"
        />
        <StatCard
          title="Zafiyet Bulundu"
          value={stats.vulnerabilities_found.toString()}
          icon={AlertTriangle}
          color={stats.vulnerabilities_found > 0 ? 'red' : 'emerald'}
          subtext="Nuclei taramalarından"
        />
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Zap className="w-5 h-5 text-amber-500" />
          Hızlı Erişim
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <QuickActionCard
            title="Yeni Tarama"
            description="Nmap, Nuclei, RustScan"
            icon={Search}
            to="/scan"
            color="blue"
          />
          <QuickActionCard
            title="Recon Intelligence"
            description="Varlık keşfi & teknoloji istihbaratı"
            icon={Globe}
            to="/recon-intelligence"
            color="cyan"
          />
          <QuickActionCard
            title="Hash Kırıcı"
            description="Wordlist saldırıları"
            icon={Shield}
            to="/hash-cracker"
            color="purple"
          />
          <QuickActionCard
            title="OSINT"
            description="Açık kaynak istihbarat"
            icon={Database}
            to="/osint"
            color="emerald"
          />
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activities - 2 columns */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-5 md:p-6 shadow-sm dark:shadow-none">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <Clock className="w-5 h-5 text-blue-500" />
              Son Aktiviteler
            </h3>
            <Link
              to="/active-scans"
              className="text-sm text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300 flex items-center gap-1"
            >
              Tümünü Gör <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="space-y-3 max-h-[400px] overflow-y-auto custom-scrollbar">
            {stats.recent_activities.length > 0 ? (
              stats.recent_activities.map((activity, index) => (
                <ActivityItem key={index} activity={activity} />
              ))
            ) : (
              <div className="text-center py-12 text-slate-500">
                <Activity className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p className="text-sm">Henüz aktivite kaydı bulunmuyor.</p>
                <p className="text-xs mt-1">Tarama başlatarak aktivite oluşturabilirsiniz.</p>
              </div>
            )}
          </div>
        </div>

        {/* Services Status - 1 column */}
        <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-5 md:p-6 shadow-sm dark:shadow-none">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-emerald-500" />
              Servis Durumu
            </h3>
            <button
              onClick={() => window.location.reload()}
              className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              title="Yenile"
            >
              <RefreshCw className="w-4 h-4 text-slate-400" />
            </button>
          </div>
          <div className="space-y-3">
            {servicesList.map((service) => (
              <ServiceStatusCard
                key={service.key}
                name={service.name}
                health={stats.services_health[service.key]}
                icon={service.icon}
              />
            ))}
          </div>

          {/* Mini Stats */}
          <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800">
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-3 bg-slate-100 dark:bg-slate-800/30 rounded-lg">
                <p className="text-2xl font-bold text-slate-900 dark:text-white">{stats.failed_scans}</p>
                <p className="text-xs text-slate-500">Başarısız</p>
              </div>
              <div className="text-center p-3 bg-slate-100 dark:bg-slate-800/30 rounded-lg">
                <p className="text-2xl font-bold text-slate-900 dark:text-white">
                  {stats.total_scans > 0
                    ? Math.round((stats.completed_scans / stats.total_scans) * 100)
                    : 0}%
                </p>
                <p className="text-xs text-slate-500">Başarı Oranı</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Info */}
      <div className="flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 pt-4 border-t border-slate-200 dark:border-slate-800/50 gap-2">
        <p>Kadim Güvenlik Platformu v1.0</p>
        <p>Veriler MongoDB'de kalıcı olarak saklanmaktadır.</p>
      </div>
    </div>
  );
}
