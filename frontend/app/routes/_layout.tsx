import { Outlet, Link, useLocation, useNavigate } from 'react-router';
import { useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import {
  Shield,
  LayoutDashboard,
  ScanLine,
  Terminal,
  Activity,
  Cloud,
  Radio,
  Lock,
  History,
  Bug,
  Globe,
  Database,
  Users,
  LogOut,
  ChevronRight,
  Zap,
  Brain,
  Bot,
  Crosshair,
  CalendarClock
} from 'lucide-react';

const Navbar = () => {
  const location = useLocation();
  const { logout } = useAuth();
  const { theme, toggleTheme } = useTheme();

  const isActive = (path: string) => location.pathname === path || location.pathname.startsWith(path + '/');

  const NavItem = ({ to, icon: Icon, label, color = "emerald" }: { to: string; icon: any; label: string; color?: "emerald" | "blue" | "purple" | "orange" | "red" }) => {
    const active = isActive(to);

    // Dynamic color styles
    let activeClass = "";
    let iconColor = "";

    switch (color) {
      case "emerald":
        activeClass = "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-r-2 border-emerald-500 shadow-[inset_0_0_20px_rgba(16,185,129,0.05)]";
        iconColor = active ? "text-emerald-600 dark:text-emerald-400" : "text-slate-400 dark:text-slate-500 group-hover:text-emerald-500 dark:group-hover:text-emerald-400";
        break;
      case "blue":
        activeClass = "bg-blue-500/10 text-blue-700 dark:text-blue-400 border-r-2 border-blue-500 shadow-[inset_0_0_20px_rgba(59,130,246,0.05)]";
        iconColor = active ? "text-blue-600 dark:text-blue-400" : "text-slate-400 dark:text-slate-500 group-hover:text-blue-500 dark:group-hover:text-blue-400";
        break;
      case "purple":
        activeClass = "bg-purple-500/10 text-purple-700 dark:text-purple-400 border-r-2 border-purple-500 shadow-[inset_0_0_20px_rgba(168,85,247,0.05)]";
        iconColor = active ? "text-purple-600 dark:text-purple-400" : "text-slate-400 dark:text-slate-500 group-hover:text-purple-500 dark:group-hover:text-purple-400";
        break;
      case "orange":
        activeClass = "bg-orange-500/10 text-orange-700 dark:text-orange-400 border-r-2 border-orange-500 shadow-[inset_0_0_20px_rgba(249,115,22,0.05)]";
        iconColor = active ? "text-orange-600 dark:text-orange-400" : "text-slate-400 dark:text-slate-500 group-hover:text-orange-500 dark:group-hover:text-orange-400";
        break;
      case "red":
        activeClass = "bg-red-500/10 text-red-700 dark:text-red-400 border-r-2 border-red-500 shadow-[inset_0_0_20px_rgba(239,68,68,0.05)]";
        iconColor = active ? "text-red-600 dark:text-red-400" : "text-slate-400 dark:text-slate-500 group-hover:text-red-500 dark:group-hover:text-red-400";
        break;
      default:
        activeClass = "bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-white";
        iconColor = "text-slate-400";
    }

    return (
      <Link
        to={to}
        className={`group flex items-center justify-between px-4 py-3 mx-2 rounded-lg transition-all duration-200 mb-0.5 ${active
          ? activeClass
          : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-white border-r-2 border-transparent'
          }`}
      >
        <div className="flex items-center space-x-3">
          <Icon className={`w-5 h-5 transition-colors ${iconColor}`} />
          <span className={`text-sm font-medium tracking-wide ${active ? 'font-semibold' : ''}`}>{label}</span>
        </div>
        {active && <ChevronRight className={`w-4 h-4 opacity-50 ${iconColor}`} />}
      </Link>
    );
  };

  const SectionLabel = ({ label }: { label: string }) => (
    <div className="px-6 py-3 mt-4 text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest leading-none flex items-center gap-2">
      <span className="w-8 h-[1px] bg-slate-200 dark:bg-slate-800"></span>
      {label}
    </div>
  );

  return (
    <aside className="w-72 bg-white/95 dark:bg-slate-950/90 backdrop-blur-xl border-r border-slate-200 dark:border-slate-800/80 flex flex-col h-screen fixed left-0 top-0 z-50 shadow-xl dark:shadow-2xl transition-colors duration-300">
      {/* Brand Header */}
      <div className="p-6 border-b border-slate-200 dark:border-slate-800/80 bg-white/50 dark:bg-slate-950/50">
        <div className="flex items-center space-x-3 group cursor-default">
          <div className="relative">
            <div className="absolute inset-0 bg-emerald-500/20 rounded-full blur-md group-hover:bg-emerald-500/30 transition-all"></div>
            <Shield className="w-9 h-9 text-emerald-600 dark:text-emerald-500 relative z-10" />
          </div>
          <div>
            <h1 className="text-xl font-black tracking-wider text-slate-900 dark:text-white">
              KADİM
            </h1>
            <p className="text-[10px] font-bold text-emerald-600 dark:text-emerald-500 tracking-[0.2em]">GÜVENLİK</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto py-4 custom-scrollbar">
        <NavItem to="/" icon={LayoutDashboard} label="Dashboard" color="emerald" />

        <SectionLabel label="Operasyon" />
        <NavItem to="/auto-scan" icon={Crosshair} label="Akilli Tarama v2" color="emerald" />
        <NavItem to="/scan" icon={ScanLine} label="Manuel Tarama" color="blue" />
        <NavItem to="/active-scans" icon={Activity} label="Aktif Taramalar" color="blue" />
        <NavItem to="/scan-history" icon={History} label="Tarama Geçmişi" color="blue" />
        <NavItem to="/scheduled-scans" icon={CalendarClock} label="Zamanlanmış Taramalar" color="blue" />

        <SectionLabel label="İstihbarat & Keşif" />
        <NavItem to="/recon-intelligence" icon={Globe} label="Recon Intellijans" color="purple" />
        <NavItem to="/osint" icon={Database} label="OSINT Suite" color="purple" />
        <NavItem to="/ai-reports" icon={Brain} label="AI Security Reports" color="purple" />
        <NavItem to="/ai-brain" icon={Bot} label="AI Brain 101" color="red" />

        <SectionLabel label="Analiz Araçları" />
        <NavItem to="/nmap-advanced" icon={Terminal} label="Nmap Gelişmiş" color="orange" />
        <NavItem to="/vulnerabilities" icon={Bug} label="Zafiyet Veritabanı" color="orange" />
        <NavItem to="/cf-analyzer" icon={Cloud} label="Cloudflare Analiz" color="orange" />

        <SectionLabel label="Özel Araçlar" />
        <NavItem to="/hash-cracker" icon={Lock} label="Hash Cracker" color="red" />
        <NavItem to="/wifi-audit" icon={Radio} label="Wi-Fi Sentinel" color="red" />
        <NavItem to="/stress-test" icon={Zap} label="Stress Test" color="red" />

        {/* Admin Section (optional, could be hidden based on role) */}
        <SectionLabel label="Sistem" />
        <NavItem to="/admin/users" icon={Users} label="Kullanıcılar" />
        <NavItem to="/admin/ai-settings" icon={Bot} label="AI Ayarları" color="emerald" />
      </nav>

      {/* Footer / User Profile */}
      <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/40 backdrop-blur-sm space-y-3">

        {/* Theme Toggle & User Info Row */}
        <div className="flex items-center gap-2">
          <div className="flex-1 bg-slate-100 dark:bg-slate-900/80 rounded-xl p-2 border border-slate-200 dark:border-slate-800 flex items-center gap-2 group hover:border-slate-300 dark:hover:border-slate-700 transition-all cursor-pointer">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-emerald-500 to-emerald-700 flex items-center justify-center text-white font-bold text-xs ring-2 ring-white dark:ring-slate-900 shadow-md">
              AD
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-bold text-slate-900 dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors truncate">Admin</p>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-[10px] text-slate-500 uppercase font-bold truncate">Online</span>
              </div>
            </div>
          </div>

          {/* Theme Toggle Button */}
          <button
            onClick={toggleTheme}
            className="w-10 h-12 rounded-xl bg-slate-100 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-center hover:border-slate-300 dark:hover:border-slate-700 transition-all group"
            title={theme === 'dark' ? "Açık Mod" : "Koyu Mod"}
          >
            {theme === 'dark' ? (
              <div className="relative">
                <div className="absolute inset-0 bg-yellow-400/20 blur-sm rounded-full opacity-0 group-hover:opacity-100 transition-opacity"></div>
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-yellow-500"><circle cx="12" cy="12" r="5" /><path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4" /></svg>
              </div>
            ) : (
              <div className="relative">
                <div className="absolute inset-0 bg-slate-400/20 blur-sm rounded-full opacity-0 group-hover:opacity-100 transition-opacity"></div>
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-slate-600"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" /></svg>
              </div>
            )}
          </button>
        </div>

        <button
          onClick={logout}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider
                     text-slate-500 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-all duration-300"
        >
          <LogOut className="w-4 h-4" />
          Çıkış Yap
        </button>
      </div>
    </aside>
  );
};


export default function MainLayout() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

  if (!isAuthenticated) return null;

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#020617] font-sans text-slate-900 dark:text-slate-200 selection:bg-emerald-500/30 selection:text-emerald-200">
      <Navbar />
      <main className="ml-72 min-h-screen relative">
        {/* Global Background Elements */}
        <div className="fixed inset-0 pointer-events-none z-0">
          <div className="absolute top-0 left-0 w-full h-[500px] bg-gradient-to-b from-slate-100 dark:from-slate-900 to-transparent opacity-60" />
          <div className="absolute top-[-20%] right-[-10%] w-[600px] h-[600px] rounded-full bg-emerald-500/5 blur-[100px]" />
          <div className="absolute bottom-[-10%] right-[20%] w-[500px] h-[500px] rounded-full bg-blue-500/5 blur-[100px]" />
        </div>

        {/* Content Wrapper — kompakt kenar boşluğu (sayfalar çok padding'li olmasın) */}
        <div className="relative z-10 p-3 md:p-5">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
