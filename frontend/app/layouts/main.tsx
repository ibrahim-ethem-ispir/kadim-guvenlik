import { Outlet, Link, useLocation } from 'react-router';
import {
  Shield,
  LayoutDashboard,
  ScanLine,
  FileText,
  Terminal,
  Activity,
  Cloud,
  Radio,
  Lock,
  History,
  Bug,
  Database,
  Sun, // Added
  Moon, // Added
  Crosshair
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext'; // Added

const Navbar = () => {
  const location = useLocation();
  const { theme, toggleTheme } = useTheme(); // Added

  const isActive = (path: string) => location.pathname === path || location.pathname.startsWith(path + '/');

  const NavItem = ({ to, icon: Icon, label }: { to: string; icon: any; label: string }) => (
    <Link
      to={to}
      className={`flex items-center space-x-3 px-4 py-2.5 rounded-lg transition-all duration-300 ${isActive(to)
        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.1)]'
        : 'text-txt-muted hover:text-emerald-300 hover:bg-hover' // Updated colors
        }`}
    >
      <Icon className="w-5 h-5" />
      <span className="font-medium tracking-wide text-sm">{label}</span>
    </Link>
  );

  const SectionLabel = ({ label }: { label: string }) => (
    <div className="px-4 py-2 text-xs font-semibold text-txt-scent uppercase tracking-wider">
      {label}
    </div>
  );

  return (
    <aside className="w-64 bg-surface border-r border-brd-main flex flex-col h-screen fixed left-0 top-0 z-50 transition-colors duration-300">
      <div className="p-6 border-b border-brd-main">
        <div className="flex items-center space-x-3 text-emerald-500">
          <Shield className="w-8 h-8" />
          <div>
            <h1 className="text-xl font-bold tracking-wider text-txt-main">KADİM</h1>
            <p className="text-xs text-emerald-500/70 tracking-[0.2em]">GÜVENLİK</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1 overflow-y-auto custom-scrollbar">
        <NavItem to="/" icon={LayoutDashboard} label="DASHBOARD" />

        <SectionLabel label="Taramalar" />
        <NavItem to="/auto-scan" icon={Crosshair} label="AKILLI TARAMA v2" />
        <NavItem to="/scan" icon={ScanLine} label="MANUEL TARAMA" />
        <NavItem to="/nmap-advanced" icon={Terminal} label="NMAP GELİŞMİŞ" />
        <NavItem to="/active-scans" icon={Activity} label="AKTİF TARAMALAR" />
        <NavItem to="/scan-history" icon={History} label="TARAMA GEÇMİŞİ" />
        <NavItem to="/results" icon={FileText} label="SONUÇLAR" />

        <SectionLabel label="Analiz" />
        <NavItem to="/vulnerabilities" icon={Bug} label="ZAFİYETLER" />
        <NavItem to="/cf-analyzer" icon={Cloud} label="CF ANALYZER" />

        <SectionLabel label="Araçlar" />
        <NavItem to="/hash-cracker" icon={Lock} label="HASH KIRICI" />
        <NavItem to="/osint" icon={Database} label="OSINT" />
      </nav>

      <div className="p-4 border-t border-brd-main space-y-3">
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="w-full flex items-center justify-between px-4 py-2 rounded-lg bg-element border border-brd-subtle hover:border-emerald-500/30 transition-all group"
        >
          <span className="text-xs font-medium text-txt-muted group-hover:text-txt-main transition-colors">
            {theme === 'dark' ? 'Karanlık Mod' : 'Aydınlık Mod'}
          </span>
          {theme === 'dark' ? (
            <Moon className="w-4 h-4 text-purple-400 group-hover:text-purple-300" />
          ) : (
            <Sun className="w-4 h-4 text-amber-500 group-hover:text-amber-400" />
          )}
        </button>

        <div className="bg-main rounded-lg p-3 border border-brd-main">
          <div className="flex items-center space-x-3">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
            <span className="text-xs text-txt-muted font-mono">SİSTEM AKTİF</span>
          </div>
          <p className="text-xs text-txt-scent mt-2">MongoDB Bağlı</p>
        </div>
      </div>
    </aside>
  );
};


export default function MainLayout() {
  return (
    <div className="min-h-screen bg-main font-mono text-txt-main selection:bg-emerald-500/30 selection:text-emerald-700 transition-colors duration-300">
      <Navbar />
      <main className="ml-64 p-8 min-h-screen relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none opacity-[0.03]"
          style={{ backgroundImage: 'linear-gradient(#10b981 1px, transparent 1px), linear-gradient(90deg, #10b981 1px, transparent 1px)', backgroundSize: '40px 40px' }}>
        </div>

        <div className="relative z-10 max-w-7xl mx-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
