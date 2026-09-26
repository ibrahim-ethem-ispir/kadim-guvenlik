import { useState } from 'react';
import { useNavigate } from 'react-router';
import { Search, Terminal, Activity, Shield, Globe, Server, Settings, Zap, ShieldAlert, ArrowRight, Play, CheckCircle2, Fingerprint, X } from 'lucide-react';
import { api } from '../services/api';
import FingerprintPanel, { type FingerprintData } from '../components/FingerprintPanel';
import NmapConfigModal from '../components/NmapConfigModal';
import RustScanConfigModal from '../components/RustScanConfigModal';
import NucleiConfigModal from '../components/NucleiConfigModal';
import SubfinderConfigModal from '../components/SubfinderConfigModal';
import FuzzConfigModal from '../components/FuzzConfigModal';

export default function NewScan() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [services, setServices] = useState({
    nmap: true,
    subfinder: false,
    rustscan: false,
    nuclei: false,
    fuzz: false
  });

  // Modals
  const [showNmapConfig, setShowNmapConfig] = useState(false);
  const [nmapOptions, setNmapOptions] = useState<any>({});

  const [showRustScanConfig, setShowRustScanConfig] = useState(false);
  const [rustscanOptions, setRustscanOptions] = useState<any>({});

  const [showNucleiConfig, setShowNucleiConfig] = useState(false);
  const [nucleiOptions, setNucleiOptions] = useState<any>({
    severity: ["critical", "high", "medium", "low"],
    tags: [],
    templates: [],
    rate_limit: 150,
    timeout: 5,
    retries: 1,
    exclude_tags: ["dos", "fuzz"],
    profile: "balanced"
  });

  const [showSubfinderConfig, setShowSubfinderConfig] = useState(false);
  const [subfinderOptions, setSubfinderOptions] = useState<any>({});

  const [showFuzzConfig, setShowFuzzConfig] = useState(false);
  const [fuzzOptions, setFuzzOptions] = useState<any>({});

  // Hızlı parmak izi (wappalyzergo) — üstteki hedef için anında teknoloji tespiti (tarama YOK).
  const [fpResult, setFpResult] = useState<FingerprintData | null>(null);
  const [fpLoading, setFpLoading] = useState(false);
  const [fpError, setFpError] = useState<string | null>(null);
  const [showFpModal, setShowFpModal] = useState(false);

  const handleFingerprint = async () => {
    const t = target.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    setShowFpModal(true);
    setFpError(null);
    setFpResult(null);
    if (!t) {
      setFpError('Önce üstteki alana bir domain veya IP girin.');
      return;
    }
    setFpLoading(true);
    try {
      const data = await api.post<FingerprintData>('/api/fingerprint/analyze', { target: t });
      setFpResult(data);
    } catch (err: any) {
      setFpError(err?.message || 'Parmak izi tespiti başarısız oldu.');
    } finally {
      setFpLoading(false);
    }
  };

  const toggleService = (key: keyof typeof services) => {
    setServices(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const servicesList = [
    {
      key: 'nmap',
      title: 'Nmap Port Tarama',
      description: 'Ağ keşfi ve port tarama standardı.',
      icon: Activity,
      color: 'emerald',
      modalOpen: () => setShowNmapConfig(true)
    },
    {
      key: 'rustscan',
      title: 'RustScan Hızlı Tarama',
      description: 'Ultra hızlı port keşfi.',
      icon: Zap,
      color: 'orange',
      modalOpen: () => setShowRustScanConfig(true)
    },
    {
      key: 'nuclei',
      title: 'Nuclei Zafiyet Tarama',
      description: 'Otomatize şablon tabanlı zafiyet analizi.',
      icon: ShieldAlert,
      color: 'indigo',
      modalOpen: () => setShowNucleiConfig(true)
    },
    {
      key: 'subfinder',
      title: 'Subfinder Keşif',
      description: 'Pasif kaynaklardan subdomain keşfi.',
      icon: Globe,
      color: 'cyan',
      modalOpen: () => setShowSubfinderConfig(true)
    },
    {
      key: 'fuzz',
      title: 'Fuzzing & Keşif',
      description: 'Dizin, dosya ve parametre keşfi (Smart Seeding).',
      icon: Zap, // Or create a new icon usage if possible, usage of imported Zap is fine
      color: 'purple',
      modalOpen: () => setShowFuzzConfig(true)
    }
  ];

  const validateTarget = (item: string) => {
    // Simple regex for domain or IP
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const localhostRegex = /^localhost$/;
    return domainRegex.test(item) || ipRegex.test(item) || localhostRegex.test(item);
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const cleanTarget = target.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');

    if (!cleanTarget) {
      setError("Hedef adresi boş olamaz.");
      return;
    }

    if (!validateTarget(cleanTarget)) {
      setError("Geçersiz hedef formatı. Lütfen geçerli bir domain veya IP adresi girin.");
      return;
    }

    setLoading(true);
    try {
      const scanTypes = Object.keys(services).filter(k => services[k as keyof typeof services]);
      const data = await api.post<any>('/api/scan', {
        target,
        scan_types: scanTypes,
        nmap_options: nmapOptions,
        rustscan_options: rustscanOptions,
        nuclei_options: nucleiOptions,
        subfinder_options: subfinderOptions,
        fuzz_options: fuzzOptions
      });

      if (data.scan_id) {
        navigate(`/results?id=${data.scan_id}`);
      }
    } catch (error) {
      console.error("Scan failed:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen py-10 px-4">

      {/* Modals */}
      <NmapConfigModal
        isOpen={showNmapConfig}
        onClose={() => setShowNmapConfig(false)}
        onSave={(opts) => { setNmapOptions(opts); setShowNmapConfig(false); }}
        initialOptions={nmapOptions}
      />
      <RustScanConfigModal
        isOpen={showRustScanConfig}
        onClose={() => setShowRustScanConfig(false)}
        onSave={(opts) => { setRustscanOptions(opts); setShowRustScanConfig(false); }}
        initialOptions={rustscanOptions}
      />
      <NucleiConfigModal
        isOpen={showNucleiConfig}
        onClose={() => setShowNucleiConfig(false)}
        onSave={(opts) => { setNucleiOptions(opts); setShowNucleiConfig(false); }}
        initialOptions={nucleiOptions}
      />
      <SubfinderConfigModal
        isOpen={showSubfinderConfig}
        onClose={() => setShowSubfinderConfig(false)}
        onSave={(opts) => { setSubfinderOptions(opts); setShowSubfinderConfig(false); }}
        initialOptions={subfinderOptions}
      />
      <FuzzConfigModal
        isOpen={showFuzzConfig}
        onClose={() => setShowFuzzConfig(false)}
        onSave={(opts) => { setFuzzOptions(opts); setShowFuzzConfig(false); }}
        initialOptions={fuzzOptions}
      />

      <div className="max-w-5xl mx-auto space-y-12">

        {/* Header Section */}
        <div className="text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-500 dark:text-blue-400 text-sm font-medium backdrop-blur-sm">
            <Shield className="w-4 h-4" />
            <span>Profesyonel Güvenlik Taraması</span>
          </div>
          <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold text-slate-900 dark:text-white tracking-tight">
            Yeni Hedef <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-500">Analizi</span>
          </h1>
          <p className="text-base md:text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
            Gelişmiş araçlarla hedef sistem üzerinde kapsamlı güvenlik testleri başlatın.
            Pasif keşiften aktif zafiyet taramasına kadar tam kontrol.
          </p>
        </div>

        {/* Main Scan Form */}
        <form onSubmit={handleScan} className="space-y-10">

          {/* Target Input */}
          <div className="relative group max-w-3xl mx-auto">
            {error && (
              <div className="absolute -top-12 left-0 right-0 bg-red-500/10 border border-red-500/20 text-red-500 px-4 py-2 rounded-lg text-center text-sm font-medium animate-fade-in">
                {error}
              </div>
            )}
            <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl blur opacity-20 dark:opacity-25 group-hover:opacity-40 dark:group-hover:opacity-50 transition duration-1000 group-hover:duration-200" />
            <div className="relative flex items-center bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700/50 rounded-xl p-2 shadow-lg dark:shadow-2xl">
              <Search className="w-6 h-6 text-slate-400 ml-4" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Hedef Domain veya IP (örn: example.com)"
                className="w-full bg-transparent border-none text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 text-base md:text-lg px-4 py-4 focus:ring-0 focus:outline-none"
                required
              />
              <div className="hidden md:flex items-center gap-2 pr-4 text-xs text-slate-400 dark:text-slate-500 font-mono border-l border-slate-200 dark:border-slate-800 pl-4">
                <Terminal className="w-4 h-4" />
                <span>READY</span>
              </div>
            </div>
          </div>

          {/* Service Selection Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6">
            {servicesList.map((service) => {
              const ServiceIcon = service.icon;
              const isSelected = services[service.key as keyof typeof services];

              // Dynamic colors based on selection and type
              let activeClass = '';
              let borderClass = 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700';
              let iconClass = 'text-slate-400 dark:text-slate-500 group-hover:text-slate-600 dark:group-hover:text-slate-300';

              if (isSelected) {
                if (service.color === 'emerald') {
                  activeClass = 'bg-emerald-500/5 shadow-emerald-900/10'; borderClass = 'border-emerald-500/50'; iconClass = 'text-emerald-500';
                } else if (service.color === 'orange') {
                  activeClass = 'bg-orange-500/5 shadow-orange-900/10'; borderClass = 'border-orange-500/50'; iconClass = 'text-orange-500';
                } else if (service.color === 'indigo') {
                  activeClass = 'bg-indigo-500/5 shadow-indigo-900/10'; borderClass = 'border-indigo-500/50'; iconClass = 'text-indigo-500';
                } else if (service.color === 'cyan') {
                  activeClass = 'bg-cyan-500/5 shadow-cyan-900/10'; borderClass = 'border-cyan-500/50'; iconClass = 'text-cyan-500';
                } else if (service.color === 'purple') {
                  activeClass = 'bg-purple-500/5 shadow-purple-900/10'; borderClass = 'border-purple-500/50'; iconClass = 'text-purple-500';
                }
              }

              return (
                <div
                  key={service.key}
                  className={`group relative rounded-2xl border transition-all duration-300 ${isSelected ? activeClass + ' shadow-xl transform -translate-y-1' : 'bg-white dark:bg-slate-900/50 ' + borderClass}`}
                >
                  <div className="p-4 md:p-5 h-full flex flex-col">
                    <div className="flex justify-between items-start mb-4">
                      <div className={`p-2 md:p-3 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 transition-colors ${isSelected ? 'bg-opacity-50' : ''}`}>
                        <ServiceIcon className={`w-5 h-5 md:w-6 md:h-6 transition-colors ${iconClass}`} />
                      </div>
                      <div
                        onClick={() => toggleService(service.key as keyof typeof services)}
                        className={`w-6 h-6 rounded-full border flex items-center justify-center cursor-pointer transition-all ${isSelected ? `border-${service.color}-500 bg-${service.color}-500 text-white` : 'border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500'}`}
                      >
                        {isSelected && <CheckCircle2 className="w-4 h-4" />}
                      </div>
                    </div>

                    <div onClick={() => toggleService(service.key as keyof typeof services)} className="cursor-pointer flex-1">
                      <h3 className={`font-bold text-base md:text-lg mb-1 transition-colors ${isSelected ? 'text-slate-900 dark:text-white' : 'text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-white'}`}>
                        {service.title}
                      </h3>
                      <p className="text-sm text-slate-500 leading-relaxed">
                        {service.description}
                      </p>
                    </div>

                    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800/50 flex items-center justify-between">
                      <button
                        type="button"
                        onClick={service.modalOpen}
                        className="flex items-center gap-1 text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors py-1 px-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
                      >
                        <Settings className="w-3 h-3" />
                        Ayarlar
                      </button>
                      {isSelected && (
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full bg-${service.color}-500/10 text-${service.color}-500 dark:text-${service.color}-400`}>
                          SEÇİLDİ
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}

            {/* TEKNOLOJİ PARMAK İZİ — seçilebilir tarama aracı DEĞİL; tıklanınca üstteki
                hedef için anında tespit yapıp modal açar (tam tarama gerektirmez). */}
            <button
              type="button"
              onClick={handleFingerprint}
              disabled={fpLoading}
              className="group relative rounded-2xl border border-slate-200 dark:border-slate-800 hover:border-indigo-500/50 bg-white dark:bg-slate-900/50 transition-all duration-300 text-left disabled:opacity-60"
            >
              <div className="p-4 md:p-5 h-full flex flex-col">
                <div className="flex justify-between items-start mb-4">
                  <div className="p-2 md:p-3 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                    <Fingerprint className="w-5 h-5 md:w-6 md:h-6 text-indigo-400" />
                  </div>
                  {fpLoading
                    ? <div className="w-6 h-6 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
                    : <ArrowRight className="w-5 h-5 text-slate-400 group-hover:text-indigo-400 transition-colors" />}
                </div>
                <div className="flex-1">
                  <h3 className="font-bold text-base md:text-lg mb-1 text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-white transition-colors">
                    Teknoloji Parmak İzi
                  </h3>
                  <p className="text-sm text-slate-500 leading-relaxed">
                    Anında teknoloji/sürüm/CPE tespiti (tam tarama gerekmez).
                  </p>
                </div>
                <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800/50 flex items-center justify-between">
                  <span className="flex items-center gap-1 text-xs font-medium text-indigo-500 dark:text-indigo-400">
                    <Fingerprint className="w-3 h-3" />
                    {fpLoading ? 'Tespit ediliyor...' : 'Tespit Et'}
                  </span>
                </div>
              </div>
            </button>
          </div>

          {/* Action Button */}
          <div className="flex justify-center pt-8 pb-10">
            <button
              type="submit"
              disabled={loading || !target || !Object.values(services).some(v => v)}
              className="group relative inline-flex items-center justify-center px-8 py-4 text-base font-bold text-white transition-all duration-200 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-full hover:from-blue-500 hover:to-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-600 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-blue-900/30 hover:shadow-blue-900/50 transform hover:-translate-y-0.5"
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin mr-3" />
                  Tarama Başlatılıyor...
                </>
              ) : (
                <>
                  Taramayı Başlat
                  <Play className="ml-2 w-5 h-5 fill-current" />
                </>
              )}
            </button>
          </div>

        </form>
      </div>

      {/* PARMAK İZİ MODALI — grid'deki "Teknoloji Parmak İzi" kartından açılır (üstteki hedef). */}
      {showFpModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div className="w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 p-6 text-slate-200 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-white text-base">Tespit Edilen Teknolojiler (Parmak İzi)</h3>
              </div>
              <button onClick={() => setShowFpModal(false)} className="text-slate-400 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            {fpError ? (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-sm">
                {fpError}
              </div>
            ) : fpLoading ? (
              <div className="text-center text-slate-400 text-sm py-10">
                Hedef çekiliyor ve imzalar eşleştiriliyor...
              </div>
            ) : (
              <FingerprintPanel fingerprint={fpResult} maxHeightClass="max-h-[26rem]" />
            )}

            <div className="border-t border-slate-800 pt-3 mt-4 text-right">
              <button onClick={() => setShowFpModal(false)} className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors">
                Kapat
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
