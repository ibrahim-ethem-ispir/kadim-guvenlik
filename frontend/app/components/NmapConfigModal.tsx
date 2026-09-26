import { useState, useEffect } from "react";
import { X, Save, Settings, Shield, Clock, FileCode, Activity, Terminal, AlertTriangle } from "lucide-react";
import { api } from "../services/api";

interface NmapConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (options: any) => void;
  initialOptions: any;
}

export default function NmapConfigModal({ isOpen, onClose, onSave, initialOptions }: NmapConfigModalProps) {
  const [config, setConfig] = useState<any>(null);
  const [options, setOptions] = useState<any>(initialOptions || {});
  const [activeTab, setActiveTab] = useState("scan_type");
  const [customCmd, setCustomCmd] = useState("");
  const [useCustom, setUseCustom] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && !config && !loading && !error) {
      setLoading(true);
      setError(null);
      api.get<any>("/api/nmap/config")
        .then((data) => {
          setConfig(data);
          if (Object.keys(options).length === 0) {
            const defaults: any = {};
            data.categories?.forEach((cat: any) => {
              cat.options.forEach((opt: any) => {
                if (opt.default !== null && opt.default !== undefined) {
                  if (opt.type === "checkbox" && opt.default) {
                    defaults[opt.flag] = true;
                  } else if (opt.type === "radio" && opt.default) {
                    defaults[opt.group] = opt.flag;
                  }
                }
              });
            });
            setOptions(defaults);
          }
        })
        .catch((err) => {
          console.error("Config yüklenemedi:", err);
          setError("Ayarlar yüklenirken bir hata oluştu.");
        })
        .finally(() => setLoading(false));
    }
  }, [isOpen, config, options, loading, error]);

  const handleCheckbox = (flag: string, group?: string) => {
    if (group) {
      const newOptions = { ...options };
      newOptions[group] = newOptions[group] || [];
      if (newOptions[group].includes(flag)) {
        newOptions[group] = newOptions[group].filter((f: string) => f !== flag);
      } else {
        newOptions[group].push(flag);
      }
      setOptions(newOptions);
    } else {
      setOptions({ ...options, [flag]: !options[flag] });
    }
  };

  const handleRadio = (group: string, flag: string) => {
    setOptions({ ...options, [group]: flag });
  };

  const handleInput = (flag: string, value: any) => {
    setOptions({ ...options, [flag]: value });
  };

  const handleSave = () => {
    if (useCustom && customCmd.trim()) {
      onSave({ custom_cmd: customCmd.trim() });
    } else {
      onSave(options);
    }
  };

  if (!isOpen) return null;

  const categories = config?.categories || [];

  const getIcon = (id: string) => {
    switch (id) {
      case "scan_type": return <Activity className="w-4 h-4" />;
      case "timing": return <Clock className="w-4 h-4" />;
      case "scripts": return <FileCode className="w-4 h-4" />;
      case "advanced": return <Settings className="w-4 h-4" />;
      case "custom": return <Terminal className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <div className="fixed inset-0 !z-[9999] flex items-center justify-center bg-slate-950/40 backdrop-blur-md p-4 animate-in fade-in duration-200">
      <div className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl shadow-emerald-900/10 animate-in zoom-in-95 duration-200 overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-10">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/20 shadow-lg shadow-emerald-900/20">
              <Settings className="w-6 h-6 text-emerald-500" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">Gelişmiş Nmap Ayarları</h2>
              <p className="text-sm text-slate-400">Port tarama motoru yapılandırması</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-all hover:rotate-90 duration-300">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content Area */}
        {loading ? (
          <div className="flex-1 flex items-center justify-center text-slate-400 bg-slate-900/50">
            <div className="flex flex-col items-center gap-4">
              <div className="w-10 h-10 border-4 border-emerald-500/30 border-t-emerald-500 rounded-full animate-spin" />
              <p className="text-emerald-500 font-medium">Ayarlar yükleniyor...</p>
            </div>
          </div>
        ) : error ? (
          <div className="flex-1 flex items-center justify-center text-red-400 bg-slate-900/50">
            <div className="flex flex-col items-center gap-4 max-w-sm text-center">
              <div className="p-4 bg-red-500/10 rounded-full">
                <Shield className="w-8 h-8 text-red-500" />
              </div>
              <p className="text-lg font-medium text-white">Yükleme Başarısız</p>
              <p className="text-sm text-slate-400">{error}</p>
              <button onClick={() => { setConfig(null); setError(null); }} className="px-6 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-white text-sm transition-colors border border-slate-700">
                Tekrar Dene
              </button>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col md:flex-row overflow-hidden bg-slate-900/30">
            {/* Sidebar */}
            <div className="hidden md:block w-72 bg-slate-950/50 border-r border-slate-800 overflow-y-auto p-4 space-y-2 custom-scrollbar">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4 px-2">Kategoriler</div>
              {categories.map((cat: any) => (
                <button
                  key={cat.id}
                  onClick={() => { setActiveTab(cat.id); setUseCustom(false); }}
                  className={`w-full flex items-center gap-3 px-4 py-3.5 rounded-xl text-sm font-medium transition-all duration-200 group ${activeTab === cat.id && !useCustom
                    ? "bg-gradient-to-r from-emerald-500/10 to-transparent text-emerald-400 border-l-2 border-emerald-500"
                    : "text-slate-400 hover:bg-slate-900 hover:text-white border-l-2 border-transparent"
                    }`}
                >
                  <span className={`transition-transform duration-200 ${activeTab === cat.id && !useCustom ? 'scale-110' : 'group-hover:scale-110'}`}>
                    {getIcon(cat.id)}
                  </span>
                  {cat.name}
                </button>
              ))}

              {/* Özel Komut Tab */}
              <div className="border-t border-slate-800 pt-3 mt-3">
                <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 px-2">Gelişmiş</div>
                <button
                  onClick={() => { setActiveTab("custom"); setUseCustom(true); }}
                  className={`w-full flex items-center gap-3 px-4 py-3.5 rounded-xl text-sm font-medium transition-all duration-200 group ${useCustom
                    ? "bg-gradient-to-r from-amber-500/10 to-transparent text-amber-400 border-l-2 border-amber-500"
                    : "text-slate-400 hover:bg-slate-900 hover:text-white border-l-2 border-transparent"
                    }`}
                >
                  <Terminal className={`w-4 h-4 transition-transform duration-200 ${useCustom ? 'scale-110' : 'group-hover:scale-110'}`} />
                  Özel Komut
                </button>
              </div>
            </div>

            {/* Main Panel */}
            <div className="flex-1 overflow-y-auto p-6 md:p-8 space-y-6 custom-scrollbar bg-slate-900">
              {/* Category Options */}
              {!useCustom && categories.map((cat: any) => (
                <div key={cat.id} className={`${activeTab === cat.id ? "block" : "hidden"} animate-in fade-in slide-in-from-right-4 duration-300`}>
                  <div className="mb-8">
                    <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-3">
                      <div className="p-2 bg-emerald-500/10 rounded-lg">{getIcon(cat.id)}</div>
                      {cat.name}
                    </h3>
                    <p className="text-slate-400 text-sm">Bu kategorideki tarama seçeneklerini yapılandırın.</p>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {cat.options.map((opt: any) => (
                      <div key={opt.flag || opt.group} className={`group bg-slate-800/40 p-5 rounded-xl border border-slate-800/50 transition-all duration-300 hover:border-emerald-500/30 hover:bg-slate-800/60 ${(opt.type === 'checkbox' && (opt.group ? options[opt.group]?.includes(opt.flag) : options[opt.flag])) || (opt.type === 'radio' && options[opt.group] === opt.flag) ? 'border-emerald-500/30 bg-emerald-500/5' : ''}`}>
                        {opt.type === "checkbox" && (
                          <label className="flex items-start gap-4 cursor-pointer">
                            <input type="checkbox" checked={opt.group ? options[opt.group]?.includes(opt.flag) : !!options[opt.flag]} onChange={() => handleCheckbox(opt.flag, opt.group)} className="peer h-5 w-5 cursor-pointer appearance-none rounded-md border border-slate-600 bg-slate-900 transition-all checked:border-emerald-500 checked:bg-emerald-500 hover:border-emerald-400" />
                            <div className="flex-1">
                              <span className="text-slate-200 font-semibold block group-hover:text-white transition-colors">{opt.name}</span>
                              <span className="text-xs text-slate-500 block mt-1 leading-relaxed">{opt.description}</span>
                            </div>
                          </label>
                        )}
                        {opt.type === "radio" && (
                          <label className="flex items-start gap-4 cursor-pointer">
                            <input type="radio" name={opt.group} value={opt.flag} checked={options[opt.group] === opt.flag} onChange={() => handleRadio(opt.group, opt.flag)} className="peer h-5 w-5 cursor-pointer appearance-none rounded-full border border-slate-600 bg-slate-900 transition-all checked:border-emerald-500 checked:bg-emerald-500 hover:border-emerald-400" />
                            <div className="flex-1">
                              <span className={`font-semibold block transition-colors ${options[opt.group] === opt.flag ? "text-emerald-400" : "text-slate-200 group-hover:text-white"}`}>{opt.name}</span>
                              <p className="text-xs text-slate-500 mt-1 leading-relaxed">{opt.description}</p>
                            </div>
                          </label>
                        )}
                        {(opt.type === "text" || opt.type === "number") && (
                          <div>
                            <label className="block text-sm font-medium text-slate-300 mb-2 group-hover:text-emerald-400 transition-colors">{opt.name}</label>
                            <input type={opt.type} value={options[opt.flag] || ""} onChange={(e) => handleInput(opt.flag, e.target.value)} placeholder={opt.placeholder} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white placeholder-slate-600 focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 outline-none transition-all" />
                            <p className="text-xs text-slate-500 mt-2">{opt.description}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}

              {/* Özel Komut Paneli */}
              {useCustom && (
                <div className="animate-in fade-in slide-in-from-right-4 duration-300">
                  <div className="mb-6">
                    <h3 className="text-xl font-bold text-white mb-2 flex items-center gap-3">
                      <div className="p-2 bg-amber-500/10 rounded-lg">
                        <Terminal className="w-5 h-5 text-amber-400" />
                      </div>
                      Özel Nmap Komutu
                    </h3>
                    <p className="text-slate-400 text-sm">Doğrudan nmap komutu girin. Güvenlik kontrolleri uygulanır.</p>
                  </div>

                  {/* Güvenlik Uyarısı */}
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 mb-6">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-amber-400 font-semibold mb-1">Güvenlik Kontrolleri Aktif</h4>
                        <ul className="text-sm text-slate-400 space-y-1">
                          <li>• Komut enjeksiyonu engellenir (<code className="bg-slate-800 px-1 rounded">; | && $</code>)</li>
                          <li>• Tehlikeli flagler engellenir (<code className="bg-slate-800 px-1 rounded">-iR, --script=exploit</code>)</li>
                          <li>• Dosya erişimi engellenir (<code className="bg-slate-800 px-1 rounded">-iL, --script-args-file</code>)</li>
                          <li>• Sadece güvenli script kategorileri izin verilir</li>
                        </ul>
                      </div>
                    </div>
                  </div>

                  {/* Komut Girişi */}
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-2">Nmap Komutu</label>
                      <textarea
                        value={customCmd}
                        onChange={(e) => setCustomCmd(e.target.value)}
                        placeholder="nmap -p 443 --script ssl-enum-ciphers example.com"
                        rows={4}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white font-mono text-sm placeholder-slate-600 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 outline-none transition-all resize-none"
                      />
                      <p className="text-xs text-slate-500 mt-2">Hedef IP/domain'i komuta dahil edin veya ana ekrandan hedef seçin.</p>
                    </div>

                    {/* Örnek Komutlar */}
                    <div className="bg-slate-800/50 rounded-xl p-4">
                      <h5 className="text-sm font-medium text-slate-300 mb-3">Örnek Komutlar</h5>
                      <div className="space-y-2">
                        {[
                          { cmd: "-p 443 --script ssl-enum-ciphers", desc: "SSL/TLS cipher analizi" },
                          { cmd: "-sV --script=default,vuln -p 1-1000", desc: "Versiyon + zafiyet taraması" },
                          { cmd: "-sS -T4 -A --top-ports 100", desc: "Hızlı agresif tarama" },
                          { cmd: "-p 22 --script ssh-auth-methods", desc: "SSH auth metodları" },
                        ].map((ex, idx) => (
                          <button key={idx} onClick={() => setCustomCmd(ex.cmd)} className="w-full text-left p-2 rounded-lg bg-slate-900/50 hover:bg-slate-700/50 transition-colors group">
                            <code className="text-xs text-amber-400 font-mono">{ex.cmd}</code>
                            <p className="text-xs text-slate-500 mt-0.5">{ex.desc}</p>
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="p-6 border-t border-slate-800 bg-slate-900/50 backdrop-blur-md sticky bottom-0 z-10 rounded-b-2xl flex justify-end gap-4">
          <button onClick={onClose} className="px-6 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors font-medium border border-transparent hover:border-slate-700">
            İptal
          </button>
          <button
            onClick={handleSave}
            className={`px-8 py-2.5 text-white rounded-xl shadow-lg transition-all font-medium flex items-center gap-2 transform hover:-translate-y-0.5 active:translate-y-0 ${useCustom ? "bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 shadow-amber-900/20" : "bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 shadow-emerald-900/20"}`}
          >
            <Save className="w-4 h-4" />
            {useCustom ? "Özel Komut Çalıştır" : "Değişiklikleri Kaydet"}
          </button>
        </div>
      </div>
    </div>
  );
}
