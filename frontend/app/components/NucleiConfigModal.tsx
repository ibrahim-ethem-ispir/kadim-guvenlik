import { useState, useEffect, useMemo, useRef } from "react";
import { createPortal } from "react-dom";
import { X, Save, Shield, AlertTriangle, Zap, Search, List, Filter, Check, Loader2, HelpCircle, Info, Book, Settings } from "lucide-react";
import NucleiGuideModal from "./NucleiGuideModal";
import { api } from "../services/api";

// Türkçe: Template objesi arayüzü
interface TemplateItem {
  id: string;
  name: string;
  path: string;
  severity: string;
  category: string;
  tags: string[];
  description?: string;
}

interface NucleiConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (options: any) => void;
  initialOptions: any;
}

type Tab = 'general' | 'categories' | 'templates' | 'presets';

const SCAN_PRESETS = [
  {
    id: 'comprehensive-slow',
    icon: '🐢',
    name: 'Kapsamlı Tarama (Yavaş)',
    description: 'Linux sistemlerde en yavaş, takip edilebilir çıktılı zafiyet taraması. WAF/IPS atlatma için ideal.',
    estimatedTime: '30-60 dk',
    settings: {
      severity: ['critical', 'high', 'medium', 'low', 'info'],
      tags: [],
      templates: [],
      rate_limit: 5,
      timeout: 30,
      profile: 'stealth'
    }
  },
  {
    id: 'tech-detection',
    icon: '🎯',
    name: 'Teknoloji Tespiti',
    description: 'Hedef sistemdeki framework, CMS ve teknolojileri hızlıca tespit eder.',
    estimatedTime: '2-5 dk',
    settings: {
      severity: ['info'],
      tags: ['tech'],
      templates: [],
      rate_limit: 100,
      timeout: 5,
      profile: 'balanced'
    }
  },
  {
    id: 'critical-vulns',
    icon: '🔒',
    name: 'Kritik Zafiyetler',
    description: 'Sadece kritik ve yüksek seviye CVE zafiyetlerini tarar. Acil müdahale gerektiren açıklar için.',
    estimatedTime: '10-20 dk',
    settings: {
      severity: ['critical', 'high'],
      tags: ['cve'],
      templates: [],
      rate_limit: 150,
      timeout: 10,
      profile: 'balanced'
    }
  },
  {
    id: 'web-panels',
    icon: '🌐',
    name: 'Web Panelleri',
    description: 'Açık admin panellerini, login sayfalarını ve dashboard\'ları tespit eder.',
    estimatedTime: '5-10 dk',
    settings: {
      severity: ['info', 'low', 'medium'],
      tags: ['panel', 'login', 'exposure'],
      templates: [],
      rate_limit: 100,
      timeout: 5,
      profile: 'balanced'
    }
  },
  {
    id: 'fast-general',
    icon: '⚡',
    name: 'Hızlı Genel Tarama',
    description: 'Dengeli hızda genel zafiyet taraması. Hızlı sonuç almak isteyenler için.',
    estimatedTime: '5-15 dk',
    settings: {
      severity: ['critical', 'high', 'medium'],
      tags: [],
      templates: [],
      rate_limit: 300,
      timeout: 5,
      profile: 'fast'
    }
  }
];

export default function NucleiConfigModal({ isOpen, onClose, onSave, initialOptions }: NucleiConfigModalProps) {
  const [activeTab, setActiveTab] = useState<Tab>('general');
  const [options, setOptions] = useState<any>(initialOptions || {
    severity: ["critical", "high", "medium", "low"],
    tags: [],
    templates: [],
    rate_limit: 150,
    timeout: 5,
    retries: 1,
    exclude_tags: ["dos", "fuzz"],
    profile: "balanced"
  });

  const [availableTags, setAvailableTags] = useState<string[]>([]);
  const [availableTemplates, setAvailableTemplates] = useState<TemplateItem[]>([]);
  const [tagSearch, setTagSearch] = useState("");
  const [templateSearch, setTemplateSearch] = useState("");
  const [loading, setLoading] = useState(false);
  const [showGuide, setShowGuide] = useState(false);

  useEffect(() => {
    if (isOpen && availableTags.length === 0) {
      setLoading(true);
      Promise.all([
        api.get<any>("/api/nuclei/tags"),
        api.get<any>("/api/nuclei/templates")
      ])
        .then(([tagsData, templatesData]) => {
          setAvailableTags(tagsData.tags || []);
          // Türkçe: Templates artık objeler olarak geliyor
          const templates = (templatesData.templates || []) as TemplateItem[];
          setAvailableTemplates(templates);
        })
        .catch(console.error)
        .finally(() => setLoading(false));
    }
  }, [isOpen]);

  const filteredTags = useMemo(() => {
    return availableTags.filter(t => t.toLowerCase().includes(tagSearch.toLowerCase()));
  }, [availableTags, tagSearch]);

  const filteredTemplates = useMemo(() => {
    if (!templateSearch.trim()) return availableTemplates;
    const search = templateSearch.toLowerCase();
    return availableTemplates.filter(t =>
      t.id?.toLowerCase().includes(search) ||
      t.name?.toLowerCase().includes(search) ||
      t.path?.toLowerCase().includes(search) ||
      t.category?.toLowerCase().includes(search) ||
      t.tags?.some((tag: string) => tag.toLowerCase().includes(search))
    );
  }, [availableTemplates, templateSearch]);

  const toggleSeverity = (sev: string) => {
    const current = options.severity || [];
    if (current.includes(sev)) {
      setOptions({ ...options, severity: current.filter((s: string) => s !== sev) });
    } else {
      setOptions({ ...options, severity: [...current, sev] });
    }
  };

  const toggleTag = (tag: string) => {
    const current = options.tags || [];
    if (current.includes(tag)) {
      setOptions({ ...options, tags: current.filter((t: string) => t !== tag) });
    } else {
      setOptions({ ...options, tags: [...current, tag] });
    }
  };

  const toggleTemplate = (tplPath: string) => {
    const current = options.templates || [];
    if (current.includes(tplPath)) {
      setOptions({ ...options, templates: current.filter((t: string) => t !== tplPath) });
    } else {
      setOptions({ ...options, templates: [...current, tplPath] });
    }
  };

  // Türkçe: Severity rengini belirle
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const applyPreset = (preset: any) => {
    setOptions({ ...options, ...preset.settings });
    setActiveTab('general');
  };

  if (!isOpen) return null;

  return (
    <>
      <div className="fixed inset-0 !z-[9999] flex items-center justify-center bg-slate-950/40 backdrop-blur-md p-4 animate-in fade-in duration-200">
        <div className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl shadow-indigo-900/10 animate-in zoom-in-95 duration-200 overflow-hidden">

          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-indigo-500/10 rounded-xl border border-indigo-500/20 shadow-lg shadow-indigo-900/20">
                <Shield className="w-6 h-6 text-indigo-500" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white tracking-tight">Nuclei Gelişmiş Ayarlar</h2>
                <div className="flex items-center gap-2">
                  <p className="text-sm text-slate-400">Zafiyet tarama motoru yapılandırması</p>
                  <button
                    onClick={() => setShowGuide(true)}
                    className="text-xs flex items-center gap-1 text-indigo-400 hover:text-indigo-300 font-medium px-2 py-0.5 rounded-full bg-indigo-500/10 hover:bg-indigo-500/20 transition-colors"
                  >
                    <Book className="w-3 h-3" />
                    Kılavuz
                  </button>
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-all hover:rotate-90 duration-300"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          <div className="flex-1 flex flex-col md:flex-row overflow-hidden bg-slate-900/30">
            {/* Sidebar */}
            <div className="hidden md:block w-64 bg-slate-950/50 border-r border-slate-800 p-4 space-y-2">
              <button
                onClick={() => setActiveTab('presets')}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${activeTab === 'presets'
                  ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                  : "text-slate-400 hover:bg-slate-900 hover:text-white border border-transparent"}`}
              >
                <Zap className="w-4 h-4" /> Hazır Şablonlar
              </button>
              <button
                onClick={() => setActiveTab('general')}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${activeTab === 'general'
                  ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                  : "text-slate-400 hover:bg-slate-900 hover:text-white border border-transparent"}`}
              >
                <Settings className="w-4 h-4" /> Genel Ayarlar
              </button>
              <button
                onClick={() => setActiveTab('categories')}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${activeTab === 'categories'
                  ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                  : "text-slate-400 hover:bg-slate-900 hover:text-white border border-transparent"}`}
              >
                <Filter className="w-4 h-4" /> Kategoriler & Etiketler
              </button>
              <button
                onClick={() => setActiveTab('templates')}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${activeTab === 'templates'
                  ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                  : "text-slate-400 hover:bg-slate-900 hover:text-white border border-transparent"}`}
              >
                <List className="w-4 h-4" /> Özel Şablonlar
              </button>
            </div>

            {/* Mobile Tabs */}
            <div className="md:hidden flex overflow-x-auto border-b border-slate-800 bg-slate-950">
              {['presets', 'general', 'categories', 'templates'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab as Tab)}
                  className={`flex-1 min-w-[120px] py-3 text-sm font-medium border-b-2 ${activeTab === tab ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400'}`}
                >
                  {tab === 'presets' ? 'Şablonlar' : tab === 'general' ? 'Genel' : tab === 'categories' ? 'Kategoriler' : 'Özel'}
                </button>
              ))}
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-y-auto p-6 md:p-8 bg-slate-900 custom-scrollbar">

              {/* Presets Tab */}
              {activeTab === 'presets' && (
                <div className="space-y-4 animate-in fade-in slide-in-from-right-4 duration-300">
                  <div className="grid grid-cols-1 gap-4">
                    {SCAN_PRESETS.map((preset) => (
                      <button
                        key={preset.id}
                        onClick={() => applyPreset(preset)}
                        className="group relative flex items-start gap-4 p-5 rounded-xl border border-slate-800 bg-slate-800/30 hover:bg-slate-800 hover:border-indigo-500/50 transition-all text-left"
                      >
                        <div className="text-3xl bg-slate-900 rounded-lg p-3 group-hover:scale-110 transition-transform">{preset.icon}</div>
                        <div className="flex-1">
                          <div className="flex items-center justify-between mb-1">
                            <h3 className="font-bold text-white group-hover:text-indigo-400 transition-colors">{preset.name}</h3>
                            <span className="text-xs font-mono text-slate-500 bg-slate-900 px-2 py-1 rounded border border-slate-700">{preset.estimatedTime}</span>
                          </div>
                          <p className="text-sm text-slate-400 leading-relaxed mb-3">{preset.description}</p>
                          <div className="flex flex-wrap gap-2">
                            {preset.settings.severity.slice(0, 3).map((sev: string) => (
                              <span key={sev} className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-slate-900 text-slate-500 border border-slate-700">
                                {sev}
                              </span>
                            ))}
                            {preset.settings.severity.length > 3 && <span className="text-[10px] text-slate-500 px-1">...</span>}
                          </div>
                        </div>
                        <div className="absolute right-4 bottom-4 opacity-0 group-hover:opacity-100 transition-opacity">
                          <span className="text-xs font-bold text-indigo-400 flex items-center gap-1">SEÇ <ArrowRight className="w-3 h-3" /></span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* General Settings Tab */}
              {activeTab === 'general' && (
                <div className="space-y-8 animate-in fade-in slide-in-from-right-4 duration-300">

                  {/* Severity */}
                  <div className="space-y-3">
                    <label className="text-sm font-medium text-slate-300 ml-1">Zafiyet Seviyeleri</label>
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                      {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                        let colorClass = "";
                        const severityList = options.severity || [];
                        if (sev === 'critical') colorClass = severityList.includes(sev) ? "bg-red-500/20 border-red-500 text-red-400" : "hover:border-red-500/50 text-slate-400";
                        else if (sev === 'high') colorClass = severityList.includes(sev) ? "bg-orange-500/20 border-orange-500 text-orange-400" : "hover:border-orange-500/50 text-slate-400";
                        else if (sev === 'medium') colorClass = severityList.includes(sev) ? "bg-yellow-500/20 border-yellow-500 text-yellow-400" : "hover:border-yellow-500/50 text-slate-400";
                        else if (sev === 'low') colorClass = severityList.includes(sev) ? "bg-blue-500/20 border-blue-500 text-blue-400" : "hover:border-blue-500/50 text-slate-400";
                        else if (sev === 'info') colorClass = severityList.includes(sev) ? "bg-slate-500/20 border-slate-500 text-slate-300" : "hover:border-slate-500/50 text-slate-400";

                        return (
                          <button
                            key={sev}
                            onClick={() => toggleSeverity(sev)}
                            className={`px-3 py-2 rounded-lg border border-slate-700 bg-slate-800/50 transition-all font-medium uppercase text-xs flex items-center justify-center gap-2 ${colorClass}`}
                          >
                            {severityList.includes(sev) && <Check className="w-3 h-3" />}
                            {sev}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Performance */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Rate Limit (İstek/sn)</label>
                      <input
                        type="number"
                        value={options.rate_limit}
                        onChange={(e) => setOptions({ ...options, rate_limit: parseInt(e.target.value) })}
                        className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-slate-300">Timeout (sn)</label>
                      <input
                        type="number"
                        value={options.timeout}
                        onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) })}
                        className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Categories/Tags Tab */}
              {activeTab === 'categories' && (
                <div className="space-y-4 animate-in fade-in slide-in-from-right-4 duration-300 h-full flex flex-col">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                      type="text"
                      value={tagSearch}
                      onChange={(e) => setTagSearch(e.target.value)}
                      placeholder="Etiket ara (örn: cve, panel, exposure)..."
                      className="w-full bg-slate-900/50 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-white focus:border-indigo-500 focus:outline-none"
                    />
                  </div>

                  <div className="flex-1 overflow-y-auto min-h-[300px] border border-slate-800 rounded-xl bg-slate-900/50 p-2">
                    {loading ? (
                      <div className="flex items-center justify-center h-full">
                        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
                      </div>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {filteredTags.map(tag => (
                          <button
                            key={tag}
                            onClick={() => toggleTag(tag)}
                            className={`px-3 py-1.5 rounded-lg text-sm transition-all border ${(options.tags || []).includes(tag)
                              ? "bg-indigo-500/20 border-indigo-500 text-indigo-300"
                              : "bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500"
                              }`}
                          >
                            {tag}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Templates Tab */}
              {activeTab === 'templates' && (
                <div className="space-y-4 animate-in fade-in slide-in-from-right-4 duration-300 h-full flex flex-col">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                      type="text"
                      value={templateSearch}
                      onChange={(e) => setTemplateSearch(e.target.value)}
                      placeholder="Şablon ara (örn: nginx-status, git-config)..."
                      className="w-full bg-slate-900/50 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-white focus:border-indigo-500 focus:outline-none"
                    />
                  </div>

                  <div className="flex-1 overflow-y-auto min-h-[300px] border border-slate-800 rounded-xl bg-slate-900/50">
                    {loading ? (
                      <div className="flex items-center justify-center h-full">
                        <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
                      </div>
                    ) : (
                      <div className="divide-y divide-slate-800">
                        {filteredTemplates.slice(0, 100).map(tpl => (
                          <button
                            key={tpl.path || tpl.id}
                            onClick={() => toggleTemplate(tpl.path)}
                            className={`w-full text-left px-4 py-3 text-sm transition-colors hover:bg-slate-800 flex items-center justify-between gap-3 ${(options.templates || []).includes(tpl.path) ? "bg-indigo-500/10" : ""
                              }`}
                          >
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className={`text-xs font-bold uppercase px-1.5 py-0.5 rounded border ${getSeverityColor(tpl.severity)}`}>
                                  {tpl.severity?.charAt(0) || 'I'}
                                </span>
                                <span className={`font-medium truncate ${(options.templates || []).includes(tpl.path) ? "text-indigo-300" : "text-slate-300"}`}>
                                  {tpl.name || tpl.id}
                                </span>
                              </div>
                              <div className="text-xs text-slate-500 font-mono mt-0.5 truncate">
                                {tpl.path}
                              </div>
                            </div>
                            {(options.templates || []).includes(tpl.path) && <Check className="w-4 h-4 text-indigo-500 flex-shrink-0" />}
                          </button>
                        ))}
                        {filteredTemplates.length > 100 && (
                          <div className="p-4 text-center text-xs text-slate-500 italic">
                            + {filteredTemplates.length - 100} şablon daha (aramayı daraltın)
                          </div>
                        )}
                        {filteredTemplates.length === 0 && !loading && (
                          <div className="p-8 text-center text-slate-500">
                            <p>Şablon bulunamadı</p>
                            <p className="text-xs mt-1">Aramanızı değiştirmeyi deneyin</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

            </div>
          </div>

          {/* Footer */}
          <div className="p-6 border-t border-slate-800 bg-slate-900/50 backdrop-blur-md sticky bottom-0 z-10 flex justify-between items-center">
            <div className="text-sm text-slate-500 hidden sm:block">
              {(options.tags || []).length > 0 ? `${(options.tags || []).length} etiket` : ""}
              {(options.tags || []).length > 0 && (options.templates || []).length > 0 ? ", " : ""}
              {(options.templates || []).length > 0 ? `${(options.templates || []).length} şablon` : ""}
              {((options.tags || []).length === 0 && (options.templates || []).length === 0) ? "Varsayılan şablonlar kullanılacak" : " seçili"}
            </div>
            <div className="flex gap-3">
              <button
                onClick={onClose}
                className="px-6 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors font-medium border border-transparent hover:border-slate-700"
              >
                İptal
              </button>
              <button
                onClick={() => onSave(options)}
                className="px-8 py-2.5 bg-gradient-to-r from-indigo-600 to-indigo-500 hover:from-indigo-500 hover:to-indigo-400 text-white rounded-xl shadow-lg shadow-indigo-900/20 hover:shadow-indigo-900/30 transition-all font-medium flex items-center gap-2 transform hover:-translate-y-0.5 active:translate-y-0"
              >
                <Save className="w-4 h-4" />
                Kaydet
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* Guide Modal */}
      {showGuide && <NucleiGuideModal isOpen={true} onClose={() => setShowGuide(false)} />}
    </>
  );
}
import { ArrowRight } from "lucide-react";
