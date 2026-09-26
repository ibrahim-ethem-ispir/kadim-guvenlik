import { useState, useEffect } from "react";
import { X, Save, Settings, Shield, Clock, FileCode, Zap, Database, HelpCircle, Info } from "lucide-react";
import { api } from "../services/api";

interface FuzzConfigModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSave: (options: any) => void;
    initialOptions: any;
}

export default function FuzzConfigModal({ isOpen, onClose, onSave, initialOptions }: FuzzConfigModalProps) {
    const [options, setOptions] = useState<any>(initialOptions || {
        wordlist: "common.txt",
        smart_seeding: false,
        threads: 40,
        extensions: "",
        mc: "200,204,301,302,307,401,403",
        method: "GET"
    });

    const [activeTab, setActiveTab] = useState("general");
    const [wordlists, setWordlists] = useState<any[]>([]);
    const [categories, setCategories] = useState<any>({});
    const [selectedWordlist, setSelectedWordlist] = useState<any>(null);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (isOpen) {
            // Fetch wordlists with metadata
            setLoading(true);
            api.get<any>("/api/fuzz/wordlists")
                .then(data => {
                    if (data.wordlists) {
                        setWordlists(data.wordlists);
                        setCategories(data.categories || {});
                        // Find selected wordlist metadata
                        const selected = data.wordlists.find((w: any) => w.filename === options.wordlist);
                        setSelectedWordlist(selected || data.wordlists[0]);
                    }
                })
                .catch(err => console.error("Wordlists fetch error:", err))
                .finally(() => setLoading(false));
        }
    }, [isOpen]);

    const handleInput = (key: string, value: any) => {
        setOptions({ ...options, [key]: value });
    };

    const handleToggle = (key: string) => {
        setOptions({ ...options, [key]: !options[key] });
    };

    if (!isOpen) return null;

    const tabs = [
        { id: "general", name: "Genel Ayarlar", icon: <Settings className="w-4 h-4" /> },
        { id: "wordlist", name: "Wordlist & Seeding", icon: <Database className="w-4 h-4" /> },
        { id: "advanced", name: "Gelişmiş", icon: <Zap className="w-4 h-4" /> },
    ];

    return (
        <div className="fixed inset-0 !z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-md p-4 animate-in fade-in duration-200">
            <div className="bg-surface border border-brd-main rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl shadow-emerald-500/10 animate-in zoom-in-95 duration-200 overflow-hidden">

                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-brd-main bg-element/50 backdrop-blur-md sticky top-0 z-10 transition-colors">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-purple-500/10 rounded-xl border border-purple-500/20 shadow-lg shadow-purple-500/20">
                            <Zap className="w-6 h-6 text-purple-500" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-txt-main tracking-tight">Fuzzing Yapılandırması</h2>
                            <p className="text-sm text-txt-muted">Dizin ve dosya keşif motoru ayarları</p>
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-hover rounded-lg text-txt-muted hover:text-txt-main transition-all hover:rotate-90 duration-300"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <div className="flex-1 flex flex-col md:flex-row overflow-hidden bg-main/30">
                    {/* Sidebar */}
                    <div className="hidden md:block w-64 bg-surface border-r border-brd-main overflow-y-auto p-4 space-y-2 transition-colors">
                        <div className="text-xs font-semibold text-txt-muted uppercase tracking-wider mb-4 px-2">Kategoriler</div>
                        {tabs.map((tab) => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`w-full flex items-center gap-3 px-4 py-3.5 rounded-xl text-sm font-medium transition-all duration-200 group ${activeTab === tab.id
                                    ? "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-l-2 border-purple-500"
                                    : "text-txt-muted hover:bg-hover hover:text-txt-main border-l-2 border-transparent"
                                    }`}
                            >
                                <span className={`transition-transform duration-200 ${activeTab === tab.id ? 'scale-110' : 'group-hover:scale-110'}`}>
                                    {tab.icon}
                                </span>
                                {tab.name}
                            </button>
                        ))}
                    </div>

                    {/* Content */}
                    <div className="flex-1 overflow-y-auto p-6 md:p-8 space-y-6 custom-scrollbar bg-main/50">

                        {/* General Tab */}
                        {activeTab === "general" && (
                            <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
                                <div className="bg-surface p-5 rounded-xl border border-brd-main shadow-sm">
                                    <div className="flex items-center gap-2 mb-2">
                                        <label className="block text-sm font-medium text-txt-main">HTTP Method</label>
                                        <div className="group relative">
                                            <HelpCircle className="w-4 h-4 text-txt-muted cursor-help" />
                                            <div className="absolute left-6 top-0 w-72 p-3 bg-surface border border-brd-strong rounded-lg text-xs text-txt-scent opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 shadow-xl">
                                                <div className="font-semibold text-purple-500 mb-1">🌐 Sunucuya yapılacak istek tipi:</div>
                                                <div className="space-y-1">
                                                    <div>• <span className="text-green-600 dark:text-green-400">GET</span>: Sayfa/dosya indirme (en yaygın)</div>
                                                    <div>• <span className="text-blue-600 dark:text-blue-400">POST</span>: Form gönderme</div>
                                                    <div>• <span className="text-amber-600 dark:text-yellow-400">HEAD</span>: Sadece header (daha hızlı)</div>
                                                    <div>• <span className="text-orange-600 dark:text-orange-400">PUT</span>: Dosya yükleme</div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <select
                                        value={options.method}
                                        onChange={(e) => handleInput("method", e.target.value)}
                                        className="w-full bg-element border border-brd-strong rounded-lg px-4 py-2.5 text-txt-main focus:border-purple-500 outline-none transition-colors"
                                    >
                                        <option value="GET">GET</option>
                                        <option value="POST">POST</option>
                                        <option value="HEAD">HEAD</option>
                                        <option value="PUT">PUT</option>
                                    </select>
                                </div>

                                <div className="bg-surface p-5 rounded-xl border border-brd-main shadow-sm">
                                    <div className="flex items-center gap-2 mb-2">
                                        <label className="block text-sm font-medium text-txt-main">Thread Sayısı</label>
                                        <div className="group relative">
                                            <HelpCircle className="w-4 h-4 text-txt-muted cursor-help" />
                                            <div className="absolute left-6 top-0 w-72 p-3 bg-surface border border-brd-strong rounded-lg text-xs text-txt-scent opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 shadow-xl">
                                                <div className="font-semibold text-purple-500 mb-1">⚡ Aynı anda kaç istek yapılacağı:</div>
                                                <div className="space-y-1">
                                                    <div>• <span className="text-green-600 dark:text-green-400">10-20</span>: Yavaş ama güvenli</div>
                                                    <div>• <span className="text-amber-600 dark:text-yellow-400">40-60</span>: Dengeli (önerilen)</div>
                                                    <div>• <span className="text-red-600 dark:text-red-400">100+</span>: Hızlı ama sunucu yükü fazla</div>
                                                </div>
                                                <div className="mt-2 text-txt-muted">⚠️ Çok yüksek değerler hedef sunucuyu yavaşlatabilir veya IP'nizi engelleyebilir.</div>
                                            </div>
                                        </div>
                                    </div>
                                    <input
                                        type="number"
                                        min="1"
                                        max="200"
                                        value={options.threads}
                                        onChange={(e) => handleInput("threads", parseInt(e.target.value))}
                                        className="w-full bg-element border border-brd-strong rounded-lg px-4 py-2.5 text-txt-main focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <div className="flex items-center gap-2 mt-2">
                                        <div className="flex-1 h-2 bg-element rounded-full overflow-hidden border border-brd-subtle">
                                            <div
                                                className={`h-full transition-all ${options.threads < 30 ? 'bg-green-500 w-1/4' :
                                                    options.threads < 70 ? 'bg-amber-500 w-1/2' :
                                                        'bg-red-500 w-full'
                                                    }`}
                                            />
                                        </div>
                                        <span className="text-xs text-txt-muted w-16 text-right">{options.threads} thread</span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Wordlist Tab */}
                        {activeTab === "wordlist" && (
                            <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">

                                {/* Wordlist Selection - Enhanced */}
                                <div className="bg-surface p-5 rounded-xl border border-brd-main shadow-sm">
                                    <div className="flex items-center justify-between mb-3">
                                        <label className="block text-sm font-medium text-txt-main">Wordlist Seçimi</label>
                                        {wordlists.length > 0 && (
                                            <span className="text-xs text-txt-muted">{wordlists.length} wordlist mevcut</span>
                                        )}
                                    </div>
                                    {loading ? (
                                        <div className="text-txt-muted text-sm flex items-center gap-2">
                                            <div className="w-4 h-4 border-2 border-txt-muted border-t-purple-500 rounded-full animate-spin"></div>
                                            Listeler yükleniyor...
                                        </div>
                                    ) : (
                                        <div className="space-y-3">
                                            <select
                                                value={options.wordlist}
                                                onChange={(e) => {
                                                    handleInput("wordlist", e.target.value);
                                                    const selected = wordlists.find((w: any) => w.filename === e.target.value);
                                                    setSelectedWordlist(selected);
                                                }}
                                                className="w-full bg-element border border-brd-strong rounded-lg px-4 py-2.5 text-txt-main focus:border-purple-500 outline-none transition-colors"
                                            >
                                                {wordlists.length > 0 ? (
                                                    Object.keys(categories).length > 0 ? (
                                                        // Kategorili görünüm
                                                        Object.entries(categories).map(([catKey, catData]: [string, any]) => (
                                                            <optgroup key={catKey} label={`${catData.info?.icon || '📋'} ${catData.info?.name || catKey}`}>
                                                                {catData.items?.map((w: any) => (
                                                                    <option key={w.filename} value={w.filename}>
                                                                        {w.name || w.filename} ({w.line_count?.toLocaleString() || '?'} satır)
                                                                        {w.recommended ? ' ⭐' : ''}
                                                                    </option>
                                                                ))}
                                                            </optgroup>
                                                        ))
                                                    ) : (
                                                        // Kategorisiz yedek görünüm
                                                        wordlists.map((w: any) => (
                                                            <option key={w.filename} value={w.filename}>
                                                                {w.name || w.filename} ({w.line_count?.toLocaleString() || '?'} satır)
                                                                {w.recommended ? ' ⭐' : ''}
                                                            </option>
                                                        ))
                                                    )
                                                ) : (
                                                    <option value="common.txt">common.txt (Varsayılan)</option>
                                                )}
                                            </select>

                                            {/* Selected Wordlist Info Card */}
                                            {selectedWordlist && (
                                                <div className="p-4 bg-element/50 rounded-lg border border-brd-strong">
                                                    <p className="text-sm text-txt-main mb-2">{selectedWordlist.description}</p>
                                                    <div className="flex flex-wrap gap-2">
                                                        <span className={`text-xs px-2 py-1 rounded-full font-medium ${selectedWordlist.size_label === 'small' ? 'bg-green-500/10 text-green-600 dark:text-green-400 border border-green-500/20' :
                                                            selectedWordlist.size_label === 'medium' ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20' :
                                                                'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20'
                                                            }`}>
                                                            {selectedWordlist.size_label === 'small' ? '⚡ Hızlı' :
                                                                selectedWordlist.size_label === 'medium' ? '⏱️ Orta' : '🐢 Yavaş'}
                                                        </span>
                                                        <span className="text-xs px-2 py-1 rounded-full bg-hover text-txt-main border border-brd-strong">
                                                            {selectedWordlist.category}
                                                        </span>
                                                        {selectedWordlist.recommended && (
                                                            <span className="text-xs px-2 py-1 rounded-full bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
                                                                ⭐ Önerilen
                                                            </span>
                                                        )}
                                                    </div>
                                                    {selectedWordlist.tooltip && (
                                                        <p className="text-xs text-txt-muted mt-2">{selectedWordlist.tooltip}</p>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>

                                {/* Smart Seeding Toggle */}
                                <div className={`group p-5 rounded-xl border transition-all duration-300 ${options.smart_seeding ? "bg-purple-500/10 border-purple-500/30" : "bg-surface border-brd-main shadow-sm"}`}>
                                    <label className="flex items-start gap-4 cursor-pointer">
                                        <div className="relative flex items-center pt-1">
                                            <input
                                                type="checkbox"
                                                checked={options.smart_seeding}
                                                onChange={() => handleToggle("smart_seeding")}
                                                className="peer h-5 w-5 cursor-pointer appearance-none rounded-md border border-brd-strong bg-element transition-all checked:border-purple-500 checked:bg-purple-500"
                                            />
                                            <div className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-[40%] text-white opacity-0 peer-checked:opacity-100 transition-opacity">
                                                <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
                                            </div>
                                        </div>
                                        <div className="flex-1">
                                            <span className={`text-sm font-semibold block transition-colors ${options.smart_seeding ? "text-purple-600 dark:text-purple-400" : "text-txt-main"}`}>
                                                Smart Seeding (OSINT Zenginleştirme)
                                            </span>
                                            <p className="text-xs text-txt-muted mt-1 leading-relaxed">
                                                🧠 Akıllı WordList Zenginleştirme:<br />
                                                1. OSINT veritabanından path'ler çeker<br />
                                                2. VirusTotal'dan bilinen URL'leri alır<br />
                                                3. Seçili wordlist ile birleştirir<br />
                                                <span className="block mt-2 text-purple-500 dark:text-purple-400/70 text-[10px] uppercase font-bold tracking-wider">⭐ Hedefe özel sonuçlar için önerilir!</span>
                                            </p>
                                            {options.smart_seeding && (
                                                <div className="mt-2 p-2 bg-blue-500/10 rounded-lg border border-blue-500/20 text-xs text-blue-600 dark:text-blue-300">
                                                    <Info className="w-3 h-3 inline mr-1" />
                                                    VirusTotal verileri 24 saat boyunca önbelleklenir (rate limit koruması)
                                                </div>
                                            )}
                                        </div>
                                    </label>
                                </div>

                                <div className="bg-surface p-5 rounded-xl border border-brd-main shadow-sm">
                                    <div className="flex items-center gap-2 mb-2">
                                        <label className="block text-sm font-medium text-txt-main">Uzantılar (Extensions)</label>
                                        <div className="group relative">
                                            <HelpCircle className="w-4 h-4 text-txt-muted cursor-help" />
                                            <div className="absolute left-6 top-0 w-80 p-3 bg-surface border border-brd-strong rounded-lg text-xs text-txt-scent opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 shadow-xl">
                                                <div className="font-semibold text-purple-500 mb-1">📄 Denenmesi gereken dosya uzantıları:</div>
                                                <div className="space-y-1 mb-2">
                                                    <div>Örnek: <code className="bg-element px-1 rounded border border-brd-subtle">.php,.asp,.txt</code></div>
                                                    <div>→ admin.php, admin.asp, admin.txt denenecek</div>
                                                </div>
                                                <div className="text-txt-muted">💡 Boş bırakırsanız sadece dizin/dosya isimleri taranır.</div>
                                            </div>
                                        </div>
                                    </div>
                                    <input
                                        type="text"
                                        value={options.extensions}
                                        onChange={(e) => handleInput("extensions", e.target.value)}
                                        placeholder=".php,.html,.txt"
                                        className="w-full bg-element border border-brd-strong rounded-lg px-4 py-2.5 text-txt-main focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <div className="flex flex-wrap gap-2 mt-2">
                                        {['.php', '.asp', '.aspx', '.jsp', '.html', '.txt', '.js'].map(ext => (
                                            <button
                                                key={ext}
                                                type="button"
                                                onClick={() => {
                                                    const current = options.extensions ? options.extensions.split(',').map((e: string) => e.trim()) : [];
                                                    if (!current.includes(ext)) {
                                                        handleInput('extensions', [...current, ext].join(','));
                                                    }
                                                }}
                                                className="text-xs px-2 py-1 bg-element hover:bg-purple-500 hover:text-white rounded transition-colors text-txt-muted border border-brd-subtle"
                                            >
                                                {ext}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Advanced Tab */}
                        {activeTab === "advanced" && (
                            <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
                                <div className="bg-surface p-5 rounded-xl border border-brd-main shadow-sm">
                                    <div className="flex items-center gap-2 mb-2">
                                        <label className="block text-sm font-medium text-txt-main">Match Codes (MC)</label>
                                        <div className="group relative">
                                            <HelpCircle className="w-4 h-4 text-txt-muted cursor-help" />
                                            <div className="absolute left-6 top-0 w-80 p-3 bg-surface border border-brd-strong rounded-lg text-xs text-txt-scent opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 shadow-xl">
                                                <div className="font-semibold text-purple-500 mb-1">✅ Başarılı sayılacak HTTP durum kodları:</div>
                                                <div className="space-y-1">
                                                    <div>• <span className="text-green-600 dark:text-green-400">200</span>: Sayfa bulundu</div>
                                                    <div>• <span className="text-blue-600 dark:text-blue-400">301/302</span>: Yönlendirme</div>
                                                    <div>• <span className="text-amber-600 dark:text-yellow-400">401</span>: Kimlik doğrulama gerekli</div>
                                                    <div>• <span className="text-orange-600 dark:text-orange-400">403</span>: Erişim yasak (ama var!)</div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <input
                                        type="text"
                                        value={options.mc}
                                        onChange={(e) => handleInput("mc", e.target.value)}
                                        className="w-full bg-element border border-brd-strong rounded-lg px-4 py-2.5 text-txt-main focus:border-purple-500 outline-none transition-colors"
                                    />
                                </div>

                                <div className="bg-surface p-5 rounded-xl border border-brd-main shadow-sm">
                                    <label className="block text-sm font-medium text-txt-main mb-2">Filter Size (FS)</label>
                                    <input
                                        type="text"
                                        value={options.fs || ""}
                                        onChange={(e) => handleInput("fs", e.target.value)}
                                        placeholder="Örn: 0,123"
                                        className="w-full bg-element border border-brd-strong rounded-lg px-4 py-2.5 text-txt-main focus:border-purple-500 outline-none transition-colors"
                                    />
                                    <p className="text-xs text-txt-muted mt-2">Göz ardı edilecek response boyutları.</p>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Footer */}
                <div className="p-6 border-t border-brd-main bg-element/50 backdrop-blur-md sticky bottom-0 z-10 rounded-b-2xl flex justify-end gap-4 transition-colors">
                    <button onClick={onClose} className="px-6 py-2.5 rounded-xl text-txt-muted hover:text-txt-main hover:bg-hover transition-colors font-medium border border-transparent hover:border-brd-strong">
                        İptal
                    </button>
                    <button
                        onClick={() => onSave(options)}
                        className="px-8 py-2.5 bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white rounded-xl shadow-lg shadow-purple-500/20 hover:shadow-purple-500/30 transition-all font-medium flex items-center gap-2 transform hover:-translate-y-0.5 active:translate-y-0"
                    >
                        <Save className="w-4 h-4" />
                        Yapılandırmayı Kaydet
                    </button>
                </div>

            </div>
        </div>
    );
}
