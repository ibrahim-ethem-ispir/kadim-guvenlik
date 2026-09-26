import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { Terminal, Download, Play, Info, Activity, CheckCircle, Clock, AlertCircle, Eye } from "lucide-react";
import { api } from "../services/api";

// Türkçe: Nmap konfigürasyonu ve tarama UI'ı
export default function NmapAdvanced() {
  const navigate = useNavigate();
  const [config, setConfig] = useState<any>(null);
  const [target, setTarget] = useState("");
  const [options, setOptions] = useState<any>({});
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState("");
  const [output, setOutput] = useState<string[]>([]);
  const [ws, setWs] = useState<WebSocket | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [commandPreview, setCommandPreview] = useState<string>("");
  const [showPreview, setShowPreview] = useState(false);
  const [scanProgress, setScanProgress] = useState({
    status: "",
    lineCount: 0,
    discoveries: 0,
    lastUpdate: "",
  });

  // Türkçe: Nmap konfigürasyonu ve tarama UI'ı
  useEffect(() => {
    setLoading(true);
    setError(null);
    api.get<any>("/api/nmap/config")
      .then((data) => {
        setConfig(data);
        // Türkçe: Varsayılan değerleri ayarla
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
      })
      .catch((err) => {
        console.error("Config yüklenemedi:", err);
        setError("Ayarlar yüklenirken bir hata oluştu. Lütfen sayfayı yenileyin.");
      })
      .finally(() => setLoading(false));
  }, []);

  // Türkçe: Checkbox değişikliği
  const handleCheckbox = (flag: string, group?: string) => {
    if (group) {
      // Türkçe: Group içinde sadece bir tane seçilebilir
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

  // Türkçe: Radio değişikliği
  const handleRadio = (group: string, flag: string) => {
    setOptions({ ...options, [group]: flag });
  };

  // Türkçe: Text/Number input değişikliği
  const handleInput = (flag: string, value: any) => {
    setOptions({ ...options, [flag]: value });
    // Real-time validation tetikle
    validateOptions({ ...options, [flag]: value });
  };

  // Türkçe: Real-time validation
  const validateOptions = async (opts: any) => {
    if (!target) return;

    try {
      const data = await api.post<any>("/api/nmap/validate", { target, options: opts });

      if (!data.valid) {
        setValidationError(data.error);
      } else {
        setValidationError(null);
      }
    } catch (err) {
      console.error("Validation error:", err);
    }
  };

  // Türkçe: Komut önizlemesini getir
  const previewCommand = async () => {
    try {
      const data = await api.post<any>("/api/nmap/preview", { target: target || "example.com", options });

      if (data.valid) {
        setCommandPreview(data.command);
        setShowPreview(true);
      } else {
        setValidationError(data.error);
      }
    } catch (err) {
      console.error("Preview error:", err);
    }
  };

  // Türkçe: Options değiştiğinde validation yap
  useEffect(() => {
    if (target && Object.keys(options).length > 0) {
      const timer = setTimeout(() => validateOptions(options), 500);
      return () => clearTimeout(timer);
    }
  }, [options, target]);

  // Türkçe: Taramayı başlat (WebSocket ile real-time)
  const startScan = async () => {
    if (!target) {
      alert("Lütfen hedef IP/domain girin");
      return;
    }

    // Validation kontrolü
    const validation = await api.post<any>("/api/nmap/validate", { target, options });

    if (!validation.valid) {
      setValidationError(validation.error);
      alert(`Geçersiz parametreler: ${validation.error}`);
      return;
    }

    const newScanId = crypto.randomUUID();
    setScanId(newScanId);
    setScanning(true);
    setOutput([]);
    setScanProgress({ status: "Başlatılıyor...", lineCount: 0, discoveries: 0, lastUpdate: new Date().toLocaleTimeString() });

    // Türkçe: WebSocket bağlantısı kur
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/scan/stream/${newScanId}`;
    console.log("🔌 WebSocket URL:", wsUrl);
    const websocket = new WebSocket(wsUrl);

    websocket.onopen = () => {
      console.log("✅ WebSocket AÇILDI");
      // Türkçe: Bağlantı açıldığında scan parametrelerini gönder
      websocket.send(JSON.stringify({ target, options }));
      console.log("📤 Tarama parametreleri gönderildi:", { target, options });
      setScanProgress(prev => ({ ...prev, status: "Bağlantı kuruldu, tarama başlıyor..." }));
    };

    websocket.onmessage = (event) => {
      console.log("📨 WebSocket mesaj geldi:", event.data);
      const data = JSON.parse(event.data);

      if (data.type === "output") {
        setOutput((prev) => [...prev, data.data]);
        setScanProgress(prev => ({
          ...prev,
          lineCount: data.line_number || prev.lineCount + 1,
          lastUpdate: new Date(data.timestamp || Date.now()).toLocaleTimeString()
        }));
      } else if (data.type === "progress") {
        // Türkçe: Progress mesajları (Scanning, Completed, vb.)
        setOutput((prev) => [...prev, `📊 ${data.data}`]);
        setScanProgress(prev => ({
          ...prev,
          status: data.data,
          lastUpdate: new Date(data.timestamp || Date.now()).toLocaleTimeString()
        }));
      } else if (data.type === "discovery") {
        // Türkçe: Port/servis keşfi mesajları
        setOutput((prev) => [...prev, `🔍 ${data.data}`]);
        setScanProgress(prev => ({
          ...prev,
          discoveries: prev.discoveries + 1,
          lastUpdate: new Date(data.timestamp || Date.now()).toLocaleTimeString()
        }));
      } else if (data.type === "script") {
        // Türkçe: NSE script çıktıları
        setOutput((prev) => [...prev, `📜 ${data.data}`]);
      } else if (data.type === "heartbeat") {
        // Türkçe: Heartbeat mesajları (uzun sessiz periyotlar için)
        setScanProgress(prev => ({
          ...prev,
          status: data.data,
          lastUpdate: new Date(data.timestamp || Date.now()).toLocaleTimeString()
        }));
      } else if (data.type === "status") {
        // Türkçe: Genel durum mesajları
        setOutput((prev) => [...prev, `ℹ️ ${data.data}`]);
        setScanProgress(prev => ({
          ...prev,
          status: data.data,
          lastUpdate: new Date(data.timestamp || Date.now()).toLocaleTimeString()
        }));
      } else if (data.type === "complete") {
        setScanning(false);
        setOutput((prev) => [...prev, `\n✅ Tarama tamamlandı (Exit code: ${data.exit_code}, Toplam ${data.total_lines} satır)`]);
        setScanProgress(prev => ({
          ...prev,
          status: "Tamamlandı ✓",
          lastUpdate: new Date(data.timestamp || Date.now()).toLocaleTimeString()
        }));
        websocket.close();
      } else if (data.type === "error") {
        setScanning(false);
        setOutput((prev) => [...prev, `\n❌ Hata: ${data.message}`]);
        setOutput((prev) => [...prev, `\nℹ️ Tarama arka planda devam edebilir. "Tarama Geçmişi" sayfasından kontrol edebilirsiniz.`]);
        setScanProgress(prev => ({
          ...prev,
          status: "Bağlantı hatası - Arka planda devam ediyor",
          lastUpdate: new Date().toLocaleTimeString()
        }));
      }
    };

    websocket.onerror = (error) => {
      console.error("❌ WebSocket HATA:", error);
      setOutput((prev) => [...prev, "\n⚠️ WebSocket bağlantı hatası"]);
      setOutput((prev) => [...prev, "ℹ️ Tarama sunucuda devam ediyor. Sayfayı yenileyip 'Tarama Geçmişi' bölümünden kontrol edebilirsiniz."]);
      setScanProgress(prev => ({
        ...prev,
        status: "Bağlantı hatası - Tarama sunucuda devam ediyor",
        lastUpdate: new Date().toLocaleTimeString()
      }));
    };

    websocket.onclose = (event) => {
      console.log("🔒 WebSocket KAPANDI:", event.code, event.reason);

      if (scanning && event.code !== 1000) {
        // Tarama devam ederken beklenmedik kapanma
        setOutput((prev) => [...prev, "\n⚠️ Bağlantı kesildi"]);
        setOutput((prev) => [...prev, "ℹ️ Tarama arka planda devam ediyor. Sonuçları 'Tarama Geçmişi' sayfasından görebilirsiniz."]);
        setScanning(false);
        setScanProgress(prev => ({
          ...prev,
          status: "Bağlantı kesildi - Arka planda devam ediyor",
          lastUpdate: new Date().toLocaleTimeString()
        }));
      }
    };

    setWs(websocket);
  };

  // Türkçe: Log dosyasını indir
  const downloadLog = () => {
    if (!scanId) return;
    window.open(`/api/nmap/logs/${scanId}`, "_blank");
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-emerald-500/30 border-t-emerald-500 rounded-full animate-spin" />
          <p className="text-slate-600 dark:text-slate-400 font-medium">Ayarlar yükleniyor...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="bg-white dark:bg-slate-900/80 backdrop-blur-sm border border-red-500/30 p-8 rounded-lg max-w-md w-full text-center shadow-[0_0_30px_rgba(239,68,68,0.2)]">
          <div className="w-16 h-16 bg-red-500/10 text-red-400 rounded-full flex items-center justify-center mx-auto mb-4">
            <Info size={32} />
          </div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">Bir Hata Oluştu</h2>
          <p className="text-slate-600 dark:text-slate-400 mb-6">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="px-6 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 transition-colors"
          >
            Sayfayı Yenile
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Türkçe: Başlık */}
      <div className="border-b border-slate-300 dark:border-slate-800 pb-6">
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2 tracking-wide">GELİŞMİŞ NMAP TARAMA</h1>
        <p className="text-slate-600 dark:text-slate-400">
          Tüm Nmap özelliklerini kullanarak detaylı güvenlik taraması yapın
        </p>
      </div>

      {/* Türkçe: Hedef girişi */}
      <div className="bg-slate-50 dark:bg-slate-900/50 backdrop-blur-sm border border-slate-300 dark:border-slate-800/80 rounded-lg p-6 hover:border-emerald-500/30 transition-all">
        <label className="block text-sm font-medium text-emerald-600 dark:text-emerald-400 mb-2 tracking-wider">HEDEF IP/DOMAIN</label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="192.168.1.1 veya example.com"
          className="w-full px-4 py-3 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded-lg text-slate-900 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-600 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all"
          disabled={scanning}
        />
      </div>

      {/* Türkçe: Validation Hatası Gösterimi */}
      {validationError && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-start gap-3 animate-pulse">
          <AlertCircle size={24} className="text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="text-red-400 font-bold mb-1">Parametre Hatası</h3>
            <p className="text-slate-700 dark:text-slate-300 text-sm">{validationError}</p>
          </div>
        </div>
      )}

      {/* Türkçe: Nmap seçenekleri */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {config.categories?.map((category: any) => (
          <div key={category.id} className="bg-slate-50 dark:bg-slate-900/50 backdrop-blur-sm border border-slate-300 dark:border-slate-800/80 rounded-lg p-6 hover:border-emerald-500/30 transition-all">
            <h2 className="text-lg font-bold text-emerald-600 dark:text-emerald-400 mb-1 tracking-wider">{category.name}</h2>
            <p className="text-xs text-slate-500 dark:text-slate-500 mb-4">{category.description}</p>

            <div className="space-y-3">
              {category.options.map((option: any) => (
                <div key={option.flag} className="border-b border-slate-200 dark:border-slate-800/50 pb-3 last:border-0">
                  {/* Türkçe: Checkbox */}
                  {option.type === "checkbox" && (
                    <label className="flex items-start gap-3 cursor-pointer group">
                      <input
                        type="checkbox"
                        checked={
                          option.group
                            ? options[option.group]?.includes(option.flag)
                            : options[option.flag] || false
                        }
                        onChange={() => handleCheckbox(option.flag, option.group)}
                        disabled={scanning}
                        className="mt-1 accent-emerald-500"
                      />
                      <div className="flex-1">
                        <div className="font-medium text-sm text-slate-800 dark:text-slate-200 group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors">
                          {option.name}
                          <code className="ml-2 text-xs bg-slate-200 dark:bg-slate-950 text-emerald-600 dark:text-emerald-500 px-2 py-0.5 rounded border border-slate-300 dark:border-slate-800">
                            {option.flag}
                          </code>
                        </div>
                        <div className="text-xs text-slate-500 dark:text-slate-500 mt-1">{option.description}</div>
                      </div>
                    </label>
                  )}

                  {/* Türkçe: Radio */}
                  {option.type === "radio" && (
                    <label className="flex items-start gap-3 cursor-pointer group">
                      <input
                        type="radio"
                        name={option.group}
                        checked={options[option.group] === option.flag}
                        onChange={() => handleRadio(option.group, option.flag)}
                        disabled={scanning}
                        className="mt-1 accent-emerald-500"
                      />
                      <div className="flex-1">
                        <div className="font-medium text-sm text-slate-800 dark:text-slate-200 group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors">
                          {option.name}
                          <code className="ml-2 text-xs bg-slate-200 dark:bg-slate-950 text-emerald-600 dark:text-emerald-500 px-2 py-0.5 rounded border border-slate-300 dark:border-slate-800">
                            {option.flag}
                          </code>
                        </div>
                        <div className="text-xs text-slate-500 dark:text-slate-500 mt-1">{option.description}</div>
                      </div>
                    </label>
                  )}

                  {/* Türkçe: Text/Number Input */}
                  {(option.type === "text" || option.type === "number") && (
                    <div>
                      <label className="block font-medium text-sm text-slate-800 dark:text-slate-200 mb-2">
                        {option.name}
                        <code className="ml-2 text-xs bg-slate-200 dark:bg-slate-950 text-emerald-600 dark:text-emerald-500 px-2 py-0.5 rounded border border-slate-300 dark:border-slate-800">
                          {option.flag}
                        </code>
                      </label>
                      <input
                        type={option.type}
                        value={options[option.flag] || ""}
                        onChange={(e) => handleInput(option.flag, e.target.value)}
                        placeholder={option.placeholder}
                        disabled={scanning}
                        className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-800 rounded text-slate-900 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-600 focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-all"
                      />
                      <div className="text-xs text-slate-500 dark:text-slate-500 mt-1">{option.description}</div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Türkçe: Aksiyon butonları */}
      <div className="flex flex-wrap gap-4">
        <button
          onClick={startScan}
          disabled={scanning || !target || !!validationError}
          className="flex items-center gap-2 px-6 py-3 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 disabled:bg-slate-800/50 disabled:text-slate-600 disabled:cursor-not-allowed transition-all shadow-[0_0_20px_rgba(16,185,129,0.3)] hover:shadow-[0_0_30px_rgba(16,185,129,0.5)] font-semibold tracking-wider"
        >
          <Play size={20} />
          {scanning ? "TARAMA DEVAM EDİYOR..." : "TARAMAYI BAŞLAT"}
        </button>

        <button
          onClick={previewCommand}
          disabled={!target}
          className="flex items-center gap-2 px-6 py-3 bg-blue-500/20 backdrop-blur-sm border border-blue-500/50 text-blue-400 rounded-lg hover:bg-blue-500/30 hover:border-blue-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all font-semibold tracking-wider"
        >
          <Eye size={20} />
          KOMUTU ÖNİZLE
        </button>

        {scanId && (
          <button
            onClick={downloadLog}
            className="flex items-center gap-2 px-6 py-3 bg-slate-800/50 backdrop-blur-sm border border-slate-700 text-emerald-400 rounded-lg hover:bg-slate-700 hover:border-emerald-500/50 transition-all font-semibold tracking-wider"
          >
            <Download size={20} />
            LOG DOSYASINI İNDİR
          </button>
        )}
      </div>

      {/* Türkçe: Progress göstergesi (uzun taramalar için) */}
      {scanning && (
        <div className="bg-white dark:bg-slate-900/80 backdrop-blur-sm border border-emerald-500/30 rounded-lg p-6 shadow-[0_0_30px_rgba(16,185,129,0.1)]">
          <div className="flex items-center gap-3 mb-4">
            <Activity size={24} className="text-emerald-400 animate-pulse" />
            <h3 className="text-lg font-bold text-emerald-600 dark:text-emerald-400 tracking-wider">TARAMA DURUMU</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-100 dark:bg-slate-950/50 border border-slate-300 dark:border-slate-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400 text-sm mb-1">
                <CheckCircle size={16} />
                <span>Durum</span>
              </div>
              <p className="text-slate-900 dark:text-white font-semibold">{scanProgress.status}</p>
            </div>

            <div className="bg-slate-100 dark:bg-slate-950/50 border border-slate-300 dark:border-slate-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400 text-sm mb-1">
                <Terminal size={16} />
                <span>İşlenen Satır</span>
              </div>
              <p className="text-slate-900 dark:text-white font-semibold">{scanProgress.lineCount.toLocaleString()}</p>
            </div>

            <div className="bg-slate-100 dark:bg-slate-950/50 border border-slate-300 dark:border-slate-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400 text-sm mb-1">
                <Clock size={16} />
                <span>Son Güncelleme</span>
              </div>
              <p className="text-slate-900 dark:text-white font-semibold">{scanProgress.lastUpdate}</p>
            </div>
          </div>

          {scanProgress.discoveries > 0 && (
            <div className="mt-4 bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3">
              <p className="text-emerald-600 dark:text-emerald-400 text-sm font-medium">
                🔍 {scanProgress.discoveries} adet açık port/servis keşfedildi
              </p>
            </div>
          )}
        </div>
      )}

      {/* Türkçe: Komut Önizleme Modal */}
      {showPreview && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowPreview(false)}>
          <div className="bg-slate-900 border border-emerald-500/30 rounded-lg p-6 max-w-4xl w-full shadow-[0_0_50px_rgba(16,185,129,0.3)]" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-4">
              <h2 className="text-xl font-bold text-emerald-400 flex items-center gap-2">
                <Terminal size={24} />
                NMAP KOMUT ÖNİZLEMESİ
              </h2>
              <button onClick={() => setShowPreview(false)} className="text-slate-400 hover:text-white transition-colors">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-sm overflow-x-auto">
              <code className="text-emerald-400">{commandPreview}</code>
            </div>

            <div className="mt-4 flex gap-3">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(commandPreview);
                  alert("Komut panoya kopyalandı!");
                }}
                className="flex items-center gap-2 px-4 py-2 bg-blue-500/20 border border-blue-500/50 text-blue-400 rounded-lg hover:bg-blue-500/30 transition-all"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
                Kopyala
              </button>

              <button
                onClick={() => setShowPreview(false)}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 border border-slate-700 text-slate-400 rounded-lg hover:bg-slate-700 transition-all"
              >
                Kapat
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Türkçe: Real-time terminal çıktısı */}
      {output.length > 0 && (
        <div className="bg-slate-100 dark:bg-slate-950/80 backdrop-blur-sm border border-slate-300 dark:border-emerald-500/30 rounded-lg p-6 font-mono text-sm shadow-[0_0_30px_rgba(16,185,129,0.1)]">
          <div className="flex items-center gap-2 mb-4 text-emerald-600 dark:text-emerald-400 border-b border-slate-300 dark:border-slate-800 pb-3">
            <Terminal size={20} />
            <span className="font-semibold tracking-wider">TARAMA ÇIKTISI (REAL-TIME)</span>
          </div>
          <div className="max-h-96 overflow-y-auto whitespace-pre-wrap text-emerald-700 dark:text-emerald-400/90 leading-relaxed">
            {output.map((line, i) => (
              <div key={i} className="hover:bg-slate-200 dark:hover:bg-slate-900/50 px-2 py-0.5 rounded transition-colors">{line}</div>
            ))}
          </div>
        </div>
      )}

      {/* Türkçe: Bilgilendirme */}
      <div className="bg-emerald-50 dark:bg-emerald-500/5 backdrop-blur-sm border border-emerald-300 dark:border-emerald-500/30 rounded-lg p-4 flex gap-3 hover:bg-emerald-100 dark:hover:bg-emerald-500/10 transition-all">
        <Info size={20} className="text-emerald-600 dark:text-emerald-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-slate-700 dark:text-slate-300">
          <strong className="text-emerald-700 dark:text-emerald-400">İpucu:</strong> Yeni Nmap özellikleri eklemek için{" "}
          <code className="bg-slate-200 dark:bg-slate-950 text-emerald-700 dark:text-emerald-400 px-2 py-0.5 rounded border border-slate-300 dark:border-slate-800">
            services/nmap-service/nmap_config.json
          </code>{" "}
          dosyasını düzenleyin. Değişiklikler otomatik olarak UI'a yansır.
        </div>
      </div>

      {/* Türkçe: Kullanım Senaryoları */}
      <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-800/80 rounded-lg p-6">
        <h2 className="text-xl font-bold text-emerald-400 mb-4 tracking-wider flex items-center gap-2">
          <Info size={24} />
          KULLANIM SENARYOLARI
        </h2>

        <div className="space-y-4">
          <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-4 hover:border-emerald-500/30 transition-all">
            <h3 className="text-emerald-400 font-bold mb-2">🎯 Senaryo 1: Hızlı Ağ Taraması</h3>
            <p className="text-slate-300 text-sm mb-2">Bir ağdaki aktif hostları ve açık portları hızlıca bulmak için:</p>
            <ul className="text-slate-400 text-sm space-y-1 ml-4">
              <li>• <strong>Tarama Tipi:</strong> TCP SYN Tarama (-sS)</li>
              <li>• <strong>Port:</strong> En Popüler 1000 Port (--top-ports 1000)</li>
              <li>• <strong>Zamanlama:</strong> Aggressive (-T4)</li>
              <li>• <strong>Çıktı:</strong> Sadece Açık Portlar (--open) + Verbose (-v)</li>
              <li>• <strong>Tahmini Süre:</strong> 2-5 dakika (ağ hızına bağlı)</li>
            </ul>
          </div>

          <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-4 hover:border-emerald-500/30 transition-all">
            <h3 className="text-emerald-400 font-bold mb-2">🕵️ Senaryo 2: Gizli Tarama (IDS/IPS Atlatma)</h3>
            <p className="text-slate-300 text-sm mb-2">Güvenlik sistemlerini uyandırmadan yavaş ve gizli tarama:</p>
            <ul className="text-slate-400 text-sm space-y-1 ml-4">
              <li>• <strong>Tarama Tipi:</strong> TCP SYN Tarama (-sS)</li>
              <li>• <strong>Zamanlama:</strong> Polite veya Sneaky (-T1 veya -T2)</li>
              <li>• <strong>Firewall Atlatma:</strong> Paket Parçalama (-f) + Decoy IP'ler (-D RND:10)</li>
              <li>• <strong>Gelişmiş:</strong> Kaynak Port 53 (--source-port 53) + Host Sırası Karıştır</li>
              <li>• <strong>Tahmini Süre:</strong> 1-24 saat (zamanlama ayarına bağlı)</li>
            </ul>
          </div>

          <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-4 hover:border-emerald-500/30 transition-all">
            <h3 className="text-emerald-400 font-bold mb-2">🔒 Senaryo 3: Zafiyet Taraması (Detaylı Güvenlik Analizi)</h3>
            <p className="text-slate-300 text-sm mb-2">Tüm portları tarayıp servislerin zafiyetlerini tespit etmek:</p>
            <ul className="text-slate-400 text-sm space-y-1 ml-4">
              <li>• <strong>Tarama Tipi:</strong> TCP SYN (-sS) + UDP Tarama (-sU)</li>
              <li>• <strong>Port:</strong> Tüm Portlar (-p -)</li>
              <li>• <strong>Servis:</strong> Versiyon Tespiti (-sV) + OS Tespiti (-O)</li>
              <li>• <strong>Script:</strong> Varsayılan + Zafiyet Tarama (--script=default,vuln)</li>
              <li>• <strong>Zamanlama:</strong> Normal (-T3)</li>
              <li>• <strong>Gelişmiş:</strong> Max Retries: 3, Host Timeout: 30m</li>
              <li>• <strong>Tahmini Süre:</strong> 4-12 saat (hedef büyüklüğüne bağlı)</li>
            </ul>
          </div>

          <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-4 hover:border-emerald-500/30 transition-all">
            <h3 className="text-emerald-400 font-bold mb-2">⚡ Senaryo 4: Kurumsal Ağ Taraması (Gün Boyu Sürecek)</h3>
            <p className="text-slate-300 text-sm mb-2">Büyük ağlar için kapsamlı ve güvenli tarama:</p>
            <ul className="text-slate-400 text-sm space-y-1 ml-4">
              <li>• <strong>Tarama Tipi:</strong> TCP Connect (-sT) [Root gerekmez]</li>
              <li>• <strong>Port:</strong> Tüm TCP Portları (-p 1-65535)</li>
              <li>• <strong>Servis:</strong> Aggressive Tarama (-A) [OS + Version + Scripts]</li>
              <li>• <strong>Zamanlama:</strong> Polite (-T2) [Ağı yormaz]</li>
              <li>• <strong>Script:</strong> Varsayılan + Auth + Vuln</li>
              <li>• <strong>Gelişmiş:</strong> Max Retries: 3, Host Timeout: 1800s, Min Rate: 30, Max Rate: 958</li>
              <li>• <strong>Çıktı:</strong> Çok Detaylı (-vv) + Debug (-d) + Reason (--reason)</li>
              <li>• <strong>Tahmini Süre:</strong> 8-24 saat (ağ büyüklüğüne göre)</li>
              <li>• <strong>Önemli:</strong> Progress takibi için bu sayfayı açık tutun veya log dosyasını indirin</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
