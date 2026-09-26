import { useState } from "react";
import { X, Save, Settings, Zap, Clock, Terminal } from "lucide-react";

interface RustScanConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (options: any) => void;
  initialOptions: any;
}

export default function RustScanConfigModal({ isOpen, onClose, onSave, initialOptions }: RustScanConfigModalProps) {
  const [options, setOptions] = useState<any>(initialOptions || {
    batch_size: 5000,
    timeout: 2000,
    nmap_args: "-sV"
  });

  if (!isOpen) return null;

  const handleSave = () => {
    onSave(options);
    onClose();
  };

  return (
    <div className="fixed inset-0 !z-[9999] flex items-center justify-center bg-slate-950/40 backdrop-blur-md p-4 animate-in fade-in duration-200">
      <div className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-2xl flex flex-col shadow-2xl shadow-orange-900/10 animate-in zoom-in-95 duration-200 overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-orange-500/10 rounded-xl border border-orange-500/20 shadow-lg shadow-orange-900/20">
              <Zap className="w-6 h-6 text-orange-500" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">RustScan Yapılandırması</h2>
              <p className="text-sm text-slate-400">Ultra hızlı port tarama ayarları</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-all hover:rotate-90 duration-300"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content */}
        <div className="p-8 space-y-6 bg-slate-900/30">

          {/* Info Card */}
          <div className="p-4 rounded-xl bg-orange-500/5 border border-orange-500/10 mb-6 flex gap-3">
            <div className="p-2 bg-orange-500/10 rounded-lg h-fit shrink-0">
              <Settings className="w-4 h-4 text-orange-400" />
            </div>
            <p className="text-sm text-slate-400 leading-relaxed">
              RustScan, portları saniyeler içinde bulmak için tasarlanmıştır. Bulunan portlar otomatik olarak derinlemesine analiz için Nmap'e aktarılır.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Batch Size */}
            <div className="space-y-3 group">
              <label className="flex items-center gap-2 text-sm font-medium text-slate-300 group-hover:text-orange-400 transition-colors">
                <Settings className="w-4 h-4 text-orange-500" />
                Batch Size (Limit)
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={options.batch_size}
                  onChange={(e) => setOptions({ ...options, batch_size: parseInt(e.target.value) })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all placeholder-slate-600"
                  placeholder="Örn: 5000"
                />
              </div>
              <p className="text-xs text-slate-500 group-hover:text-slate-400 transition-colors">Eşzamanlı açılacak bağlantı sayısı. Yüksek değerler = Yüksek hız.</p>
            </div>

            {/* Timeout */}
            <div className="space-y-3 group">
              <label className="flex items-center gap-2 text-sm font-medium text-slate-300 group-hover:text-orange-400 transition-colors">
                <Clock className="w-4 h-4 text-orange-500" />
                Timeout (ms)
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={options.timeout}
                  onChange={(e) => setOptions({ ...options, timeout: parseInt(e.target.value) })}
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all placeholder-slate-600"
                  placeholder="Örn: 2000"
                />
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500">ms</span>
              </div>
              <p className="text-xs text-slate-500 group-hover:text-slate-400 transition-colors">Port başına maksimum bekleme süresi.</p>
            </div>
          </div>

          {/* Nmap Args */}
          <div className="space-y-3 pt-2 group">
            <label className="flex items-center gap-2 text-sm font-medium text-slate-300 group-hover:text-orange-400 transition-colors">
              <Terminal className="w-4 h-4 text-orange-500" />
              Nmap Argümanları
            </label>
            <div className="flex bg-slate-900 border border-slate-700 rounded-xl overflow-hidden focus-within:border-orange-500 focus-within:ring-1 focus-within:ring-orange-500 transition-all">
              <div className="pl-4 py-3 text-slate-500 font-mono text-sm select-none">nmap</div>
              <input
                type="text"
                value={options.nmap_args}
                onChange={(e) => setOptions({ ...options, nmap_args: e.target.value })}
                className="flex-1 bg-transparent border-none text-white px-2 py-3 focus:ring-0 focus:outline-none font-mono text-sm placeholder-slate-600"
                placeholder="-sV -O -sC"
              />
            </div>
            <p className="text-xs text-slate-500 group-hover:text-slate-400 transition-colors">
              Keşfedilen portlar üzerinde çalıştırılacak Nmap komutları.
            </p>
          </div>

        </div>

        {/* Footer */}
        <div className="p-6 border-t border-slate-800 bg-slate-900/50 backdrop-blur-md flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-6 py-2.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-xl transition-colors font-medium border border-transparent hover:border-slate-700"
          >
            İptal
          </button>
          <button
            onClick={handleSave}
            className="flex items-center gap-2 px-8 py-2.5 bg-gradient-to-r from-orange-600 to-orange-500 hover:from-orange-500 hover:to-orange-400 text-white font-medium rounded-xl transition-all shadow-lg shadow-orange-500/20 hover:shadow-orange-500/30 transform hover:-translate-y-0.5"
          >
            <Save className="w-4 h-4" />
            Kaydet
          </button>
        </div>
      </div>
    </div>
  );
}
