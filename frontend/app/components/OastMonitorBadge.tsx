import { useState } from 'react';
import { Radio, AlertCircle, CheckCircle2, ChevronRight, X } from 'lucide-react';

export interface OastSummary {
  enabled: boolean;
  mock_mode?: boolean;
  domain?: string;
  tokens_generated?: number;
  interactions_count?: number;
  interactions?: Array<{
    protocol: string;
    full_id: string;
    remote_address: string;
    timestamp: string;
    marker?: string;
  }>;
}

export default function OastMonitorBadge({ oast }: { oast?: OastSummary | null }) {
  const [showModal, setShowModal] = useState(false);

  if (!oast || !oast.enabled) return null;

  const hitCount = oast.interactions_count || 0;
  const hasHits = hitCount > 0;

  return (
    <>
      <button
        type="button"
        onClick={() => setShowModal(true)}
        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border transition-all ${
          hasHits
            ? 'border-red-500/50 bg-red-500/10 text-red-500 hover:bg-red-500/20'
            : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20'
        }`}
        title={`OAST Callback Dinleyicisi (${oast.domain || 'oast.me'}) - ${hitCount} etkileşim`}
      >
        <Radio className={`w-3 h-3 ${hasHits ? 'animate-pulse text-red-500' : 'text-emerald-500'}`} />
        <span>OAST:</span>
        <span>{hasHits ? `${hitCount} Kör Callback Yakalandı!` : 'Aktif (0 Callback)'}</span>
      </button>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 text-slate-200 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Radio className="w-5 h-5 text-sky-400" />
                <h3 className="font-bold text-white text-base">OAST (Out-of-Band) Dinleyici Durumu</h3>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 my-4 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
                  <span className="text-slate-400 block mb-1">OAST Alan Adı</span>
                  <span className="font-mono font-bold text-sky-400">{oast.domain || 'oast.me'}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
                  <span className="text-slate-400 block mb-1">Üretilen Test Token'ı</span>
                  <span className="font-bold text-slate-200">{oast.tokens_generated || 0} adet</span>
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                  Yakalanan Arka Plan Geri Aramaları (Asenkron Callback)
                  <span className="ml-auto px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-400 font-mono">
                    {hitCount} adet
                  </span>
                </h4>

                {hasHits ? (
                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {(oast.interactions || []).map((hit, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg border border-red-500/30 bg-red-500/5 flex flex-col gap-1"
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 font-bold uppercase">
                            {hit.protocol}
                          </span>
                          <span className="text-slate-400 text-[11px]">{hit.timestamp}</span>
                        </div>
                        <div className="text-slate-300">
                          <span className="text-slate-400">Kaynak Backend IP:</span>{' '}
                          <span className="font-mono text-amber-400 font-semibold">{hit.remote_address}</span>
                        </div>
                        <div className="text-slate-400 text-[10px] truncate">
                          Token: <span className="font-mono text-slate-300">{hit.full_id}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-slate-800/40 border border-slate-800 text-center text-slate-400">
                    <CheckCircle2 className="w-6 h-6 mx-auto mb-1 text-emerald-400" />
                    Henüz asenkron bir geri arama (callback) gerçekleşmedi.
                    <p className="text-[11px] text-slate-500 mt-1">
                      Kör SSRF, XXE veya RCE durumunda banka backend sunucusu bu alana DNS/HTTP sinyali bırakır.
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="border-t border-slate-800 pt-3 text-right">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors"
              >
                Kapat
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
