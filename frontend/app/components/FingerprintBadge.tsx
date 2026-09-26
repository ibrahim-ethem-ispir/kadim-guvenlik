import { useState } from 'react';
import { Fingerprint, X } from 'lucide-react';
import FingerprintPanel, { type FingerprintData } from './FingerprintPanel';

// auto-scan başlığındaki rozet: tıkla → modalda tespit edilen teknolojiler (paylaşılan panel).
export type { FingerprintData, FingerprintTech } from './FingerprintPanel';

export default function FingerprintBadge({ fingerprint }: { fingerprint?: FingerprintData | null }) {
  const [showModal, setShowModal] = useState(false);

  const techs = fingerprint?.technologies || [];
  if (!fingerprint || techs.length === 0) return null;

  const count = fingerprint.count || techs.length;

  return (
    <>
      <button
        type="button"
        onClick={() => setShowModal(true)}
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border border-indigo-500/40 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 transition-all align-middle"
        title={`Parmak İzi (${fingerprint.engine || 'wappalyzergo'}) — ${count} teknoloji tanımlandı`}
      >
        <Fingerprint className="w-3 h-3 text-indigo-400" />
        <span>Parmak İzi: {count} Teknoloji</span>
      </button>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div className="w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 p-6 text-slate-200 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-white text-base">Tespit Edilen Teknolojiler (Parmak İzi)</h3>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <FingerprintPanel fingerprint={fingerprint} maxHeightClass="max-h-[26rem]" />

            <div className="border-t border-slate-800 pt-3 mt-4 text-right">
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
