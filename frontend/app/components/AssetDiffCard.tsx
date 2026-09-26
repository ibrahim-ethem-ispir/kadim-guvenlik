import { useState } from 'react';
import { Radar, PlusCircle, MinusCircle, RefreshCw, ChevronDown, ChevronRight, Sparkles } from 'lucide-react';

export interface AssetDiffData {
  has_changes: boolean;
  is_baseline?: boolean;
  message?: string;
  new_ports?: Array<{
    port: number;
    protocol: string;
    service?: string;
    product?: string;
    version?: string;
  }>;
  closed_ports?: Array<{
    port: number;
    protocol: string;
    service?: string;
    product?: string;
  }>;
  changed_services?: Array<{
    port_key: string;
    old: string;
    new: string;
  }>;
  new_technologies?: string[];
  removed_technologies?: string[];
}

export default function AssetDiffCard({ diff }: { diff?: AssetDiffData | null }) {
  const [expanded, setExpanded] = useState(false);

  if (!diff) return null;

  const newPorts = diff.new_ports || [];
  const closedPorts = diff.closed_ports || [];
  const changedServices = diff.changed_services || [];
  const hasChanges = diff.has_changes;

  return (
    <div className="p-5 rounded-xl border border-indigo-500/30 bg-indigo-500/5 transition-all">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Radar className="w-5 h-5 text-indigo-400" />
          <h3 className="font-bold text-slate-900 dark:text-white text-sm">
            Varlık Radarı (Zaman Serisi Değişim Takibi)
          </h3>
          {diff.is_baseline ? (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-500/20 text-slate-400">
              Referans Tabanı (Baseline)
            </span>
          ) : hasChanges ? (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-500/20 text-amber-400 animate-pulse">
              Değişim Tespit Edildi!
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/20 text-emerald-400">
              Değişim Yok (Stabil)
            </span>
          )}
        </div>

        {hasChanges && (
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium"
          >
            {expanded ? 'Daralt' : 'Detaylar'}
            {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      <p className="text-xs text-slate-400 mb-3">
        {diff.is_baseline
          ? 'Hedef için ilk tarama kaydı oluşturuldu. Gelecekteki tekrarlı veya zamanlanmış taramalarda açılan yeni portlar ve değişen servisler burada karşılaştırılacaktır.'
          : hasChanges
          ? 'Önceki tarama snapshot\'ına kıyasla hedefin dış saldırı yüzeyinde port/servis seviyesinde değişim tespit edildi.'
          : 'Önceki taramaya kıyasla açık port ve servis profilinde herhangi bir değişiklik tespit edilmedi (yüzey stabil).'}
      </p>

      {/* Özet sayaçlar */}
      {hasChanges && (
        <div className="flex flex-wrap gap-2 text-xs mb-2">
          {newPorts.length > 0 && (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 font-semibold">
              <PlusCircle className="w-3.5 h-3.5" /> {newPorts.length} Yeni Açılan Port!
            </span>
          )}
          {changedServices.length > 0 && (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-400 font-semibold">
              <RefreshCw className="w-3.5 h-3.5" /> {changedServices.length} Değişen Servis / Sürüm
            </span>
          )}
          {closedPorts.length > 0 && (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-slate-400">
              <MinusCircle className="w-3.5 h-3.5" /> {closedPorts.length} Kapanan Port
            </span>
          )}
        </div>
      )}

      {/* Detay Listesi */}
      {expanded && hasChanges && (
        <div className="mt-3 pt-3 border-t border-indigo-500/20 space-y-3 text-xs">
          {newPorts.length > 0 && (
            <div>
              <h4 className="font-semibold text-red-400 mb-1.5 flex items-center gap-1">
                <PlusCircle className="w-3.5 h-3.5" /> Yeni Açılan Portlar (Kritik Yüzey Genişlemesi)
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {newPorts.map((p, i) => (
                  <div key={i} className="p-2 rounded bg-red-500/5 border border-red-500/20 font-mono text-[11px]">
                    <span className="font-bold text-red-300">{p.port}/{p.protocol}</span>{' '}
                    <span className="text-slate-400">({p.service})</span>
                    {p.product && <div className="text-slate-300 text-[10px]">{p.product} {p.version}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {changedServices.length > 0 && (
            <div>
              <h4 className="font-semibold text-amber-400 mb-1.5 flex items-center gap-1">
                <RefreshCw className="w-3.5 h-3.5" /> Değişen Servis ve Versiyonlar
              </h4>
              <div className="space-y-1.5">
                {changedServices.map((c, i) => (
                  <div key={i} className="p-2 rounded bg-amber-500/5 border border-amber-500/20 text-[11px]">
                    <span className="font-mono font-bold text-amber-300">{c.port_key}:</span>{' '}
                    <span className="line-through text-slate-500">{c.old}</span>{' '}
                    <span className="text-indigo-400">➔</span>{' '}
                    <span className="font-semibold text-slate-200">{c.new}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
