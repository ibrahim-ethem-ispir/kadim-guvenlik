import { useState } from 'react';
import { Activity, Brain, RefreshCw, AlertTriangle, XCircle, Info, ChevronDown, ChevronUp } from 'lucide-react';
import type { EngineNotice } from '../hooks/usePipelineStream';

/**
 * Motor Farkındalığı paneli — otonom motorun KENDİSİ HAKKINDAKİ canlı sinyalleri:
 *  - loop-guard: davranış denetimi bir aracın takıntılı tekrarını yakaladı (skor cezası uygulandı)
 *  - memory: vektör hafıza geçmiş taramalardan benzer ders/bulgu hatırladı
 *  - warning/error: düşen servis, degrade aşama, doğrulama uyarısı (eskiden SESSİZCE düşüyordu)
 *
 * Kurumsal değer: operatör "motor neden bu hamleyi seçti / neden yavaş / hangi servis yok"
 * sorularını log kazmadan görür. Bildirim yoksa panel HİÇ render edilmez (gürültü sıfır).
 */

const KIND_META: Record<EngineNotice['kind'], {
  label: string;
  icon: typeof Brain;
  chip: string;
  border: string;
}> = {
  'loop-guard': {
    label: 'Davranış Denetimi',
    icon: RefreshCw,
    chip: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    border: 'border-l-amber-500',
  },
  memory: {
    label: 'Vektör Hafıza',
    icon: Brain,
    chip: 'bg-violet-500/10 text-violet-500 border-violet-500/30',
    border: 'border-l-violet-500',
  },
  warning: {
    label: 'Uyarı',
    icon: AlertTriangle,
    chip: 'bg-orange-500/10 text-orange-500 border-orange-500/30',
    border: 'border-l-orange-500',
  },
  error: {
    label: 'Hata',
    icon: XCircle,
    chip: 'bg-red-500/10 text-red-500 border-red-500/30',
    border: 'border-l-red-500',
  },
  info: {
    label: 'Bilgi',
    icon: Info,
    chip: 'bg-slate-500/10 text-slate-500 border-slate-500/30',
    border: 'border-l-slate-500',
  },
};

function saat(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString('tr-TR', { hour12: false });
  } catch {
    return '';
  }
}

export default function EngineAwareness({ notices }: { notices: EngineNotice[] }) {
  const [open, setOpen] = useState(true);
  if (!notices.length) return null;

  // Özet sayaçlar — başlıkta tür bazında rozet (hızlı triage).
  const counts = notices.reduce<Record<string, number>>((acc, n) => {
    acc[n.kind] = (acc[n.kind] || 0) + 1;
    return acc;
  }, {});
  const kritik = (counts['error'] || 0) + (counts['loop-guard'] || 0);

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between gap-2 px-4 py-3 text-left hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
        data-testid="engine-awareness-toggle"
      >
        <div className="flex items-center gap-2 min-w-0">
          <Activity className="w-4 h-4 text-cyan-500 shrink-0" />
          <span className="text-sm font-semibold text-slate-900 dark:text-white">
            Motor Farkındalığı
          </span>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {notices.length} bildirim
          </span>
          {kritik > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-500/10 text-red-500 border border-red-500/30">
              {kritik} kritik
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {(['loop-guard', 'memory', 'warning', 'error'] as const).map(k => (
            counts[k] ? (
              <span key={k} className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full border ${KIND_META[k].chip}`}>
                {counts[k]} {KIND_META[k].label}
              </span>
            ) : null
          ))}
          {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </div>
      </button>

      {open && (
        <div className="max-h-64 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/70 border-t border-slate-100 dark:border-slate-800">
          {/* Kronolojik: en yeni üstte — operatör son durumu ilk görür. */}
          {[...notices].reverse().map(n => {
            const meta = KIND_META[n.kind] || KIND_META.info;
            const Icon = meta.icon;
            return (
              <div key={n.id} className={`flex items-start gap-3 px-4 py-2.5 border-l-2 ${meta.border}`}>
                <Icon className="w-4 h-4 shrink-0 mt-0.5 text-slate-500 dark:text-slate-400" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${meta.chip}`}>
                      {meta.label}
                    </span>
                    {typeof n.step === 'number' && (
                      <span className="text-[10px] text-slate-400 font-mono">adım {n.step}</span>
                    )}
                    <span className="text-[10px] text-slate-400 font-mono ml-auto">{saat(n.at)}</span>
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 mt-1 break-words">{n.message}</p>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
