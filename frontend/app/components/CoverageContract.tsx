import { useState } from 'react';
import { ShieldCheck, AlertTriangle, CheckCircle2, Search, ChevronDown, ChevronRight } from 'lucide-react';

/**
 * Kapsama Sözleşmesi paneli (B adımı — A1'in ekrandaki yüzü).
 *
 * Türkçe: Motorun "whack-a-mole" hastalığının panzehiri olan coverage_contract çıktısını
 * operatöre GÖSTERİR. Amaç kullanıcının "IP buldum ama UI'da göremiyorum / bir sınıf sessizce
 * kaçıyor" şikayetini kapatmak: her taban-tespit-sınıfı için bulundu/temiz/kontrol-edilemedi
 * DURUMU + kontrol-edilemediyse NEDENİ ekrana çıkar. Manşet = "gaps" (ne taranMADI), çünkü
 * asıl güven kaybı orada. Backend: summary["coverage_contract"] (scan_pipeline_v2).
 */

type CovStatus = 'found' | 'clean' | 'not_checked';

interface CoverageClass {
  key: string;
  label: string;
  family: string;
  status: CovStatus;
  status_label: string;
  reason: string;
  finding_count: number;
  top_severity: string | null;
  confirmed: boolean;
}

interface CoverageGap {
  key: string;
  label: string;
  reason: string;
  family: string;
}

export interface CoverageData {
  classes: CoverageClass[];
  found: number;
  clean: number;
  not_checked: number;
  total: number;
  coverage_percent: number;
  gaps: CoverageGap[];
  generated?: string;
}

// Bulgu şiddetine göre renk (bulundu sınıflarında bulgu sayısını renklendirir).
function sevTone(sev: string | null): string {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': return 'text-amber-500';
    case 'low': return 'text-yellow-500';
    default: return 'text-cyan-500';
  }
}

// Kapsam yüzdesi rengi — düşük kapsam = güven düşük (kırmızı), yüksek = yeşil.
function coverageTone(pct: number): string {
  if (pct >= 80) return 'text-emerald-500';
  if (pct >= 50) return 'text-amber-500';
  return 'text-red-500';
}

function StatusIcon({ status }: { status: CovStatus }) {
  if (status === 'found') return <Search className="w-3.5 h-3.5 text-cyan-500 shrink-0" />;
  if (status === 'clean') return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />;
  return <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />;
}

export default function CoverageContract({ coverage }: { coverage?: CoverageData | null }) {
  const [showAll, setShowAll] = useState(false);

  // Veri yoksa / boşsa hiç render etme (degrade-safe — eski taramalar bu alana sahip değil).
  if (!coverage || !Array.isArray(coverage.classes) || coverage.classes.length === 0) {
    return null;
  }

  const gaps = Array.isArray(coverage.gaps) ? coverage.gaps : [];
  const pct = coverage.coverage_percent ?? 0;

  return (
    <div className="p-6 rounded-xl border border-sky-500/30 bg-sky-500/5">
      {/* Başlık + kapsam yüzdesi */}
      <div className="flex items-center gap-2 mb-1">
        <ShieldCheck className="w-5 h-5 text-sky-500" />
        <h3 className="font-bold text-slate-900 dark:text-white">Kapsama Sözleşmesi</h3>
        <span className={`ml-auto text-2xl font-bold ${coverageTone(pct)}`}>{pct}%</span>
      </div>
      <p className="text-[11px] text-slate-400 mb-3">
        Her taban-tespit sınıfı için ne kontrol edildi, ne edilemedi. Kapsam = incelenen
        (bulundu + temiz) / toplam — bulgu sayısı değil, <span className="italic">ne kadarını gerçekten baktık</span>.
      </p>

      {/* Sayaç şeridi */}
      <div className="flex flex-wrap gap-2 mb-4 text-xs">
        <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-cyan-500/10 text-cyan-600 dark:text-cyan-400">
          <Search className="w-3 h-3" /> {coverage.found} bulundu
        </span>
        <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
          <CheckCircle2 className="w-3 h-3" /> {coverage.clean} temiz
        </span>
        <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400">
          <AlertTriangle className="w-3 h-3" /> {coverage.not_checked} kontrol-edilemedi
        </span>
      </div>

      {/* MANŞET: BOŞLUKLAR — "ne taranMADI + neden". Asıl değer burada; hep açık. */}
      {gaps.length > 0 && (
        <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
          <h4 className="text-xs font-bold text-amber-500 mb-2 uppercase flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            Kontrol Edilemeyenler ({gaps.length})
          </h4>
          <ul className="space-y-1.5">
            {gaps.map((g) => (
              <li key={g.key} className="text-xs text-slate-600 dark:text-slate-300 flex gap-2">
                <span className="text-amber-500 mt-0.5">•</span>
                <span>
                  <span className="font-semibold">{g.label}</span>
                  <span className="text-slate-500 dark:text-slate-400"> — {g.reason}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Tüm sınıf matrisi — katlanabilir (bulundu/temiz gürültü yapmasın). */}
      <button
        onClick={() => setShowAll((v) => !v)}
        className="flex items-center gap-1 text-xs font-semibold text-sky-500 hover:text-sky-400 transition-colors"
      >
        {showAll ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        Tüm sınıflar ({coverage.total})
      </button>
      {showAll && (
        <ul className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5">
          {coverage.classes.map((c) => (
            <li key={c.key} className="flex items-center gap-2 text-xs">
              <StatusIcon status={c.status} />
              <span className="text-slate-700 dark:text-slate-300 truncate" title={c.reason}>
                {c.label}
              </span>
              {c.status === 'found' && c.finding_count > 0 && (
                <span className={`ml-auto font-bold ${sevTone(c.top_severity)}`}>
                  {c.finding_count}
                </span>
              )}
              {c.status === 'clean' && (
                <span className="ml-auto text-emerald-500/70">temiz</span>
              )}
              {c.status === 'not_checked' && (
                <span className="ml-auto text-amber-500/70">—</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
