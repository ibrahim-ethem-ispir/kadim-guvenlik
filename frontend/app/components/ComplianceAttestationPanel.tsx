import { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, Lock, HelpCircle, ChevronDown, ChevronRight } from 'lucide-react';

/**
 * AI Uyum & Güvence (attestation) paneli — compliance_map.attest_coverage çıktısının yüzü.
 *
 * Türkçe: Motorun ürettiği AI-güvenlik bulgularını STANDART diline (OWASP LLM Top-10 2025 +
 * MITRE ATLAS + NIST AI RMF + EU AI Act) çevrilmiş ve KANITA bağlı biçimde operatöre/denetçiye
 * gösterir. Manşet = TERS-KAPSAMA: "neyi test ETMEDİK" (not_tested) ve "neyi test EDEMEYİZ"
 * (not_reachable, white-box) — piyasadaki AI tarayıcıları bunu vermez; satılabilir güvence budur.
 * Backend: session.ai_analysis.compliance_attestation (scan_pipeline_v2._redteam_llm_endpoints).
 */

type ClassStatus = 'confirmed' | 'probable' | 'tested_clean' | 'not_tested' | 'not_reachable' | 'not_applicable';
type Posture = 'fail' | 'attention' | 'inconclusive' | 'pass' | 'not_applicable';

interface AttClass {
  title: string;
  status: ClassStatus;
  reason: string;
  evidence: string[];
  atlas: string;
  nist_ai_rmf: string;
  eu_ai_act: string[];
}

export interface ComplianceAttestation {
  framework: string;
  standards: string[];
  classes: Record<string, AttClass>;
  eu_ai_act: {
    primary_article: string;
    obligation: string;
    posture: Posture;
    confirmed: string[];
    gaps_not_tested: string[];
    gaps_not_reachable: string[];
  };
  /** LLM baseline echo ile doğrulandı mı? false ise sınıflar test EDİLEMEDİ (dürüst boşluk). */
  llm_confirmed?: boolean;
  note_llm?: string;
  /** Generate-and-verify aile kazanma istatistiği (experience replay): hangi strateji işe yarıyor. */
  sampling?: Record<string, { tried: number; wins: number; win_rate: number }>;
  summary: Record<string, number>;
}

// Duruş → manşet rengi + Türkçe etiket. En kötü sinyal yönetir (dürüst/muhafazakâr).
const POSTURE: Record<Posture, { label: string; tone: string; bg: string }> = {
  fail:           { label: 'UYGUNSUZLUK SİNYALİ', tone: 'text-red-500',     bg: 'bg-red-500/10 border-red-500/30' },
  attention:      { label: 'DİKKAT',              tone: 'text-orange-500',  bg: 'bg-orange-500/10 border-orange-500/30' },
  inconclusive:   { label: 'SONUÇSUZ (kapsam boşluğu)', tone: 'text-sky-500', bg: 'bg-sky-500/10 border-sky-500/30' },
  pass:           { label: 'GEÇTİ',               tone: 'text-emerald-500', bg: 'bg-emerald-500/10 border-emerald-500/30' },
  not_applicable: { label: 'AI YÜZEYİ YOK',       tone: 'text-slate-500',   bg: 'bg-slate-500/10 border-slate-500/30' },
};

// Sınıf durumu → ikon + renk + kısa etiket.
const STATUS: Record<ClassStatus, { label: string; tone: string; Icon: any }> = {
  confirmed:      { label: 'kanıtlı',       tone: 'text-red-500',     Icon: ShieldAlert },
  probable:       { label: 'olası',         tone: 'text-orange-500',  Icon: AlertTriangle },
  tested_clean:   { label: 'temiz',         tone: 'text-emerald-500', Icon: CheckCircle2 },
  not_tested:     { label: 'test edilmedi', tone: 'text-amber-500',   Icon: AlertTriangle },
  not_reachable:  { label: 'white-box',     tone: 'text-slate-400',   Icon: Lock },
  not_applicable: { label: 'n/a',           tone: 'text-slate-400',   Icon: HelpCircle },
};

export default function ComplianceAttestationPanel({ attestation }: { attestation?: ComplianceAttestation | null }) {
  const [showAll, setShowAll] = useState(false);

  // Degrade-safe: veri yoksa / boşsa hiç render etme (eski taramalar bu alana sahip değil).
  if (!attestation || !attestation.classes || Object.keys(attestation.classes).length === 0) {
    return null;
  }

  const eu = attestation.eu_ai_act || ({} as ComplianceAttestation['eu_ai_act']);
  const posture = POSTURE[eu.posture] || POSTURE.inconclusive;
  const notTested = eu.gaps_not_tested || [];
  const notReachable = eu.gaps_not_reachable || [];
  const summary = attestation.summary || {};
  const classEntries = Object.entries(attestation.classes);

  return (
    <div className="p-5 rounded-xl border border-violet-500/30 bg-violet-500/5">
      {/* Başlık + EU AI Act duruşu */}
      <div className="flex items-center gap-2 mb-1">
        <ShieldCheck className="w-5 h-5 text-violet-500" />
        <h3 className="font-bold text-slate-900 dark:text-white">AI Uyum & Güvence</h3>
        <span className={`ml-auto text-xs font-bold px-2 py-1 rounded-md border ${posture.bg} ${posture.tone}`}>
          EU AI Act Art.15: {posture.label}
        </span>
      </div>
      <p className="text-[11px] text-slate-400 mb-3">
        {attestation.framework} · her sınıf için kanıtlı durum + <span className="italic">neyi test etmediğimiz</span>.
        Duruş, en kötü sinyalce belirlenir (kanıtlı bulgu → uygunsuzluk; kapsam boşluğu → "geçti" DEMEYİZ).
      </p>

      {/* LLM doğrulanamadı uyarısı: AI yolu var ama baseline echo yok → sınıflar test EDİLEMEDİ.
          Panelin sessizce kaybolması yerine boşluğu açıkça gösterir (yanlış güven önlenir). */}
      {attestation.llm_confirmed === false && (
        <div className="flex items-start gap-2 mb-3 text-[11px] text-amber-600 dark:text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{attestation.note_llm || 'LLM doğrulanamadı — AI sınıfları test EDİLEMEDİ.'}</span>
        </div>
      )}

      {/* Standart rozetleri */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        {(attestation.standards || []).map((s) => (
          <span key={s} className="text-[10px] px-2 py-0.5 rounded bg-violet-500/10 text-violet-600 dark:text-violet-300">
            {s}
          </span>
        ))}
      </div>

      {/* Sayaç şeridi */}
      <div className="flex flex-wrap gap-2 mb-4 text-xs">
        {summary.confirmed ? (
          <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-red-500/10 text-red-600 dark:text-red-400">
            <ShieldAlert className="w-3 h-3" /> {summary.confirmed} kanıtlı
          </span>
        ) : null}
        {summary.probable ? (
          <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-orange-500/10 text-orange-600 dark:text-orange-400">
            <AlertTriangle className="w-3 h-3" /> {summary.probable} olası
          </span>
        ) : null}
        {summary.tested_clean ? (
          <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="w-3 h-3" /> {summary.tested_clean} temiz
          </span>
        ) : null}
        {summary.not_tested ? (
          <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400">
            <AlertTriangle className="w-3 h-3" /> {summary.not_tested} test edilmedi
          </span>
        ) : null}
        {summary.not_reachable ? (
          <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-slate-500/10 text-slate-500 dark:text-slate-400">
            <Lock className="w-3 h-3" /> {summary.not_reachable} white-box
          </span>
        ) : null}
      </div>

      {/* ADAY AİLELERİ (generate-and-verify · experience replay): hangi strateji kanıt üretiyor
          → sonraki taramalarda aday önceliğini besler. Karar değil, öncelik sinyali. */}
      {attestation.sampling && Object.keys(attestation.sampling).length > 0 && (
        <div className="mb-4">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
            Aday aileleri (kazanma oranı)
          </div>
          <div className="flex flex-wrap gap-2 text-[11px]">
            {Object.entries(attestation.sampling).map(([fam, s]) => (
              <span key={fam}
                className="px-2 py-0.5 rounded bg-violet-500/10 text-violet-600 dark:text-violet-300 font-mono">
                {fam}: {Math.round((s.win_rate ?? 0) * 100)}% ({s.wins}/{s.tried})
              </span>
            ))}
          </div>
        </div>
      )}

      {/* MANŞET: TERS-KAPSAMA — asıl güvence değeri. Kanıtlı bulgular + test edilmeyenler. */}
      {eu.confirmed && eu.confirmed.length > 0 && (
        <div className="mb-3 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
          <h4 className="text-xs font-bold text-red-500 mb-1.5 uppercase flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" /> Kanıtlanan sınıflar ({eu.confirmed.length})
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {eu.confirmed.map((k) => (
              <span key={k} className="text-xs font-semibold text-red-600 dark:text-red-300">
                {k} {attestation.classes[k]?.title}
              </span>
            ))}
          </div>
        </div>
      )}
      {notTested.length > 0 && (
        <div className="mb-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
          <h4 className="text-xs font-bold text-amber-500 mb-1.5 uppercase flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" /> Test edilmeyenler — kapsam boşluğu ({notTested.length})
          </h4>
          <ul className="space-y-1">
            {notTested.map((k) => (
              <li key={k} className="text-xs text-slate-600 dark:text-slate-300 flex gap-2">
                <span className="text-amber-500 mt-0.5">•</span>
                <span><span className="font-semibold">{k}</span> {attestation.classes[k]?.title}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {notReachable.length > 0 && (
        <p className="mb-4 text-[11px] text-slate-500 dark:text-slate-400 flex items-start gap-1.5">
          <Lock className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">Kara-kutuda test edilemez</span> (white-box/kimlikli erişim gerekir):{' '}
            {notReachable.map((k) => `${k} ${attestation.classes[k]?.title || ''}`).join(', ')}.
          </span>
        </p>
      )}

      {/* Tüm sınıf matrisi — katlanabilir. */}
      <button
        onClick={() => setShowAll((v) => !v)}
        className="flex items-center gap-1 text-xs font-semibold text-violet-500 hover:text-violet-400 transition-colors"
      >
        {showAll ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        Tüm sınıflar ({classEntries.length})
      </button>
      {showAll && (
        <ul className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5">
          {classEntries.map(([code, c]) => {
            const st = STATUS[c.status] || STATUS.not_applicable;
            const Icon = st.Icon;
            return (
              <li key={code} className="flex items-center gap-2 text-xs" title={c.reason}>
                <Icon className={`w-3.5 h-3.5 shrink-0 ${st.tone}`} />
                <span className="text-slate-500 dark:text-slate-400 font-mono">{code}</span>
                <span className="text-slate-700 dark:text-slate-300 truncate">{c.title}</span>
                <span className={`ml-auto ${st.tone}`}>
                  {c.status === 'confirmed' && c.evidence?.length ? `${c.evidence.length} kanıt` : st.label}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
