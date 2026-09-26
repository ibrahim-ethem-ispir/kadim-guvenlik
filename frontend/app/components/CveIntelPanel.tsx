import { Brain, ShieldAlert, FileCode2, Bug, AlertTriangle, Zap, KeyRound } from 'lucide-react';

// vulnx (ProjectDiscovery PDCP) CVE istihbaratı — orchestrator ai_analysis.cve_intel.
interface CveResult {
  cve: string;
  severity?: string | null;
  cvss?: number | null;
  epss?: number | null;
  epss_pct?: number | null;
  is_kev?: boolean;
  is_poc?: boolean;
  poc_count?: number;
  is_template?: boolean;
  is_remote?: boolean;
  is_patch_available?: boolean;
  product?: string | null;
  vendor?: string | null;
}

export interface CveIntelData {
  enabled?: boolean;
  has_key?: boolean;
  results?: Record<string, CveResult>;
  checked?: string[];
  skipped?: Array<{ cve: string; reason: string }>;
  rate_limited?: boolean;
  note?: string;
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };

function sevClass(sev?: string | null): string {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 'bg-red-500/15 text-red-500 border-red-500/30';
    case 'high': return 'bg-orange-500/15 text-orange-500 border-orange-500/30';
    case 'medium': return 'bg-amber-500/15 text-amber-500 border-amber-500/30';
    case 'low': return 'bg-sky-500/15 text-sky-500 border-sky-500/30';
    default: return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  }
}

export default function CveIntelPanel({ cveIntel }: { cveIntel?: CveIntelData | null }) {
  if (!cveIntel || !cveIntel.enabled) return null;

  const results = Object.values(cveIntel.results || {});
  const rateLimited = (cveIntel.skipped || []).filter((s) => s.reason === 'rate_limit').map((s) => s.cve);
  const capped = (cveIntel.skipped || []).filter((s) => s.reason === 'cap').map((s) => s.cve);

  if (results.length === 0 && rateLimited.length === 0 && capped.length === 0) return null;

  results.sort((a, b) => {
    const s = (SEV_ORDER[(a.severity || 'none').toLowerCase()] ?? 4) - (SEV_ORDER[(b.severity || 'none').toLowerCase()] ?? 4);
    return s !== 0 ? s : (b.epss || 0) - (a.epss || 0);
  });

  return (
    <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 p-5 shadow-sm">
      <div className="flex items-center gap-2 mb-1">
        <Brain className="w-5 h-5 text-indigo-500 dark:text-indigo-400" />
        <h3 className="text-base font-bold text-slate-900 dark:text-white">CVE İstihbaratı (vulnx)</h3>
        <span className="ml-auto text-[10px] font-mono text-slate-400">
          {cveIntel.has_key ? 'PDCP anahtarı: var' : 'anahtarsız (10/dk)'}
        </span>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
        Her CVE için EPSS + KEV + PoC + hazır nuclei-template varlığı — "açık var" değil "şununla doğrulanabilir".
      </p>

      {/* RATE-LIMIT GÖRÜNÜRLÜĞÜ — "bakılacaktı ama bakılamadı" (sessiz yutma yok). */}
      {rateLimited.length > 0 && (
        <div className="mb-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400 text-xs">
          <div className="flex items-center gap-1.5 font-semibold mb-1">
            <AlertTriangle className="w-4 h-4" />
            Dakikalık limit doldu — {rateLimited.length} CVE bakılacaktı ama bakılamadı
          </div>
          <div className="flex flex-wrap gap-1 mb-1.5">
            {rateLimited.map((c) => (
              <span key={c} className="px-1.5 py-0.5 rounded bg-amber-500/15 font-mono text-[10px]">{c}</span>
            ))}
          </div>
          <div className="flex items-center gap-1 text-[11px] opacity-90">
            <KeyRound className="w-3 h-3" />
            Ücretsiz PDCP anahtarı (cloud.projectdiscovery.io → .env: PDCP_API_KEY) ile bu limit kalkar.
          </div>
        </div>
      )}

      {capped.length > 0 && (
        <div className="mb-3 text-[11px] text-slate-500 dark:text-slate-400">
          Bu taramada bütçe doldu ({capped.length} CVE atlandı) — VULNX_MAX_LOOKUPS ile artırılabilir.
        </div>
      )}

      {/* Bakılan CVE'ler */}
      <div className="space-y-1.5 max-h-[24rem] overflow-y-auto pr-1">
        {results.map((c) => (
          <div key={c.cve} className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-700/50 bg-slate-50 dark:bg-slate-800/40 flex items-center gap-2 flex-wrap">
            <span className="font-mono font-semibold text-slate-800 dark:text-slate-100 text-xs">{c.cve}</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${sevClass(c.severity)}`}>
              {(c.severity || '?').toUpperCase()}{typeof c.cvss === 'number' ? ` ${c.cvss}` : ''}
            </span>
            {typeof c.epss === 'number' && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-slate-500/10 text-slate-500 dark:text-slate-300 font-mono">
                <Zap className="w-3 h-3" /> EPSS {(c.epss * 100).toFixed(1)}%
              </span>
            )}
            {c.is_kev && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-red-500/15 text-red-500 font-semibold">
                <ShieldAlert className="w-3 h-3" /> KEV (aktif sömürü)
              </span>
            )}
            {c.is_poc && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-orange-500/15 text-orange-500 font-semibold">
                <Bug className="w-3 h-3" /> PoC{c.poc_count ? ` ×${c.poc_count}` : ''}
              </span>
            )}
            {c.is_template && (
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/15 text-emerald-500 font-semibold">
                <FileCode2 className="w-3 h-3" /> nuclei-template
              </span>
            )}
            {(c.product || c.vendor) && (
              <span className="ml-auto text-[10px] text-slate-400 font-mono truncate max-w-[40%]" title={`${c.vendor || ''} ${c.product || ''}`}>
                {[c.vendor, c.product].filter(Boolean).join(' / ')}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
