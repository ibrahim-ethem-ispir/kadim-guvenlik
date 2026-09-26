import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Brain, Play, Radar, AlertTriangle, CheckCircle2, Wifi, WifiOff,
  ChevronDown, ChevronUp, Target, Filter, ArrowDown, Clock, FlaskConical,
  Eye, EyeOff, X, Loader2, Database, Copy, Check, FileJson, ScrollText,
  ShieldAlert, FolderSearch, Swords, ExternalLink, Globe, Download, Terminal,
} from 'lucide-react';
import { usePipelineStream, type AgentStep, type TargetProfileData, type EvidenceCard, type UsePipelineStreamReturn, type EngineActivity } from '../hooks/usePipelineStream';
import { api } from '../services/api';
// Kademe rozeti ortak bileşeni (FAQ 4.1) — TIER_BADGE ikiz kopyası buraya göçtü.
import TierBadge from './TierBadge';

interface AutonomousTimelineProps {
  scanId: string;
  /** İki fazlı onay kapısı için — /v2/scan/{sessionId}/approve session_id ister. */
  sessionId?: string;
  /** session.ai_analysis.agent_timeline'dan (EKSİK-0, kalıcı kaynak) — reconnect/açılışta seed. */
  initialTimeline?: RawTimelineEntry[];
  /** session tamamlandığında engine.summary() çıktısı. */
  summary?: Record<string, any>;
  /** Onay kapısı için başlangıç durumu (reconnect: session.status==='awaiting_approval'). */
  initialPhaseGate?: Record<string, any> | null;
  /** TEK-WS DOKTRİNİ: parent (auto-scan) zaten aynı scan_id'ye canlı akış kuruyorsa
   *  stream'i buraya geçir — bileşen İKİNCİ bir WebSocket açmaz. Verilmezse (ör.
   *  results.tsx statik görünümü) kendi akışını kurar (eski davranış). */
  stream?: UsePipelineStreamReturn;
}

interface RawTimelineEntry {
  event_type: string;
  message: string;
  data: Record<string, any>;
  timestamp: string;
}

const SOURCE_BADGE: Record<string, string> = {
  llm: 'bg-violet-500/10 text-violet-500 border-violet-500/30',
  rules: 'bg-blue-500/10 text-blue-500 border-blue-500/30',
  fallback: 'bg-slate-500/10 text-slate-500 border-slate-500/30',
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-500 border-red-500/40 bg-red-500/5',
  high: 'text-orange-500 border-orange-500/40 bg-orange-500/5',
  medium: 'text-amber-500 border-amber-500/40 bg-amber-500/5',
  low: 'text-blue-500 border-blue-500/40 bg-blue-500/5',
};

// FP gerekçesi (P2 deterministik sinyal) — insan-okunur etiket.
const FP_REASON_LABEL: Record<string, string> = {
  waf_block: '🛡️ WAF engel sayfası',
  auth_wall: '🔒 Giriş duvarı',
  generic_error: '❓ Genel hata/soft-404',
  maintenance: '🚧 Bakım sayfası',
  empty: '␀ Boş yanıt',
  catchall_host: '🌀 Catch-all host',
};

/** RawTimelineEntry (kalıcı session kaydı) dizisini AgentStep[] modeline indirger —
 * usePipelineStream'in canlı reducer'ıyla aynı birleştirme kuralını (step numarası) uygular. */
function rawTimelineToAgentSteps(raw: RawTimelineEntry[]): AgentStep[] {
  const steps: AgentStep[] = [];
  const byStep = new Map<number, AgentStep>();
  let syntheticCounter = 0;

  for (const entry of raw) {
    const data = entry.data || {};
    if (entry.event_type === 'agent_thinking') {
      const step = data.step ?? ++syntheticCounter;
      const existing = byStep.get(step);
      const patched: AgentStep = {
        step,
        phase: data.action === 'stop' ? 'stopped' : 'thinking',
        reasoning: data.message || entry.message || '',
        tool: data.tool ?? null,
        action: data.action,
        expected: data.expected,
        confidence: data.confidence,
        source: data.source,
        siegeScore: data.siege_score ?? null,
        chosenBecause: data.chosen_because,
        considered: data.considered,
        targetNode: data.target_node ?? null,
        targetValue: data.target_value ?? null,
        startedAt: entry.timestamp,
        ...existing,
      };
      byStep.set(step, patched);
    } else if (entry.event_type === 'agent_action') {
      const step = data.step;
      const existing = byStep.get(step);
      if (existing) {
        existing.phase = 'acting';
        existing.options = data.options;
        if (data.expected) existing.expected = data.expected;
      }
    } else if (entry.event_type === 'agent_observation') {
      const step = data.step;
      const existing = byStep.get(step);
      if (existing) {
        existing.phase = 'observed';
        existing.status = data.status;
        existing.newEvidence = data.new_evidence;
        existing.totalEvidence = data.total_evidence;
        existing.services = data.services;
        existing.leads = data.leads;
        existing.resultSummary = data.result_summary ?? null;
        existing.artifactId = data.artifact_id ?? null;
        existing.errorMessage = data.error ?? null;
        existing.endedAt = entry.timestamp;
      }
    } else if (entry.event_type === 'agent_approval_needed') {
      steps.push({
        step: -1 - syntheticCounter++,
        phase: 'approval',
        reasoning: entry.message || '',
        tool: data.tool ?? null,
        action: 'approval',
        expected: '',
        confidence: 0,
        source: 'rules',
        options: data.options,
        startedAt: entry.timestamp,
      });
    }
  }

  return [...byStep.values(), ...steps].sort((a, b) => a.step - b.step);
}

function PhaseBadge({ step }: { step: AgentStep }) {
  switch (step.phase) {
    case 'thinking':
      return (
        <div className="p-2 rounded-lg bg-violet-500/10">
          <Brain className="w-5 h-5 text-violet-500 animate-pulse" />
        </div>
      );
    case 'acting':
      return (
        <div className="p-2 rounded-lg bg-blue-500/10">
          <Play className="w-5 h-5 text-blue-500 animate-pulse" />
        </div>
      );
    case 'observed':
      return (step.newEvidence ?? 0) > 0 ? (
        <div className="p-2 rounded-lg bg-red-500/10">
          <AlertTriangle className="w-5 h-5 text-red-500" />
        </div>
      ) : (
        <div className="p-2 rounded-lg bg-emerald-500/10">
          <Radar className="w-5 h-5 text-emerald-500" />
        </div>
      );
    case 'approval':
      return (
        <div className="p-2 rounded-lg bg-amber-500/10">
          <AlertTriangle className="w-5 h-5 text-amber-500" />
        </div>
      );
    case 'stopped':
      return (
        <div className="p-2 rounded-lg bg-emerald-500/10">
          <CheckCircle2 className="w-5 h-5 text-emerald-500" />
        </div>
      );
    default:
      return null;
  }
}

/** Domain benzeri string'leri yakalar (sub.example.com, example.com.tr vb.).
 * Chip'lere tıklanabilirlik bu kontrolle verilir — rastgele metin etkilenmez. */
const DOMAIN_LIKE_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

/** Bir tablo değerini okunur şekilde render eder (dizi/nesne/skaler).
 * onDomainClick verilirse domain benzeri chip'ler buton olur (red-team aksiyon menüsü). */
function renderTableValue(value: any, onDomainClick?: (domain: string) => void): React.ReactNode {
  if (value == null) return <span className="text-slate-500">—</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-slate-500">boş</span>;
    return (
      <div className="flex flex-wrap gap-1">
        {value.slice(0, 60).map((v, i) => {
          const label = typeof v === 'object' ? JSON.stringify(v) : String(v);
          const isDomain = typeof v === 'string' && DOMAIN_LIKE_RE.test(v);
          if (isDomain && onDomainClick) {
            return (
              <button
                key={`${label}-${i}`}
                onClick={() => onDomainClick(v)}
                title={`${v} — red team aksiyonları için tıkla`}
                className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-[11px] font-mono cursor-pointer
                           hover:bg-violet-500/20 hover:text-violet-600 dark:hover:text-violet-400
                           hover:ring-1 hover:ring-violet-500/40 transition-all"
              >
                {label}
              </button>
            );
          }
          return (
            <span key={`${label}-${i}`} className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-[11px] font-mono">
              {label}
            </span>
          );
        })}
        {value.length > 60 && <span className="text-[11px] text-slate-400">+{value.length - 60} daha</span>}
      </div>
    );
  }
  if (typeof value === 'object') {
    return (
      <pre className="text-[11px] font-mono whitespace-pre-wrap break-all text-slate-600 dark:text-slate-300 max-h-40 overflow-y-auto">
        {JSON.stringify(value, null, 2)}
      </pre>
    );
  }
  return <span className="font-mono text-[12px] break-all">{String(value)}</span>;
}

// ============== Red Team Domain Aksiyon Paneli ==============

interface PathProbeFinding {
  url: string;
  path: string;
  category: string;
  severity: string;
  status: number;
  content_length: number;
  validator: string;
  snippet?: string;
  curl?: string;
  mitre?: string | null;
  redacted?: boolean;
}

interface PathProbeResult {
  target: string;
  base_url?: string | null;
  probed: number;
  findings: PathProbeFinding[];
  severity_counts: Record<string, number>;
  note?: string;
  elapsed_seconds?: number;
}

interface RedTeamAiResult {
  provider: string;
  model: string;
  analysis: string;
  risk_score?: number | null;
  critical_findings?: string[];
  recommendations?: string[];
  technical_details?: string[];
  next_steps?: string[];
}

/** DB'deki (redteam_scans) geçmiş kayıt özeti — GET /api/redteam/scans döndürür. */
interface RedTeamHistoryItem {
  id: string;
  kind: 'path_probe' | 'analyze' | string;
  target: string;
  created_at?: string;
  severity_counts?: Record<string, number>;
  finding_count?: number;
  partial?: boolean;
  tech_hints?: string[];
  ai_risk?: number | null;
}

const FINDING_SEV_STYLE: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/5 text-red-500',
  high: 'border-orange-500/40 bg-orange-500/5 text-orange-500',
  medium: 'border-amber-500/40 bg-amber-500/5 text-amber-500',
  low: 'border-blue-500/40 bg-blue-500/5 text-blue-500',
  info: 'border-slate-500/40 bg-slate-500/5 text-slate-400',
};

/**
 * Domain chip'ine tıklayınca açılan red-team aksiyon paneli.
 * Üç aksiyon: (1) hassas yol taraması (.env/.git/yedek — deterministik),
 * (2) fuzz taraması başlat, (3) AI red team analizi (saldırgan gibi zincir kurar).
 * Sonuçlar modal içinde inline gösterilir — kullanıcı akışı kopmaz.
 */
function DomainActionPanel({ domain, onClose }: { domain: string; onClose: () => void }) {
  const [activeAction, setActiveAction] = useState<'probe' | 'fuzz' | 'redteam' | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [probeResult, setProbeResult] = useState<PathProbeResult | null>(null);
  const [fuzzStarted, setFuzzStarted] = useState<{ scanId: string } | null>(null);
  const [aiResult, setAiResult] = useState<RedTeamAiResult | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [showAnalysis, setShowAnalysis] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  // Ham kanıt modu: snippet'lerdeki sırlar maskesiz gösterilsin mi (kanıtlama için).
  const [revealed, setRevealed] = useState(false);
  const [revealLoading, setRevealLoading] = useState(false);
  // Geçmiş red-team taramaları (bu domain için) — DB'den (redteam_scans).
  const [history, setHistory] = useState<RedTeamHistoryItem[] | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [showHistory, setShowHistory] = useState(false);

  const loadHistory = async () => {
    setShowHistory(v => !v);
    if (history !== null) return; // bir kez yükle
    setHistoryLoading(true);
    try {
      const res = await api.get<{ scans: RedTeamHistoryItem[] }>(
        `/api/redteam/scans?target=${encodeURIComponent(domain)}&limit=25`
      );
      setHistory(res?.scans ?? []);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  // Bir tarama tamamlanınca geçmiş bayatlar — sonraki açılışta tazelensin.
  const invalidateHistory = () => setHistory(null);

  const runProbe = async () => {
    setActiveAction('probe');
    setLoading(true);
    setError(null);
    setProbeResult(null);
    setRevealed(false); // yeni tarama maskeli başlasın
    try {
      const res = await api.post<PathProbeResult>('/api/redteam/path-probe', { target: domain });
      setProbeResult(res);
      invalidateHistory(); // yeni tarama DB'ye yazıldı → geçmiş tazelensin
    } catch (e: any) {
      setError(e?.message || 'Hassas yol taraması başarısız');
    } finally {
      setLoading(false);
    }
  };

  // Ham kanıt: aynı taramayı reveal=true ile yeniden çalıştır (maskesiz snippet döner).
  // DB'ye yine maskeli yazılır (backend). "Açığı kanıtlamam lazım" senaryosu.
  const toggleReveal = async () => {
    if (revealed) { setRevealed(false); return; }
    setRevealLoading(true);
    setError(null);
    try {
      const res = await api.post<PathProbeResult>('/api/redteam/path-probe', { target: domain, reveal: true });
      setProbeResult(res);
      setRevealed(true);
    } catch (e: any) {
      setError(e?.message || 'Ham kanıt taraması başarısız');
    } finally {
      setRevealLoading(false);
    }
  };

  // İndir: bulguları okunabilir bir kanıt raporu (.txt) olarak indir.
  const downloadReport = () => {
    if (!probeResult) return;
    const lines: string[] = [];
    lines.push('KADIM GÜVENLİK — HASSAS YOL / İFŞA KANIT RAPORU');
    lines.push('='.repeat(60));
    lines.push(`Hedef      : ${probeResult.target}`);
    lines.push(`Taban URL  : ${probeResult.base_url ?? '-'}`);
    lines.push(`Taranan yol: ${probeResult.probed}`);
    lines.push(`Bulgu      : ${probeResult.findings.length}`);
    lines.push(`Kanıt modu : ${revealed ? 'HAM (maskesiz)' : 'MASKELİ'}`);
    lines.push(`Tarih      : ${new Date().toLocaleString('tr-TR')}`);
    lines.push('='.repeat(60));
    lines.push('');
    for (const f of probeResult.findings) {
      lines.push(`[${(f.severity || '').toUpperCase()}] ${f.url}`);
      lines.push(`  kategori : ${f.category}   validator: ${f.validator}`);
      lines.push(`  HTTP ${f.status} · ${f.content_length}B` + (f.mitre ? `   MITRE: ${f.mitre}` : ''));
      if (f.curl) lines.push(`  yeniden üret: ${f.curl}`);
      if (f.snippet) {
        lines.push('  --- KANIT (yanıt içeriği) ---');
        for (const l of String(f.snippet).split('\n')) lines.push(`  | ${l}`);
      }
      lines.push('');
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    a.download = `kanit-${probeResult.target}-${revealed ? 'ham' : 'maskeli'}-${stamp}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runFuzz = async () => {
    setActiveAction('fuzz');
    setLoading(true);
    setError(null);
    setFuzzStarted(null);
    try {
      const scanId = crypto.randomUUID();
      await api.post<any>('/api/fuzz/run', {
        target: domain,
        scan_id: scanId,
        wordlist: 'common.txt',
        smart_seeding: true,
        options: {},
      });
      setFuzzStarted({ scanId });
    } catch (e: any) {
      setError(e?.message || 'Fuzz taraması başlatılamadı');
    } finally {
      setLoading(false);
    }
  };

  const runRedTeam = async () => {
    setActiveAction('redteam');
    setLoading(true);
    setError(null);
    setAiResult(null);
    setAiError(null);
    try {
      const res = await api.post<any>('/api/redteam/analyze', { target: domain });
      if (res?.ai) {
        setAiResult(res.ai);
      }
      if (res?.ai_error) {
        setAiError(res.ai_error);
      }
      invalidateHistory(); // analyze de DB'ye yazıldı → geçmiş tazelensin
      if (res?.snapshot?.sensitive_path_scan && !probeResult) {
        // Analiz snapshot'ındaki prob bulgularını da göster — iki kuş bir taşla
        const sps = res.snapshot.sensitive_path_scan;
        setProbeResult({
          target: domain,
          probed: sps.probed ?? 0,
          findings: sps.findings ?? [],
          severity_counts: sps.severity_counts ?? {},
          note: sps.note,
        });
      }
    } catch (e: any) {
      setError(e?.message || 'AI red team analizi başarısız');
    } finally {
      setLoading(false);
    }
  };

  const riskColor = (score?: number | null) =>
    score == null ? 'text-slate-400' :
    score >= 70 ? 'text-red-500' : score >= 40 ? 'text-amber-500' : 'text-emerald-500';

  return (
    <div className="rounded-xl border border-violet-500/30 bg-violet-500/5 overflow-hidden">
      {/* Panel başlığı */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-violet-500/20">
        <div className="flex items-center gap-2 min-w-0">
          <Globe className="w-3.5 h-3.5 text-violet-500 shrink-0" />
          <span className="text-[12px] font-mono font-semibold text-violet-600 dark:text-violet-300 truncate">{domain}</span>
          <span className="text-[10px] text-slate-400 shrink-0">red team aksiyonu seç</span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={loadHistory}
            className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition
              ${showHistory ? 'bg-violet-500/15 text-violet-600 dark:text-violet-300' : 'text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'}`}
            title="Bu domain için geçmiş red-team taramaları"
          >
            <ScrollText className="w-3 h-3" />
            Geçmiş
          </button>
          <button onClick={onClose} className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800">
            <X className="w-3.5 h-3.5 text-slate-400" />
          </button>
        </div>
      </div>

      {/* Aksiyon butonları */}
      <div className="grid grid-cols-3 gap-2 p-3">
        <button
          onClick={runProbe}
          disabled={loading}
          className={`flex flex-col items-center gap-1 p-2.5 rounded-lg border text-center transition-all
            ${activeAction === 'probe'
              ? 'border-red-500/50 bg-red-500/10'
              : 'border-slate-200 dark:border-slate-700 hover:border-red-500/40 hover:bg-red-500/5'}
            disabled:opacity-50`}
        >
          <ShieldAlert className="w-4 h-4 text-red-500" />
          <span className="text-[11px] font-semibold text-slate-700 dark:text-slate-200">Hassas Yol Tara</span>
          <span className="text-[9px] text-slate-400 leading-tight">.env / .git / yedek / config ifşası</span>
        </button>
        <button
          onClick={runFuzz}
          disabled={loading}
          className={`flex flex-col items-center gap-1 p-2.5 rounded-lg border text-center transition-all
            ${activeAction === 'fuzz'
              ? 'border-blue-500/50 bg-blue-500/10'
              : 'border-slate-200 dark:border-slate-700 hover:border-blue-500/40 hover:bg-blue-500/5'}
            disabled:opacity-50`}
        >
          <FolderSearch className="w-4 h-4 text-blue-500" />
          <span className="text-[11px] font-semibold text-slate-700 dark:text-slate-200">Fuzz Tara</span>
          <span className="text-[9px] text-slate-400 leading-tight">dizin/endpoint keşfi (feroxbuster)</span>
        </button>
        <button
          onClick={runRedTeam}
          disabled={loading}
          className={`flex flex-col items-center gap-1 p-2.5 rounded-lg border text-center transition-all
            ${activeAction === 'redteam'
              ? 'border-violet-500/50 bg-violet-500/10'
              : 'border-slate-200 dark:border-slate-700 hover:border-violet-500/40 hover:bg-violet-500/5'}
            disabled:opacity-50`}
        >
          <Swords className="w-4 h-4 text-violet-500" />
          <span className="text-[11px] font-semibold text-slate-700 dark:text-slate-200">AI Red Team</span>
          <span className="text-[9px] text-slate-400 leading-tight">saldırgan analizi + saldırı zinciri</span>
        </button>
      </div>

      {/* Geçmiş taramalar (bu domain) — DB'den (redteam_scans) */}
      {showHistory && (
        <div className="mx-3 mb-3 rounded-lg border border-violet-500/20 bg-white/40 dark:bg-slate-900/40">
          <div className="px-2.5 py-1.5 border-b border-violet-500/10 text-[10px] font-semibold text-slate-500 flex items-center gap-1.5">
            <ScrollText className="w-3 h-3" /> Geçmiş red-team taramaları
          </div>
          {historyLoading ? (
            <div className="flex items-center gap-2 px-2.5 py-2 text-[11px] text-slate-400">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> geçmiş yükleniyor…
            </div>
          ) : (history && history.length > 0) ? (
            <div className="max-h-48 overflow-y-auto divide-y divide-slate-200/50 dark:divide-slate-800/50">
              {history.map((h) => {
                const crit = h.severity_counts?.critical ?? 0;
                const high = h.severity_counts?.high ?? 0;
                const when = h.created_at ? new Date(h.created_at).toLocaleString('tr-TR', { dateStyle: 'short', timeStyle: 'short' }) : '—';
                return (
                  <div key={h.id} className="flex items-center gap-2 px-2.5 py-1.5 text-[10px]">
                    <span className="px-1.5 py-0.5 rounded bg-slate-500/10 text-slate-500 font-mono shrink-0">
                      {h.kind === 'analyze' ? 'AI' : 'PROB'}
                    </span>
                    <span className="text-slate-500 shrink-0">{when}</span>
                    <div className="flex items-center gap-1 ml-auto shrink-0">
                      {crit > 0 && <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-500 font-semibold">{crit} kritik</span>}
                      {high > 0 && <span className="px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-500 font-semibold">{high} yüksek</span>}
                      {crit === 0 && high === 0 && (
                        <span className="text-slate-400">{h.finding_count ?? 0} bulgu</span>
                      )}
                      {h.partial && <span className="text-amber-500" title="Tarama kısmen tamamlandı">kısmi</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="px-2.5 py-2 text-[11px] text-slate-400">
              Bu domain için henüz kayıtlı tarama yok.
            </div>
          )}
        </div>
      )}

      {/* Yükleniyor */}
      {loading && (
        <div className="flex items-center gap-2 px-3 pb-3 text-[11px] text-slate-400">
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
          {activeAction === 'probe' && 'hassas yollar problanıyor…'}
          {activeAction === 'fuzz' && 'fuzz taraması başlatılıyor…'}
          {activeAction === 'redteam' && 'yüzey snapshot + AI saldırgan analizi (LLM sürebilir)…'}
        </div>
      )}

      {/* Hata */}
      {error && (
        <div className="mx-3 mb-3 p-2 rounded-lg border border-red-500/30 bg-red-500/5 text-[11px] text-red-500">
          ⚠️ {error}
        </div>
      )}

      {/* Fuzz başlatıldı */}
      {fuzzStarted && (
        <div className="mx-3 mb-3 p-2.5 rounded-lg border border-blue-500/30 bg-blue-500/5 text-[11px] text-slate-600 dark:text-slate-300 space-y-1.5">
          <div className="flex items-center gap-1.5 text-blue-500 font-semibold">
            <CheckCircle2 className="w-3.5 h-3.5" /> Fuzz taraması kuyruğa alındı
          </div>
          <div className="font-mono text-[10px] text-slate-400">scan_id: {fuzzStarted.scanId}</div>
          <button
            onClick={() => window.open(`/api/fuzz/logs/${fuzzStarted.scanId}`, '_blank')}
            className="inline-flex items-center gap-1 text-[11px] text-blue-500 hover:underline"
          >
            <ExternalLink className="w-3 h-3" /> sonuçları yeni sekmede aç (tamamlanınca dolar)
          </button>
        </div>
      )}

      {/* Path probe sonuçları */}
      {probeResult && (
        <div className="mx-3 mb-3 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h5 className="text-[11px] font-semibold text-slate-500 uppercase shrink-0">Hassas yol sonucu</h5>
            <div className="flex items-center gap-1.5 flex-wrap justify-end">
              <span className="text-[10px] text-slate-400">
                {probeResult.probed} yol{probeResult.elapsed_seconds != null ? ` · ${probeResult.elapsed_seconds}sn` : ''}
              </span>
              {probeResult.findings.length > 0 && (
                <>
                  {/* Ham kanıt: sırları maskesiz göster (kanıtlama). Yetkili operatör aracı. */}
                  <button
                    onClick={toggleReveal}
                    disabled={revealLoading}
                    className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium border transition disabled:opacity-50
                      ${revealed
                        ? 'border-red-500/50 bg-red-500/10 text-red-500'
                        : 'border-slate-300 dark:border-slate-700 text-slate-500 hover:bg-slate-200/50 dark:hover:bg-slate-800'}`}
                    title={revealed ? 'Sırları tekrar maskele' : 'Sırları maskesiz göster — açığı kanıtlamak için'}
                  >
                    {revealLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : revealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    {revealed ? 'Maskele' : 'Ham kanıt'}
                  </button>
                  {/* İndir: okunabilir kanıt raporu (.txt) */}
                  <button
                    onClick={downloadReport}
                    className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium border border-slate-300 dark:border-slate-700 text-slate-500 hover:bg-slate-200/50 dark:hover:bg-slate-800 transition"
                    title="Kanıt raporunu indir (.txt)"
                  >
                    <Download className="w-3 h-3" /> İndir
                  </button>
                </>
              )}
            </div>
          </div>
          {revealed && (
            <div className="flex items-center gap-1.5 text-[10px] text-red-500 bg-red-500/5 border border-red-500/30 rounded px-2 py-1">
              <ShieldAlert className="w-3 h-3 shrink-0" />
              Ham kanıt modu — sırlar MASKESİZ gösteriliyor. Yalnız yetkili kanıtlama için. (Kalıcı kayıt yine maskeli.)
            </div>
          )}
          {probeResult.note && (
            <div className="text-[11px] text-slate-400">ℹ️ {probeResult.note}</div>
          )}
          {probeResult.findings.length === 0 && !probeResult.note && (
            <div className="flex items-center gap-1.5 text-[11px] text-emerald-500">
              <CheckCircle2 className="w-3.5 h-3.5" /> ifşa bulunamadı — yüzey temiz görünüyor
            </div>
          )}
          <div className="space-y-1.5">
            {probeResult.findings.map((f, i) => (
              <div key={i} className={`rounded-lg border ${FINDING_SEV_STYLE[f.severity] || FINDING_SEV_STYLE.info}`}>
                <button
                  onClick={() => setExpandedFinding(expandedFinding === i ? null : i)}
                  className="w-full flex items-center justify-between gap-2 px-2.5 py-1.5 text-left"
                >
                  <div className="min-w-0">
                    <span className="text-[10px] font-bold uppercase mr-1.5">[{f.severity}]</span>
                    <span className="text-[11px] font-mono break-all">{f.url}</span>
                  </div>
                  <span className="text-[10px] shrink-0 opacity-70">HTTP {f.status} · {f.content_length}B</span>
                </button>
                {expandedFinding === i && (
                  <div className="px-2.5 pb-2 space-y-1.5 border-t border-current/10">
                    <div className="text-[10px] opacity-80 mt-1.5">
                      kategori: {f.category} · validator: {f.validator}
                    </div>
                    {f.snippet && (
                      <pre className="text-[10px] font-mono whitespace-pre-wrap break-all bg-black/10 dark:bg-black/30 rounded p-2 max-h-32 overflow-y-auto text-slate-600 dark:text-slate-300">
                        {f.snippet}
                      </pre>
                    )}
                    {f.curl && (
                      <code className="block text-[10px] font-mono break-all opacity-80">{f.curl}</code>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI red team sonucu */}
      {aiResult && (
        <div className="mx-3 mb-3 space-y-2">
          <div className="flex items-center justify-between">
            <h5 className="text-[11px] font-semibold text-slate-500 uppercase">AI red team analizi</h5>
            <span className="text-[10px] text-slate-400">{aiResult.provider} · {aiResult.model}</span>
          </div>
          {aiResult.risk_score != null && (
            <div className="flex items-center gap-2">
              <span className={`text-xl font-bold ${riskColor(aiResult.risk_score)}`}>{aiResult.risk_score}</span>
              <span className="text-[10px] text-slate-400">/ 100 risk skoru</span>
            </div>
          )}
          {(aiResult.critical_findings?.length ?? 0) > 0 && (
            <div className="space-y-1">
              <div className="text-[10px] font-semibold text-red-500 uppercase">Kritik bulgular</div>
              {aiResult.critical_findings!.map((f, i) => (
                <div key={i} className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">• {f}</div>
              ))}
            </div>
          )}
          {(aiResult.technical_details?.length ?? 0) > 0 && (
            <div className="space-y-1">
              <div className="text-[10px] font-semibold text-orange-500 uppercase">Saldırı zincirleri</div>
              {aiResult.technical_details!.map((f, i) => (
                <div key={i} className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">• {f}</div>
              ))}
            </div>
          )}
          {(aiResult.next_steps?.length ?? 0) > 0 && (
            <div className="space-y-1">
              <div className="text-[10px] font-semibold text-emerald-500 uppercase">Hemen doğrulanacaklar</div>
              {aiResult.next_steps!.map((f, i) => (
                <div key={i} className="text-[11px] font-mono text-slate-600 dark:text-slate-300 leading-relaxed break-all">• {f}</div>
              ))}
            </div>
          )}
          <button
            onClick={() => setShowAnalysis(v => !v)}
            className="inline-flex items-center gap-1 text-[10px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
          >
            {showAnalysis ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            tam analiz metni
          </button>
          {showAnalysis && (
            <pre className="text-[10px] font-mono whitespace-pre-wrap break-all text-slate-600 dark:text-slate-300 max-h-64 overflow-y-auto bg-slate-100 dark:bg-slate-800/40 rounded-lg p-2.5">
              {aiResult.analysis}
            </pre>
          )}
        </div>
      )}
      {aiError && !aiResult && (
        <div className="mx-3 mb-3 p-2 rounded-lg border border-amber-500/30 bg-amber-500/5 text-[11px] text-amber-600 dark:text-amber-400">
          ⚠️ AI analizi alınamadı ({aiError}) — hassas yol sonuçları yukarıda yine de listelendi.
        </div>
      )}
    </div>
  );
}

/** Adım sonuç modalı — "recon taradı, e ne çıktı?" cevabı. Event özetini anında gösterir,
 * ham veriyi (istenirse) scan_artifacts'ten lazy çeker. */
function ResultModal({ step, onClose }: { step: AgentStep; onClose: () => void }) {
  const summary = step.resultSummary;
  const [rawData, setRawData] = useState<any>(null);
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [rawTab, setRawTab] = useState<'json' | 'lines'>('json');
  const [copied, setCopied] = useState(false);
  // Seçili domain (chip tıklaması) → red team aksiyon paneli
  const [actionDomain, setActionDomain] = useState<string | null>(null);

  const fetchRaw = async () => {
    if (rawData || !step.artifactId) return;
    setRawLoading(true);
    setRawError(null);
    try {
      // artifactId formatı: "<scan_id>:<step>:<tool>"
      const parts = step.artifactId.split(':');
      const scanId = parts.slice(0, -2).join(':');
      const stepNo = parts[parts.length - 2];
      const tool = parts[parts.length - 1];
      const data = await api.get<any>(`/api/v2/scan/${scanId}/artifact/${stepNo}/${tool}`);
      setRawData(data);
    } catch (e: any) {
      setRawError(e?.message || 'Ham veri alınamadı');
    } finally {
      setRawLoading(false);
    }
  };

  const rawJson = useMemo(() => {
    if (!rawData) return '';
    return JSON.stringify(rawData.raw_data ?? rawData, null, 2);
  }, [rawData]);

  const rawLines = useMemo(() => {
    if (!rawData) return [];
    const payload = rawData.raw_data ?? rawData;
    // Nuclei/nmap servisleri log/çıktı alanlarını farklı isimlerde tutabilir.
    const candidates = [
      payload.raw_log_content,
      payload.log_content,
      payload.raw_output,
      payload.output,
      Array.isArray(payload.logs) ? payload.logs.map((l: any) =>
        typeof l === 'string' ? l : JSON.stringify(l)
      ).join('\n') : undefined,
      Array.isArray(payload.raw_lines) ? payload.raw_lines.join('\n') : undefined,
    ];
    const text = candidates.find(c => typeof c === 'string' && c.length > 0) as string | undefined;
    if (!text) return [];
    return text.split('\n').filter(line => line.trim().length > 0);
  }, [rawData]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(rawJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard API bazı ortamlarda yok, sessizce geç
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl max-h-[85vh] overflow-hidden rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-violet-500/10">
              <Database className="w-4 h-4 text-violet-500" />
            </div>
            <div>
              <h3 className="font-bold text-slate-900 dark:text-white text-sm">
                Adım {step.step} · {(step.tool || '').toUpperCase()} sonucu
              </h3>
              <p className="text-[11px] text-slate-500">{step.status || 'tamamlandı'}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800">
            <X className="w-4 h-4 text-slate-500" />
          </button>
        </div>

        <div className="overflow-y-auto p-5 space-y-4">
          {step.errorMessage && (
            <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/5 text-xs text-red-500">
              ⚠️ {step.errorMessage}
            </div>
          )}

          {/* Sayısal rozetler */}
          {summary?.counts && Object.keys(summary.counts).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(summary.counts).map(([k, v]) => (
                <div key={k} className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800/60 text-center">
                  <div className="text-base font-bold text-slate-900 dark:text-white">{v as number}</div>
                  <div className="text-[10px] text-slate-500">{k}</div>
                </div>
              ))}
            </div>
          )}

          {/* Öne çıkanlar */}
          {summary?.highlights && summary.highlights.length > 0 && (
            <div className="space-y-1">
              <h4 className="text-[11px] font-semibold text-slate-400 uppercase">Öne çıkanlar</h4>
              <div className="space-y-1">
                {summary.highlights.map((h, i) => (
                  <div key={i} className="text-xs text-slate-700 dark:text-slate-200 leading-relaxed">{h}</div>
                ))}
              </div>
            </div>
          )}

          {/* Detay tablo — domain chip'leri tıklanabilir (red team aksiyonu) */}
          {summary?.table && Object.keys(summary.table).length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-[11px] font-semibold text-slate-400 uppercase">Detaylar</h4>
                <span className="text-[10px] text-slate-400">
                  💡 domain'e tıkla → hassas yol / fuzz / AI red team
                </span>
              </div>
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 divide-y divide-slate-200 dark:divide-slate-800">
                {Object.entries(summary.table).map(([k, v]) => (
                  <div key={k} className="px-3 py-2">
                    <div className="text-[11px] font-semibold text-slate-500 mb-1">{k}</div>
                    {renderTableValue(v, (d) => setActionDomain(d))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Red team aksiyon paneli (domain chip'inden açılır) */}
          {actionDomain && (
            <DomainActionPanel domain={actionDomain} onClose={() => setActionDomain(null)} />
          )}

          {(!summary || (summary.highlights.length === 0 && Object.keys(summary.table).length === 0)) && !step.errorMessage && (
            <div className="text-xs text-slate-400 py-4 text-center">
              Bu adımda gösterilecek yapılandırılmış sonuç yok.
            </div>
          )}

          {/* Ham veri (lazy) */}
          {step.artifactId && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30">
              <button
                onClick={() => { setShowRaw(v => !v); if (!showRaw) fetchRaw(); }}
                className="w-full flex items-center justify-between px-3 py-2 text-[11px] text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
              >
                <span className="inline-flex items-center gap-1.5">
                  <FlaskConical className="w-3 h-3" />
                  Ham araç çıktısı {showRaw ? 'gizle' : 'göster'}
                </span>
                {showRaw ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
              {showRaw && (
                <div className="border-t border-slate-200 dark:border-slate-800 p-3">
                  {rawLoading ? (
                    <div className="flex items-center gap-2 text-xs text-slate-400 py-4">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" /> ham veri yükleniyor…
                    </div>
                  ) : rawError ? (
                    <div className="text-xs text-red-500 py-2">{rawError}</div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 rounded-md p-0.5">
                          <button
                            onClick={() => setRawTab('json')}
                            className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] ${rawTab === 'json' ? 'bg-white dark:bg-slate-700 shadow-sm text-slate-700 dark:text-slate-200' : 'text-slate-500'}`}
                          >
                            <FileJson className="w-3 h-3" /> JSON
                          </button>
                          {rawLines.length > 0 && (
                            <button
                              onClick={() => setRawTab('lines')}
                              className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] ${rawTab === 'lines' ? 'bg-white dark:bg-slate-700 shadow-sm text-slate-700 dark:text-slate-200' : 'text-slate-500'}`}
                            >
                              <ScrollText className="w-3 h-3" /> Satırlar ({rawLines.length})
                            </button>
                          )}
                        </div>
                        <button
                          onClick={handleCopy}
                          className="inline-flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                        >
                          {copied ? <Check className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
                          {copied ? 'kopyalandı' : 'kopyala'}
                        </button>
                      </div>
                      {rawTab === 'json' ? (
                        <pre className="text-[10px] font-mono whitespace-pre-wrap break-all text-slate-600 dark:text-slate-300 max-h-64 overflow-y-auto">
                          {rawJson}
                        </pre>
                      ) : (
                        <div className="text-[10px] font-mono text-slate-600 dark:text-slate-300 max-h-64 overflow-y-auto space-y-0.5">
                          {rawLines.map((line, i) => (
                            <div key={i} className="break-all border-l-2 border-slate-200 dark:border-slate-700 pl-2 hover:bg-slate-100 dark:hover:bg-slate-800/50">
                              {line}
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AgentStepCard({ step, onOpenResult }: { step: AgentStep; onOpenResult: (s: AgentStep) => void }) {
  const [expanded, setExpanded] = useState(false);
  const hasEvidence = (step.newEvidence ?? 0) > 0;
  const borderColor =
    hasEvidence ? 'border-red-500/40' :
    step.phase === 'approval' ? 'border-amber-500/40' :
    step.phase === 'stopped' ? 'border-emerald-500/40' :
    'border-slate-200 dark:border-slate-800';

  return (
    <div className={`rounded-xl border ${borderColor} bg-white dark:bg-slate-900/50 overflow-hidden transition-all ${hasEvidence ? 'shadow-lg shadow-red-500/10' : ''}`}>
      <div className="flex items-start gap-3 p-4">
        <PhaseBadge step={step} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {step.step >= 0 && (
              <span className="text-xs font-mono text-slate-400">Adım {step.step}</span>
            )}
            {step.source && (
              <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${SOURCE_BADGE[step.source] || SOURCE_BADGE.rules}`}>
                {step.source}
              </span>
            )}
            {typeof step.confidence === 'number' && step.confidence > 0 && (
              <span className="text-[10px] text-slate-400">güven %{Math.round(step.confidence * 100)}</span>
            )}
          </div>
          <p className="text-sm text-slate-800 dark:text-slate-100 mt-1 leading-relaxed">
            {step.reasoning}
          </p>

          {step.phase === 'acting' && step.tool && (
            <div className="mt-2 rounded-lg border border-blue-500/30 bg-blue-500/5 p-2.5 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-medium text-blue-500">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span className="font-mono uppercase">{step.tool}</span>
                <span className="text-slate-400 font-normal">
                  çalışıyor…{typeof step.elapsedSeconds === 'number' ? ` (${step.elapsedSeconds}sn)` : ''}
                </span>
              </div>
              {step.expected && (
                <p className="text-[11px] text-slate-500">🎯 hedef: {step.expected}</p>
              )}
              {step.options && Object.keys(step.options).length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {Object.entries(step.options).slice(0, 8).map(([k, v]) => (
                    <span key={k} className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-[10px] font-mono text-slate-600 dark:text-slate-300">
                      {k}={typeof v === 'object' ? JSON.stringify(v).slice(0, 30) : String(v).slice(0, 30)}
                    </span>
                  ))}
                </div>
              )}
              <p className="text-[10px] text-slate-400">
                Bu araç servisde çalışıyor; sonuç gelince adım "gözlem"e döner ve çıktı burada görünür.
              </p>
            </div>
          )}

          {step.phase === 'observed' && (
            <div className="mt-2 space-y-2">
              <p className="text-xs text-slate-500">
                {hasEvidence
                  ? `🔴 ${step.newEvidence} KANITLI zafiyet · ${(step.services || []).join(', ') || 'servis yok'}`
                  : `📊 ${step.tool || ''} → ${step.status || 'tamamlandı'}`}
              </p>
              {/* Özet öne-çıkanlar (ilk 3) — modal açmadan da ne bulunduğu görünsün */}
              {step.resultSummary?.highlights && step.resultSummary.highlights.length > 0 && (
                <div className="space-y-0.5">
                  {step.resultSummary.highlights.slice(0, 3).map((h, i) => (
                    <p key={i} className="text-[11px] text-slate-600 dark:text-slate-300">{h}</p>
                  ))}
                </div>
              )}
              {step.leads && step.leads.length > 0 && (
                <p className="text-[11px] text-slate-400">ipuçları: {step.leads.slice(0, 3).join(' · ')}</p>
              )}
              {/* "Ne çıktı?" — sonuç modalını aç */}
              {(step.resultSummary || step.artifactId) && (
                <button
                  onClick={() => onOpenResult(step)}
                  className="inline-flex items-center gap-1 text-[11px] font-medium text-violet-500 hover:text-violet-600 dark:hover:text-violet-400"
                >
                  <Eye className="w-3 h-3" />
                  Bu taramada ne çıktı? — sonuçları gör
                </button>
              )}
            </div>
          )}

          {step.phase === 'approval' && (
            <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
              ⚠️ İnsan onayı gerekiyor — otomatik atlandı.
            </p>
          )}

          {(step.considered && step.considered.length > 0) && (
            <button
              onClick={() => setExpanded(v => !v)}
              className="mt-2 inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
            >
              <FlaskConical className="w-3 h-3" />
              Neden bu hamle?
              {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          )}

          {expanded && step.considered && (
            <div className="mt-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3 space-y-1.5">
              <div className="flex items-center gap-1.5 text-[11px] text-slate-500 mb-1">
                <Target className="w-3 h-3" />
                <span>siege_score değerlendirilen alternatifler</span>
              </div>
              {step.considered.map((c, i) => (
                <div key={i} className="flex items-center justify-between text-[11px] font-mono">
                  <span className={i === 0 ? 'text-violet-500 font-semibold' : 'text-slate-500'}>
                    {i === 0 ? '★ ' : '  '}{c.tool}
                  </span>
                  <span className={i === 0 ? 'text-violet-500 font-semibold' : 'text-slate-400'}>
                    {c.score.toFixed(3)}
                  </span>
                </div>
              ))}
              {step.chosenBecause && (
                <p className="text-[10px] text-slate-400 pt-1 border-t border-slate-200 dark:border-slate-800 mt-1.5">
                  {step.chosenBecause}
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** İki fazlı onay kapısı paneli — keşif fazı bitti, sömürüye geçmeden önce insan onayı.
 * recon_map'i özetler; Onayla → /v2/scan/{sessionId}/approve, Durdur → cancel. */
function PhaseGatePanel({
  gate, sessionId, onApproved, onStopped,
}: {
  gate: Record<string, any>;
  sessionId?: string;
  onApproved: () => void;
  onStopped: () => void;
}) {
  const [busy, setBusy] = useState<null | 'approve' | 'stop'>(null);
  const [err, setErr] = useState<string | null>(null);
  const map = gate.recon_map || {};
  const hosts: any[] = map.discovered_hosts || [];
  const services: string[] = map.discovered_services || [];
  const coHosted: string[] = map.co_hosted_domains || gate.co_hosted_domains || [];
  const waiting: any[] = map.active_edges_waiting || [];

  const approve = async () => {
    if (!sessionId) { setErr('session_id yok — onay gönderilemiyor'); return; }
    setBusy('approve'); setErr(null);
    try {
      await api.post(`/api/v2/scan/${sessionId}/approve`, {});
      onApproved();
    } catch (e: any) {
      setErr(e?.message || 'Onay gönderilemedi');
    } finally { setBusy(null); }
  };

  const stop = async () => {
    if (!sessionId) { onStopped(); return; }
    setBusy('stop'); setErr(null);
    try {
      await api.post(`/api/v2/scan/${sessionId}/cancel`, {});
      onStopped();
    } catch (e: any) {
      setErr(e?.message || 'Durdurulamadı');
    } finally { setBusy(null); }
  };

  return (
    <div className="rounded-2xl border-2 border-amber-500/50 bg-amber-500/5 p-5 space-y-4 shadow-lg shadow-amber-500/10">
      <div className="flex items-center gap-2">
        <div className="p-2 rounded-lg bg-amber-500/15">
          <AlertTriangle className="w-5 h-5 text-amber-500" />
        </div>
        <div>
          <h3 className="font-bold text-slate-900 dark:text-white">Keşif Fazı Tamamlandı — Onay Bekleniyor</h3>
          <p className="text-xs text-slate-500">
            Saldırı yüzeyi haritalandı. Sömürü fazına (aktif araçlar) geçmek için onayınız gerekiyor.
          </p>
        </div>
      </div>

      {/* Harita özeti */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
        <div className="p-2 rounded-lg bg-white dark:bg-slate-900/50">
          <div className="text-lg font-bold text-slate-900 dark:text-white">{hosts.length}</div>
          <div className="text-[10px] text-slate-500">Host</div>
        </div>
        <div className="p-2 rounded-lg bg-white dark:bg-slate-900/50">
          <div className="text-lg font-bold text-slate-900 dark:text-white">{services.length}</div>
          <div className="text-[10px] text-slate-500">Servis</div>
        </div>
        <div className="p-2 rounded-lg bg-white dark:bg-slate-900/50">
          <div className="text-lg font-bold text-slate-900 dark:text-white">{coHosted.length}</div>
          <div className="text-[10px] text-slate-500">Co-hosted domain</div>
        </div>
        <div className="p-2 rounded-lg bg-white dark:bg-slate-900/50">
          <div className="text-lg font-bold text-violet-500">{waiting.length}</div>
          <div className="text-[10px] text-slate-500">Bekleyen aktif araç</div>
        </div>
      </div>

      {map.real_ip && (
        <p className="text-xs text-slate-600 dark:text-slate-300">
          🎯 Gerçek IP: <span className="font-mono">{map.real_ip}</span>
          {map.is_behind_cdn && <span className="ml-2 text-amber-600">(CDN arkasından çözüldü)</span>}
        </p>
      )}
      {services.length > 0 && (
        <div className="text-xs text-slate-600 dark:text-slate-300">
          <span className="font-semibold">Servisler: </span>
          <span className="font-mono">{services.slice(0, 12).join(', ')}{services.length > 12 ? ' …' : ''}</span>
        </div>
      )}
      {waiting.length > 0 && (
        <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-2.5">
          <div className="text-[11px] font-semibold text-violet-500 mb-1">Onaylanırsa çalışacak aktif araçlar:</div>
          <div className="space-y-0.5">
            {waiting.slice(0, 6).map((w, i) => (
              <div key={i} className="text-[11px] text-slate-600 dark:text-slate-300 font-mono">
                ▶️ {w.tool} → {w.target} {w.rationale ? `· ${w.rationale}` : ''}
              </div>
            ))}
          </div>
        </div>
      )}

      {err && <div className="text-xs text-red-500">{err}</div>}

      <div className="flex items-center gap-3 pt-1">
        <button
          onClick={approve}
          disabled={busy !== null}
          className="flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-bold text-white bg-gradient-to-r from-red-600 to-orange-500 hover:shadow-lg transition-all disabled:opacity-50"
        >
          {busy === 'approve' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          Sömürü Fazını Onayla
        </button>
        <button
          onClick={stop}
          disabled={busy !== null}
          className="flex items-center gap-2 px-5 py-2.5 rounded-full text-sm font-semibold text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors disabled:opacity-50"
        >
          {busy === 'stop' ? <Loader2 className="w-4 h-4 animate-spin" /> : <X className="w-4 h-4" />}
          Keşifte Dur (sömürü yapma)
        </button>
      </div>
    </div>
  );
}

/** Bug bounty kapsam skoru — checklist tamamlanma yüzdesi. Ağırlıklı puanlama
    ile "bakılacak yer kalmadı" hissini ölçülebilir yüze çevirir. */
function CoverageBar({ coverage }: { coverage: Record<string, any> }) {
  const pct = coverage.percent ?? 0;
  const items: any[] = coverage.items || [];
  const tone = pct >= 80 ? 'emerald' : pct >= 50 ? 'amber' : 'red';
  const barBg = tone === 'emerald' ? 'bg-emerald-500' : tone === 'amber' ? 'bg-amber-500' : 'bg-red-500';
  const textTone = tone === 'emerald' ? 'text-emerald-500' : tone === 'amber' ? 'text-amber-500' : 'text-red-500';

  return (
    <div className="mb-4 p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/30">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
          Kapsam Skoru
        </h4>
        <span className={`text-lg font-bold ${textTone}`}>{pct}%</span>
      </div>
      <div className="h-2 bg-slate-200 dark:bg-slate-700 rounded-full mb-3 overflow-hidden">
        <div
          className={`h-full rounded-full ${barBg} transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
        {items.slice(0, 12).map((item: any, i: number) => (
          <div key={i} className="flex items-center gap-1.5">
            <span className="text-[10px]">
              {item.done ? '✅' : '⬜'}
            </span>
            <span className={`text-[10px] ${item.done ? 'text-slate-700 dark:text-slate-300' : 'text-slate-400 dark:text-slate-500'}`}>
              {item.name}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function EvidenceSummary({ summary }: { summary: Record<string, any> }) {
  const vulns: any[] = summary.verified_vulnerabilities || [];
  // Şiddet sayaçlarını önce backend'in açık alanından al; yoksa (eski taramalar backend
  // düzeltmesinden önce medium/low üretmiyordu) kanıt listesinden türet. Böylece medium/low
  // bulgusu olan taramalar da "0 kritik / 0 yüksek" ile boş görünmez, gerçek sayı yansır.
  const countBySev = (sev: string) => vulns.filter(v => String(v.severity || '').toLowerCase() === sev).length;
  const criticalCount = summary.critical_count ?? countBySev('critical');
  const highCount = summary.high_count ?? countBySev('high');
  const mediumCount = summary.medium_count ?? countBySev('medium');
  const lowCount = summary.low_count ?? countBySev('low');
  // FALSE-POSITIVE ekseni: kanıt güç kademesi dağılımı. Eski taramalarda alan yoksa
  // kanıt listesinden türet (geriye-uyumlu). unconfirmed = "incelenmeli" (olası FP).
  const tierOf = (v: any) => String(v.confidence_tier || 'unconfirmed').toLowerCase();
  const tierCounts: Record<string, number> = summary.tier_counts ?? {
    confirmed: vulns.filter(v => tierOf(v) === 'confirmed').length,
    probable: vulns.filter(v => tierOf(v) === 'probable').length,
    unconfirmed: vulns.filter(v => tierOf(v) === 'unconfirmed').length,
  };
  const promotedCount = (tierCounts.confirmed ?? 0) + (tierCounts.probable ?? 0);
  const needsReview = summary.needs_review_count ?? (tierCounts.unconfirmed ?? 0);
  return (
    <div className={`rounded-xl border p-6 ${promotedCount > 0 ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50'}`}>
      <div className="flex items-center gap-2 mb-4">
        {/* Yeşil ✓ yalnız KANITLI/OLASI bulgu varken — manşetle tutarlı (yukarı bkz.). */}
        {promotedCount > 0 ? (
          <CheckCircle2 className="w-5 h-5 text-emerald-500" />
        ) : (
          <Radar className="w-5 h-5 text-slate-400" />
        )}
        <h3 className="font-bold text-slate-900 dark:text-white">
          {/* Manşet kademe-farkında olmalı: backend `success = kanıt>0` (unconfirmed dahil),
              ama başlık "Kanıtlı Zafiyet Bulundu" yalnız KANITLI/OLASI varken doğru. Aksi
              halde "0 kanıtlı · 0 olası · 8 incelenmeli" rozetiyle çelişir. Üç durum:
              promoted>0 → kanıtlı; yalnız incelenmeli → teyit bekliyor; hiç bulgu yok → boş. */}
          {promotedCount > 0
            ? 'Kuşatma Başarılı — Kanıtlı Zafiyet Bulundu'
            : (vulns.length > 0
                ? 'Kuşatma Tamamlandı — İncelenecek Bulgu Var (bağımsız teyit bekliyor)'
                : 'Kuşatma Tamamlandı — Kanıt Bulunamadı')}
        </h3>
      </div>
      {/* KANIT GÜVEN KADEMESİ — false-positive ekseni. "8 kritik" değil, kaçı KANITLI kaçı
          incelenmeli. unconfirmed = araç iddia etti, bağımsız teyit yok (olası FP). */}
      {vulns.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 mb-4 text-[11px]">
          <span className="px-2 py-1 rounded-lg font-semibold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
            ✅ {tierCounts.confirmed ?? 0} kanıtlı
          </span>
          <span className="px-2 py-1 rounded-lg font-semibold bg-sky-500/15 text-sky-600 dark:text-sky-400">
            ◐ {tierCounts.probable ?? 0} olası
          </span>
          <span className="px-2 py-1 rounded-lg font-semibold bg-amber-500/15 text-amber-600 dark:text-amber-400">
            ⚠️ {needsReview} incelenmeli (olası FP)
          </span>
          <span className="text-slate-500 dark:text-slate-400">
            — manşet kritik/yüksek sayısı yalnız kanıtlı + olası bulguları içerir
          </span>
        </div>
      )}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 mb-4 text-center">
        <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/50">
          <div className="text-lg font-bold text-slate-900 dark:text-white">{summary.steps_taken ?? '-'}</div>
          <div className="text-[10px] text-slate-500">Adım</div>
        </div>
        <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/50">
          <div className="text-lg font-bold text-slate-900 dark:text-white">{summary.open_ports ?? 0}</div>
          <div className="text-[10px] text-slate-500">Açık Port</div>
        </div>
        <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/50">
          <div className="text-lg font-bold text-red-500">{criticalCount}</div>
          <div className="text-[10px] text-slate-500">Kritik</div>
        </div>
        <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/50">
          <div className="text-lg font-bold text-orange-500">{highCount}</div>
          <div className="text-[10px] text-slate-500">Yüksek</div>
        </div>
        {/* Orta/Düşük: tek bulgusu bu seviyelerde olan taramalar da sayısal olarak görünür. */}
        <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/50">
          <div className="text-lg font-bold text-amber-500">{mediumCount}</div>
          <div className="text-[10px] text-slate-500">Orta</div>
        </div>
        <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/50">
          <div className="text-lg font-bold text-blue-500">{lowCount}</div>
          <div className="text-[10px] text-slate-500">Düşük</div>
        </div>
      </div>

      {/* KAPSAM SKORU — Bug bounty checklist tamamlanma yüzdesi */}
      {summary.coverage && (
        <CoverageBar coverage={summary.coverage} />
      )}

      {/* APT SALDIRI ZİNCİRİ (kill-chain) — izole bulguları ATT&CK yoluna dizer */}
      {summary.kill_chain && Array.isArray(summary.kill_chain.links) && summary.kill_chain.links.length > 0 && (
        <div className="mb-4 rounded-xl border border-violet-500/30 bg-violet-500/5 p-4">
          <div className="flex items-center gap-2 mb-3 flex-wrap">
            <span className="text-sm font-bold text-violet-600 dark:text-violet-300">⚔️ APT Saldırı Zinciri</span>
            <span className="text-[11px] px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-600 dark:text-violet-300 font-semibold">
              skor {Math.round(summary.kill_chain.score)}/100
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400">
              hedef: <b>{summary.kill_chain.objective || '—'}</b> · {summary.kill_chain.links.length} aşama
            </span>
          </div>
          {/* Faz akışı — soldan sağa kill-chain */}
          <div className="flex items-center gap-1.5 flex-wrap mb-3">
            {summary.kill_chain.links.map((l: any, i: number) => {
              const tierCls = l.confidence_tier === 'confirmed'
                ? 'border-emerald-500/50 bg-emerald-500/10'
                : l.confidence_tier === 'probable'
                  ? 'border-sky-500/50 bg-sky-500/10'
                  : 'border-amber-500/40 bg-amber-500/10';
              return (
                <div key={i} className="flex items-center gap-1.5">
                  {i > 0 && <span className="text-violet-400 text-xs">→</span>}
                  <div className={`px-2 py-1 rounded-lg border ${tierCls}`} title={`${l.technique_id} · ${l.technique_name}\n${l.title}`}>
                    <div className="text-[10px] font-bold text-slate-700 dark:text-slate-200">{l.phase_tr}</div>
                    <div className="text-[9px] font-mono text-slate-500">{l.technique_id}</div>
                  </div>
                </div>
              );
            })}
          </div>
          {summary.kill_chain.narrative && (
            <pre className="text-[10px] whitespace-pre-wrap font-mono text-slate-600 dark:text-slate-400 opacity-90 max-h-40 overflow-y-auto">{summary.kill_chain.narrative}</pre>
          )}
        </div>
      )}

      {vulns.length > 0 && (
        <div className="space-y-2">
          {vulns.map((v, i) => (
            <div key={i} className={`p-3 rounded-lg border text-xs ${SEVERITY_COLOR[v.severity] || SEVERITY_COLOR.low}`}>
              <div className="flex items-center gap-2 font-semibold flex-wrap">
                <span className="uppercase text-[10px]">{v.severity}</span>
                {/* Kanıt tipi: CVE mi, MITRE tekniği mi, yoksa motor mu buldu? */}
                {v.cve
                  ? <span className="font-mono px-1.5 py-0.5 rounded bg-black/10 dark:bg-white/10 text-[10px]">CVE · {v.cve}</span>
                  : <span className="px-1.5 py-0.5 rounded bg-black/10 dark:bg-white/10 text-[10px]">Motor bulgusu</span>}
                {v.mitre && <span className="font-mono text-[10px] opacity-70">MITRE {v.mitre}</span>}
                {/* Plan B: LLM'in ürettiği + PoC ile kanıtlanan bulgu (AI akıl yürüttü → kanıtlandı) */}
                {v.tool === 'poc_verify' && (
                  <span className="px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-600 dark:text-violet-400 text-[10px] font-bold">
                    🧠 LLM hipotezi
                  </span>
                )}
                {/* PoC doğrulama rozeti — aktif teyit (nuclei tahmininden GÜÇLÜ kanıt) */}
                {v.verified === true && (
                  <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 text-[10px] font-bold">
                    ✅ PoC DOĞRULANDI{typeof v.verification_confidence === 'number' ? ` · %${Math.round(v.verification_confidence * 100)}` : ''}
                  </span>
                )}
                {v.verified === false && (
                  <span
                    title={v.verification_detail || ''}
                    className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 text-[10px] font-semibold"
                  >
                    ⚠️ teyit edilemedi
                  </span>
                )}
                {/* Kademe rozeti — aktif PoC denenmemiş bulgularda (verified null) probable'ı
                    unconfirmed'dan ayırır: pathprobe ifşası "olası" iken ham nuclei "incele". */}
                {(v.verified === null || v.verified === undefined) && (
                  <TierBadge tier={v.confidence_tier} />
                )}
                {/* P2: neden şüpheli (WAF/giriş/hata/catch-all) — deterministik FP gerekçesi */}
                {v.fp_reason && (
                  <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-600 dark:text-rose-400 text-[10px] font-semibold">
                    {FP_REASON_LABEL[String(v.fp_reason)] || String(v.fp_reason)}
                  </span>
                )}
                {/* P3: LLM-hakem ikincil görüşü (kademeyi DEĞİŞTİRMEZ — danışma) */}
                {v.llm_fp_opinion?.verdict && (
                  <span
                    title={v.llm_fp_opinion.reason || ''}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      v.llm_fp_opinion.verdict === 'false_positive'
                        ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400'
                        : v.llm_fp_opinion.verdict === 'real'
                          ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                          : 'bg-slate-500/15 text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    🧠 {v.llm_fp_opinion.verdict === 'false_positive' ? 'LLM: olası FP'
                        : v.llm_fp_opinion.verdict === 'real' ? 'LLM: gerçek olabilir' : 'LLM: belirsiz'}
                    {typeof v.llm_fp_opinion.confidence === 'number' ? ` · %${Math.round(v.llm_fp_opinion.confidence * 100)}` : ''}
                  </span>
                )}
                <span>{v.title}</span>
              </div>
              <div className="flex items-center gap-2 mt-1 text-[10px] opacity-70">
                {v.tool && <span>🔧 kaynak: {v.tool}</span>}
                {v.target && <span className="font-mono">🎯 {v.target}</span>}
                {typeof v.step === 'number' && <span>adım {v.step}</span>}
              </div>
              {v.proof && (
                <div className="mt-1.5">
                  <div className="text-[10px] font-semibold opacity-60 mb-0.5">KANIT</div>
                  <div className="font-mono text-[10px] opacity-80 break-all whitespace-pre-wrap max-h-32 overflow-y-auto">{v.proof}</div>
                </div>
              )}
              {/* Aktif PoC doğrulama gerekçesi (yalnız teyit edilenlerde) */}
              {v.verified === true && v.verification_detail && (
                <div className="mt-1.5">
                  <div className="text-[10px] font-semibold text-emerald-600 dark:text-emerald-400 mb-0.5">PoC DOĞRULAMA</div>
                  <div className="text-[10px] opacity-80">{v.verification_detail}</div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      {vulns.length === 0 && (summary.vulnerability_count ?? 0) > 0 && (
        <div className="text-xs text-slate-500 border border-slate-200 dark:border-slate-800 rounded-lg p-3">
          {summary.vulnerability_count} zafiyet sayıldı ancak detaylı kanıt kaydı bu özette yok —
          adım adım ne bulunduğunu görmek için yukarıdaki timeline'da ilgili adımın
          "sonuçları gör" bağlantısını kullanın.
        </div>
      )}

      {/* Dikkat maddeleri — kanıtlı açık çıkmasa bile incelenmesi gereken varlıklar.
          Kullanıcının beklentisi: "illa açık olmasa da detaylı incelenmesi gereken
          bir sürü madde olmalı". Boş sonuç hissini önler, doğru yolda olunduğunu gösterir. */}
      {Array.isArray(summary.attention_items) && summary.attention_items.length > 0 && (
        <AttentionItems items={summary.attention_items} noVulns={vulns.length === 0} />
      )}

      {/* Kapanış anlatısı — motor neden durdu, ne denedi, sırada ne vardı */}
      {summary.closing_narrative && (
        <ClosingNarrative narrative={summary.closing_narrative} />
      )}
    </div>
  );
}

/** Dikkat maddeleri: kanıtlanmamış ama incelenmeye değer varlıklar (servis+sürüm, web yüzeyi).
    Zafiyet İDDİASI değil — analistin manuel bakması için önceliklendirilmiş liste. */
function AttentionItems({ items, noVulns }: { items: any[]; noVulns: boolean }) {
  return (
    <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
      <div className="flex items-center gap-2 mb-1">
        <Eye className="w-4 h-4 text-amber-500" />
        <h4 className="font-bold text-sm text-slate-900 dark:text-white">
          İncelenmesi Önerilen Maddeler
        </h4>
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-600 dark:text-amber-400">
          {items.length}
        </span>
      </div>
      <p className="text-[11px] text-slate-500 mb-3">
        {noVulns
          ? 'Otomatik kanıtlı açık çıkmadı; aşağıdaki varlıklar tespit edildi ve manuel incelenmeye değer.'
          : 'Kanıtlı bulgulara ek olarak, aşağıdaki varlıklar da manuel incelemeye değer.'}
        {' '}Bunlar bir zafiyet iddiası değil, öncelik notudur.
      </p>
      <div className="space-y-1.5">
        {items.map((it, i) => (
          <div key={i} className={`p-2.5 rounded-lg border text-xs ${SEVERITY_COLOR[it.severity] || SEVERITY_COLOR.low}`}>
            <div className="flex items-center gap-2 font-semibold flex-wrap">
              <span className="uppercase text-[10px]">{it.severity}</span>
              <span className="font-mono">{it.detail || it.label}</span>
              {typeof it.port === 'number' && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/10 dark:bg-white/10">port {it.port}</span>
              )}
            </div>
            {it.reason && (
              <div className="mt-1 text-[11px] opacity-80">{it.reason}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Motorun kapanış anlatısı: NEDEN durdu, hangi araçları kullandı, sırada ne vardı. */
function ClosingNarrative({ narrative }: { narrative: Record<string, any> }) {
  const tools: Record<string, number> = narrative.tools_used || {};
  const nextMoves: any[] = narrative.next_moves || [];
  const notes: string[] = narrative.notes_tail || [];
  return (
    <div className="mt-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40 p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Brain className="w-4 h-4 text-violet-500" />
        <h4 className="text-sm font-bold text-slate-900 dark:text-white">Motorun Kapanış Değerlendirmesi</h4>
      </div>
      <p className="text-xs text-slate-600 dark:text-slate-300">
        <span className="font-semibold">Neden durdu: </span>
        {narrative.stop_reason_text || narrative.stop_reason}
      </p>
      {narrative.last_reasoning && (
        <p className="text-xs text-slate-500">
          <span className="font-semibold">Son gerekçe: </span>{narrative.last_reasoning}
        </p>
      )}
      {Object.keys(tools).length > 0 && (
        <div className="text-xs text-slate-600 dark:text-slate-300">
          <span className="font-semibold">Kullanılan araçlar: </span>
          <span className="inline-flex flex-wrap gap-1 align-middle">
            {Object.entries(tools).map(([t, n]) => (
              <span key={t} className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 font-mono text-[10px]">
                {t}{n > 1 ? `×${n}` : ''}
              </span>
            ))}
          </span>
        </div>
      )}
      {nextMoves.length > 0 && (
        <div>
          <div className="text-[11px] font-semibold text-slate-500 mb-1">
            Sıradaki mantıklı hamleler (bütçe/karar nedeniyle denenmedi):
          </div>
          <div className="space-y-0.5">
            {nextMoves.map((m, i) => (
              <div key={i} className="text-[11px] text-slate-600 dark:text-slate-300 font-mono">
                ▶️ {m.tool} → {m.target}{m.rationale ? ` · ${m.rationale}` : ''}
              </div>
            ))}
          </div>
        </div>
      )}
      {notes.length > 0 && (
        <div>
          <div className="text-[11px] font-semibold text-slate-500 mb-1">Son ipuçları / anomaliler:</div>
          <div className="space-y-0.5">
            {notes.map((n, i) => (
              <div key={i} className="text-[11px] text-slate-500">• {n}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** IPB — "hangi sistem?" kartı. target_profiled olayından gelen yapılandırılmış gerçekleri
 * (altyapı/dil/framework/sunucu/app-tipi/waf) güven yüzdesiyle gösterir + playbook planı. */
const _PROFILE_DIMS: Array<{ key: string; label: string; icon: any }> = [
  { key: 'infra', label: 'Altyapı', icon: Database },
  { key: 'os', label: 'İşletim Sistemi', icon: Database },
  { key: 'cloud', label: 'Bulut', icon: Globe },
  { key: 'language', label: 'Dil', icon: FileJson },
  { key: 'framework', label: 'Framework', icon: Swords },
  { key: 'server', label: 'Sunucu', icon: ScrollText },
  { key: 'app_type', label: 'Uygulama', icon: Globe },
  { key: 'waf', label: 'WAF', icon: ShieldAlert },
  { key: 'auth_type', label: 'Kimlik', icon: ShieldAlert },
];

// Backend modül adları (playbook.py CAPABILITIES) → operatöre okunabilir Türkçe etiket.
// Harita eksikse ham ad fallback olarak gösterilir (yeni modül eklendiğinde motor kırılmaz).
const _MODULE_LABELS: Record<string, string> = {
  k8s_probe: 'Kubernetes/Rancher Probu',
  wp_probe: 'WordPress Probu',
  ssrf_metadata: 'Bulut Metadata SSRF',
  headless_crawl: 'Headless Tarama (JS Render)',
  graphql_intel: 'GraphQL Şema Keşfi',
  php_modules: 'PHP/CMS Modülleri',
  idor: 'IDOR/BOLA Probu',
  web_misconfig: 'Web Yanlış Yapılandırma (CORS/JWT)',
};
const _moduleLabel = (name: string) => _MODULE_LABELS[name] || name;

function TargetProfilePanel({ profile }: { profile: TargetProfileData | null }) {
  if (!profile) return null;
  const facts = profile.facts || {};
  const rows = _PROFILE_DIMS.filter(d => facts[d.key]?.value);
  return (
    <div className="rounded-xl border border-indigo-400/40 bg-indigo-500/5 dark:bg-indigo-500/10 p-4 mb-3">
      <div className="flex items-center gap-2 mb-2">
        <Target className="w-4 h-4 text-indigo-500" />
        <span className="text-sm font-semibold text-indigo-600 dark:text-indigo-300">
          🎯 Hedef Profili — önce düşmanı tanı (IPB)
        </span>
      </div>
      {/* Hedef TİPİ rozeti — motor "her hedefi web sitesi" saymasın. Çıplak sunucu / cihaz
          arkası / web uygulaması farkını operatör en başta görsün (kullanıcı: "bu Ubuntu server"). */}
      {profile.kind && profile.kind !== 'web' && profile.kind !== 'unknown' && (
        <div className={`mb-2 text-[11px] rounded-lg px-2.5 py-1.5 border ${
          profile.kind === 'appliance'
            ? 'border-amber-400/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
            : 'border-sky-400/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'}`}>
          {profile.kind === 'appliance'
            ? '🛡️ Hedef bir güvenlik cihazı/firewall ARKASINDA (dış yüzey filtreli) — web sitesi gibi değerlendirilmiyor.'
            : '🖥️ Hedef çıplak bir SUNUCU/HOST (web sitesi değil) — host/ağ odaklı değerlendiriliyor.'}
        </div>
      )}
      {rows.length === 0 ? (
        <div className="text-xs text-slate-500">
          {profile.kind === 'host'
            ? 'Çıplak sunucu/host — web uygulaması sinyali yok. Host/ağ yüzeyine odaklanılıyor.'
            : profile.kind === 'appliance'
              ? 'Güvenlik cihazı/firewall arkasında — dış web yüzeyi filtreli.'
              : 'Yeterli parmak-izi sinyali yok — genel tarama.'}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {rows.map(d => {
            const f = facts[d.key]!;
            const pct = Math.round((f.confidence || 0) * 100);
            const Icon = d.icon;
            const ev = (f.evidence || []).filter(Boolean);
            return (
              <div key={d.key} className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-900/40 px-2.5 py-1.5">
                <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-slate-400">
                  <Icon className="w-3 h-3" /> {d.label}
                </div>
                <div className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate" title={f.value}>
                  {f.value}
                </div>
                <div className="h-1 mt-1 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                  <div className="h-full bg-indigo-500" style={{ width: `${pct}%` }} />
                </div>
                {/* KANIT görünürlüğü: bu "gerçek" NEYE dayanıyor? (ör. header:cf-ray → Cloudflare).
                    Operatör yanlış-pozitifi (kullanıcı: "IP'de CF yok") buradan izleyebilsin. */}
                <div className="text-[9px] text-slate-400 mt-0.5 truncate" title={ev.join('  •  ')}>
                  %{pct} güven{ev.length > 0 ? ` — kanıt: ${ev.slice(0, 2).join(', ')}` : ''}
                </div>
              </div>
            );
          })}
        </div>
      )}
      {/* Ürün kimliği — nmap/Shodan CPE'sinden (elle imza yazmadan). "Bu sistemde ne çalışıyor". */}
      {profile.products && profile.products.length > 0 && (
        <div className="mt-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400 mb-1">
            Ürünler — CPE (otoriter) · "LLM~" (tahmin, doğrulanmamış) · "öğrenildi~" (hafızadan)
          </div>
          <div className="flex flex-wrap gap-1">
            {profile.products.slice(0, 16).map((p, i) => (
              <span key={i} className="text-[10px] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-900/40 text-slate-600 dark:text-slate-300 font-mono">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}
      {/* K8s/altyapı port-sweep — YALNIZ pozitif sinyalde göster: kontrol-düzlemi portu
          GERÇEKTEN açıksa operatöre bildir. Port kapalı/firewall arkasındayken "yokladım,
          bulamadım" ilanı yapılmaz — K8s yokken UI'da K8s reklamı istenmiyor. */}
      {profile.infra_probe?.attempted && !facts['infra']?.value
        && profile.infra_probe.k8s_ports_open.length > 0 && (
        <div className="mt-2 text-[11px] text-amber-600 dark:text-amber-400 flex items-start gap-1">
          <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span>K8s kontrol-düzlemi portları açık: {profile.infra_probe.k8s_ports_open.join(', ')}</span>
        </div>
      )}
      {profile.playbook_decisions ? (() => {
        // DÜRÜSTLÜK: yalnız AKTİF (run=true) modüller çip olur. YEŞİL = pozitif tespit/hedefli
        // (priority high); AMBER = 'kör kalma' genel kapsam, pozitif sinyal YOK (tespit DEĞİL).
        // ATLANAN modüller artık çip DEĞİL — eskiden her taramada üstü-çizili "Kubernetes/
        // WordPress..." çipi basılıyordu → sistem öyleymiş gibi yanıltıyordu (kullanıcı şikayeti).
        // İlgisizler tek, soluk bir sayaçta toplanır; adlar yalnız hover'da.
        const all = Object.entries(profile.playbook_decisions!);
        const active = all.filter(([, d]) => d.run);
        const skipped = all.filter(([, d]) => !d.run);
        return (
          <div className="mt-2">
            <div className="text-[10px] uppercase tracking-wide text-slate-400 mb-1">Saldırı planı</div>
            {active.length === 0 ? (
              <div className="text-[11px] text-slate-500">
                Hedefli modül yok — genel tarama yürütülüyor.
              </div>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {active.map(([name, d]) => {
                  const detected = d.priority === 'high';
                  const cls = detected
                    ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300'
                    : 'border-amber-400/50 bg-amber-500/10 text-amber-700 dark:text-amber-300 border-dashed';
                  return (
                    <span key={name} title={d.reason}
                      className={`text-[10px] px-1.5 py-0.5 rounded-full border ${cls}`}>
                      {_moduleLabel(name)}{detected ? '' : ' • genel'}
                    </span>
                  );
                })}
              </div>
            )}
            {skipped.length > 0 && (
              <div
                className="mt-1 text-[9px] text-slate-400/70 cursor-help"
                title={`İlgisiz → atlandı: ${skipped.map(([n]) => _moduleLabel(n)).join(', ')}`}>
                +{skipped.length} modül hedef profiliyle ilgisiz (atlandı)
              </div>
            )}
            {active.length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[9px] text-slate-400">
                <span><span className="text-emerald-500">●</span> tespit edildi / hedefli</span>
                <span><span className="text-amber-500">●</span> genel kapsam — pozitif sinyal yok (tespit DEĞİL)</span>
              </div>
            )}
          </div>
        );
      })() : profile.playbook ? (
        <div className="mt-2 text-[11px] text-slate-500 dark:text-slate-400">
          <span className="font-semibold text-indigo-500">Saldırı planı:</span> {profile.playbook}
        </div>
      ) : null}
    </div>
  );
}

/** Bulgu ayrıntısı — canlı bulgu kartına tıklayınca ham alanları modalda gösterir.
 * Operatör "ne bulundu"yu tam ham haliyle (kanıt + JSON) görüp kopyalayabilsin. */
function FindingModal({ finding, onClose }: { finding: EvidenceCard; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const hasTier = Boolean(finding.confidence_tier);
  const raw = useMemo(() => JSON.stringify(finding, null, 2), [finding]);
  // Etiketli alanlar — yalnız dolu olanlar gösterilir (boş alan gürültü yapmasın).
  const rows: Array<[string, any]> = [
    ['Başlık', finding.title],
    ['Önem', finding.severity],
    ['Güven kademesi', finding.confidence_tier],
    ['Araç', finding.tool],
    ['Hedef', finding.target],
    ['URL', finding.url],
    ['CVE', finding.cve],
    ['Kanıt', finding.proof],
    ['Mesaj', finding.message],
    ['Zaman', finding.ts],
  ];
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(raw);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard API bazı ortamlarda yok, sessizce geç
    }
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
      onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[85vh] overflow-hidden rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col"
        onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-red-500/10"><ShieldAlert className="w-4 h-4 text-red-500" /></div>
            <div>
              <h3 className="font-bold text-slate-900 dark:text-white text-sm">Bulgu ayrıntısı</h3>
              <p className="text-[11px] text-slate-500 flex items-center gap-1.5">
                <span className="uppercase font-semibold">{finding.severity}</span>
                {hasTier && <TierBadge tier={finding.confidence_tier} />}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800">
            <X className="w-4 h-4 text-slate-500" />
          </button>
        </div>
        <div className="overflow-y-auto p-5 space-y-4">
          <div className="space-y-1.5">
            {rows.filter(([, v]) => v != null && v !== '').map(([k, v]) => (
              <div key={k} className="grid grid-cols-[110px_1fr] gap-2 text-xs">
                <div className="text-[10px] uppercase tracking-wide text-slate-400 pt-0.5">{k}</div>
                <div className="text-slate-700 dark:text-slate-200 font-mono break-all whitespace-pre-wrap">{String(v)}</div>
              </div>
            ))}
          </div>
          {/* Ham hali — tüm alanlar JSON olarak (operatör kopyalayıp kanıtlasın). */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <div className="text-[10px] uppercase tracking-wide text-slate-400">Ham (JSON)</div>
              <button onClick={handleCopy}
                className="text-[10px] px-2 py-0.5 rounded border border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800">
                {copied ? 'Kopyalandı' : 'Kopyala'}
              </button>
            </div>
            <pre className="text-[10px] font-mono bg-slate-100 dark:bg-slate-950 rounded-lg p-3 overflow-x-auto text-slate-700 dark:text-slate-300">{raw}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Tarama SIRASINDA yakalanan bulgular — summary'yi (bitiş) beklemeden canlı gösterir. */
function LiveFindingsPanel({ findings }: { findings: EvidenceCard[] }) {
  const [open, setOpen] = useState(true);
  // Tıklanan bulgu → ham ayrıntı modalı.
  const [selected, setSelected] = useState<EvidenceCard | null>(null);
  if (!findings || findings.length === 0) return null;
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort(
    (a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
  return (
    <div className="rounded-xl border border-red-400/40 bg-red-500/5 dark:bg-red-500/10 p-4 mb-3">
      <button onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between">
        <span className="flex items-center gap-2 text-sm font-semibold text-red-600 dark:text-red-300">
          <ShieldAlert className="w-4 h-4" /> Canlı Bulgular ({findings.length})
        </span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </button>
      {open && (
        <div className="mt-2 space-y-1.5 max-h-72 overflow-y-auto">
          {sorted.map((f, i) => {
            const sc = SEVERITY_COLOR[f.severity] || 'text-slate-500 border-slate-500/40 bg-slate-500/5';
            const hasTier = Boolean(f.confidence_tier);
            return (
              <button key={i} type="button" onClick={() => setSelected(f)}
                title="Ayrıntı için tıkla — ham bulgu"
                className={`w-full text-left rounded-lg border px-2.5 py-1.5 text-xs cursor-pointer hover:brightness-110 transition ${sc}`}>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold uppercase text-[10px]">{f.severity}</span>
                  {hasTier && <TierBadge tier={f.confidence_tier} className="text-[9px]" />}
                  {/* AI/LLM red-team rozeti — MITRE ATLAS + OWASP LLM Top10 eşlemesi */}
                  {f.atlas && (
                    <span className="px-1 py-0.5 rounded bg-violet-500/20 text-violet-600 dark:text-violet-400 text-[9px] font-bold"
                      title="AI/LLM red-team (MITRE ATLAS)">
                      ⚔️ AI {f.atlas}{f.owasp_llm ? ` · ${f.owasp_llm}` : ''}
                    </span>
                  )}
                  {f.tool && <span className="text-[9px] text-slate-400">{f.tool}</span>}
                </div>
                <div className="text-slate-700 dark:text-slate-200 mt-0.5">{f.title}</div>
                {f.target && <div className="text-[10px] text-slate-400 font-mono truncate">{f.target}</div>}
              </button>
            );
          })}
        </div>
      )}
      {selected && <FindingModal finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

export default function AutonomousTimeline({
  scanId, sessionId, initialTimeline, summary, initialPhaseGate, stream: externalStream,
}: AutonomousTimelineProps) {
  const [onlyEvidence, setOnlyEvidence] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [showLog, setShowLog] = useState(false);
  const [resultModalStep, setResultModalStep] = useState<AgentStep | null>(null);
  // Onay gönderilince kapıyı elle kapatmak için (WS yeni adım getirene kadar).
  const [gateDismissed, setGateDismissed] = useState(false);
  // LLM parse hatası: kullanıcı-tetiklemeli yeniden danışma durumu.
  const [retryingAppraisal, setRetryingAppraisal] = useState(false);
  const [appraisalRetryMsg, setAppraisalRetryMsg] = useState<string | null>(null);
  // Kullanıcı 'yeniden danış'a bastıktan sonra uyarıyı gizle (yeni parse hatası gelene dek).
  const [parseNoticeDismissed, setParseNoticeDismissed] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const startedAtRef = useRef<number>(Date.now());
  const [elapsed, setElapsed] = useState(0);

  /** Kullanıcı elle yukarı kaydırırsa otomatik-scroll'u kapat; en alta dönünce tekrar aç. */
  const handleTimelineScroll = () => {
    const el = scrollContainerRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    setAutoScroll(distanceFromBottom < 40);
  };

  // TEK-WS DOKTRİNİ: parent stream verdiyse onu kullan (ikinci WebSocket AÇILMAZ —
  // eskiden auto-scan + Timeline aynı scan_id'ye iki bağlantı açıyordu: çift yük,
  // çift stale-closure riski, sunucuda çift subscriber queue). Parent stream yoksa
  // (results.tsx statik görünümü) kendi akışını kurar.
  const ownStream = usePipelineStream({});
  const stream = externalStream ?? ownStream;

  useEffect(() => {
    if (externalStream || !scanId) return;
    ownStream.connect(scanId);
    return () => ownStream.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  useEffect(() => {
    if (initialTimeline && initialTimeline.length > 0) {
      stream.seedAgentSteps(rawTimelineToAgentSteps(initialTimeline));
    }
    // initialTimeline REST'ten ASENKRON gelir — deps'e alınmazsa oturum verisi mount'tan
    // sonra çözüldüğünde seed hiç çalışmaz ve WS replay'i (son 20 event) tek kaynak kalır
    // → tamamlanmış taramada ilk adımlar kaybolur ("adım 2" görünümü).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, initialTimeline]);

  useEffect(() => {
    const interval = setInterval(() => setElapsed(Math.floor((Date.now() - startedAtRef.current) / 1000)), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [stream.agentSteps, autoScroll]);

  const visibleSteps = useMemo(() => {
    if (!onlyEvidence) return stream.agentSteps;
    return stream.agentSteps.filter(s => (s.newEvidence ?? 0) > 0 || s.phase === 'approval');
  }, [stream.agentSteps, onlyEvidence]);

  const totalEvidence = useMemo(() => {
    const last = [...stream.agentSteps].reverse().find(s => typeof s.totalEvidence === 'number');
    return last?.totalEvidence ?? 0;
  }, [stream.agentSteps]);

  const criticalCount = useMemo(
    () => (summary?.critical_count as number) ?? 0,
    [summary]
  );

  const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
  const ss = String(elapsed % 60).padStart(2, '0');

  // Onay kapısı: canlı stream'den veya (reconnect'te) initial'dan. Onay/durdurulunca gizlenir.
  // Yeni bir agent adımı geldiyse (stream.phaseGate null'a döndü) da otomatik kapanır.
  const activeGate = !gateDismissed && !stream.isComplete
    ? (stream.phaseGate ?? (stream.agentSteps.length === 0 ? initialPhaseGate : null))
    : null;

  // LLM parse hatası: stream.events içinde 'can_retry_appraisal' bayrağı taşıyan EN SON
  // olay var mı? Motor kural+graf ile çalışmaya devam eder; bu yalnız operatöre "LLM
  // sezgisini geri kazanmak istersen yeniden danış" aksiyonu sunar. Tarama bitti ya da
  // kullanıcı zaten dismiss ettiyse gösterme.
  // En son parse-failure event'ini (step'iyle) bul — dismiss reset'i buna bağlı.
  const latestParseFailureStep = useMemo(() => {
    const evs = stream.events || [];
    for (let i = evs.length - 1; i >= 0; i--) {
      const e: any = evs[i];
      const d = e?.data || {};
      if (e?.event_type === 'agent_action') return null; // sonrası: uyarı geçmişte kaldı
      if (d?.can_retry_appraisal) return d.step ?? -1;
    }
    return null;
  }, [stream.events]);

  // Yeni bir parse hatası (farklı step) gelirse dismiss'i sıfırla — buton tekrar çıksın.
  useEffect(() => {
    if (latestParseFailureStep !== null) setParseNoticeDismissed(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [latestParseFailureStep]);

  const parseFailureActive =
    !parseNoticeDismissed && !stream.isComplete && latestParseFailureStep !== null;

  const handleRetryAppraisal = async () => {
    if (!sessionId) { setAppraisalRetryMsg('session_id yok — yeniden danışma gönderilemiyor'); return; }
    setRetryingAppraisal(true);
    setAppraisalRetryMsg(null);
    try {
      const res = await api.post<any>(`/api/v2/scan/${sessionId}/llm/retry`, {});
      setAppraisalRetryMsg(res?.message || 'Yeniden danışma planlandı.');
      setParseNoticeDismissed(true); // uyarıyı gizle; yeni parse hatası olursa tekrar çıkar
    } catch (e: any) {
      setAppraisalRetryMsg(e?.message || 'Yeniden danışma başarısız.');
    } finally {
      setRetryingAppraisal(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* İki fazlı onay kapısı — keşif bitti, sömürü için onay bekliyor */}
      {activeGate && (
        <PhaseGatePanel
          gate={activeGate}
          sessionId={sessionId}
          onApproved={() => { setGateDismissed(true); stream.clearPhaseGate(); }}
          onStopped={() => { setGateDismissed(true); stream.clearPhaseGate(); }}
        />
      )}

      {/* LLM parse hatası — kullanıcı-tetiklemeli yeniden danışma bandı.
          Motor kural+graf ile çalışmaya devam eder; bu yalnız LLM sezgisini geri kazanma
          fırsatı sunar (tarama durmaz). */}
      {parseFailureActive && (
        <div className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-xl border border-amber-500/40 bg-amber-500/5 text-xs">
          <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
            <Brain className="w-4 h-4 shrink-0" />
            <span className="font-medium">
              İstihbarat subayı (LLM) cevabı yorumlanamadı — motor kural+graf ile devam ediyor.
            </span>
          </div>
          <div className="flex items-center gap-2 ml-auto">
            <button
              onClick={handleRetryAppraisal}
              disabled={retryingAppraisal}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-700 dark:text-amber-300 border border-amber-500/40 font-medium disabled:opacity-50 transition"
            >
              {retryingAppraisal ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Brain className="w-3.5 h-3.5" />}
              LLM'e yeniden danış
            </button>
            <button
              onClick={() => setParseNoticeDismissed(true)}
              className="p-1.5 rounded-lg hover:bg-slate-500/10 text-slate-400"
              title="Uyarıyı gizle"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          {appraisalRetryMsg && (
            <div className="w-full text-slate-500 dark:text-slate-400">{appraisalRetryMsg}</div>
          )}
        </div>
      )}

      {/* Üst özet çubuğu */}
      <div className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 text-xs">
        <div className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
          <Target className="w-3.5 h-3.5" />
          <span className="font-mono">{scanId.slice(0, 8)}</span>
        </div>
        <div className="flex items-center gap-1.5 text-slate-500">
          <Clock className="w-3.5 h-3.5" />
          <span>{mm}:{ss} geçti</span>
        </div>
        <div className="flex items-center gap-1.5 text-slate-500">
          <Brain className="w-3.5 h-3.5" />
          <span>adım {stream.agentSteps.filter(s => s.step >= 0).length}</span>
        </div>
        <div className={`flex items-center gap-1.5 ${totalEvidence > 0 ? 'text-red-500 font-semibold' : 'text-slate-500'}`}>
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>kanıt {totalEvidence}{criticalCount > 0 ? ` (${criticalCount} kritik)` : ''}</span>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <button
            onClick={() => setShowLog(v => !v)}
            className={`flex items-center gap-1 px-2 py-1 rounded-full border text-[11px] transition-colors ${
              showLog
                ? 'border-violet-500/40 bg-violet-500/10 text-violet-500'
                : 'border-slate-300 dark:border-slate-700 text-slate-500'
            }`}
            title="Son WS olaylarını göster/gizle (ham log)"
          >
            <Terminal className="w-3 h-3" />
            ham log
          </button>
          <button
            onClick={() => setOnlyEvidence(v => !v)}
            className={`flex items-center gap-1 px-2 py-1 rounded-full border text-[11px] transition-colors ${
              onlyEvidence
                ? 'border-red-500/40 bg-red-500/10 text-red-500'
                : 'border-slate-300 dark:border-slate-700 text-slate-500'
            }`}
          >
            <Filter className="w-3 h-3" />
            yalnız kanıtlılar
          </button>
          {stream.isConnected ? (
            <span className="flex items-center gap-1 text-emerald-500">
              <Wifi className="w-3.5 h-3.5" /> canlı
            </span>
          ) : stream.isComplete ? (
            <span className="flex items-center gap-1 text-slate-400">
              <CheckCircle2 className="w-3.5 h-3.5" /> tamamlandı
            </span>
          ) : (
            <span className="flex items-center gap-1 text-amber-500">
              <WifiOff className="w-3.5 h-3.5" /> bağlanıyor
            </span>
          )}
        </div>
      </div>

      {/* CANLI MOTOR ETKİNLİĞİ — motor uzun bir blokta (LLM danışma, araç koşma, probe zinciri,
          kapanış) sessiz beklerken UI "dondu" hissi veriyordu. orchestrator her FAZ SINIRINDA
          `engine_activity` yayınlar; bu bant "şu an ne yapılıyor" + faz rengi + "N sn önce"
          sayacıyla canlı olduğunu gösterir. Tarama bitince kalkar. */}
      <EngineActivityBand activity={stream.engineActivity} running={!stream.isComplete} />

      {/* IPB: hedef profili ("hangi sistem") — timeline'ın üstünde, canlı. Canlı olay yoksa
          (tamamlanmış/yeniden açılan tarama) summary.target_profile'dan geri düşer. */}
      <TargetProfilePanel profile={
        stream.targetProfile
        || (summary?.target_profile
            ? { facts: summary.target_profile.facts, profile: summary.target_profile.summary,
                kind: summary.target_profile.kind }
            : null)
      } />

      {/* Tarama sırasında yakalanan bulgular — bitişi (summary) beklemeden canlı */}
      <LiveFindingsPanel findings={stream.liveFindings} />

      {/* Ham olay günlüğü — "ihtiyaç halinde log gör": son 100 WS olayı, en yenisi üstte.
          Adım kartlarının ham WS kaynağı; hata ayıklarken/tarama beklerken ne olduğu görünür. */}
      {showLog && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-950 overflow-hidden">
          <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
            <span>Ham olay günlüğü (son {stream.events.length})</span>
            <button onClick={() => setShowLog(false)} className="text-slate-500 hover:text-slate-300 transition-colors" aria-label="Günlüğü kapat">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="max-h-60 overflow-y-auto text-[10px] font-mono">
            {stream.events.length === 0 ? (
              <div className="px-3 py-3 text-slate-600">Olay yok — WS henüz veri göndermedi.</div>
            ) : (
              [...stream.events].reverse().map((ev, i) => {
                const d: Record<string, any> = ev.data || {};
                const msg = typeof d.message === 'string' ? d.message : '';
                const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString('tr-TR') : '';
                return (
                  <div key={i} className="flex items-start gap-2 px-3 py-1 border-b border-slate-800/40 leading-relaxed">
                    {ts && <span className="text-slate-600 whitespace-nowrap">{ts}</span>}
                    <span className="text-violet-400 whitespace-nowrap">{ev.event_type || ev.type}</span>
                    <span className="text-slate-300 break-all">{msg || JSON.stringify(d).slice(0, 180)}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Timeline */}
      <div
        ref={scrollContainerRef}
        onScroll={handleTimelineScroll}
        className="space-y-3 max-h-[32rem] overflow-y-auto pr-1"
      >
        {visibleSteps.length === 0 ? (
          <div className="flex items-center gap-2 text-sm text-slate-400 p-4">
            <Brain className="w-4 h-4 animate-pulse" />
            Motor hedefi analiz ediyor…
          </div>
        ) : (
          visibleSteps.map((step, i) => (
            <AgentStepCard key={`${step.step}-${i}`} step={step} onOpenResult={setResultModalStep} />
          ))
        )}
        <div ref={bottomRef} />
      </div>

      {!autoScroll && (
        <button
          onClick={() => { setAutoScroll(true); bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }}
          className="flex items-center gap-1 mx-auto text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
        >
          <ArrowDown className="w-3.5 h-3.5" /> en sona git
        </button>
      )}

      {/* Bitiş özeti */}
      {summary && <EvidenceSummary summary={summary} />}

      {/* Adım sonuç modalı — "ne çıktı?" */}
      {resultModalStep && (
        <ResultModal step={resultModalStep} onClose={() => setResultModalStep(null)} />
      )}
    </div>
  );
}

/** Canlı etkinlik bandının "N sn önce" sayacı — her saniye tazelenir. Uzun post-observe
 *  probe'lerinde bant HİPERSIZ görünmesin; saniye arttıkça "hâlâ çalışıyor" netleşir. */
function ActivityAge({ at }: { at: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);
  const seconds = Math.max(0, Math.floor((now - new Date(at).getTime()) / 1000));
  return (
    <span className="text-slate-400 font-mono shrink-0" title={new Date(at).toLocaleTimeString('tr-TR')}>
      {seconds}sn önce
    </span>
  );
}

/** Mesajın önc-emoji'sinden faz kategorisi → renk. Motor `act()` mesajları stabil emoji
 *  öneki taşır (🔧 araç, 🧠🧪🔌 LLM/karar, 🚀🩺 başlangıç, 🧾 kapanış, gerisi keşif/probe). */
function activityTone(message: string): { ring: string; icon: string; bar: string } {
  const s = message.trimStart();
  const has = (arr: string[]) => arr.some((e) => s.startsWith(e));
  if (has(['🔧'])) return { ring: 'border-blue-500/30 bg-blue-500/5', icon: 'text-blue-500', bar: 'bg-blue-500' };
  if (has(['🧠', '🧪', '🔌'])) return { ring: 'border-violet-500/30 bg-violet-500/5', icon: 'text-violet-500', bar: 'bg-violet-500' };
  if (has(['🚀', '🩺'])) return { ring: 'border-sky-500/30 bg-sky-500/5', icon: 'text-sky-500', bar: 'bg-sky-500' };
  if (has(['🧾'])) return { ring: 'border-amber-500/30 bg-amber-500/5', icon: 'text-amber-500', bar: 'bg-amber-500' };
  return { ring: 'border-emerald-500/30 bg-emerald-500/5', icon: 'text-emerald-500', bar: 'bg-emerald-500' };
}

/** Üstteki özet çubuğunun hemen altında "şu an ne yapılıyor" bandı. Motor her faz sınırında
 *  `engine_activity` yayınlar; bant mesaj + faz rengi + adım + "N sn önce" gösterir. Çalışırken
 *  altında ince pulse çubuğu akar → "donmadı, işliyor" hissi. Tarama bittiyse/kayıt yoksa sessiz. */
function EngineActivityBand({ activity, running }: { activity: EngineActivity | null; running: boolean }) {
  if (!running || !activity) return null;
  const tone = activityTone(activity.message);
  return (
    <div className={`rounded-xl border ${tone.ring} px-4 py-2.5 text-xs overflow-hidden`}>
      <div className="flex items-center gap-2.5">
        <Loader2 className={`w-4 h-4 animate-spin shrink-0 ${tone.icon}`} />
        <span className="font-medium text-slate-800 dark:text-slate-100 truncate">
          {activity.message}
        </span>
        {typeof activity.step === 'number' && (
          <span className="font-mono text-slate-500 shrink-0">adım {activity.step}</span>
        )}
        <span className="ml-auto shrink-0">
          <ActivityAge at={activity.at} />
        </span>
      </div>
      <div className="mt-2 h-0.5 w-full overflow-hidden rounded bg-slate-200/70 dark:bg-slate-700/40">
        <div className={`h-full w-1/2 animate-pulse rounded ${tone.bar}`} />
      </div>
    </div>
  );
}
