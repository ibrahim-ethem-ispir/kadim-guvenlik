import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Brain, ChevronRight, ChevronDown, Loader2, CheckCircle2, XCircle,
  Cpu, MessageSquare, Terminal, Clock, RefreshCw, X,
} from 'lucide-react';
import { api } from '../services/api';

/**
 * LLM Log Modalı — otonom motorun her kuşatma turunda İSTİHBARAT SUBAYINA (LLM) SORDUĞU
 * prompt ve aldığı HAM cevabı, sayfa üstündeki bir butondan açılan modalde gösterir.
 * Şeffaflık + hata ayıklama: "LLM ne düşündü, neden kural fallback'e geçildi?" sorusunun
 * görünür cevabı.
 *
 * - Yalnızca ADMIN için render edilir (çağıran taraf yetkiyi kontrol eder).
 * - Veri kaynağı: GET /api/v2/scan/{scanId}/llm-logs (DB'de kalıcı; reload sonrası da dolu).
 * - Modal deseni AutonomousLlmStatus ile aynı (backdrop + ESC kapanma).
 * - Sistem talimatı her turda aynı olduğu için EN ÜSTTE bir kez gösterilir.
 */

interface LlmLog {
  log_id: string;
  scan_id: string;
  step: number;
  provider?: string;
  model?: string;
  system_prompt?: string;
  prompt?: string;
  raw_response?: string;
  parsed_ok?: boolean;
  duration_ms?: number;
  healthy?: boolean;
  created_at?: string;
}

interface LlmLogsModalProps {
  scanId: string;
  /** Tarama bittiyse polling durur; çalışırken periyodik tazelenir. */
  isDone?: boolean;
}

export default function LlmLogsModal({ scanId, isDone }: LlmLogsModalProps) {
  const [open, setOpen] = useState(false);
  const [logs, setLogs] = useState<LlmLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [fetched, setFetched] = useState(false);   // ilk fetch tamamlandı mı (buton rozeti için)
  const [expandedStep, setExpandedStep] = useState<number | null>(null);
  const [showSystem, setShowSystem] = useState(false);

  const fetchLogs = useCallback(async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const data = await api.get<{ logs: LlmLog[] }>(`/api/v2/scan/${scanId}/llm-logs`);
      setLogs(data.logs || []);
      setFetched(true);
    } catch {
      // Sessizce geç — modal opsiyonel bir görünürlük katmanı, taramayı etkilemez.
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  // Butonun üzerindeki "(N danışma)" rozeti için açılışta bir kez hafif fetch.
  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Modal açıkken: bir kez çek + tarama sürerken periyodik tazele. Tarama bittiğinde
  // motorun son adımı DB'ye yazması bu fetch'ten sonraya sarkabileceği için bir kez
  // geç tazeleme yap.
  useEffect(() => {
    if (!open) return;
    fetchLogs();
    if (isDone) {
      const trailing = setTimeout(fetchLogs, 2500);
      return () => clearTimeout(trailing);
    }
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [open, isDone, fetchLogs]);

  // Modal açıkken ESC ile kapat.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  // Sistem talimatı her turda aynı; ilk logdan bir kez al.
  const systemPrompt = useMemo(
    () => logs.find(l => l.system_prompt)?.system_prompt || '',
    [logs]
  );

  return (
    <>
      {/* Sayfa üstündeki buton */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 px-3 py-2 rounded-full border border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400 text-sm font-medium transition-all hover:bg-violet-500/20 hover:shadow-sm"
        title="LLM danışma loglarını görüntüle (admin)"
      >
        <Brain className="w-4 h-4" />
        <span>LLM Logları</span>
        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-violet-500/15 border border-violet-500/30">
          admin
        </span>
        {fetched && (
          <span className="font-mono text-[11px] opacity-80">({logs.length})</span>
        )}
      </button>

      {/* Modal */}
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-4xl max-h-[85vh] flex flex-col bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl shadow-2xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Başlık */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800 shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <div className="p-2 rounded-lg bg-violet-500/10 shrink-0">
                  <Brain className="w-5 h-5 text-violet-500" />
                </div>
                <div className="min-w-0">
                  <h3 className="font-bold text-slate-900 dark:text-white leading-tight">LLM Danışma Logları</h3>
                  <p className="text-xs text-slate-500 truncate">
                    İstihbarat subayına sorulan sorular + ham cevaplar
                    <span className="font-mono ml-1">({scanId.slice(0, 8)})</span>
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={fetchLogs}
                  disabled={loading}
                  title="Yenile"
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={() => setOpen(false)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                  aria-label="Kapat"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Gövde — koyu terminal görünümü (eski panel dili) */}
            <div className="flex-1 overflow-y-auto bg-slate-950">
              {/* Sistem talimatı — her turda aynı, bir kez göster */}
              {systemPrompt && (
                <div className="border-b border-slate-800">
                  <button
                    onClick={() => setShowSystem(s => !s)}
                    className="w-full flex items-center gap-2 px-4 py-2.5 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    {showSystem ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    <Cpu className="w-3.5 h-3.5 text-violet-400" />
                    <span>Sistem Talimatı (istihbarat subayı rolü)</span>
                  </button>
                  {showSystem && (
                    <pre className="px-4 pb-3 text-[11px] leading-relaxed text-slate-400 whitespace-pre-wrap font-mono">
                      {systemPrompt}
                    </pre>
                  )}
                </div>
              )}

              {/* Boş / yükleniyor */}
              {logs.length === 0 && (
                <div className="px-4 py-10 text-center text-xs text-slate-600 font-mono">
                  {loading ? (
                    <span className="inline-flex items-center gap-2">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" /> LLM logları yükleniyor…
                    </span>
                  ) : (
                    'Henüz LLM danışması yok. (Kural motoru fallback\'te olabilir ya da anahtar tanımlı değil.)'
                  )}
                </div>
              )}

              {/* Alışveriş satırları */}
              <div className="divide-y divide-slate-800/70">
                {logs.map((log) => {
                  const isExpanded = expandedStep === log.step;
                  return (
                    <div key={log.log_id}>
                      <button
                        onClick={() => setExpandedStep(isExpanded ? null : log.step)}
                        className="w-full flex flex-wrap items-center gap-x-2 gap-y-1 px-4 py-2.5 text-left hover:bg-slate-900/60 transition-colors"
                      >
                        {isExpanded
                          ? <ChevronDown className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                          : <ChevronRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />}
                        <span className="text-[11px] font-mono text-slate-500 shrink-0">#{log.step}</span>
                        <span
                          className="text-[11px] font-medium px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20 min-w-0 max-w-[52%] md:max-w-none truncate"
                          title={log.provider + (log.model ? `/${log.model}` : '')}
                        >
                          {log.provider}{log.model ? `/${log.model}` : ''}
                        </span>
                        {log.parsed_ok
                          ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          : <XCircle className="w-3.5 h-3.5 text-orange-400 shrink-0" />}
                        <span className="flex-1 min-w-0 text-[11px] text-slate-500 font-mono truncate">
                          {log.parsed_ok ? 'JSON çözümlendi' : 'çözümlenemedi → kural fallback'}
                        </span>
                        {typeof log.duration_ms === 'number' && (
                          <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-slate-600 font-mono shrink-0">
                            <Clock className="w-3 h-3" /> {log.duration_ms}ms
                          </span>
                        )}
                      </button>

                      {isExpanded && (
                        <div className="px-4 pb-4 space-y-3">
                          {/* SORU */}
                          <div>
                            <div className="flex items-center gap-1.5 mb-1 text-[10px] font-semibold uppercase tracking-wide text-blue-400">
                              <MessageSquare className="w-3 h-3" /> Soru (prompt)
                            </div>
                            <pre className="text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap font-mono bg-slate-900/70 rounded-lg p-3 border border-slate-800">
                              {log.prompt || '—'}
                            </pre>
                          </div>
                          {/* CEVAP */}
                          <div>
                            <div className="flex items-center gap-1.5 mb-1 text-[10px] font-semibold uppercase tracking-wide text-emerald-400">
                              <Terminal className="w-3 h-3" /> Cevap (ham)
                            </div>
                            <pre className="text-[11px] leading-relaxed text-emerald-200/80 whitespace-pre-wrap font-mono bg-slate-900/70 rounded-lg p-3 border border-slate-800">
                              {log.raw_response || '— (boş cevap / hata)'}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Alt bar */}
            <div className="flex items-center justify-between px-5 py-3 border-t border-slate-200 dark:border-slate-800 shrink-0">
              <span className="text-[11px] text-slate-500">
                {logs.length} danışma{!isDone && ' • tarama sürerken 5sn\'de bir tazelenir'}
              </span>
              <button
                onClick={() => setOpen(false)}
                className="px-4 py-1.5 rounded-lg text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
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
