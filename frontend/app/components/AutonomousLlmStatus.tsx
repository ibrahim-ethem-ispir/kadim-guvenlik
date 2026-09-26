import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router';
import { Brain, X, RefreshCw, CheckCircle2, AlertTriangle, Cpu, Cloud, HardDrive } from 'lucide-react';
import { api } from '../services/api';

/**
 * Otonom motorun AKTİF LLM (istihbarat subayı) durumunu gösterir.
 * Türkçe: Tarama BAŞLATMADAN "hangi LLM aktif, erişilebilir mi, motor LLM-destekli mi
 * yoksa kural-fallback mı çalışacak" bilgisini bir rozet + modal ile sunar. Aktif varsayılan
 * (4 sağlayıcı: ollama/deepseek/claude/gemini) AI Yapılandırması sayfasından seçilir (DB).
 * Backend: GET /api/settings/ai/autonomous-status (motorun kendi preflight'ını kullanır).
 */

interface LlmStatus {
  provider: string;                 // "ollama" | "deepseek" | "claude" | "gemini"
  model: string | null;
  configured?: boolean;             // .env'de anahtar/URL var mı (erişilemez ≠ yapılandırılmamış)
  reachable: boolean;               // sağlayıcı erişilebilir mi
  model_available: boolean;         // seçili model hazır mı
  mode: 'llm-assisted' | 'rules-only' | string;
  url?: string | null;
  error?: string;
}

// Provider'a göre ikon: local (Ollama) vs bulut (deepseek/claude/gemini).
function providerIcon(provider: string) {
  return provider === 'ollama' ? HardDrive : Cloud;
}

// Ollama dışındaki tüm sağlayıcılar bulut → hedef/tarama verisi harici sunucuya gider.
function dataLeavesNetwork(provider: string) {
  return provider !== 'ollama';
}

export default function AutonomousLlmStatus() {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<LlmStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<LlmStatus>('/api/settings/ai/autonomous-status');
      setStatus(data);
    } catch (e: any) {
      setError(e?.message || 'Durum alınamadı');
    } finally {
      setLoading(false);
    }
  }, []);

  // Rozet, sayfa açılışında hafif durumu bir kez çeker (küçük, hızlı bir GET).
  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Modal açıkken ESC ile kapat.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  const isAssisted = status?.mode === 'llm-assisted';
  const ProviderIcon = providerIcon(status?.provider || 'ollama');

  // Rozet rengi: aktif (yeşil) / kural-fallback (amber) / bilinmiyor (slate).
  const badgeTone = !status
    ? 'border-slate-300 dark:border-slate-700 text-slate-500'
    : isAssisted
      ? 'border-emerald-500/40 text-emerald-600 dark:text-emerald-400 bg-emerald-500/5'
      : 'border-amber-500/40 text-amber-600 dark:text-amber-400 bg-amber-500/5';

  return (
    <>
      {/* Rozet / buton */}
      <button
        type="button"
        onClick={() => { setOpen(true); fetchStatus(); }}
        className={`inline-flex items-center gap-2 px-3 py-2 rounded-full border text-sm font-medium transition-all hover:shadow-sm ${badgeTone}`}
        title="Aktif istihbarat LLM'ini görüntüle"
      >
        <Brain className="w-4 h-4" />
        <span>Aktif LLM</span>
        {status && (
          <span className="inline-flex items-center gap-1 font-mono text-[11px] opacity-80">
            <ProviderIcon className="w-3.5 h-3.5" />
            {status.provider}
          </span>
        )}
        <span className={`w-2 h-2 rounded-full ${
          !status ? 'bg-slate-400' : isAssisted ? 'bg-emerald-500' : 'bg-amber-500'
        }`} />
      </button>

      {/* Modal */}
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-fade-in"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Başlık */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-lg bg-violet-500/10">
                  <Brain className="w-5 h-5 text-violet-500" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 dark:text-white leading-tight">İstihbarat Subayı (LLM)</h3>
                  <p className="text-xs text-slate-500">Otonom motorun aktif danışman modeli</p>
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                aria-label="Kapat"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Gövde */}
            <div className="p-5 space-y-4">
              {loading && (
                <div className="flex items-center justify-center gap-2 py-6 text-slate-500">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Durum kontrol ediliyor...</span>
                </div>
              )}

              {!loading && error && (
                <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 text-sm">
                  <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {!loading && !error && status && (
                <>
                  {/* Mod özeti */}
                  <div className={`flex items-center gap-3 p-3 rounded-lg border ${
                    isAssisted
                      ? 'bg-emerald-500/5 border-emerald-500/30'
                      : 'bg-amber-500/5 border-amber-500/30'
                  }`}>
                    {isAssisted
                      ? <CheckCircle2 className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                      : <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0" />}
                    <div>
                      <p className="font-semibold text-sm text-slate-900 dark:text-white">
                        {isAssisted ? 'LLM destekli (istihbarat aktif)' : 'Kural + graf modu (LLM sezgisi kapalı)'}
                      </p>
                      <p className="text-xs text-slate-500">
                        {isAssisted
                          ? 'Motor, değer/olasılık takdirinde LLM danışmanlığını kullanacak.'
                          : 'LLM erişilemedi — karar mekanizması bozulmaz, deterministik kural+graf çalışır.'}
                      </p>
                    </div>
                  </div>

                  {/* Detay satırları */}
                  <dl className="space-y-2 text-sm">
                    <Row label="Sağlayıcı" icon={providerIcon(status.provider)}>
                      <span className="capitalize">{status.provider}</span>
                      <span className="ml-2 text-[11px] text-slate-400">
                        {dataLeavesNetwork(status.provider) ? '(bulut — veri dışarı çıkar)' : '(local — veri dışarı çıkmaz)'}
                      </span>
                    </Row>
                    <Row label="Model" icon={Cpu}>
                      <span className="font-mono text-xs break-all">{status.model || '—'}</span>
                    </Row>
                    <Row label="Erişilebilir" icon={status.reachable ? CheckCircle2 : AlertTriangle}>
                      <StatusPill
                        ok={status.reachable}
                        okText="Evet"
                        badText={status.configured === false ? 'Yapılandırılmamış' : 'Hayır'}
                      />
                    </Row>
                    <Row label="Model hazır" icon={status.model_available ? CheckCircle2 : AlertTriangle}>
                      <StatusPill ok={status.model_available} okText="Evet" badText="Hayır" />
                    </Row>
                    {status.url && (
                      <Row label="Adres" icon={ProviderIcon}>
                        <span className="font-mono text-xs break-all text-slate-500">{status.url}</span>
                      </Row>
                    )}
                  </dl>
                </>
              )}
            </div>

            {/* Alt bar */}
            <div className="flex items-center justify-between px-5 py-3 border-t border-slate-200 dark:border-slate-800">
              <Link
                to="/admin/ai-settings"
                className="text-[11px] text-violet-500 hover:text-violet-600 dark:hover:text-violet-400 hover:underline"
                onClick={() => setOpen(false)}
              >
                Değiştirmek için: AI Yapılandırması sayfası →
              </Link>
              <button
                onClick={fetchStatus}
                disabled={loading}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                Yenile
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// --- Küçük yardımcı alt bileşenler (yalnız bu modalda kullanılır) ---

function Row({ label, icon: Icon, children }: { label: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="flex items-center gap-2 text-slate-500 flex-shrink-0">
        <Icon className="w-4 h-4" />
        {label}
      </dt>
      <dd className="text-right text-slate-900 dark:text-slate-200">{children}</dd>
    </div>
  );
}

function StatusPill({ ok, okText, badText }: { ok: boolean; okText: string; badText: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
      ok
        ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
        : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
    }`}>
      {ok ? okText : badText}
    </span>
  );
}
