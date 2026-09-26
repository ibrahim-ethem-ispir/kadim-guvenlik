import { useEffect, useState } from 'react';
import { KeyRound, CheckCircle2, XCircle, ExternalLink, Loader2, Gift, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

interface IntegrationStatus {
  name: string;
  configured: boolean;
  requires_key: boolean;
  free_tier: boolean;
  signup_url: string;
  note: string;
}

interface IntegrationsResponse {
  reachable: boolean;
  integrations: IntegrationStatus[];
  error?: string;
}

const DISPLAY_NAME: Record<string, string> = {
  shodan: 'Shodan',
  virustotal: 'VirusTotal',
  abuseipdb: 'AbuseIPDB',
  securitytrails: 'SecurityTrails',
};

/**
 * OSINT API key durum paneli — "hangi kaynak aktif, hangisi eksik?" görünürlüğü.
 * Kullanıcı VirusTotal key'i eklediğinde burada yeşil görünür; Shodan yoksa "ücretsiz al" linki çıkar.
 */
export default function OsintKeyStatus() {
  const [data, setData] = useState<IntegrationsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.get<IntegrationsResponse>('/api/v2/osint/integrations');
      setData(res);
    } catch {
      setData({ reachable: false, integrations: [] });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const activeCount = data?.integrations.filter(i => i.configured).length ?? 0;
  const total = data?.integrations.length ?? 0;

  return (
    <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-amber-500/10">
            <KeyRound className="w-4 h-4 text-amber-500" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-slate-900 dark:text-white">İstihbarat Kaynakları (API Key)</h3>
            <p className="text-[11px] text-slate-500">
              {loading ? 'kontrol ediliyor…'
                : !data?.reachable ? 'OSINT servisine ulaşılamadı'
                : `${activeCount}/${total} kaynak aktif`}
            </p>
          </div>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400"
          title="Yenile"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
        </button>
      </div>

      <div className="p-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
        {loading && !data ? (
          <div className="col-span-full flex items-center gap-2 text-xs text-slate-400 p-3">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> yükleniyor…
          </div>
        ) : !data?.reachable ? (
          <div className="col-span-full text-xs text-red-500 p-3">
            OSINT servisi çevrimdışı — key durumu okunamıyor. {data?.error}
          </div>
        ) : (
          data.integrations.map((it) => (
            <div
              key={it.name}
              className={`flex items-start gap-3 p-3 rounded-xl border ${
                it.configured
                  ? 'border-emerald-500/30 bg-emerald-500/5'
                  : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40'
              }`}
            >
              <div className="mt-0.5">
                {it.configured
                  ? <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  : <XCircle className="w-4 h-4 text-slate-400" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                    {DISPLAY_NAME[it.name] || it.name}
                  </span>
                  <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded ${
                    it.configured
                      ? 'bg-emerald-500/10 text-emerald-500'
                      : 'bg-slate-400/10 text-slate-500'
                  }`}>
                    {it.configured ? 'AKTİF' : 'KEY YOK'}
                  </span>
                  {it.free_tier && (
                    <span className="inline-flex items-center gap-0.5 text-[10px] font-medium px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-500">
                      <Gift className="w-2.5 h-2.5" /> ücretsiz plan var
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-500 mt-0.5 leading-relaxed">{it.note}</p>
                {!it.configured && (
                  <a
                    href={it.signup_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 mt-1.5 text-[11px] font-medium text-violet-500 hover:text-violet-600"
                  >
                    <ExternalLink className="w-3 h-3" />
                    {it.free_tier ? 'Ücretsiz key al' : 'Key edinme sayfası'}
                  </a>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      <div className="px-5 py-2.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40">
        <p className="text-[11px] text-slate-500 leading-relaxed">
          💡 Key'ler orchestrator/OSINT servisine <span className="font-mono">.env</span> üzerinden verilir
          (<span className="font-mono">SHODAN_API_KEY</span>, <span className="font-mono">VIRUSTOTAL_API_KEY</span>,
          <span className="font-mono"> ABUSEIPDB_API_KEY</span>, <span className="font-mono">SECURITYTRAILS_API_KEY</span>).
          Servisi yeniden başlatınca burada güncellenir.
        </p>
      </div>
    </div>
  );
}
