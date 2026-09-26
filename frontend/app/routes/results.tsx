import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router';
import { Search, Terminal, AlertCircle, Loader2, Server, Globe, Download, Zap, ShieldAlert, Brain, ListChecks } from 'lucide-react';
import LiveTerminal from '../components/LiveTerminal';
import NucleiLiveResults from '../components/NucleiLiveResults';
import AIAnalysisPanel from '../components/AIAnalysisPanel';
import AutonomousTimeline from '../components/AutonomousTimeline';
import ComplianceAttestationPanel from '../components/ComplianceAttestationPanel';
import { generateScanReport } from '../libs/report-generator';
import { api } from '../services/api';

interface ScanResult {
  scan_id: string;
  target: string;
  status?: string;
  timestamp?: string;
  results: {
    nmap?: any;
    subfinder?: any;
    rustscan?: any;
    nuclei?: any;
    fuzz?: any;
  };
}

/** Otonom (v2) session — /api/v2/scan/{id}. Otonom tarama sonuçları burada durur. */
interface AutonomousSession {
  session_id: string;
  scan_id: string;
  target: string;
  profile?: string;
  status?: string;
  ai_analysis?: (Record<string, any> & { agent_timeline?: any[] }) | null;
}

export default function Results() {
  const [searchParams] = useSearchParams();
  const scanId = searchParams.get('id');
  const [data, setData] = useState<ScanResult | null>(null);
  const [autoSession, setAutoSession] = useState<AutonomousSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveOutput, setLiveOutput] = useState<string[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [ws, setWs] = useState<WebSocket | null>(null);

  // Türkçe: Live monitoring WebSocket bağlantısı kur
  const startMonitoring = () => {
    if (!scanId || isMonitoring) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/scan/monitor/${scanId}`;
    console.log("🔌 Monitoring WebSocket URL:", wsUrl);

    const websocket = new WebSocket(wsUrl);

    websocket.onopen = () => {
      console.log("✅ Monitoring WebSocket AÇILDI");
      setIsMonitoring(true);
      setLiveOutput([`📡 Canlı izleme başlatıldı (${new Date().toLocaleTimeString()})`]);
    };

    websocket.onmessage = (event) => {
      console.log("📨 Monitoring mesaj:", event.data);
      const msg = JSON.parse(event.data);

      if (msg.type === "output") {
        setLiveOutput(prev => [...prev, msg.data]);
      } else if (msg.type === "error") {
        setLiveOutput(prev => [...prev, `❌ Hata: ${msg.message}`]);
      }
    };

    websocket.onerror = (error) => {
      console.error("❌ Monitoring WebSocket HATA:", error);
      setLiveOutput(prev => [...prev, "⚠️ Bağlantı hatası"]);
    };

    websocket.onclose = (event) => {
      console.log("🔒 Monitoring WebSocket KAPANDI:", event.code);
      setIsMonitoring(false);
      setLiveOutput(prev => [...prev, `🔌 Bağlantı kapatıldı (${new Date().toLocaleTimeString()})`]);
    };

    setWs(websocket);
  };

  // Türkçe: Monitoring'i durdur
  const stopMonitoring = () => {
    if (ws) {
      ws.close();
      setWs(null);
      setIsMonitoring(false);
    }
  };

  const fetchData = async () => {
    if (!scanId) return;
    let terminal = false;
    try {
      const json = await api.get<ScanResult>(`/api/scan/${scanId}`);
      setData(json);
      if (json.status === 'completed' || json.status === 'failed' || json.status === 'cancelled') {
        terminal = true;
      }
    } catch (err) {
      // Legacy scan yoksa hata basma — otonom session olabilir.
      setData(null);
    }

    // Otonom (v2) session'ı ayrıca dene — otonom taramalar burada durur.
    try {
      const sess = await api.get<AutonomousSession>(`/api/v2/scan/${scanId}`);
      if (sess && sess.profile === 'autonomous') {
        setAutoSession(sess);
        if (sess.status === 'completed' || sess.status === 'failed' || sess.status === 'cancelled') {
          terminal = true;
        } else {
          terminal = false; // otonom hâlâ çalışıyorsa polling sürsün
        }
      }
    } catch {
      // v2 session yoksa sorun değil (saf legacy tarama).
    }

    if (terminal) stopMonitoring();
    // Ne legacy ne v2 bulunduysa hata göster.
    if (!data && !autoSession) {
      // ilk denemede state henüz set edilmemiş olabilir; sessiz geç.
    }
    return terminal;
  };

  useEffect(() => {
    let interval: any = null;

    const init = async () => {
      const shouldStop = await fetchData();
      if (!shouldStop) {
        interval = setInterval(async () => {
          const finished = await fetchData();
          if (finished && interval) {
            clearInterval(interval);
          }
        }, 5000);
      }
    };

    init();

    return () => {
      if (interval) clearInterval(interval);
      stopMonitoring(); // Component unmount olurken WebSocket'i kapat
    };
  }, [scanId]);

  if (!scanId) {
    return (
      <div className="space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl md:text-3xl font-bold text-slate-900 dark:text-white mb-2">Tarama Sonuçları</h1>
            <p className="text-slate-600 dark:text-slate-400">Geçmiş tarama raporları ve detaylı analizler.</p>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-8 md:p-12 text-center backdrop-blur-sm shadow-sm dark:shadow-none">
          <div className="w-16 h-16 md:w-20 md:h-20 bg-slate-100 dark:bg-slate-800/50 rounded-full flex items-center justify-center mx-auto mb-6 border border-slate-200 dark:border-slate-700">
            <Terminal className="w-8 h-8 md:w-10 md:h-10 text-slate-400 dark:text-slate-500" />
          </div>
          <h3 className="text-lg md:text-xl font-semibold text-slate-900 dark:text-white mb-2">Sonuç Bulunamadı</h3>
          <p className="text-slate-500 dark:text-slate-400 max-w-md mx-auto mb-8">
            Görüntülenecek tarama ID'si belirtilmedi. Yeni bir tarama başlatarak sistem güvenliğini analiz edin.
          </p>
          <a
            href="/scan"
            className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-600/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/50 rounded-lg hover:bg-emerald-600/30 transition-all font-medium"
          >
            <Search className="w-4 h-4" />
            Yeni Tarama Başlat
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 md:space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-slate-900 dark:text-white mb-2">Tarama Sonuçları</h1>
          <p className="text-slate-600 dark:text-slate-400">ID: <span className="font-mono text-emerald-600 dark:text-emerald-400">{scanId}</span></p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => data && generateScanReport(data)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm"
          >
            <Download className="w-4 h-4" />
            Raporla (PDF)
          </button>
          {!isMonitoring ? (
            <button
              onClick={startMonitoring}
              className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors text-sm"
            >
              <Terminal className="w-4 h-4" />
              Canlı İzle
            </button>
          ) : (
            <button
              onClick={stopMonitoring}
              className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors text-sm"
            >
              <Terminal className="w-4 h-4" />
              İzlemeyi Durdur
            </button>
          )}
          <a
            href="/scan"
            className="inline-flex items-center gap-2 px-4 py-2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors text-sm"
          >
            <Search className="w-4 h-4" />
            Yeni Tarama
          </a>
        </div>
      </div>

      {/* Türkçe: Canlı izleme çıktısı */}
      {isMonitoring && liveOutput.length > 0 && (
        <div className="bg-slate-950 border border-emerald-500/30 rounded-xl overflow-hidden">
          <div className="bg-slate-900 px-4 py-3 border-b border-slate-800 flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
              <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></div>
            </div>
            <span className="text-sm text-slate-400 font-mono ml-2">📡 Canlı Tarama İzleme</span>
          </div>
          <div className="p-4 max-h-96 overflow-y-auto font-mono text-sm text-emerald-400 space-y-1">
            {liveOutput.map((line, i) => (
              <div key={i} className="whitespace-pre-wrap">{line}</div>
            ))}
          </div>
        </div>
      )}

      {error ? (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-red-400 flex items-center gap-4">
          <AlertCircle className="w-6 h-6" />
          <p>{error}</p>
        </div>
      ) : !data && !autoSession ? (
        <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-12 text-center shadow-sm dark:shadow-none">
          <Loader2 className="w-10 h-10 text-emerald-500 animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Sonuçlar yükleniyor...</p>
        </div>
      ) : (
        <div className="grid gap-6">
          {/* Otonom (Kuşatma Doktrini) sonuçları — timeline + kanıtlar + adım artifact'leri */}
          {autoSession && (
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-violet-500/30 overflow-hidden shadow-sm dark:shadow-none">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center gap-3 bg-violet-500/5">
                <div className="p-2 bg-violet-500/10 rounded-lg">
                  <Brain className="w-5 h-5 text-violet-500" />
                </div>
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-white">Otonom Saldırı Simülasyonu (Kuşatma Doktrini)</h3>
                  <p className="text-xs text-slate-500">
                    {autoSession.target} · durum: {autoSession.status || '—'}
                  </p>
                </div>
              </div>
              <div className="p-4">
                <AutonomousTimeline
                  scanId={autoSession.scan_id}
                  sessionId={autoSession.session_id}
                  initialTimeline={autoSession.ai_analysis?.agent_timeline}
                  summary={autoSession.status === 'completed' ? autoSession.ai_analysis ?? undefined : undefined}
                />
              </div>
            </div>
          )}

          {/* AI Uyum & Güvence — OWASP LLM Top-10 (2025) / EU AI Act attestation.
              Degrade-safe: attestation yoksa panel kendini render etmez. */}
          {autoSession?.ai_analysis?.compliance_attestation && (
            <ComplianceAttestationPanel attestation={autoSession.ai_analysis.compliance_attestation} />
          )}

          {/* Legacy (statik pipeline) sonuçları — yalnız legacy scan varsa */}
          {data && data.results && (<>
          {/* Nmap Results */}
          {data.results.nmap && (
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm dark:shadow-none">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900/80">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-emerald-500/10 rounded-lg">
                    <Server className="w-5 h-5 text-emerald-500" />
                  </div>
                  <h3 className="font-semibold text-slate-900 dark:text-white">Nmap Port Taraması</h3>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${data.results.nmap.status === 'completed' || data.results.nmap.output
                    ? 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
                    : 'bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400'
                    }`}>
                    {data.results.nmap.status === 'completed' || data.results.nmap.output ? 'Tamamlandı' : 'Devam Ediyor'}
                  </span>
                </div>
              </div>

              <div className="p-0">
                {/* Canlı ham log terminali: nmap + nuclei çıktısını tek akışta gösterir */}
                <LiveTerminal scanId={scanId} title="Canlı Ham Log Akışı" />
              </div>
            </div>
          )}

          {/* RustScan Results */}
          {data.results.rustscan && (
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm dark:shadow-none">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900/80">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-orange-500/10 rounded-lg">
                    <Zap className="w-5 h-5 text-orange-500" />
                  </div>
                  <h3 className="font-semibold text-slate-900 dark:text-white">RustScan Hızlı Tarama</h3>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium ${data.results.rustscan.status === 'completed'
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : data.results.rustscan.status === 'failed' || data.results.rustscan.status === 'timeout'
                    ? 'bg-red-500/10 text-red-400'
                    : 'bg-blue-500/10 text-blue-400'
                  }`}>
                  {data.results.rustscan.status === 'completed' ? 'Tamamlandı'
                    : data.results.rustscan.status === 'failed' ? 'Başarısız'
                      : data.results.rustscan.status === 'timeout' ? 'Zaman Aşımı'
                        : 'Devam Ediyor'}
                </span>
              </div>
              <div className="p-4">
                {/* Port ve Servis Sonuçları */}
                {data.results.rustscan.open_ports && data.results.rustscan.open_ports.length > 0 ? (
                  <div className="space-y-4">
                    {/* Port Sayısı Özeti */}
                    <div className="flex items-center gap-3 p-3 bg-orange-50 dark:bg-orange-500/10 rounded-lg border border-orange-200 dark:border-orange-500/20">
                      <Zap className="w-5 h-5 text-orange-500" />
                      <span className="text-orange-700 dark:text-orange-400 font-medium">
                        {data.results.rustscan.open_ports_count || data.results.rustscan.open_ports.length} açık port bulundu
                      </span>
                    </div>

                    {/* Port Listesi */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2">
                      {data.results.rustscan.open_ports.map((port: number) => (
                        <div key={port} className="px-3 py-2 bg-slate-100 dark:bg-slate-800 rounded-lg text-center">
                          <span className="font-mono font-bold text-orange-600 dark:text-orange-400">{port}</span>
                        </div>
                      ))}
                    </div>

                    {/* Servis Detayları */}
                    {data.results.rustscan.services && data.results.rustscan.services.length > 0 && (
                      <div className="mt-4">
                        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Servis Detayları</h4>
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="text-left text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                                <th className="py-2 px-3">Port</th>
                                <th className="py-2 px-3">Protokol</th>
                                <th className="py-2 px-3">Durum</th>
                                <th className="py-2 px-3">Servis</th>
                              </tr>
                            </thead>
                            <tbody>
                              {data.results.rustscan.services.map((svc: any, i: number) => (
                                <tr key={i} className="border-b border-slate-100 dark:border-slate-800">
                                  <td className="py-2 px-3 font-mono text-orange-600 dark:text-orange-400">{svc.port}</td>
                                  <td className="py-2 px-3 text-slate-600 dark:text-slate-400">{svc.protocol}</td>
                                  <td className="py-2 px-3">
                                    <span className={`px-2 py-0.5 rounded text-xs ${svc.state === 'open' ? 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
                                        : svc.state === 'filtered' ? 'bg-yellow-100 dark:bg-yellow-500/10 text-yellow-700 dark:text-yellow-400'
                                          : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
                                      }`}>
                                      {svc.state}
                                    </span>
                                  </td>
                                  <td className="py-2 px-3 text-slate-700 dark:text-slate-300">{svc.service || '-'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* Ham Çıktı (Opsiyonel) */}
                    {data.results.rustscan.raw_output && (
                      <details className="mt-4">
                        <summary className="cursor-pointer text-sm text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300">
                          Ham çıktıyı göster
                        </summary>
                        <pre className="mt-2 font-mono text-xs text-slate-600 dark:text-slate-400 whitespace-pre-wrap overflow-x-auto max-h-[300px] bg-slate-50 dark:bg-slate-950/50 p-4 rounded-lg">
                          {data.results.rustscan.raw_output}
                        </pre>
                      </details>
                    )}
                  </div>
                ) : data.results.rustscan.output ? (
                  <pre className="font-mono text-xs sm:text-sm text-slate-800 dark:text-slate-300 whitespace-pre-wrap overflow-x-auto max-h-[500px] bg-slate-50 dark:bg-transparent p-4 rounded-lg">
                    {data.results.rustscan.output}
                  </pre>
                ) : data.results.rustscan.error ? (
                  <div className="p-4 bg-red-50 dark:bg-red-500/10 rounded-lg border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400">
                    <p className="font-medium">Hata: {data.results.rustscan.error}</p>
                  </div>
                ) : (
                  <div className="flex items-center justify-center py-12 text-slate-500">
                    {data.status === 'completed' ? (
                      <span className="text-slate-500">Açık port bulunamadı</span>
                    ) : (
                      <>
                        <Loader2 className="w-6 h-6 animate-spin mr-2" />
                        Tarama devam ediyor...
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Subfinder Results */}
          {data.results.subfinder && (
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm dark:shadow-none">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900/80">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-cyan-500/10 rounded-lg">
                    <Globe className="w-5 h-5 text-cyan-500" />
                  </div>
                  <h3 className="font-semibold text-slate-900 dark:text-white">Subfinder Subdomain Keşfi</h3>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium ${data.results.subfinder.status === 'completed' || data.results.subfinder.subdomains
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : 'bg-blue-500/10 text-blue-400'
                  }`}>
                  {data.results.subfinder.status === 'completed' || data.results.subfinder.subdomains ? 'Tamamlandı' : 'Devam Ediyor'}
                </span>
              </div>
              <div className="p-4">
                {data.results.subfinder.subdomains && data.results.subfinder.subdomains.length > 0 ? (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-sm text-slate-500 dark:text-slate-400">
                        {data.results.subfinder.subdomains_count || data.results.subfinder.subdomains.length} subdomain bulundu
                      </span>
                      {data.results.subfinder.source_counts && (
                        <div className="flex gap-2">
                          {Object.entries(data.results.subfinder.source_counts).map(([source, count]: [string, any]) => (
                            <span key={source} className="text-xs px-2 py-1 bg-cyan-100 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 rounded">
                              {source}: {count}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="max-h-[300px] overflow-y-auto font-mono text-xs text-cyan-700 dark:text-cyan-400 bg-cyan-50 dark:bg-slate-950/50 rounded-lg p-3">
                      {data.results.subfinder.subdomains.map((subdomain: string, i: number) => (
                        <div key={i} className="py-0.5 hover:bg-cyan-500/10 px-2 rounded">
                          {subdomain}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-center py-12 text-slate-500">
                    {data.status === 'completed' ? (
                      <span className="text-slate-500">Subdomain bulunamadı</span>
                    ) : (
                      <>
                        <Loader2 className="w-6 h-6 animate-spin mr-2" />
                        Tarama devam ediyor...
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Nuclei Results */}
          {data.results.nuclei && (
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm dark:shadow-none">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900/80">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/10 rounded-lg">
                    <ShieldAlert className="w-5 h-5 text-purple-500" />
                  </div>
                  <h3 className="font-semibold text-slate-900 dark:text-white">Nuclei Zafiyet Taraması</h3>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium ${data.results.nuclei.status === 'completed'
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : 'bg-blue-500/10 text-blue-400'
                  }`}>
                  {data.results.nuclei.status === 'completed' ? 'Tamamlandı' : 'Devam Ediyor'}
                </span>
                {data.results.nuclei.status === 'completed' && (
                  <button
                    onClick={() => window.open(`/api/nuclei/logs/${scanId}`, '_blank')}
                    className="p-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-purple-600 dark:hover:text-purple-400 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                    title="Logları İndir"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                )}
              </div>

              <div className="p-4">
                {/* SCAN-SCOPE'LU ZAFIYET KÖPRÜSÜ: "2 kritik dedi ama nerede?" → tam bu taramanın
                    bulguları, kanıt kademeleriyle (kanıtlı / olası / incelenecek) ve proof ile.
                    Manşet sayımı motorun confirmed_critical_count'u ile AYNI kuralı kullanır. */}
                <Link
                  to={`/vulnerabilities?scan_id=${encodeURIComponent(scanId)}`}
                  className="inline-flex items-center gap-2 mb-3 px-3 py-1.5 rounded-lg text-sm bg-purple-50 dark:bg-purple-950/30 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/50 hover:bg-purple-100 dark:hover:bg-purple-900/40 transition-colors"
                >
                  <ListChecks className="w-4 h-4" />
                  Bu taramanın zafiyetlerini kanıt kademeleriyle gör
                </Link>
                <NucleiLiveResults
                  scanId={scanId}
                  initialStatus={data.results.nuclei?.status}
                  initialFindings={data.results.nuclei?.findings}
                />
              </div>
            </div>
          )}

          {/* Fuzzing Results */}
          {data.results.fuzz && (
            <div className="bg-white dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm dark:shadow-none">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900/80">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/10 rounded-lg">
                    <Zap className="w-5 h-5 text-purple-500" />
                  </div>
                  <h3 className="font-semibold text-slate-900 dark:text-white">Fuzzing & Keşif Sonuçları</h3>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium ${data.results.fuzz.status === 'completed'
                  ? 'bg-emerald-500/10 text-emerald-400'
                  : 'bg-blue-500/10 text-blue-400'
                  }`}>
                  {data.results.fuzz.status === 'completed' ? 'Tamamlandı' : 'Devam Ediyor'}
                </span>
              </div>
              <div className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm text-slate-500 dark:text-slate-400">
                    {data.results.fuzz.findings_count != null ? data.results.fuzz.findings_count : '0'} benzersiz yol bulundu
                  </span>
                </div>

                {/* Note: FuzzLogs are in separate collection, Orchestrator only returns finding count in summary usually 
                     unless we updated complete_scan_in_wrapper to include them. 
                     For now, we just show status. If we want detailed list, we need an endpoint or fetch them.
                     Fuzz Service/Orchestrator currently puts findings into FuzzLogs.
                     Let's assume we view Live Terminal for details or just status for now. 
                     Ideally we should have a 'FuzzLiveResults' component or fetch logs.
                     For MVP, let's point to the Monitoring log or add a download button if log available.
                 */}
                <div className="p-4 bg-slate-50 dark:bg-slate-950/50 rounded-lg border border-slate-200 dark:border-slate-800 text-center">
                  <p className="text-slate-500 dark:text-slate-400 text-sm mb-2">
                    Fuzzing işlemi {data.results.fuzz.status === 'completed' ? 'tamamlandı' : 'devam ediyor'}.
                  </p>
                  {data.results.fuzz.status === 'completed' && (
                    <p className="text-emerald-600 dark:text-emerald-400 font-bold">
                      Toplam {data.results.fuzz.findings_count || 0} bulgu tespit edildi.
                    </p>
                  )}
                  <div className="mt-4">
                    <button
                      onClick={() => window.open(`/api/fuzz/logs/${scanId}`, '_blank')}
                      className="px-4 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded text-slate-600 dark:text-slate-300 text-sm transition-colors"
                    >
                      Sonuç Loglarını İndir (JSON)
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
          </>)}

          {/* AI Güvenlik Analizi */}
          <AIAnalysisPanel
            scanId={scanId}
            analysisType="security"
            title="🤖 AI Güvenlik Analizi"
          />
        </div>
      )}
    </div>
  );
}
