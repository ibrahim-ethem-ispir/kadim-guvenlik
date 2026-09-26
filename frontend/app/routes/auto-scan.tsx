import { useState, useEffect, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import {
  Search, Terminal, Shield, Play, EyeOff,
  Clock, ChevronRight, Loader2, CheckCircle2, XCircle,
  AlertTriangle, Activity, Timer, Crosshair, Bug, Wifi,
  Eye, Brain
} from 'lucide-react';
import { api } from '../services/api';
import { usePipelineStream } from '../hooks/usePipelineStream';
import AutonomousTimeline from '../components/AutonomousTimeline';
import OsintKeyStatus from '../components/OsintKeyStatus';
import AutonomousLlmStatus from '../components/AutonomousLlmStatus';
import LlmLogsModal from '../components/LlmLogsModal';
import WafBadge from '../components/WafBadge';
import EngineAwareness from '../components/EngineAwareness';
import CoverageContract from '../components/CoverageContract';
import ComplianceAttestationPanel from '../components/ComplianceAttestationPanel';
import OastMonitorBadge from '../components/OastMonitorBadge';
import FingerprintBadge from '../components/FingerprintBadge';
import AssetDiffCard from '../components/AssetDiffCard';
import CveIntelPanel from '../components/CveIntelPanel';
import { useAuth } from '../context/AuthContext';

interface PipelineStage {
  tool: string;
  status: string;
  parallel_group?: string;
  duration?: number;
}

interface PipelineSession {
  session_id: string;
  scan_id: string;
  target: string;
  profile: string;
  status: string;
  stages: Record<string, PipelineStage>;
  // Otonom mod (Kuşatma Doktrini): agent_timeline EKSİK-0'ın kalıcı kaynağı, reconnect'te
  // AutonomousTimeline'ı seed eder. Diğer alanlar engine.summary() ile aynı.
  ai_analysis?: (Record<string, any> & { agent_timeline?: any[] }) | null;
  duration_seconds?: number;
}

const PROFILE_COLORS: Record<string, string> = {
  quick: 'emerald',
  normal: 'blue',
  full: 'red',
  stealth: 'slate',
  web: 'purple',
  infra: 'orange',
  cf_bypass: 'cyan',
  lazarus: 'rose',
  recon_only: 'teal',
  autonomous: 'violet',
};

// ---- Tek Doktrin: 3 tarama seviyesi (statik profillerin yerine) ----
interface ScanLevelCard {
  id: 'recon' | 'standard' | 'deep';
  name: string;
  description: string;
  icon: any;
  color: string;
  detail: string;
}

const SCAN_LEVELS: ScanLevelCard[] = [
  {
    id: 'recon',
    name: 'Kesif',
    description: 'Pasif harita — pahali arac calismaz. Sunucudaki domainleri, servisleri, saldiri yuzeyini cikarir.',
    icon: Eye,
    color: 'teal',
    detail: 'recon, subfinder, osint, origin_discovery',
  },
  {
    id: 'standard',
    name: 'Standart',
    description: 'Kesif + en zayif noktalara HEDEFLI zafiyet taramasi + hassas yol ifsasi (.env/.git). Kor tarama yok, kanit odakli.',
    icon: Shield,
    color: 'blue',
    detail: 'nmap (kademeli) + nuclei (servis-hedefli) + pathprobe (.env/.git/yedek)',
  },
  {
    id: 'deep',
    name: 'Derin',
    description: 'Tam derinlik: fuzz + pivot + gizli portlar. En yuksek butce, en kapsamli kusatma.',
    icon: Crosshair,
    color: 'red',
    detail: 'nmap -p- + nuclei + fuzz + pathprobe + pivot',
  },
];

const STAGE_STATUS_ICON: Record<string, any> = {
  pending: Clock,
  running: Loader2,
  completed: CheckCircle2,
  failed: XCircle,
  timeout: AlertTriangle,
  skipped: ChevronRight,
  cancelled: XCircle,
};

export default function AutoScan() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [target, setTarget] = useState('');
  // Sayfa yenilenince aktif tarama ekranı uçmasın: session_id URL'de tutulur, mount'ta geri yüklenir.
  const [restoring, setRestoring] = useState<boolean>(() => !!searchParams.get('session'));
  const [selectedLevel, setSelectedLevel] = useState<'recon' | 'standard' | 'deep'>('standard');
  const [stealth, setStealth] = useState(false);
  // Dayanıklılık & maruz-kalma probu (L7 DoS + origin-CDN-bypass + SSH parola-auth).
  // VARSAYILAN KAPALI — operatör bilinçli açar. Açıkken motor TAHRİBATSIZ dayanıklılık
  // göstergeleri toplar (gerçek DDoS/brute-force atmaz).
  const [resilience, setResilience] = useState(false);
  // Operatör "bu hedef ne?" ipucu — otomatik parmak-izi ıskalarsa tipi damgalar.
  // 'api' seçince motor uygulama tipini API çerçeveler → kitlesel BOLA/broken-auth önceliklenir.
  const [targetKind, setTargetKind] = useState<'auto' | 'api' | 'web' | 'server'>('auto');
  // T1-B: kimlik doğrulamalı tarama — login-ARKASI yüzey (gerçek zafiyetlerin ~%80'i).
  const [showAuth, setShowAuth] = useState(false);
  const [authBearer, setAuthBearer] = useState('');
  const [authCookie, setAuthCookie] = useState('');
  const [authHeaders, setAuthHeaders] = useState('');  // her satır "Ad: değer"
  // T2-A: İKİNCİ hesap kimliği — IDOR/BOLA iki-hesap diferansiyeli (confirmed kanıt).
  const [authBBearer, setAuthBBearer] = useState('');
  const [authBCookie, setAuthBCookie] = useState('');
  const [authBHeaders, setAuthBHeaders] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Pipeline tracking
  const [activeSession, setActiveSession] = useState<PipelineSession | null>(null);
  const [polling, setPolling] = useState(false);

  // Live event tracking
  const [liveFindings, setLiveFindings] = useState<any[]>([]);
  const [livePorts, setLivePorts] = useState<any[]>([]);
  const [showEventLog, setShowEventLog] = useState(false);
  const eventLogRef = useRef<HTMLDivElement>(null);
  // Canlı akışta yakalanan WAF tespiti (waf_detect anlık olayı) — session'dan önce gelir.
  const [liveWaf, setLiveWaf] = useState<any>(null);

  // WebSocket stream
  const pipelineStream = usePipelineStream({
    onPortFound: (data) => {
      setLivePorts(prev => [...prev, data]);
    },
    onVulnerabilityFound: (data) => {
      setLiveFindings(prev => [...prev, data]);
    },
    // WAF tespiti AGENT_OBSERVATION olayıyla yayılır (data.waf) — rozeti anında besle.
    onAgentObservation: (obs: any) => {
      if (obs?.waf) setLiveWaf(obs.waf);
    },
    onCompleted: () => {
      // Force a final poll to get complete data
      if (activeSession) {
        pollSession(activeSession.session_id);
      }
    },
    onFailed: (err) => {
      setError(err);
    },
  });

  // Mount'ta URL'de ?session=... varsa aktif taramayı geri yükle (sayfa yenileme dayanıklılığı).
  // Tarama hâlâ sürüyorsa polling + canlı WS akışını yeniden bağlar; bittiyse son durumu gösterir.
  useEffect(() => {
    const sid = searchParams.get('session');
    if (!sid) {
      setRestoring(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const data = await api.get<PipelineSession>(`/api/v2/scan/${sid}`);
        if (cancelled) return;
        setActiveSession(data);
        const isLive = data.status === 'running' || data.status === 'awaiting_approval';
        if (isLive) {
          setPolling(true);
          if (data.scan_id) pipelineStream.connect(data.scan_id);
        }
      } catch {
        // Session bulunamadı (ör. sunucu yeniden başladı / süresi doldu) → URL'i temizle, form'a dön.
        if (!cancelled) setSearchParams({}, { replace: true });
      } finally {
        if (!cancelled) setRestoring(false);
      }
    })();
    return () => { cancelled = true; };
    // Yalnızca ilk mount'ta çalışır — sonraki tarama başlatmaları handleScan üzerinden yürür.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Poll for active session status
  useEffect(() => {
    if (!activeSession || !polling) return;
    if (activeSession.status === 'completed' || activeSession.status === 'failed' || activeSession.status === 'cancelled') {
      setPolling(false);
      pipelineStream.disconnect();
      return;
    }

    const interval = setInterval(() => {
      pollSession(activeSession.session_id);
    }, 3000);

    return () => clearInterval(interval);
  }, [activeSession?.session_id, activeSession?.status, polling]);

  // §2.1: Tarama bitince AI raporu ARKA PLANDA üretilir (async). report_status'u yakalamak
  // için tamamlandıktan sonra çözülene (ok/failed) kadar yoklamaya devam et — böylece rapor
  // sessizce kaybolmaz; UI rozet + 'yeniden dene' gösterebilir.
  useEffect(() => {
    if (!activeSession || activeSession.status !== 'completed') return;
    const rs = activeSession.ai_analysis?.report_status;
    if (rs === 'ok' || rs === 'failed') return;
    const interval = setInterval(() => pollSession(activeSession.session_id), 4000);
    return () => clearInterval(interval);
  }, [activeSession?.session_id, activeSession?.status, activeSession?.ai_analysis?.report_status]);

  // Auto-scroll event log
  useEffect(() => {
    if (eventLogRef.current && showEventLog) {
      eventLogRef.current.scrollTop = eventLogRef.current.scrollHeight;
    }
  }, [pipelineStream.events, showEventLog]);

  const pollSession = async (sessionId: string) => {
    try {
      const data = await api.get<PipelineSession>(`/api/v2/scan/${sessionId}`);
      setActiveSession(data);
      if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
        setPolling(false);
        pipelineStream.disconnect();
      }
    } catch (err) {
      console.error('Polling error:', err);
    }
  };

  const validateTarget = (item: string) => {
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return domainRegex.test(item) || ipRegex.test(item);
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLiveFindings([]);
    setLivePorts([]);

    const cleanTarget = target.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (!cleanTarget) {
      setError('Hedef adresi bos olamaz.');
      return;
    }
    if (!validateTarget(cleanTarget)) {
      setError('Gecersiz hedef formati. Lutfen gecerli bir domain veya IP adresi girin.');
      return;
    }

    setLoading(true);
    try {
      // T1-B: auth objesi — yalnız doldurulan alanlar gönderilir (backend bearer/cookie/headers okur).
      const authObj: any = {};
      if (authBearer.trim()) authObj.bearer = authBearer.trim();
      if (authCookie.trim()) authObj.cookie = authCookie.trim();
      const hdrLines = authHeaders.split('\n').map(l => l.trim()).filter(l => l.includes(':'));
      if (hdrLines.length) authObj.headers = hdrLines;

      // T2-A: ikinci hesap (auth_b) — verilirse IDOR iki-hesap diferansiyeli confirmed olur.
      const authBObj: any = {};
      if (authBBearer.trim()) authBObj.bearer = authBBearer.trim();
      if (authBCookie.trim()) authBObj.cookie = authBCookie.trim();
      const hdrBLines = authBHeaders.split('\n').map(l => l.trim()).filter(l => l.includes(':'));
      if (hdrBLines.length) authBObj.headers = hdrBLines;

      const data = await api.post<any>('/api/v2/scan', {
        target: cleanTarget,
        profile: 'autonomous',
        level: selectedLevel,
        stealth,
        ...(resilience ? { resilience: true } : {}),
        ...(targetKind !== 'auto' ? { target_kind: targetKind } : {}),
        ...(Object.keys(authObj).length ? { auth: authObj } : {}),
        ...(Object.keys(authBObj).length ? { auth_b: authBObj } : {}),
      });

      if (data.session_id) {
        setActiveSession({
          session_id: data.session_id,
          scan_id: data.scan_id,
          target: cleanTarget,
          profile: data.profile || 'autonomous',
          status: 'running',
          stages: data.stages?.reduce((acc: any, s: string) => {
            acc[s] = { tool: s, status: 'pending' };
            return acc;
          }, {}) || {},
        });
        setPolling(true);
        // Sayfa yenilenirse tarama ekranı uçmasın: session_id'yi URL'e yaz (geri yükleme anahtarı).
        setSearchParams({ session: data.session_id }, { replace: true });

        // Connect WebSocket for live events
        pipelineStream.connect(data.scan_id);
      }
    } catch (err: any) {
      setError(err.message || 'Tarama baslatilamadi');
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    if (!activeSession) return;
    try {
      await api.post(`/api/v2/scan/${activeSession.session_id}/cancel`, {});
      setActiveSession(prev => prev ? { ...prev, status: 'cancelled' } : null);
      setPolling(false);
      pipelineStream.disconnect();
    } catch (err) {
      console.error('Cancel error:', err);
    }
  };

  // §2.1: AI raporu üretilemediyse (report_status='failed') kullanıcı-tetiklemeli yeniden üret.
  // Motor artık çalışmadığından backend kanıt+özeti Mongo'dan yeniden kurup raporu tekrar gönderir.
  const handleRetryReport = async () => {
    if (!activeSession) return;
    try {
      await api.post(`/api/v2/scan/${activeSession.session_id}/report/retry`, {});
      // İyimser: pending'e çek → rozet "üretiliyor" olur ve post-completion effect yoklamaya başlar.
      setActiveSession(prev => prev
        ? { ...prev, ai_analysis: { ...(prev.ai_analysis || {}), report_status: 'pending', report_error: undefined } }
        : null);
    } catch (err) {
      console.error('Report retry error:', err);
    }
  };

  // §2.5: Duraklat/Devam — cancel'dan farkı geri dönüşlü olması. Çalışan stage'i kesmez,
  // sıradaki hamleyi bekletir; devam edilince kaldığı yerden sürer.
  const handlePause = async () => {
    if (!activeSession) return;
    try {
      await api.post(`/api/v2/scan/${activeSession.session_id}/pause`, {});
      setActiveSession(prev => prev ? { ...prev, status: 'paused' } : null);
    } catch (err) {
      console.error('Pause error:', err);
    }
  };

  const handleResume = async () => {
    if (!activeSession) return;
    try {
      await api.post(`/api/v2/scan/${activeSession.session_id}/resume`, {});
      setActiveSession(prev => prev ? { ...prev, status: 'running' } : null);
    } catch (err) {
      console.error('Resume error:', err);
    }
  };

  const handleViewResults = () => {
    if (activeSession?.scan_id) {
      navigate(`/results?id=${activeSession.scan_id}`);
    }
  };

  const handleNewScan = () => {
    setActiveSession(null);
    setTarget('');
    setError(null);
    setLiveFindings([]);
    setLivePorts([]);
    setSearchParams({}, { replace: true });   // URL'deki session anahtarını temizle → form ekranına dön
    pipelineStream.disconnect();
  };

  // ---- URL'den tarama geri yükleniyor — form/tarama ekranı flash etmesin ----
  if (restoring) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex items-center gap-3 text-slate-500 dark:text-slate-400">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span className="text-sm">Aktif tarama geri yukleniyor...</span>
        </div>
      </div>
    );
  }

  // ---- Otonom Mod (Kuşatma Doktrini) — attack-graph tabanli kusatma, statik stage YOK ----
  if (activeSession && activeSession.profile === 'autonomous') {
    const isAwaitingApproval = activeSession.status === 'awaiting_approval';
    const isPaused = activeSession.status === 'paused';   // §2.5: duraklatıldı (geri dönüşlü)
    const isRunning = activeSession.status === 'running' || isAwaitingApproval;
    const isActive = isRunning || isPaused;               // iptal edilebilir aktif durumlar
    const isDone = activeSession.status === 'completed' || activeSession.status === 'failed' || activeSession.status === 'cancelled';
    // Reconnect: onay bekleyen session'da recon_map'ten kapıyı yeniden kur.
    const reconnectGate = isAwaitingApproval && activeSession.ai_analysis?.recon_map
      ? { recon_map: activeSession.ai_analysis.recon_map }
      : null;

    return (
      <div className="min-h-screen py-3 px-3 md:px-5">
        <div className="max-w-8xl mx-auto space-y-4">
          {/* STICKY HEADER BAR — hedef + durum + TÜM aksiyonlar tek yerde (üste açılan
              davranışlar buradan yönetilir; sayfa aşağı kaysa da erişilebilir kalır). */}
          <div className="sticky top-0 z-30 -mx-3 md:-mx-5 px-3 md:px-5 py-2.5 backdrop-blur-md bg-white/85 dark:bg-slate-950/85 border-b border-slate-200 dark:border-slate-800">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              <div className="flex items-center gap-2 min-w-0">
                <Brain className="w-4 h-4 text-violet-500 shrink-0" />
                <span className="font-mono text-sm font-semibold text-slate-900 dark:text-white truncate max-w-[36vw]">
                  {activeSession.target}
                </span>
                {pipelineStream.isConnected && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-[10px] font-semibold">
                    <Wifi className="w-3 h-3" /> CANLI
                  </span>
                )}
                <WafBadge waf={liveWaf || (activeSession.ai_analysis as any)?.waf || null} />
                <OastMonitorBadge oast={(activeSession.ai_analysis as any)?.oast || null} />
                <FingerprintBadge fingerprint={(activeSession.ai_analysis as any)?.fingerprint || null} />
              </div>
              <div className="ml-auto flex flex-wrap items-center gap-2">
                {/* LLM Logları — istihbarat subayına sorulan soru + ham cevap (yalnız admin). */}
                {isAdmin && <LlmLogsModal scanId={activeSession.scan_id} isDone={isDone} />}
                {activeSession.status === 'running' && (
                  <button onClick={handlePause}
                    className="px-3 py-1.5 text-xs font-semibold text-amber-500 border border-amber-500/30 rounded-full hover:bg-amber-500/10 transition-colors">
                    Duraklat
                  </button>
                )}
                {isPaused && (
                  <button onClick={handleResume}
                    className="px-3 py-1.5 text-xs font-semibold text-emerald-500 border border-emerald-500/30 rounded-full hover:bg-emerald-500/10 transition-colors">
                    Devam Et
                  </button>
                )}
                {isActive && (
                  <button onClick={handleCancel}
                    className="px-3 py-1.5 text-xs font-semibold text-red-500 border border-red-500/30 rounded-full hover:bg-red-500/10 transition-colors">
                    Iptal Et
                  </button>
                )}
                {isDone && (
                  <button onClick={handleNewScan}
                    className="px-3 py-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                    Yeni Tarama
                  </button>
                )}
                {isDone && (
                  <button onClick={handleViewResults}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-bold text-white bg-gradient-to-r from-violet-600 to-purple-500 rounded-full hover:shadow-lg transition-all">
                    Sonuclari Gor <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          </div>
          <div className="text-center space-y-2">
            <h1 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white">
              {isAwaitingApproval ? 'Onay Bekleniyor — Kesif Tamamlandi'
                : isPaused ? 'Kusatma Duraklatildi'
                : activeSession.status === 'running' ? 'Kusatma Devam Ediyor...'
                : activeSession.status === 'failed' ? 'Kusatma Basarisiz'
                : activeSession.status === 'cancelled' ? 'Kusatma Iptal Edildi'
                : isDone ? 'Kusatma Tamamlandi' : 'Kusatma'}
            </h1>
            {(activeSession.ai_analysis as any)?.stealth?.stealth_active && (
              <span
                title={`APT Gizlilik Kipi Aktif - Dinamik Jitter: ${(activeSession.ai_analysis as any)?.stealth?.jitter_range}`}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border border-purple-500/40 bg-purple-500/10 text-purple-400"
              >
                <Shield className="w-3 h-3 text-purple-400" />
                APT Stealth (Jitter Aktif)
              </span>
            )}
          </div>

          {/* MOTOR FARKINDALIĞI: loop-guard uyarıları + vektör-hafıza recall + düşen
              servis/uyarı olayları. Bildirim yoksa panel hiç görünmez (gürültü sıfır). */}
          <EngineAwareness notices={pipelineStream.notices} />

          <AutonomousTimeline
            stream={pipelineStream}
            scanId={activeSession.scan_id}
            sessionId={activeSession.session_id}
            initialTimeline={activeSession.ai_analysis?.agent_timeline}
            initialPhaseGate={reconnectGate}
            summary={activeSession.status === 'completed' ? activeSession.ai_analysis ?? undefined : undefined}
          />

          {/* KAPSAMA SÖZLEŞMESİ — motorun "ne taradı / ne taraMADI + neden"i (otonom görünümde
              canlı; veri yoksa null döner). */}
          {activeSession.ai_analysis?.coverage_contract && (
            <CoverageContract coverage={activeSession.ai_analysis.coverage_contract} />
          )}

          {/* AI UYUM & GÜVENCE — OWASP LLM Top-10 (2025) / MITRE ATLAS / NIST AI RMF / EU AI Act.
              compliance_map.attest_coverage çıktısı; manşet = ters-kapsama. Veri yoksa null. */}
          {(activeSession.ai_analysis as any)?.compliance_attestation && (
            <ComplianceAttestationPanel attestation={(activeSession.ai_analysis as any).compliance_attestation} />
          )}

          {/* §2.1: AI rapor durumu — sessiz başarısızlık yerine görünür rozet + yeniden dene */}
          {isDone && activeSession.ai_analysis?.report_status === 'failed' && (
            <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
              <div className="flex items-start gap-2 text-amber-500 text-sm">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>
                  AI raporu uretilemedi{activeSession.ai_analysis?.report_error ? `: ${activeSession.ai_analysis.report_error}` : ''}.
                  {' '}Tarama sonuclari kayitli — raporu yeniden deneyebilirsiniz.
                </span>
              </div>
              <button
                onClick={handleRetryReport}
                className="px-4 py-2 text-sm font-semibold text-amber-500 border border-amber-500/40 rounded-full hover:bg-amber-500/10 transition-colors whitespace-nowrap"
              >
                Raporu Yeniden Dene
              </button>
            </div>
          )}
          {isDone && activeSession.ai_analysis?.report_status === 'pending' && (
            <div className="flex items-center gap-2 p-4 rounded-xl border border-violet-500/20 bg-violet-500/5 text-violet-500 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>AI raporu uretiliyor...</span>
            </div>
          )}

          </div>
      </div>
    );
  }

  // ---- Pipeline Progress View ----
  if (activeSession) {
    const stages = activeSession.stages || {};
    const totalStages = Object.keys(stages).length;
    const completedStages = Object.values(stages).filter(s => s.status === 'completed').length;
    const progress = totalStages > 0 ? Math.round((completedStages / totalStages) * 100) : 0;
    const isRunning = activeSession.status === 'running';
    const isDone = activeSession.status === 'completed' || activeSession.status === 'failed' || activeSession.status === 'cancelled';
    const profileColor = PROFILE_COLORS[activeSession.profile] || 'blue';

    return (
      <div className="min-h-screen py-3 px-3 md:px-5">
        <div className="max-w-6xl mx-auto space-y-4">

          {/* Header */}
          <div className="text-center space-y-3">
            <div className="flex items-center justify-center gap-3">
              <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full bg-${profileColor}-500/10 border border-${profileColor}-500/20 text-${profileColor}-500 text-sm font-medium`}>
                <Activity className="w-4 h-4" />
                <span>v2 Pipeline</span>
              </div>
              {pipelineStream.isConnected && (
                <div className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-xs font-medium">
                  <Wifi className="w-3 h-3" />
                  <span>CANLI</span>
                </div>
              )}
            </div>
            <h1 className="text-2xl md:text-3xl font-bold text-slate-900 dark:text-white">
              {isRunning ? 'Tarama Devam Ediyor...' : isDone ? 'Tarama Tamamlandi' : 'Pipeline'}
            </h1>
            <p className="text-slate-500 dark:text-slate-400">
              <span className="font-mono text-sm">{activeSession.target}</span>
              <span className="mx-2">-</span>
              <span>{activeSession.profile}</span>{' '}
              <WafBadge waf={liveWaf || (activeSession.ai_analysis as any)?.waf || null} />{' '}
              <OastMonitorBadge oast={(activeSession.ai_analysis as any)?.oast || null} />{' '}
              <FingerprintBadge fingerprint={(activeSession.ai_analysis as any)?.fingerprint || null} />{' '}
              {(activeSession.ai_analysis as any)?.stealth?.stealth_active && (
                <span
                  title={`APT Gizlilik Kipi Aktif - Dinamik Jitter: ${(activeSession.ai_analysis as any)?.stealth?.jitter_range}`}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border border-purple-500/40 bg-purple-500/10 text-purple-400 align-middle"
                >
                  <Shield className="w-3 h-3 text-purple-400" />
                  <span>APT Stealth (Jitter Aktif)</span>
                </span>
              )}
            </p>
          </div>

          {/* Live Counters */}
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50">
              <Activity className="w-5 h-5 text-blue-500 mx-auto mb-1" />
              <div className="text-2xl font-bold text-slate-900 dark:text-white">{livePorts.length}</div>
              <div className="text-xs text-slate-500">Acik Port</div>
            </div>
            <div className="text-center p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50">
              <Bug className="w-5 h-5 text-red-500 mx-auto mb-1" />
              <div className="text-2xl font-bold text-slate-900 dark:text-white">{liveFindings.length}</div>
              <div className="text-xs text-slate-500">Zafiyet</div>
            </div>
            <div className="text-center p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50">
              <Timer className="w-5 h-5 text-orange-500 mx-auto mb-1" />
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {activeSession.duration_seconds ? `${Math.round(activeSession.duration_seconds)}s` : '-'}
              </div>
              <div className="text-xs text-slate-500">Sure</div>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="relative">
            <div className="flex justify-between text-xs text-slate-500 dark:text-slate-400 mb-2">
              <span>{completedStages}/{totalStages} asama tamamlandi</span>
              <span>{pipelineStream.progress > 0 ? pipelineStream.progress : progress}%</span>
            </div>
            <div className="h-3 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  activeSession.status === 'failed' ? 'bg-red-500' :
                  activeSession.status === 'cancelled' ? 'bg-slate-500' :
                  `bg-${profileColor}-500`
                }`}
                style={{ width: `${Math.max(pipelineStream.progress, progress)}%` }}
              />
            </div>
          </div>

          {/* Stages */}
          <div className="space-y-3">
            {Object.entries(stages).map(([name, stage]) => {
              const StatusIcon = STAGE_STATUS_ICON[stage.status] || Clock;
              const isActive = stage.status === 'running';

              return (
                <div
                  key={name}
                  className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${
                    isActive
                      ? `border-${profileColor}-500/50 bg-${profileColor}-500/5 shadow-lg`
                      : stage.status === 'completed'
                      ? 'border-emerald-500/30 bg-emerald-500/5'
                      : stage.status === 'failed' || stage.status === 'timeout'
                      ? 'border-red-500/30 bg-red-500/5'
                      : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50'
                  }`}
                >
                  <div className={`p-2 rounded-lg ${
                    isActive ? `bg-${profileColor}-500/10` :
                    stage.status === 'completed' ? 'bg-emerald-500/10' :
                    stage.status === 'failed' ? 'bg-red-500/10' :
                    'bg-slate-100 dark:bg-slate-800'
                  }`}>
                    <StatusIcon className={`w-5 h-5 ${
                      isActive ? `text-${profileColor}-500 animate-spin` :
                      stage.status === 'completed' ? 'text-emerald-500' :
                      stage.status === 'failed' || stage.status === 'timeout' ? 'text-red-500' :
                      'text-slate-400'
                    }`} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-slate-900 dark:text-white capitalize">
                        {name.replace(/_/g, ' ')}
                      </span>
                      <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                        [{stage.tool}]
                      </span>
                    </div>
                    {stage.duration && stage.duration > 0 && (
                      <span className="text-xs text-slate-400">{stage.duration.toFixed(1)}s</span>
                    )}
                  </div>

                  <span className={`text-xs font-medium px-2 py-1 rounded-full ${
                    isActive ? `bg-${profileColor}-500/10 text-${profileColor}-500` :
                    stage.status === 'completed' ? 'bg-emerald-500/10 text-emerald-500' :
                    stage.status === 'failed' ? 'bg-red-500/10 text-red-500' :
                    stage.status === 'timeout' ? 'bg-orange-500/10 text-orange-500' :
                    stage.status === 'skipped' ? 'bg-slate-500/10 text-slate-500' :
                    'bg-slate-100 dark:bg-slate-800 text-slate-500'
                  }`}>
                    {stage.status === 'running' ? 'Calisiyor' :
                     stage.status === 'completed' ? 'Tamamlandi' :
                     stage.status === 'failed' ? 'Basarisiz' :
                     stage.status === 'timeout' ? 'Zaman Asimi' :
                     stage.status === 'skipped' ? 'Atlandi' :
                     stage.status === 'cancelled' ? 'Iptal' :
                     'Bekliyor'}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Live Event Log (Terminal) */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
            <button
              onClick={() => setShowEventLog(!showEventLog)}
              className="w-full flex items-center justify-between px-4 py-3 bg-slate-100 dark:bg-slate-900 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4" />
                <span>Canli Olay Akisi</span>
                <span className="text-xs text-slate-400">({pipelineStream.events.length} olay)</span>
              </div>
              <ChevronRight className={`w-4 h-4 transition-transform ${showEventLog ? 'rotate-90' : ''}`} />
            </button>
            {showEventLog && (
              <div
                ref={eventLogRef}
                className="h-64 overflow-y-auto bg-slate-950 p-4 font-mono text-xs space-y-1"
              >
                {pipelineStream.events.length === 0 ? (
                  <div className="text-slate-600">Olaylar bekleniyor...</div>
                ) : (
                  pipelineStream.events.map((evt, i) => {
                    const eventType = evt.event_type || evt.type || '';
                    let color = 'text-slate-500';
                    if (eventType.includes('completed') || eventType.includes('port_found')) color = 'text-emerald-400';
                    else if (eventType.includes('failed') || eventType.includes('error')) color = 'text-red-400';
                    else if (eventType.includes('vulnerability') || eventType.includes('critical')) color = 'text-orange-400';
                    else if (eventType.includes('started') || eventType.includes('running')) color = 'text-blue-400';
                    else if (eventType === 'heartbeat') color = 'text-slate-700';

                    const time = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '';
                    const source = evt.source || '';
                    const dataStr = evt.data ? JSON.stringify(evt.data).slice(0, 120) : '';

                    return (
                      <div key={i} className={`${color} leading-relaxed`}>
                        <span className="text-slate-600">[{time}]</span>{' '}
                        {source && <span className="text-slate-500">{source}:</span>}{' '}
                        <span className="font-semibold">{eventType}</span>{' '}
                        {dataStr && <span className="text-slate-600">{dataStr}</span>}
                      </div>
                    );
                  })
                )}
              </div>
            )}
          </div>

          {/* Türkçe: Faz 1 + Faz 0 görünürlüğü — kanıt/endpoint/dikkat/aşama çipetleri.
              AI raporu ÜRETİLMEMİŞ olsa bile render edilir (ai_analysis kapısının DIŞINDA):
              metrikler ai_analysis'ten gelir, yoksa aşama durumlarından (stages) türetilir.
              Böylece "0 bulgu / boş tarama" hissi raporsuz senaryoda da kırılır. */}
          {(() => {
            const s: any = activeSession.ai_analysis || {};
            const stageEntries = Object.entries(activeSession.stages || {});
            // Rapor yoksa düşen aşamaları canlı stage durumlarından türet
            // (failed/timeout/cancelled = kısmi sonuç sinyali).
            const failedStages = stageEntries
              .filter(([, st]: any) => ['failed', 'timeout', 'cancelled'].includes(st?.status))
              .map(([name]) => name);
            const endpointsFound =
              typeof s.endpoints_found === 'number' ? s.endpoints_found :
              Array.isArray(s.endpoints) ? s.endpoints.length : 0;
            const attentionItems: any[] = Array.isArray(s.attention_items) ? s.attention_items : [];
            const sh: any = s.stage_health || {};
            const degradedCount =
              typeof sh.degraded_count === 'number' ? sh.degraded_count :
              typeof sh.total_degraded === 'number' ? sh.total_degraded :
              Array.isArray(sh.degraded) ? sh.degraded.length :
              failedStages.length;
            const totalStages =
              typeof sh.total_stages === 'number' ? sh.total_stages :
              stageEntries.length;
            const verifiedVulns =
              Array.isArray(s.verified_vulnerabilities) ? s.verified_vulnerabilities.length : 0;
            if (!(endpointsFound || attentionItems.length || verifiedVulns || degradedCount || totalStages)) {
              return null;
            }
            const degNames = Array.isArray(sh.degraded)
              ? sh.degraded.map((d: any) => (typeof d === 'string' ? d : (d.stage || d.tool || '?'))).join(', ')
              : failedStages.join(', ');
            const Chip = ({ label, value, tone }: { label: string; value: any; tone: string }) => (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                <span className="text-xs uppercase font-bold text-slate-400">{label}</span>
                <span className={`text-sm font-bold ${tone}`}>{value}</span>
              </div>
            );
            return (
              <div className="mb-4">
                <div className="flex flex-wrap gap-2 mb-2">
                  <Chip label="Kanıtlanmış Zafiyet" value={verifiedVulns} tone="text-red-500" />
                  <Chip label="Keşfedilen Endpoint" value={endpointsFound} tone="text-cyan-500" />
                  {attentionItems.length > 0 && (
                    <Chip label="Dikkat Maddesi" value={attentionItems.length} tone="text-amber-500" />
                  )}
                  {totalStages > 0 && (
                    <Chip
                      label="Aşama / Düşen"
                      value={degradedCount > 0 ? `${totalStages} / ${degradedCount}` : `${totalStages}`}
                      tone={degradedCount > 0 ? 'text-orange-500' : 'text-emerald-500'}
                    />
                  )}
                  {activeSession.ai_analysis?.coverage_contract?.classes?.some(
                    (c: any) => c.key === 'app.race_condition' && c.status === 'found'
                  ) && (
                    <Chip label="Race Condition (CWE-362)" value="Tespit Edildi!" tone="text-red-500 font-bold" />
                  )}
                  {activeSession.ai_analysis?.coverage_contract?.classes?.some(
                    (c: any) => c.key === 'vuln.oast' && c.status === 'found'
                  ) && (
                    <Chip label="Kör Callback (OAST)" value="Kanıtlandı!" tone="text-purple-500 font-bold" />
                  )}
                  {(activeSession.ai_analysis as any)?.asset_diff?.has_changes && (
                    <Chip label="Varlık Radarı" value="Değişim Var!" tone="text-indigo-400 font-bold" />
                  )}
                </div>
                {/* Aşama sağlığı uyarısı — sessiz yutma görünür kılındı. */}
                {degradedCount > 0 && (
                  <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20 text-xs text-orange-600 dark:text-orange-400">
                    <AlertTriangle className="inline-block w-3.5 h-3.5 mr-1 -mt-0.5" />
                    {degradedCount} aşama düşmüş olabilir (kısmi sonuç).{degNames ? ` Etkilenen: ${degNames}` : ''}
                  </div>
                )}
              </div>
            );
          })()}

          {/* VARLIK DELTA RADARI (Port & Servis Zaman Serisi) */}
          {(activeSession.ai_analysis as any)?.asset_diff && (
            <AssetDiffCard diff={(activeSession.ai_analysis as any).asset_diff} />
          )}

          {/* CVE İSTİHBARATI (vulnx/PDCP) — EPSS+KEV+PoC+nuclei-template + rate-limit görünürlüğü */}
          {(activeSession.ai_analysis as any)?.cve_intel && (
            <CveIntelPanel cveIntel={(activeSession.ai_analysis as any).cve_intel} />
          )}

          {/* KAPSAMA SÖZLEŞMESİ (B adımı) — motorun "ne taradı / ne taraMADI + neden"i.
              A1'in ürettiği coverage_contract'ı ekrana çıkarır; "IP buldum göremiyorum" +
              "bir sınıf sessizce kaçıyor" şikayetinin çözümü. Veri yoksa null döner. */}
          {activeSession.ai_analysis?.coverage_contract && (
            <CoverageContract coverage={activeSession.ai_analysis.coverage_contract} />
          )}

          {/* AI UYUM & GÜVENCE — OWASP LLM Top-10 (2025) / MITRE ATLAS / NIST AI RMF / EU AI Act.
              compliance_map.attest_coverage çıktısı; manşet = ters-kapsama (test edilmeyen +
              white-box). Veri yoksa null döner (degrade-safe). */}
          {(activeSession.ai_analysis as any)?.compliance_attestation && (
            <ComplianceAttestationPanel attestation={(activeSession.ai_analysis as any).compliance_attestation} />
          )}

          {/* AI Analysis (if available) */}
          {activeSession.ai_analysis && (
            <div className="p-5 rounded-xl border border-purple-500/30 bg-purple-500/5">
              {/* Dikkat maddeleri listesi */}
              {Array.isArray(activeSession.ai_analysis.attention_items) &&
                activeSession.ai_analysis.attention_items.length > 0 && (
                <div className="mb-3">
                  <h4 className="text-xs font-bold text-amber-400 mb-1.5 uppercase">Dikkat Maddeleri</h4>
                  <ul className="space-y-1">
                    {activeSession.ai_analysis.attention_items.slice(0, 6).map((it: any, i: number) => (
                      <li key={i} className="text-xs text-slate-600 dark:text-slate-400 flex gap-2">
                        <span className="text-amber-400 mt-0.5">!</span>
                        <span>
                          {typeof it === 'string' ? it : (
                            <span>
                              <span className="font-mono">{it.label || it.target || '?'}</span>
                              {it.reason ? <span className="text-slate-400"> — {it.reason}</span> : null}
                            </span>
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>
                  {activeSession.ai_analysis.attention_items.length > 6 && (
                    <p className="text-[11px] text-slate-400 mt-1">
                      +{activeSession.ai_analysis.attention_items.length - 6} madde daha...
                    </p>
                  )}
                </div>
              )}

              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-5 h-5 text-purple-500" />
                <h3 className="font-bold text-slate-900 dark:text-white">AI Analiz</h3>
                {activeSession.ai_analysis.model_used && (
                  <span className="text-xs font-mono text-purple-400">{activeSession.ai_analysis.model_used}</span>
                )}
              </div>
              {activeSession.ai_analysis.risk_score !== undefined && activeSession.ai_analysis.risk_score !== null && (
                <div className="flex items-center gap-3 mb-3">
                  <span className="text-sm text-slate-500">Risk Skoru:</span>
                  <span className={`text-2xl font-bold ${
                    activeSession.ai_analysis.risk_score >= 70 ? 'text-red-500' :
                    activeSession.ai_analysis.risk_score >= 40 ? 'text-orange-500' :
                    'text-emerald-500'
                  }`}>
                    {activeSession.ai_analysis.risk_score}/100
                  </span>
                </div>
              )}
              {activeSession.ai_analysis.executive_summary && (
                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed mb-3">
                  {activeSession.ai_analysis.executive_summary}
                </p>
              )}
              {activeSession.ai_analysis.recommendations && activeSession.ai_analysis.recommendations.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-purple-400 mb-2 uppercase">Oneriler</h4>
                  <ul className="space-y-1">
                    {activeSession.ai_analysis.recommendations.slice(0, 5).map((rec: string, i: number) => (
                      <li key={i} className="text-xs text-slate-500 dark:text-slate-400 flex gap-2">
                        <span className="text-purple-400 mt-0.5">-</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-center gap-4 pt-4">
            {isRunning && (
              <button
                onClick={handleCancel}
                className="px-6 py-3 text-sm font-semibold text-red-500 border border-red-500/30 rounded-full hover:bg-red-500/10 transition-colors"
              >
                Iptal Et
              </button>
            )}
            {isDone && (
              <>
                <button
                  onClick={handleNewScan}
                  className="px-6 py-3 text-sm font-semibold text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                >
                  Yeni Tarama
                </button>
                <button
                  onClick={handleViewResults}
                  className={`px-6 py-3 text-sm font-bold text-white bg-gradient-to-r from-${profileColor}-600 to-${profileColor}-500 rounded-full hover:shadow-lg transition-all`}
                >
                  Sonuclari Gor
                  <ChevronRight className="inline-block w-4 h-4 ml-1" />
                </button>
              </>
            )}
          </div>

          {/* Duration */}
          {activeSession.duration_seconds && activeSession.duration_seconds > 0 && (
            <div className="text-center text-sm text-slate-400">
              <Timer className="inline-block w-4 h-4 mr-1" />
              Toplam sure: {Math.round(activeSession.duration_seconds)}s
            </div>
          )}
        </div>
      </div>
    );
  }

  // ---- Profile Selection View ----
  return (
    <div className="min-h-screen py-8 px-4">
      <div className="max-w-5xl mx-auto space-y-8">

        {/* Header */}
        <div className="text-center space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 dark:text-emerald-400 text-sm font-medium backdrop-blur-sm">
            <Crosshair className="w-4 h-4" />
            <span>v2 Akilli Tarama</span>
          </div>
          <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold text-slate-900 dark:text-white tracking-tight">
            Otomatik <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-500 to-cyan-500">Guvenlik Taramasi</span>
          </h1>
          <p className="text-base md:text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
            Profil sec, hedefi gir, gerisini pipeline halletsin.
            AI destekli otomatik analiz dahil.
          </p>
          {/* Aktif LLM rozeti — tarama başlatmadan hangi istihbarat modeli aktif görülebilir */}
          <div className="flex justify-center pt-2">
            <AutonomousLlmStatus />
          </div>
        </div>

        <form onSubmit={handleScan} className="space-y-10">

          {/* Target Input */}
          <div className="relative group max-w-3xl mx-auto">
            {error && (
              <div className="absolute -top-12 left-0 right-0 bg-red-500/10 border border-red-500/20 text-red-500 px-4 py-2 rounded-lg text-center text-sm font-medium animate-fade-in">
                {error}
              </div>
            )}
            <div className="absolute -inset-1 bg-gradient-to-r from-emerald-600 to-cyan-600 rounded-2xl blur opacity-20 dark:opacity-25 group-hover:opacity-40 dark:group-hover:opacity-50 transition duration-1000 group-hover:duration-200" />
            <div className="relative flex items-center bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700/50 rounded-xl p-2 shadow-lg dark:shadow-2xl">
              <Search className="w-6 h-6 text-slate-400 ml-4" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Hedef Domain veya IP (orn: example.com)"
                className="w-full bg-transparent border-none text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 text-base md:text-lg px-4 py-4 focus:ring-0 focus:outline-none"
                required
              />
              <div className="hidden md:flex items-center gap-2 pr-4 text-xs text-slate-400 dark:text-slate-500 font-mono border-l border-slate-200 dark:border-slate-800 pl-4">
                <Terminal className="w-4 h-4" />
                <span>v2</span>
              </div>
            </div>
          </div>

          {/* Scan Level Cards (Tek Doktrin — 3 seviye) */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 md:gap-6">
            {SCAN_LEVELS.map((lvl) => {
              const LevelIcon = lvl.icon;
              const color = lvl.color;
              const isSelected = selectedLevel === lvl.id;

              return (
                <div
                  key={lvl.id}
                  onClick={() => setSelectedLevel(lvl.id)}
                  className={`group relative rounded-2xl border cursor-pointer transition-all duration-300 ${
                    isSelected
                      ? `bg-${color}-500/5 border-${color}-500/50 shadow-xl transform -translate-y-1`
                      : 'bg-white dark:bg-slate-900/50 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <div className="p-5 h-full flex flex-col">
                    <div className="flex justify-between items-start mb-4">
                      <div className={`p-3 rounded-xl transition-colors ${
                        isSelected
                          ? `bg-${color}-500/10`
                          : 'bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800'
                      }`}>
                        <LevelIcon className={`w-6 h-6 transition-colors ${
                          isSelected ? `text-${color}-500` : 'text-slate-400 dark:text-slate-500 group-hover:text-slate-600'
                        }`} />
                      </div>
                      <div className={`w-6 h-6 rounded-full border flex items-center justify-center transition-all ${
                        isSelected
                          ? `border-${color}-500 bg-${color}-500 text-white`
                          : 'border-slate-300 dark:border-slate-700'
                      }`}>
                        {isSelected && <CheckCircle2 className="w-4 h-4" />}
                      </div>
                    </div>

                    <h3 className={`font-bold text-lg mb-1 transition-colors ${
                      isSelected ? 'text-slate-900 dark:text-white' : 'text-slate-700 dark:text-slate-300'
                    }`}>
                      {lvl.name}
                    </h3>
                    <p className="text-sm text-slate-500 leading-relaxed flex-1">
                      {lvl.description}
                    </p>

                    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800/50">
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
                        {lvl.detail}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Stealth toggle (seviyeden bagimsiz kip bayragi) */}
          <div className="flex justify-center">
            <button
              type="button"
              onClick={() => setStealth(s => !s)}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-medium transition-all ${
                stealth
                  ? 'bg-slate-700 border-slate-500 text-white'
                  : 'bg-white dark:bg-slate-900/50 border-slate-300 dark:border-slate-700 text-slate-500 hover:border-slate-400'
              }`}
            >
              <EyeOff className="w-4 h-4" />
              <span>Gizli kip {stealth ? '(acik)' : '(kapali)'}</span>
              <span className="text-[10px] text-slate-400 font-mono">nmap -T2, dusuk gurultu</span>
            </button>
          </div>

          {/* Dayaniklilik & maruz-kalma probu (L7 DoS + origin-CDN-bypass + SSH parola-auth).
              VARSAYILAN KAPALI — operator bilincli acar. Acikken motor TAHRIBATSIZ dayaniklilik
              gostergeleri toplar (gercek DDoS/brute-force ATMAZ): anasayfa CDN cache duruşu,
              rate-limit varligi, origin IP ifsasi (CDN bypass), SSH parola-auth aciklik. */}
          <div className="flex flex-col items-center gap-1">
            <button
              type="button"
              onClick={() => setResilience(s => !s)}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-medium transition-all ${
                resilience
                  ? 'bg-cyan-600 border-cyan-400 text-white'
                  : 'bg-white dark:bg-slate-900/50 border-slate-300 dark:border-slate-700 text-slate-500 hover:border-cyan-400'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span>Dayaniklilik &amp; maruz-kalma {resilience ? '(acik)' : '(kapali)'}</span>
              <span className="text-[10px] text-slate-400 font-mono">L7-DoS · origin-ifsa · SSH</span>
            </button>
            <span className="text-[10px] text-slate-400 dark:text-slate-500">
              Tahribatsiz — gercek DDoS/brute-force atmaz; yalnizca dayaniklilik gostergeleri olcer
            </span>
          </div>

          {/* "Bu hedef ne?" — operatör tip ipucu. Otomatik tespit ıskalarsa (API sürüm
              ifşa etmez, JSON döner ama HTML yok) operatör tipi damgalar. 'API' seçince
              motor kitlesel BOLA/broken-auth (token'sız veri sızıntısı) yolunu önceliklendirir. */}
          <div className="flex flex-col items-center gap-2">
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Bu hedef ne? <span className="text-slate-400">(otomatik tespiti geçersiz kılar)</span>
            </span>
            <div className="inline-flex rounded-full border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900/50 p-1">
              {([
                { k: 'auto', label: '🔍 Otomatik' },
                { k: 'api', label: '🔌 API' },
                { k: 'web', label: '🌐 Web uygulaması' },
                { k: 'server', label: '🖥️ Çıplak sunucu' },
              ] as const).map(opt => (
                <button
                  key={opt.k}
                  type="button"
                  onClick={() => setTargetKind(opt.k)}
                  className={`px-3.5 py-1.5 rounded-full text-sm font-medium transition-all ${
                    targetKind === opt.k
                      ? 'bg-indigo-500 text-white shadow'
                      : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            {targetKind === 'api' && (
              <span className="text-[11px] text-indigo-500 dark:text-indigo-400">
                API kipi: token'sız kitlesel veri sızıntısı (BOLA/broken-auth) önceliklenir.
                İkinci hesap token'ı verirsen çapraz-erişim <b>confirmed</b> kanıtlanır.
              </span>
            )}
          </div>

          {/* T1-B: Kimlik doğrulamalı tarama (opsiyonel) — login-ARKASI yüzeyi açar */}
          <div className="max-w-3xl mx-auto">
            <button
              type="button"
              onClick={() => setShowAuth(s => !s)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-medium transition-all bg-white dark:bg-slate-900/50 border-slate-300 dark:border-slate-700 text-slate-500 hover:border-slate-400"
            >
              <span>🔐 Kimlik doğrulamalı tarama {(authBearer || authCookie || authHeaders) ? ((authBBearer || authBCookie || authBHeaders) ? '(2 hesap — IDOR aktif)' : '(aktif)') : '(opsiyonel)'}</span>
              <span className="text-[10px] text-slate-400">{showAuth ? '▲' : '▼'}</span>
            </button>
            {showAuth && (
              <div className="mt-3 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 space-y-3 text-sm">
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Login-arkası yüzey (gerçek zafiyetlerin ~%80'i) crawl + nuclei + verifier'larda
                  bu kimlikle taranır. Yalnız YETKİLİ olduğun hedeflerde kullan.
                </p>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Bearer Token</label>
                  <input type="text" value={authBearer} onChange={e => setAuthBearer(e.target.value)}
                    placeholder="eyJhbGciOi... (Authorization: Bearer bunu)"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 font-mono text-xs" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Cookie</label>
                  <input type="text" value={authCookie} onChange={e => setAuthCookie(e.target.value)}
                    placeholder="session=abc; token=xyz"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 font-mono text-xs" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Özel Başlıklar (her satır "Ad: değer")</label>
                  <textarea value={authHeaders} onChange={e => setAuthHeaders(e.target.value)} rows={2}
                    placeholder={"X-API-Key: 123\nX-Tenant: acme"}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 font-mono text-xs" />
                </div>

                {/* T2-A: İkinci hesap — IDOR/BOLA iki-hesap diferansiyeli */}
                <div className="pt-3 mt-1 border-t border-dashed border-slate-300 dark:border-slate-700 space-y-3">
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    <span className="font-semibold text-slate-600 dark:text-slate-300">🕵️ İkinci hesap (IDOR/BOLA testi)</span> —
                    opsiyonel ama <span className="font-semibold">şiddetle önerilir</span>. İki farklı kimlik
                    verirsen motor "B, A'nın nesnesine erişebiliyor mu?" diferansiyelini çalıştırır ve yetki
                    boşluğunu <span className="font-semibold text-emerald-600 dark:text-emerald-400">kanıtlar (confirmed)</span>.
                    Boş bırakırsan tek-hesap enumerasyonu (probable) çalışır.
                  </p>
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Hesap B — Bearer Token</label>
                    <input type="text" value={authBBearer} onChange={e => setAuthBBearer(e.target.value)}
                      placeholder="İkinci kullanıcının token'ı"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 font-mono text-xs" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Hesap B — Cookie</label>
                    <input type="text" value={authBCookie} onChange={e => setAuthBCookie(e.target.value)}
                      placeholder="session=def; token=uvw"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 font-mono text-xs" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-300 mb-1">Hesap B — Özel Başlıklar (her satır "Ad: değer")</label>
                    <textarea value={authBHeaders} onChange={e => setAuthBHeaders(e.target.value)} rows={2}
                      placeholder={"X-API-Key: 456"}
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 font-mono text-xs" />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* İstihbarat kaynakları (API key durumu) */}
          <div className="max-w-3xl mx-auto">
            <OsintKeyStatus />
          </div>

          {/* Submit */}
          <div className="flex justify-center pt-8 pb-10">
            <button
              type="submit"
              disabled={loading || !target}
              className="group relative inline-flex items-center justify-center px-8 py-4 text-base font-bold text-white transition-all duration-200 bg-gradient-to-r from-emerald-600 to-cyan-600 rounded-full hover:from-emerald-500 hover:to-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-emerald-900/30 hover:shadow-emerald-900/50 transform hover:-translate-y-0.5"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 mr-3 animate-spin" />
                  Pipeline Baslatiliyor...
                </>
              ) : (
                <>
                  Taramayi Baslat
                  <Play className="ml-2 w-5 h-5 fill-current" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
