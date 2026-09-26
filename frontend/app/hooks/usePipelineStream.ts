import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Pipeline Event tipleri (orchestrator scan_events.py ile uyumlu)
 */
export interface PipelineEvent {
  type: string; // 'event' | 'initial_state' | 'event_history' | 'heartbeat' | 'stream_ended' | 'error'
  scan_id?: string;
  event_type?: string;
  timestamp?: string;
  data?: Record<string, any>;
  source?: string;
  // initial_state fields
  target?: string;
  status?: string;
  scan_types?: string[];
  results?: Record<string, any>;
  // event_history
  events?: any[];
  // error/stream_ended
  message?: string;
}

export interface PipelineStageUpdate {
  stage: string;
  tool: string;
  status: string; // pending, running, completed, failed, timeout, skipped
  percentage?: number;
  message?: string;
}

/**
 * Kuşatma Doktrini — otonom motorun bir kuşatma turunda değerlendirdiği alternatif
 * (orchestrator attack_graph.siege_score çıktısı, agent_thinking.considered[])
 */
export interface ConsideredEdge {
  tool: string;
  score: number;
  target_node?: string;
}

export interface AgentThinkingData {
  step: number;
  action: 'run_tool' | 'verify' | 'escalate' | 'approval' | 'stop';
  tool: string | null;
  expected: string;
  confidence: number;
  source: 'llm' | 'rules' | 'fallback';
  siege_score?: number | null;
  chosen_because?: string;
  considered?: ConsideredEdge[];
  target_node?: string | null;
  target_value?: number | null;
  [key: string]: any;
}

export interface AgentActionData {
  step: number;
  tool: string;
  options?: Record<string, any>;
  [key: string]: any;
}

export interface AgentObservationData {
  step: number;
  status: 'completed' | 'failed' | 'timeout';
  new_evidence: number;
  total_evidence: number;
  known_ports?: number;
  services?: string[];
  leads?: string[];
  [key: string]: any;
}

export interface AgentApprovalData {
  tool: string;
  options?: Record<string, any>;
  [key: string]: any;
}

export interface EvidenceCard {
  title: string;
  severity: string;
  cve?: string | null;
  target: string;
  proof?: string;
  /** false-positive ekseni (confirmed/probable/unconfirmed) — canlı bulgu rozetinde. */
  confidence_tier?: string;
  tool?: string;
  url?: string;
  message?: string;
  /** AI/LLM red-team: MITRE ATLAS tekniği (ör. AML.T0051) + OWASP LLM Top10 kodu (ör. LLM01). */
  atlas?: string;
  owasp_llm?: string;
  ts?: string;
}

/** IPB — hedef profili (target_profiled olayı). facts: boyut→{value,confidence,evidence}. */
export interface TargetProfileData {
  target?: string;
  profile?: string;        // tek satır özet
  /** Hedef TİPİ — 'site' varsayma: web | appliance (önünde firewall) | host (çıplak sunucu) | unknown. */
  kind?: 'web' | 'appliance' | 'host' | 'unknown';
  /** CPE'den türeyen ürün kimliği (nmap/Shodan otoriter veri) — elle imza yazmadan "hangi ürünler". */
  products?: string[];
  playbook?: string;       // aktif/atlanan modül özeti (ham string, geriye dönük uyumluluk)
  playbook_decisions?: Record<string, { run: boolean; priority: string; reason: string }>;
  facts?: Record<string, { value: string; confidence: number; evidence?: string[] }>;
  /** K8s/altyapı kontrol-düzlemi port yoklaması sonucu (görünürlük: "yoklandı, erişilemez"). */
  infra_probe?: { attempted: boolean; k8s_ports_open: number[] };
  message?: string;
}

/** Timeline'da tek bir kuşatma adımı — thinking/action/observation aynı `step` ile birleşir. */
export interface AgentStep {
  step: number;
  phase: 'thinking' | 'acting' | 'observed' | 'approval' | 'stopped';
  reasoning: string;
  tool: string | null;
  action: string;
  expected: string;
  confidence: number;
  source: 'llm' | 'rules' | 'fallback';
  siegeScore?: number | null;
  chosenBecause?: string;
  considered?: ConsideredEdge[];
  targetNode?: string | null;
  targetValue?: number | null;
  options?: Record<string, any>;
  status?: 'completed' | 'failed' | 'timeout';
  newEvidence?: number;
  totalEvidence?: number;
  services?: string[];
  leads?: string[];
  /** Görünürlük: bu adımın ham sonuç özeti (recon/nmap/osint çıktısı) — modal bunu gösterir. */
  resultSummary?: StageResultSummary | null;
  /** scan_artifacts referansı — modal ham veriyi buradan fetch eder. */
  artifactId?: string | null;
  errorMessage?: string | null;
  /** Araç çalışırken periyodik heartbeat'ten gelen geçen süre (canlı "çalışıyor…"). */
  elapsedSeconds?: number;
  startedAt: string;
  endedAt?: string;
}

/** Bir adımın sonuç özeti (orchestrator summarize_stage_result çıktısı). */
export interface StageResultSummary {
  highlights: string[];
  table: Record<string, any>;
  counts: Record<string, number>;
}

/** İki fazlı onay kapısı verisi (orchestrator AGENT_PHASE_GATE event'i). Keşif fazı
 * bitince gelir; kullanıcı sömürü fazını onaylayana kadar motor bekler. */
export interface PhaseGateData {
  message: string;
  recon_map?: Record<string, any>;
  total_hosts?: number;
  co_hosted_domains?: string[];
  active_edges_waiting?: number;
  [key: string]: any;
}

/** Motor farkındalığı bildirimi — kronolojik, kalıcı (adım kartı ezilse de kaybolmaz).
 *  Kaynaklar: düşürülen warning/error olayları, loop-guard (davranış denetimi) uyarıları,
 *  vektör-hafıza recall hit'leri. Kurumsal kullanıcı "motor neden böyle karar verdi /
 *  hangi servis düştü / geçmişten ne hatırladı" sorularını buradan görür. */
export interface EngineNotice {
  id: number;
  kind: 'warning' | 'error' | 'loop-guard' | 'memory' | 'info';
  message: string;
  at: string;
  /** Adım numarası varsa (loop-guard step taşır) — timeline ile ilişkilendirme için. */
  step?: number;
  data?: Record<string, any>;
}

/** Canlı motor etkinliği — orkestratörün post-observe probe'leri (WAF parmak izi, servis
 *  derin-dalış, K8s, IDOR...) WS'e SESSİZ koşunca UI "dondu/bekliyor" hissi veriyordu.
 *  Her probun başında yayınlanan `engine_activity` olayı, timeline'ın canlı etkinlik
 *  bandında "şu an ne yapılıyor" gösterir. agent_timeline'a persist edilmez (yalnız WS). */
export interface EngineActivity {
  message: string;
  step?: number | null;
  at: string; // ISO — bandın "N sn önce" sayacı bundan hesaplanır
}

interface UsePipelineStreamOptions {
  onStageStarted?: (stage: string, tool: string) => void;
  onStageCompleted?: (stage: string, tool: string) => void;
  onProgress?: (percentage: number, message: string) => void;
  onVulnerabilityFound?: (data: any) => void;
  onPortFound?: (data: any) => void;
  onCompleted?: (summary: any) => void;
  onFailed?: (error: string) => void;
  onAgentThinking?: (data: AgentThinkingData) => void;
  onAgentAction?: (data: AgentActionData) => void;
  onAgentObservation?: (data: AgentObservationData) => void;
  onApprovalNeeded?: (data: AgentApprovalData) => void;
  onPhaseGate?: (data: PhaseGateData) => void;
}

export interface UsePipelineStreamReturn {
  isConnected: boolean;
  isComplete: boolean;
  events: PipelineEvent[];
  stageUpdates: Record<string, PipelineStageUpdate>;
  agentSteps: AgentStep[];
  progress: number;
  error: string | null;
  /** Keşif fazı bitip onay bekliyorsa dolu; onaylanınca/tarama devam edince null'a döner. */
  phaseGate: PhaseGateData | null;
  /** IPB: hedef profili (target_profiled olayından). "hangi sistem" kartını besler. */
  targetProfile: TargetProfileData | null;
  /** Tarama SIRASINDA yakalanan bulgular (vulnerability_found/critical_finding) — canlı liste. */
  liveFindings: EvidenceCard[];
  /** Motor farkındalığı: uyarılar + loop-guard + vektör-hafıza sinyalleri (kronolojik, kalıcı). */
  notices: EngineNotice[];
  /** En son canlı motor etkinliği ("şu an: WAF parmak izi yapılıyor") — tarama sürerken dolu. */
  engineActivity: EngineActivity | null;
  connect: (scanId: string) => void;
  disconnect: () => void;
  seedAgentSteps: (steps: AgentStep[]) => void;
  clearPhaseGate: () => void;
}
/** step numarasıyla idempotent birleştirme — reconnect'te aynı adım tekrar gelirse duplike kart oluşmaz. */
function upsertAgentStep(
  steps: AgentStep[],
  step: number,
  patch: Partial<AgentStep>,
  defaults: Partial<AgentStep> = {}
): AgentStep[] {
  const idx = steps.findIndex(s => s.step === step);
  if (idx === -1) {
    const fresh: AgentStep = {
      step,
      phase: 'thinking',
      reasoning: '',
      tool: null,
      action: '',
      expected: '',
      confidence: 0,
      source: 'rules',
      startedAt: new Date().toISOString(),
      ...defaults,
      ...patch,
    };
    return [...steps, fresh].sort((a, b) => a.step - b.step);
  }
  const next = [...steps];
  next[idx] = { ...next[idx], ...patch };
  return next;
}

/**
 * WebSocket hook for v2 pipeline real-time events
 * orchestrator /scan/events/{scan_id} endpoint'ine baglanir
 */
export function usePipelineStream(options: UsePipelineStreamOptions = {}): UsePipelineStreamReturn {
  const [isConnected, setIsConnected] = useState(false);
  const [isComplete, setIsComplete] = useState(false);
  // STALE-CLOSURE KALKANI: ws.onclose closure'ı, connect'in çağrıldığı andaki state'i
  // görür (render'dan bağımsız). Önceki tarama bitti (isComplete=true) + yeni tarama
  // başladı + WS düşerse (nginx restart / network kopması) reconnect guard bayat
  // isComplete=true'ye takılıyordu → yeni taramanın akışı SONSUZA dek donardı.
  // Ref her zaman güncel değeri taşır.
  const isCompleteRef = useRef(false);
  const setComplete = useCallback((v: boolean) => {
    isCompleteRef.current = v;
    setIsComplete(v);
  }, []);
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const [stageUpdates, setStageUpdates] = useState<Record<string, PipelineStageUpdate>>({});
  const [agentSteps, setAgentSteps] = useState<AgentStep[]>([]);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [phaseGate, setPhaseGate] = useState<PhaseGateData | null>(null);
  const [targetProfile, setTargetProfile] = useState<TargetProfileData | null>(null);
  const [liveFindings, setLiveFindings] = useState<EvidenceCard[]>([]);
  const [notices, setNotices] = useState<EngineNotice[]>([]);
  const [engineActivity, setEngineActivity] = useState<EngineActivity | null>(null);

  // Bildirim id sayacı (ref — render tetiklemez, reconnect'te sıfırlanmaz ki duplike olmasın).
  const noticeIdRef = useRef(0);
  /** Ring-buffer: son 50 bildirim. Aynı içerik+kind arka arkaya gelirse (loop-guard spam'i)
   *  yeni kayıt EKLEMEZ, mevcut kaydın sayacını/zamanını tazeler → UI şişmez. */
  const pushNotice = useCallback((n: Omit<EngineNotice, 'id' | 'at'>) => {
    setNotices(prev => {
      const last = prev[prev.length - 1];
      if (last && last.kind === n.kind && last.message === n.message) {
        const next = [...prev];
        next[next.length - 1] = { ...last, at: new Date().toISOString(), data: n.data };
        return next;
      }
      noticeIdRef.current += 1;
      const capped = prev.length >= 50 ? prev.slice(prev.length - 49) : prev;
      return [...capped, { ...n, id: noticeIdRef.current, at: new Date().toISOString() }];
    });
  }, []);

  const wsRef = useRef<WebSocket | null>(null);
  const optionsRef = useRef(options);
  const reconnectTimerRef = useRef<NodeJS.Timeout | null>(null);
  const scanIdRef = useRef<string | null>(null);
  optionsRef.current = options;

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
    scanIdRef.current = null;
  }, []);

  const connect = useCallback((scanId: string) => {
    // Aynı scan'e YENİDEN bağlanıyorsak (reconnect) state'i SIFIRLAMA — replay zaten
    // upsertAgentStep ile idempotent beslenir. Önceden her reconnect agentSteps'i
    // boşaltıp yalnız son 20 event'i replay ediyordu → tamamlanmış taramada ilk
    // adımlar ekrandan düşüyordu ("tarama bitince önceki adımlar gizleniyor" bug'ı).
    const sameScan = scanIdRef.current === scanId;
    disconnect();

    scanIdRef.current = scanId;
    setError(null);
    if (!sameScan) {
      setComplete(false);
      setEvents([]);
      setStageUpdates({});
      setAgentSteps([]);
      setProgress(0);
      setPhaseGate(null);
      setTargetProfile(null);
      setLiveFindings([]);
      setNotices([]);
      setEngineActivity(null);
    }

    // WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/scan/events/${scanId}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      // Geçici bağlantı hatası sonrası YENİDEN bağlanma başarılı — eski onerror'ın
      // bıraktığı hata mesajı temizlenmezse UI'da kalıcı "WebSocket baglanti hatasi"
      // asılı kalırdı (bağlantı sağlamken bile).
      setError(null);
    };

    ws.onclose = (e) => {
      setIsConnected(false);

      // Auto-reconnect if not intentionally closed and not complete
      // isCompleteRef: closure'daki state bayat olabilir (bkz. yukarıdaki kalkan notu).
      if (scanIdRef.current && !isCompleteRef.current && e.code !== 1000) {
        reconnectTimerRef.current = setTimeout(() => {
          if (scanIdRef.current) {
            connect(scanIdRef.current);
          }
        }, 3000);
      }
    };

    ws.onerror = () => {
      setError('WebSocket baglanti hatasi');
    };

    /** İç `event_type` yönlendirmesi. `event` mesajlarında da, `event_history` tekrar
     * oynatmasında da (reconnect) aynı yoldan geçer — agentSteps böylece her iki
     * durumda da idempotent (step numarasıyla) besilenir. */
    function handleInnerEvent(eventType: string | undefined, data: Record<string, any>) {
      switch (eventType) {
        case 'phase_started':
          setStageUpdates(prev => ({
            ...prev,
            [data.stage || data.tool]: {
              stage: data.stage || '',
              tool: data.tool || '',
              status: 'running',
            },
          }));
          optionsRef.current.onStageStarted?.(data.stage, data.tool);
          break;

        case 'phase_completed':
          setStageUpdates(prev => ({
            ...prev,
            [data.stage || data.tool]: {
              ...prev[data.stage || data.tool],
              status: 'completed',
            },
          }));
          optionsRef.current.onStageCompleted?.(data.stage, data.tool);
          break;

        case 'progress_update':
          // IPB: hedef profili olayı progress_update kanalından gelir — profili YAKALA,
          // ilerleme çubuğuna DOKUNMA (percentage taşımaz → çubuğu 0'a düşürmesin).
          if (data.type === 'target_profiled') {
            setTargetProfile(data as TargetProfileData);
            break;
          }
          // Canlı motor etkinliği (WAF parmak izi, servis derin-dalış, IDOR...): bandın
          // "şu an ne yapılıyor" satırını güncelle — UI donmuş gibi görünmesin.
          if (data.type === 'engine_activity') {
            setEngineActivity({
              message: String(data.message || 'Motor çalışıyor…'),
              step: typeof data.step === 'number' ? data.step : null,
              at: new Date().toISOString(),
            });
            break;
          }
          // Yalnız GERÇEK yüzde geldiğinde çubuğu güncelle (percentage'siz progress
          // olayları — crawl/keşif bildirimleri — çubuğu sıfırlamasın).
          if (typeof data.percentage === 'number') {
            setProgress(data.percentage);
          }
          setStageUpdates(prev => {
            if (data.phase && prev[data.phase]) {
              return {
                ...prev,
                [data.phase]: {
                  ...prev[data.phase],
                  percentage: data.percentage,
                  message: data.message,
                },
              };
            }
            return prev;
          });
          optionsRef.current.onProgress?.(data.percentage || 0, data.message || '');
          break;

        case 'port_found':
          optionsRef.current.onPortFound?.(data);
          break;

        case 'vulnerability_found':
        case 'critical_finding':
          // Tarama SIRASINDA bulguyu canlı listeye ekle (başlık+hedef ile idempotent —
          // reconnect replay'inde duplike olmaz). Önceden bu olaylar yalnız callback'e
          // gidiyordu; UI'da bulgular ancak tarama BİTİNCE (summary) görünüyordu.
          setLiveFindings(prev => {
            // İki olay ŞEKLİNİ de destekle: çekirdek akış (emit_vulnerability_found →
            // name/matched_at/template_id) ve enrichment probları (title/target). Aksi halde
            // çekirdek nuclei bulguları "Bulgu" olarak detaysız görünürdü.
            const title = String(data.title || data.name || data.message || 'Bulgu');
            const target = String(data.target || data.matched_at || data.url || '');
            const tmpl = data.template_id ? String(data.template_id) : '';
            const cve = data.cve ?? (tmpl.toUpperCase().startsWith('CVE-') ? tmpl : null);
            const key = `${title}|${target}`;
            if (prev.some(f => `${f.title}|${f.target}` === key)) return prev;
            const card: EvidenceCard = {
              title,
              severity: String(data.severity || 'info'),
              cve,
              target,
              proof: data.proof || data.detail,
              confidence_tier: data.confidence_tier,
              tool: data.tool || data.source,
              url: data.url,
              message: data.message,
              atlas: data.atlas || data.mitre,
              owasp_llm: data.owasp_llm,
              ts: new Date().toISOString(),
            };
            return [...prev, card];
          });
          optionsRef.current.onVulnerabilityFound?.(data);
          break;

        case 'scan_completed':
          setComplete(true);
          setProgress(100);
          setAgentSteps(prev => prev.map(s => {
            if (s.phase === 'acting' || s.phase === 'thinking') {
              return { ...s, phase: 'observed' as const, status: (s.status || 'completed') as any };
            }
            return s;
          }));
          optionsRef.current.onCompleted?.(data);
          break;

        case 'scan_failed':
          setComplete(true);
          setError(data.error || 'Tarama basarisiz');
          setAgentSteps(prev => prev.map(s => {
            if (s.phase === 'acting' || s.phase === 'thinking') {
              return { ...s, phase: 'observed' as const, status: 'failed' as any, errorMessage: data.error };
            }
            return s;
          }));
          optionsRef.current.onFailed?.(data.error || 'Tarama basarisiz');
          break;

        case 'command_executing':
          // Tool'un calistirdigi komut bilgisi
          break;

        // ---- Kuşatma Doktrini: otonom motor kuşatma adımları ----
        case 'agent_thinking': {
          const thinking = data as AgentThinkingData;
          // Onay sonrası motor yeni adıma geçtiyse kapı geçildi → bekleme ekranını kaldır.
          setPhaseGate(null);
          // MOTOR FARKINDALIĞI: bu adım bir davranış-denetimi (loop-guard) uyarısı mı?
          // Bu bildirimler adım kartını taşırır ama gerçek karar kartı aynı step'i
          // sonra ezer → kalıcı `notices` akışına AYRICA yaz (kaybolmasın).
          const anyData = thinking as any;
          if (anyData.behavior_monitor) {
            pushNotice({
              kind: 'loop-guard',
              message: thinking.message || 'Davranış denetimi: tekrar eden araç tespit edildi.',
              step: thinking.step,
              data: { behavior_monitor: anyData.behavior_monitor },
            });
          }
          if (typeof anyData.vector_memory_hits === 'number' && anyData.vector_memory_hits > 0) {
            pushNotice({
              kind: 'memory',
              message: thinking.message || `Vektör hafıza: ${anyData.vector_memory_hits} geçmiş ders hatırlandı.`,
              step: thinking.step,
              data: { vector_memory_hits: anyData.vector_memory_hits },
            });
          }
          setAgentSteps(prev => upsertAgentStep(prev, thinking.step, {
            phase: thinking.action === 'stop' ? 'stopped' : 'thinking',
            reasoning: thinking.message || '',
            tool: thinking.tool ?? null,
            action: thinking.action,
            expected: thinking.expected,
            confidence: thinking.confidence,
            source: thinking.source,
            siegeScore: thinking.siege_score ?? null,
            chosenBecause: thinking.chosen_because,
            considered: thinking.considered,
            targetNode: thinking.target_node ?? null,
            targetValue: thinking.target_value ?? null,
          }));
          optionsRef.current.onAgentThinking?.(thinking);
          break;
        }

        case 'agent_action': {
          const action = data as AgentActionData;
          setAgentSteps(prev => upsertAgentStep(prev, action.step, {
            phase: 'acting',
            options: action.options,
            ...(action.expected ? { expected: action.expected } : {}),
            // Uzun süren araçlarda periyodik heartbeat "hâlâ çalışıyor (Ns)" süresini taşır.
            ...(typeof action.elapsed_seconds === 'number' ? { elapsedSeconds: action.elapsed_seconds } : {}),
          }));
          optionsRef.current.onAgentAction?.(action);
          break;
        }

        case 'agent_observation': {
          const obs = data as AgentObservationData;
          setAgentSteps(prev => upsertAgentStep(prev, obs.step, {
            phase: 'observed',
            status: obs.status,
            newEvidence: obs.new_evidence,
            totalEvidence: obs.total_evidence,
            services: obs.services,
            leads: obs.leads,
            resultSummary: obs.result_summary ?? null,
            artifactId: obs.artifact_id ?? null,
            errorMessage: obs.error ?? null,
            endedAt: new Date().toISOString(),
          }));
          optionsRef.current.onAgentObservation?.(obs);
          break;
        }

        case 'agent_approval_needed': {
          const approval = data as AgentApprovalData;
          setAgentSteps(prev => {
            // approval event'i step numarası taşımaz — tekrar oynatmada (reconnect) aynı
            // tool+timestamp'li kartın çift eklenmemesi için basit bir içerik eşleşmesi kullanılır.
            const already = prev.some(
              s => s.phase === 'approval' && s.tool === approval.tool &&
                   JSON.stringify(s.options) === JSON.stringify(approval.options)
            );
            if (already) return prev;
            const syntheticStep = prev.length ? Math.max(...prev.map(s => s.step)) + 0.1 : 0.1;
            return [...prev, {
              step: syntheticStep,
              // `as const`: literal tip korunmazsa TS 'string'e genişletip AgentStep
              // union'ını bozuyordu (mevcut tip hatası — bu dokunuşla kapandı).
              phase: 'approval' as const,
              reasoning: (data as any).message || '',
              tool: approval.tool,
              action: 'approval' as const,
              expected: '',
              confidence: 0,
              source: 'rules' as const,
              options: approval.options,
              startedAt: new Date().toISOString(),
            }].sort((a, b) => a.step - b.step);
          });
          optionsRef.current.onApprovalNeeded?.(approval);
          break;
        }

        case 'agent_phase_gate': {
          const gate = data as PhaseGateData;
          setPhaseGate(gate);
          optionsRef.current.onPhaseGate?.(gate);
          break;
        }

        case 'heartbeat':
          break;

        case 'error':
        case 'warning': {
          // Non-fatal error/warning — ESKİDEN SESSİZCE DÜŞÜRÜLÜYORDU. Kurumsal kullanıcı
          // "servis kapalı → dispatch sessiz failed → boş tarama" durumunu GÖRMELİ (AGENTS.md
          // kırılgan-nokta). Artık Motor Farkındalığı paneline düşer; tarama yine sürer.
          const wmsg = (data as any)?.message || (data as any)?.error || eventType;
          pushNotice({
            kind: eventType === 'error' ? 'error' : 'warning',
            message: String(wmsg),
            step: (data as any)?.step,
            data,
          });
          break;
        }
      }
    }

    ws.onmessage = (e) => {
      try {
        const msg: PipelineEvent = JSON.parse(e.data);

        // Add to events log
        setEvents(prev => [...prev.slice(-100), msg]); // Keep last 100

        switch (msg.type) {
          case 'initial_state':
            // Initial scan state from MongoDB
            break;

          case 'event_history':
            // Batch historical events — reconnect'te agentSteps'i de idempotent besler
            if (msg.events) {
              setEvents(prev => [...msg.events!, ...prev].slice(-100));
              for (const histEvent of msg.events) {
                handleInnerEvent(histEvent.event_type, histEvent.data || {});
              }
            }
            break;

          case 'event': {
            handleInnerEvent(msg.event_type, msg.data || {});
            break;
          }

          case 'heartbeat':
            break;

          case 'stream_ended':
            setComplete(true);
            disconnect();
            break;

          case 'error':
            setError(msg.message || 'Stream hatasi');
            break;
        }
      } catch (err) {
        console.error('[WS] Parse error:', err);
      }
    };
  }, [disconnect, setComplete]);
  // NOT: isComplete bilinçli olarak dependency DEĞİL — ws.onclose artık isCompleteRef
  // üzerinden okur (stale-closure kalkanı) ve connect her tarama için stabil kalmalı.

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  /** session.ai_analysis.agent_timeline'dan (EKSİK-0, kalıcı kaynak) gelen adımlarla
   * timeline'ı seed eder — reconnect/sayfa açılışında WS'in 20-event sınırını aşar. */
  const seedAgentSteps = useCallback((steps: AgentStep[]) => {
    setAgentSteps(prev => {
      const merged = [...steps];
      for (const s of prev) {
        if (!merged.some(m => m.step === s.step)) merged.push(s);
      }
      return merged.sort((a, b) => a.step - b.step);
    });
  }, []);

  /** Onay gönderildikten sonra bekleme ekranını hemen kaldırmak için (WS'ten yeni
   * agent_thinking gelene kadar iyimser UI). */
  const clearPhaseGate = useCallback(() => setPhaseGate(null), []);

  return {
    isConnected,
    isComplete,
    events,
    stageUpdates,
    agentSteps,
    progress,
    error,
    phaseGate,
    targetProfile,
    liveFindings,
    notices,
    engineActivity,
    connect,
    disconnect,
    seedAgentSteps,
    clearPhaseGate,
  };
}
