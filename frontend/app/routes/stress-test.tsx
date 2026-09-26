import { useState, useEffect, useRef } from 'react';
import { Form } from 'react-router';
import Tooltip from '../components/Tooltip';
import { api } from '../services/api';

interface AttackMetrics {
    requests_sent: number;
    requests_success: number;
    requests_failed: number;
    responses_2xx: number;
    responses_4xx: number;
    responses_5xx: number;
    responses_timeout: number;
    current_rps: number;
    avg_latency_ms: number;
    min_latency_ms: number;
    max_latency_ms: number;
    bandwidth_mbps: number;
    target_health: number;
}

interface StressJob {
    id: string;
    state: 'pending' | 'recon' | 'armed' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
    config: {
        target_url: string;
        mode: string;
        rps: number;
        threads: number;
        duration_secs: number;
    };
    metrics: AttackMetrics;
    logs: string[];
    created_at: number;
    started_at: number | null;
    completed_at: number | null;
}

interface EndpointInfo {
    url: string;
    method: string;
    latency_ms: number;
    status_code: number;
    content_length: number;
    is_slow: boolean;
}

interface ReconResult {
    endpoints: EndpointInfo[];
    recommended_target: EndpointInfo | null;
}

const ATTACK_MODES = [
    {
        id: 'smart',
        name: '🎯 Smart Mode',
        desc: 'Zayıf endpoint\'leri tespit eder ve odaklanır',
        color: 'from-cyan-600 to-blue-600'
    },
    {
        id: 'pulse',
        name: '💓 Pulse Mode',
        desc: '10 sn atak, 5 sn dinlenme - savunmaları yorar',
        color: 'from-purple-600 to-pink-600'
    },
    {
        id: 'chaos',
        name: '🌀 Chaos Mode',
        desc: 'Rastgele RPS ve endpoint - tahmin edilemez',
        color: 'from-red-600 to-orange-600'
    },
    {
        id: 'manual',
        name: '⚙️ Manual Mode',
        desc: 'Sabit RPS ile kontrollü test',
        color: 'from-slate-600 to-slate-500'
    },
];

export default function StressTestPage() {
    // Form state
    const [targetUrl, setTargetUrl] = useState('');
    const [attackMode, setAttackMode] = useState('smart');
    const [rps, setRps] = useState(100);
    const [threads, setThreads] = useState(10);
    const [duration, setDuration] = useState(60);

    // Job state
    const [jobId, setJobId] = useState<string | null>(null);
    const [job, setJob] = useState<StressJob | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Recon state
    const [reconResult, setReconResult] = useState<ReconResult | null>(null);
    const [isReconning, setIsReconning] = useState(false);

    // WebSocket
    const wsRef = useRef<WebSocket | null>(null);

    // Terminal scroll
    const logsEndRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [job?.logs]);

    // Poll job status
    useEffect(() => {
        let interval: any;
        if (jobId && job?.state === 'running') {
            interval = setInterval(async () => {
                try {
                    const response = await api.get<{ success: boolean; job: StressJob }>(`/api/stress/attack/${jobId}`);
                    if (response.success && response.job) {
                        setJob(response.job);
                        if (response.job.state === 'completed' || response.job.state === 'failed' || response.job.state === 'cancelled') {
                            clearInterval(interval);
                        }
                    }
                } catch (err) {
                    console.error('Polling error:', err);
                }
            }, 500);
        }
        return () => clearInterval(interval);
    }, [jobId, job?.state]);

    // Connect WebSocket for real-time metrics
    useEffect(() => {
        if (jobId && job?.state === 'running') {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${protocol}//${window.location.host}/api/stress/attack/${jobId}/ws`);

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.metrics) {
                        setJob(prev => prev ? { ...prev, metrics: data.metrics } : null);
                    }
                } catch (e) {
                    console.error('WS parse error:', e);
                }
            };

            wsRef.current = ws;

            return () => {
                ws.close();
            };
        }
    }, [jobId, job?.state]);

    const handleRecon = async () => {
        if (!targetUrl) return;
        setIsReconning(true);
        setError(null);

        try {
            const result = await api.post<ReconResult>('/api/stress/recon', {
                target_url: targetUrl,
                max_endpoints: 30
            });
            setReconResult(result);
        } catch (err: any) {
            setError(err.message || 'Recon failed');
        } finally {
            setIsReconning(false);
        }
    };

    const handleCreateJob = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);

        try {
            const response = await api.post<{ job_id: string }>('/api/stress/attack', {
                target_url: targetUrl,
                mode: attackMode,
                rps,
                threads,
                duration_secs: duration
            });

            setJobId(response.job_id);

            // Fetch initial job state
            const jobResponse = await api.get<{ success: boolean; job: StressJob }>(`/api/stress/attack/${response.job_id}`);
            if (jobResponse.success) {
                setJob(jobResponse.job);
            }
        } catch (err: any) {
            setError(err.message || 'Failed to create job');
        } finally {
            setIsLoading(false);
        }
    };

    const handleLaunch = async () => {
        if (!jobId) return;
        setIsLoading(true);

        try {
            await api.post(`/api/stress/attack/${jobId}/launch`, {});
            const jobResponse = await api.get<{ success: boolean; job: StressJob }>(`/api/stress/attack/${jobId}`);
            if (jobResponse.success) {
                setJob(jobResponse.job);
            }
        } catch (err: any) {
            setError(err.message || 'Failed to launch');
        } finally {
            setIsLoading(false);
        }
    };

    const handlePause = async () => {
        if (!jobId) return;
        try {
            await api.post(`/api/stress/attack/${jobId}/pause`, {});
            const jobResponse = await api.get<{ success: boolean; job: StressJob }>(`/api/stress/attack/${jobId}`);
            if (jobResponse.success) {
                setJob(jobResponse.job);
            }
        } catch (err: any) {
            setError(err.message);
        }
    };

    const handleCancel = async () => {
        if (!jobId) return;
        try {
            await api.delete(`/api/stress/attack/${jobId}`);
            const jobResponse = await api.get<{ success: boolean; job: StressJob }>(`/api/stress/attack/${jobId}`);
            if (jobResponse.success) {
                setJob(jobResponse.job);
            }
        } catch (err: any) {
            setError(err.message);
        }
    };

    const handleReset = () => {
        setJobId(null);
        setJob(null);
        setReconResult(null);
        setError(null);
    };

    // Calculate stats for display
    const successRate = job?.metrics.requests_sent
        ? ((job.metrics.requests_success / job.metrics.requests_sent) * 100).toFixed(1)
        : '0.0';

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex-1">
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-3">
                        <span className="text-4xl">⚡</span>
                        STRESS TEST MOTORU
                        <Tooltip content="Profesyonel yük testi ve DDoS simülasyon aracı. Sadece yetkili testler için kullanın." position="bottom">
                            <div className="w-5 h-5 rounded-full bg-yellow-500/20 hover:bg-yellow-500/30 flex items-center justify-center cursor-help transition-colors border border-yellow-500/40">
                                <span className="text-xs text-yellow-600 dark:text-yellow-300 font-bold">!</span>
                            </div>
                        </Tooltip>
                    </h1>
                    <p className="text-slate-600 dark:text-slate-400">Network Stress Testing & DDoS Simulation</p>
                </div>
                <div className="flex items-center gap-3">
                    {job?.state === 'running' && (
                        <div className="flex items-center gap-2 text-xs font-mono text-red-600 dark:text-red-400 bg-red-500/10 px-4 py-2 rounded-full border border-red-500/20 animate-pulse">
                            <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                            ATTACK IN PROGRESS
                        </div>
                    )}
                    {!job && (
                        <div className="flex items-center gap-2 text-xs font-mono text-cyan-600 dark:text-cyan-400 bg-cyan-500/10 px-4 py-2 rounded-full border border-cyan-500/20">
                            <span className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse"></span>
                            SYSTEM READY
                        </div>
                    )}
                </div>
            </div>

            {/* Warning Banner */}
            <div className="bg-gradient-to-r from-yellow-100 to-orange-100 dark:from-yellow-900/30 dark:to-orange-900/20 border-l-4 border-yellow-500 p-4 rounded-r-xl">
                <div className="flex items-start gap-3">
                    <span className="text-2xl">⚠️</span>
                    <div>
                        <h3 className="font-bold text-yellow-700 dark:text-yellow-400 mb-1">Kullanım Uyarısı</h3>
                        <p className="text-sm text-slate-700 dark:text-slate-300">
                            Bu araç <strong className="text-slate-900 dark:text-white">sadece yetkili güvenlik testleri</strong> için tasarlanmıştır.
                            İzinsiz hedeflere saldırı yapmak <strong className="text-red-600 dark:text-red-400">yasadışıdır</strong>.
                        </p>
                    </div>
                </div>
            </div>

            {/* Main Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Left - Controls */}
                <div className="lg:col-span-5 space-y-6">

                    {/* Config Panel */}
                    <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm dark:shadow-none">
                        <h2 className="text-lg font-bold mb-4 text-cyan-600 dark:text-cyan-400 flex items-center gap-2">
                            <span>⚙️</span> Attack Configuration
                        </h2>

                        <Form onSubmit={handleCreateJob} className="space-y-6">
                            {/* Target URL */}
                            <div>
                                <label className="block text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                                    Target URL
                                    <Tooltip content="Test edilecek hedef URL. Örnek: https://httpbin.org" position="right" />
                                </label>
                                <div className="flex gap-2">
                                    <input
                                        type="url"
                                        placeholder="https://httpbin.org"
                                        value={targetUrl}
                                        onChange={(e) => setTargetUrl(e.target.value)}
                                        disabled={!!job}
                                        className="flex-1 bg-slate-100 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:ring-2 focus:ring-cyan-500 focus:border-transparent outline-none font-mono disabled:opacity-50"
                                    />
                                    <button
                                        type="button"
                                        onClick={handleRecon}
                                        disabled={!targetUrl || isReconning || !!job}
                                        className="px-4 py-3 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-300 dark:disabled:bg-slate-700 disabled:cursor-not-allowed text-white rounded-lg font-semibold transition-all"
                                    >
                                        {isReconning ? '🔍' : '🕵️'} Recon
                                    </button>
                                </div>
                            </div>

                            {/* Attack Mode Selection */}
                            <div>
                                <label className="block text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">
                                    Attack Mode
                                </label>
                                <div className="grid grid-cols-2 gap-2">
                                    {ATTACK_MODES.map(mode => (
                                        <button
                                            key={mode.id}
                                            type="button"
                                            disabled={!!job}
                                            onClick={() => setAttackMode(mode.id)}
                                            className={`p-3 rounded-lg text-left transition-all ${attackMode === mode.id
                                                ? `bg-gradient-to-r ${mode.color} border-2 border-white/30`
                                                : 'bg-slate-100 dark:bg-slate-800/50 border border-slate-300 dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500'
                                                } ${job ? 'opacity-50 cursor-not-allowed' : ''}`}
                                        >
                                            <div className={`font-bold text-sm ${attackMode === mode.id ? 'text-white' : 'text-slate-900 dark:text-white'}`}>{mode.name}</div>
                                            <div className={`text-xs mt-1 ${attackMode === mode.id ? 'text-white/80' : 'text-slate-500 dark:text-slate-400'}`}>{mode.desc}</div>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* RPS Slider */}
                            <div>
                                <label className="block text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center justify-between">
                                    <span>Requests Per Second (RPS)</span>
                                    <span className="text-cyan-600 dark:text-cyan-400 text-lg font-mono">{rps}</span>
                                </label>
                                <input
                                    type="range"
                                    min="10"
                                    max="5000"
                                    step="10"
                                    value={rps}
                                    onChange={(e) => setRps(parseInt(e.target.value))}
                                    disabled={!!job}
                                    className="w-full h-2 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-500 disabled:opacity-50"
                                />
                                <div className="flex justify-between text-xs text-slate-400 dark:text-slate-500 mt-1">
                                    <span>10</span>
                                    <span>1000</span>
                                    <span>5000</span>
                                </div>
                            </div>

                            {/* Threads & Duration */}
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                                        Threads
                                    </label>
                                    <input
                                        type="number"
                                        min="1"
                                        max="100"
                                        value={threads}
                                        onChange={(e) => setThreads(parseInt(e.target.value) || 1)}
                                        disabled={!!job}
                                        className="w-full bg-slate-100 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white focus:ring-2 focus:ring-cyan-500 outline-none font-mono disabled:opacity-50"
                                    />
                                </div>
                                <div>
                                    <label className="block text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                                        Duration (secs)
                                    </label>
                                    <input
                                        type="number"
                                        min="10"
                                        max="3600"
                                        value={duration}
                                        onChange={(e) => setDuration(parseInt(e.target.value) || 60)}
                                        disabled={!!job}
                                        className="w-full bg-slate-100 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white focus:ring-2 focus:ring-cyan-500 outline-none font-mono disabled:opacity-50"
                                    />
                                </div>
                            </div>

                            {/* Error Display */}
                            {error && (
                                <div className="bg-red-100 dark:bg-red-900/30 border border-red-300 dark:border-red-500/50 rounded-lg p-3 text-red-700 dark:text-red-300 text-sm">
                                    ❌ {error}
                                </div>
                            )}

                            {/* Action Buttons */}
                            {!job ? (
                                <button
                                    type="submit"
                                    disabled={isLoading || !targetUrl}
                                    className={`w-full py-4 rounded-xl font-bold text-lg tracking-wide transition-all ${isLoading || !targetUrl
                                        ? 'bg-slate-200 dark:bg-slate-800 text-slate-400 dark:text-slate-500 cursor-not-allowed'
                                        : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg hover:scale-[1.02] shadow-cyan-500/20'
                                        }`}
                                >
                                    {isLoading ? 'PREPARING...' : '🎯 ARM ATTACK'}
                                </button>
                            ) : job.state === 'armed' ? (
                                <button
                                    type="button"
                                    onClick={handleLaunch}
                                    disabled={isLoading}
                                    className="w-full py-4 rounded-xl font-bold text-lg tracking-wide bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white shadow-lg hover:scale-[1.02] shadow-red-500/30 animate-pulse"
                                >
                                    🚀 LAUNCH ATTACK
                                </button>
                            ) : job.state === 'running' ? (
                                <div className="grid grid-cols-2 gap-3">
                                    <button
                                        type="button"
                                        onClick={handlePause}
                                        className="py-4 rounded-xl font-bold bg-yellow-500 hover:bg-yellow-400 text-white transition-all"
                                    >
                                        ⏸️ PAUSE
                                    </button>
                                    <button
                                        type="button"
                                        onClick={handleCancel}
                                        className="py-4 rounded-xl font-bold bg-red-600 hover:bg-red-500 text-white transition-all"
                                    >
                                        ⛔ ABORT
                                    </button>
                                </div>
                            ) : (
                                <button
                                    type="button"
                                    onClick={handleReset}
                                    className="w-full py-4 rounded-xl font-bold text-lg bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-white transition-all"
                                >
                                    🔄 NEW TEST
                                </button>
                            )}
                        </Form>
                    </div>

                    {/* Recon Results */}
                    {reconResult && (
                        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 shadow-sm dark:shadow-none">
                            <h3 className="text-sm font-bold text-purple-600 dark:text-purple-400 uppercase mb-3 flex items-center gap-2">
                                🕵️ Recon Results
                                <span className="text-xs text-slate-500">({reconResult.endpoints.length} endpoints)</span>
                            </h3>

                            {reconResult.recommended_target && (
                                <div className="bg-purple-100 dark:bg-purple-900/30 border border-purple-300 dark:border-purple-500/30 rounded-lg p-3 mb-3">
                                    <div className="text-xs text-purple-600 dark:text-purple-400 uppercase mb-1">Recommended Target (Slowest)</div>
                                    <div className="font-mono text-sm text-slate-900 dark:text-white truncate">{reconResult.recommended_target.url}</div>
                                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                                        Latency: <span className="text-red-600 dark:text-red-400">{reconResult.recommended_target.latency_ms}ms</span>
                                    </div>
                                </div>
                            )}

                            <div className="max-h-40 overflow-y-auto space-y-1">
                                {reconResult.endpoints.slice(0, 10).map((ep, i) => (
                                    <div
                                        key={i}
                                        onClick={() => setTargetUrl(ep.url)}
                                        className={`flex items-center justify-between p-2 rounded cursor-pointer transition-colors ${ep.is_slow
                                            ? 'bg-red-100 hover:bg-red-200 dark:bg-red-900/20 dark:hover:bg-red-900/30'
                                            : 'bg-slate-100 hover:bg-slate-200 dark:bg-slate-800/50 dark:hover:bg-slate-800'
                                            }`}
                                    >
                                        <span className="text-xs font-mono text-slate-700 dark:text-slate-300 truncate flex-1">{ep.url}</span>
                                        <span className={`text-xs font-mono ${ep.latency_ms > 500 ? 'text-red-600 dark:text-red-400' : ep.latency_ms > 200 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'}`}>
                                            {ep.latency_ms}ms
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                {/* Right - Dashboard */}
                <div className="lg:col-span-7 flex flex-col gap-6">

                    {/* Metrics Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {/* RPS Gauge */}
                        <div className="bg-gradient-to-br from-cyan-100 to-blue-100 dark:from-cyan-900/30 dark:to-blue-900/20 border border-cyan-300 dark:border-cyan-500/30 rounded-xl p-4 text-center">
                            <div className="text-3xl font-bold text-cyan-600 dark:text-cyan-400 font-mono">
                                {job?.metrics.current_rps.toFixed(0) || '0'}
                            </div>
                            <div className="text-xs text-slate-500 dark:text-slate-400 uppercase mt-1">RPS</div>
                        </div>

                        {/* Bandwidth */}
                        <div className="bg-gradient-to-br from-purple-100 to-pink-100 dark:from-purple-900/30 dark:to-pink-900/20 border border-purple-300 dark:border-purple-500/30 rounded-xl p-4 text-center">
                            <div className="text-3xl font-bold text-purple-600 dark:text-purple-400 font-mono">
                                {job?.metrics.bandwidth_mbps.toFixed(1) || '0.0'}
                            </div>
                            <div className="text-xs text-slate-500 dark:text-slate-400 uppercase mt-1">Mbps</div>
                        </div>

                        {/* Latency */}
                        <div className="bg-gradient-to-br from-yellow-100 to-orange-100 dark:from-yellow-900/30 dark:to-orange-900/20 border border-yellow-300 dark:border-yellow-500/30 rounded-xl p-4 text-center">
                            <div className="text-3xl font-bold text-yellow-600 dark:text-yellow-400 font-mono">
                                {job?.metrics.avg_latency_ms.toFixed(0) || '0'}
                            </div>
                            <div className="text-xs text-slate-500 dark:text-slate-400 uppercase mt-1">Latency (ms)</div>
                        </div>

                        {/* Success Rate */}
                        <div className="bg-gradient-to-br from-emerald-100 to-green-100 dark:from-emerald-900/30 dark:to-green-900/20 border border-emerald-300 dark:border-emerald-500/30 rounded-xl p-4 text-center">
                            <div className="text-3xl font-bold text-emerald-600 dark:text-emerald-400 font-mono">
                                {successRate}%
                            </div>
                            <div className="text-xs text-slate-500 dark:text-slate-400 uppercase mt-1">Success</div>
                        </div>
                    </div>

                    {/* Target Health Bar */}
                    <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm dark:shadow-none">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-bold text-slate-600 dark:text-slate-400 uppercase">Target Health</span>
                            <span className={`text-lg font-bold font-mono ${(job?.metrics.target_health ?? 100) > 70 ? 'text-emerald-600 dark:text-emerald-400' :
                                (job?.metrics.target_health ?? 100) > 30 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400'
                                }`}>
                                {(job?.metrics.target_health ?? 100).toFixed(0)}%
                            </span>
                        </div>
                        <div className="h-6 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden relative">
                            <div
                                className={`h-full rounded-full transition-all duration-500 ${(job?.metrics.target_health ?? 100) > 70 ? 'bg-gradient-to-r from-emerald-500 to-green-400' :
                                    (job?.metrics.target_health ?? 100) > 30 ? 'bg-gradient-to-r from-yellow-500 to-orange-400' :
                                        'bg-gradient-to-r from-red-500 to-rose-400'
                                    }`}
                                style={{ width: `${job?.metrics.target_health ?? 100}%` }}
                            />
                            {/* Crack effect when health is low */}
                            {(job?.metrics.target_health ?? 100) < 30 && (
                                <div className="absolute inset-0 flex items-center justify-center">
                                    <span className="text-white text-xs font-bold animate-pulse drop-shadow-lg">⚡ CRITICAL ⚡</span>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Response Codes Distribution */}
                    <div className="grid grid-cols-4 gap-3">
                        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3 text-center shadow-sm dark:shadow-none">
                            <div className="text-xl font-bold text-emerald-600 dark:text-emerald-400 font-mono">{job?.metrics.responses_2xx || 0}</div>
                            <div className="text-xs text-slate-500">2xx</div>
                        </div>
                        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3 text-center shadow-sm dark:shadow-none">
                            <div className="text-xl font-bold text-yellow-600 dark:text-yellow-400 font-mono">{job?.metrics.responses_4xx || 0}</div>
                            <div className="text-xs text-slate-500">4xx</div>
                        </div>
                        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3 text-center shadow-sm dark:shadow-none">
                            <div className="text-xl font-bold text-red-600 dark:text-red-400 font-mono">{job?.metrics.responses_5xx || 0}</div>
                            <div className="text-xs text-slate-500">5xx</div>
                        </div>
                        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3 text-center shadow-sm dark:shadow-none">
                            <div className="text-xl font-bold text-orange-600 dark:text-orange-400 font-mono">{job?.metrics.responses_timeout || 0}</div>
                            <div className="text-xs text-slate-500">Timeout</div>
                        </div>
                    </div>

                    {/* Terminal */}
                    <div className="bg-slate-100 dark:bg-black border border-slate-300 dark:border-slate-800 rounded-2xl overflow-hidden shadow-lg dark:shadow-2xl flex flex-col h-[400px]">
                        <div className="bg-slate-200 dark:bg-slate-900/50 px-4 py-2 border-b border-slate-300 dark:border-slate-800 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full bg-red-400 dark:bg-red-500/20 border border-red-500"></div>
                                <div className="w-3 h-3 rounded-full bg-yellow-400 dark:bg-yellow-500/20 border border-yellow-500"></div>
                                <div className="w-3 h-3 rounded-full bg-green-400 dark:bg-green-500/20 border border-green-500"></div>
                            </div>
                            <div className="text-xs font-mono text-slate-500">stress-service v1.0</div>
                        </div>
                        <div className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1 bg-gradient-to-b from-slate-50 to-slate-100 dark:from-black dark:to-slate-950">
                            {!job && (
                                <>
                                    <div className="text-cyan-600 dark:text-cyan-500">╔═══════════════════════════════════════════╗</div>
                                    <div className="text-cyan-600 dark:text-cyan-500">║            STRESS TEST ENGINE             ║</div>
                                    <div className="text-cyan-600 dark:text-cyan-500">╚═══════════════════════════════════════════╝</div>
                                    <div className="text-slate-400 dark:text-slate-600"># System initialized. Configure target and launch...</div>
                                </>
                            )}
                            {job?.logs.map((log, i) => (
                                <div key={i} className="break-all">
                                    <span className={
                                        log.includes('LAUNCH') || log.includes('🚀') ? 'text-red-600 dark:text-red-400 font-bold' :
                                            log.includes('✅') || log.includes('completed') ? 'text-emerald-600 dark:text-emerald-400' :
                                                log.includes('⛔') || log.includes('❌') ? 'text-red-600 dark:text-red-400' :
                                                    log.includes('⚡') || log.includes('⚙️') ? 'text-cyan-600 dark:text-cyan-400' :
                                                        log.includes('🎯') ? 'text-purple-600 dark:text-purple-400' :
                                                            'text-slate-700 dark:text-slate-300'
                                    }>{log}</span>
                                </div>
                            ))}
                            <div ref={logsEndRef} />
                            {job?.state === 'running' && <div className="animate-pulse text-cyan-600 dark:text-cyan-500">▌</div>}
                        </div>
                    </div>

                    {/* Stats Summary */}
                    {job && (
                        <div className="grid grid-cols-3 gap-3">
                            <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3 shadow-sm dark:shadow-none">
                                <div className="text-xs text-slate-500 uppercase">Total Requests</div>
                                <div className="text-xl font-bold text-slate-900 dark:text-white font-mono">{job.metrics.requests_sent.toLocaleString()}</div>
                            </div>
                            <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3 shadow-sm dark:shadow-none">
                                <div className="text-xs text-slate-500 uppercase">Min Latency</div>
                                <div className="text-xl font-bold text-green-600 dark:text-green-400 font-mono">{job.metrics.min_latency_ms}ms</div>
                            </div>
                            <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg p-3 shadow-sm dark:shadow-none">
                                <div className="text-xs text-slate-500 uppercase">Max Latency</div>
                                <div className="text-xl font-bold text-red-600 dark:text-red-400 font-mono">{job.metrics.max_latency_ms}ms</div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
