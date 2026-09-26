/**
 * AI Ayarları — Admin Panel
 * =========================
 * Türkçe: İki katman: (1) HASSAS BİLGİ — API anahtarı/URL/model `.env`'de tutulur ve burada
 * SALT-OKUR gösterilir (maskeli) + canlı "Bağlantıyı Test Et". (2) VARSAYILAN SEÇİMİ — hangi
 * sağlayıcının varsayılan olacağı BURADAN seçilir ve DB'ye yazılır (yalnız provider adı; anahtar
 * asla DB'ye gitmez). Otonom motor ve Rapor/Analiz için ayrı varsayılan seçilir.
 *
 * Backend:
 *   GET  /api/settings/ai/env-status          → 4 sağlayıcı özeti + canlı durum + aktif varsayılanlar
 *   POST /api/settings/ai/env-test/{provider} → gerçek bağlantı testi (.env anahtarıyla)
 *   PUT  /api/settings/ai/default/autonomous  → otonom motor varsayılanını DB'ye yaz
 *   PUT  /api/settings/ai/default/ai-service  → rapor/analiz varsayılanını DB'ye yaz
 */

import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router';
import {
    ArrowLeft, Bot, RefreshCw, TestTube2, Cloud, HardDrive, Cpu,
    CheckCircle2, XCircle, AlertTriangle, ShieldCheck, Info,
} from 'lucide-react';
import { api } from '../../services/api';

// --- Tipler ---
type Provider = 'ollama' | 'deepseek' | 'claude' | 'gemini';

interface ProviderStatus {
    provider: Provider;
    configured: boolean;
    requires_key: boolean;
    api_key_set: boolean;
    api_key_masked: string | null;
    url: string | null;
    default_model: string;
    data_leaves_network: boolean;
    is_autonomous_default: boolean;
    is_ai_service_default: boolean;
    // canlı probe alanları (env-status doldurur)
    reachable?: boolean;
    model_available?: boolean | null;
    message?: string;
    models?: string[];
}

interface EnvStatus {
    providers: ProviderStatus[];
    autonomous_provider: string;   // auto-scan motoru (ollama|deepseek)
    ai_service_provider: string;   // rapor/analiz motoru
    ai_service_model: string;
}

interface TestResult {
    status: 'success' | 'error' | 'testing';
    message: string;
    models?: string[];
}

// Sağlayıcı meta (görsel)
const PROVIDER_META: Record<Provider, { name: string; local: boolean; envHint: string }> = {
    ollama: { name: 'Ollama', local: true, envHint: 'OLLAMA_URL, AUTONOMOUS_MODEL' },
    deepseek: { name: 'DeepSeek', local: false, envHint: 'DEEPSEEK_API_KEY, DEEPSEEK_MODEL, DEEPSEEK_BASE_URL' },
    claude: { name: 'Claude', local: false, envHint: 'CLAUDE_API_KEY, CLAUDE_MODEL' },
    gemini: { name: 'Gemini', local: false, envHint: 'GEMINI_API_KEY, GEMINI_MODEL' },
};

function ProviderIcon({ local, className }: { local: boolean; className?: string }) {
    const Icon = local ? HardDrive : Cloud;
    return <Icon className={className} />;
}

// --- Sağlayıcı Kartı (salt-okur) ---
function ProviderCard({
    p, testResult, onTest,
}: {
    p: ProviderStatus;
    testResult?: TestResult;
    onTest: () => void;
}) {
    const meta = PROVIDER_META[p.provider];
    const reachable = !!p.reachable;

    // Durum tonu: yapılandırılmamış → slate, erişilebilir → emerald, sorunlu → amber.
    const tone = !p.configured
        ? 'border-slate-200 dark:border-slate-800'
        : reachable
            ? 'border-emerald-500/40 bg-emerald-500/5'
            : 'border-amber-500/40 bg-amber-500/5';

    return (
        <div className={`rounded-2xl border transition-all ${tone}`}>
            {/* Başlık */}
            <div className="flex items-center justify-between p-4 border-b border-slate-200/70 dark:border-slate-800">
                <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800">
                        <ProviderIcon local={meta.local} className="w-5 h-5 text-slate-600 dark:text-slate-300" />
                    </div>
                    <div>
                        <h3 className="font-bold text-slate-900 dark:text-white leading-tight">{meta.name}</h3>
                        <span className={`text-[11px] px-1.5 py-0.5 rounded-full ${
                            meta.local
                                ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                                : 'bg-orange-500/15 text-orange-600 dark:text-orange-400'
                        }`}>
                            {meta.local ? 'Local' : 'Bulut'}
                        </span>
                    </div>
                </div>
                {/* Yapılandırma / erişilebilirlik pili */}
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                    !p.configured
                        ? 'bg-slate-500/10 text-slate-500'
                        : reachable
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                            : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                }`}>
                    <span className={`w-2 h-2 rounded-full ${
                        !p.configured ? 'bg-slate-400' : reachable ? 'bg-emerald-500' : 'bg-amber-500'
                    }`} />
                    {!p.configured ? 'Yapılandırılmamış' : reachable ? 'Erişilebilir' : 'Erişilemez'}
                </span>
            </div>

            {/* İçerik */}
            <div className="p-4 space-y-3 text-sm">
                {/* Varsayılan rozetleri */}
                <div className="flex flex-wrap gap-2">
                    {p.is_autonomous_default && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-violet-500/10 text-violet-600 dark:text-violet-400">
                            <ShieldCheck className="w-3 h-3" /> Otonom motor varsayılanı
                        </span>
                    )}
                    {p.is_ai_service_default && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-cyan-500/10 text-cyan-600 dark:text-cyan-400">
                            <Bot className="w-3 h-3" /> Rapor/Analiz varsayılanı
                        </span>
                    )}
                </div>

                {/* API Key (SALT-OKUR, maskeli) */}
                {meta.local ? (
                    <Field label="Adres" icon={HardDrive}>
                        <span className="font-mono text-xs break-all text-slate-500">{p.url || '—'}</span>
                    </Field>
                ) : (
                    <Field label="API Key" icon={ShieldCheck}>
                        {p.api_key_set ? (
                            <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                                {p.api_key_masked}
                            </span>
                        ) : (
                            <span className="inline-flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                                <AlertTriangle className="w-3.5 h-3.5" /> .env'de tanımlı değil
                            </span>
                        )}
                    </Field>
                )}

                {/* Model */}
                <Field label="Varsayılan Model" icon={Cpu}>
                    <span className="font-mono text-xs break-all">{p.default_model || '—'}</span>
                </Field>

                {/* Gizlilik uyarısı */}
                <div className={`text-[11px] rounded-lg px-2.5 py-1.5 ${
                    p.data_leaves_network
                        ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400'
                        : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                }`}>
                    {p.data_leaves_network
                        ? 'Bulut — hedef/tarama verisi harici sunucuya gider (KVKK/bankacılıkta dikkat).'
                        : 'Local — veri dışarı çıkmaz (KVKK/bankacılık için önerilen).'}
                </div>

                {/* Test butonu */}
                <button
                    onClick={onTest}
                    disabled={testResult?.status === 'testing' || !p.configured}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {testResult?.status === 'testing'
                        ? <RefreshCw className="w-4 h-4 animate-spin" />
                        : <TestTube2 className="w-4 h-4" />}
                    Bağlantıyı Test Et
                </button>

                {/* Test sonucu */}
                {testResult && testResult.status !== 'testing' && (
                    <div className={`p-2.5 rounded-lg flex items-start gap-2 text-sm ${
                        testResult.status === 'success'
                            ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
                            : 'bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400'
                    }`}>
                        {testResult.status === 'success'
                            ? <CheckCircle2 className="w-4 h-4 mt-0.5 flex-shrink-0" />
                            : <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />}
                        <span>{testResult.message}</span>
                    </div>
                )}

                {/* .env ipucu */}
                <p className="text-[11px] text-slate-400 pt-1 border-t border-slate-200/60 dark:border-slate-800">
                    .env: <span className="font-mono">{meta.envHint}</span>
                </p>
            </div>
        </div>
    );
}

function Field({ label, icon: Icon, children }: { label: string; icon: any; children: React.ReactNode }) {
    return (
        <div className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-1.5 text-slate-500 flex-shrink-0">
                <Icon className="w-4 h-4" /> {label}
            </span>
            <span className="text-right text-slate-900 dark:text-slate-200">{children}</span>
        </div>
    );
}

// --- Varsayılan sağlayıcı seçici (DB'ye yazar) ---
// Yalnız `.env`'de yapılandırılmış sağlayıcılar seçilebilir; seçim anında DB'ye kaydedilir.
function DefaultSelector({
    title, icon: Icon, tone, current, modelLabel, configured, saving, onSelect,
}: {
    title: string;
    icon: any;
    tone: 'violet' | 'cyan';
    current: string;
    modelLabel?: string;
    configured: Provider[];
    saving: boolean;
    onSelect: (provider: string) => void;
}) {
    const toneCls = tone === 'violet'
        ? { border: 'border-violet-500/30 bg-violet-500/5', text: 'text-violet-600 dark:text-violet-400', ring: 'focus:ring-violet-500/40' }
        : { border: 'border-cyan-500/30 bg-cyan-500/5', text: 'text-cyan-600 dark:text-cyan-400', ring: 'focus:ring-cyan-500/40' };

    return (
        <div className={`rounded-xl border p-4 ${toneCls.border}`}>
            <div className={`flex items-center gap-2 mb-2 ${toneCls.text}`}>
                <Icon className="w-5 h-5" />
                <h2 className="font-semibold">{title}</h2>
                {saving && <RefreshCw className="w-4 h-4 animate-spin ml-auto" />}
            </div>
            <label className="text-sm text-slate-600 dark:text-slate-300 flex items-center gap-2 flex-wrap">
                Varsayılan sağlayıcı:
                <select
                    value={current}
                    disabled={saving}
                    onChange={(e) => { if (e.target.value !== current) onSelect(e.target.value); }}
                    className={`px-2.5 py-1 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm font-medium capitalize focus:outline-none focus:ring-2 ${toneCls.ring} disabled:opacity-50`}
                >
                    {configured.map((p) => (
                        <option key={p} value={p} className="capitalize">{PROVIDER_META[p].name}</option>
                    ))}
                    {/* Aktif değer yapılandırılmamışsa yine göster (aksi halde select boş görünür) */}
                    {!configured.includes(current as Provider) && (
                        <option value={current} className="capitalize">{current} (yapılandırılmamış)</option>
                    )}
                </select>
            </label>
            {modelLabel && (
                <p className="text-[11px] text-slate-400 mt-2">
                    Model: <span className="font-mono break-all">{modelLabel}</span>
                </p>
            )}
            <p className="text-[11px] text-slate-400 mt-1">
                Seçim DB'de tutulur · API anahtarı <span className="font-mono">.env</span>'de kalır
            </p>
        </div>
    );
}

// --- Ana Sayfa ---
export default function AISettings() {
    const [status, setStatus] = useState<EnvStatus | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [testResults, setTestResults] = useState<Record<string, TestResult>>({});
    const [savingDefault, setSavingDefault] = useState<null | 'autonomous' | 'ai-service'>(null);
    const [defaultError, setDefaultError] = useState<string | null>(null);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await api.get<EnvStatus>('/api/settings/ai/env-status');
            setStatus(data);
        } catch (e: any) {
            setError(e?.message || 'Yapılandırma yüklenemedi');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);

    const testProvider = async (provider: string) => {
        setTestResults((prev) => ({ ...prev, [provider]: { status: 'testing', message: 'Test ediliyor...' } }));
        try {
            const res = await api.post<TestResult>(`/api/settings/ai/env-test/${provider}`, {});
            setTestResults((prev) => ({ ...prev, [provider]: res }));
        } catch (e: any) {
            setTestResults((prev) => ({ ...prev, [provider]: { status: 'error', message: e?.message || 'Test başarısız' } }));
        }
    };

    // Varsayılan sağlayıcıyı DB'ye yaz (yalnız provider adı; anahtar .env'de kalır). Başarıda yenile.
    const setDefault = async (scope: 'autonomous' | 'ai-service', provider: string) => {
        setSavingDefault(scope);
        setDefaultError(null);
        try {
            await api.put(`/api/settings/ai/default/${scope}`, { provider });
            await load();
        } catch (e: any) {
            setDefaultError(e?.message || 'Varsayılan kaydedilemedi');
        } finally {
            setSavingDefault(null);
        }
    };

    // Yalnız `.env`'de yapılandırılmış (anahtar/URL dolu) sağlayıcılar varsayılan seçilebilir.
    const configuredProviders = (status?.providers ?? []).filter((p) => p.configured).map((p) => p.provider);

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex flex-col gap-4">
                <Link to="/" className="flex items-center gap-2 text-sm text-slate-500 hover:text-emerald-500 transition-colors w-fit">
                    <ArrowLeft className="w-4 h-4" /> Dashboard'a Dön
                </Link>
                <div className="flex items-center justify-between flex-wrap gap-3">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-gradient-to-br from-emerald-500 to-cyan-600 rounded-xl">
                            <Bot className="w-8 h-8 text-white" />
                        </div>
                        <div>
                            <h1 className="text-2xl md:text-3xl font-bold text-slate-900 dark:text-white">AI Yapılandırması</h1>
                            <p className="text-slate-500 dark:text-slate-400">
                                Varsayılan sağlayıcı buradan seçilir (DB) · anahtarlar .env'de (salt-okur)
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={load}
                        disabled={loading}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Yenile
                    </button>
                </div>
            </div>

            {/* Aktif varsayılan özeti + SEÇİCİ (DB'ye yazılır) */}
            {status && (
                <>
                    {defaultError && (
                        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 text-sm flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" /> {defaultError}
                        </div>
                    )}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <DefaultSelector
                            title="Otonom Motor (auto-scan)"
                            icon={ShieldCheck}
                            tone="violet"
                            current={status.autonomous_provider}
                            configured={configuredProviders}
                            saving={savingDefault === 'autonomous'}
                            onSelect={(p) => setDefault('autonomous', p)}
                        />
                        <DefaultSelector
                            title="Rapor / Analiz (ai-service)"
                            icon={Bot}
                            tone="cyan"
                            current={status.ai_service_provider}
                            modelLabel={status.ai_service_model}
                            configured={configuredProviders}
                            saving={savingDefault === 'ai-service'}
                            onSelect={(p) => setDefault('ai-service', p)}
                        />
                    </div>
                </>
            )}

            {/* Yükleme / hata */}
            {loading && (
                <div className="flex items-center justify-center min-h-[240px] text-slate-500">
                    <RefreshCw className="w-8 h-8 animate-spin text-emerald-500" />
                </div>
            )}
            {!loading && error && (
                <div className="p-6 rounded-xl bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5" /> {error}
                </div>
            )}

            {/* Sağlayıcı kartları */}
            {!loading && !error && status && (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                    {status.providers.map((p) => (
                        <ProviderCard
                            key={p.provider}
                            p={p}
                            testResult={testResults[p.provider]}
                            onTest={() => testProvider(p.provider)}
                        />
                    ))}
                </div>
            )}

            {/* Bilgi kutusu */}
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
                <h3 className="font-semibold text-blue-600 dark:text-blue-400 mb-2 flex items-center gap-2">
                    <Info className="w-5 h-5" /> Bilgi — Nasıl çalışır?
                </h3>
                <ul className="text-sm text-blue-600/80 dark:text-blue-400/80 space-y-1">
                    <li>• <strong>Varsayılan sağlayıcı</strong> yukarıdaki seçicilerden ayarlanır ve <strong>DB'de</strong> tutulur — servis yeniden başlatmaya gerek yok, yeni tarama/analiz seçimi kullanır.</li>
                    <li>• Yalnız <strong>.env'de yapılandırılmış</strong> (anahtar/URL dolu) sağlayıcılar varsayılan seçilebilir.</li>
                    <li>• <strong>Otonom motor</strong> ve <strong>Rapor/Analiz</strong> için ayrı ayrı varsayılan seçilir (4 sağlayıcı: ollama | deepseek | claude | gemini).</li>
                    <li>• <strong>API anahtarları</strong> güvenlik için yalnız <span className="font-mono">.env</span>'de tutulur, maskeli gösterilir ve <strong>hiçbir zaman DB'ye yazılmaz</strong>. Anahtar/model değişimi elle <span className="font-mono">.env</span>'den yapılır.</li>
                </ul>
            </div>
        </div>
    );
}
