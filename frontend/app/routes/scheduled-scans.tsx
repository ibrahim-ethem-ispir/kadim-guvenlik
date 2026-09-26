import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router';
import {
    CalendarClock, Plus, RefreshCw, Search, Play, Edit3, Trash2, X,
    Clock, CheckCircle2, AlertTriangle, XCircle, Activity, Hourglass,
    Shield, ListChecks, Loader2, Sparkles, Lightbulb, Bell,
    CheckSquare, Square, GitCompareArrows, Radio, Tag, Zap, StopCircle,
} from 'lucide-react';
import { api } from '../services/api';
import { useSchedulesStream } from '../hooks/useSchedulesStream';

// ---- Tipler ----
type IntervalKey = 'off' | 'hourly' | 'daily' | 'weekly';
type LevelKey = 'recon' | 'standard' | 'deep';

interface Schedule {
    schedule_id: string;
    target: string;
    target_type: 'ip' | 'domain';
    label: string;
    notes: string;
    level: LevelKey;
    stealth: boolean;
    schedule: {
        enabled: boolean;
        interval: IntervalKey;
        next_run_at: string | null;
        last_run_at: string | null;
    };
    last_scan: {
        session_id: string;
        scan_id: string;
        status: 'running' | 'completed' | 'failed' | 'cancelled' | 'stale' | 'timeout' | 'starting';
        started_at: string;
        finished_at?: string;
        error?: string;
        notification?: { severity: string; message: string };
    } | null;
    enabled: boolean;
    tags: string[];
    auto_tune_enabled: boolean;
    pending_subdomains?: Array<{ subdomain: string; discovered_at: string }>;
    paused_by_agent?: boolean;
    agent_pause_reason?: string;
    last_tune_at?: string;
    tune_history?: Array<{ from: string; to: string; reason: string; at: string }>;
    created_at: string;
}

const INTERVAL_LABELS: Record<IntervalKey, string> = {
    off: 'Kapalı',
    hourly: 'Saatlik',
    daily: 'Günlük',
    weekly: 'Haftalık',
};

const LEVEL_LABELS: Record<LevelKey, string> = {
    recon: 'Keşif',
    standard: 'Standart',
    deep: 'Derin',
};

// ---- Yardımcılar ----
// Sebep: V2ScanRequest ile birebir aynı regex'ler (auto-scan.tsx:218-220). İstemcide
// erken geri bildirim için, son kale backend.
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

function validateTarget(v: string) {
    const c = v.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    if (!c) return 'Hedef boş olamaz';
    if (DOMAIN_RE.test(c) || IPV4_RE.test(c)) return null;
    return 'Geçersiz hedef (IPv4 veya domain)';
}

function formatDate(iso: string | null | undefined) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString('tr-TR', { dateStyle: 'short', timeStyle: 'short' });
    } catch {
        return '—';
    }
}

// Sebep: göreceli zaman hem tarama geçmişinde hem scheduled listesinde tutarlı olmalı
// (kullanıcı "2 saat önce" bilgisine alışık). Çok basit — i18n ileride eklenebilir.
function timeAgo(iso: string | null | undefined) {
    if (!iso) return '—';
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 0) return 'az sonra';
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'az önce';
    if (m < 60) return `${m}dk önce`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}sa önce`;
    const d = Math.floor(h / 24);
    return `${d}gün önce`;
}

// ---- Durum rozeti ----
// Sebep: pipeline_v2'de bilinen tüm status'lar kapsanmalı (auto-scan.tsx:173, 208 + status
// alanı yorumu scan_pipeline_v2.py:106). paused da pipeline'da mevcut ama scheduled tarama
// için nadir — yine de listeliyoruz.
function StatusBadge({ status }: { status?: string }) {
    if (!status) return <span className="text-slate-500 text-xs">—</span>;
    const map: Record<string, { cls: string; icon: any; label: string }> = {
        starting: { cls: 'bg-blue-500/10 border-blue-500/30 text-blue-400', icon: Loader2, label: 'Başlatılıyor' },
        running: { cls: 'bg-blue-500/10 border-blue-500/30 text-blue-400', icon: Activity, label: 'Çalışıyor' },
        awaiting_approval: { cls: 'bg-amber-500/10 border-amber-500/30 text-amber-400', icon: Hourglass, label: 'Onay Bekliyor' },
        completed: { cls: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400', icon: CheckCircle2, label: 'Tamamlandı' },
        failed: { cls: 'bg-red-500/10 border-red-500/30 text-red-400', icon: XCircle, label: 'Hata' },
        cancelled: { cls: 'bg-slate-500/10 border-slate-500/30 text-slate-400', icon: XCircle, label: 'İptal' },
        stale: { cls: 'bg-amber-500/10 border-amber-500/30 text-amber-400', icon: AlertTriangle, label: 'Stale' },
        timeout: { cls: 'bg-amber-500/10 border-amber-500/30 text-amber-400', icon: AlertTriangle, label: 'Zaman Aşımı' },
        paused: { cls: 'bg-slate-500/10 border-slate-500/30 text-slate-400', icon: Hourglass, label: 'Duraklatıldı' },
    };
    const m = map[status] || { cls: 'bg-slate-500/10 border-slate-500/30 text-slate-400', icon: AlertTriangle, label: status };
    const Icon = m.icon;
    return (
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium border ${m.cls}`}>
            <Icon className={`w-3 h-3 ${status === 'running' || status === 'starting' ? 'animate-pulse' : ''}`} />
            {m.label}
        </span>
    );
}

// ---- Form Modal ----
// Sebep: admin/users.tsx modal pattern'i (EditUserModal, satır 22-123) — overlay, başlık,
// kapatma butonu, içerik. Inline yerine modal: daha az sayfa kayması, liste bağlamı korunur.
function ScheduleModal({
    initial,
    onClose,
    onSave,
}: {
    initial?: Schedule | null;
    onClose: () => void;
    onSave: (data: Partial<Schedule>) => Promise<void>;
}) {
    const isEdit = !!initial;
    const [target, setTarget] = useState(initial?.target || '');
    const [label, setLabel] = useState(initial?.label || '');
    const [notes, setNotes] = useState(initial?.notes || '');
    const [level, setLevel] = useState<LevelKey>(initial?.level || 'standard');
    const [stealth, setStealth] = useState(initial?.stealth || false);
    const [interval, setInterval] = useState<IntervalKey>(initial?.schedule?.interval || 'off');
    const [enabled, setEnabled] = useState(initial?.schedule?.enabled ?? false);
    const [tags, setTags] = useState<string[]>(initial?.tags || []);
    const [tagInput, setTagInput] = useState('');
    const [autoTune, setAutoTune] = useState(initial?.auto_tune_enabled ?? true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    // AI 1: hedef girilince LLM/kural periyot önerisi
    const [aiSuggest, setAiSuggest] = useState<{ interval: IntervalKey; reasoning: string; source: string } | null>(null);
    const [aiLoading, setAiLoading] = useState(false);

    const targetErr = target ? validateTarget(target) : null;

    const addTag = () => {
        const t = tagInput.trim().toLowerCase().replace(/\s+/g, '-').slice(0, 32);
        if (t && !tags.includes(t) && tags.length < 10) {
            setTags([...tags, t]);
            setTagInput('');
        }
    };
    const removeTag = (t: string) => setTags(tags.filter(x => x !== t));

    // AI 1 tetikleyicisi: hedef geçerli olduğunda öneri iste.
    useEffect(() => {
        if (!target || targetErr) { setAiSuggest(null); return; }
        const t = setTimeout(async () => {
            setAiLoading(true);
            try {
                const ttype = IPV4_RE.test(target.trim()) ? 'ip' : 'domain';
                const r = await api.post<{ interval: string; reasoning: string; source: string }>(
                    '/api/schedules/suggest-interval',
                    { target: target.trim(), target_type: ttype, label, notes }
                );
                if (r.interval && ['off', 'hourly', 'daily', 'weekly'].includes(r.interval)) {
                    setAiSuggest({ interval: r.interval as IntervalKey, reasoning: r.reasoning || '', source: r.source });
                }
            } catch (e) {
                // AI yoksa sessizce geç — kural-fallback zaten server'da
            } finally {
                setAiLoading(false);
            }
        }, 600);
        return () => clearTimeout(t);
    }, [target, targetErr]);

    const applyAiSuggest = () => {
        if (!aiSuggest) return;
        setInterval(aiSuggest.interval);
        if (aiSuggest.interval !== 'off') setEnabled(true);
    };

    const handleSave = async () => {
        if (targetErr) { setError(targetErr); return; }
        setSaving(true);
        setError(null);
        try {
            await onSave({
                target: target.trim().replace(/^https?:\/\//, '').replace(/\/$/, ''),
                label: label.trim(),
                notes: notes.trim(),
                level,
                stealth,
                schedule: { enabled, interval, next_run_at: null, last_run_at: null },
                tags,
                auto_tune_enabled: autoTune,
            } as any);
            onClose();
        } catch (e: any) {
            setError(e?.message || 'Kayıt başarısız');
            setSaving(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-y-auto">
                <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800 sticky top-0 bg-white dark:bg-slate-900 z-10">
                    <h3 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        {isEdit ? <Edit3 className="w-5 h-5 text-emerald-400" /> : <Plus className="w-5 h-5 text-emerald-400" />}
                        {isEdit ? 'Kayıt Düzenle' : 'Yeni Hedef Kaydı'}
                    </h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <div className="p-6 space-y-5">
                    {/* Hedef */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            Hedef <span className="text-red-400">*</span>
                        </label>
                        <input
                            value={target}
                            onChange={e => setTarget(e.target.value)}
                            placeholder="example.com veya 10.0.0.5"
                            disabled={isEdit}
                            className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white font-mono text-sm focus:outline-none focus:border-emerald-500 transition-colors disabled:opacity-60"
                        />
                        {targetErr && <p className="text-xs text-red-400 mt-1">{targetErr}</p>}
                    </div>

                    {/* Etiket + Not */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Etiket</label>
                            <input
                                value={label}
                                onChange={e => setLabel(e.target.value)}
                                placeholder="Ana web sunucusu"
                                className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500 transition-colors"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Notlar</label>
                            <input
                                value={notes}
                                onChange={e => setNotes(e.target.value)}
                                placeholder="Opsiyonel"
                                className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500 transition-colors"
                            />
                        </div>
                    </div>

                    {/* Seviye kartları */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Seviye</label>
                        <div className="grid grid-cols-3 gap-2">
                            {(['recon', 'standard', 'deep'] as LevelKey[]).map(lv => (
                                <button
                                    key={lv}
                                    onClick={() => setLevel(lv)}
                                    className={`px-3 py-2.5 rounded-lg border text-sm font-medium transition-all ${
                                        level === lv
                                            ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400'
                                            : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-400'
                                    }`}
                                >
                                    {LEVEL_LABELS[lv]}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Stealth toggle */}
                    <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg">
                        <div>
                            <div className="text-sm font-medium text-slate-900 dark:text-white">Stealth (düşük gürültü)</div>
                            <div className="text-xs text-slate-500 dark:text-slate-400">nmap -T2, daha yavaş ama daha az iz</div>
                        </div>
                        <button
                            onClick={() => setStealth(!stealth)}
                            className={`w-12 h-6 rounded-full transition-colors ${stealth ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-700'} relative`}
                        >
                            <span className={`absolute top-0.5 ${stealth ? 'right-0.5' : 'left-0.5'} w-5 h-5 rounded-full bg-white shadow transition-all`} />
                        </button>
                    </div>

                    {/* Auto-tune toggle */}
                    <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg">
                        <div>
                            <div className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-1.5">
                                <Zap className="w-3.5 h-3.5 text-amber-400" />
                                AI Auto-Tune
                            </div>
                            <div className="text-xs text-slate-500 dark:text-slate-400">Agent bulgulara göre sıklığı otomatik ayarlar</div>
                        </div>
                        <button
                            onClick={() => setAutoTune(!autoTune)}
                            className={`w-12 h-6 rounded-full transition-colors ${autoTune ? 'bg-amber-500' : 'bg-slate-300 dark:bg-slate-700'} relative`}
                        >
                            <span className={`absolute top-0.5 ${autoTune ? 'right-0.5' : 'left-0.5'} w-5 h-5 rounded-full bg-white shadow transition-all`} />
                        </button>
                    </div>

                    {/* Tags */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-1.5">
                            <Tag className="w-3.5 h-3.5" /> Etiketler (bulk işlemler için)
                        </label>
                        <div className="flex flex-wrap gap-1.5 mb-2">
                            {tags.map(t => (
                                <span key={t} className="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs">
                                    {t}
                                    <button onClick={() => removeTag(t)} className="hover:text-blue-200"><X className="w-3 h-3" /></button>
                                </span>
                            ))}
                        </div>
                        <div className="flex gap-2">
                            <input
                                value={tagInput}
                                onChange={e => setTagInput(e.target.value)}
                                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag(); } }}
                                placeholder="ör. prod, staging, api"
                                className="flex-1 px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white text-sm focus:outline-none focus:border-emerald-500"
                            />
                            <button
                                onClick={addTag}
                                disabled={!tagInput.trim() || tags.length >= 10}
                                className="px-3 py-2 rounded-lg bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 text-sm disabled:opacity-50"
                            >
                                Ekle
                            </button>
                        </div>
                    </div>

                    {/* Periyot */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Periyot</label>
                        {/* AI 1: periyot önerisi banner'ı */}
                        {aiSuggest && aiSuggest.interval !== interval && !isEdit && (
                            <button
                                onClick={applyAiSuggest}
                                className="w-full mb-2 p-2.5 rounded-lg bg-gradient-to-r from-purple-500/10 to-blue-500/10 border border-purple-500/30 hover:border-purple-500/60 transition-all flex items-center gap-3 text-left group"
                            >
                                <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0" />
                                <div className="flex-1 min-w-0">
                                    <div className="text-xs font-semibold text-purple-300">
                                        AI önerisi: {INTERVAL_LABELS[aiSuggest.interval]}
                                        {aiLoading && <Loader2 className="w-3 h-3 inline ml-2 animate-spin" />}
                                    </div>
                                    {aiSuggest.reasoning && (
                                        <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{aiSuggest.reasoning}</div>
                                    )}
                                </div>
                                <span className="text-xs text-purple-400 group-hover:text-purple-300">Uygula →</span>
                            </button>
                        )}
                        <div className="grid grid-cols-4 gap-2">
                            {(['off', 'hourly', 'daily', 'weekly'] as IntervalKey[]).map(iv => (
                                <button
                                    key={iv}
                                    onClick={() => {
                                        setInterval(iv);
                                        if (iv === 'off') setEnabled(false);
                                    }}
                                    className={`px-3 py-2 rounded-lg border text-sm font-medium transition-all ${
                                        interval === iv
                                            ? 'bg-blue-500/10 border-blue-500 text-blue-400'
                                            : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-400'
                                    }`}
                                >
                                    {INTERVAL_LABELS[iv]}
                                </button>
                            ))}
                        </div>
                        {interval !== 'off' && (
                            <label className="flex items-center gap-2 mt-3 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
                                <input
                                    type="checkbox"
                                    checked={enabled}
                                    onChange={e => setEnabled(e.target.checked)}
                                    className="w-4 h-4 rounded border-slate-300 text-emerald-500 focus:ring-emerald-500"
                                />
                                Zamanlamayı etkinleştir
                            </label>
                        )}
                        {interval !== 'off' && enabled && level === 'recon' && (
                            <p className="text-xs text-amber-400 mt-2 flex items-center gap-1.5">
                                <AlertTriangle className="w-3 h-3" />
                                Seviye "Keşif" zamanlanmış taramalarda sömürü onayında takılabilir. Standart veya Derin önerilir.
                            </p>
                        )}
                    </div>

                    {error && (
                        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg text-sm flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}
                        </div>
                    )}
                </div>

                <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-200 dark:border-slate-800 sticky bottom-0 bg-white dark:bg-slate-900">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                    >
                        İptal
                    </button>
                    <button
                        onClick={handleSave}
                        disabled={saving || !!targetErr || !target}
                        className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition-colors flex items-center gap-2"
                    >
                        {saving && <Loader2 className="w-4 h-4 animate-spin" />}
                        {isEdit ? 'Güncelle' : 'Kaydet'}
                    </button>
                </div>
            </div>
        </div>
    );
}

// ---- İki aşamalı silme onayı (admin/users.tsx:488-514 deseni) ----
function DeleteButton({ onConfirm, busy }: { onConfirm: () => void; busy: boolean }) {
    const [confirming, setConfirming] = useState(false);
    if (!confirming) {
        return (
            <button
                onClick={() => setConfirming(true)}
                className="p-2 text-slate-500 hover:text-red-400 transition-colors"
                title="Sil"
            >
                <Trash2 className="w-4 h-4" />
            </button>
        );
    }
    return (
        <div className="flex items-center gap-2">
            <button
                onClick={onConfirm}
                disabled={busy}
                className="px-2.5 py-1 bg-red-500/20 border border-red-500/40 text-red-400 rounded text-xs font-medium hover:bg-red-500/30 transition-colors flex items-center gap-1"
            >
                {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
                Emin misiniz?
            </button>
            <button
                onClick={() => setConfirming(false)}
                className="px-2 py-1 text-slate-500 hover:text-slate-300 text-xs"
            >
                Vazgeç
            </button>
        </div>
    );
}

// ---- Ana sayfa ----
export default function ScheduledScans() {
    const navigate = useNavigate();
    const [items, setItems] = useState<Schedule[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [q, setQ] = useState('');
    const [modalOpen, setModalOpen] = useState(false);
    const [editing, setEditing] = useState<Schedule | null>(null);
    const [runningIds, setRunningIds] = useState<Set<string>>(new Set([]));
    const [stoppingIds, setStoppingIds] = useState<Set<string>>(new Set([]));
    const [anomalies, setAnomalies] = useState<Array<{ type: string; severity: string; target: string; schedule_id: string; message: string }>>([]);
    const [insights, setInsights] = useState<Record<string, string>>({});
    const [insightModal, setInsightModal] = useState<{ schedule: Schedule; text: string; loading: boolean } | null>(null);
    // Tier 3: çoklu seçim, diff modal, WS
    const [selected, setSelected] = useState<Set<string>>(new Set([]));
    const [bulkBusy, setBulkBusy] = useState(false);
    const [diffModal, setDiffModal] = useState<{ schedule: Schedule; data: any; loading: boolean } | null>(null);
    // WS — anlık event'ler için (scan tamamlanınca anında tazeleme, kritik bulgu banner'ı)
    const { connected: wsConnected } = useSchedulesStream({
        onScanCompleted: () => fetchAll(),
        onCriticalFinding: () => fetchAnomalies(),
        onScanFailed: () => fetchAll(),
        onSubdomainFound: () => fetchAll(),
    });

    useEffect(() => {
        fetchAll();
        fetchAnomalies();
        const t = setInterval(() => { fetchAll(); fetchAnomalies(); }, 30000);
        return () => clearInterval(t);
    }, []);

    const fetchAll = async () => {
        try {
            const data = await api.get<{ items: Schedule[]; count: number }>('/api/schedules');
            setItems(data.items || []);
            setError(null);
        } catch (e: any) {
            setError(e?.message || 'Kayıtlar yüklenemedi');
        } finally {
            setLoading(false);
        }
    };

    const fetchAnomalies = async () => {
        try {
            const r = await api.get<{ anomalies: typeof anomalies; count: number }>('/api/schedules/anomalies');
            setAnomalies(r.anomalies || []);
        } catch {
            // AI endpoint'i kapalıysa sessizce geç
        }
    };

    const openInsight = async (s: Schedule) => {
        setInsightModal({ schedule: s, text: insights[s.schedule_id] || '', loading: true });
        try {
            const r = await api.get<{ insight: string; source: string; confidence: number }>(
                `/api/schedules/${s.schedule_id}/insight`
            );
            setInsightModal({ schedule: s, text: r.insight, loading: false });
            setInsights(prev => ({ ...prev, [s.schedule_id]: r.insight }));
        } catch (e: any) {
            setInsightModal({ schedule: s, text: e?.message || 'Özet alınamadı', loading: false });
        }
    };

    const handleSave = async (data: Partial<Schedule>) => {
        if (editing) {
            await api.put(`/api/schedules/${editing.schedule_id}`, {
                label: data.label,
                notes: data.notes,
                level: data.level,
                stealth: data.stealth,
                schedule: { enabled: data.schedule?.enabled, interval: data.schedule?.interval },
                tags: data.tags,
                auto_tune_enabled: data.auto_tune_enabled,
            });
        } else {
            await api.post('/api/schedules', data);
        }
        await fetchAll();
    };

    // Tier 3: bulk aksiyon
    const handleBulk = async (action: 'run' | 'delete' | 'enable' | 'disable' | 'pause' | 'resume') => {
        if (selected.size === 0) return;
        if (action === 'delete' && !confirm(`${selected.size} kayıt silinsin mi?`)) return;
        setBulkBusy(true);
        try {
            const r = await api.post<any>('/api/schedules/bulk', {
                schedule_ids: Array.from(selected),
                action,
            });
            if (action === 'run' && r.queued) {
                // İlk başarılı session'a navigate et
                if (r.queued[0]?.session_id) {
                    navigate(`/auto-scan?session=${r.queued[0].session_id}`);
                }
            }
            setSelected(new Set([]));
            await fetchAll();
        } catch (e: any) {
            setError(e?.message || 'Toplu işlem başarısız');
        } finally {
            setBulkBusy(false);
        }
    };

    // Tier 3: diff aç
    const openDiff = async (s: Schedule) => {
        setDiffModal({ schedule: s, data: null, loading: true });
        try {
            const r = await api.get<any>(`/api/schedules/${s.schedule_id}/diff`);
            setDiffModal({ schedule: s, data: r, loading: false });
        } catch (e: any) {
            setDiffModal({ schedule: s, data: { error: e?.message || 'Diff alınamadı' }, loading: false });
        }
    };

    // Tier 3: pending subdomain accept/dismiss
    const acceptSubdomain = async (s: Schedule, subdomain: string) => {
        try {
            await api.post(`/api/schedules/${s.schedule_id}/accept-subdomain?subdomain=${encodeURIComponent(subdomain)}`, {});
            await fetchAll();
        } catch (e: any) { setError(e?.message || 'Eklenemedi'); }
    };
    const dismissSubdomain = async (s: Schedule, subdomain: string) => {
        try {
            await api.post(`/api/schedules/${s.schedule_id}/dismiss-subdomain?subdomain=${encodeURIComponent(subdomain)}`, {});
            await fetchAll();
        } catch (e: any) { setError(e?.message || 'Reddedilemedi'); }
    };

    const handleDelete = async (id: string) => {
        await api.delete(`/api/schedules/${id}`);
        await fetchAll();
    };

    const handleRun = async (s: Schedule) => {
        setRunningIds(prev => new Set(prev).add(s.schedule_id));
        try {
            const result = await api.post<{ session_id: string; scan_id: string }>(
                `/api/schedules/${s.schedule_id}/run`, {}
            );
            // Sebep: auto-scan sayfası ?session= ile mount'ta oturumu geri yükleyip WS'e
            // bağlanıyor (auto-scan.tsx:141-168). Direkt navigate → kullanıcı canlı
            // timeline'ı hazır bulur, ayrı başlatma butonuna basmasına gerek kalmaz.
            navigate(`/auto-scan?session=${result.session_id}`);
        } catch (e: any) {
            setError(e?.message || 'Tarama başlatılamadı');
            setRunningIds(prev => {
                const n = new Set(prev);
                n.delete(s.schedule_id);
                return n;
            });
        }
    };

    const handleStop = async (s: Schedule) => {
        setStoppingIds(prev => new Set(prev).add(s.schedule_id));
        try {
            await api.post(`/api/schedules/${s.schedule_id}/stop`, {});
            setRunningIds(prev => {
                const n = new Set(prev);
                n.delete(s.schedule_id);
                return n;
            });
            await fetchAll();
        } catch (e: any) {
            setError(e?.message || 'Tarama durdurulamadı');
        } finally {
            setStoppingIds(prev => {
                const n = new Set(prev);
                n.delete(s.schedule_id);
                return n;
            });
        }
    };

    // Sebep: istemci tarafı filtreleme — backend zaten ?q= kabul ediyor ama sayfa-içi
    // anlık arama için 500 öğenin üstüne çıkmadan lokal filter yeterli.
    const filtered = useMemo(() => {
        if (!q.trim()) return items;
        const r = new RegExp(q.trim(), 'i');
        return items.filter(s => r.test(s.target) || r.test(s.label) || r.test(s.notes));
    }, [items, q]);

    // İstatistikler
    const stats = useMemo(() => ({
        total: items.length,
        activeSchedules: items.filter(s => s.schedule.enabled).length,
        runningNow: items.filter(s => s.last_scan?.status === 'running' || s.last_scan?.status === 'starting').length,
        // Bu ay tarama sayısı
        monthCount: items.reduce((acc, s) => {
            const ts = s.last_scan?.started_at;
            if (!ts) return acc;
            const d = new Date(ts);
            const now = new Date();
            return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear() ? acc + 1 : acc;
        }, 0),
    }), [items]);

    return (
        <div className="p-2 lg:p-4 max-w-8xl mx-auto">
            {/* Başlık */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center shadow-lg">
                        <CalendarClock className="w-6 h-6 text-white" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                            Zamanlanmış Taramalar
                            {/* WS bağlantı indikatörü — Tier 3 real-time */}
                            <span
                                className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${
                                    wsConnected
                                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                                        : 'bg-slate-500/10 border-slate-500/30 text-slate-500'
                                }`}
                                title={wsConnected ? 'Real-time bağlı' : 'Yeniden bağlanılıyor...'}
                            >
                                <Radio className={`w-3 h-3 ${wsConnected ? 'animate-pulse' : ''}`} />
                                {wsConnected ? 'Canlı' : 'Offline'}
                            </span>
                        </h1>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Kendi hedeflerinizi kaydedin, AI sürekli izlesin</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={fetchAll}
                        disabled={loading}
                        className="p-2.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition-colors"
                        title="Yenile"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                    <button
                        onClick={() => { setEditing(null); setModalOpen(true); }}
                        className="px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium transition-colors flex items-center gap-2"
                    >
                        <Plus className="w-4 h-4" /> Yeni Kayıt
                    </button>
                </div>
            </div>

            {/* Tier 3: Bulk action toolbar — seçili öğe varsa göster */}
            {selected.size > 0 && (
                <div className="mb-4 p-3 bg-blue-500/10 border border-blue-500/30 rounded-xl flex items-center gap-3 flex-wrap">
                    <span className="text-sm text-blue-400 font-medium">{selected.size} kayıt seçili</span>
                    <div className="flex items-center gap-2 ml-auto flex-wrap">
                        <button onClick={() => handleBulk('run')} disabled={bulkBusy} className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium disabled:opacity-50 flex items-center gap-1.5">
                            <Play className="w-3 h-3" /> Taramayı Başlat
                        </button>
                        <button onClick={() => handleBulk('pause')} disabled={bulkBusy} className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-medium disabled:opacity-50">
                            Duraklat
                        </button>
                        <button onClick={() => handleBulk('resume')} disabled={bulkBusy} className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium disabled:opacity-50">
                            Sürdür
                        </button>
                        <button onClick={() => handleBulk('enable')} disabled={bulkBusy} className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium disabled:opacity-50">
                            Etkinleştir
                        </button>
                        <button onClick={() => handleBulk('disable')} disabled={bulkBusy} className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium disabled:opacity-50">
                            Devre dışı
                        </button>
                        <button onClick={() => handleBulk('delete')} disabled={bulkBusy} className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-medium disabled:opacity-50 flex items-center gap-1.5">
                            <Trash2 className="w-3 h-3" /> Sil
                        </button>
                        <button onClick={() => setSelected(new Set([]))} className="px-3 py-1.5 text-slate-500 hover:text-slate-300 text-xs">
                            Seçimi temizle
                        </button>
                    </div>
                </div>
            )}

            {/* İstatistik kartları */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                {[
                    { label: 'Toplam Kayıt', value: stats.total, icon: ListChecks, color: 'emerald' },
                    { label: 'Aktif Zamanlama', value: stats.activeSchedules, icon: Clock, color: 'blue' },
                    { label: 'Çalışan', value: stats.runningNow, icon: Activity, color: 'amber' },
                    { label: 'Bu Ay Tarama', value: stats.monthCount, icon: Shield, color: 'purple' },
                ].map(c => {
                    const Icon = c.icon;
                    const colors: Record<string, string> = {
                        emerald: 'from-emerald-500/20 to-emerald-500/5 text-emerald-400',
                        blue: 'from-blue-500/20 to-blue-500/5 text-blue-400',
                        amber: 'from-amber-500/20 to-amber-500/5 text-amber-400',
                        purple: 'from-purple-500/20 to-purple-500/5 text-purple-400',
                    };
                    return (
                        <div key={c.label} className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                            <div className="flex items-center justify-between mb-2">
                                <div className={`w-9 h-9 rounded-lg bg-gradient-to-br ${colors[c.color]} flex items-center justify-center`}>
                                    <Icon className="w-4 h-4" />
                                </div>
                            </div>
                            <div className="text-2xl font-bold text-slate-900 dark:text-white">{c.value}</div>
                            <div className="text-xs text-slate-500 dark:text-slate-400">{c.label}</div>
                        </div>
                    );
                })}
            </div>

            {/* Hata banner'ı */}
            {error && (
                <div className="mb-4 bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg text-sm flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />{error}
                    </div>
                    <button onClick={() => setError(null)} className="text-red-300 hover:text-red-200">
                        <X className="w-4 h-4" />
                    </button>
                </div>
            )}

            {/* Tier 3: AI Agent tarafından keşfedilen subdomain önerileri */}
            {items.some(s => (s.pending_subdomains || []).length > 0) && (
                <div className="mb-4 space-y-2">
                    {items.filter(s => (s.pending_subdomains || []).length > 0).flatMap(s =>
                        (s.pending_subdomains || []).map(p => (
                            <div key={`${s.schedule_id}-${p.subdomain}`} className="px-4 py-3 rounded-lg border bg-purple-500/10 border-purple-500/30 text-purple-300 flex items-center gap-3">
                                <Sparkles className="w-4 h-4 flex-shrink-0" />
                                <div className="flex-1 text-sm">
                                    <span className="font-semibold">{p.subdomain}</span>
                                    <span className="mx-2 opacity-50">·</span>
                                    <span>AI Agent <span className="font-mono">{s.target}</span> taramasında keşfetti</span>
                                </div>
                                <button onClick={() => acceptSubdomain(s, p.subdomain)} className="px-2.5 py-1 bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded text-xs font-medium hover:bg-emerald-500/30">
                                    Ekle
                                </button>
                                <button onClick={() => dismissSubdomain(s, p.subdomain)} className="px-2 py-1 text-slate-500 hover:text-slate-300 text-xs">
                                    Reddet
                                </button>
                            </div>
                        ))
                    )}
                </div>
            )}

            {/* AI 3: Anomali banner'ı — kritik/warning anomalileri üstte göster */}
            {anomalies.length > 0 && (
                <div className="mb-4 space-y-2">
                    {anomalies.slice(0, 5).map((a, i) => {
                        const isCrit = a.severity === 'critical';
                        return (
                            <div key={i} className={`px-4 py-3 rounded-lg border flex items-center gap-3 ${
                                isCrit ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                            }`}>
                                {isCrit ? <Bell className="w-4 h-4 flex-shrink-0 animate-pulse" /> : <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
                                <div className="flex-1 text-sm">
                                    <span className="font-mono font-semibold">{a.target}</span>
                                    <span className="mx-2 opacity-50">·</span>
                                    <span>{a.message}</span>
                                </div>
                                <button
                                    onClick={() => navigate(`/auto-scan?session=${items.find(it => it.schedule_id === a.schedule_id)?.last_scan?.session_id || ''}`)}
                                    className="text-xs underline opacity-80 hover:opacity-100"
                                >
                                    İncele
                                </button>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Arama */}
            <div className="mb-4 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                    value={q}
                    onChange={e => setQ(e.target.value)}
                    placeholder="Hedef, etiket veya not içinde ara..."
                    className="w-full pl-10 pr-4 py-2.5 bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 transition-colors"
                />
            </div>

            {/* Tablo veya boş durum */}
            {loading && items.length === 0 ? (
                <div className="flex items-center justify-center py-20 text-slate-500">
                    <Loader2 className="w-6 h-6 animate-spin mr-2" /> Yükleniyor...
                </div>
            ) : filtered.length === 0 ? (
                <div className="bg-white dark:bg-slate-900/50 border border-dashed border-slate-300 dark:border-slate-700 rounded-2xl p-12 text-center">
                    <CalendarClock className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                        {items.length === 0 ? 'Henüz kayıt yok' : 'Eşleşen kayıt bulunamadı'}
                    </h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                        {items.length === 0 ? 'İlk hedefinizi ekleyerek başlayın' : 'Farklı bir arama terimi deneyin'}
                    </p>
                    {items.length === 0 && (
                        <button
                            onClick={() => { setEditing(null); setModalOpen(true); }}
                            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors"
                        >
                            <Plus className="w-4 h-4 inline mr-1" /> İlk Kaydı Ekle
                        </button>
                    )}
                </div>
            ) : (
                <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="bg-slate-50 dark:bg-slate-900/80 border-b border-slate-200 dark:border-slate-800">
                                    <th className="px-4 py-3 w-10">
                                        <button
                                            onClick={() => {
                                                if (selected.size === filtered.length) setSelected(new Set([]));
                                                else setSelected(new Set(filtered.map(s => s.schedule_id)));
                                            }}
                                            className="text-slate-500 hover:text-slate-300"
                                        >
                                            {selected.size === filtered.length && filtered.length > 0
                                                ? <CheckSquare className="w-4 h-4 text-blue-400" />
                                                : <Square className="w-4 h-4" />}
                                        </button>
                                    </th>
                                    <th className="text-left px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Hedef</th>
                                    <th className="text-left px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Etiket</th>
                                    <th className="text-left px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Seviye</th>
                                    <th className="text-left px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Periyot</th>
                                    <th className="text-left px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Son Tarama</th>
                                    <th className="text-left px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Sonraki</th>
                                    <th className="text-left px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">AI</th>
                                    <th className="text-right px-4 py-3 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">İşlem</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                {filtered.map(s => {
                                    const isRunning = runningIds.has(s.schedule_id) || s.last_scan?.status === 'running' || s.last_scan?.status === 'starting';
                                    const isSelected = selected.has(s.schedule_id);
                                    return (
                                        <tr key={s.schedule_id} className={`hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors ${isSelected ? 'bg-blue-500/5' : ''}`}>
                                            <td className="px-4 py-3">
                                                <button
                                                    onClick={() => {
                                                        const n = new Set(selected);
                                                        if (n.has(s.schedule_id)) n.delete(s.schedule_id); else n.add(s.schedule_id);
                                                        setSelected(n);
                                                    }}
                                                    className="text-slate-500 hover:text-slate-300"
                                                >
                                                    {isSelected
                                                        ? <CheckSquare className="w-4 h-4 text-blue-400" />
                                                        : <Square className="w-4 h-4" />}
                                                </button>
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex items-center gap-2">
                                                    <div>
                                                        <div className="font-mono text-sm text-slate-900 dark:text-white">{s.target}</div>
                                                        {s.label && <div className="text-xs text-slate-500 dark:text-slate-400">{s.label}</div>}
                                                    </div>
                                                    {s.paused_by_agent && (
                                                        <span className="text-xs px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400" title={s.agent_pause_reason || 'AI agent duraklattı'}>
                                                            AI pause
                                                        </span>
                                                    )}
                                                    {s.auto_tune_enabled && (
                                                        <span className="text-xs px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 inline-flex items-center gap-1" title="AI auto-tune aktif">
                                                            <Zap className="w-2.5 h-2.5" />
                                                        </span>
                                                    )}
                                                </div>
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex flex-wrap gap-1">
                                                    {(s.tags || []).slice(0, 3).map(t => (
                                                        <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400">{t}</span>
                                                    ))}
                                                    {(s.tags || []).length > 3 && <span className="text-xs text-slate-500">+{s.tags.length - 3}</span>}
                                                </div>
                                            </td>
                                            <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300">
                                                {LEVEL_LABELS[s.level]}
                                                {s.stealth && <span className="ml-1.5 text-xs text-amber-400" title="Stealth">⚡</span>}
                                            </td>
                                            <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300">
                                                {s.schedule.enabled ? (
                                                    <span className="inline-flex items-center gap-1 text-blue-400">
                                                        <Clock className="w-3 h-3" /> {INTERVAL_LABELS[s.schedule.interval]}
                                                    </span>
                                                ) : (
                                                    <span className="text-slate-500">—</span>
                                                )}
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex flex-col gap-1">
                                                    <StatusBadge status={s.last_scan?.status} />
                                                    <span className="text-xs text-slate-500 dark:text-slate-400">
                                                        {timeAgo(s.last_scan?.started_at)}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
                                                {s.schedule.enabled && s.schedule.next_run_at ? formatDate(s.schedule.next_run_at) : '—'}
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex flex-col gap-1">
                                                    {s.last_scan && (
                                                        <>
                                                            <button
                                                                onClick={() => openInsight(s)}
                                                                className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium bg-purple-500/10 border border-purple-500/30 text-purple-400 hover:bg-purple-500/20 transition-colors"
                                                                title="AI özetini göster"
                                                            >
                                                                <Sparkles className="w-3 h-3" />
                                                                Özet
                                                            </button>
                                                            <button
                                                                onClick={() => openDiff(s)}
                                                                className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                                                                title="Son iki tarama farkı"
                                                            >
                                                                <GitCompareArrows className="w-3 h-3" />
                                                                Diff
                                                            </button>
                                                        </>
                                                    )}
                                                </div>
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex items-center justify-end gap-1">
                                                    {isRunning ? (
                                                        <button
                                                            onClick={() => handleStop(s)}
                                                            disabled={stoppingIds.has(s.schedule_id)}
                                                            className="p-2 text-red-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                                            title="Taramayı zorla durdur (takılı kaldıysa)"
                                                        >
                                                            {stoppingIds.has(s.schedule_id)
                                                                ? <Loader2 className="w-4 h-4 animate-spin" />
                                                                : <StopCircle className="w-4 h-4" />}
                                                        </button>
                                                    ) : (
                                                        <button
                                                            onClick={() => handleRun(s)}
                                                            disabled={!s.enabled}
                                                            className="p-2 text-emerald-500 hover:text-emerald-400 hover:bg-emerald-500/10 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                                            title="Şimdi Tara"
                                                        >
                                                            <Play className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                    <button
                                                        onClick={() => { setEditing(s); setModalOpen(true); }}
                                                        className="p-2 text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors"
                                                        title="Düzenle"
                                                    >
                                                        <Edit3 className="w-4 h-4" />
                                                    </button>
                                                    <DeleteButton onConfirm={() => handleDelete(s.schedule_id)} busy={false} />
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {modalOpen && (
                <ScheduleModal
                    initial={editing}
                    onClose={() => { setModalOpen(false); setEditing(null); }}
                    onSave={handleSave}
                />
            )}

            {/* AI 4: Insight modal — satır başına AI özeti */}
            {insightModal && (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setInsightModal(null)}>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-lg shadow-2xl" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-between p-5 border-b border-slate-200 dark:border-slate-800">
                            <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                <Sparkles className="w-5 h-5 text-purple-400" />
                                AI Özet — <span className="font-mono text-sm">{insightModal.schedule.target}</span>
                            </h3>
                            <button onClick={() => setInsightModal(null)} className="text-slate-400 hover:text-slate-900 dark:hover:text-white">
                                <X className="w-5 h-5" />
                            </button>
                        </div>
                        <div className="p-5">
                            {insightModal.loading ? (
                                <div className="flex items-center gap-2 text-slate-500">
                                    <Loader2 className="w-4 h-4 animate-spin" /> AI özetleniyor...
                                </div>
                            ) : (
                                <p className="text-slate-700 dark:text-slate-300 text-sm leading-relaxed">{insightModal.text}</p>
                            )}
                        </div>
                        {insightModal.schedule.last_scan?.session_id && (
                            <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex justify-end">
                                <button
                                    onClick={() => navigate(`/auto-scan?session=${insightModal.schedule.last_scan?.session_id}`)}
                                    className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors"
                                >
                                    Taramayı Aç →
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Tier 3: Diff modal — son iki tarama farkı + LLM özeti */}
            {diffModal && (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setDiffModal(null)}>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-2xl w-full max-w-2xl shadow-2xl" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-between p-5 border-b border-slate-200 dark:border-slate-800">
                            <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                <GitCompareArrows className="w-5 h-5 text-cyan-400" />
                                Tarama Farkı — <span className="font-mono text-sm">{diffModal.schedule.target}</span>
                            </h3>
                            <button onClick={() => setDiffModal(null)} className="text-slate-400 hover:text-slate-900 dark:hover:text-white">
                                <X className="w-5 h-5" />
                            </button>
                        </div>
                        <div className="p-5 space-y-4">
                            {diffModal.loading ? (
                                <div className="flex items-center gap-2 text-slate-500">
                                    <Loader2 className="w-4 h-4 animate-spin" /> Karşılaştırma hazırlanıyor...
                                </div>
                            ) : diffModal.data?.error ? (
                                <div className="text-red-400 text-sm">{diffModal.data.error}</div>
                            ) : !diffModal.data?.available ? (
                                <div className="text-slate-500 text-sm">
                                    {diffModal.data?.reason || 'Diff hesaplanamadı'}
                                    <div className="text-xs mt-1 opacity-60">Şu an {diffModal.data?.current_count || 0} tamamlanmış tarama var. En az 2 gerekli.</div>
                                </div>
                            ) : (
                                <>
                                    <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50">
                                        <div className="flex items-center gap-2 text-xs text-slate-500 mb-1">
                                            {diffModal.data.summary_source === 'llm' ? <Sparkles className="w-3 h-3 text-purple-400" /> : null}
                                            <span>{diffModal.data.summary_source === 'llm' ? 'AI Özet' : 'Kural Özet'}</span>
                                        </div>
                                        <p className="text-slate-900 dark:text-white text-sm leading-relaxed">{diffModal.data.summary}</p>
                                    </div>
                                    <div className="grid grid-cols-2 gap-3">
                                        <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                                            <div className="text-2xl font-bold text-emerald-400">{diffModal.data.new_count}</div>
                                            <div className="text-xs text-slate-500">Yeni Bulgu</div>
                                        </div>
                                        <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                                            <div className="text-2xl font-bold text-amber-400">{diffModal.data.resolved_count}</div>
                                            <div className="text-xs text-slate-500">Çözüldü</div>
                                        </div>
                                    </div>
                                    {diffModal.data.new_count > 0 && (
                                        <div>
                                            <div className="text-xs font-bold text-slate-500 uppercase mb-1">Yeni Bulgular</div>
                                            <div className="space-y-1 max-h-40 overflow-y-auto">
                                                {diffModal.data.new_findings.slice(0, 10).map((f: string, i: number) => (
                                                    <div key={i} className="text-xs font-mono text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800/50 px-2 py-1 rounded">
                                                        {f}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
