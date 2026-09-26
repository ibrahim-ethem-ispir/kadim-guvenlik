import React from 'react';
import { Target, Database, Globe, FileJson, Swords, ScrollText, ShieldAlert } from 'lucide-react';
import type { TargetProfileData } from '../../hooks/usePipelineStream';

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

interface TargetProfileHeaderProps {
  profile: TargetProfileData | null;
}

export function TargetProfileHeader({ profile }: TargetProfileHeaderProps) {
  if (!profile) return null;
  const facts = profile.facts || {};
  const rows = _PROFILE_DIMS.filter(d => facts[d.key]?.value);

  return (
    <div className="rounded-xl border border-indigo-400/30 bg-indigo-500/5 dark:bg-indigo-500/10 p-4 mb-3 transition-all shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Target className="w-4 h-4 text-indigo-500 animate-pulse" />
          <span className="text-xs font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-300">
            Hedef Profili — Önce Düşmanı Tanı (IPB)
          </span>
        </div>
        {profile.kind && (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono uppercase bg-indigo-500/15 text-indigo-600 dark:text-indigo-300 border border-indigo-500/20">
            {profile.kind}
          </span>
        )}
      </div>

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
        <div className="text-xs text-slate-500 py-1">
          {profile.kind === 'host'
            ? 'Çıplak sunucu/host — web uygulaması sinyali yok. Host/ağ yüzeyine odaklanılıyor.'
            : profile.kind === 'appliance'
              ? 'Güvenlik cihazı/firewall arkasında — dış web yüzeyi filtreli.'
              : 'Yeterli parmak-izi sinyali yok — genel tarama yürütülüyor.'}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-2">
          {rows.map(d => {
            const f = facts[d.key]!;
            const pct = Math.round((f.confidence || 0) * 100);
            const Icon = d.icon;
            const ev = (f.evidence || []).filter(Boolean);
            return (
              <div key={d.key} className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/70 dark:bg-slate-900/60 px-3 py-2 shadow-xs">
                <div className="flex items-center gap-1.5 text-[10px] uppercase font-medium tracking-wider text-slate-400">
                  <Icon className="w-3 h-3 text-slate-500 dark:text-slate-400" />
                  {d.label}
                </div>
                <div className="text-sm font-bold text-slate-800 dark:text-slate-100 truncate mt-0.5" title={f.value}>
                  {f.value}
                </div>
                <div className="h-1 mt-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                  <div className="h-full bg-indigo-500 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                </div>
                <div className="text-[9px] text-slate-400 mt-1 truncate" title={ev.join('  •  ')}>
                  %{pct} güven{ev.length > 0 ? ` — ${ev.slice(0, 2).join(', ')}` : ''}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {profile.products && profile.products.length > 0 && (
        <div className="mt-2 pt-2 border-t border-indigo-400/20">
          <div className="text-[10px] uppercase font-semibold tracking-wider text-slate-400 mb-1">
            Tespit Edilen Ürünler (CPE)
          </div>
          <div className="flex flex-wrap gap-1">
            {profile.products.slice(0, 16).map((p, i) => (
              <span key={i} className="text-[10px] px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/40 text-slate-600 dark:text-slate-300 font-mono">
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {profile.infra_probe?.attempted && !facts['infra']?.value
        && profile.infra_probe.k8s_ports_open.length > 0 && (
        <div className="mt-2 text-[11px] text-amber-600 dark:text-amber-400 flex items-start gap-1.5 bg-amber-500/10 px-2.5 py-1.5 rounded-lg border border-amber-500/20">
          <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span>K8s kontrol-düzlemi portları açık: {profile.infra_probe.k8s_ports_open.join(', ')}</span>
        </div>
      )}

      {profile.playbook_decisions && (
        <div className="mt-2.5 pt-2 border-t border-indigo-400/20">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-400">Taktik Saldırı Planı</span>
            <div className="flex items-center gap-2 text-[10px]">
              <span className="inline-flex items-center gap-1 text-emerald-500 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> hedefli
              </span>
              <span className="inline-flex items-center gap-1 text-amber-500 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500" /> genel
              </span>
              <span className="inline-flex items-center gap-1 text-slate-400">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400" /> atlandı
              </span>
            </div>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(profile.playbook_decisions).map(([name, d]) => {
              const detected = d.run && d.priority === 'high';
              const generic = d.run && !detected;
              const cls = detected
                ? 'border-emerald-400/50 bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 font-medium'
                : generic
                  ? 'border-amber-400/50 bg-amber-500/10 text-amber-700 dark:text-amber-300 border-dashed'
                  : 'border-slate-200 dark:border-slate-800 bg-slate-100/50 dark:bg-slate-800/40 text-slate-400 line-through opacity-60';
              return (
                <span
                  key={name}
                  title={`${name}: ${d.reason || ''} (öncelik: ${d.priority})`}
                  className={`text-[10px] px-2 py-0.5 rounded-md border ${cls} transition-all`}
                >
                  {_moduleLabel(name)}
                </span>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
export default TargetProfileHeader;
