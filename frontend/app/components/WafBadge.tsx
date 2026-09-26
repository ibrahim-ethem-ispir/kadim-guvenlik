// Türkçe: WAF rozet bileşeni — otonom taramada tespit edilen güvenlik duvarını gösterir.
// Veri iki kaynaktan gelir (auto-scan.tsx çözer): canlı olay akışındaki `waf` alanı
// (waf_detect anlık tespiti) veya session.ai_analysis.waf (kalıcı — refresh dayanıklı).
// Rozet üzerine gelince imza kanıtları (hangi cookie/header/gövde izi yakaladı) görünür.

export interface WafInfo {
  vendor: string;
  confidence: number;
  evidence?: string[];
  blocked_probe?: boolean;
}

const VENDOR_LABEL: Record<string, string> = {
  fortiweb: 'FortiWeb',
  fortiguard: 'FortiGate / FortiGuard',
  cloudflare: 'Cloudflare',
  modsecurity: 'ModSecurity',
  akamai: 'Akamai',
  imperva: 'Imperva (Incapsula)',
  f5_asm: 'F5 BIG-IP ASM',
  aws_waf: 'AWS WAF',
  sucuri: 'Sucuri',
  unknown: 'Bilinmeyen WAF',
};

export default function WafBadge({ waf }: { waf: WafInfo | null }) {
  if (!waf || !waf.vendor) return null;
  const label = VENDOR_LABEL[waf.vendor] || waf.vendor;
  const pct = Math.round((waf.confidence || 0) * 100);
  const tooltip = [
    `Guven: %${pct}`,
    waf.blocked_probe ? 'Aktif tetik bloklandi (WAF devrede)' : 'Pasif imza tespiti',
    ...(waf.evidence || []).map(e => `• ${e}`),
    'Vendor-profilli payload mutasyonu devrede',
  ].join('\n');

  return (
    <span
      title={tooltip}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold
                 border border-sky-500/40 bg-sky-500/10 text-sky-500 cursor-help align-middle"
    >
      <span aria-hidden>🛡️</span>
      WAF: {label}
      <span className="text-sky-500/70 font-normal">%{pct}</span>
      {waf.blocked_probe && (
        <span className="text-amber-500 font-normal" title="Aktif tetik bloklandi">· aktif</span>
      )}
    </span>
  );
}
