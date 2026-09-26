// Kanıt güven kademesi rozeti — severity'den BAĞIMSIZ ortak bileşen (FAQ 4.1).
// confirmed = bağımsız teyit; probable = güçlü sinyal (aktif teyit yok); unconfirmed =
// araç iddia etti (olası FP).
// TEK KAYNAK: eski AutonomousTimeline.TIER_BADGE ile vulnerabilities.TIER_STYLE ikiz
// kopyaları buraya göçtü — etiket/renk tutarsızlığı biter, tüketici Türkçe etiketi
// (laciverdi korku/rahat) ayrı yazamaz.

export type Tier = 'confirmed' | 'probable' | 'unconfirmed';

export const TIER_LABEL: Record<Tier, { label: string; cls: string }> = {
  confirmed: { label: '✅ Kanıtlı', cls: 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30' },
  probable: { label: '◐ Olası', cls: 'bg-sky-500/15 text-sky-600 dark:text-sky-400 border-sky-500/30' },
  unconfirmed: { label: '⚠️ Doğrulanmadı', cls: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30' },
};

interface TierBadgeProps {
  tier?: string | null;
  /** Varsa "%NN" ekini gösterir (verification_confidence). */
  confidence?: number | null;
  title?: string;
  /** Rozete border ekler (liste/tablo görünümü). */
  bordered?: boolean;
  className?: string;
}

export default function TierBadge({
  tier,
  confidence,
  title,
  bordered = false,
  className = '',
}: TierBadgeProps) {
  const key = (tier || 'unconfirmed').toLowerCase();
  const t = TIER_LABEL[key as Tier] || TIER_LABEL.unconfirmed;
  return (
    <span
      title={title}
      className={`inline-flex items-center rounded-full text-[10px] font-semibold ${bordered ? 'border' : ''} ${t.cls} ${className}`}
    >
      {t.label}
      {typeof confidence === 'number' && confidence > 0 ? ` · %${Math.round(confidence * 100)}` : ''}
    </span>
  );
}