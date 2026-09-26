import { Layers, ExternalLink, ShieldCheck, Server, Cloud } from 'lucide-react';

// Parmak izi (wappalyzergo) + TLS/IP istihbaratı çıktısı — hem auto-scan rozet-modalı hem
// manuel tarama hızlı-tespit kartı AYNI bileşeni kullanır (tek kaynak, kod tekrarı yok).
export interface FingerprintTech {
  name: string;
  version?: string;
  categories?: string[];
  cpe?: string;
  website?: string;
}

export interface ServerIntel {
  host?: string;
  main_ip?: string | null;
  ips?: string[];
  reverse_dns?: Record<string, string>;
  san_domains?: string[];
  cert?: {
    issuer?: string | null;
    subject_cn?: string | null;
    not_before?: string | null;
    not_after?: string | null;
    verified?: boolean;
  } | null;
  behind_cdn?: boolean | null;
  cdn?: string | null;
}

export interface FingerprintData {
  engine?: string;
  count?: number;
  title?: string;
  source?: string; // "fetch" | "html"
  final_url?: string;
  technologies?: FingerprintTech[];
  server_intel?: ServerIntel | null;
}

function groupByCategory(techs: FingerprintTech[]): Record<string, FingerprintTech[]> {
  const groups: Record<string, FingerprintTech[]> = {};
  for (const t of techs) {
    const cat = (t.categories && t.categories[0]) || 'Diğer';
    (groups[cat] ||= []).push(t);
  }
  return groups;
}

function ServerIntelBlock({ si }: { si: ServerIntel }) {
  const ips = si.ips || [];
  return (
    <div className="mb-4 rounded-lg border border-slate-700/50 bg-slate-800/40 p-3">
      <h4 className="font-semibold text-slate-200 mb-2 flex items-center gap-1.5 text-xs">
        <Server className="w-3.5 h-3.5 text-sky-400" />
        Sunucu / Sertifika İstihbaratı
      </h4>

      {si.main_ip && (
        <div className="flex items-center gap-2 flex-wrap mb-2 text-xs">
          <span className="text-slate-400">Ana Sunucu IP:</span>
          <span className="font-mono font-bold text-sky-300">{si.main_ip}</span>
          {si.behind_cdn && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-orange-500/15 text-orange-400 font-semibold">
              <Cloud className="w-3 h-3" />
              {si.cdn || 'CDN'} arkasında — gerçek origin gizli olabilir
            </span>
          )}
        </div>
      )}

      {ips.length > 0 && (
        <div className="mb-2">
          <span className="text-slate-400 text-[11px]">Sunucu Grubu ({ips.length} IP):</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {ips.map((ip) => (
              <span
                key={ip}
                title={si.reverse_dns?.[ip] || ''}
                className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-[10px] text-slate-300"
              >
                {ip}
                {si.reverse_dns?.[ip] ? ` · ${si.reverse_dns[ip]}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}

      {si.cert && (si.cert.issuer || si.cert.not_after) && (
        <div className="mb-2 text-[11px] text-slate-400 flex items-center gap-1.5 flex-wrap">
          <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />
          <span>Sertifika:</span>
          {si.cert.issuer && <span className="text-slate-300">{si.cert.issuer}</span>}
          {si.cert.not_after && <span>· geçerlilik: {si.cert.not_after}</span>}
          {si.cert.verified === false && <span className="text-amber-400">· doğrulanamadı</span>}
        </div>
      )}

      {si.san_domains && si.san_domains.length > 0 && (
        <div>
          <span className="text-slate-400 text-[11px]">Sertifika SAN domainleri (ek yüzey):</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {si.san_domains.map((d) => (
              <span
                key={d}
                className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-[10px] text-indigo-300"
              >
                {d}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface Props {
  fingerprint?: FingerprintData | null;
  maxHeightClass?: string;
  showFooterNote?: boolean;
}

export default function FingerprintPanel({
  fingerprint,
  maxHeightClass = 'max-h-[26rem]',
  showFooterNote = true,
}: Props) {
  const techs = fingerprint?.technologies || [];
  const si = fingerprint?.server_intel || null;
  const hasTech = techs.length > 0;
  const hasSI = !!si && !!(si.main_ip || (si.ips && si.ips.length) || (si.san_domains && si.san_domains.length) || si.cert);

  if (!fingerprint || (!hasTech && !hasSI)) {
    return (
      <div className="p-4 rounded-lg bg-slate-800/40 border border-slate-700/50 text-center text-slate-400 text-sm">
        Teknoloji ya da sunucu bilgisi tespit edilemedi (hedef ulaşılamadı veya imza eşleşmedi).
      </div>
    );
  }

  const count = fingerprint.count || techs.length;
  const groups = groupByCategory(techs);
  const withVersion = techs.filter((t) => t.version).length;

  return (
    <div>
      {hasSI && si && <ServerIntelBlock si={si} />}

      {hasTech && (
        <>
          <div className="grid grid-cols-3 gap-3 mb-4 text-xs">
            <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
              <span className="text-slate-400 block mb-1">Tanımlanan</span>
              <span className="font-bold text-indigo-400">{count} teknoloji</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
              <span className="text-slate-400 block mb-1">Sürüm Çıkarılan</span>
              <span className="font-bold text-slate-200">{withVersion} adet</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/50">
              <span className="text-slate-400 block mb-1">Motor / Kaynak</span>
              <span className="font-mono font-semibold text-slate-300">
                {fingerprint.engine || 'wappalyzergo'}
                {fingerprint.source ? ` · ${fingerprint.source === 'html' ? 'render-DOM' : 'HTTP'}` : ''}
              </span>
            </div>
          </div>

          <div className={`space-y-4 ${maxHeightClass} overflow-y-auto pr-1`}>
            {Object.entries(groups).map(([cat, list]) => (
              <div key={cat}>
                <h4 className="font-semibold text-slate-300 mb-2 flex items-center gap-1.5 text-xs">
                  <Layers className="w-3.5 h-3.5 text-slate-500" />
                  {cat}
                  <span className="ml-auto px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-400 font-mono">
                    {list.length}
                  </span>
                </h4>
                <div className="space-y-1.5">
                  {list.map((t, idx) => (
                    <div
                      key={`${t.name}-${idx}`}
                      className="p-2.5 rounded-lg border border-slate-700/50 bg-slate-800/40 flex flex-col gap-1"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-100">{t.name}</span>
                        {t.version && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/15 text-emerald-400 font-mono font-bold">
                            v{t.version}
                          </span>
                        )}
                        {t.website && (
                          <a
                            href={t.website}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-slate-500 hover:text-indigo-400 transition-colors"
                            title={t.website}
                          >
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                      {t.cpe && (
                        <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                          <ShieldCheck className="w-3 h-3 text-amber-400 shrink-0" />
                          <span className="font-mono truncate" title={t.cpe}>
                            {t.cpe}
                          </span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {showFooterNote && hasTech && (
        <p className="text-[10px] text-slate-500 mt-4 border-t border-slate-800 pt-3">
          CPE eşleşmeleri KEV/CVE istihbaratını besler — bu kimlik hem motor kararına hem ekrana tek kaynaktan gider.
        </p>
      )}
    </div>
  );
}
