// Türkçe: Recon Intelligence (Varlık Keşfi) modülü ana sayfası
// Asset Guard / Recon Master - Gelişmiş varlık keşfi ve teknoloji istihbaratı

import { useState, useEffect, useMemo } from "react";
import { Link } from "react-router";
import { api } from "../services/api";
import Tooltip from "../components/Tooltip";
import ScanHistory from "../components/ScanHistory";
import GlobalStatsChart from "../components/GlobalStatsChart";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  Tooltip as ReTooltip,
  PieChart,
  Pie,
  Cell,
} from "recharts";

interface Technology {
  name: string;
  version?: string;
  category: string;
  confidence: number;
}

interface Infrastructure {
  provider?: string;
  is_cloud: boolean;
  is_private_ip: boolean;
  is_waf_protected: boolean;
}

interface SubdomainAsset {
  subdomain: string;
  ip?: string;
  is_cf: boolean;
  is_live: boolean;
  status_code?: number;
  response_time_ms?: number;
  infrastructure: Infrastructure;
  technologies: Technology[];
  page_title?: string;
}

interface ScanSummary {
  total_subdomains_found: number;
  total_live_assets: number;
  total_technologies: number;
  cloud_hosted_count: number;
  direct_ip_count: number;
  top_technologies?: TechCount[];
}

interface TechCount {
  name: string;
  count: number;
  percentage: number;
}

interface ScanStatus {
  id: string;
  state: "Pending" | "Running" | "Completed" | "Failed" | "Cancelled";
  progress: number;
  current_step: string;
  total_subdomains: number;
  scanned_subdomains: number;
  logs: string[];
  result?: {
    domain: string;
    subdomains: { found: SubdomainAsset[] };
    summary: ScanSummary;
  };
}

interface Wordlist {
  path: string;
  description: string;
  size_bytes: number;
}

export default function ReconIntelligence() {
  const [domain, setDomain] = useState("");
  const [selectedWordlist, setSelectedWordlist] = useState(
    "files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt"
  );
  const [wordlists, setWordlists] = useState<Wordlist[]>([]);
  const [concurrency, setConcurrency] = useState(50);
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [filter, setFilter] = useState<"all" | "live" | "direct" | "cloud">("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<SubdomainAsset | null>(null);
  const [activeTab, setActiveTab] = useState<"scan" | "history" | "stats">("scan");

  // Türkçe: Wordlist listesini yükle
  useEffect(() => {
    api.get<any>("/api/recon/wordlists")
      .then((data) => setWordlists(data.wordlists || []))
      .catch((err) => console.error("Wordlist yükleme hatası:", err));
  }, []);

  // Türkçe: Tarama durumunu poll et (her 2 saniyede bir)
  useEffect(() => {
    if (!scanId || scanStatus?.state === "Completed" || scanStatus?.state === "Failed" || scanStatus?.state === "Cancelled") {
      return;
    }

    const interval = setInterval(() => {
      api.get<ScanStatus>(`/api/recon/analyze/${scanId}`)
        .then((data) => {
          if (data) {
            setScanStatus(data);
            if (data.state === "Completed" || data.state === "Failed" || data.state === "Cancelled") {
              setIsScanning(false);
            }
          }
        })
        .catch((err) => console.error("Status kontrol hatası:", err));
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, scanStatus?.state]);

  const handleStartScan = async () => {
    if (!domain.trim()) {
      alert("Lütfen hedef domain girin");
      return;
    }

    setIsScanning(true);
    setScanStatus(null);

    try {
      const data = await api.post<any>("/api/recon/analyze", {
        domain: domain.trim(),
        wordlist: selectedWordlist,
        concurrency,
        delay_ms: 0,
        timeout_minutes: 30,
      });

      setScanId(data.scan_id);
    } catch (error) {
      console.error("Tarama başlatma hatası:", error);
      setIsScanning(false);
      alert("Tarama başlatılamadı");
    }
  };

  const handleCancelScan = async () => {
    if (!scanId) return;

    try {
      await api.post(`/api/recon/analyze/${scanId}/cancel`, {});
      setIsScanning(false);
    } catch (error) {
      console.error("İptal hatası:", error);
    }
  };

  // Türkçe: Geçmişten taramayı yükle
  const handleLoadHistoryScan = async (histScanId: string) => {
    try {
      const data = await api.get<any>(`/api/recon/history/${histScanId}`);
      if (!data.error) {
        // MongoDB'den gelen veriyi ScanStatus formatına dönüştür
        const convertedStatus: ScanStatus = {
          id: data.scan_id,
          state: "Completed",
          progress: 100,
          current_step: "Completed",
          total_subdomains: data.summary.total_subdomains_found,
          scanned_subdomains: data.summary.total_subdomains_found,
          logs: [`Tarama ${new Date(data.timestamp).toLocaleString()} tarihinde tamamlandı`],
          result: {
            domain: data.target_domain,
            subdomains: {
              found: data.assets.map((asset: any) => ({
                subdomain: asset.subdomain,
                ip: asset.ip_address,
                is_cf: asset.infrastructure.is_cloud,
                is_live: asset.is_live,
                status_code: asset.status_code,
                response_time_ms: asset.response_time_ms,
                infrastructure: asset.infrastructure,
                technologies: asset.technologies,
                page_title: asset.page_title,
              })),
            },
            summary: data.summary,
          },
        };
        setScanStatus(convertedStatus);
        setScanId(histScanId);
        setActiveTab("scan");
      }
    } catch (error) {
      console.error("Geçmiş tarama yükleme hatası:", error);
    }
  };

  // Türkçe: Sonuçları filtrele
  const filteredAssets = () => {
    if (!scanStatus?.result?.subdomains?.found) return [];

    let assets = scanStatus.result.subdomains.found;

    // Filtre uygula
    if (filter === "live") {
      assets = assets.filter((a) => a.is_live);
    } else if (filter === "direct") {
      assets = assets.filter((a) => !a.is_cf && a.ip);
    } else if (filter === "cloud") {
      assets = assets.filter((a) => a.is_cf);
    }

    // Arama terimi
    if (searchTerm) {
      assets = assets.filter((a) =>
        a.subdomain.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    return assets;
  };

  const assets = filteredAssets();
  const topTechnologies: TechCount[] = scanStatus?.result?.summary.top_technologies || [];

  const categoryBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    assets.forEach((asset) => {
      asset.technologies.forEach((tech) => {
        const key = tech.category || "Other";
        counts[key] = (counts[key] || 0) + 1;
      });
    });
    return Object.entries(counts).map(([category, count]) => ({ category, count }));
  }, [assets]);

  const uniqueTechCount = useMemo(() => {
    const names = assets.flatMap((asset) => asset.technologies.map((t) => t.name));
    return new Set(names).size;
  }, [assets]);

  const pieData = useMemo(() => {
    if (topTechnologies.length > 0) {
      return topTechnologies.slice(0, 6).map((t) => ({ name: t.name, value: t.count }));
    }
    return categoryBreakdown.map((item) => ({ name: item.category, value: item.count }));
  }, [topTechnologies, categoryBreakdown]);

  // Pro Palette: Emerald, Sky, Violet, Rose, Amber, Slate, Indigo
  const chartColors = ["#10b981", "#0ea5e9", "#8b5cf6", "#f43f5e", "#f59e0b", "#64748b", "#6366f1"];

  // Export fonksiyonları
  const exportJSON = () => {
    const data = {
      domain: scanStatus?.result?.domain,
      scan_date: new Date().toISOString(),
      summary: scanStatus?.result?.summary,
      assets: assets
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon-${scanStatus?.result?.domain}-${Date.now()}.json`;
    a.click();
  };

  const exportCSV = () => {
    const headers = ['Subdomain', 'IP', 'Status', 'Response Time (ms)', 'Technologies', 'Infrastructure'];
    const rows = assets.map(a => [
      a.subdomain,
      a.ip || '-',
      a.is_live ? a.status_code : 'Offline',
      a.response_time_ms || '-',
      a.technologies.map(t => `${t.name} ${t.version || ''}`).join('; '),
      a.infrastructure.provider || 'Direct'
    ]);
    const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon-${scanStatus?.result?.domain}-${Date.now()}.csv`;
    a.click();
  };

  const exportMarkdown = () => {
    const md = `# Recon Intelligence Report\n\n**Domain**: ${scanStatus?.result?.domain}\n**Date**: ${new Date().toISOString()}\n\n## Summary\n\n- Total Subdomains: ${scanStatus?.result?.summary.total_subdomains_found}\n- Live Assets: ${scanStatus?.result?.summary.total_live_assets}\n- Cloud Hosted: ${scanStatus?.result?.summary.cloud_hosted_count}\n- Direct IP: ${scanStatus?.result?.summary.direct_ip_count}\n\n## Assets\n\n${assets.map(a => `### ${a.subdomain}\n- IP: ${a.ip || 'N/A'}\n- Status: ${a.is_live ? a.status_code : 'Offline'}\n- Technologies: ${a.technologies.map(t => t.name).join(', ') || 'None'}\n`).join('\n')}`;
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recon-${scanStatus?.result?.domain}-${Date.now()}.md`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 p-4 transition-colors duration-300">
      <div className="mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-3">
            <span className="text-cyan-600 dark:text-cyan-400">🔍</span> Recon Intelligence
          </h1>
          <p className="text-slate-600 dark:text-slate-400 text-lg">
            Gelişmiş Varlık Keşfi & Teknoloji İstihbaratı Modülü
          </p>
          <Link
            to="/"
            className="text-cyan-600 hover:text-cyan-700 dark:text-cyan-400 dark:hover:text-cyan-300 transition-colors mt-2 inline-block"
          >
            ← Ana Sayfaya Dön
          </Link>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 mb-6 border-b border-slate-200 dark:border-slate-700">
          <button
            onClick={() => setActiveTab("scan")}
            className={`px-6 py-3 font-medium transition-colors border-b-2 ${activeTab === "scan"
              ? "text-cyan-600 dark:text-cyan-400 border-cyan-600 dark:border-cyan-400"
              : "text-slate-500 dark:text-slate-400 border-transparent hover:text-slate-700 dark:hover:text-slate-300"
              }`}
          >
            🚀 Yeni Tarama
          </button>
          <button
            onClick={() => setActiveTab("history")}
            className={`px-6 py-3 font-medium transition-colors border-b-2 ${activeTab === "history"
              ? "text-cyan-600 dark:text-cyan-400 border-cyan-600 dark:border-cyan-400"
              : "text-slate-500 dark:text-slate-400 border-transparent hover:text-slate-700 dark:hover:text-slate-300"
              }`}
          >
            📜 Tarama Geçmişi
          </button>
          <button
            onClick={() => setActiveTab("stats")}
            className={`px-6 py-3 font-medium transition-colors border-b-2 ${activeTab === "stats"
              ? "text-cyan-600 dark:text-cyan-400 border-cyan-600 dark:border-cyan-400"
              : "text-slate-500 dark:text-slate-400 border-transparent hover:text-slate-700 dark:hover:text-slate-300"
              }`}
          >
            📊 İstatistikler
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === "history" && (
          <ScanHistory onLoadScan={handleLoadHistoryScan} />
        )}

        {activeTab === "stats" && <GlobalStatsChart />}

        {activeTab === "scan" && (
          <>
            {/* Bilgi Kutusu - Daraltılabilir */}
            <details className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-500/30 rounded-lg p-4 mb-4">
              <summary className="cursor-pointer text-blue-700 dark:text-blue-300 font-semibold flex items-center gap-2">
                <span>💡</span> Bu Modül Ne İşe Yarar?
              </summary>
              <ul className="text-slate-600 dark:text-slate-300 text-sm space-y-1 ml-6 list-disc mt-3">
                <li><strong>Subdomain Enumeration</strong>: DNS brute-force ile tüm subdomain'leri bulur (api, admin, staging, test, vb.)</li>
                <li><strong>Live Asset Detection</strong>: HTTP/HTTPS erişilebilirlik kontrolü (200, 403, 404 status code'ları)</li>
                <li><strong>Technology Fingerprinting</strong>: 50+ teknoloji otomatik tespit (WordPress, React, Nginx, PHP, Node.js)</li>
                <li><strong>Cloudflare Detection</strong>: CDN/WAF koruması analizi (IP range + header check)</li>
                <li><strong>Origin IP Discovery</strong>: Cloudflare bypass için direkt IP tespiti (saldırı yüzeyi analizi)</li>
                <li><strong>Infrastructure Mapping</strong>: Cloud provider tespiti (AWS, Azure, GCP, Cloudflare)</li>
              </ul>
            </details>

            {/* Wordlist Seçim Rehberi - Daraltılabilir */}
            <details className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-500/30 rounded-lg p-4 mb-4">
              <summary className="cursor-pointer text-purple-700 dark:text-purple-300 font-semibold flex items-center gap-2">
                <span>📚</span> Wordlist Seçim Rehberi
              </summary>
              <div className="grid md:grid-cols-2 gap-3 text-sm text-slate-600 dark:text-slate-300 mt-3">
                <div className="bg-white dark:bg-slate-800/50 rounded p-3 border border-slate-100 dark:border-transparent">
                  <div className="font-medium text-cyan-600 dark:text-cyan-400 mb-1">⚡ Quick Scan (5K)</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">Süre: 2-5 dakika | Yaygın subdomain'ler (api, www, mail, admin)</div>
                </div>
                <div className="bg-white dark:bg-slate-800/50 rounded p-3 border border-slate-100 dark:border-transparent">
                  <div className="font-medium text-green-600 dark:text-green-400 mb-1">🚀 Fast Scan (20K)</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">Süre: 5-15 dakika | Dengeli hız/kapsam, çoğu subdomain'i bulur</div>
                </div>
                <div className="bg-white dark:bg-slate-800/50 rounded p-3 border border-slate-100 dark:border-transparent">
                  <div className="font-medium text-orange-600 dark:text-orange-400 mb-1">🔥 Deep Scan (110K)</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">Süre: 15-45 dakika | Shadow IT tespiti için ideal</div>
                </div>
                <div className="bg-white dark:bg-slate-800/50 rounded p-3 border border-slate-100 dark:border-transparent">
                  <div className="font-medium text-red-600 dark:text-red-400 mb-1">💎 Comprehensive (26M)</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">Süre: 1-3 saat | Bug bounty için, tüm bilinen pattern'ler</div>
                </div>
              </div>
            </details>

            {/* Tarama Başlatma Formu */}
            <div className="bg-white dark:bg-slate-800/50 backdrop-blur-sm rounded-xl p-5 mb-4 border border-slate-200 dark:border-slate-700 shadow-sm dark:shadow-none">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Yeni Tarama Başlat</h2>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <Tooltip content="Taranacak hedef domain (örn: example.com). Alt domain eklemeyin, sadece ana domain girin.">
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Hedef Domain 💡
                    </label>
                  </Tooltip>
                  <input
                    type="text"
                    placeholder="example.com"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    disabled={isScanning}
                    className="w-full px-4 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 transition-colors"
                  />
                </div>

                <div>
                  <Tooltip content="Wordlist boyutu tarama süresini etkiler. Quick (5K) hızlı keşif, Deep (110K) kapsamlı tarama için idealdir.">
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Wordlist Profili 💡
                    </label>
                  </Tooltip>
                  <select
                    value={selectedWordlist}
                    onChange={(e) => setSelectedWordlist(e.target.value)}
                    disabled={isScanning}
                    className="w-full px-4 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 transition-colors"
                  >
                    {wordlists.map((wl) => (
                      <option key={wl.path} value={wl.path}>
                        {wl.description}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <Tooltip content="Eşzamanlı istek sayısı. Yüksek değerler (150+) hızlı ama rate limit riski vardır. Stealth mod için 10-30 kullanın.">
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Eşzamanlılık (Thread) 💡
                    </label>
                  </Tooltip>
                  <input
                    type="number"
                    value={concurrency}
                    onChange={(e) => setConcurrency(Number(e.target.value))}
                    disabled={isScanning}
                    min={10}
                    max={200}
                    className="w-full px-4 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 transition-colors"
                  />
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    Önerilen: 50-100 (dengeli) | Stealth: 10-30 | Hızlı: 150-200
                  </div>
                </div>
              </div>

              <div className="mt-4 flex gap-3">
                {!isScanning ? (
                  <button
                    onClick={handleStartScan}
                    className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white font-semibold rounded-lg transition-all transform hover:scale-105"
                  >
                    🚀 Taramayı Başlat
                  </button>
                ) : (
                  <button
                    onClick={handleCancelScan}
                    className="px-6 py-2 bg-red-500 hover:bg-red-600 text-white font-semibold rounded-lg transition-colors"
                  >
                    ⛔ Taramayı Durdur
                  </button>
                )}
              </div>
            </div>

            {/* Tarama Durumu */}
            {scanStatus && (
              <div className="bg-white dark:bg-slate-800/50 backdrop-blur-sm rounded-xl p-5 mb-4 border border-slate-200 dark:border-slate-700 shadow-sm dark:shadow-none">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-semibold text-slate-900 dark:text-white">Tarama Durumu</h2>
                  <span
                    className={`px-3 py-1 rounded-full text-sm font-medium ${scanStatus.state === "Completed"
                      ? "bg-green-500/20 text-green-300"
                      : scanStatus.state === "Failed" || scanStatus.state === "Cancelled"
                        ? "bg-red-500/20 text-red-300"
                        : "bg-yellow-500/20 text-yellow-300"
                      }`}
                  >
                    {scanStatus.state}
                  </span>
                </div>

                <div className="mb-4">
                  <div className="flex justify-between text-sm text-slate-500 dark:text-slate-400 mb-2">
                    <span>{scanStatus.current_step}</span>
                    <span>{Math.round(scanStatus.progress)}%</span>
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                      style={{ width: `${scanStatus.progress}%` }}
                    ></div>
                  </div>
                </div>

                {/* Özet İstatistikler */}
                {scanStatus.result?.summary && (
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
                    <div className="bg-slate-50 dark:bg-slate-900/50 rounded-lg p-3 text-center border border-slate-100 dark:border-transparent">
                      <div className="text-2xl font-bold text-cyan-400">
                        {scanStatus.result.summary.total_subdomains_found}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">Toplam Subdomain</div>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-900/50 rounded-lg p-3 text-center border border-slate-100 dark:border-transparent">
                      <div className="text-2xl font-bold text-green-400">
                        {scanStatus.result.summary.total_live_assets}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">Canlı Varlık</div>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-900/50 rounded-lg p-3 text-center border border-slate-100 dark:border-transparent">
                      <div className="text-2xl font-bold text-purple-400">
                        {scanStatus.result.summary.total_technologies}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">Teknoloji</div>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-900/50 rounded-lg p-3 text-center border border-slate-100 dark:border-transparent">
                      <div className="text-2xl font-bold text-orange-400">
                        {scanStatus.result.summary.cloud_hosted_count}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">Cloud/CDN</div>
                    </div>
                    <div className="bg-slate-50 dark:bg-slate-900/50 rounded-lg p-3 text-center border border-slate-100 dark:border-transparent">
                      <div className="text-2xl font-bold text-red-400">
                        {scanStatus.result.summary.direct_ip_count}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">Origin IP</div>
                    </div>
                  </div>
                )}

                {/* Teknoloji Analizi Kartları */}
                {scanStatus.result && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    <div className="bg-slate-50 dark:bg-slate-900/50 rounded-lg p-4 border border-slate-200 dark:border-slate-700">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <div className="text-sm text-slate-500 dark:text-slate-400">Teknoloji Envanteri</div>
                          <div className="text-3xl font-bold text-slate-900 dark:text-white">{uniqueTechCount}</div>
                          <div className="text-xs text-slate-500 dark:text-slate-400">Benzersiz teknoloji tespit edildi</div>
                        </div>
                        <Tooltip content="Teknoloji çeşitliliği, saldırı yüzeyinin genişliğini gösterir. Fazla çeşitlilik patch yönetimi ihtiyacını artırır.">
                          <span className="text-cyan-400 text-lg">ℹ️</span>
                        </Tooltip>
                      </div>
                      <div className="flex flex-wrap gap-2 mt-2">
                        {(topTechnologies.length > 0 ? topTechnologies.slice(0, 6) : [])
                          .map((tech, idx) => (
                            <span
                              key={tech.name}
                              className="px-2 py-1 rounded bg-purple-500/20 text-purple-200 text-xs"
                            >
                              {idx + 1}. {tech.name} ({tech.count})
                            </span>
                          ))}
                        {topTechnologies.length === 0 && (
                          <span className="text-slate-500 text-sm">Bu taramada teknoloji listesi boş</span>
                        )}
                      </div>
                    </div>

                    <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                      <div className="flex items-center justify-between mb-3">
                        <div className="text-sm text-slate-700 dark:text-slate-300 font-semibold">Kategori Dağılımı</div>
                        <Tooltip content="Backend, frontend ve WAF dağılımını görmek zafiyet önceliklendirmesinde yardımcı olur.">
                          <span className="text-cyan-400 text-lg">ℹ️</span>
                        </Tooltip>
                      </div>
                      <div className="h-48">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={categoryBreakdown} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                            <XAxis dataKey="category" tick={{ fill: "#94a3b8", fontSize: 12 }} interval={0} angle={-20} height={50} tickLine={false} axisLine={{ stroke: "#334155" }} />
                            <ReTooltip
                              contentStyle={{ background: "#e2e8f0", border: "none", borderRadius: "8px", color: "#0f172a", boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)" }}
                              itemStyle={{ color: "#0f172a", fontWeight: 600 }}
                              cursor={{ fill: "rgba(255,255,255,0.05)" }}
                            />
                            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                              {categoryBreakdown.map((_, idx) => (
                                <Cell key={`cell-${idx}`} fill={chartColors[idx % chartColors.length]} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                      <div className="flex items-center justify-between mb-3">
                        <div className="text-sm text-slate-700 dark:text-slate-300 font-semibold">Top Teknolojiler</div>
                        <Tooltip content="İlk 5 teknoloji ve oranları. Öncelikli zafiyet araştırması için kullanılabilir.">
                          <span className="text-cyan-400 text-lg">ℹ️</span>
                        </Tooltip>
                      </div>
                      <div className="h-48">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie dataKey="value" data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3}>
                              {pieData.map((_, idx) => (
                                <Cell key={`slice-${idx}`} fill={chartColors[idx % chartColors.length]} />
                              ))}
                            </Pie>
                            <ReTooltip
                              contentStyle={{ background: "#e2e8f0", border: "none", borderRadius: "8px", color: "#0f172a", boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)" }}
                              itemStyle={{ color: "#0f172a", fontWeight: 600 }}
                              formatter={(value: number, name: string) => [`${value}`, name]}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                      <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                        Pie dilimleri tarama sırasında en sık görülen teknoloji veya kategorileri gösterir.
                      </div>
                    </div>
                  </div>
                )}

                {/* Log Çıktısı */}
                <details className="mt-4">
                  <summary className="cursor-pointer text-cyan-400 font-medium">
                    Detaylı Logları Göster ({scanStatus.logs.length} satır)
                  </summary>
                  <div className="mt-2 bg-slate-100 dark:bg-slate-900 rounded-lg p-4 max-h-64 overflow-y-auto font-mono text-xs text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-transparent">
                    {scanStatus.logs.map((log, i) => (
                      <div key={i} className="mb-1">
                        {log}
                      </div>
                    ))}
                  </div>
                </details>
              </div>
            )}

            {/* Sonuç Tablosu */}
            {scanStatus?.result?.subdomains?.found && (
              <div className="bg-white dark:bg-slate-800/50 backdrop-blur-sm rounded-xl p-5 border border-slate-200 dark:border-slate-700 shadow-sm dark:shadow-none">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-semibold text-slate-900 dark:text-white">Bulunan Varlıklar</h2>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setFilter("all")}
                      className={`px-3 py-1 rounded-lg text-sm ${filter === "all" ? "bg-cyan-500 text-white" : "bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
                        }`}
                    >
                      Tümü
                    </button>
                    <button
                      onClick={() => setFilter("live")}
                      className={`px-3 py-1 rounded-lg text-sm ${filter === "live" ? "bg-green-500 text-white" : "bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
                        }`}
                    >
                      Canlı
                    </button>
                    <button
                      onClick={() => setFilter("direct")}
                      className={`px-3 py-1 rounded-lg text-sm ${filter === "direct" ? "bg-red-500 text-white" : "bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
                        }`}
                    >
                      Origin IP
                    </button>
                    <button
                      onClick={() => setFilter("cloud")}
                      className={`px-3 py-1 rounded-lg text-sm ${filter === "cloud" ? "bg-orange-500 text-white" : "bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
                        }`}
                    >
                      Cloud/CDN
                    </button>
                  </div>
                </div>

                <input
                  type="text"
                  placeholder="Subdomain ara..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full px-4 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 mb-4 transition-colors"
                />

                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead className="text-xs text-slate-500 dark:text-slate-400 uppercase bg-slate-100 dark:bg-slate-900/50">
                      <tr>
                        <th className="px-4 py-3">Subdomain</th>
                        <th className="px-4 py-3">IP</th>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Response</th>
                        <th className="px-4 py-3">Technologies</th>
                        <th className="px-4 py-3">Infrastructure</th>
                      </tr>
                    </thead>
                    <tbody>
                      {assets.map((asset, i) => (
                        <tr
                          key={i}
                          className="border-b border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/30 cursor-pointer transition-colors"
                          onClick={() => setSelectedAsset(asset)}
                        >
                          <td className="px-4 py-3 font-medium text-cyan-700 dark:text-cyan-300">{asset.subdomain}</td>
                          <td className="px-4 py-3 text-slate-600 dark:text-slate-300">{asset.ip || "-"}</td>
                          <td className="px-4 py-3">
                            {asset.is_live ? (
                              <span className="px-2 py-1 bg-green-500/20 text-green-300 rounded text-xs">
                                {asset.status_code}
                              </span>
                            ) : (
                              <span className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs">
                                Offline
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-slate-500 dark:text-slate-400">
                            {asset.response_time_ms ? `${asset.response_time_ms}ms` : "-"}
                          </td>
                          <td className="px-4 py-3">
                            {asset.technologies.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {asset.technologies.slice(0, 3).map((tech, j) => (
                                  <span
                                    key={j}
                                    className="px-2 py-1 bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-300 rounded text-xs"
                                    title={`${tech.category} - ${tech.confidence}% confidence`}
                                  >
                                    {tech.name}
                                    {tech.version && ` ${tech.version}`}
                                  </span>
                                ))}
                                {asset.technologies.length > 3 && (
                                  <span className="px-2 py-1 bg-slate-600 text-slate-300 rounded text-xs">
                                    +{asset.technologies.length - 3}
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="text-slate-500">-</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            {asset.infrastructure.provider ? (
                              <Tooltip content={`Cloud Provider: ${asset.infrastructure.provider}${asset.infrastructure.is_waf_protected ? ' (WAF Protected)' : ''}`}>
                                <span
                                  className={`px-2 py-1 rounded text-xs ${asset.is_cf
                                    ? "bg-orange-500/20 text-orange-300"
                                    : "bg-blue-500/20 text-blue-300"
                                    }`}
                                >
                                  {asset.infrastructure.provider}
                                </span>
                              </Tooltip>
                            ) : (
                              <Tooltip content="Direkt IP - Cloudflare/CDN koruması yok. Potansiyel saldırı noktası.">
                                <span className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs">
                                  Direct
                                </span>
                              </Tooltip>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="mt-4 flex items-center justify-between">
                  <div className="text-slate-500 dark:text-slate-400 text-sm">
                    Gösterilen: {assets.length} / {scanStatus.result.subdomains.found.length} varlık
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={exportJSON}
                      className="px-3 py-1 bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 rounded text-sm transition-colors"
                      title="JSON formatında indir"
                    >
                      📥 JSON
                    </button>
                    <button
                      onClick={exportCSV}
                      className="px-3 py-1 bg-green-500/20 hover:bg-green-500/30 text-green-300 rounded text-sm transition-colors"
                      title="CSV formatında indir (Excel)"
                    >
                      📊 CSV
                    </button>
                    <button
                      onClick={exportMarkdown}
                      className="px-3 py-1 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 rounded text-sm transition-colors"
                      title="Markdown rapor"
                    >
                      📝 Markdown
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Kullanım Senaryoları - Daraltılabilir */}
            <details className="mt-6 bg-slate-800/30 rounded-xl p-5 border border-slate-700">
              <summary className="cursor-pointer text-lg font-semibold text-white flex items-center gap-2 mb-4">
                💡 Detaylı Kullanım Senaryoları
              </summary>

              {/* Senaryo 1: Cloudflare Bypass */}
              <details className="mb-4 bg-slate-900/50 rounded-lg p-4">
                <summary className="cursor-pointer font-medium text-cyan-400 flex items-center gap-2">
                  <span>🎯</span> Senaryo 1: Cloudflare Bypass (Origin IP Bulma)
                  <span className="text-xs bg-orange-500/20 text-orange-300 px-2 py-1 rounded ml-auto">Orta Seviye</span>
                </summary>
                <div className="mt-3 space-y-2 text-sm text-slate-300">
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">1.</span>
                    <span>Deep Scan (110K) wordlist ile subdomain taraması başlatın</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">2.</span>
                    <span>"Origin IP" filtresini aktif edin (Cloudflare olmayan varlıklar)</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">3.</span>
                    <span>Bulunan direkt IP'leri not edin (örn: staging.example.com → 1.2.3.4)</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">4.</span>
                    <span>Bu IP'ye /etc/hosts ekleyerek ana domain'i test edin:</span>
                  </div>
                  <div className="bg-slate-950 rounded p-2 font-mono text-xs text-green-400 ml-6">
                    1.2.3.4 example.com
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">5.</span>
                    <span>Eğer site açılıyorsa, Cloudflare WAF'ı bypass edilmiştir ✅</span>
                  </div>
                  <div className="bg-red-900/20 border border-red-500/30 rounded p-2 mt-3">
                    <span className="text-red-300 text-xs">⚠️ Bu teknik sadece yetkilendirilmiş sistemlerde kullanılmalıdır.</span>
                  </div>
                </div>
              </details>

              {/* Senaryo 2: Shadow IT */}
              <details className="mb-4 bg-slate-900/50 rounded-lg p-4">
                <summary className="cursor-pointer font-medium text-cyan-400 flex items-center gap-2">
                  <span>👻</span> Senaryo 2: Shadow IT Tespiti
                  <span className="text-xs bg-green-500/20 text-green-300 px-2 py-1 rounded ml-auto">Kolay</span>
                </summary>
                <div className="mt-3 space-y-2 text-sm text-slate-300">
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">1.</span>
                    <span>Fast Scan (20K) ile tarama yapın</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">2.</span>
                    <span>"Canlı" filtresini aktif edin</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">3.</span>
                    <span>Şüpheli subdomain'leri arayın:</span>
                  </div>
                  <ul className="ml-6 space-y-1 text-xs">
                    <li>• test.*, dev.*, staging.*, demo.*</li>
                    <li>• old.*, backup.*, temp.*</li>
                    <li>• jenkins.*, gitlab.*, jira.*</li>
                  </ul>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">4.</span>
                    <span>Bu varlıkların IT departmanı tarafından bilinip bilinmediğini kontrol edin</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">5.</span>
                    <span>Bilinmeyen varlıklar güvenlik riski oluşturur (genellikle güncel değildir)</span>
                  </div>
                </div>
              </details>

              {/* Senaryo 3: Teknoloji Envanteri */}
              <details className="mb-4 bg-slate-900/50 rounded-lg p-4">
                <summary className="cursor-pointer font-medium text-cyan-400 flex items-center gap-2">
                  <span>📊</span> Senaryo 3: Teknoloji Envanteri ve Zafiyet Analizi
                  <span className="text-xs bg-orange-500/20 text-orange-300 px-2 py-1 rounded ml-auto">Orta Seviye</span>
                </summary>
                <div className="mt-3 space-y-2 text-sm text-slate-300">
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">1.</span>
                    <span>Quick Scan (5K) ile hızlı tarama yapın</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">2.</span>
                    <span>Technologies sütununu inceleyin, eski versiyonları not edin</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">3.</span>
                    <span>CVE veritabanlarında arama yapın:</span>
                  </div>
                  <div className="bg-slate-950 rounded p-2 font-mono text-xs text-green-400 ml-6 space-y-1">
                    <div>WordPress 5.0 CVE</div>
                    <div>PHP 7.0 vulnerabilities</div>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">4.</span>
                    <span>Nuclei modülü ile otomatik zafiyet taraması yapın</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">5.</span>
                    <span>Bulunan zafiyetleri öncelik sırasına göre raporlayın</span>
                  </div>
                </div>
              </details>

              {/* Senaryo 4: Sürekli İzleme */}
              <details className="bg-slate-900/50 rounded-lg p-4">
                <summary className="cursor-pointer font-medium text-cyan-400 flex items-center gap-2">
                  <span>🔔</span> Senaryo 4: Sürekli İzleme (Continuous Monitoring)
                  <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded ml-auto">İleri Seviye</span>
                </summary>
                <div className="mt-3 space-y-2 text-sm text-slate-300">
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">1.</span>
                    <span>İlk baseline taraması yapın ve sonuçları kaydedin</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">2.</span>
                    <span>Haftalık/aylık otomatik tarama ayarlayın (cron job)</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">3.</span>
                    <span>Yeni subdomain'leri tespit edin (diff comparison)</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">4.</span>
                    <span>Teknoloji değişikliklerini takip edin (version updates)</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-cyan-400 font-mono">5.</span>
                    <span>Beklenmeyen değişiklikler için alarm oluşturun</span>
                  </div>
                  <div className="bg-blue-900/20 border border-blue-500/30 rounded p-2 mt-3">
                    <span className="text-blue-300 text-xs">💡 API endpoint'ini kullanarak otomasyonu kolayca kurabilirsiniz</span>
                  </div>
                </div>
              </details>
            </details>

            {/* Yasal Uyarı */}
            <div className="mt-4 bg-red-900/20 border border-red-500/30 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <span className="text-2xl">⚠️</span>
                <div>
                  <h4 className="text-red-300 font-semibold mb-1">Yasal Uyarı</h4>
                  <p className="text-slate-300 text-sm">
                    Bu araç sadece <strong>yetkilendirilmiş sistemlerde</strong> kullanılmalıdır.
                    İzinsiz tarama <strong>yasadışıdır</strong> ve cezai sorumluluk doğurur.
                    Kullanıcı tüm sorumluluğu kabul eder.
                  </p>
                </div>
              </div>
            </div>
          </>
        )}

        {/* Asset Detay Modal */}
        {selectedAsset && (
          <div
            className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
            onClick={() => setSelectedAsset(null)}
          >
            <div
              className="bg-slate-800 rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="sticky top-0 bg-slate-800 border-b border-slate-700 p-6 flex items-center justify-between">
                <h2 className="text-xl font-bold text-white">Asset Detayları</h2>
                <button
                  onClick={() => setSelectedAsset(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>

              <div className="p-6 space-y-6">
                {/* Genel Bilgiler */}
                <div>
                  <h3 className="text-lg font-semibold text-cyan-400 mb-3">Genel Bilgiler</h3>
                  <div className="grid grid-cols-2 gap-4 bg-slate-900/50 rounded-lg p-4">
                    <div>
                      <div className="text-xs text-slate-400 mb-1">Subdomain</div>
                      <div className="text-white font-medium">{selectedAsset.subdomain}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-400 mb-1">IP Address</div>
                      <div className="text-white font-medium">{selectedAsset.ip || 'N/A'}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-400 mb-1">Status Code</div>
                      <div className="text-white font-medium">{selectedAsset.status_code || 'N/A'}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-400 mb-1">Response Time</div>
                      <div className="text-white font-medium">{selectedAsset.response_time_ms ? `${selectedAsset.response_time_ms}ms` : 'N/A'}</div>
                    </div>
                    {selectedAsset.page_title && (
                      <div className="col-span-2">
                        <div className="text-xs text-slate-400 mb-1">Page Title</div>
                        <div className="text-white font-medium">{selectedAsset.page_title}</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Teknolojiler */}
                {selectedAsset.technologies.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold text-purple-400 mb-3">Tespit Edilen Teknolojiler</h3>
                    <div className="space-y-2">
                      {selectedAsset.technologies.map((tech, i) => (
                        <div key={i} className="bg-slate-900/50 rounded-lg p-3 flex items-center justify-between">
                          <div>
                            <div className="text-white font-medium">
                              {tech.name} {tech.version && <span className="text-slate-400">v{tech.version}</span>}
                            </div>
                            <div className="text-xs text-slate-400">{tech.category}</div>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="text-xs text-slate-400">Confidence: {tech.confidence}%</div>
                            <a
                              href={`https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${tech.name}+${tech.version || ''}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs hover:bg-red-500/30 transition-colors"
                            >
                              CVE Check
                            </a>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Infrastructure */}
                <div>
                  <h3 className="text-lg font-semibold text-orange-400 mb-3">Infrastructure</h3>
                  <div className="bg-slate-900/50 rounded-lg p-4 space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Provider</span>
                      <span className="text-white font-medium">{selectedAsset.infrastructure.provider || 'Direct IP'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Cloud Hosted</span>
                      <span className={selectedAsset.infrastructure.is_cloud ? 'text-green-400' : 'text-red-400'}>
                        {selectedAsset.infrastructure.is_cloud ? 'Yes' : 'No'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">WAF Protected</span>
                      <span className={selectedAsset.infrastructure.is_waf_protected ? 'text-orange-400' : 'text-green-400'}>
                        {selectedAsset.infrastructure.is_waf_protected ? 'Yes (Cloudflare/WAF)' : 'No'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Private IP</span>
                      <span className={selectedAsset.infrastructure.is_private_ip ? 'text-yellow-400' : 'text-slate-400'}>
                        {selectedAsset.infrastructure.is_private_ip ? 'Yes' : 'No'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Güvenlik Önerileri */}
                <div>
                  <h3 className="text-lg font-semibold text-yellow-400 mb-3">Güvenlik Önerileri</h3>
                  <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4 space-y-2 text-sm text-slate-300">
                    {!selectedAsset.infrastructure.is_waf_protected && (
                      <div className="flex gap-2">
                        <span>⚠️</span>
                        <span>WAF koruması yok - Direkt saldırılara açık olabilir</span>
                      </div>
                    )}
                    {selectedAsset.technologies.some(t => t.name.includes('WordPress')) && (
                      <div className="flex gap-2">
                        <span>🔍</span>
                        <span>WordPress tespit edildi - wp-admin, xmlrpc.php endpoint'lerini kontrol edin</span>
                      </div>
                    )}
                    {selectedAsset.technologies.some(t => t.name.includes('PHP')) && (
                      <div className="flex gap-2">
                        <span>🐘</span>
                        <span>PHP tespit edildi - Versiyon güncel mi kontrol edin (PHP 7.x EOL)</span>
                      </div>
                    )}
                    {selectedAsset.subdomain.includes('test') || selectedAsset.subdomain.includes('staging') && (
                      <div className="flex gap-2">
                        <span>👻</span>
                        <span>Test/Staging ortamı - Production'dan izole olmalı, public erişim kapalı olmalı</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Hızlı Aksiyonlar */}
                <div>
                  <h3 className="text-lg font-semibold text-green-400 mb-3">Hızlı Aksiyonlar</h3>
                  <div className="grid grid-cols-2 gap-3">
                    <a
                      href={`https://${selectedAsset.subdomain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 rounded-lg text-center transition-colors"
                    >
                      🌐 Siteyi Aç
                    </a>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(selectedAsset.ip || selectedAsset.subdomain);
                        alert('IP kopyalandı!');
                      }}
                      className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 rounded-lg transition-colors"
                    >
                      📋 IP Kopyala
                    </button>
                    <Link
                      to={`/scan?target=${selectedAsset.subdomain}&type=nuclei`}
                      className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded-lg text-center transition-colors"
                    >
                      🔍 Nuclei Tara
                    </Link>
                    <Link
                      to={`/nmap-advanced?target=${selectedAsset.ip || selectedAsset.subdomain}`}
                      className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 text-green-300 rounded-lg text-center transition-colors"
                    >
                      🔎 Nmap Tara
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
