import { useState, useMemo } from 'react';
import { Search, ArrowUpDown, ExternalLink, Filter, Download } from 'lucide-react';
import type { ScanResult, ScanStatus } from '../types/feroxbuster';

interface LiveResultsStreamProps {
  results: ScanResult[];
  status: ScanStatus;
  findingsCount: number;
  isLoading?: boolean;
}

// Status code renk kodlaması
const getStatusColor = (code: number): string => {
  if (code >= 200 && code < 300) return 'text-green-500 bg-green-500/10';
  if (code >= 300 && code < 400) return 'text-blue-500 bg-blue-500/10';
  if (code >= 400 && code < 500) return 'text-yellow-500 bg-yellow-500/10';
  if (code >= 500) return 'text-red-500 bg-red-500/10';
  return 'text-txt-muted bg-hover';
};

export default function LiveResultsStream({
  results,
  status,
  findingsCount,
  isLoading = false,
}: LiveResultsStreamProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'url' | 'status' | 'size'>('url');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [filterStatus, setFilterStatus] = useState<number | null>(null);

  // Filtreleme ve sıralama
  const filteredResults = useMemo(() => {
    let filtered = [...results];

    // Arama
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(r => 
        r.url.toLowerCase().includes(term) ||
        r.content_type?.toLowerCase().includes(term)
      );
    }

    // Status filtresi
    if (filterStatus !== null) {
      filtered = filtered.filter(r => r.status === filterStatus);
    }

    // Sıralama
    filtered.sort((a, b) => {
      let cmp = 0;
      switch (sortBy) {
        case 'url':
          cmp = a.url.localeCompare(b.url);
          break;
        case 'status':
          cmp = a.status - b.status;
          break;
        case 'size':
          cmp = a.content_length - b.content_length;
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return filtered;
  }, [results, searchTerm, sortBy, sortDir, filterStatus]);

  // Unique status codes
  const statusCodes = useMemo(() => {
    return [...new Set(results.map(r => r.status))].sort();
  }, [results]);

  const handleSort = (field: 'url' | 'status' | 'size') => {
    if (sortBy === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortDir('asc');
    }
  };

  const handleExport = () => {
    const csv = [
      ['URL', 'Status', 'Method', 'Size', 'Words', 'Lines', 'Content-Type'].join(','),
      ...filteredResults.map(r => [
        `"${r.url}"`,
        r.status,
        r.method,
        r.content_length,
        r.word_count,
        r.line_count,
        `"${r.content_type || ''}"`,
      ].join(','))
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fuzz-results-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  return (
    <div className="bg-surface border border-brd-main rounded-xl overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-brd-main bg-element/50 flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <h3 className="font-semibold text-txt-main">
            Sonuçlar
            <span className="ml-2 text-sm text-txt-muted">
              ({filteredResults.length}/{findingsCount})
            </span>
          </h3>
          
          {/* Status indicator */}
          <span className={`px-2 py-1 rounded text-xs font-medium ${
            status === 'running' ? 'bg-yellow-500/10 text-yellow-500' :
            status === 'completed' ? 'bg-green-500/10 text-green-500' :
            status === 'failed' ? 'bg-red-500/10 text-red-500' :
            'bg-hover text-txt-muted'
          }`}>
            {status === 'running' ? '🔄 Taranıyor...' :
             status === 'completed' ? '✅ Tamamlandı' :
             status === 'failed' ? '❌ Başarısız' :
             '⏳ Bekliyor'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-txt-muted" />
            <input
              type="text"
              placeholder="URL ara..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 pr-4 py-2 bg-element border border-brd-strong rounded-lg text-sm text-txt-main focus:border-purple-500 outline-none w-48"
            />
          </div>

          {/* Status filter */}
          <select
            value={filterStatus ?? ''}
            onChange={(e) => setFilterStatus(e.target.value ? Number(e.target.value) : null)}
            className="px-3 py-2 bg-element border border-brd-strong rounded-lg text-sm text-txt-main"
          >
            <option value="">Tüm Status</option>
            {statusCodes.map(code => (
              <option key={code} value={code}>{code}</option>
            ))}
          </select>

          {/* Export */}
          <button
            onClick={handleExport}
            className="p-2 bg-element hover:bg-hover border border-brd-strong rounded-lg text-txt-muted hover:text-txt-main transition-colors"
            title="CSV olarak indir"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Results table */}
      <div className="overflow-x-auto max-h-96 overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="bg-element/50 sticky top-0">
            <tr>
              <th 
                className="px-4 py-3 text-left font-medium text-txt-muted cursor-pointer hover:text-txt-main"
                onClick={() => handleSort('status')}
              >
                <div className="flex items-center gap-1">
                  Status
                  {sortBy === 'status' && <ArrowUpDown className="w-3 h-3" />}
                </div>
              </th>
              <th 
                className="px-4 py-3 text-left font-medium text-txt-muted cursor-pointer hover:text-txt-main"
                onClick={() => handleSort('url')}
              >
                <div className="flex items-center gap-1">
                  URL
                  {sortBy === 'url' && <ArrowUpDown className="w-3 h-3" />}
                </div>
              </th>
              <th 
                className="px-4 py-3 text-left font-medium text-txt-muted cursor-pointer hover:text-txt-main"
                onClick={() => handleSort('size')}
              >
                <div className="flex items-center gap-1">
                  Size
                  {sortBy === 'size' && <ArrowUpDown className="w-3 h-3" />}
                </div>
              </th>
              <th className="px-4 py-3 text-left font-medium text-txt-muted">Method</th>
              <th className="px-4 py-3 text-center font-medium text-txt-muted">Aç</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-brd-main">
            {filteredResults.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-txt-muted">
                  {isLoading ? (
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-4 h-4 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
                      Sonuçlar bekleniyor...
                    </div>
                  ) : results.length === 0 ? (
                    'Henüz sonuç yok'
                  ) : (
                    'Filtreye uygun sonuç bulunamadı'
                  )}
                </td>
              </tr>
            ) : (
              filteredResults.slice(0, 100).map((result, idx) => (
                <tr key={idx} className="hover:bg-hover/50 transition-colors">
                  <td className="px-4 py-2">
                    <span className={`px-2 py-1 rounded text-xs font-mono font-bold ${getStatusColor(result.status)}`}>
                      {result.status}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <span className="font-mono text-txt-main text-xs break-all">
                      {result.url}
                    </span>
                    {result.content_type && (
                      <span className="ml-2 text-xs text-txt-muted">
                        ({result.content_type.split(';')[0]})
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-txt-muted text-xs">
                    {result.content_length > 1024 
                      ? `${(result.content_length / 1024).toFixed(1)}KB`
                      : `${result.content_length}B`
                    }
                  </td>
                  <td className="px-4 py-2 text-txt-muted text-xs">
                    {result.method}
                  </td>
                  <td className="px-4 py-2 text-center">
                    <a
                      href={result.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex p-1 hover:bg-purple-500/10 rounded text-txt-muted hover:text-purple-500 transition-colors"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        
        {filteredResults.length > 100 && (
          <div className="px-4 py-2 text-center text-xs text-txt-muted bg-element/50 border-t border-brd-main">
            İlk 100 sonuç gösteriliyor. Tüm sonuçlar için CSV'yi indirin.
          </div>
        )}
      </div>
    </div>
  );
}
