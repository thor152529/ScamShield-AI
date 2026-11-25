import { useState } from 'react';
import { Check, Copy, Download, Eye, Search, Trash2 } from 'lucide-react';
import { exportHistoryAsCsv } from '../utils/demoData';
import type { RiskLevel, ScanHistoryItem } from '../types/scamshield';

interface ScanHistoryProps {
  items: ScanHistoryItem[];
  onInspectItem: (item: ScanHistoryItem) => void;
  onDeleteItem: (id: string) => void;
  onClearAll: () => void;
}

type FilterOption = 'ALL' | RiskLevel;

export function ScanHistory({
  items,
  onInspectItem,
  onDeleteItem,
  onClearAll,
}: ScanHistoryProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<FilterOption>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filtered = items.filter((item) => {
    const matchesFilter = filter === 'ALL' || item.risk_level === filter;
    const q = query.trim().toLowerCase();
    const matchesQuery =
      !q ||
      item.url.toLowerCase().includes(q) ||
      item.prediction.toLowerCase().includes(q) ||
      item.indicators.some((ind) => ind.toLowerCase().includes(q));
    return matchesFilter && matchesQuery;
  });

  const handleCopy = async (item: ScanHistoryItem) => {
    try {
      await navigator.clipboard.writeText(item.url);
      setCopiedId(item.id);
      window.setTimeout(() => setCopiedId(null), 1500);
    } catch {
      // Clipboard unavailable
    }
  };

  const handleDownloadCsv = () => {
    const csv = exportHistoryAsCsv(filtered);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'scamshield-scan-history.csv';
    link.click();
    URL.revokeObjectURL(url);
  };

  const riskTextColor = (level: RiskLevel) => {
    if (level === 'HIGH') return 'text-[#FF6878]';
    if (level === 'SUSPICIOUS') return 'text-[#F3B94F]';
    return 'text-[#35C7AD]';
  };

  return (
    <section
      aria-label="Scan History"
      className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6"
    >
      <div className="flex flex-col gap-4 border-b border-[#91A5B8]/15 pb-5 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h2 className="font-display text-lg font-semibold text-[#EAF0F7]">
            Scan History ({filtered.length})
          </h2>
          <p className="mt-1 text-xs text-[#91A5B8]">
            Filter past URL analyses, copy indicators, or inspect full lexical reports.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Segmented Risk Filter */}
          <div
            role="group"
            aria-label="Filter scans by risk level"
            className="flex items-center gap-1 rounded-lg border border-[#91A5B8]/20 bg-[#07111F] p-1"
          >
            {(['ALL', 'LOW', 'SUSPICIOUS', 'HIGH'] as FilterOption[]).map((opt) => (
              <button
                key={opt}
                type="button"
                onClick={() => setFilter(opt)}
                className={`rounded-md px-3 py-1 text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  filter === opt
                    ? 'bg-[#35C7AD] text-[#07111F]'
                    : 'text-[#91A5B8] hover:text-[#EAF0F7]'
                }`}
              >
                {opt === 'ALL' ? 'All' : opt}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={handleDownloadCsv}
            disabled={filtered.length === 0}
            className="inline-flex min-h-[36px] items-center gap-1.5 rounded-lg border border-[#91A5B8]/20 bg-[#07111F] px-3 py-1.5 text-xs font-medium text-[#EAF0F7] hover:border-[#35C7AD]/50 disabled:opacity-40 cursor-pointer"
          >
            <Download className="h-3.5 w-3.5 text-[#45D6BB]" aria-hidden="true" />
            <span>Export CSV</span>
          </button>

          <button
            type="button"
            onClick={onClearAll}
            className="inline-flex min-h-[36px] items-center gap-1.5 rounded-lg border border-[#FF6878]/30 bg-[#07111F] px-3 py-1.5 text-xs font-medium text-[#FF6878] hover:bg-[#FF6878]/10 cursor-pointer"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="mt-4">
        <label htmlFor="history-search" className="sr-only">
          Search scan history
        </label>
        <div className="relative max-w-md">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#91A5B8]"
            aria-hidden="true"
          />
          <input
            id="history-search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by URL, classification, or indicator..."
            className="min-h-[40px] w-full rounded-lg border border-[#91A5B8]/20 bg-[#07111F] pl-9 pr-3 text-sm text-[#EAF0F7] placeholder:text-[#91A5B8]/60 focus:border-[#35C7AD] focus:outline-none"
          />
        </div>
      </div>

      {/* High-Density Data Table */}
      <div className="mt-4 overflow-x-auto">
        {filtered.length === 0 ? (
          <div className="py-10 text-center text-sm text-[#91A5B8]">
            No scan records match the active filter or search query.
          </div>
        ) : (
          <table data-testid="scan-history-table" className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-[#91A5B8]/15 text-xs font-medium text-[#91A5B8]">
                <th className="py-3 pr-4">Scanned URL</th>
                <th className="px-3 py-3 text-right">Risk Score</th>
                <th className="px-3 py-3">Risk Tier</th>
                <th className="px-3 py-3 text-right">ML Prob.</th>
                <th className="px-3 py-3">Top Indicator</th>
                <th className="px-3 py-3 text-right">Scanned</th>
                <th className="py-3 pl-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#91A5B8]/10">
              {filtered.map((item) => {
                const timeText = new Date(item.scanned_at).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                });
                return (
                  <tr
                    key={item.id}
                    data-testid="scan-history-row"
                    className="transition-colors hover:bg-[#07111F]/60"
                  >
                    <td className="max-w-[280px] py-3 pr-4">
                      <div className="truncate font-mono text-xs text-[#EAF0F7]" title={item.url}>
                        {item.url}
                      </div>
                      <div
                        className={`mt-0.5 text-[11px] ${
                          item.is_demo ? 'text-[#91A5B8]' : 'font-medium text-[#45D6BB]'
                        }`}
                      >
                        {item.is_demo ? 'Sample Benchmark Record' : 'Live Scan'}
                      </div>
                    </td>
                    <td className="px-3 py-3 text-right font-mono text-xs font-semibold tabular-nums text-[#EAF0F7]">
                      {item.risk_score}/100
                    </td>
                    <td className={`px-3 py-3 text-xs font-semibold ${riskTextColor(item.risk_level)}`}>
                      {item.risk_level} · {item.prediction}
                    </td>
                    <td className="px-3 py-3 text-right font-mono text-xs tabular-nums text-[#91A5B8]">
                      {Math.round(item.phishing_probability * 100)}%
                    </td>
                    <td className="max-w-[240px] truncate px-3 py-3 text-xs text-[#91A5B8]">
                      {item.indicators[0] ?? 'None'}
                    </td>
                    <td className="px-3 py-3 text-right font-mono text-xs tabular-nums text-[#91A5B8] whitespace-nowrap">
                      {timeText}
                    </td>
                    <td className="py-3 pl-3 text-right">
                      <div className="inline-flex items-center justify-end gap-1.5">
                        <button
                          type="button"
                          onClick={() => onInspectItem(item)}
                          aria-label={`Inspect scan report for ${item.url}`}
                          className="inline-flex h-8 items-center gap-1 rounded-md border border-[#91A5B8]/20 bg-[#07111F] px-2.5 text-xs font-medium text-[#EAF0F7] hover:border-[#35C7AD]/60 cursor-pointer"
                        >
                          <Eye className="h-3.5 w-3.5 text-[#45D6BB]" aria-hidden="true" />
                          <span>View</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleCopy(item)}
                          aria-label={`Copy URL ${item.url}`}
                          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-[#91A5B8]/20 bg-[#07111F] text-[#91A5B8] hover:text-[#EAF0F7] cursor-pointer"
                        >
                          {copiedId === item.id ? (
                            <Check className="h-3.5 w-3.5 text-[#35C7AD]" aria-hidden="true" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => onDeleteItem(item.id)}
                          aria-label={`Delete scan entry for ${item.url}`}
                          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-[#91A5B8]/20 bg-[#07111F] text-[#91A5B8] hover:border-[#FF6878]/50 hover:text-[#FF6878] cursor-pointer"
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
