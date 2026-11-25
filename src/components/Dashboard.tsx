import {
  BarChart3,
  Database,
  PlusCircle,
  ShieldAlert,
  ShieldCheck,
  Target,
} from 'lucide-react';
import type { PageRoute, ScanHistoryItem } from '../types/scamshield';
import { computeDashboardStats, MODEL_VALIDATION_ACCURACY } from '../utils/demoData';
import { ScanHistory } from './ScanHistory';

interface DashboardProps {
  history: ScanHistoryItem[];
  onNavigate: (page: PageRoute) => void;
  onInspectItem: (item: ScanHistoryItem) => void;
  onDeleteItem: (id: string) => void;
  onClearAll: () => void;
  onLoadDemoData: () => void;
}

export function Dashboard({
  history,
  onNavigate,
  onInspectItem,
  onDeleteItem,
  onClearAll,
  onLoadDemoData,
}: DashboardProps) {
  const { total, threatsBlocked, suspiciousCount, lowCount, avgScore } =
    computeDashboardStats(history);
  const highCount = threatsBlocked;
  const hasDemoItems = history.some((h) => h.is_demo);

  const pct = (count: number) => (total > 0 ? Math.round((count / total) * 100) : 0);

  // Donut Chart geometry
  const radius = 56;
  const circ = 2 * Math.PI * radius;
  const lowLen = total > 0 ? (lowCount / total) * circ : 0;
  const susLen = total > 0 ? (suspiciousCount / total) * circ : 0;
  const highLen = total > 0 ? (highCount / total) * circ : 0;

  const recentEight = history.slice(0, 8).reverse();

  return (
    <div className="mx-auto max-w-[1200px] space-y-8 px-4 py-10 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="flex flex-col gap-4 border-b border-[#91A5B8]/15 pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-[#EAF0F7] sm:text-3xl">
            Security Analytics Dashboard
          </h1>
          <p className="mt-2 text-sm text-[#91A5B8] sm:text-base">
            Aggregate risk distribution, recent scan telemetry, and explainable threat history
            from your URL scans.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-4">
          {hasDemoItems && (
            <span className="text-xs font-medium text-[#F3B94F]">
              Includes clearly labeled synthetic demo records
            </span>
          )}
          <button
            type="button"
            onClick={() => onNavigate('scanner')}
            className="inline-flex min-h-[40px] items-center gap-2 rounded-lg bg-[#35C7AD] px-4 py-2 text-sm font-semibold text-[#07111F] whitespace-nowrap shrink-0 hover:bg-[#45D6BB] cursor-pointer"
          >
            <PlusCircle className="h-4 w-4" aria-hidden="true" />
            <span>New URL Scan</span>
          </button>
        </div>
      </div>

      {/* Empty State when no scans exist */}
      {total === 0 ? (
        <div
          data-testid="dashboard-empty-state"
          className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-10 text-center"
        >
          <BarChart3 className="mx-auto h-10 w-10 text-[#35C7AD]" aria-hidden="true" />
          <h2 className="mt-4 font-display text-xl font-semibold text-[#EAF0F7]">
            No URL Scans Recorded Yet
          </h2>
          <p className="mx-auto mt-2 max-w-[56ch] text-sm leading-relaxed text-[#91A5B8]">
            ScamShield AI does not fabricate scan statistics. Run a real URL scan in the URL
            Scanner to populate live analytics, or load our clearly labeled synthetic benchmark
            samples for a hackathon demonstration.
          </p>

          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => onNavigate('scanner')}
              className="inline-flex min-h-[44px] items-center gap-2 rounded-lg bg-[#35C7AD] px-5 py-2.5 text-sm font-semibold text-[#07111F] hover:bg-[#45D6BB] cursor-pointer"
            >
              <PlusCircle className="h-4 w-4" aria-hidden="true" />
              <span>Scan Your First URL</span>
            </button>

            <button
              type="button"
              onClick={onLoadDemoData}
              className="inline-flex min-h-[44px] items-center gap-2 rounded-lg border border-[#91A5B8]/25 bg-[#07111F] px-5 py-2.5 text-sm font-medium text-[#EAF0F7] hover:border-[#35C7AD]/60 cursor-pointer"
            >
              <Database className="h-4 w-4 text-[#45D6BB]" aria-hidden="true" />
              <span>Load Demo Benchmark Data</span>
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* 4 KPI Summary Cards */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-[#91A5B8]/20 bg-[#101E30] p-5">
              <div className="flex items-center justify-between text-xs text-[#91A5B8]">
                <span>Total Scans</span>
                <BarChart3 className="h-4 w-4 text-[#45D6BB]" aria-hidden="true" />
              </div>
              <div
                data-testid="kpi-total-scans"
                className="mt-2 font-mono text-3xl font-bold tabular-nums text-[#EAF0F7]"
              >
                {total}
              </div>
              <div className="mt-1 text-xs text-[#91A5B8] tabular-nums">
                {threatsBlocked} blocked · {suspiciousCount} suspicious · {lowCount} legitimate
              </div>
            </div>

            <div className="rounded-xl border border-[#91A5B8]/20 bg-[#101E30] p-5">
              <div className="flex items-center justify-between text-xs text-[#91A5B8]">
                <span>Threats Blocked</span>
                <ShieldAlert className="h-4 w-4 text-[#FF6878]" aria-hidden="true" />
              </div>
              <div
                data-testid="kpi-threats-blocked"
                className="mt-2 font-mono text-3xl font-bold tabular-nums text-[#FF6878]"
              >
                {threatsBlocked}
              </div>
              <div className="mt-1 text-xs text-[#91A5B8] tabular-nums">
                High-risk phishing &amp; malicious (avg {avgScore}/100)
              </div>
            </div>

            <div className="rounded-xl border border-[#91A5B8]/20 bg-[#101E30] p-5">
              <div className="flex items-center justify-between text-xs text-[#91A5B8]">
                <span>Detection Accuracy</span>
                <Target className="h-4 w-4 text-[#45D6BB]" aria-hidden="true" />
              </div>
              <div
                data-testid="kpi-detection-accuracy"
                className="mt-2 font-mono text-3xl font-bold tabular-nums text-[#45D6BB]"
              >
                {MODEL_VALIDATION_ACCURACY}%
              </div>
              <div className="mt-1 text-xs text-[#91A5B8]">
                Validation Benchmark
              </div>
            </div>

            <div className="rounded-xl border border-[#91A5B8]/20 bg-[#101E30] p-5">
              <div className="flex items-center justify-between text-xs text-[#91A5B8]">
                <span>Legitimate (Low Risk)</span>
                <ShieldCheck className="h-4 w-4 text-[#35C7AD]" aria-hidden="true" />
              </div>
              <div
                data-testid="kpi-low-scans"
                className="mt-2 font-mono text-3xl font-bold tabular-nums text-[#35C7AD]"
              >
                {lowCount}
              </div>
              <div className="mt-1 text-xs text-[#91A5B8] tabular-nums">
                {suspiciousCount} suspicious · {pct(lowCount)}% legitimate (0–39)
              </div>
            </div>
          </div>

          {/* Interactive Charts Row */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Risk Distribution Donut + Horizontal Breakdown */}
            <div className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6 lg:col-span-5">
              <h2 className="font-display text-lg font-semibold text-[#EAF0F7]">
                Risk Classification Distribution
              </h2>
              <p className="mt-1 text-xs text-[#91A5B8]">
                Proportion of scanned URLs across Low, Suspicious, and High tiers.
              </p>

              <div className="mt-6 flex flex-col items-center gap-6 sm:flex-row">
                <div className="relative flex h-36 w-36 shrink-0 items-center justify-center">
                  <svg viewBox="0 0 140 140" className="h-full w-full -rotate-90">
                    <circle
                      cx="70"
                      cy="70"
                      r={radius}
                      fill="none"
                      stroke="#07111F"
                      strokeWidth="16"
                    />
                    {lowLen > 0 && (
                      <circle
                        cx="70"
                        cy="70"
                        r={radius}
                        fill="none"
                        stroke="#35C7AD"
                        strokeWidth="16"
                        strokeDasharray={`${lowLen} ${circ}`}
                        strokeDashoffset={0}
                      />
                    )}
                    {susLen > 0 && (
                      <circle
                        cx="70"
                        cy="70"
                        r={radius}
                        fill="none"
                        stroke="#F3B94F"
                        strokeWidth="16"
                        strokeDasharray={`${susLen} ${circ}`}
                        strokeDashoffset={-lowLen}
                      />
                    )}
                    {highLen > 0 && (
                      <circle
                        cx="70"
                        cy="70"
                        r={radius}
                        fill="none"
                        stroke="#FF6878"
                        strokeWidth="16"
                        strokeDasharray={`${highLen} ${circ}`}
                        strokeDashoffset={-(lowLen + susLen)}
                      />
                    )}
                  </svg>
                  <div className="absolute text-center">
                    <div className="font-mono text-2xl font-bold tabular-nums text-[#EAF0F7]">
                      {total}
                    </div>
                    <div className="text-[11px] text-[#91A5B8]">Scans</div>
                  </div>
                </div>

                <div className="w-full space-y-3.5 text-xs">
                  <div>
                    <div className="flex justify-between">
                      <span className="font-medium text-[#35C7AD]">Low Risk (0–39)</span>
                      <span className="font-mono tabular-nums text-[#EAF0F7]">
                        {lowCount} ({pct(lowCount)}%)
                      </span>
                    </div>
                    <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-[#07111F]">
                      <div
                        className="h-full bg-[#35C7AD]"
                        style={{ width: `${pct(lowCount)}%` }}
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between">
                      <span className="font-medium text-[#F3B94F]">Suspicious (40–69)</span>
                      <span className="font-mono tabular-nums text-[#EAF0F7]">
                        {suspiciousCount} ({pct(suspiciousCount)}%)
                      </span>
                    </div>
                    <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-[#07111F]">
                      <div
                        className="h-full bg-[#F3B94F]"
                        style={{ width: `${pct(suspiciousCount)}%` }}
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between">
                      <span className="font-medium text-[#FF6878]">High Risk (70–100)</span>
                      <span className="font-mono tabular-nums text-[#EAF0F7]">
                        {highCount} ({pct(highCount)}%)
                      </span>
                    </div>
                    <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-[#07111F]">
                      <div
                        className="h-full bg-[#FF6878]"
                        style={{ width: `${pct(highCount)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Scan Risk Score Bar Chart */}
            <div className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6 lg:col-span-7">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="font-display text-lg font-semibold text-[#EAF0F7]">
                    Recent Scan Activity & Risk Scores
                  </h2>
                  <p className="mt-1 text-xs text-[#91A5B8]">
                    Select any bar to open the full explainable threat report.
                  </p>
                </div>
                <span className="font-mono text-xs text-[#91A5B8] tabular-nums">
                  Latest {recentEight.length} scans
                </span>
              </div>

              <div className="mt-6 flex h-44 w-full items-end gap-2.5 overflow-hidden border-b border-[#91A5B8]/15 pb-3">
                {recentEight.map((item) => {
                  const barBg =
                    item.risk_level === 'HIGH'
                      ? 'bg-[#FF6878]'
                      : item.risk_level === 'SUSPICIOUS'
                        ? 'bg-[#F3B94F]'
                        : 'bg-[#35C7AD]';
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => onInspectItem(item)}
                      title={`${item.url} — Score ${item.risk_score}/100`}
                      aria-label={`Inspect ${item.url}, risk score ${item.risk_score} out of 100`}
                      className="group flex h-full min-w-0 flex-1 flex-col items-center justify-end gap-1.5 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#35C7AD] rounded"
                    >
                      <span className="font-mono text-[11px] tabular-nums text-[#91A5B8] group-hover:text-[#EAF0F7]">
                        {item.risk_score}
                      </span>
                      <div className="flex w-full max-w-[44px] flex-1 items-end rounded-t-md bg-[#07111F] p-0.5">
                        <div
                          className={`w-full rounded-t-sm transition-all duration-300 group-hover:opacity-85 ${barBg}`}
                          style={{ height: `${Math.max(8, item.risk_score)}%` }}
                        />
                      </div>
                      <span className="w-full truncate text-center font-mono text-[10px] text-[#91A5B8]">
                        {item.normalized_hostname}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Scan History Table */}
          <ScanHistory
            items={history}
            onInspectItem={onInspectItem}
            onDeleteItem={onDeleteItem}
            onClearAll={onClearAll}
          />
        </>
      )}
    </div>
  );
}
