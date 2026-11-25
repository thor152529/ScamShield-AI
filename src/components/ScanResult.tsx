import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Globe,
  Info,
  KeyRound,
  Lock,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react';
import type {
  LexicalFeatures,
  RiskLevel,
  ScanResponse,
  ThreatBreakdownCard,
  ThreatCategoryId,
  ThreatCategorySeverity,
} from '../types/scamshield';
import { buildThreatBreakdown } from '../utils/urlAnalyzer';
import { RiskMeter } from './RiskMeter';

interface ScanResultProps {
  result: ScanResponse;
  onClear?: () => void;
}

const FEATURE_META: {
  key: keyof LexicalFeatures;
  label: string;
  format: (v: number | boolean) => string;
  hint: string;
}[] = [
  { key: 'url_length', label: 'URL Length', format: (v) => `${v} chars`, hint: 'Total URL characters' },
  { key: 'hostname_length', label: 'Hostname Length', format: (v) => `${v} chars`, hint: 'Domain length' },
  { key: 'dot_count', label: 'Dot Count', format: (v) => String(v), hint: 'Total dots in URL' },
  { key: 'hyphen_count', label: 'Hyphen Count', format: (v) => String(v), hint: 'Hyphens in hostname' },
  { key: 'subdomain_count', label: 'Subdomains', format: (v) => String(v), hint: 'Domain nesting depth' },
  {
    key: 'suspicious_keyword_count',
    label: 'Suspicious Keywords',
    format: (v) => String(v),
    hint: 'Matched phishing terms',
  },
  {
    key: 'has_https',
    label: 'HTTPS Protocol',
    format: (v) => (v ? 'Yes' : 'No'),
    hint: 'Encrypted transport flag',
  },
  {
    key: 'has_ip_address',
    label: 'IP Hostname',
    format: (v) => (v ? 'Detected' : 'None'),
    hint: 'Raw IPv4/IPv6 host',
  },
  {
    key: 'has_punycode',
    label: 'Punycode (xn--)',
    format: (v) => (v ? 'Detected' : 'None'),
    hint: 'IDN homograph prefix',
  },
  {
    key: 'is_shortener',
    label: 'URL Shortener',
    format: (v) => (v ? 'Detected' : 'None'),
    hint: 'Known shortener domain',
  },
];

function getRiskPresentation(level: RiskLevel) {
  if (level === 'HIGH') {
    return {
      icon: ShieldAlert,
      badgeClass: 'border-[#FF6878]/40 bg-[#FF6878]/12 text-[#FF6878]',
      statusTitle: 'High Risk — Potential Phishing / Malicious Pattern',
      barColor: 'bg-[#FF6878]',
    };
  }
  if (level === 'SUSPICIOUS') {
    return {
      icon: AlertTriangle,
      badgeClass: 'border-[#F3B94F]/40 bg-[#F3B94F]/12 text-[#F3B94F]',
      statusTitle: 'Suspicious — Manual Verification Recommended',
      barColor: 'bg-[#F3B94F]',
    };
  }
  return {
    icon: ShieldCheck,
    badgeClass: 'border-[#35C7AD]/40 bg-[#35C7AD]/12 text-[#35C7AD]',
    statusTitle: 'Low Lexical Risk — Still Verify Before Trusting',
    barColor: 'bg-[#35C7AD]',
  };
}

function getBreakdownCardStyles(severity: ThreatCategorySeverity) {
  if (severity === 'danger') {
    return {
      cardClass: 'border-[#FF6878]/35 bg-[#07111F]',
      badgeClass: 'border-[#FF6878]/35 bg-[#FF6878]/12 text-[#FF6878]',
      badgeText: 'High Risk',
      iconColor: 'text-[#FF6878]',
      statusColor: 'text-[#FF6878]',
    };
  }
  if (severity === 'warning') {
    return {
      cardClass: 'border-[#F3B94F]/35 bg-[#07111F]',
      badgeClass: 'border-[#F3B94F]/35 bg-[#F3B94F]/12 text-[#F3B94F]',
      badgeText: 'Caution',
      iconColor: 'text-[#F3B94F]',
      statusColor: 'text-[#F3B94F]',
    };
  }
  return {
    cardClass: 'border-[#35C7AD]/30 bg-[#07111F]',
    badgeClass: 'border-[#35C7AD]/35 bg-[#35C7AD]/12 text-[#35C7AD]',
    badgeText: 'Passed',
    iconColor: 'text-[#35C7AD]',
    statusColor: 'text-[#45D6BB]',
  };
}

function getBreakdownIcon(id: ThreatCategoryId) {
  switch (id) {
    case 'domain_spoofing':
      return Globe;
    case 'ssl_https':
      return Lock;
    case 'suspicious_keywords':
      return KeyRound;
    case 'redirect_risk':
      return ExternalLink;
  }
}

export function ScanResult({ result, onClear }: ScanResultProps) {
  const [copied, setCopied] = useState(false);
  const [expandedTip, setExpandedTip] = useState<number | null>(0);

  const pres = getRiskPresentation(result.risk_level);
  const StatusIcon = pres.icon;
  const probPercent = Math.round(result.phishing_probability * 100);

  const breakdownCards = useMemo<ThreatBreakdownCard[]>(() => {
    if (result.threat_breakdown && result.threat_breakdown.length === 4) {
      return result.threat_breakdown;
    }
    try {
      return buildThreatBreakdown(result.url);
    } catch {
      return [];
    }
  }, [result.threat_breakdown, result.url]);

  const handleCopyUrl = async () => {
    try {
      await navigator.clipboard.writeText(result.url);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard API unavailable
    }
  };

  const indicatorDetails =
    result.indicator_details && result.indicator_details.length > 0
      ? result.indicator_details
      : result.indicators.map((label) => ({
          label,
          severity: 'info' as const,
          explanation: 'Lexical indicator reported by the ScamShield AI backend.',
        }));

  return (
    <section
      aria-label="Scan Results"
      data-testid="scan-result-panel"
      className="space-y-6 rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6 sm:p-8"
    >
      {/* Top Status & Scanned URL Header */}
      <div className="flex flex-col gap-4 border-b border-[#91A5B8]/15 pb-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1 text-xs font-semibold tracking-wide ${pres.badgeClass}`}
            >
              <StatusIcon className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>
                {result.risk_level} · {result.prediction}
              </span>
            </span>
            {result.engine && (
              <span className="text-xs text-[#91A5B8]">
                {result.engine}
                {result.latency_ms ? ` · ${result.latency_ms} ms` : ''}
              </span>
            )}
          </div>

          <h2 className="font-display text-xl font-semibold text-[#EAF0F7] sm:text-2xl">
            {pres.statusTitle}
          </h2>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-xs font-medium text-[#91A5B8]">Submitted URL:</span>
            <code className="rounded-md border border-[#91A5B8]/15 bg-[#07111F] px-2.5 py-1 font-mono text-xs text-[#EAF0F7] break-all">
              {result.url}
            </code>
            <button
              type="button"
              onClick={handleCopyUrl}
              aria-label="Copy scanned URL"
              className="inline-flex min-h-[32px] items-center gap-1.5 rounded-md border border-[#91A5B8]/20 bg-[#07111F] px-2.5 py-1 text-xs font-medium text-[#91A5B8] transition-colors hover:border-[#35C7AD]/50 hover:text-[#EAF0F7] cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-[#35C7AD]" aria-hidden="true" />
                  <span className="text-[#35C7AD]">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Copy URL</span>
                </>
              )}
            </button>
          </div>
        </div>

        {onClear && (
          <button
            type="button"
            onClick={onClear}
            className="inline-flex min-h-[40px] items-center justify-center rounded-lg border border-[#91A5B8]/25 bg-[#07111F] px-4 py-2 text-sm font-medium text-[#EAF0F7] whitespace-nowrap shrink-0 transition-colors hover:border-[#91A5B8]/50 cursor-pointer"
          >
            Clear Scan
          </button>
        )}
      </div>

      {/* Clean Green AI Threat Engine Active Status Pill */}
      <div className="flex items-center">
        <span
          role="status"
          data-testid="ai-engine-status-pill"
          className="inline-flex items-center gap-2 rounded-full border border-emerald-400/40 bg-emerald-500/12 px-3.5 py-1 text-xs font-medium text-emerald-300"
        >
          <span className="h-2 w-2 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
          <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-emerald-400" aria-hidden="true" />
          <span>AI Threat Engine Active</span>
        </span>
      </div>

      {/* Main Metric Grid: Risk Meter + Probability / Status + Recommendation */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="lg:col-span-4">
          <RiskMeter score={result.risk_score} riskLevel={result.risk_level} />
        </div>

        <div className="flex flex-col justify-between space-y-5 lg:col-span-8">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-4">
              <div className="text-xs text-[#91A5B8]">Heuristic Risk Score</div>
              <div className="mt-1.5 font-mono text-2xl font-bold text-[#EAF0F7] tabular-nums">
                {result.risk_score} / 100
              </div>
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[#101E30]">
                <div
                  className={`h-full transition-all duration-500 ${pres.barColor}`}
                  style={{ width: `${result.risk_score}%` }}
                />
              </div>
            </div>

            <div className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-4">
              <div className="text-xs text-[#91A5B8]">ML Phishing Probability</div>
              <div className="mt-1.5 font-mono text-2xl font-bold text-[#EAF0F7] tabular-nums">
                {probPercent}%
              </div>
              <div className="mt-2 text-xs text-[#91A5B8] tabular-nums">
                Raw model output: {result.phishing_probability.toFixed(2)}
              </div>
            </div>

            <div className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-4">
              <div className="text-xs text-[#91A5B8]">Model Classification</div>
              <div className="mt-1.5 font-display text-lg font-semibold text-[#EAF0F7]">
                {result.prediction}
              </div>
              <div className="mt-2 truncate font-mono text-xs text-[#91A5B8]">
                {result.normalized_hostname || new URL(result.url).hostname}
              </div>
            </div>
          </div>

          {/* Recommended Action Box */}
          <div className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-5">
            <h3 className="font-display text-sm font-semibold text-[#EAF0F7]">
              Recommended Security Action
            </h3>
            <p className="mt-2 text-sm leading-relaxed text-[#EAF0F7]/90">
              {result.recommendation}
            </p>
            <p className="mt-3 text-xs leading-relaxed text-[#91A5B8]">
              {result.analysis_scope_note ||
                'Provisional hackathon thresholds (0–39 Low, 40–69 Suspicious, 70–100 High) are heuristic risk scores from lexical URL inspection only—not calibrated probabilities or proof that a website is safe.'}
            </p>
          </div>
        </div>
      </div>

      {/* Color-Coded Threat Breakdown Cards */}
      {breakdownCards.length > 0 && (
        <div
          data-testid="threat-breakdown-cards"
          className="border-t border-[#91A5B8]/15 pt-6"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-display text-base font-semibold text-[#EAF0F7]">
              Threat Breakdown Analysis
            </h3>
            <span className="text-xs text-[#91A5B8]">
              Four-signal lexical inspection across spoofing, transport, keywords, and redirects
            </span>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {breakdownCards.map((card) => {
              const cardStyle = getBreakdownCardStyles(card.severity);
              const CategoryIcon = getBreakdownIcon(card.id);
              return (
                <div
                  key={card.id}
                  data-testid={`threat-card-${card.id}`}
                  data-severity={card.severity}
                  className={`flex flex-col justify-between rounded-xl border p-4 ${cardStyle.cardClass}`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-1.5 text-[13px] font-semibold text-[#EAF0F7]">
                        <CategoryIcon
                          className={`h-4 w-4 shrink-0 ${cardStyle.iconColor}`}
                          aria-hidden="true"
                        />
                        <span className="truncate">{card.title}</span>
                      </div>
                      <span
                        className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold whitespace-nowrap shrink-0 ${cardStyle.badgeClass}`}
                      >
                        {cardStyle.badgeText}
                      </span>
                    </div>

                    <div className={`mt-3 text-xs font-semibold ${cardStyle.statusColor}`}>
                      {card.status_label}
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed text-[#91A5B8]">
                      {card.summary}
                    </p>
                  </div>

                  <div className="mt-3 border-t border-[#91A5B8]/15 pt-2.5 font-mono text-[11px] text-[#EAF0F7]/90 tabular-nums truncate">
                    {card.metric_value}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Domain Age & SSL/TLS Analysis */}
      {(result.ssl_analysis || result.domain_age_analysis) && (
        <div
          data-testid="ssl-domain-analysis"
          className="grid grid-cols-1 gap-4 border-t border-[#91A5B8]/15 pt-6 md:grid-cols-2"
        >
          {result.ssl_analysis && (
            <div className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-5">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm font-semibold text-[#EAF0F7]">
                  <Lock
                    className={`h-4 w-4 ${
                      result.ssl_analysis.protocol === 'HTTPS'
                        ? 'text-[#35C7AD]'
                        : 'text-[#F3B94F]'
                    }`}
                    aria-hidden="true"
                  />
                  <span>SSL / TLS Protocol Analysis</span>
                </div>
                <span className="font-mono text-xs text-[#91A5B8]">
                  {result.ssl_analysis.protocol}
                </span>
              </div>
              <div
                className={`mt-2 text-xs font-medium ${
                  result.ssl_analysis.protocol === 'HTTPS'
                    ? 'text-[#45D6BB]'
                    : 'text-[#F3B94F]'
                }`}
              >
                {result.ssl_analysis.status_label}
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-[#91A5B8]">
                {result.ssl_analysis.summary}
              </p>
            </div>
          )}

          {result.domain_age_analysis && (
            <div className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-5">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm font-semibold text-[#EAF0F7]">
                  <Globe className="h-4 w-4 text-[#45D6BB]" aria-hidden="true" />
                  <span>Domain Age & Structure Analysis</span>
                </div>
                <span className="font-mono text-xs text-[#91A5B8]">
                  {result.domain_age_analysis.hostname_type}
                </span>
              </div>
              <div
                className={`mt-2 text-xs font-medium ${
                  result.risk_level === 'HIGH'
                    ? 'text-[#FF6878]'
                    : result.risk_level === 'SUSPICIOUS'
                      ? 'text-[#F3B94F]'
                      : 'text-[#45D6BB]'
                }`}
              >
                {result.domain_age_analysis.risk_assessment}
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-[#91A5B8]">
                {result.domain_age_analysis.summary}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Explainable Detection Indicators with Interactive Tooltips */}
      <div className="border-t border-[#91A5B8]/15 pt-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-display text-base font-semibold text-[#EAF0F7]">
            Explainable Detection Indicators ({indicatorDetails.length})
          </h3>
          <span className="text-xs text-[#91A5B8]">
            Select an indicator to view why it affects the score
          </span>
        </div>

        <ul className="mt-4 space-y-2.5">
          {indicatorDetails.map((item, idx) => {
            const isOpen = expandedTip === idx;
            const iconColor =
              item.severity === 'danger'
                ? 'text-[#FF6878]'
                : item.severity === 'warning'
                  ? 'text-[#F3B94F]'
                  : 'text-[#35C7AD]';
            const ItemIcon =
              item.severity === 'danger'
                ? ShieldAlert
                : item.severity === 'warning'
                  ? ShieldQuestion
                  : CheckCircle2;

            return (
              <li
                key={`${item.label}-${idx}`}
                className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F]"
              >
                <button
                  type="button"
                  onClick={() => setExpandedTip(isOpen ? null : idx)}
                  aria-expanded={isOpen}
                  className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-[#101E30]/60 cursor-pointer min-h-[44px]"
                >
                  <div className="flex items-center gap-3">
                    <ItemIcon className={`h-4 w-4 shrink-0 ${iconColor}`} aria-hidden="true" />
                    <span className="text-sm font-medium text-[#EAF0F7]">{item.label}</span>
                  </div>
                  <span className="inline-flex items-center gap-1 text-xs text-[#91A5B8] shrink-0">
                    <Info className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{isOpen ? 'Hide note' : 'Why?'}</span>
                  </span>
                </button>
                {isOpen && (
                  <div className="border-t border-[#91A5B8]/10 px-4 py-3 text-xs leading-relaxed text-[#91A5B8]">
                    {item.explanation}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </div>

      {/* Extracted 10 Lexical Features Breakdown */}
      {result.features && (
        <div className="border-t border-[#91A5B8]/15 pt-6">
          <h3 className="font-display text-base font-semibold text-[#EAF0F7]">
            Extracted Lexical URL Features (10 Features)
          </h3>
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {FEATURE_META.map((feat) => {
              const rawVal = result.features![feat.key];
              const isFlagged =
                (feat.key === 'has_ip_address' && rawVal === true) ||
                (feat.key === 'has_punycode' && rawVal === true) ||
                (feat.key === 'is_shortener' && rawVal === true) ||
                (feat.key === 'has_https' && rawVal === false) ||
                (feat.key === 'suspicious_keyword_count' && Number(rawVal) > 0);

              return (
                <div
                  key={feat.key}
                  title={feat.hint}
                  className="rounded-lg border border-[#91A5B8]/15 bg-[#07111F] p-3"
                >
                  <div className="text-xs text-[#91A5B8]">{feat.label}</div>
                  <div
                    className={`mt-1 font-mono text-sm font-semibold tabular-nums ${
                      isFlagged ? 'text-[#F3B94F]' : 'text-[#EAF0F7]'
                    }`}
                  >
                    {feat.format(rawVal)}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}
