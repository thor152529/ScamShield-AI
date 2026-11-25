import { useState, type FormEvent } from 'react';
import {
  ArrowRight,
  Cpu,
  FileSearch,
  Lock,
  MessageSquareWarning,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react';
import { sanitizeScanUrlInput, validateScanUrl } from '../utils/urlAnalyzer';
import type { PageRoute } from '../types/scamshield';

interface HeroProps {
  onScanFromHero: (url: string) => void;
  onNavigate: (page: PageRoute) => void;
}

const HIGHLIGHTS = [
  {
    index: '01',
    title: 'Random Forest Classifier',
    description:
      'Ensemble of decision trees trained on 60,000 labeled benign, phishing, defacement, and malware URLs.',
    icon: Cpu,
  },
  {
    index: '02',
    title: '10 Lexical URL Features',
    description:
      'Extracts length, dots, hyphens, IP literals, HTTPS, subdomains, keywords, Punycode, and shorteners.',
    icon: FileSearch,
  },
  {
    index: '03',
    title: '0–100 Heuristic Risk Score',
    description:
      'Combines ML phishing probability with transparent warning rules into Low, Suspicious, and High tiers.',
    icon: SlidersHorizontal,
  },
  {
    index: '04',
    title: 'Explainable Threat Report',
    description:
      'Reveals exact URL indicators and clear next-step guidance instead of an opaque pass/fail label.',
    icon: ShieldCheck,
  },
];

const ATTACK_VECTORS = [
  'WhatsApp & SMS delivery or KYC links',
  'Urgent email account-suspension notices',
  'Fake banking & payment verification pages',
  'Lookalike job offer & social media scams',
];

export function Hero({ onScanFromHero, onNavigate }: HeroProps) {
  const [urlInput, setUrlInput] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const check = validateScanUrl(urlInput);
    if (!check.valid) {
      setValidationError(check.error ?? 'Please enter a valid http:// or https:// URL.');
      return;
    }
    setValidationError(null);
    setUrlInput(check.normalizedUrl);
    onScanFromHero(check.normalizedUrl);
  };

  const handleQuickFill = (sampleUrl: string) => {
    setUrlInput(sampleUrl);
    setValidationError(null);
  };

  return (
    <div className="space-y-20 pb-12">
      {/* Primary Hero Split */}
      <section className="relative overflow-hidden pt-10 sm:pt-14">
        <div className="mx-auto grid max-w-[1200px] grid-cols-1 items-stretch gap-10 px-4 sm:px-6 lg:grid-cols-12 lg:gap-12 lg:px-8">
          {/* Left Column: Value Proposition + Immediate URL Scanner */}
          <div className="flex flex-col justify-center lg:col-span-7">
            <p className="text-sm font-medium tracking-wide text-[#45D6BB]">
              Detect Threats. Browse Smarter.
            </p>

            <h1
              className="mt-3 font-display font-bold tracking-tight text-[#EAF0F7] text-balance"
              style={{ fontSize: 'clamp(2.25rem, 4.2vw, 3.6rem)', lineHeight: 1.1 }}
            >
              Stay One Step Ahead of Online Scams.
            </h1>

            <p className="mt-5 max-w-[60ch] text-base leading-relaxed text-[#91A5B8] sm:text-lg">
              AI-powered phishing detection that helps identify suspicious URLs before they put your
              digital security at risk. Paste any link to inspect lexical features, calculate a
              provisional risk score, and review explainable security indicators.
            </p>

            {/* Hero URL Scan Form */}
            <form onSubmit={handleSubmit} className="mt-8" noValidate>
              <label htmlFor="hero-url-input" className="sr-only">
                Enter suspicious URL to scan
              </label>
              <div className="flex flex-col gap-3 rounded-xl border border-[#91A5B8]/20 bg-[#101E30] p-2.5 sm:flex-row sm:items-center">
                <input
                  id="hero-url-input"
                  type="url"
                  value={urlInput}
                  onPaste={(e) => {
                    const pasted = e.clipboardData.getData('text');
                    const sanitized = sanitizeScanUrlInput(pasted);
                    if (sanitized && sanitized !== pasted) {
                      e.preventDefault();
                      setUrlInput(sanitized);
                      if (validationError) setValidationError(null);
                    }
                  }}
                  onChange={(e) => {
                    setUrlInput(e.target.value);
                    if (validationError) setValidationError(null);
                  }}
                  placeholder="https://example.com or http://secure-login-verify-example.com"
                  className="min-h-[44px] flex-1 bg-transparent px-3 font-mono text-sm text-[#EAF0F7] placeholder:text-[#91A5B8]/60 focus:outline-none"
                  aria-describedby={validationError ? 'hero-url-error' : undefined}
                />
                <button
                  type="submit"
                  className="inline-flex min-h-[44px] items-center justify-center gap-2 rounded-lg bg-[#35C7AD] px-6 py-2.5 text-sm font-semibold text-[#07111F] whitespace-nowrap shrink-0 transition-colors duration-150 hover:bg-[#45D6BB] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#45D6BB] cursor-pointer"
                >
                  <span>Scan Now</span>
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>

              {validationError && (
                <p
                  id="hero-url-error"
                  role="alert"
                  className="mt-2.5 text-sm text-[#FF6878]"
                >
                  {validationError}
                </p>
              )}

              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-[#91A5B8]">
                <span>Try a test URL:</span>
                <button
                  type="button"
                  onClick={() => handleQuickFill('https://example.com')}
                  className="font-mono text-[#45D6BB] underline-offset-4 hover:underline cursor-pointer"
                >
                  https://example.com
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('http://192.168.1.1/login')}
                  className="font-mono text-[#F3B94F] underline-offset-4 hover:underline cursor-pointer"
                >
                  http://192.168.1.1/login
                </button>
                <button
                  type="button"
                  onClick={() => handleQuickFill('http://secure-login-verify-example.com')}
                  className="font-mono text-[#FF6878] underline-offset-4 hover:underline cursor-pointer"
                >
                  http://secure-login-verify-example.com
                </button>
              </div>
            </form>

            <div className="mt-7 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-[#91A5B8]/15 pt-6 text-xs text-[#91A5B8]">
              <span>Lexical ML Inspection</span>
              <span aria-hidden="true" className="hidden sm:inline">
                ·
              </span>
              <span>No URL Auto-Execution</span>
              <span aria-hidden="true" className="hidden sm:inline">
                ·
              </span>
              <button
                type="button"
                onClick={() => onNavigate('how-it-works')}
                className="font-medium text-[#EAF0F7] underline-offset-4 hover:text-[#45D6BB] hover:underline cursor-pointer"
              >
                Inspect detection pipeline
              </button>
            </div>
          </div>

          {/* Right Column: Animated Shield & Threat Radar Illustration */}
          <div className="flex items-center justify-center lg:col-span-5">
            <div className="relative flex w-full max-w-[460px] flex-col justify-between rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6 sm:p-8">
              <div className="flex items-center justify-between text-xs text-[#91A5B8]">
                <span className="font-medium text-[#EAF0F7]">Lexical Threat Inspection</span>
                <span className="font-mono text-[#45D6BB]">10-Feature Vector</span>
              </div>

              {/* Animated SVG Shield Radar */}
              <div className="relative my-6 flex items-center justify-center">
                <svg
                  viewBox="0 0 280 280"
                  className="h-60 w-60 sm:h-64 sm:w-64"
                  role="img"
                  aria-label="Animated ScamShield AI security shield and threat detection radar"
                >
                  <defs>
                    <radialGradient id="shieldGlow" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="#35C7AD" stopOpacity="0.22" />
                      <stop offset="100%" stopColor="#07111F" stopOpacity="0" />
                    </radialGradient>
                    <linearGradient id="sweepGrad" x1="50%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#45D6BB" stopOpacity="0.45" />
                      <stop offset="100%" stopColor="#35C7AD" stopOpacity="0" />
                    </linearGradient>
                  </defs>

                  <circle cx="140" cy="140" r="130" fill="url(#shieldGlow)" />
                  <circle
                    cx="140"
                    cy="140"
                    r="116"
                    fill="none"
                    stroke="#91A5B8"
                    strokeOpacity="0.18"
                    strokeDasharray="4 6"
                  />
                  <circle
                    cx="140"
                    cy="140"
                    r="86"
                    fill="none"
                    stroke="#35C7AD"
                    strokeOpacity="0.24"
                  />

                  {/* Rotating Radar Sweep */}
                  <g className="origin-[140px_140px] animate-radar-sweep">
                    <path
                      d="M140 140 L140 24 A116 116 0 0 1 240 82 Z"
                      fill="url(#sweepGrad)"
                    />
                    <line
                      x1="140"
                      y1="140"
                      x2="140"
                      y2="24"
                      stroke="#45D6BB"
                      strokeWidth="1.5"
                      strokeOpacity="0.8"
                    />
                  </g>

                  {/* Center Shield */}
                  <path
                    d="M140 58L88 79V132C88 171 110 206 140 219C170 206 192 171 192 132V79L140 58Z"
                    fill="#07111F"
                    stroke="#35C7AD"
                    strokeWidth="2.5"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M140 74L102 89.5V131C102 161 118.5 188.5 140 199.5C161.5 188.5 178 161 178 131V89.5L140 74Z"
                    fill="#35C7AD"
                    fillOpacity="0.12"
                  />
                  <path
                    d="M123 136L135 148L160 121"
                    stroke="#45D6BB"
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />

                  {/* Orbital Feature Nodes */}
                  <circle cx="140" cy="24" r="4" fill="#45D6BB" />
                  <circle cx="240" cy="82" r="4" fill="#F3B94F" />
                  <circle cx="240" cy="198" r="4" fill="#35C7AD" />
                  <circle cx="40" cy="198" r="4" fill="#FF6878" />
                  <circle cx="40" cy="82" r="4" fill="#35C7AD" />
                </svg>
              </div>

              {/* Clean Illustrative Pattern Summary */}
              <div className="space-y-2.5 border-t border-[#91A5B8]/15 pt-4 text-xs">
                <div className="flex items-center justify-between text-[#91A5B8]">
                  <span>Classification Tiers</span>
                  <span className="font-mono text-[#EAF0F7] tabular-nums">
                    0–39 · 40–69 · 70–100
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
                  <div className="rounded-md border border-[#35C7AD]/30 bg-[#35C7AD]/10 px-2.5 py-1.5 text-center text-[#35C7AD]">
                    LOW
                  </div>
                  <div className="rounded-md border border-[#F3B94F]/30 bg-[#F3B94F]/10 px-2.5 py-1.5 text-center text-[#F3B94F]">
                    SUSPICIOUS
                  </div>
                  <div className="rounded-md border border-[#FF6878]/30 bg-[#FF6878]/10 px-2.5 py-1.5 text-center text-[#FF6878]">
                    HIGH
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4-Column Technology & Trust Highlights */}
      <section className="mx-auto max-w-[1200px] px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {HIGHLIGHTS.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.index}
                className="flex flex-col justify-between rounded-xl border border-[#91A5B8]/15 bg-[#101E30] p-6"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-medium text-[#45D6BB]">
                      {item.index}.
                    </span>
                    <Icon className="h-5 w-5 text-[#35C7AD]" aria-hidden="true" />
                  </div>
                  <h2 className="mt-4 font-display text-base font-semibold text-[#EAF0F7]">
                    {item.title}
                  </h2>
                  <p className="mt-2 text-sm leading-relaxed text-[#91A5B8]">
                    {item.description}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Problem & Explainable Advantage Strip */}
      <section className="mx-auto max-w-[1200px] px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-6 rounded-2xl border border-[#91A5B8]/15 bg-[#101E30] p-6 sm:p-8 lg:grid-cols-12">
          <div className="lg:col-span-6">
            <h2 className="font-display text-xl font-semibold text-[#EAF0F7] sm:text-2xl">
              Why URL-Level Explanation Matters
            </h2>
            <p className="mt-3 text-sm leading-relaxed text-[#91A5B8] sm:text-base">
              Phishing campaigns spread through everyday messaging channels before blocklists catch
              up. Rather than showing a vague warning, ScamShield AI breaks down the exact
              structural signals inside a suspicious link.
            </p>
            <ul className="mt-5 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              {ATTACK_VECTORS.map((vector) => (
                <li
                  key={vector}
                  className="flex items-start gap-2.5 text-sm text-[#EAF0F7]"
                >
                  <MessageSquareWarning
                    className="mt-0.5 h-4 w-4 shrink-0 text-[#F3B94F]"
                    aria-hidden="true"
                  />
                  <span>{vector}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="flex flex-col justify-between border-t border-[#91A5B8]/15 pt-6 lg:col-span-6 lg:border-l lg:border-t-0 lg:pl-8 lg:pt-0">
            <div>
              <div className="flex items-center gap-2 text-sm font-semibold text-[#FF6878]">
                <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                <span>Example Flagged Pattern</span>
              </div>
              <p className="mt-3 rounded-lg border border-[#91A5B8]/15 bg-[#07111F] px-3.5 py-2.5 font-mono text-xs text-[#EAF0F7] break-all">
                http://secure-bank-login-example.com
              </p>
              <p className="mt-3 text-sm leading-relaxed text-[#91A5B8]">
                Flagged for combining unencrypted HTTP transport with high-risk credential keywords
                (<code className="text-[#EAF0F7]">secure</code>,{' '}
                <code className="text-[#EAF0F7]">bank</code>,{' '}
                <code className="text-[#EAF0F7]">login</code>) and multi-hyphen brand impersonation
                patterns.
              </p>
            </div>

            <div className="mt-6 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => onScanFromHero('http://secure-bank-login-example.com')}
                className="inline-flex min-h-[40px] items-center gap-2 rounded-lg bg-[#35C7AD] px-4 py-2 text-sm font-semibold text-[#07111F] transition-colors hover:bg-[#45D6BB] cursor-pointer"
              >
                <span>Scan Example URL</span>
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </button>
              <button
                type="button"
                onClick={() => onNavigate('dashboard')}
                className="inline-flex min-h-[40px] items-center gap-2 rounded-lg border border-[#91A5B8]/25 bg-[#07111F] px-4 py-2 text-sm font-medium text-[#EAF0F7] transition-colors hover:border-[#35C7AD]/60 cursor-pointer"
              >
                <Lock className="h-4 w-4 text-[#45D6BB]" aria-hidden="true" />
                <span>Open Analytics Dashboard</span>
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
