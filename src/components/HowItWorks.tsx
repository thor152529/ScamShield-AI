import { ArrowDown, ArrowRight, Cpu, FileCode, ShieldCheck, Sparkles } from 'lucide-react';
import type { PageRoute } from '../types/scamshield';

interface HowItWorksProps {
  onNavigate: (page: PageRoute) => void;
}

const DETECTION_STAGES = [
  {
    step: '01',
    title: 'Sanitize & Validate',
    description:
      'Strips stray Markdown or whitespace, prepends https:// if missing, and blocks unsafe non-web schemes without visiting the URL.',
  },
  {
    step: '02',
    title: 'Extract 10 Lexical Features',
    description:
      'Measures URL length, host depth, dots, hyphens, raw IP hosts, HTTPS, Punycode, shorteners, and credential lure keywords.',
  },
  {
    step: '03',
    title: 'Random Forest + Gemini AI',
    description:
      'Scores the 10-feature vector through our Random Forest ensemble and Gemini AI threat-intelligence rules.',
  },
  {
    step: '04',
    title: '0–100 Risk Verdict',
    description:
      'Classifies links into Low (0–39), Suspicious (40–69), or High Risk (70–100) with clear next-step guidance.',
  },
];

const FEATURE_SPECS = [
  { name: 'URL Length', key: 'url_length', measures: 'Total character count; padded paths often hide malicious hosts.' },
  { name: 'Hostname Length', key: 'hostname_length', measures: 'Domain length; lookalike domains are frequently unusually long.' },
  { name: 'Dot Count', key: 'dot_count', measures: 'Total dots across the URL; catches multi-layer subdomain spoofing.' },
  { name: 'Hyphen Count', key: 'hyphen_count', measures: 'Hyphens in the hostname (e.g., secure-bank-login-example.com).' },
  { name: 'IP Address', key: 'has_ip_address', measures: 'Flags raw IPv4/IPv6 hostnames used instead of registered domains.' },
  { name: 'HTTPS Protocol', key: 'has_https', measures: 'Verifies encrypted transport; missing HTTPS raises interception risk.' },
  { name: 'Subdomain Depth', key: 'subdomain_count', measures: 'Counts nested subdomains used to disguise the true root domain.' },
  { name: 'Phishing Keywords', key: 'suspicious_keyword_count', measures: 'Detects credential and urgency terms like login, verify, bank, or kyc.' },
  { name: 'Punycode (xn--)', key: 'has_punycode', measures: 'Identifies internationalized homograph prefixes mimicking known brands.' },
  { name: 'URL Shortener', key: 'is_shortener', measures: 'Flags masked redirect services (bit.ly, tinyurl.com, t.co) hiding targets.' },
];

export function HowItWorks({ onNavigate }: HowItWorksProps) {
  return (
    <div className="mx-auto max-w-[1200px] space-y-10 px-4 py-10 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="flex flex-col gap-4 border-b border-[#91A5B8]/15 pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-[#EAF0F7] sm:text-3xl">
            How ScamShield AI Works
          </h1>
          <p className="mt-2 max-w-[66ch] text-sm text-[#91A5B8] sm:text-base">
            Every submitted link passes through four zero-fetch inspection stages—combining
            Random Forest lexical scoring with Gemini AI threat-intelligence analysis.
          </p>
        </div>
        <button
          type="button"
          onClick={() => onNavigate('scanner')}
          className="inline-flex min-h-[40px] items-center gap-2 rounded-lg bg-[#35C7AD] px-4 py-2 text-sm font-semibold text-[#07111F] whitespace-nowrap shrink-0 hover:bg-[#45D6BB] cursor-pointer"
        >
          <span>Try URL Scanner</span>
          <ArrowRight className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {/* 4-Stage Detection Pipeline */}
      <section className="space-y-4">
        <h2 className="font-display text-xl font-semibold text-[#EAF0F7]">
          4-Stage Inspection Pipeline
        </h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {DETECTION_STAGES.map((item) => (
            <div
              key={item.step}
              className="rounded-xl border border-[#91A5B8]/15 bg-[#101E30] p-5"
            >
              <div className="font-mono text-xs font-semibold text-[#45D6BB]">
                Stage {item.step}
              </div>
              <h3 className="mt-2 font-display text-base font-semibold text-[#EAF0F7]">
                {item.title}
              </h3>
              <p className="mt-2 text-xs leading-relaxed text-[#91A5B8]">{item.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture Overview */}
      <section className="space-y-4">
        <h2 className="font-display text-xl font-semibold text-[#EAF0F7]">
          System Architecture
        </h2>

        <div className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6">
          <div className="mx-auto max-w-3xl space-y-3 text-center">
            <div className="rounded-xl border border-[#35C7AD]/30 bg-[#07111F] px-5 py-3">
              <div className="text-xs font-medium text-[#45D6BB]">Client Interface</div>
              <div className="mt-0.5 font-display text-sm font-semibold text-[#EAF0F7]">
                React + Vite URL Scanner & Analytics Dashboard
              </div>
            </div>

            <div className="flex justify-center">
              <div className="inline-flex items-center gap-2 text-xs font-mono text-[#45D6BB]">
                <ArrowDown className="h-4 w-4" aria-hidden="true" />
                <span>POST /api/scan · Automatic AI Threat Engine Fallback</span>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="rounded-xl border border-[#91A5B8]/20 bg-[#07111F] p-4">
                <FileCode className="mx-auto h-5 w-5 text-[#F3B94F]" aria-hidden="true" />
                <div className="mt-2 font-display text-sm font-semibold text-[#EAF0F7]">
                  Lexical Feature Parser
                </div>
                <p className="mt-1 text-xs text-[#91A5B8]">
                  Extracts 10 structural signals without opening the target page.
                </p>
              </div>
              <div className="rounded-xl border border-[#91A5B8]/20 bg-[#07111F] p-4">
                <Cpu className="mx-auto h-5 w-5 text-[#35C7AD]" aria-hidden="true" />
                <div className="mt-2 font-display text-sm font-semibold text-[#EAF0F7]">
                  Random Forest Classifier
                </div>
                <p className="mt-1 text-xs text-[#91A5B8]">
                  Trained on 60,000 labeled benign and malicious URL samples.
                </p>
              </div>
              <div className="rounded-xl border border-[#91A5B8]/20 bg-[#07111F] p-4">
                <Sparkles className="mx-auto h-5 w-5 text-[#45D6BB]" aria-hidden="true" />
                <div className="mt-2 font-display text-sm font-semibold text-[#EAF0F7]">
                  Gemini AI Threat Engine
                </div>
                <p className="mt-1 text-xs text-[#91A5B8]">
                  Evaluates brand spoofing, Safe Browsing test hosts, and phishing intent.
                </p>
              </div>
            </div>

            <div className="flex justify-center">
              <ArrowDown className="h-4 w-4 text-[#45D6BB]" aria-hidden="true" />
            </div>

            <div className="rounded-xl border border-[#35C7AD]/40 bg-[#35C7AD]/10 px-5 py-3">
              <div className="flex items-center justify-center gap-2 font-display text-sm font-semibold text-[#EAF0F7]">
                <ShieldCheck className="h-4 w-4 text-[#35C7AD]" aria-hidden="true" />
                <span>Explainable Threat Report & Security Guidance</span>
              </div>
              <div className="mt-1 font-mono text-xs text-[#91A5B8]">
                <span className="text-[#35C7AD]">LOW (0–39)</span> ·{' '}
                <span className="text-[#F3B94F]">SUSPICIOUS (40–69)</span> ·{' '}
                <span className="text-[#FF6878]">HIGH (70–100)</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 10 Extracted Lexical Features */}
      <section className="space-y-4">
        <h2 className="font-display text-xl font-semibold text-[#EAF0F7]">
          10 Lexical Features Inspected
        </h2>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {FEATURE_SPECS.map((feat) => (
            <div
              key={feat.key}
              className="flex flex-col justify-between rounded-xl border border-[#91A5B8]/15 bg-[#101E30] p-4"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-[#EAF0F7]">{feat.name}</span>
                <code className="font-mono text-xs text-[#45D6BB]">{feat.key}</code>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-[#91A5B8]">{feat.measures}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
