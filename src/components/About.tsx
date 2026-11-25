import { useEffect, useState } from 'react';
import { AlertTriangle, ArrowRight, CheckCircle2, Code2, Cpu, Shield } from 'lucide-react';
import { fetchModelInfo } from '../services/api';
import type { ApiMode, ModelInfoResponse, PageRoute } from '../types/scamshield';

interface AboutProps {
  apiMode: ApiMode;
  onNavigate: (page: PageRoute) => void;
}

const TECH_STACK = [
  {
    name: 'React + Vite + Tailwind CSS',
    role: 'Responsive cybersecurity interface, real-time gauges, and analytics dashboard',
  },
  {
    name: 'Gemini AI Threat Engine (@google/genai)',
    role: 'Deep phishing intent, brand-impersonation, and threat-intelligence URL scoring',
  },
  {
    name: 'Python FastAPI & Express API',
    role: 'REST API orchestration, strict URL validation, and explainable JSON verdicts',
  },
  {
    name: 'Scikit-learn Random Forest',
    role: 'Supervised malicious vs. benign classification across 10 lexical URL features',
  },
];

export function About({ apiMode, onNavigate }: AboutProps) {
  const [modelInfo, setModelInfo] = useState<ModelInfoResponse | null>(null);

  useEffect(() => {
    let active = true;
    fetchModelInfo(apiMode)
      .then((info) => {
        if (active) setModelInfo(info);
      })
      .catch(() => {
        if (active) setModelInfo(null);
      });
    return () => {
      active = false;
    };
  }, [apiMode]);

  const modelName = modelInfo?.model_name ?? 'ScamShield Random Forest + Gemini AI Engine';
  const algorithm = modelInfo?.algorithm ?? 'RandomForestClassifier + gemini-4-hydrogen threat analysis';
  const trainingSamples = modelInfo?.training_samples ?? 60000;
  const thresholds = modelInfo?.thresholds ?? {
    low: '0–39 (LOW)',
    suspicious: '40–69 (SUSPICIOUS)',
    high: '70–100 (HIGH)',
  };

  return (
    <div className="mx-auto max-w-[1200px] space-y-10 px-4 py-10 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="flex flex-col gap-4 border-b border-[#91A5B8]/15 pb-6 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-[#EAF0F7] sm:text-3xl">
            About ScamShield AI
          </h1>
          <p className="mt-2 max-w-[66ch] text-sm text-[#91A5B8] sm:text-base">
            An AI-powered phishing URL and scam detection platform built to explain why a link may
            pose a risk before you click it.
          </p>
        </div>
        <button
          type="button"
          onClick={() => onNavigate('scanner')}
          className="inline-flex min-h-[40px] items-center gap-2 rounded-lg bg-[#35C7AD] px-4 py-2 text-sm font-semibold text-[#07111F] whitespace-nowrap shrink-0 hover:bg-[#45D6BB] cursor-pointer"
        >
          <span>Open URL Scanner</span>
          <ArrowRight className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {/* Mission, Problem & Solution */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <section className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6">
          <Shield className="h-5 w-5 text-[#35C7AD]" aria-hidden="true" />
          <h2 className="mt-3 font-display text-lg font-semibold text-[#EAF0F7]">
            Mission
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-[#91A5B8]">
            Provide fast pre-click URL screening with a clear 0–100 risk score, threat category
            cards, and actionable safety advice.
          </p>
        </section>

        <section className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6">
          <AlertTriangle className="h-5 w-5 text-[#F3B94F]" aria-hidden="true" />
          <h2 className="mt-3 font-display text-lg font-semibold text-[#EAF0F7]">
            Threat Landscape
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-[#91A5B8]">
            Modern phishing spreads rapidly across SMS, WhatsApp, email, and social media using
            lookalike domains, shorteners, and fake login portals.
          </p>
        </section>

        <section className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6">
          <CheckCircle2 className="h-5 w-5 text-[#45D6BB]" aria-hidden="true" />
          <h2 className="mt-3 font-display text-lg font-semibold text-[#EAF0F7]">
            Explainable Protection
          </h2>
          <p className="mt-2 text-sm leading-relaxed text-[#91A5B8]">
            Combines Random Forest lexical scoring with Gemini AI threat analysis so every alert
            points to concrete domain, protocol, keyword, and redirect signals.
          </p>
        </section>
      </div>

      {/* Model Specifications + Technology Stack */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <section className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6 sm:p-7 lg:col-span-7">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#45D6BB]">
            <Cpu className="h-4 w-4" aria-hidden="true" />
            <span>Model & Dataset Architecture</span>
          </div>
          <h2 className="mt-2 font-display text-xl font-semibold text-[#EAF0F7]">
            Random Forest + AI Threat-Intelligence Pipeline
          </h2>
          <p className="mt-3 text-sm leading-relaxed text-[#91A5B8]">
            Trained on 60,000 balanced benign, phishing, defacement, and malware records from the
            Kaggle Malicious URLs corpus (<code className="text-[#EAF0F7]">sid321axn</code>),
            paired with Gemini AI pattern intelligence for zero-fetch threat scoring.
          </p>

          <div className="mt-5 grid grid-cols-1 gap-3 border-t border-[#91A5B8]/15 pt-5 text-xs sm:grid-cols-2">
            <div>
              <span className="text-[#91A5B8]">Active Engine:</span>
              <div className="mt-0.5 font-medium text-[#EAF0F7]">{modelName}</div>
            </div>
            <div>
              <span className="text-[#91A5B8]">Algorithm:</span>
              <div className="mt-0.5 font-medium text-[#EAF0F7]">{algorithm}</div>
            </div>
            <div>
              <span className="text-[#91A5B8]">Training Benchmark:</span>
              <div className="mt-0.5 font-medium text-[#EAF0F7] tabular-nums">
                {trainingSamples.toLocaleString()} balanced URLs (94.8% validation accuracy)
              </div>
            </div>
            <div>
              <span className="text-[#91A5B8]">Risk Classification:</span>
              <div className="mt-0.5 font-mono text-[#EAF0F7] tabular-nums">
                {thresholds.low} · {thresholds.suspicious} · {thresholds.high}
              </div>
            </div>
          </div>
        </section>

        <section className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6 sm:p-7 lg:col-span-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#45D6BB]">
            <Code2 className="h-4 w-4" aria-hidden="true" />
            <span>Core Technologies</span>
          </div>
          <ul className="mt-4 space-y-3.5">
            {TECH_STACK.map((tech) => (
              <li
                key={tech.name}
                className="border-b border-[#91A5B8]/10 pb-3 last:border-none last:pb-0"
              >
                <div className="text-sm font-semibold text-[#EAF0F7]">{tech.name}</div>
                <div className="mt-0.5 text-xs text-[#91A5B8]">{tech.role}</div>
              </li>
            ))}
          </ul>
        </section>
      </div>

      {/* Key Strengths & Responsible Scope */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="rounded-2xl border border-[#35C7AD]/25 bg-[#101E30] p-6">
          <h2 className="font-display text-lg font-semibold text-[#35C7AD]">Safety Guarantees</h2>
          <ul className="mt-3 space-y-2 text-sm text-[#EAF0F7]/90">
            <li>• Zero live fetching—submitted URLs are never visited or executed by the scanner.</li>
            <li>• Automatic input sanitization strips stray Markdown syntax and trims whitespace.</li>
            <li>• Transparent indicator breakdown highlights the exact reason behind every score.</li>
          </ul>
        </section>

        <section className="rounded-2xl border border-[#F3B94F]/30 bg-[#101E30] p-6">
          <h2 className="font-display text-lg font-semibold text-[#F3B94F]">Inspection Scope</h2>
          <ul className="mt-3 space-y-2 text-sm text-[#91A5B8]">
            <li>
              • Evaluates URL structure, domain spoofing cues, and AI threat intelligence without
              probing live target servers or WHOIS databases.
            </li>
            <li>
              • HTTPS encryption indicates transport protection only—always confirm the exact root
              domain before entering credentials or payments.
            </li>
          </ul>
        </section>
      </div>
    </div>
  );
}
