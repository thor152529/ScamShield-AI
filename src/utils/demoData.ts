import type { ScanHistoryItem } from '../types/scamshield';
import { analyzeUrlLexically } from './urlAnalyzer';

export interface DemoSampleUrl {
  id: 'safe' | 'suspicious' | 'high-risk';
  buttonLabel: string;
  tierLabel: string;
  url: string;
  tone: 'low' | 'suspicious' | 'high';
}

export const DEMO_SAMPLE_URLS: DemoSampleUrl[] = [
  {
    id: 'safe',
    buttonLabel: 'Safe Site',
    tierLabel: 'Low Risk · 0–39',
    url: 'https://example.com',
    tone: 'low',
  },
  {
    id: 'suspicious',
    buttonLabel: 'Suspicious Link',
    tierLabel: 'Suspicious · 40–69',
    url: 'https://bit.ly/3xyz99',
    tone: 'suspicious',
  },
  {
    id: 'high-risk',
    buttonLabel: 'High-Risk Phishing',
    tierLabel: 'High Risk · 70–100',
    url: 'http://secure-bank-login-example.com',
    tone: 'high',
  },
];

export interface SampleUrlPreset {
  label: string;
  url: string;
  category: 'Normal' | 'IP-Based' | 'Suspicious Keywords' | 'Punycode' | 'Shortener';
}

export const SAMPLE_URL_PRESETS: SampleUrlPreset[] = [
  {
    label: 'Normal URL',
    url: 'https://example.com',
    category: 'Normal',
  },
  {
    label: 'IP-based URL',
    url: 'http://192.168.1.1/login',
    category: 'IP-Based',
  },
  {
    label: 'Suspicious keywords',
    url: 'http://secure-login-verify-example.com',
    category: 'Suspicious Keywords',
  },
  {
    label: 'Bank impersonation',
    url: 'http://secure-bank-login-example.com',
    category: 'Suspicious Keywords',
  },
  {
    label: 'Punycode homograph',
    url: 'https://xn--pypal-4ve.com/verify',
    category: 'Punycode',
  },
  {
    label: 'Shortened link',
    url: 'https://bit.ly/3xyz99',
    category: 'Shortener',
  },
];

export const MODEL_VALIDATION_ACCURACY = 94.8;

export function buildDemoBenchmarkHistory(): ScanHistoryItem[] {
  const entries: { url: string; minutesAgo: number }[] = [
    { url: 'http://secure-bank-login-example.com', minutesAgo: 4 },
    { url: 'https://docs.python.org/3/library/', minutesAgo: 11 },
    { url: 'https://bit.ly/3xyz99', minutesAgo: 18 },
    { url: 'http://192.168.1.1/login', minutesAgo: 27 },
    { url: 'https://xn--pypal-4ve.com/verify', minutesAgo: 39 },
    { url: 'https://github.com/features/security', minutesAgo: 52 },
    { url: 'http://account-update-verify-billing.example.com/signin', minutesAgo: 68 },
    { url: 'https://portal.example.org/auth?next=https://tracking.example.net', minutesAgo: 84 },
    { url: 'https://developer.mozilla.org/en-US/docs/Web/Security', minutesAgo: 105 },
  ];

  const baseTime = Date.now();
  return entries.map((entry, idx) => {
    const analyzed = analyzeUrlLexically(entry.url);
    return {
      ...analyzed,
      id: `demo-${idx + 1}`,
      scanned_at: new Date(baseTime - entry.minutesAgo * 60_000).toISOString(),
      is_demo: true,
    };
  });
}

export interface DashboardStats {
  total: number;
  threatsBlocked: number;
  suspiciousCount: number;
  lowCount: number;
  avgScore: number;
}

export function computeDashboardStats(items: ScanHistoryItem[]): DashboardStats {
  let threatsBlocked = 0;
  let suspiciousCount = 0;
  let lowCount = 0;
  let scoreSum = 0;

  for (const item of items) {
    scoreSum += item.risk_score;
    if (item.risk_level === 'HIGH') {
      threatsBlocked += 1;
    } else if (item.risk_level === 'SUSPICIOUS') {
      suspiciousCount += 1;
    } else {
      lowCount += 1;
    }
  }

  const total = threatsBlocked + suspiciousCount + lowCount;
  return {
    total,
    threatsBlocked,
    suspiciousCount,
    lowCount,
    avgScore: total > 0 ? Math.round(scoreSum / total) : 0,
  };
}

export function exportHistoryAsCsv(items: ScanHistoryItem[]): string {
  const header = [
    'id',
    'url',
    'risk_score',
    'risk_level',
    'prediction',
    'phishing_probability',
    'indicators',
    'scanned_at',
    'is_demo',
  ];
  const escape = (val: string | number | boolean) =>
    `"${String(val).replace(/"/g, '""')}"`;

  const rows = items.map((item) =>
    [
      item.id,
      item.url,
      item.risk_score,
      item.risk_level,
      item.prediction,
      item.phishing_probability,
      item.indicators.join(' | '),
      item.scanned_at,
      Boolean(item.is_demo),
    ]
      .map(escape)
      .join(',')
  );

  return [header.join(','), ...rows].join('\n');
}
