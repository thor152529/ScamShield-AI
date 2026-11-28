import { performance } from 'node:perf_hooks';
import { analyzeUrlLexically } from '../src/utils/urlAnalyzer';

interface LabeledCase {
  url: string;
  label: 0 | 1; // 0 = benign, 1 = malicious/phishing/suspicious-flagged
  note: string;
}

const EVAL_SUITE: LabeledCase[] = [
  // Benign (15)
  { url: 'https://example.com', label: 0, note: 'canonical benign' },
  { url: 'https://github.com/features/security', label: 0, note: 'developer docs' },
  { url: 'https://docs.python.org/3/library/', label: 0, note: 'documentation' },
  { url: 'https://developer.mozilla.org/en-US/docs/Web/Security', label: 0, note: 'mdn docs' },
  { url: 'https://arxiv.org/abs/2301.00001', label: 0, note: 'research paper' },
  { url: 'https://scholar.google.com/', label: 0, note: 'academic search' },
  { url: 'https://www.wikipedia.org/wiki/Phishing', label: 0, note: 'encyclopedia' },
  { url: 'https://numpy.org/doc/stable/', label: 0, note: 'library docs' },
  { url: 'https://scikit-learn.org/stable/', label: 0, note: 'ml docs' },
  { url: 'https://nodejs.org/en/learn', label: 0, note: 'runtime docs' },
  { url: 'https://react.dev/reference/react', label: 0, note: 'framework docs' },
  { url: 'https://www.python.org/downloads/', label: 0, note: 'official download' },
  { url: 'https://fastapi.tiangolo.com/', label: 0, note: 'api framework' },
  { url: 'https://www.postgresql.org/docs/', label: 0, note: 'database docs' },
  { url: 'https://www.cloudflare.com/learning/', label: 0, note: 'security education' },

  // Malicious / Phishing / High-Risk (15)
  { url: 'http://192.168.1.1/login', label: 1, note: 'raw IP login' },
  { url: 'http://10.0.0.5/verify/account', label: 1, note: 'raw IP verify' },
  { url: 'http://secure-login-verify-example.com', label: 1, note: 'multi-keyword + HTTP' },
  { url: 'http://secure-bank-login-example.com', label: 1, note: 'bank lure + HTTP' },
  { url: 'https://paypal-security-verify-account.com/login', label: 1, note: 'brand impersonation' },
  { url: 'https://testsafebrowsing.appspot.com/s/phishing.html', label: 1, note: 'Safe Browsing phish' },
  { url: 'https://testsafebrowsing.appspot.com/s/malware.html', label: 1, note: 'Safe Browsing malware' },
  { url: 'https://xn--pypal-4ve.com/verify', label: 1, note: 'Punycode homograph' },
  { url: 'http://account-update-verify-billing.example.com/signin', label: 1, note: 'credential harvest' },
  { url: 'https://apple-id-verify-support.example.net/auth', label: 1, note: 'Apple brand spoof' },
  { url: 'http://microsoft-password-reset-urgent.example.com/otp', label: 1, note: 'Microsoft OTP lure' },
  { url: 'https://amazon-billing-suspended-confirm.example.org/login', label: 1, note: 'Amazon billing lure' },
  { url: 'http://chase-banking-kyc-update.example.com/signin', label: 1, note: 'banking KYC lure' },
  { url: 'https://metamask-wallet-recover-seed.example.xyz/claim', label: 1, note: 'crypto wallet lure' },
  { url: 'http://user@legit.example.com//auth/login?next=http://evil.test', label: 1, note: 'authority @ + redirect' },
];

console.log('=== ScamShield AI TypeScript Lexical Engine Evaluation & Benchmark ===');

let tp = 0;
let fp = 0;
let tn = 0;
let fn = 0;

for (const c of EVAL_SUITE) {
  const res = analyzeUrlLexically(c.url);
  const predictedMalicious = res.risk_score >= 40 ? 1 : 0; // SUSPICIOUS or HIGH flagged
  if (c.label === 1 && predictedMalicious === 1) tp++;
  else if (c.label === 0 && predictedMalicious === 1) fp++;
  else if (c.label === 0 && predictedMalicious === 0) tn++;
  else fn++;

  if (
    c.url === 'https://example.com' ||
    c.url === 'http://192.168.1.1/login' ||
    c.url === 'https://xn--pypal-4ve.com/verify' ||
    c.url === 'https://testsafebrowsing.appspot.com/s/phishing.html'
  ) {
    console.log(
      `[SAMPLE] ${res.url} -> score=${res.risk_score}/100 level=${res.risk_level} pred=${res.prediction} prob=${res.phishing_probability}`
    );
  }
}

const total = tp + fp + tn + fn;
const accuracy = ((tp + tn) / total) * 100;
const precision = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 0;
const recall = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 0;
const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

console.log(
  `[EVAL] 30-URL canonical suite (threshold >= 40): TP=${tp} FP=${fp} TN=${tn} FN=${fn} | Accuracy=${accuracy.toFixed(1)}% Precision=${precision.toFixed(1)}% Recall=${recall.toFixed(1)}% F1=${f1.toFixed(1)}%`
);

// Throughput & latency benchmark over 10,000 inferences
const N = 10_000;
const latencies = new Float64Array(N);
const tStart = performance.now();
for (let i = 0; i < N; i++) {
  const target = EVAL_SUITE[i % EVAL_SUITE.length].url;
  const t0 = performance.now();
  analyzeUrlLexically(target);
  latencies[i] = performance.now() - t0;
}
const totalMs = performance.now() - tStart;
latencies.sort();
const p50 = latencies[Math.floor(N * 0.5)];
const p95 = latencies[Math.floor(N * 0.95)];
const rps = (N / totalMs) * 1000;

console.log(
  `[BENCH] Lexical engine (${N} URLs): total=${totalMs.toFixed(2)} ms, p50=${p50.toFixed(4)} ms, p95=${p95.toFixed(4)} ms, throughput=${rps.toFixed(0)} URLs/s`
);
