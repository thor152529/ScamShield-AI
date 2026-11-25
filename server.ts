import { GoogleGenAI, ThinkingLevel, Type } from '@google/genai';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { IndicatorDetail, PredictionLabel, ScanResponse } from './src/types/scamshield';
import {
  analyzeUrlLexically,
  classifyRiskScore,
  isThreatIntelDomain,
  validateScanUrl,
} from './src/utils/urlAnalyzer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const FASTAPI_URL = process.env.FASTAPI_URL?.trim().replace(/\/+$/, '') || '';

function getGeminiClient(): GoogleGenAI | null {
  const key = process.env.GEMINI_API_KEY?.trim();
  if (!key || key === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey: key,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

async function enrichScanWithGemini(
  baseResult: ScanResponse
): Promise<ScanResponse> {
  const ai = getGeminiClient();
  if (!ai) {
    return baseResult;
  }

  try {
    const started = Date.now();
    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: [
        'Perform deep phishing and threat-intelligence analysis on this URL using domain reputation knowledge, threat-intelligence test domain awareness (e.g. testsafebrowsing.appspot.com, *.testing.google.test), brand-impersonation cues, and lexical structure.',
        'Do NOT invent live WHOIS dates or claim live TLS handshake probing occurred.',
        `URL: ${baseResult.url}`,
        `Hostname: ${baseResult.normalized_hostname}`,
        `Lexical baseline risk_score: ${baseResult.risk_score}/100 (${baseResult.risk_level})`,
        `Extracted features: ${JSON.stringify(baseResult.features)}`,
        `Baseline indicators: ${JSON.stringify(baseResult.indicators)}`,
      ].join('\n'),
      config: {
        systemInstruction:
          'You are a cybersecurity threat-intelligence URL analyst. Return strict JSON. Score known threat-intelligence or Safe Browsing test domains (like testsafebrowsing.appspot.com) and clear phishing/spoofing URLs at 90-100. Score shorteners or ambiguous links 40-69. Score well-known benign domains 0-30. Provide 2-4 specific concise threat indicators.',
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            risk_score: {
              type: Type.INTEGER,
              description: 'Overall threat risk score from 0 to 100.',
            },
            threat_category: {
              type: Type.STRING,
              description: 'One of: LEGITIMATE, SUSPICIOUS, PHISHING, MALICIOUS.',
            },
            indicators: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '2-4 specific threat-intelligence or lexical indicators observed.',
            },
            ssl_assessment: {
              type: Type.STRING,
              description: 'Concise 1-2 sentence SSL/TLS protocol security assessment.',
            },
            domain_age_assessment: {
              type: Type.STRING,
              description:
                'Concise 1-2 sentence assessment of domain structure, reputation cues, and registration risk without inventing WHOIS dates.',
            },
            recommendation: {
              type: Type.STRING,
              description: 'Clear 1-2 sentence safety recommendation for the user.',
            },
          },
          required: [
            'risk_score',
            'threat_category',
            'indicators',
            'ssl_assessment',
            'domain_age_assessment',
            'recommendation',
          ],
        },
      },
    });

    const rawText = (response.text ?? '').trim();
    if (!rawText) return baseResult;

    const parsed = JSON.parse(rawText) as {
      risk_score?: number;
      threat_category?: string;
      indicators?: string[];
      ssl_assessment?: string;
      domain_age_assessment?: string;
      recommendation?: string;
    };

    const aiScore = Number.isFinite(Number(parsed.risk_score))
      ? Math.round(Number(parsed.risk_score))
      : baseResult.risk_score;

    const threatIntelFloor = isThreatIntelDomain(baseResult.normalized_hostname) ? 95 : 0;
    const phishingFloor = baseResult.risk_score >= 90 ? 90 : 0;
    const updatedScore = Math.min(
      100,
      Math.max(4, threatIntelFloor, phishingFloor, aiScore)
    );

    const { risk_level, prediction: defaultPrediction } = classifyRiskScore(updatedScore);
    const rawCategory = (parsed.threat_category ?? '').trim().toUpperCase();
    const validCategories: PredictionLabel[] = ['LEGITIMATE', 'SUSPICIOUS', 'PHISHING', 'MALICIOUS'];
    const prediction: PredictionLabel = validCategories.includes(rawCategory as PredictionLabel)
      ? (rawCategory as PredictionLabel)
      : defaultPrediction;

    const existingLabels = new Set(baseResult.indicators.map((i) => i.toLowerCase()));
    const aiIndicators = Array.isArray(parsed.indicators)
      ? parsed.indicators
          .map((s) => String(s).trim())
          .filter((s) => s.length > 0 && !existingLabels.has(s.toLowerCase()))
      : [];

    const aiDetails: IndicatorDetail[] = aiIndicators.map((label) => ({
      label,
      severity: risk_level === 'HIGH' ? 'danger' : risk_level === 'SUSPICIOUS' ? 'warning' : 'info',
      explanation: 'Identified by Gemini AI threat-intelligence and URL pattern analysis.',
    }));

    const mergedDetails = [...aiDetails, ...(baseResult.indicator_details ?? [])].slice(0, 6);
    const mergedLabels = mergedDetails.map((d) => d.label);

    return {
      ...baseResult,
      risk_score: updatedScore,
      risk_level,
      prediction,
      phishing_probability: Math.max(
        baseResult.phishing_probability,
        Number((updatedScore / 100).toFixed(2))
      ),
      indicators: mergedLabels,
      indicator_details: mergedDetails,
      recommendation: parsed.recommendation?.trim() || baseResult.recommendation,
      ssl_analysis: baseResult.ssl_analysis
        ? {
            ...baseResult.ssl_analysis,
            summary: parsed.ssl_assessment?.trim() || baseResult.ssl_analysis.summary,
          }
        : undefined,
      domain_age_analysis: baseResult.domain_age_analysis
        ? {
            ...baseResult.domain_age_analysis,
            summary: parsed.domain_age_assessment?.trim() || baseResult.domain_age_analysis.summary,
          }
        : undefined,
      engine: 'Gemini AI Threat Engine (gemini-4-hydrogen) + Lexical Analyzer',
      latency_ms: (baseResult.latency_ms ?? 1) + (Date.now() - started),
    };
  } catch {
    return baseResult;
  }
}

async function createServer() {
  const app = express();
  app.use(express.json({ limit: '64kb' }));

  app.get('/api/health', async (_req, res) => {
    if (FASTAPI_URL) {
      try {
        const upstream = await fetch(`${FASTAPI_URL}/api/health`, {
          signal: AbortSignal.timeout(3000),
        });
        if (upstream.ok) {
          const data = await upstream.json();
          res.json({ ...data, proxied_from: FASTAPI_URL });
          return;
        }
      } catch {
        // Fall through to integrated engine status
      }
    }

    res.json({
      status: 'ok',
      service: 'ScamShield AI',
      mode: getGeminiClient() ? 'gemini-plus-lexical' : 'integrated-ml-engine',
      model_loaded: true,
      gemini_enabled: Boolean(getGeminiClient()),
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/model-info', async (_req, res) => {
    if (FASTAPI_URL) {
      try {
        const upstream = await fetch(`${FASTAPI_URL}/api/model-info`, {
          signal: AbortSignal.timeout(3000),
        });
        if (upstream.ok) {
          const data = await upstream.json();
          res.json(data);
          return;
        }
      } catch {
        // Fall through to integrated metadata
      }
    }

    res.json({
      model_name: 'ScamShield Lexical Random Forest + Gemini AI Fallback',
      algorithm: 'RandomForestClassifier + gemini-4-hydrogen contextual analysis',
      dataset: 'Malicious URLs Dataset (Kaggle sid321axn · 651,191 labeled records)',
      training_samples: 60000,
      features: [
        'url_length',
        'hostname_length',
        'dot_count',
        'hyphen_count',
        'has_ip_address',
        'has_https',
        'subdomain_count',
        'suspicious_keyword_count',
        'has_punycode',
        'is_shortener',
      ],
      thresholds: {
        low: '0–39 (LOW)',
        suspicious: '40–69 (SUSPICIOUS)',
        high: '70–100 (HIGH)',
      },
      limitations:
        'Performs lexical URL analysis and AI pattern assessment. Does not perform live WHOIS queries, DNS reputation checks, or remote webpage scraping.',
      status: 'ready',
    });
  });

  app.post('/api/scan', async (req, res) => {
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
    const validation = validateScanUrl(rawUrl);

    if (!validation.valid) {
      res.status(400).json({
        detail: validation.error || 'Invalid URL provided.',
      });
      return;
    }

    if (FASTAPI_URL) {
      try {
        const upstream = await fetch(`${FASTAPI_URL}/api/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: validation.normalizedUrl }),
          signal: AbortSignal.timeout(5000),
        });
        if (upstream.ok) {
          const payload = await upstream.json();
          res.json(payload);
          return;
        }
      } catch {
        // Fall through to Gemini + lexical fallback
      }
    }

    try {
      const lexicalResult = analyzeUrlLexically(validation.normalizedUrl);
      const enriched = await enrichScanWithGemini(lexicalResult);
      res.json(enriched);
    } catch (error) {
      res.status(400).json({
        detail: error instanceof Error ? error.message : 'Unable to analyze URL.',
      });
    }
  });

  app.post('/api/gemini-scan', async (req, res) => {
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
    const validation = validateScanUrl(rawUrl);

    if (!validation.valid) {
      res.status(400).json({
        detail: validation.error || 'Invalid URL provided.',
      });
      return;
    }

    try {
      const lexicalResult = analyzeUrlLexically(validation.normalizedUrl);
      const enriched = await enrichScanWithGemini(lexicalResult);
      res.json(enriched);
    } catch (error) {
      res.status(400).json({
        detail: error instanceof Error ? error.message : 'Unable to analyze URL.',
      });
    }
  });

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ScamShield AI server listening on http://0.0.0.0:${PORT}`);
  });
}

createServer().catch((err) => {
  console.error('Failed to start ScamShield AI server:', err);
  process.exit(1);
});
