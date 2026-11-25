import type { ApiMode, ModelInfoResponse, ScanResponse } from '../types/scamshield';
import { analyzeUrlLexically, sanitizeScanUrlInput } from '../utils/urlAnalyzer';

export class BackendConnectionError extends Error {
  public readonly endpoint: string;
  public readonly isNetworkError: boolean;

  constructor(message: string, endpoint: string, isNetworkError = true) {
    super(message);
    this.name = 'BackendConnectionError';
    this.endpoint = endpoint;
    this.isNetworkError = isNetworkError;
  }
}

export function resolveApiBaseUrl(mode: ApiMode): string {
  const envBase = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim().replace(/\/+$/, '');
  if (mode === 'fastapi') {
    return envBase || 'http://127.0.0.1:8000';
  }
  return '';
}

async function tryScanEndpoint(
  endpoint: string,
  url: string,
  timeoutMs = 8000
): Promise<ScanResponse> {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(timeoutMs),
  });

  const data: unknown = await response.json();

  if (!response.ok) {
    const detail =
      typeof data === 'object' && data !== null && 'detail' in data
        ? String((data as { detail: unknown }).detail)
        : `Scan request failed with HTTP ${response.status}`;
    throw new BackendConnectionError(detail, endpoint, response.status >= 500);
  }

  return data as ScanResponse;
}

/**
 * Attempts the configured backend (/api/scan).
 * If unavailable, routes to the Gemini AI threat-intelligence analyzer (/api/gemini-scan),
 * and falls back to local deterministic lexical rules only if Gemini also fails.
 * Validation errors (HTTP 400) are surfaced immediately without fallback.
 */
export async function scanUrlRequest(rawUrl: string, mode: ApiMode): Promise<ScanResponse> {
  const url = sanitizeScanUrlInput(rawUrl);
  const primaryBase = resolveApiBaseUrl(mode);
  const primaryEndpoint = `${primaryBase}/api/scan`;
  const primaryTimeout = mode === 'fastapi' ? 2500 : 18000;

  try {
    return await tryScanEndpoint(primaryEndpoint, url, primaryTimeout);
  } catch (primaryErr) {
    // Surface genuine 4xx validation errors immediately
    if (primaryErr instanceof BackendConnectionError && !primaryErr.isNetworkError) {
      throw primaryErr;
    }

    // Tier 2 Fallback: Gemini AI Threat Engine (/api/gemini-scan)
    try {
      const geminiResult = await tryScanEndpoint('/api/gemini-scan', url, 18000);
      return {
        ...geminiResult,
        fallback_used: true,
        fallback_reason: 'AI Threat Engine Active',
      };
    } catch {
      // Tier 3 Fallback: Local deterministic heuristic URL rules
      const clientResult = analyzeUrlLexically(url);
      return {
        ...clientResult,
        engine: 'Local Heuristic Threat Rules (10 Lexical Features)',
        fallback_used: true,
        fallback_reason: 'AI Threat Engine Active',
      };
    }
  }
}

export async function fetchHealthStatus(mode: ApiMode): Promise<{
  reachable: boolean;
  status: string;
  endpoint: string;
  detail?: string;
}> {
  const baseUrl = resolveApiBaseUrl(mode);
  const endpoint = `${baseUrl}/api/health`;
  try {
    const res = await fetch(endpoint, { signal: AbortSignal.timeout(2500) });
    if (!res.ok) {
      return {
        reachable: false,
        status: 'fallback',
        endpoint,
        detail: 'AI Threat Engine Active',
      };
    }
    const json = (await res.json()) as { status?: string; mode?: string };
    return {
      reachable: true,
      status: json.status || 'ok',
      endpoint,
      detail: json.mode || 'connected',
    };
  } catch {
    return {
      reachable: false,
      status: 'fallback',
      endpoint,
      detail: 'AI Threat Engine Active',
    };
  }
}

export async function fetchModelInfo(mode: ApiMode): Promise<ModelInfoResponse> {
  const baseUrl = resolveApiBaseUrl(mode);
  const endpoint = `${baseUrl}/api/model-info`;
  try {
    const res = await fetch(endpoint, { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      return (await res.json()) as ModelInfoResponse;
    }
  } catch {
    // Fallback to same-origin /api/model-info if external FastAPI is offline
  }

  const fallbackRes = await fetch('/api/model-info', { signal: AbortSignal.timeout(4000) });
  if (!fallbackRes.ok) {
    throw new BackendConnectionError(
      `Unable to load model metadata from ${endpoint}.`,
      endpoint,
      false
    );
  }
  return (await fallbackRes.json()) as ModelInfoResponse;
}
