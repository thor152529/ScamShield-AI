import { useEffect, useState, type FormEvent, type RefObject } from 'react';
import {
  AlertCircle,
  Loader2,
  RefreshCw,
  Search,
  Server,
  Shield,
  Terminal,
  Trash2,
} from 'lucide-react';
import {
  BackendConnectionError,
  fetchHealthStatus,
  resolveApiBaseUrl,
} from '../services/api';
import { DEMO_SAMPLE_URLS, SAMPLE_URL_PRESETS } from '../utils/demoData';
import { sanitizeScanUrlInput, validateScanUrl } from '../utils/urlAnalyzer';
import type { ApiMode, ScanResponse } from '../types/scamshield';
import { ScanResult } from './ScanResult';

interface URLScannerProps {
  inputUrl: string;
  inputRef?: RefObject<HTMLInputElement | null>;
  onInputChange: (val: string) => void;
  apiMode: ApiMode;
  onApiModeChange: (mode: ApiMode) => void;
  isScanning: boolean;
  scanError: string | null;
  backendError: BackendConnectionError | null;
  currentResult: ScanResponse | null;
  onRunScan: (url: string) => Promise<void>;
  onClearScan: () => void;
}

export function URLScanner({
  inputUrl,
  inputRef,
  onInputChange,
  apiMode,
  onApiModeChange,
  isScanning,
  scanError,
  backendError,
  currentResult,
  onRunScan,
  onClearScan,
}: URLScannerProps) {
  const [localError, setLocalError] = useState<string | null>(null);
  const [health, setHealth] = useState<{
    checking: boolean;
    reachable: boolean;
    detail: string;
    endpoint: string;
  }>({
    checking: true,
    reachable: false,
    detail: 'Checking backend...',
    endpoint: '',
  });

  const checkBackend = async (mode: ApiMode) => {
    setHealth((prev) => ({ ...prev, checking: true }));
    const res = await fetchHealthStatus(mode);
    setHealth({
      checking: false,
      reachable: res.reachable,
      detail: res.reachable
        ? `Connected (${res.detail ?? 'ready'})`
        : `${res.detail ?? 'AI Threat Engine Active'}`,
      endpoint: res.endpoint,
    });
  };

  useEffect(() => {
    void checkBackend(apiMode);
  }, [apiMode]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const validation = validateScanUrl(inputUrl);
    if (!validation.valid) {
      setLocalError(validation.error ?? 'Please enter a valid http:// or https:// URL.');
      return;
    }
    setLocalError(null);
    onInputChange(validation.normalizedUrl);
    await onRunScan(validation.normalizedUrl);
  };

  const handlePresetClick = async (presetUrl: string) => {
    onInputChange(presetUrl);
    setLocalError(null);
    await onRunScan(presetUrl);
  };

  const activeError = localError || scanError;

  return (
    <div className="mx-auto max-w-[1200px] space-y-8 px-4 py-10 sm:px-6 lg:px-8">
      {/* Scanner Header & API Target Switcher */}
      <div className="flex flex-col gap-4 border-b border-[#91A5B8]/15 pb-6 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-[#EAF0F7] sm:text-3xl">
            URL Threat Scanner
          </h1>
          <p className="mt-2 max-w-[65ch] text-sm text-[#91A5B8] sm:text-base">
            Submit any HTTP or HTTPS link for lexical feature extraction, Random Forest probability
            inference, and explainable risk scoring. Submitted URLs are never fetched or executed.
          </p>
        </div>

        {/* Backend Endpoint Selector */}
        <div className="flex flex-col items-start gap-2 md:items-end">
          <div
            className="inline-flex items-center gap-1 rounded-lg border border-[#91A5B8]/20 bg-[#101E30] p-1"
            role="group"
            aria-label="Backend engine target"
          >
            <button
              type="button"
              onClick={() => onApiModeChange('integrated')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                apiMode === 'integrated'
                  ? 'bg-[#35C7AD] text-[#07111F]'
                  : 'text-[#91A5B8] hover:text-[#EAF0F7]'
              }`}
            >
              Integrated API (/api/scan)
            </button>
            <button
              type="button"
              onClick={() => onApiModeChange('fastapi')}
              className={`rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                apiMode === 'fastapi'
                  ? 'bg-[#35C7AD] text-[#07111F]'
                  : 'text-[#91A5B8] hover:text-[#EAF0F7]'
              }`}
            >
              Local FastAPI (127.0.0.1:8000)
            </button>
          </div>

          <div className="flex items-center gap-2 text-xs text-[#91A5B8]">
            {health.checking ? (
              <>
                <Server className="h-3.5 w-3.5 text-[#45D6BB]" aria-hidden="true" />
                <span className="text-[#91A5B8]">Checking API health...</span>
              </>
            ) : health.reachable ? (
              <>
                <Server className="h-3.5 w-3.5 text-[#35C7AD]" aria-hidden="true" />
                <span className="text-[#35C7AD]">{health.detail}</span>
              </>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-400/40 bg-emerald-500/12 px-2.5 py-0.5 text-xs font-medium text-emerald-300">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shrink-0" aria-hidden="true" />
                <span>{health.detail}</span>
              </span>
            )}
            <button
              type="button"
              onClick={() => void checkBackend(apiMode)}
              aria-label="Refresh backend connection status"
              className="rounded p-1 text-[#91A5B8] hover:text-[#EAF0F7] cursor-pointer"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Scan Input Card */}
      <div className="rounded-2xl border border-[#91A5B8]/20 bg-[#101E30] p-6 sm:p-8">
        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="scanner-url-input"
              className="text-sm font-medium text-[#EAF0F7]"
            >
              Website URL to Analyze
            </label>
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[#91A5B8]"
                  aria-hidden="true"
                />
                <input
                  id="scanner-url-input"
                  ref={inputRef}
                  type="text"
                  inputMode="url"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  value={inputUrl}
                  onPaste={(e) => {
                    const pasted = e.clipboardData.getData('text');
                    const sanitized = sanitizeScanUrlInput(pasted);
                    if (sanitized && sanitized !== pasted) {
                      e.preventDefault();
                      onInputChange(sanitized);
                      if (localError) setLocalError(null);
                    }
                  }}
                  onChange={(e) => {
                    onInputChange(e.target.value);
                    if (localError) setLocalError(null);
                  }}
                  placeholder="https://example.com"
                  className="min-h-[46px] w-full rounded-lg border border-[#91A5B8]/25 bg-[#07111F] pl-10 pr-4 font-mono text-sm text-[#EAF0F7] placeholder:text-[#91A5B8]/60 focus:border-[#35C7AD] focus:outline-none"
                  aria-describedby={activeError ? 'scanner-error-msg' : undefined}
                />
              </div>

              <div className="flex items-center gap-2.5 shrink-0">
                <button
                  type="submit"
                  disabled={isScanning}
                  className="inline-flex min-h-[46px] items-center justify-center gap-2 rounded-lg bg-[#35C7AD] px-6 py-2.5 text-sm font-semibold text-[#07111F] whitespace-nowrap shrink-0 transition-colors hover:bg-[#45D6BB] disabled:opacity-60 cursor-pointer"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                      <span>Scanning...</span>
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4" aria-hidden="true" />
                      <span>Scan URL</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setLocalError(null);
                    onClearScan();
                  }}
                  aria-label="Clear URL and scan result"
                  className="inline-flex min-h-[46px] items-center justify-center gap-1.5 rounded-lg border border-[#91A5B8]/25 bg-[#07111F] px-4 py-2.5 text-sm font-medium text-[#91A5B8] whitespace-nowrap shrink-0 transition-colors hover:border-[#91A5B8]/50 hover:text-[#EAF0F7] cursor-pointer"
                >
                  <Trash2 className="h-4 w-4" aria-hidden="true" />
                  <span>Clear</span>
                </button>
              </div>
            </div>
          </div>

          {activeError && !backendError?.isNetworkError && (
            <div
              id="scanner-error-msg"
              role="alert"
              className="flex items-start gap-2.5 rounded-lg border border-[#FF6878]/35 bg-[#FF6878]/10 px-4 py-3 text-sm text-[#FF6878]"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{activeError}</span>
            </div>
          )}

          {/* 3 Clickable "Try Sample URL" One-Click Demo Buttons */}
          <div className="border-t border-[#91A5B8]/15 pt-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-medium text-[#EAF0F7]">
                Try Sample URL — One-Click Demo
              </span>
              <span className="text-xs text-[#91A5B8]">
                Safe synthetic inputs — inspected lexically without visiting
              </span>
            </div>

            <div
              data-testid="sample-url-buttons"
              className="grid grid-cols-1 gap-3 md:grid-cols-3"
            >
              {DEMO_SAMPLE_URLS.map((sample) => {
                const toneStyle =
                  sample.tone === 'low'
                    ? {
                        border: 'border-[#35C7AD]/35 hover:border-[#35C7AD]/70',
                        badge: 'text-[#35C7AD]',
                        shortLabel: 'Safe',
                        rangeLabel: '0–39 Low',
                      }
                    : sample.tone === 'suspicious'
                      ? {
                          border: 'border-[#F3B94F]/35 hover:border-[#F3B94F]/70',
                          badge: 'text-[#F3B94F]',
                          shortLabel: 'Suspicious',
                          rangeLabel: '40–69 Warn',
                        }
                      : {
                          border: 'border-[#FF6878]/35 hover:border-[#FF6878]/70',
                          badge: 'text-[#FF6878]',
                          shortLabel: 'Phishing',
                          rangeLabel: '70–100 High',
                        };

                return (
                  <button
                    key={sample.id}
                    type="button"
                    data-testid={`try-sample-${sample.id}`}
                    aria-label={`Try Sample URL: ${sample.buttonLabel} (${sample.url})`}
                    disabled={isScanning}
                    onClick={() => void handlePresetClick(sample.url)}
                    className={`flex min-h-[56px] flex-col justify-between rounded-xl border bg-[#07111F] px-4 py-3 text-left transition-colors disabled:opacity-50 cursor-pointer ${toneStyle.border}`}
                  >
                    <div className="flex w-full items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-[#EAF0F7] whitespace-nowrap shrink-0">
                        Try Sample URL: {toneStyle.shortLabel}
                      </span>
                      <span
                        className={`font-mono text-[11px] font-medium whitespace-nowrap shrink-0 tabular-nums ${toneStyle.badge}`}
                      >
                        {toneStyle.rangeLabel}
                      </span>
                    </div>
                    <span className="mt-1.5 w-full truncate font-mono text-xs text-[#91A5B8]">
                      {sample.url}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Secondary Edge-Case Presets (IP / Punycode / Keyword) */}
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-[#91A5B8]">
              <span>Additional patterns:</span>
              {SAMPLE_URL_PRESETS.filter(
                (p) => !DEMO_SAMPLE_URLS.some((d) => d.url === p.url)
              ).map((preset) => (
                <button
                  key={preset.url}
                  type="button"
                  disabled={isScanning}
                  onClick={() => void handlePresetClick(preset.url)}
                  className="font-mono text-xs text-[#91A5B8] underline-offset-4 transition-colors hover:text-[#45D6BB] hover:underline disabled:opacity-50 cursor-pointer"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
        </form>
      </div>

      {/* Backend Connection Error & FastAPI Startup Instructions */}
      {backendError?.isNetworkError && (
        <div
          role="alert"
          data-testid="backend-connection-error"
          className="space-y-4 rounded-2xl border border-[#FF6878]/40 bg-[#101E30] p-6"
        >
          <div className="flex items-start gap-3">
            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-[#FF6878]" aria-hidden="true" />
            <div>
              <h2 className="font-display text-lg font-semibold text-[#EAF0F7]">
                Backend API Connection Error
              </h2>
              <p className="mt-1 text-sm text-[#91A5B8]">{backendError.message}</p>
              <p className="mt-1 text-xs text-[#91A5B8]">
                ScamShield AI never fabricates a passing scan when the selected backend is offline.
              </p>
            </div>
          </div>

          <div className="rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#45D6BB]">
              <Terminal className="h-4 w-4" aria-hidden="true" />
              <span>Start the Local Python FastAPI Backend (Windows PowerShell):</span>
            </div>
            <pre className="mt-2.5 overflow-x-auto font-mono text-xs leading-relaxed text-[#EAF0F7]">
{`cd backend
.venv\\Scripts\\Activate.ps1
uvicorn main:app --reload`}
            </pre>
            <p className="mt-2 text-xs text-[#91A5B8]">
              Target endpoint: <code className="text-[#EAF0F7]">{resolveApiBaseUrl(apiMode)}/api/scan</code>
            </p>
          </div>

          {apiMode === 'fastapi' && (
            <button
              type="button"
              onClick={() => onApiModeChange('integrated')}
              className="inline-flex min-h-[40px] items-center gap-2 rounded-lg bg-[#35C7AD] px-4 py-2 text-sm font-semibold text-[#07111F] hover:bg-[#45D6BB] cursor-pointer"
            >
              Switch to Integrated ML API (/api/scan)
            </button>
          )}
        </div>
      )}

      {/* Loading State */}
      {isScanning && (
        <div
          aria-live="polite"
          className="relative overflow-hidden rounded-2xl border border-[#35C7AD]/30 bg-[#101E30] p-8 text-center"
        >
          <div className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-[#35C7AD]/15 to-transparent animate-scan-beam" />
          <Loader2 className="mx-auto h-8 w-8 animate-spin text-[#35C7AD]" aria-hidden="true" />
          <h2 className="mt-4 font-display text-lg font-semibold text-[#EAF0F7]">
            Extracting Lexical Features & Evaluating Random Forest Model
          </h2>
          <p className="mt-1.5 text-sm text-[#91A5B8]">
            Analyzing URL structure, hostname complexity, protocol indicators, and phishing tokens...
          </p>
        </div>
      )}

      {/* Result Display or Idle Empty State */}
      {!isScanning && currentResult && (
        <ScanResult result={currentResult} onClear={onClearScan} />
      )}

      {!isScanning && !currentResult && !backendError?.isNetworkError && (
        <div className="rounded-2xl border border-[#91A5B8]/15 bg-[#101E30]/60 p-8 text-center">
          <Shield className="mx-auto h-9 w-9 text-[#35C7AD]/70" aria-hidden="true" />
          <h2 className="mt-3 font-display text-lg font-semibold text-[#EAF0F7]">
            Ready to Inspect a URL
          </h2>
          <p className="mx-auto mt-1.5 max-w-[54ch] text-sm text-[#91A5B8]">
            Paste any <code className="text-[#EAF0F7]">http://</code> or{' '}
            <code className="text-[#EAF0F7]">https://</code> link above or choose one of the
            synthetic test cases to inspect the full risk score and explainable indicators.
          </p>
        </div>
      )}
    </div>
  );
}
