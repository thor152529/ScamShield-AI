import { useEffect, useRef, useState } from 'react';
import { About } from './components/About';
import { Dashboard } from './components/Dashboard';
import { Footer } from './components/Footer';
import { Hero } from './components/Hero';
import { HowItWorks } from './components/HowItWorks';
import { Navbar } from './components/Navbar';
import { URLScanner } from './components/URLScanner';
import { BackendConnectionError, scanUrlRequest } from './services/api';
import type {
  ApiMode,
  PageRoute,
  ScanHistoryItem,
  ScanResponse,
} from './types/scamshield';
import { buildDemoBenchmarkHistory } from './utils/demoData';
import { sanitizeScanUrlInput } from './utils/urlAnalyzer';

const HISTORY_STORAGE_KEY = 'scamshield.scanHistory.v2';

const VALID_PAGES: PageRoute[] = [
  'home',
  'scanner',
  'dashboard',
  'how-it-works',
  'about',
];

function getInitialPage(): PageRoute {
  if (typeof window === 'undefined') return 'home';
  const params = new URLSearchParams(window.location.search);
  if (params.get('autostart') === '1') return 'scanner';
  const hash = window.location.hash.replace('#', '') as PageRoute;
  if (VALID_PAGES.includes(hash)) return hash;
  return 'home';
}

function loadStoredHistory(): ScanHistoryItem[] {
  if (typeof window === 'undefined') return buildDemoBenchmarkHistory();
  try {
    const raw = window.localStorage.getItem(HISTORY_STORAGE_KEY);
    if (raw === null) {
      return buildDemoBenchmarkHistory();
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ScanHistoryItem[]) : buildDemoBenchmarkHistory();
  } catch {
    return buildDemoBenchmarkHistory();
  }
}

export default function App() {
  const [currentPage, setCurrentPage] = useState<PageRoute>(getInitialPage);
  const [apiMode, setApiMode] = useState<ApiMode>('integrated');
  const [scannerInput, setScannerInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [backendError, setBackendError] = useState<BackendConnectionError | null>(null);
  const [currentResult, setCurrentResult] = useState<ScanResponse | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>(loadStoredHistory);
  const [focusScannerTrigger, setFocusScannerTrigger] = useState(0);
  const scannerInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    try {
      window.localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
    } catch {
      // Ignore storage quota errors
    }
  }, [history]);

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '') as PageRoute;
      if (VALID_PAGES.includes(hash)) {
        setCurrentPage(hash);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  useEffect(() => {
    if (focusScannerTrigger === 0 || currentPage !== 'scanner') return;
    const raf = window.requestAnimationFrame(() => {
      const target =
        scannerInputRef.current ??
        (document.getElementById('scanner-url-input') as HTMLInputElement | null);
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
        target.focus({ preventScroll: true });
      }
    });
    return () => window.cancelAnimationFrame(raf);
  }, [currentPage, focusScannerTrigger]);

  const navigateTo = (page: PageRoute) => {
    setCurrentPage(page);
    if (window.location.hash !== `#${page}`) {
      window.history.pushState(null, '', `#${page}`);
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleGetStarted = () => {
    setCurrentPage('scanner');
    if (window.location.hash !== '#scanner') {
      window.history.pushState(null, '', '#scanner');
    }
    setFocusScannerTrigger((n) => n + 1);
  };

  const runScan = async (urlToScan: string) => {
    setIsScanning(true);
    setScanError(null);
    setBackendError(null);

    try {
      const result = await scanUrlRequest(urlToScan, apiMode);
      setCurrentResult(result);

      const newEntry: ScanHistoryItem = {
        ...result,
        id:
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `scan-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
        scanned_at: result.scanned_at || new Date().toISOString(),
        is_demo: false,
      };
      setHistory((prev) => [newEntry, ...prev].slice(0, 100));
    } catch (err) {
      setCurrentResult(null);
      if (err instanceof BackendConnectionError) {
        setBackendError(err);
        setScanError(err.message);
      } else {
        setScanError(err instanceof Error ? err.message : 'Unexpected scan error.');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const handleScanFromHero = (url: string) => {
    const clean = sanitizeScanUrlInput(url);
    setScannerInput(clean);
    navigateTo('scanner');
    void runScan(clean);
  };

  const handleClearScan = () => {
    setScannerInput('');
    setCurrentResult(null);
    setScanError(null);
    setBackendError(null);
  };

  const handleInspectHistoryItem = (item: ScanHistoryItem) => {
    setScannerInput(item.url);
    setCurrentResult(item);
    setScanError(null);
    setBackendError(null);
    navigateTo('scanner');
  };

  const handleDeleteHistoryItem = (id: string) => {
    setHistory((prev) => prev.filter((item) => item.id !== id));
  };

  const handleClearAllHistory = () => {
    setHistory([]);
  };

  const handleLoadDemoData = () => {
    setHistory(buildDemoBenchmarkHistory());
  };

  const handleApiModeChange = (mode: ApiMode) => {
    setApiMode(mode);
    setScanError(null);
    setBackendError(null);
  };

  return (
    <div className="flex min-h-screen flex-col bg-[#07111F] text-[#EAF0F7]">
      <Navbar
        currentPage={currentPage}
        onNavigate={navigateTo}
        onGetStarted={handleGetStarted}
      />

      <main className="flex-1">
        {currentPage === 'home' && (
          <Hero onScanFromHero={handleScanFromHero} onNavigate={navigateTo} />
        )}

        {currentPage === 'scanner' && (
          <URLScanner
            inputUrl={scannerInput}
            inputRef={scannerInputRef}
            onInputChange={setScannerInput}
            apiMode={apiMode}
            onApiModeChange={handleApiModeChange}
            isScanning={isScanning}
            scanError={scanError}
            backendError={backendError}
            currentResult={currentResult}
            onRunScan={runScan}
            onClearScan={handleClearScan}
          />
        )}

        {currentPage === 'dashboard' && (
          <Dashboard
            history={history}
            onNavigate={navigateTo}
            onInspectItem={handleInspectHistoryItem}
            onDeleteItem={handleDeleteHistoryItem}
            onClearAll={handleClearAllHistory}
            onLoadDemoData={handleLoadDemoData}
          />
        )}

        {currentPage === 'how-it-works' && <HowItWorks onNavigate={navigateTo} />}

        {currentPage === 'about' && (
          <About apiMode={apiMode} onNavigate={navigateTo} />
        )}
      </main>

      <Footer onNavigate={navigateTo} />
    </div>
  );
}
