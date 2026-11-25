import { useState } from 'react';
import { Menu, X } from 'lucide-react';
import type { PageRoute } from '../types/scamshield';

interface NavbarProps {
  currentPage: PageRoute;
  onNavigate: (page: PageRoute) => void;
  onGetStarted: () => void;
}

const NAV_ITEMS: { id: PageRoute; label: string }[] = [
  { id: 'home', label: 'Home' },
  { id: 'scanner', label: 'URL Scanner' },
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'how-it-works', label: 'How It Works' },
  { id: 'about', label: 'About' },
];

export function ShieldMark({ className = 'w-7 h-7' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <path
        d="M18 3L5 8.25V17.25C5 25.4 10.55 32.65 18 34.5C25.45 32.65 31 25.4 31 17.25V8.25L18 3Z"
        fill="#101E30"
        stroke="#35C7AD"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M18 7.5L9.5 11V17.2C9.5 22.85 13.15 27.95 18 29.55C22.85 27.95 26.5 22.85 26.5 17.2V11L18 7.5Z"
        fill="#35C7AD"
        fillOpacity="0.14"
      />
      <path
        d="M13.5 18.2L16.5 21.2L22.8 14.5"
        stroke="#45D6BB"
        strokeWidth="2.25"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Navbar({ currentPage, onNavigate, onGetStarted }: NavbarProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleNav = (page: PageRoute) => {
    onNavigate(page);
    setMobileOpen(false);
  };

  const handleGetStartedClick = () => {
    setMobileOpen(false);
    onGetStarted();
  };

  return (
    <header className="sticky top-0 z-40 border-b border-[#91A5B8]/15 bg-[#07111F]/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-[1200px] items-center justify-between gap-8 px-4 sm:px-6 lg:px-8">
        {/* Zone 1: Single-line Brand Wordmark */}
        <a
          href="#home"
          onClick={(e) => {
            e.preventDefault();
            handleNav('home');
          }}
          className="flex items-center gap-2.5 whitespace-nowrap shrink-0 font-display text-lg font-bold tracking-tight text-[#EAF0F7] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#35C7AD] rounded-md"
        >
          <ShieldMark className="h-7 w-7 shrink-0" />
          <span>ScamShield AI</span>
        </a>

        {/* Zone 2: 5 Single-Line Navigation Links */}
        <nav aria-label="Primary navigation" className="hidden md:flex items-center gap-7">
          {NAV_ITEMS.map((item) => {
            const active = currentPage === item.id;
            return (
              <a
                key={item.id}
                href={`#${item.id}`}
                onClick={(e) => {
                  e.preventDefault();
                  handleNav(item.id);
                }}
                aria-current={active ? 'page' : undefined}
                className={`relative py-1 text-sm font-medium whitespace-nowrap shrink-0 transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#35C7AD] rounded-sm ${
                  active
                    ? 'text-[#45D6BB]'
                    : 'text-[#91A5B8] hover:text-[#EAF0F7]'
                }`}
              >
                {item.label}
                {active && (
                  <span
                    aria-hidden="true"
                    className="absolute inset-x-0 -bottom-[19px] h-0.5 bg-[#35C7AD]"
                  />
                )}
              </a>
            );
          })}
        </nav>

        {/* Zone 3: 1 Primary CTA + Mobile Toggle */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={handleGetStartedClick}
            className="hidden sm:inline-flex items-center justify-center rounded-lg bg-[#35C7AD] px-4 py-2 text-sm font-semibold text-[#07111F] whitespace-nowrap shrink-0 transition-colors duration-150 hover:bg-[#45D6BB] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#45D6BB] focus-visible:ring-offset-2 focus-visible:ring-offset-[#07111F] cursor-pointer"
          >
            Get Started
          </button>

          <button
            type="button"
            onClick={() => setMobileOpen((prev) => !prev)}
            aria-expanded={mobileOpen}
            aria-label={mobileOpen ? 'Close navigation menu' : 'Open navigation menu'}
            className="inline-flex md:hidden items-center justify-center rounded-lg border border-[#91A5B8]/20 bg-[#101E30] p-2 text-[#EAF0F7] hover:border-[#35C7AD]/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#35C7AD] min-h-[40px] min-w-[40px]"
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <nav
          aria-label="Mobile navigation"
          className="border-t border-[#91A5B8]/15 bg-[#07111F] px-4 py-3 md:hidden"
        >
          <div className="flex flex-col gap-1">
            {NAV_ITEMS.map((item) => {
              const active = currentPage === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleNav(item.id)}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-sm font-medium transition-colors min-h-[44px] ${
                    active
                      ? 'bg-[#101E30] text-[#45D6BB]'
                      : 'text-[#91A5B8] hover:bg-[#101E30]/60 hover:text-[#EAF0F7]'
                  }`}
                >
                  <span>{item.label}</span>
                </button>
              );
            })}
            <button
              type="button"
              onClick={handleGetStartedClick}
              className="mt-2 w-full rounded-lg bg-[#35C7AD] px-4 py-2.5 text-sm font-semibold text-[#07111F] min-h-[44px]"
            >
              Get Started
            </button>
          </div>
        </nav>
      )}
    </header>
  );
}
