import type { PageRoute } from '../types/scamshield';
import { ShieldMark } from './Navbar';

interface FooterProps {
  onNavigate: (page: PageRoute) => void;
}

export function Footer({ onNavigate }: FooterProps) {
  return (
    <footer className="border-t border-[#91A5B8]/15 bg-[#07111F] py-10">
      <div className="mx-auto flex max-w-[1200px] flex-col gap-6 px-4 sm:px-6 md:flex-row md:items-center md:justify-between lg:px-8">
        <div>
          <div className="flex items-center gap-2 font-display text-base font-bold text-[#EAF0F7]">
            <ShieldMark className="h-6 w-6" />
            <span>ScamShield AI</span>
          </div>
          <p className="mt-1.5 text-xs text-[#91A5B8]">
            Detect Threats. Browse Smarter. · Lexical URL analysis only—always verify unfamiliar
            links independently.
          </p>
        </div>

        <nav aria-label="Footer navigation" className="flex flex-wrap items-center gap-5 text-xs text-[#91A5B8]">
          {(
            [
              { id: 'home', label: 'Home' },
              { id: 'scanner', label: 'URL Scanner' },
              { id: 'dashboard', label: 'Dashboard' },
              { id: 'how-it-works', label: 'How It Works' },
              { id: 'about', label: 'About' },
            ] as { id: PageRoute; label: string }[]
          ).map((item) => (
            <a
              key={item.id}
              href={`#${item.id}`}
              onClick={(e) => {
                e.preventDefault();
                onNavigate(item.id);
              }}
              className="hover:text-[#EAF0F7] transition-colors"
            >
              {item.label}
            </a>
          ))}
        </nav>
      </div>
    </footer>
  );
}
