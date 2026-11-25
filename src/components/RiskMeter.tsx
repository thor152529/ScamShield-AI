import type { RiskLevel } from '../types/scamshield';

interface RiskMeterProps {
  score: number;
  riskLevel: RiskLevel;
}

function polarToCartesian(cx: number, cy: number, r: number, scoreVal: number) {
  const rad = Math.PI * (1 - scoreVal / 100);
  return {
    x: cx + r * Math.cos(rad),
    y: cy - r * Math.sin(rad),
  };
}

function describeScoreArc(
  cx: number,
  cy: number,
  r: number,
  startScore: number,
  endScore: number
) {
  const start = polarToCartesian(cx, cy, r, startScore);
  const end = polarToCartesian(cx, cy, r, endScore);
  // A 0..100 semi-circle spans at most 180 degrees, so largeArcFlag is always 0.
  return `M ${start.x.toFixed(2)} ${start.y.toFixed(2)} A ${r} ${r} 0 0 1 ${end.x.toFixed(2)} ${end.y.toFixed(2)}`;
}

export function RiskMeter({ score, riskLevel }: RiskMeterProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const cx = 120;
  const cy = 116;
  const r = 80;
  const needleAngle = -90 + (clamped / 100) * 180;
  const tipPoint = polarToCartesian(cx, cy, r, clamped);
  const tick0 = polarToCartesian(cx, cy, r + 18, 0);
  const tick40 = polarToCartesian(cx, cy, r + 18, 40);
  const tick70 = polarToCartesian(cx, cy, r + 18, 70);
  const tick100 = polarToCartesian(cx, cy, r + 18, 100);

  const colorMap: Record<
    RiskLevel,
    { stroke: string; text: string; badge: string; label: string }
  > = {
    LOW: {
      stroke: '#35C7AD',
      text: 'text-[#35C7AD]',
      badge: 'border-[#35C7AD]/35 bg-[#35C7AD]/10 text-[#35C7AD]',
      label: 'LOW RISK',
    },
    SUSPICIOUS: {
      stroke: '#F3B94F',
      text: 'text-[#F3B94F]',
      badge: 'border-[#F3B94F]/35 bg-[#F3B94F]/10 text-[#F3B94F]',
      label: 'SUSPICIOUS',
    },
    HIGH: {
      stroke: '#FF6878',
      text: 'text-[#FF6878]',
      badge: 'border-[#FF6878]/35 bg-[#FF6878]/10 text-[#FF6878]',
      label: 'HIGH RISK',
    },
  };

  const style = colorMap[riskLevel];

  return (
    <div
      data-testid="risk-score-gauge"
      className="flex h-full flex-col items-center justify-between rounded-xl border border-[#91A5B8]/15 bg-[#07111F] p-5"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped}
      aria-label={`Threat risk score ${clamped} out of 100 (${style.label})`}
    >
      <div className="flex w-full items-center justify-between text-xs text-[#91A5B8]">
        <span className="font-medium text-[#EAF0F7]">Risk Score Gauge</span>
        <span className="font-mono tabular-nums">0–100 Scale</span>
      </div>

      <div className="relative mt-2 flex w-full max-w-[260px] flex-col items-center">
        <svg viewBox="0 0 240 142" className="w-full overflow-visible">
          {/* Base Semi-Circle Track */}
          <path
            d={describeScoreArc(cx, cy, r, 0, 100)}
            fill="none"
            stroke="#101E30"
            strokeWidth="14"
            strokeLinecap="round"
          />

          {/* Three Risk Zone Segments (Low 0-39, Suspicious 40-69, High 70-100) */}
          <path
            d={describeScoreArc(cx, cy, r, 0, 38.5)}
            fill="none"
            stroke="#35C7AD"
            strokeOpacity={riskLevel === 'LOW' ? 0.45 : 0.22}
            strokeWidth="14"
            strokeLinecap="round"
          />
          <path
            d={describeScoreArc(cx, cy, r, 40.5, 68.5)}
            fill="none"
            stroke="#F3B94F"
            strokeOpacity={riskLevel === 'SUSPICIOUS' ? 0.5 : 0.22}
            strokeWidth="14"
          />
          <path
            d={describeScoreArc(cx, cy, r, 70.5, 100)}
            fill="none"
            stroke="#FF6878"
            strokeOpacity={riskLevel === 'HIGH' ? 0.55 : 0.22}
            strokeWidth="14"
            strokeLinecap="round"
          />

          {/* Active Score Progress Arc */}
          {clamped > 0 && (
            <path
              d={describeScoreArc(cx, cy, r, 0, Math.max(1, clamped))}
              fill="none"
              stroke={style.stroke}
              strokeWidth="14"
              strokeLinecap="round"
              className="transition-all duration-500 ease-out"
            />
          )}

          {/* Threshold Labels around Arc */}
          <text
            x={tick0.x}
            y={tick0.y + 4}
            textAnchor="middle"
            className="fill-[#91A5B8] font-mono text-[10px]"
          >
            0
          </text>
          <text
            x={tick40.x}
            y={tick40.y}
            textAnchor="middle"
            className="fill-[#35C7AD] font-mono text-[10px]"
          >
            40
          </text>
          <text
            x={tick70.x}
            y={tick70.y}
            textAnchor="middle"
            className="fill-[#F3B94F] font-mono text-[10px]"
          >
            70
          </text>
          <text
            x={tick100.x}
            y={tick100.y + 4}
            textAnchor="middle"
            className="fill-[#FF6878] font-mono text-[10px]"
          >
            100
          </text>

          {/* Precision Gauge Needle */}
          <g
            style={{
              transform: `rotate(${needleAngle}deg)`,
              transformOrigin: `${cx}px ${cy}px`,
              transition: 'transform 500ms cubic-bezier(0.16, 1, 0.3, 1)',
            }}
          >
            <polygon
              points={`${cx - 3.5},${cy} ${cx},${cy - 68} ${cx + 3.5},${cy}`}
              fill="#EAF0F7"
            />
            <circle cx={cx} cy={cy} r="7" fill="#07111F" stroke={style.stroke} strokeWidth="3" />
          </g>

          {/* Active Tip Marker */}
          <circle
            cx={tipPoint.x}
            cy={tipPoint.y}
            r="4.5"
            fill="#EAF0F7"
            stroke={style.stroke}
            strokeWidth="2.5"
          />
        </svg>

        <div className="-mt-1 text-center">
          <div className={`font-mono text-4xl font-bold tabular-nums ${style.text}`}>
            {clamped}
            <span className="text-base font-medium text-[#91A5B8]"> / 100</span>
          </div>
          <div
            className={`mt-2 inline-flex items-center rounded-md border px-2.5 py-0.5 text-[11px] font-semibold tracking-wider ${style.badge}`}
          >
            {style.label}
          </div>
        </div>
      </div>

      <div className="mt-4 flex w-full items-center justify-between border-t border-[#91A5B8]/15 pt-3 text-[11px] font-mono text-[#91A5B8] tabular-nums">
        <span className="text-[#35C7AD]">0–39 Low</span>
        <span className="text-[#F3B94F]">40–69 Suspicious</span>
        <span className="text-[#FF6878]">70–100 High</span>
      </div>
    </div>
  );
}
