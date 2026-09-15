"use client";

import { useEffect, useState } from "react";

import { gradeToken } from "@/lib/format";

const RADIUS = 70;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
/** Three quarters of a circle, so the gap reads as a gauge opening downwards. */
const SWEEP = CIRCUMFERENCE * 0.75;

/**
 * The headline number. This is a hero figure with a gauge behind it, not a
 * chart: there is one value, so there is no legend, no axis and no tooltip —
 * the number itself is the label.
 */
export function ScoreDial({
  score,
  grade,
  coverage,
}: {
  score: number | null;
  grade: string | null;
  coverage: number;
}) {
  // Start empty and fill on mount, so the arc animates to its value once.
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setShown(score ?? 0));
    return () => cancelAnimationFrame(frame);
  }, [score]);

  const token = gradeToken(grade);
  const offset = SWEEP * (1 - Math.max(0, Math.min(100, shown)) / 100);

  return (
    <figure className="m-0 flex flex-col items-center">
      <div className="relative">
        <svg
          width="180"
          height="180"
          viewBox="0 0 180 180"
          role="img"
          aria-label={
            score === null
              ? "No score could be calculated"
              : `Score ${score} out of 100, grade ${grade}`
          }
        >
          <g transform="rotate(135 90 90)">
            <circle
              cx="90"
              cy="90"
              r={RADIUS}
              fill="none"
              stroke="var(--hairline)"
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={`${SWEEP} ${CIRCUMFERENCE}`}
            />
            {score !== null && (
              <circle
                className="dial-arc"
                cx="90"
                cy="90"
                r={RADIUS}
                fill="none"
                stroke={`var(--status-${token})`}
                strokeWidth="12"
                strokeLinecap="round"
                strokeDasharray={`${SWEEP} ${CIRCUMFERENCE}`}
                strokeDashoffset={offset}
              />
            )}
          </g>
        </svg>

        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="mono text-5xl font-semibold tabular-nums leading-none">
            {score === null ? "—" : score}
          </span>
          <span className="ink-muted mt-1 text-xs">out of 100</span>
        </div>
      </div>

      <figcaption className="mt-2 text-center">
        {grade ? (
          <span className="text-sm font-medium">
            Grade <span className="mono text-base font-semibold">{grade}</span>
          </span>
        ) : (
          <span className="ink-secondary text-sm">Not enough data to grade</span>
        )}
        {coverage < 1 && (
          <p className="ink-muted mx-auto mt-1 max-w-[22rem] text-xs leading-relaxed">
            Scored on {Math.round(coverage * 100)}% of the model — the rest could not be
            checked and was left out rather than counted as zero.
          </p>
        )}
      </figcaption>
    </figure>
  );
}
