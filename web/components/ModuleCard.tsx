"use client";

import { useState } from "react";

import { StatusPill } from "@/components/StatusPill";
import { MODULE_LABELS } from "@/lib/format";
import type { ModuleResult } from "@/lib/types";

/** One module's verdict, its findings, and the raw data behind them. */
export function ModuleCard({ module: result }: { module: ModuleResult }) {
  const [showRaw, setShowRaw] = useState(false);

  return (
    <section className="surface rounded-xl p-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-base font-semibold">{MODULE_LABELS[result.scan_type]}</h3>
        <StatusPill status={result.status} />
      </header>

      <p className="ink-secondary mt-2 text-sm leading-relaxed">{result.summary}</p>

      {result.findings.length === 0 && result.status === "pass" && (
        <p className="ink-muted mt-3 text-sm">No issues found.</p>
      )}

      {result.findings.length > 0 && (
        <ul className="mt-4 space-y-2">
          {result.findings.map((finding, index) => (
            <li key={index} className="flex gap-2.5 text-sm leading-relaxed">
              <span aria-hidden className="ink-muted select-none">
                •
              </span>
              <span className="ink-secondary">{finding}</span>
            </li>
          ))}
        </ul>
      )}

      <button
        type="button"
        onClick={() => setShowRaw((open) => !open)}
        className="ink-muted mt-4 cursor-pointer text-xs underline underline-offset-2"
        aria-expanded={showRaw}
      >
        {showRaw ? "Hide raw data" : "Show raw data"}
      </button>

      {showRaw && (
        <pre
          className="mono mt-3 max-h-80 overflow-auto rounded-lg p-3 text-xs leading-relaxed"
          style={{ background: "var(--surface-page)", border: "1px solid var(--hairline)" }}
        >
          {JSON.stringify(result.raw_data, null, 2)}
        </pre>
      )}
    </section>
  );
}
