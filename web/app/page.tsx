"use client";

import { useState } from "react";

import { ModuleCard } from "@/components/ModuleCard";
import { ScoreBreakdownTable } from "@/components/ScoreBreakdownTable";
import { ScoreDial } from "@/components/ScoreDial";
import { formatDuration, formatTimestamp } from "@/lib/format";
import type { ApiError, FullScanResponse } from "@/lib/types";

const EXAMPLES = ["cloudflare.com", "github.com", "example.com"];

export default function Page() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<FullScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  async function runScan(target: string) {
    const trimmed = target.trim();
    if (!trimmed || scanning) return;

    setScanning(true);
    setError(null);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: trimmed }),
      });
      const payload = (await response.json()) as FullScanResponse | ApiError;

      if (!response.ok) {
        setError((payload as ApiError).error ?? "The scan failed.");
        setResult(null);
      } else {
        setResult(payload as FullScanResponse);
      }
    } catch {
      setError("Could not reach the dashboard's API.");
      setResult(null);
    } finally {
      setScanning(false);
    }
  }

  return (
    <main className="mx-auto w-full max-w-5xl px-4 py-12 sm:px-6">
      <header className="text-center">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Web Audit</h1>
        <p className="ink-secondary mx-auto mt-3 max-w-xl text-sm leading-relaxed sm:text-base">
          Check a domain&rsquo;s DNSSEC, email authentication and TLS setup, and get one
          graded score for how exposed it is.
        </p>
      </header>

      <form
        className="mx-auto mt-8 flex w-full max-w-xl flex-col gap-3 sm:flex-row"
        onSubmit={(event) => {
          event.preventDefault();
          void runScan(domain);
        }}
      >
        <label htmlFor="domain" className="sr-only">
          Domain to scan
        </label>
        <input
          id="domain"
          name="domain"
          type="text"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          placeholder="example.com"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          className="surface min-w-0 flex-1 rounded-lg px-4 py-3 text-base outline-none focus:ring-2"
          style={{ color: "var(--text-primary)" }}
        />
        <button
          type="submit"
          disabled={scanning || domain.trim().length === 0}
          className="rounded-lg px-6 py-3 text-base font-medium text-white transition-opacity disabled:cursor-not-allowed disabled:opacity-50"
          style={{ background: "var(--text-primary)", color: "var(--surface-1)" }}
        >
          {scanning ? "Scanning…" : "Scan"}
        </button>
      </form>

      <div className="ink-muted mt-3 flex flex-wrap items-center justify-center gap-2 text-xs">
        <span>Try:</span>
        {EXAMPLES.map((example) => (
          <button
            key={example}
            type="button"
            className="cursor-pointer underline underline-offset-2"
            onClick={() => {
              setDomain(example);
              void runScan(example);
            }}
          >
            {example}
          </button>
        ))}
      </div>

      <div aria-live="polite" className="mt-10">
        {scanning && (
          <p className="ink-secondary text-center text-sm">
            Running DNSSEC, email and TLS checks…
          </p>
        )}

        {error && !scanning && (
          <div
            className="surface mx-auto max-w-xl rounded-xl p-4 text-sm"
            style={{ borderColor: "var(--status-critical)" }}
            role="alert"
          >
            <strong className="font-semibold">Scan failed.</strong>{" "}
            <span className="ink-secondary">{error}</span>
          </div>
        )}

        {result && !scanning && (
          <div className="space-y-6">
            <section className="surface rounded-xl p-6 sm:p-8">
              <div className="flex flex-col items-center gap-8 lg:flex-row lg:items-center lg:gap-12">
                <ScoreDial
                  score={result.score.score}
                  grade={result.score.grade}
                  coverage={result.score.coverage}
                />

                <div className="w-full flex-1">
                  <h2 className="mono text-lg font-semibold break-all">{result.domain}</h2>
                  <p className="ink-muted mt-1 text-xs">
                    Scanned {formatTimestamp(result.scanned_at)} in{" "}
                    {formatDuration(result.duration_ms)}
                    {result.persisted ? " · saved" : " · not saved"}
                  </p>
                  {result.score.note && (
                    <p className="ink-secondary mt-3 text-sm leading-relaxed">
                      {result.score.note}
                    </p>
                  )}
                  <div className="mt-5">
                    <ScoreBreakdownTable components={result.score.components} />
                  </div>
                </div>
              </div>
            </section>

            <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
              {result.modules.map((module) => (
                <ModuleCard key={module.scan_type} module={module} />
              ))}
            </div>
          </div>
        )}
      </div>

      <footer className="ink-muted mt-16 text-center text-xs">
        Scanner Engine on Oracle Cloud · results stored in Supabase
      </footer>
    </main>
  );
}
