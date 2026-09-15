import { NextResponse } from "next/server";

import type { ApiError, FullScanResponse } from "@/lib/types";

/**
 * Server-side proxy to the Scanner Engine.
 *
 * The browser never talks to the engine directly: SCANNER_API_KEY lives only in
 * this process, so a public dashboard cannot leak the credential that lets
 * anyone run scans on our infrastructure.
 */

export const dynamic = "force-dynamic";

// Deliberately permissive — the engine does the authoritative validation and
// returns a 422 we surface verbatim. This only catches obvious typos early.
const DOMAIN_PATTERN = /^[^\s.@/:]+(\.[^\s.@/:]+)+$/u;

function normalizeDomain(raw: unknown): string | null {
  if (typeof raw !== "string") return null;

  let value = raw.trim().toLowerCase();
  value = value.replace(/^https?:\/\//, "");
  value = value.split("/")[0].split("?")[0];
  value = value.split("@").pop() ?? value;
  value = value.split(":")[0].replace(/\.$/, "");

  return DOMAIN_PATTERN.test(value) ? value : null;
}

export async function POST(
  request: Request,
): Promise<NextResponse<FullScanResponse | ApiError>> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { error: 'Send a JSON body of {"domain": "..."}' },
      { status: 400 },
    );
  }

  const domain = normalizeDomain((body as { domain?: unknown })?.domain);
  if (!domain) {
    return NextResponse.json(
      { error: "That does not look like a domain name. Try example.com." },
      { status: 400 },
    );
  }

  const scannerUrl = process.env.SCANNER_URL ?? "http://localhost:8000";
  const timeoutSeconds = Number(process.env.SCANNER_TIMEOUT ?? 45);

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (process.env.SCANNER_API_KEY) {
    headers["X-API-Key"] = process.env.SCANNER_API_KEY;
  }

  try {
    const response = await fetch(`${scannerUrl}/scan/full`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domain }),
      signal: AbortSignal.timeout(timeoutSeconds * 1000),
      cache: "no-store",
    });

    if (!response.ok) {
      const detail = await response.text();
      // A 401 means *our* key is wrong — that is our bug, not the caller's.
      const authFailure = response.status === 401;
      return NextResponse.json(
        {
          error: authFailure
            ? "The dashboard is not authorised to use the scanner."
            : `The scanner returned ${response.status}.`,
          detail: detail.slice(0, 500),
        },
        { status: authFailure ? 500 : 502 },
      );
    }

    return NextResponse.json((await response.json()) as FullScanResponse);
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    return NextResponse.json(
      {
        error: timedOut
          ? `The scan took longer than ${timeoutSeconds}s. Try again.`
          : "Could not reach the scanner.",
        detail: error instanceof Error ? error.message : String(error),
      },
      { status: 504 },
    );
  }
}
