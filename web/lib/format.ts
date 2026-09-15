import type { ScanStatus, ScanType } from "./types";

export const MODULE_LABELS: Record<ScanType, string> = {
  dnssec: "DNSSEC",
  email: "Email (SPF / DMARC)",
  tls: "SSL/TLS",
  dkim: "DKIM",
};

/**
 * Status colours come from the reserved status palette, and every one of them
 * ships with an icon and a word — never colour alone.
 */
export const STATUS_META: Record<
  ScanStatus,
  { label: string; icon: string; token: string }
> = {
  pass: { label: "Pass", icon: "✓", token: "good" },
  warn: { label: "Warning", icon: "!", token: "warning" },
  fail: { label: "Fail", icon: "✕", token: "critical" },
  error: { label: "Unknown", icon: "?", token: "unknown" },
};

/** Grade bands mirror app/scoring.py: A >= 90, B >= 80, C >= 70, D >= 60. */
export function gradeToken(grade: string | null): string {
  switch (grade) {
    case "A":
      return "good";
    case "B":
    case "C":
      return "warning";
    case "D":
      return "serious";
    case "F":
      return "critical";
    default:
      return "unknown";
  }
}

export function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}
