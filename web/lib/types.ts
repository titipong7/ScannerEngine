/** Mirrors the Scanner Engine's response models (see app/schemas.py). */

export type ScanStatus = "pass" | "warn" | "fail" | "error";

export type ScanType = "dnssec" | "email" | "tls" | "dkim";

export interface ModuleResult {
  domain: string;
  scan_type: ScanType;
  status: ScanStatus;
  summary: string;
  findings: string[];
  raw_data: Record<string, unknown>;
  scanned_at: string;
  persisted: boolean;
  record_id: number | string | null;
}

export interface ScoreComponent {
  key: string;
  label: string;
  status: ScanStatus;
  weight: number;
  /** 1.0 pass, 0.5 warn, 0.0 fail, null when it could not be determined. */
  credit: number | null;
  points: number;
}

export interface ScoreBreakdown {
  score: number | null;
  grade: string | null;
  coverage: number;
  earned_weight: number;
  available_weight: number;
  total_weight: number;
  components: ScoreComponent[];
  undetermined: string[];
  note?: string | null;
}

export interface FullScanResponse {
  domain: string;
  scanned_at: string;
  duration_ms: number;
  score: ScoreBreakdown;
  modules: ModuleResult[];
  scan_id: number | string | null;
  persisted: boolean;
}

export interface ApiError {
  error: string;
  detail?: string;
}
