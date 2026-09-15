import { STATUS_META } from "@/lib/format";
import type { ScanStatus } from "@/lib/types";

/**
 * A status is always icon + word + colour, in that order of importance.
 * The colour lives on the dot; the text stays in an ink token, so the pill is
 * readable in greyscale, in forced-colors mode, and for colour-blind readers.
 */
export function StatusPill({ status, className = "" }: { status: ScanStatus; className?: string }) {
  const meta = STATUS_META[status];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${className}`}
      style={{ borderColor: "var(--hairline)", color: "var(--text-primary)" }}
    >
      <span
        aria-hidden
        className="grid h-4 w-4 place-items-center rounded-full text-[10px] font-bold text-white"
        style={{ background: `var(--status-${meta.token})` }}
      >
        {meta.icon}
      </span>
      {meta.label}
    </span>
  );
}
