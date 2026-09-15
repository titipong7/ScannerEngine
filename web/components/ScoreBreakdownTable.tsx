import { StatusPill } from "@/components/StatusPill";
import type { ScoreComponent } from "@/lib/types";

/**
 * The table view of the dial: same numbers, readable without colour, and the
 * place where "why is my score 78?" is actually answered.
 */
export function ScoreBreakdownTable({ components }: { components: ScoreComponent[] }) {
  if (components.length === 0) return null;

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[26rem] border-collapse text-sm">
        <caption className="ink-muted pb-2 text-left text-xs">
          Points earned per component. A pass earns its full weight, a warning half,
          a failure none.
        </caption>
        <thead>
          <tr className="text-left">
            <th className="ink-secondary pb-2 pr-3 font-medium">Component</th>
            <th className="ink-secondary pb-2 pr-3 font-medium">Status</th>
            <th className="ink-secondary pb-2 pr-3 text-right font-medium">Points</th>
          </tr>
        </thead>
        <tbody>
          {components.map((component) => (
            <tr key={component.key} style={{ borderTop: "1px solid var(--hairline)" }}>
              <td className="py-2.5 pr-3 font-medium">{component.label}</td>
              <td className="py-2.5 pr-3">
                <StatusPill status={component.status} />
              </td>
              <td className="mono py-2.5 pr-3 text-right tabular-nums">
                {component.credit === null ? (
                  <span className="ink-muted">not checked</span>
                ) : (
                  <>
                    {component.points}
                    <span className="ink-muted"> / {component.weight}</span>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
