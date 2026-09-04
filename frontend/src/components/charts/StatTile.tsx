import type { ReactNode } from "react";

/**
 * A single number is not a chart. When the job is "what is this value right
 * now", a stat tile reads faster than any plot of it.
 */
export default function StatTile({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "neutral" | "warn" | "bad";
}) {
  const valueTone =
    tone === "bad"
      ? "text-risk-critical"
      : tone === "warn"
        ? "text-orange-700"
        : "text-slate-900";

  return (
    <div className="rounded-lg border border-slate-200 bg-white px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${valueTone}`}>
        {value}
      </div>
      {hint && <div className="mt-0.5 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}
