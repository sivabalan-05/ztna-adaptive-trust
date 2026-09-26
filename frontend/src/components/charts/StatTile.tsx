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
  return (
    <div data-scroll-reveal className={`metric-card ${tone === "warn" ? "metric-warn" : tone === "bad" ? "metric-bad" : ""}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value tabular-nums">{value}</div>
      {hint && <div className="metric-hint">{hint}</div>}
    </div>
  );
}
