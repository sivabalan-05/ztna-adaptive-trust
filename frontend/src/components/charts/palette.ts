/**
 * Risk bands are a STATUS palette, not a categorical one: they encode a state,
 * not an identity. Four ordered warm-to-cool hues cannot be separated by hue
 * alone — the adjacent pairs fall below the normal-vision separation floor — so
 * every use pairs the colour with the band name in text. Colour never carries
 * the meaning by itself.
 */
export const RISK_COLOR: Record<string, string> = {
  LOW: "#34d399",
  MEDIUM: "#fbbf24",
  HIGH: "#fb923c",
  CRITICAL: "#f87171",
};

export const RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

/** Single hue for magnitude: trust over time, factor contributions. */
export const TREND_COLOR = "#ff7a52";

/** Recessive chart chrome. */
export const GRID = "#232d42";
export const INK_MUTED = "#8d99b0";

/** Dark tooltip surface shared by every chart. */
export const TOOLTIP_STYLE = {
  background: "#0e131d",
  border: "1px solid rgba(255, 255, 255, 0.14)",
  borderRadius: 10,
  color: "#eef2f8",
  fontSize: 12,
  boxShadow: "0 18px 40px rgba(0, 0, 0, 0.55)",
} as const;

export function riskColor(level: string | null | undefined): string {
  return RISK_COLOR[level ?? ""] ?? INK_MUTED;
}

/** Tailwind classes for a risk chip. Always rendered with the band name. */
export const RISK_CHIP: Record<string, string> = {
  LOW: "bg-emerald-50 text-emerald-800 ring-emerald-600/20",
  MEDIUM: "bg-amber-50 text-amber-800 ring-amber-600/20",
  HIGH: "bg-orange-50 text-orange-800 ring-orange-600/20",
  CRITICAL: "bg-red-50 text-red-800 ring-red-600/20",
};

export function riskChip(level: string | null | undefined): string {
  return RISK_CHIP[level ?? ""] ?? "bg-slate-100 text-slate-700 ring-slate-400/20";
}

export const SEVERITY_CHIP: Record<string, string> = {
  INFO: "bg-slate-100 text-slate-700 ring-slate-400/20",
  LOW: "bg-slate-100 text-slate-700 ring-slate-400/20",
  MEDIUM: "bg-amber-50 text-amber-800 ring-amber-600/20",
  HIGH: "bg-orange-50 text-orange-800 ring-orange-600/20",
  CRITICAL: "bg-red-50 text-red-800 ring-red-600/20",
};
