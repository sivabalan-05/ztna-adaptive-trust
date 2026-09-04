import type { ReactNode } from "react";

export default function Page({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="p-8">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">{title}</h1>
          {description && (
            <p className="mt-1 max-w-2xl text-sm text-slate-600">{description}</p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </header>
      <div className="mt-6">{children}</div>
    </div>
  );
}

export function Card({
  title,
  children,
  actions,
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5">
      {(title || actions) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          {title && (
            <h2 className="text-sm font-semibold text-slate-900">{title}</h2>
          )}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function RiskChip({ level, score }: { level: string; score?: number }) {
  const styles: Record<string, string> = {
    LOW: "bg-emerald-50 text-emerald-800 ring-emerald-600/20",
    MEDIUM: "bg-amber-50 text-amber-800 ring-amber-600/20",
    HIGH: "bg-orange-50 text-orange-800 ring-orange-600/20",
    CRITICAL: "bg-red-50 text-red-800 ring-red-600/20",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${
        styles[level] ?? "bg-slate-100 text-slate-700 ring-slate-400/20"
      }`}
    >
      {score !== undefined && (
        <span className="font-mono tabular-nums">{score.toFixed(0)}</span>
      )}
      {level}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 px-4 py-10 text-center text-sm text-slate-500">
      {children}
    </div>
  );
}
