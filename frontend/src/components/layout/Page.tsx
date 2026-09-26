import type { ReactNode } from "react";

export default function Page({
  title,
  description,
  actions,
  eyebrow = "Security operations",
  children,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  eyebrow?: string;
  children: ReactNode;
}) {
  return (
    <div className="app-page">
      <header className="page-heading" data-scroll-reveal>
        <div>
          <div className="page-kicker">{eyebrow}</div>
          <h1 className="page-title">{title}</h1>
          {description && <p className="page-description">{description}</p>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </header>
      <div className="page-body">{children}</div>
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
    <section className="surface-panel p-5 sm:p-6" data-scroll-reveal>
      {(title || actions) && (
        <div className="surface-panel-heading mb-4 flex items-center justify-between gap-3">
          {title && <h2>{title}</h2>}
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
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold tracking-wide ring-1 ring-inset ${styles[level] ?? "bg-slate-100 text-slate-700 ring-slate-400/20"}`}
    >
      {score !== undefined && <span className="font-mono tabular-nums">{score.toFixed(0)}</span>}
      {level}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}
