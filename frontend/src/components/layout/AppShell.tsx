import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import { useLive } from "../../live/LiveContext";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/users", label: "Users & Devices" },
  { to: "/live", label: "Live Monitoring" },
  { to: "/risk", label: "Risk Scores" },
  { to: "/alerts", label: "Alerts" },
  { to: "/trust", label: "Trust Score" },
  { to: "/audit", label: "Audit Logs" },
  { to: "/revocation", label: "Session Revocation" },
];

export default function AppShell() {
  const { me, signOut } = useAuth();
  const { status, lastHeartbeat } = useLive();

  return (
    <div className="flex min-h-full">
      <aside className="flex w-60 shrink-0 flex-col bg-shell p-5 text-slate-300">
        <div>
          <div className="text-lg font-semibold text-white">ZTNA</div>
          <div className="mt-0.5 text-xs text-slate-400">
            Adaptive Trust Scoring
          </div>
        </div>

        <div className="mt-6 rounded-lg bg-shell-soft p-3">
          <div className="truncate text-sm font-medium text-white">
            {me?.full_name}
          </div>
          <div className="truncate text-xs text-slate-400">
            {me?.username} · {me?.role}
          </div>
        </div>

        <nav className="mt-5 flex-1 space-y-0.5 text-sm">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block rounded px-3 py-2 transition ${
                  isActive
                    ? "bg-shell-soft text-white"
                    : "text-slate-400 hover:bg-shell-soft/60 hover:text-slate-200"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div
          className="mt-4 flex items-center gap-2 px-3 text-xs text-slate-400"
          title={
            status === "open"
              ? `Live. Last heartbeat ${lastHeartbeat?.toLocaleTimeString() ?? "—"}`
              : `Live stream ${status}`
          }
        >
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              status === "open"
                ? "bg-risk-low"
                : status === "connecting"
                  ? "bg-risk-medium"
                  : "bg-risk-critical"
            }`}
            aria-hidden
          />
          {status === "open" ? "live stream connected" : `stream ${status}`}
        </div>

        <button
          onClick={signOut}
          className="mt-3 w-full rounded-lg border border-slate-600 px-3 py-2 text-sm text-slate-300 hover:bg-shell-soft"
        >
          Sign out
        </button>
      </aside>

      <main className="flex-1 overflow-auto bg-slate-50">
        <Outlet />
      </main>
    </div>
  );
}
