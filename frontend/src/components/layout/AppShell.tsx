import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import { useLive } from "../../live/LiveContext";

const GROUPS = [
  {
    label: "Workspace",
    items: [
      { to: "/", label: "Overview", glyph: "◫", end: true },
      { to: "/users", label: "Users & devices", glyph: "◉" },
      { to: "/resources", label: "Resources", glyph: "▤" },
    ],
  },
  {
    label: "Access controls",
    items: [
      { to: "/policies", label: "Policies", glyph: "⌘" },
      { to: "/trust", label: "Trust scoring", glyph: "◌" },
      { to: "/risk", label: "Risk scores", glyph: "⌁" },
      { to: "/audit", label: "Audit trail", glyph: "≋" },
    ],
  },
  {
    label: "Response",
    items: [
      { to: "/live", label: "Live sessions", glyph: "◎" },
      { to: "/alerts", label: "Alerts", glyph: "◇" },
      { to: "/revocation", label: "Revocation", glyph: "⊘" },
    ],
  },
];

const PAGE_NAMES: Record<string, string> = Object.fromEntries(
  GROUPS.flatMap((group) => group.items.map((item) => [item.to, item.label])),
);

function initials(name?: string | null) {
  return (name ?? "ZT")
    .split(/[\s.@_-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

export default function AppShell() {
  const { me, signOut } = useAuth();
  const { status, lastHeartbeat } = useLive();
  const { pathname } = useLocation();
  const pageName = PAGE_NAMES[pathname] ?? "Control plane";
  const streamTitle = status === "open"
    ? `Live. Last heartbeat ${lastHeartbeat?.toLocaleTimeString() ?? "—"}`
    : `Live stream ${status}`;

  return (
    <div className="app-frame">
      <aside className="app-sidebar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">Z</div>
          <div>
            <div className="brand-name">PENETRATION PROTECTOR</div>
            <div className="brand-caption">Zero trust control plane</div>
          </div>
        </div>

        <div className="sidebar-profile">
          <div className="profile-avatar" aria-hidden="true">{initials(me?.full_name)}</div>
          <div className="profile-copy">
            <div className="profile-name">{me?.full_name}</div>
            <div className="profile-detail">{me?.username} · {me?.role}</div>
          </div>
        </div>

        <nav aria-label="Operator navigation" className="app-nav">
          {GROUPS.map((group) => (
            <div className="nav-section" key={group.label}>
              <div className="nav-heading">{group.label}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className="nav-link"
                >
                  <span className="nav-glyph" aria-hidden="true">{item.glyph}</span>
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="stream-status" title={streamTitle} role="status">
            <span className={`stream-dot ${status === "open" ? "is-open" : status === "connecting" ? "is-connecting" : ""}`} aria-hidden="true" />
            {status === "open" ? "Live stream connected" : `Stream ${status}`}
          </div>
          <button onClick={signOut} className="sidebar-signout" type="button">
            Sign out
          </button>
        </div>
      </aside>

      <main className="app-main">
        <header className="app-topbar">
          <div className="topbar-context">Control plane <span aria-hidden="true">/</span> {pageName}</div>
          <div className="topbar-right">
            <span className="topbar-date">{new Date().toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}</span>
            <span className="topbar-live" title={streamTitle}>
              <span className={`stream-dot ${status === "open" ? "is-open" : status === "connecting" ? "is-connecting" : ""}`} aria-hidden="true" />
              {status === "open" ? "System live" : status}
            </span>
          </div>
        </header>
        <Outlet />
      </main>
    </div>
  );
}
