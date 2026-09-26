import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext";
import { useLive } from "../../live/LiveContext";

const NAV = [
  { to: "/", label: "My access", glyph: "◫", end: true },
  { to: "/session", label: "My session", glyph: "◎" },
  { to: "/devices", label: "My devices", glyph: "◉" },
  { to: "/activity", label: "My activity", glyph: "≋" },
  { to: "/trust", label: "Trust & policy", glyph: "◌" },
];

function initials(name?: string | null) {
  return (name ?? "ZT")
    .split(/[\s.@_-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

export default function PortalShell() {
  const { me, signOut } = useAuth();
  const { status } = useLive();
  const { pathname } = useLocation();
  const pageName = NAV.find((item) => item.to === pathname)?.label ?? "My workspace";

  return (
    <div className="app-frame portal-frame">
      <aside className="app-sidebar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">Z</div>
          <div>
            <div className="brand-name">PENETRATION PROTECTOR</div>
            <div className="brand-caption">Secure workspace</div>
          </div>
        </div>

        <div className="sidebar-profile">
          <div className="profile-avatar" aria-hidden="true">{initials(me?.full_name)}</div>
          <div className="profile-copy">
            <div className="profile-name">{me?.full_name}</div>
            <div className="profile-detail">{me?.username} · {me?.role}</div>
          </div>
        </div>

        <div className="nav-heading">Your workspace</div>
        <nav aria-label="Workspace navigation" className="app-nav">
          {NAV.map((item) => (
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
        </nav>

        <div className="sidebar-footer">
          <div className="stream-status" role="status">
            <span className={`stream-dot ${status === "open" ? "is-open" : status === "connecting" ? "is-connecting" : ""}`} aria-hidden="true" />
            {status === "open" ? "Protection active" : `Stream ${status}`}
          </div>
          <button onClick={signOut} className="sidebar-signout" type="button">Sign out</button>
        </div>
      </aside>

      <main className="app-main">
        <header className="app-topbar">
          <div className="topbar-context">My workspace <span aria-hidden="true">/</span> {pageName}</div>
          <div className="topbar-right">
            <span className="topbar-live">
              <span className={`stream-dot ${status === "open" ? "is-open" : status === "connecting" ? "is-connecting" : ""}`} aria-hidden="true" />
              {status === "open" ? "Protection active" : status}
            </span>
          </div>
        </header>
        <Outlet />
      </main>
    </div>
  );
}
