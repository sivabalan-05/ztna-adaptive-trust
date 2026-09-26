import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import AppShell from "./components/layout/AppShell";
import PortalShell from "./components/layout/PortalShell";
import { LiveProvider } from "./live/LiveContext";
import AlertsPage from "./pages/AlertsPage";
import AuditPage from "./pages/AuditPage";
import LiveMonitoringPage from "./pages/LiveMonitoringPage";
import LoginPage from "./pages/LoginPage";
import OverviewPage from "./pages/OverviewPage";
import MyAccessPage from "./pages/portal/MyAccessPage";
import MyActivityPage from "./pages/portal/MyActivityPage";
import MyDevicesPage from "./pages/portal/MyDevicesPage";
import MyTrustPage from "./pages/portal/MyTrustPage";
import PoliciesPage from "./pages/PoliciesPage";
import ResourcesAdminPage from "./pages/ResourcesAdminPage";
import RevocationPage from "./pages/RevocationPage";
import RiskScoresPage from "./pages/RiskScoresPage";
import SessionPage from "./pages/SessionPage";
import TrustScorePage from "./pages/TrustScorePage";
import UsersPage from "./pages/UsersPage";
import MotionEffects from "./components/MotionEffects";

function TerminatedNotice({
  reason,
  onDismiss,
}: {
  reason: string;
  onDismiss: () => void;
}) {
  return (
    <div className="termination-screen">
      <div className="termination-card">
        <div className="text-lg font-semibold text-risk-critical">
          Session terminated
        </div>
        <p className="mt-2 text-sm text-slate-600">{reason}</p>
        <p className="mt-4 text-xs text-slate-500">
          Your trust score fell into the CRITICAL band, or an administrator
          revoked this session. The decision was enforced without waiting for
          you to make another request.
        </p>
        <button
          onClick={onDismiss}
          className="mt-6 w-full rounded-lg bg-shell px-4 py-2.5 text-sm font-medium text-white"
        >
          Sign in again
        </button>
      </div>
    </div>
  );
}

function Gate() {
  const { me, loading, terminated, clearTermination } = useAuth();
  const [dismissed, setDismissed] = useState(false);

  if (loading) {
    return (
      <div className="flex min-h-full items-center justify-center text-sm text-slate-500">
        Restoring session…
      </div>
    );
  }
  if (terminated && !dismissed) {
    return (
      <TerminatedNotice
        reason={terminated}
        onDismiss={() => {
          setDismissed(true);
          clearTermination();
        }}
      />
    );
  }
  if (!me) return <LoginPage />;

  // Operators get the eight-page console; everyone else gets their own session.
  const isOperator = me.is_admin || me.role === "security_analyst";

  return (
    <LiveProvider>
      {isOperator ? (
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<OverviewPage />} />
            <Route path="users" element={<UsersPage />} />
            <Route path="resources" element={<ResourcesAdminPage />} />
            <Route path="policies" element={<PoliciesPage />} />
            <Route path="live" element={<LiveMonitoringPage />} />
            <Route path="risk" element={<RiskScoresPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="trust" element={<TrustScorePage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="revocation" element={<RevocationPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      ) : (
        <Routes>
          <Route element={<PortalShell />}>
            <Route index element={<MyAccessPage />} />
            <Route path="session" element={<SessionPage />} />
            <Route path="devices" element={<MyDevicesPage />} />
            <Route path="activity" element={<MyActivityPage />} />
            <Route path="trust" element={<MyTrustPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      )}
    </LiveProvider>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <MotionEffects />
        <Gate />
      </AuthProvider>
    </BrowserRouter>
  );
}
