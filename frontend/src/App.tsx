import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import AppShell from "./components/layout/AppShell";
import { LiveProvider } from "./live/LiveContext";
import AlertsPage from "./pages/AlertsPage";
import AuditPage from "./pages/AuditPage";
import LiveMonitoringPage from "./pages/LiveMonitoringPage";
import LoginPage from "./pages/LoginPage";
import OverviewPage from "./pages/OverviewPage";
import RevocationPage from "./pages/RevocationPage";
import RiskScoresPage from "./pages/RiskScoresPage";
import SessionPage from "./pages/SessionPage";
import TrustScorePage from "./pages/TrustScorePage";
import UsersPage from "./pages/UsersPage";

function TerminatedNotice({
  reason,
  onDismiss,
}: {
  reason: string;
  onDismiss: () => void;
}) {
  return (
    <div className="flex min-h-full items-center justify-center bg-slate-50 p-6">
      <div className="w-full max-w-md rounded-xl border border-risk-critical/30 bg-white p-8 shadow-sm">
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
        <SessionPage />
      )}
    </LiveProvider>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Gate />
      </AuthProvider>
    </BrowserRouter>
  );
}
