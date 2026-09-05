import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
  type ReactNode,
} from "react";
import {
  apiErrorMessage, confirmEnrolment as apiConfirmEnrolment, getMe,
  login as apiLogin, logout as apiLogout, startEnrolment as apiStartEnrolment,
  tokenStore, verifyMfa as apiVerifyMfa,
  type LoginChallenge, type Me, type MFAEnrolment,
} from "../api/client";

interface AuthState {
  me: Me | null;
  challenge: LoginChallenge | null;
  enrolment: MFAEnrolment | null;
  loading: boolean;
  error: string | null;
  terminated: string | null;
  clearTermination: () => void;
  signIn: (username: string, password: string) => Promise<void>;
  submitCode: (code: string) => Promise<void>;
  beginEnrolment: () => Promise<void>;
  confirmEnrolment: (code: string) => Promise<void>;
  signOut: () => Promise<void>;
  cancelChallenge: () => void;
  refreshMe: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null);
  const [enrolment, setEnrolment] = useState<MFAEnrolment | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [terminated, setTerminated] = useState<string | null>(null);

  // The live stream tells us the session ended, whoever ended it. Without
  // this the page would keep rendering a session the server has already
  // stopped honouring, until the next request happened to fail.
  useEffect(() => {
    function onTerminated(event: Event) {
      const detail = (event as CustomEvent<string>).detail;
      tokenStore.clear();
      setMe(null);
      setTerminated(detail || "This session was terminated.");
    }
    window.addEventListener("ztna:session-terminated", onTerminated);
    return () =>
      window.removeEventListener("ztna:session-terminated", onTerminated);
  }, []);

  const refreshMe = useCallback(async () => {
    if (!tokenStore.access) {
      setMe(null);
      return;
    }
    try {
      setMe(await getMe());
    } catch {
      // The session is gone (revoked, expired, or bound to another device).
      tokenStore.clear();
      setMe(null);
    }
  }, []);

  useEffect(() => {
    refreshMe().finally(() => setLoading(false));
  }, [refreshMe]);

  // Fetches the QR code / secret for a first-login enrolment token. Kept
  // separate from `signIn` so a user who navigates away mid-scan can also
  // trigger it again through the public `beginEnrolment` action below.
  const fetchEnrolmentDetails = useCallback(async (enrolmentToken: string) => {
    setEnrolment(await apiStartEnrolment(enrolmentToken));
  }, []);

  const signIn = useCallback(
    async (username: string, password: string) => {
      setError(null);
      try {
        const result = await apiLogin(username, password);
        setChallenge(result);
        setEnrolment(null);
        if (result.enrolment_required && result.enrolment_token) {
          await fetchEnrolmentDetails(result.enrolment_token);
        }
      } catch (err) {
        setChallenge(null);
        setEnrolment(null);
        setError(apiErrorMessage(err, "Sign-in failed."));
        throw err;
      }
    },
    [fetchEnrolmentDetails],
  );

  const submitCode = useCallback(
    async (code: string) => {
      if (!challenge?.mfa_token) return;
      setError(null);
      try {
        const tokens = await apiVerifyMfa(challenge.mfa_token, code);
        tokenStore.set(tokens.access_token, tokens.refresh_token);
        setChallenge(null);
        await refreshMe();
      } catch (err) {
        setError(apiErrorMessage(err, "Verification failed."));
        throw err;
      }
    },
    [challenge, refreshMe],
  );

  const beginEnrolment = useCallback(async () => {
    if (!challenge?.enrolment_token) return;
    setError(null);
    try {
      await fetchEnrolmentDetails(challenge.enrolment_token);
    } catch (err) {
      setError(apiErrorMessage(err, "Could not start enrolment."));
      throw err;
    }
  }, [challenge, fetchEnrolmentDetails]);

  const confirmEnrolment = useCallback(
    async (code: string) => {
      if (!challenge?.enrolment_token) return;
      setError(null);
      try {
        const tokens = await apiConfirmEnrolment(challenge.enrolment_token, code);
        tokenStore.set(tokens.access_token, tokens.refresh_token);
        setChallenge(null);
        setEnrolment(null);
        await refreshMe();
      } catch (err) {
        setError(apiErrorMessage(err, "Verification failed."));
        throw err;
      }
    },
    [challenge, refreshMe],
  );

  const signOut = useCallback(async () => {
    try {
      await apiLogout();
    } catch {
      // The session may already be revoked server-side; clearing locally is
      // still the right outcome.
    }
    tokenStore.clear();
    setMe(null);
    setChallenge(null);
    setEnrolment(null);
  }, []);

  const cancelChallenge = useCallback(() => {
    setChallenge(null);
    setEnrolment(null);
    setError(null);
  }, []);

  const clearTermination = useCallback(() => setTerminated(null), []);

  const value = useMemo(
    () => ({
      me, challenge, enrolment, loading, error, terminated, clearTermination,
      signIn, submitCode, beginEnrolment, confirmEnrolment, signOut,
      cancelChallenge, refreshMe,
    }),
    [
      me, challenge, enrolment, loading, error, terminated, clearTermination,
      signIn, submitCode, beginEnrolment, confirmEnrolment, signOut,
      cancelChallenge, refreshMe,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
