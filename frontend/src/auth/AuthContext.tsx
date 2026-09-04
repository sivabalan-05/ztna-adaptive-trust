import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
  type ReactNode,
} from "react";
import {
  apiErrorMessage, getMe, login as apiLogin, logout as apiLogout, tokenStore,
  verifyMfa as apiVerifyMfa, type LoginChallenge, type Me,
} from "../api/client";

interface AuthState {
  me: Me | null;
  challenge: LoginChallenge | null;
  loading: boolean;
  error: string | null;
  terminated: string | null;
  clearTermination: () => void;
  signIn: (username: string, password: string) => Promise<void>;
  submitCode: (code: string) => Promise<void>;
  signOut: () => Promise<void>;
  cancelChallenge: () => void;
  refreshMe: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null);
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

  const signIn = useCallback(async (username: string, password: string) => {
    setError(null);
    try {
      setChallenge(await apiLogin(username, password));
    } catch (err) {
      setChallenge(null);
      setError(apiErrorMessage(err, "Sign-in failed."));
      throw err;
    }
  }, []);

  const submitCode = useCallback(
    async (code: string) => {
      if (!challenge) return;
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
  }, []);

  const cancelChallenge = useCallback(() => {
    setChallenge(null);
    setError(null);
  }, []);

  const clearTermination = useCallback(() => setTerminated(null), []);

  const value = useMemo(
    () => ({
      me, challenge, loading, error, terminated, clearTermination,
      signIn, submitCode, signOut, cancelChallenge, refreshMe,
    }),
    [
      me, challenge, loading, error, terminated, clearTermination,
      signIn, submitCode, signOut, cancelChallenge, refreshMe,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
