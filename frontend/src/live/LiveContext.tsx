import { createContext, useContext, type ReactNode } from "react";
import { useLiveEvents } from "../hooks/useLiveEvents";
import type { LiveEvent } from "../api/client";

interface LiveState {
  status: "connecting" | "open" | "closed" | "terminated";
  lastEvent: LiveEvent | null;
  events: LiveEvent[];
  lastHeartbeat: Date | null;
  terminationReason: string | null;
}

const LiveContext = createContext<LiveState | null>(null);

/**
 * One WebSocket for the whole app.
 *
 * Every page that wants live data reads from this context rather than opening
 * its own socket — otherwise navigating between Live Monitoring, Alerts and
 * Overview would hold three connections and issue three tickets.
 */
export function LiveProvider({ children }: { children: ReactNode }) {
  const live = useLiveEvents(true);
  return <LiveContext.Provider value={live}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveState {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive must be used inside <LiveProvider>");
  return ctx;
}
