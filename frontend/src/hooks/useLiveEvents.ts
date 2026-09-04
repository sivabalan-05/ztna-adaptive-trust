import { useCallback, useEffect, useRef, useState } from "react";
import { getWsTicket, wsBaseUrl, type LiveEvent } from "../api/client";

export type LiveStatus = "connecting" | "open" | "closed" | "terminated";

interface UseLiveEvents {
  status: LiveStatus;
  lastEvent: LiveEvent | null;
  events: LiveEvent[];
  terminationReason: string | null;
  lastHeartbeat: Date | null;
}

/**
 * Subscribes to the server's live event stream.
 *
 * The handshake uses a single-use 30-second ticket rather than the access
 * token, because a WebSocket URL ends up in proxy logs and browser history and
 * a bearer token has no business being there.
 *
 * Reconnects with backoff on an unexpected close, but *not* after a
 * termination: if the server closed the socket because the session was
 * revoked, reconnecting would be arguing with the enforcement decision.
 */
export function useLiveEvents(enabled: boolean): UseLiveEvents {
  const [status, setStatus] = useState<LiveStatus>("closed");
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [lastEvent, setLastEvent] = useState<LiveEvent | null>(null);
  const [lastHeartbeat, setLastHeartbeat] = useState<Date | null>(null);
  const [terminationReason, setTerminationReason] = useState<string | null>(null);

  const socketRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);
  const timerRef = useRef<number | null>(null);
  const stoppedRef = useRef(false);

  const connect = useCallback(async () => {
    if (stoppedRef.current) return;
    setStatus("connecting");
    try {
      const { ticket } = await getWsTicket();
      const socket = new WebSocket(
        `${wsBaseUrl}/ws/live?ticket=${encodeURIComponent(ticket)}`,
      );
      socketRef.current = socket;

      socket.onopen = () => {
        retryRef.current = 0;
        setStatus("open");
      };

      socket.onmessage = (message) => {
        const event = JSON.parse(message.data) as LiveEvent;
        if (event.type === "heartbeat") {
          setLastHeartbeat(new Date());
          return;
        }
        setLastEvent(event);
        setEvents((previous) => [event, ...previous].slice(0, 50));

        if (
          event.type === "session.terminated" ||
          event.type === "session.revoked" ||
          event.type === "session.expired"
        ) {
          const reason = String(event.payload.reason ?? "Session ended.");
          stoppedRef.current = true;
          setTerminationReason(reason);
          setStatus("terminated");
          window.dispatchEvent(
            new CustomEvent("ztna:session-terminated", { detail: reason }),
          );
        }
      };

      socket.onclose = () => {
        socketRef.current = null;
        if (stoppedRef.current) {
          setStatus("terminated");
          return;
        }
        setStatus("closed");
        const delay = Math.min(1000 * 2 ** retryRef.current, 15_000);
        retryRef.current += 1;
        timerRef.current = window.setTimeout(connect, delay);
      };

      socket.onerror = () => socket.close();
    } catch {
      setStatus("closed");
      const delay = Math.min(1000 * 2 ** retryRef.current, 15_000);
      retryRef.current += 1;
      timerRef.current = window.setTimeout(connect, delay);
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    stoppedRef.current = false;
    connect();
    return () => {
      stoppedRef.current = true;
      if (timerRef.current) window.clearTimeout(timerRef.current);
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [enabled, connect]);

  return { status, lastEvent, events, terminationReason, lastHeartbeat };
}
