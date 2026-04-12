export type WsMessage =
  | { type: "log"; level: string; phase: string; message: string }
  | { type: "phase_change"; phase: string; detail: string }
  | { type: "finding_found"; finding: { title: string; severity: string; location: string } }
  | { type: "scan_complete"; status: string; summary: Record<string, number> }
  | { type: "scan_error"; message: string }
  | { type: "ping" };

export interface ScanSocket {
  close(): void;
}

const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;
const RECONNECT_JITTER_MS = 500;
const PING_INTERVAL_MS = 25_000;

export function createScanSocket(
  scanId: string,
  onMessage: (msg: WsMessage) => void,
  onClose?: () => void,
): ScanSocket {
  let ws: WebSocket | null = null;
  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let attempt = 0;
  let destroyed = false;

  function buildUrl(): string {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}/ws/scans/${scanId}/progress`;
  }

  function clearPing() {
    if (pingTimer !== null) {
      clearInterval(pingTimer);
      pingTimer = null;
    }
  }

  function startPing() {
    clearPing();
    pingTimer = setInterval(() => {
      if (ws?.readyState === WebSocket.OPEN) ws.send("ping");
    }, PING_INTERVAL_MS);
  }

  function connect() {
    if (destroyed) return;
    ws = new WebSocket(buildUrl());

    ws.onopen = () => {
      attempt = 0;
      startPing();
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        onMessage(msg);
        // Stop reconnecting once the scan has a terminal event
        if (msg.type === "scan_complete" || msg.type === "scan_error") {
          destroyed = true;
          clearPing();
          onClose?.();
        }
      } catch {
        // ignore malformed frame
      }
    };

    ws.onclose = () => {
      clearPing();
      if (destroyed) {
        onClose?.();
        return;
      }
      // Exponential backoff with jitter
      const delay = Math.min(
        RECONNECT_BASE_MS * 2 ** attempt + Math.random() * RECONNECT_JITTER_MS,
        RECONNECT_MAX_MS,
      );
      attempt += 1;
      reconnectTimer = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      // onclose fires right after onerror — reconnect is handled there
      ws?.close();
    };
  }

  connect();

  return {
    close() {
      destroyed = true;
      clearPing();
      if (reconnectTimer !== null) clearTimeout(reconnectTimer);
      if (ws && ws.readyState !== WebSocket.CLOSED) ws.close();
    },
  };
}
