import { useEffect, useRef } from "react";
import { useNotificationStore } from "@/store/notificationStore";
import { scansApi, type Scan } from "@/api/scans";
import { createScanSocket } from "@/lib/websocket";

const POLL_MS = 8_000;

export function useScanNotifications() {
  const push = useNotificationStore((s) => s.push);
  // Track last-known status per scan to detect transitions
  const prevStatus = useRef<Record<string, string>>({});
  // Track active WS connections per scan
  const sockets = useRef<Record<string, { close(): void }>>({});

  useEffect(() => {
    let mounted = true;

    async function poll() {
      if (!mounted) return;
      try {
        const scans: Scan[] = await scansApi.list({ limit: 30 });

        for (const scan of scans) {
          const prev = prevStatus.current[scan.id];
          const cur = scan.status;

          // ── Detect status transitions ────────────────────────────────────
          if (prev && prev !== cur) {
            if (cur === "running") {
              push({
                type: "info",
                title: "Scan started",
                message: `Scanning ${new URL(scan.target_url).hostname}…`,
                scanId: scan.id,
              });
            } else if (cur === "completed") {
              const total =
                (scan.findings_critical ?? 0) +
                (scan.findings_high ?? 0) +
                (scan.findings_medium ?? 0) +
                (scan.findings_low ?? 0) +
                (scan.findings_info ?? 0);
              const critHigh = (scan.findings_critical ?? 0) + (scan.findings_high ?? 0);
              push({
                type: critHigh > 0 ? "warning" : "success",
                title: "Scan completed",
                message: `${new URL(scan.target_url).hostname}: ${total} finding${total !== 1 ? "s" : ""}${critHigh > 0 ? ` (${critHigh} Critical/High)` : ""}`,
                scanId: scan.id,
              });
            } else if (cur === "failed") {
              push({
                type: "error",
                title: "Scan failed",
                message: `${new URL(scan.target_url).hostname}: ${scan.error_message ?? "Unknown error"}`,
                scanId: scan.id,
              });
            } else if (cur === "cancelled") {
              push({
                type: "info",
                title: "Scan cancelled",
                message: `Scan of ${new URL(scan.target_url).hostname} was cancelled.`,
                scanId: scan.id,
              });
            }
          }

          // First-time observation of a running scan
          if (!prev && cur === "running") {
            push({
              type: "info",
              title: "Scan in progress",
              message: `Active scan detected: ${new URL(scan.target_url).hostname}`,
              scanId: scan.id,
            });
          }

          prevStatus.current[scan.id] = cur;

          // ── Attach WS listener for running scans ─────────────────────────
          if (cur === "running" && !sockets.current[scan.id]) {
            sockets.current[scan.id] = createScanSocket(scan.id, (msg) => {
              if (msg.type === "finding_found") {
                push({
                  type: "warning",
                  title: `Finding: ${msg.finding.severity}`,
                  message: `${msg.finding.title}: ${msg.finding.location?.slice(0, 60)}`,
                  scanId: scan.id,
                });
              } else if (msg.type === "phase_change" && msg.phase) {
                const label: Record<string, string> = {
                  recon:   "Recon - crawling target",
                  vuln:    "Analysing attack surface",
                  exploit: "Exploit phase - testing hypotheses",
                  report:  "Generating findings report",
                };
                push({
                  type: "info",
                  title: "Phase update",
                  message: `${new URL(scan.target_url).hostname}: ${label[msg.phase] ?? msg.phase}`,
                  scanId: scan.id,
                });
              } else if (msg.type === "scan_complete" || msg.type === "scan_error") {
                delete sockets.current[scan.id];
              }
            });
          }

          // Clean up WS for finished scans
          if (["completed", "failed", "cancelled"].includes(cur) && sockets.current[scan.id]) {
            sockets.current[scan.id].close();
            delete sockets.current[scan.id];
          }
        }
      } catch {
        // silently ignore — auth may not be ready yet
      }
    }

    poll();
    const timer = setInterval(poll, POLL_MS);

    return () => {
      mounted = false;
      clearInterval(timer);
      Object.values(sockets.current).forEach((s) => s.close());
      sockets.current = {};
    };
  }, [push]);
}
