import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_COLORS: Record<string, string> = {
  Critical: "text-red-600 bg-red-50 border-red-200",
  High: "text-orange-600 bg-orange-50 border-orange-200",
  Medium: "text-yellow-700 bg-yellow-50 border-yellow-200",
  Low: "text-blue-600 bg-blue-50 border-blue-200",
  Informational: "text-gray-600 bg-gray-50 border-gray-200",
};

export const SEVERITY_DOT: Record<string, string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-blue-500",
  Informational: "bg-gray-400",
};

// Finding workflow status colors (hex, used for inline styles)
export const FINDING_STATUS_HEX: Record<string, string> = {
  "Open":               "#dc2626",
  "Partially Resolved": "#2563eb",
  "Risk Accepted":      "#d97706",
  "Resolved":           "#16a34a",
  "Closed":             "#6b7280",
  "NA":                 "#94a3b8",
};

export const STATUS_COLORS: Record<string, string> = {
  queued: "text-gray-600 bg-gray-100",
  running: "text-blue-700 bg-blue-100",
  completed: "text-green-700 bg-green-100",
  failed: "text-red-700 bg-red-100",
  cancelled: "text-gray-500 bg-gray-100",
};

export function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const now = Date.now();
  // Normalize naive UTC strings (no Z / no timezone offset) from the backend
  const normalized = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
  const then = new Date(normalized).getTime();
  const diff = Math.round((now - then) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
