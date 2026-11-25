import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { SEV_BADGE } from "./badges";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_COLORS: Record<string, string> = {
  Critical: SEV_BADGE.Critical,
  High: SEV_BADGE.High,
  Medium: SEV_BADGE.Medium,
  Low: SEV_BADGE.Low,
  Informational: SEV_BADGE.Informational,
};

export const SEVERITY_DOT: Record<string, string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-amber-500",
  Low: "bg-blue-500",
  Informational: "bg-slate-400",
};

export const FINDING_STATUS_HEX: Record<string, string> = {
  "Open":               "#dc2626",
  "Partially Resolved": "#2563eb",
  "Risk Accepted":      "#d97706",
  "Resolved":           "#16a34a",
  "Closed":             "#6b7280",
  "NA":                 "#94a3b8",
};

export const STATUS_COLORS: Record<string, string> = {
  queued: "text-slate-700 bg-slate-100 border-slate-200 dark:text-zinc-300 dark:bg-zinc-800 dark:border-zinc-700",
  running: "text-blue-800 bg-blue-50 border-blue-200 dark:text-blue-300 dark:bg-blue-950/40 dark:border-blue-800/50",
  completed: "text-emerald-800 bg-emerald-50 border-emerald-200 dark:text-emerald-300 dark:bg-emerald-950/40 dark:border-emerald-800/50",
  failed: "text-red-800 bg-red-50 border-red-200 dark:text-red-300 dark:bg-red-950/40 dark:border-red-800/50",
  cancelled: "text-slate-600 bg-slate-100 border-slate-200 dark:text-zinc-400 dark:bg-zinc-800 dark:border-zinc-700",
};

export function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return "-";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString();
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const now = Date.now();
  const normalized = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
  const then = new Date(normalized).getTime();
  const diff = Math.round((now - then) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
