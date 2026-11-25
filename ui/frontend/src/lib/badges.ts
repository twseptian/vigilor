/** Dual-theme badge / severity classes — soft contrast, easy on the eyes. */

export const SEV_BADGE: Record<string, string> = {
  Critical:
    "bg-red-50/90 text-red-700 border-red-200/80 dark:bg-red-950/40 dark:text-red-300/90 dark:border-red-900/50",
  High:
    "bg-orange-50/90 text-orange-700 border-orange-200/80 dark:bg-orange-950/40 dark:text-orange-300/90 dark:border-orange-900/50",
  Medium:
    "bg-amber-50/90 text-amber-800 border-amber-200/80 dark:bg-amber-950/40 dark:text-amber-200/90 dark:border-amber-900/50",
  Low:
    "bg-blue-50/90 text-blue-700 border-blue-200/80 dark:bg-blue-950/40 dark:text-blue-300/90 dark:border-blue-900/50",
  Informational:
    "bg-slate-100/90 text-slate-600 border-slate-200/80 dark:bg-zinc-800/80 dark:text-zinc-300 dark:border-zinc-700/80",
};

/** Muted severity accents (ribbons, charts, KPI) — avoid neon #dc2626 glare */
export const SEV_HEX = {
  Critical: "#b91c1c",
  High: "#c2410c",
  Medium: "#a16207",
  Low: "#1d4ed8",
  Informational: "#64748b",
} as const;

/** Soft ribbon backgrounds */
export const SEV_SOFT_BG = {
  Critical: { light: "#fef2f2", dark: "#2a1414" },
  High: { light: "#fff7ed", dark: "#2a1c12" },
  Medium: { light: "#fefce8", dark: "#282210" },
  Low: { light: "#eff6ff", dark: "#121a28" },
  Informational: { light: "#f8fafc", dark: "#1f1f23" },
} as const;

export const TONE_BADGE = {
  teal: "bg-teal-50 text-teal-800 border-teal-200 dark:bg-teal-950/45 dark:text-teal-200 dark:border-teal-800/45",
  indigo: "bg-indigo-50 text-indigo-800 border-indigo-200 dark:bg-indigo-950/45 dark:text-indigo-200 dark:border-indigo-800/45",
  emerald: "bg-teal-50 text-teal-800 border-teal-200 dark:bg-teal-950/45 dark:text-teal-200 dark:border-teal-800/45",
  red: "bg-red-50 text-red-800 border-red-200 dark:bg-red-950/45 dark:text-red-300 dark:border-red-800/45",
  amber: "bg-amber-50 text-amber-900 border-amber-200 dark:bg-amber-950/45 dark:text-amber-200 dark:border-amber-800/45",
  orange: "bg-orange-50 text-orange-800 border-orange-200 dark:bg-orange-950/45 dark:text-orange-200 dark:border-orange-800/45",
  blue: "bg-blue-50 text-blue-800 border-blue-200 dark:bg-blue-950/45 dark:text-blue-200 dark:border-blue-800/45",
  slate: "bg-slate-100 text-slate-700 border-slate-200 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700",
} as const;

export const LINK_TEAL =
  "text-teal-700 hover:text-teal-800 dark:text-teal-300 dark:hover:text-teal-200";

export const ACCENT_TEAL =
  "text-teal-700 dark:text-teal-300";
