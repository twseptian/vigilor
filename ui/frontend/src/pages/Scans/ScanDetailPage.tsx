import { Fragment, useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import {
  XCircle, RotateCcw, ChevronRight, Search, Code2,
  ShieldAlert, Zap, FileText, Check, ChevronDown, ChevronUp,
  Cpu, ScanLine, GitBranch, MessageSquareText, Clock,
  CheckCircle2, AlertTriangle, Ban, Timer, Download, Loader2, ShieldCheck,
  Trash2, Terminal, Activity, Target, TrendingUp, Copy, Workflow, X,
} from "lucide-react";
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RTooltip,
} from "recharts";
import { scansApi, type Scan, type ScanLog } from "@/api/scans";
import { findingsApi, type Finding } from "@/api/findings";
import AttackWorkflowPanel from "@/components/workflow/AttackWorkflowPanel";
import { workflowsApi, type AttackWorkflow } from "@/api/workflows";
import { createScanSocket, type WsMessage } from "@/lib/websocket";
import { formatDuration, relativeTime } from "@/lib/utils";
import { SEV_BADGE, SEV_HEX, TONE_BADGE } from "@/lib/badges";
import { useThemeStore } from "@/store/themeStore";
import api from "@/api/client";

// ── Design tokens ─────────────────────────────────────────────────────────────

const SEV_SOFT = {
  Critical: { light: "#fef2f2", dark: "#2a1414", borderLight: "#fecaca", borderDark: "#7f1d1d" },
  High: { light: "#fff7ed", dark: "#2a1c12", borderLight: "#fed7aa", borderDark: "#7c4a1a" },
  Medium: { light: "#fefce8", dark: "#282210", borderLight: "#fde68a", borderDark: "#7a5b12" },
  Low: { light: "#eff6ff", dark: "#121a28", borderLight: "#bfdbfe", borderDark: "#1e3a5f" },
  Informational: { light: "#f8fafc", dark: "#27272a", borderLight: "#e2e8f0", borderDark: "#3f3f46" },
} as const;

const SEV: Record<string, { color: string; badge: string }> = {
  Critical:      { color: SEV_HEX.Critical, badge: SEV_BADGE.Critical },
  High:          { color: SEV_HEX.High, badge: SEV_BADGE.High },
  Medium:        { color: SEV_HEX.Medium, badge: SEV_BADGE.Medium },
  Low:           { color: SEV_HEX.Low, badge: SEV_BADGE.Low },
  Informational: { color: SEV_HEX.Informational, badge: SEV_BADGE.Informational },
};

const STATUS_COLORS_CHART: Record<string, string> = {
  "Open":               "#dc2626",
  "Partially Resolved": "#2563eb",
  "Risk Accepted":      "#d97706",
  "Resolved":           "#16a34a",
  "Closed":             "#a1a1aa",
  "NA":                 "#a1a1aa",
};

const STATUS_BADGE: Record<string, { dot: string; text: string; bg: string; border: string; label: string }> = {
  running:   { dot: "bg-blue-500 animate-pulse", text: "text-blue-800 dark:text-blue-300", bg: "bg-blue-50 dark:bg-blue-950/40", border: "border-blue-200 dark:border-blue-800/50", label: "Running" },
  queued:    { dot: "bg-indigo-400", text: "text-indigo-800 dark:text-indigo-300", bg: "bg-indigo-50 dark:bg-indigo-950/40", border: "border-indigo-200 dark:border-indigo-800/50", label: "Queued" },
  completed: { dot: "bg-emerald-500", text: "text-emerald-800 dark:text-emerald-300", bg: "bg-emerald-50 dark:bg-emerald-950/40", border: "border-emerald-200 dark:border-emerald-800/50", label: "Completed" },
  failed:    { dot: "bg-red-500", text: "text-red-800 dark:text-red-300", bg: "bg-red-50 dark:bg-red-950/40", border: "border-red-200 dark:border-red-800/50", label: "Failed" },
  cancelled: { dot: "bg-slate-400", text: "text-slate-700 dark:text-zinc-300", bg: "bg-slate-100 dark:bg-zinc-800", border: "border-slate-200 dark:border-zinc-700", label: "Cancelled" },
};

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

function chartTooltip(isLight: boolean) {
  return {
    fontSize: 12, borderRadius: 6,
    border: isLight ? "1px solid #e2e8f0" : "1px solid #3f3f46",
    boxShadow: "0 4px 16px rgba(15,23,42,0.08)",
    backgroundColor: isLight ? "#ffffff" : "#18181b",
    color: isLight ? "#334155" : "#d4d4d8",
  };
}

// ── Phase config ──────────────────────────────────────────────────────────────

const PHASE_CONFIG = [
  { key: "recon",           label: "Recon",       icon: Search,     desc: "Crawl & fingerprint"       },
  { key: "static_analysis", label: "Static",      icon: Code2,      desc: "Header & source checks"    },
  { key: "vuln",            label: "Vuln",         icon: ShieldAlert,desc: "Hypothesis generation"    },
  { key: "exploit",         label: "Exploit",      icon: Zap,        desc: "Automated exploitation"   },
  { key: "report",          label: "Report",       icon: FileText,   desc: "Findings compilation"      },
];

// ── Shared primitives ─────────────────────────────────────────────────────────

function CopyUrlButton({ url }: { url: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={handleCopy}
      title={copied ? "Copied!" : "Copy URL"}
      className={`flex items-center gap-1 text-[10px] font-medium px-1.5 py-0.5 rounded border transition-all duration-150 ${
        copied
          ? "bg-emerald-50 border-emerald-200 text-emerald-800 dark:bg-emerald-950/50 dark:border-emerald-800/50 dark:text-emerald-400"
          : "bg-slate-100 dark:bg-zinc-800/40 border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:hover:text-zinc-300 hover:border-slate-300 dark:hover:border-zinc-600 hover:bg-slate-50 dark:hover:bg-zinc-800"
      }`}
    >
      {copied
        ? <><Check className="h-3 w-3" /> Copied</>
        : <><Copy className="h-3 w-3" /> Copy</>}
    </button>
  );
}

function SectionHeader({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <Icon className="h-3.5 w-3.5 text-slate-500 dark:text-zinc-400" />
      <span className="text-[11px] font-bold uppercase tracking-[0.15em] text-slate-500 dark:text-zinc-400">{label}</span>
      <div className="flex-1 h-px bg-slate-200" />
    </div>
  );
}

function Card({ accent = "#6366f1", children, className = "" }: { accent?: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white dark:bg-zinc-900 rounded-lg border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden ${className}`}>
      <div className="w-full h-[2px]" style={{ backgroundColor: accent }} />
      {children}
    </div>
  );
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_BADGE[status] ?? STATUS_BADGE.cancelled;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-2 h-2 rounded-full shrink-0 ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

// ── Severity badge ────────────────────────────────────────────────────────────

function SevBadge({ severity }: { severity: string }) {
  const cfg = SEV[severity] ?? SEV.Informational;
  return (
    <span className={`inline-block text-[10px] font-semibold px-2 py-0.5 rounded border ${cfg.badge}`}>
      {severity === "Informational" ? "Info" : severity}
    </span>
  );
}

// ── CVSS cell (v3.1 + v4.0, compact single-row) ──────────────────────────────

function CvssCell({ score, vector, score4, vector4 }: {
  score: number | null; vector: string | null;
  score4: number | null; vector4: string | null;
}) {
  if (score == null && score4 == null) return <span className="text-[11px] text-slate-700 dark:text-zinc-300">-</span>;

  const cvssColor = (s: number) =>
    s >= 9 ? "#dc2626" : s >= 7 ? "#ea580c" : s >= 4 ? "#d97706" : s > 0 ? "#2563eb" : "#a1a1aa";
  const cvssLabel = (s: number) =>
    s >= 9 ? "CRIT" : s >= 7 ? "HIGH" : s >= 4 ? "MED" : s > 0 ? "LOW" : "NONE";

  const fullVec = [vector, vector4].filter(Boolean).join("\n");
  const highScore = Math.max(score ?? 0, score4 ?? 0);

  return (
    <div title={fullVec || undefined} className="cursor-default space-y-0.5">
      {/* Scores on one row */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {score != null && (
          <div className="flex items-center gap-0.5">
            <span className="text-[8px] font-mono font-bold text-slate-500 dark:text-zinc-400">3.1</span>
            <span className="text-[12px] font-black tabular-nums leading-none" style={{ color: cvssColor(score) }}>{score.toFixed(1)}</span>
          </div>
        )}
        {score != null && score4 != null && (
          <span className="text-slate-700 dark:text-zinc-300 text-[10px] leading-none">·</span>
        )}
        {score4 != null && (
          <div className="flex items-center gap-0.5">
            <span className="text-[8px] font-mono font-bold text-indigo-400">4.0</span>
            <span className="text-[12px] font-black tabular-nums leading-none" style={{ color: cvssColor(score4) }}>{score4.toFixed(1)}</span>
          </div>
        )}
        {/* Severity pill for highest score */}
        <span
          className="text-[8px] font-bold px-1 py-px rounded leading-none"
          style={{ color: cvssColor(highScore), backgroundColor: `${cvssColor(highScore)}14` }}
        >
          {cvssLabel(highScore)}
        </span>
      </div>
      {/* Vector — micro mono, full string in title tooltip */}
      {(vector || vector4) && (
        <p className="text-[8px] font-mono text-slate-500 dark:text-zinc-400 leading-none truncate max-w-[150px]">
          {(vector ?? vector4)!.replace(/^CVSS:[0-9.]+\//, "")}
        </p>
      )}
    </div>
  );
}

// ── Remediation card ──────────────────────────────────────────────────────────

/** Compact labelled select used by the findings triage toolbar. */
function FilterSelect({ label, value, onChange, options, render }: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
  render?: (v: string) => string;
}) {
  const active = value !== "all";
  return (
    <label className={`flex items-center gap-1.5 border rounded-lg pl-2 pr-1 py-1 bg-white dark:bg-zinc-900 transition-colors ${
      active ? "border-teal-600/50" : "border-slate-200 dark:border-zinc-800"
    }`}>
      <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 dark:text-zinc-400">{label}</span>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className={`bg-transparent text-[11px] outline-none cursor-pointer pr-1 ${
          active ? "text-teal-700 dark:text-teal-300 font-semibold" : "text-slate-700 dark:text-zinc-300"
        }`}
      >
        {options.map(o => (
          <option key={o} value={o}>{render ? render(o) : o === "all" ? "All" : o}</option>
        ))}
      </select>
    </label>
  );
}

/** Dropdown used by the bulk triage bar. */
function BulkMenu({ label, open, onToggle, options, onPick, pending }: {
  label: string;
  open: boolean;
  onToggle: () => void;
  options: string[];
  onPick: (v: string) => void;
  pending: boolean;
}) {
  return (
    <div className="relative">
      <button
        onClick={onToggle}
        disabled={pending}
        className="flex items-center gap-1 text-[10px] font-semibold px-2.5 py-1 rounded-lg border border-teal-300 dark:border-teal-800/45 bg-white dark:bg-zinc-900 text-teal-700 dark:text-teal-300 hover:bg-teal-50 dark:hover:bg-teal-950/40 disabled:opacity-50 transition-colors"
      >
        {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
        {label}
        <ChevronDown className="h-3 w-3" />
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-1 z-20 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-lg shadow-lg py-1 min-w-[140px]">
          {options.map(o => (
            <button
              key={o}
              onClick={() => onPick(o)}
              className="w-full text-left px-3 py-1.5 text-[11px] text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors"
            >
              {o}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** One column of the expanded finding row. Clamped so a long body can't blow up the table. */
function FindingPreviewBlock({ label, body }: { label: string; body: string | null | undefined }) {
  return (
    <div className="min-w-0">
      <p className="text-[9px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400 mb-1">{label}</p>
      {body ? (
        <p className="text-[11px] text-slate-700 dark:text-zinc-300 leading-relaxed whitespace-pre-wrap max-h-24 overflow-y-auto pr-1">
          {body}
        </p>
      ) : (
        <p className="text-[11px] text-slate-700 dark:text-zinc-300 italic">Not provided</p>
      )}
    </div>
  );
}

/** Compact evidence state — mirrors the badges on the finding detail page. */
function EvidenceChip({ finding }: { finding: Finding }) {
  const hasRaw = !!(finding.raw_request || finding.raw_response);
  const manual = finding.evidence_source === "manual";

  const cfg = !hasRaw
    ? { label: "No HTTP evidence", cls: TONE_BADGE.red }
    : manual
      ? { label: "Analyst-supplied", cls: TONE_BADGE.amber }
      : { label: "Agent-captured", cls: TONE_BADGE.emerald };

  return (
    <>
      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${cfg.cls}`}>
        {cfg.label}
      </span>
      <span
        className="text-[9px] font-bold px-1.5 py-0.5 rounded border bg-slate-100 dark:bg-zinc-800/40 text-slate-500 dark:text-zinc-400 border-slate-200 dark:border-zinc-800 tabular-nums"
        title="Automatic confidence score (0-100)"
      >
        CONF {finding.confidence_score}
      </span>
    </>
  );
}

// ── Findings overview ─────────────────────────────────────────────────────────

// ── Phase stepper ─────────────────────────────────────────────────────────────

function PhaseStepper({ scan }: { scan: Scan }) {
  const normalizedPhase = scan.phase?.split(":")[0] ?? "";
  const phaseIdx = PHASE_CONFIG.findIndex(p => p.key === normalizedPhase);
  const isCompleted = scan.status === "completed";
  const isFailed = scan.status === "failed";

  // Live hypothesis progress (streamed during the exploit phase).
  const hypTotal     = scan.hypotheses_total ?? 0;
  const hypConfirmed = scan.hypotheses_confirmed ?? 0;
  const hypTested    = Math.min(scan.hypotheses_tested ?? 0, hypTotal);
  const hypProgressPct = hypTotal ? Math.round((hypTested / hypTotal) * 100) : 0;

  const totalFindings =
    scan.findings_critical + scan.findings_high + scan.findings_medium +
    scan.findings_low + scan.findings_info;

  /**
   * Only phases the backend actually counts get a metric line. Recon and Static
   * have no counters on the Scan model, so they stay metric-less rather than
   * showing a number we would have had to invent.
   */
  const metricFor = (key: string): string | null => {
    if (key === "vuln" && scan.hypotheses_total > 0) return `${scan.hypotheses_total} hypotheses`;
    if (key === "exploit" && scan.hypotheses_confirmed > 0) return `${scan.hypotheses_confirmed} confirmed`;
    if (key === "report" && totalFindings > 0) return `${totalFindings} findings`;
    return null;
  };

  return (
    <Card accent="#6366f1">
      <div className="px-5 py-4">
        {/* Pipeline — same visual grammar as the attack workflow graph: stage nodes
            joined by edges, so both views of a scan read the same way. */}
        <div className="flex items-stretch gap-0 overflow-x-auto pb-1">
          {PHASE_CONFIG.map((phase, i) => {
            const done   = (isCompleted || phaseIdx > i) && !(isFailed && phaseIdx === i);
            const active = !isCompleted && phaseIdx === i && scan.status === "running";
            const failed = isFailed && phaseIdx === i;
            const Icon   = phase.icon;
            const metric = metricFor(phase.key);

            const accent = failed ? "#dc2626" : done ? "#2563eb" : active ? "#4f46e5" : "#71717a";
            const nextReached = isCompleted || phaseIdx > i;

            return (
              <Fragment key={phase.key}>
                {i > 0 && (
                  /* Edge between stages */
                  <div className="flex items-center shrink-0 px-1 pt-6">
                    <div
                      className={`h-px w-4 sm:w-6 transition-colors duration-500 ${
                        nextReached ? "bg-teal-400" : "bg-slate-200"
                      }`}
                    />
                    <ChevronRight
                      className={`h-3 w-3 -ml-1 transition-colors duration-500 ${
                        nextReached ? "text-teal-700 dark:text-teal-400" : "text-slate-700 dark:text-zinc-300"
                      }`}
                    />
                  </div>
                )}

                <div
                  className={`relative flex-1 min-w-[132px] rounded-lg border pl-3 pr-2.5 py-2.5 transition-all duration-300 ${
                    failed ? "bg-red-50/50 border-red-800/50"
                    : done   ? "bg-white dark:bg-zinc-900 border-slate-200 dark:border-zinc-800 shadow-sm"
                    : active ? "bg-white dark:bg-zinc-900 border-teal-600/50 shadow-[0_0_0_3px_rgba(139,92,246,0.12)]"
                    :          "bg-slate-100 dark:bg-zinc-800/50 border-dashed border-slate-200 dark:border-zinc-800"}`}
                >
                  {/* Stage accent, mirroring the node cards in the workflow graph */}
                  <div
                    className="absolute left-0 top-0 bottom-0 w-[3px] rounded-l-lg transition-colors duration-300"
                    style={{ backgroundColor: accent }}
                  />

                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span
                      className="text-[8px] font-bold uppercase tracking-[0.14em] transition-colors"
                      style={{ color: done || active || failed ? accent : "#a1a1aa" }}
                    >
                      Phase {i + 1}
                    </span>
                    {/* State marker only — the phase's own icon lives next to the label,
                        so a completed pipeline still reads as five distinct phases
                        instead of five identical ticks. */}
                    {failed ? (
                      <XCircle className="h-3.5 w-3.5 text-red-500" />
                    ) : done ? (
                      <Check className="h-3.5 w-3.5 text-teal-700 dark:text-teal-400" />
                    ) : active ? (
                      <span className="relative flex h-2 w-2">
                        <span className="absolute inline-flex h-2 w-2 rounded-full bg-teal-400 opacity-75 animate-ping" />
                        <span className="relative inline-flex h-2 w-2 rounded-full bg-teal-500" />
                      </span>
                    ) : null}
                  </div>

                  <div className="flex items-start gap-2">
                    <span
                      className={`shrink-0 flex items-center justify-center h-6 w-6 rounded-md border transition-colors ${
                        active ? "animate-pulse" : ""
                      }`}
                      style={{
                        backgroundColor: done || active || failed ? `${accent}14` : "#27272a",
                        borderColor: done || active || failed ? `${accent}33` : "#3f3f46",
                        color: done || active || failed ? accent : "#71717a",
                      }}
                      title={phase.desc}
                    >
                      <Icon className="h-3.5 w-3.5" />
                    </span>

                    <div className="min-w-0">
                      <p className={`text-[12px] font-bold leading-tight truncate ${
                        failed ? "text-red-700 dark:text-red-300" : done ? "text-slate-800 dark:text-zinc-200" : active ? "text-teal-700 dark:text-teal-300" : "text-slate-500 dark:text-zinc-400"
                      }`}>
                        {phase.label}
                      </p>
                      <p className={`text-[9px] leading-snug mt-0.5 truncate ${
                        done || active ? "text-slate-500 dark:text-zinc-400" : "text-slate-700 dark:text-zinc-300"
                      }`}>
                        {phase.desc}
                      </p>
                    </div>
                  </div>

                  {/* A failed phase keeps its metric — partial progress is still information */}
                  {metric && (done || active || failed) && (
                    <p className="text-[9px] font-semibold tabular-nums mt-1 pt-1 border-t border-slate-200 dark:border-zinc-800 truncate"
                       style={{ color: accent }}>
                      {metric}
                    </p>
                  )}
                </div>
              </Fragment>
            );
          })}
        </div>

        {/* Status bar */}
        {scan.status === "running" && scan.phase && (
          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-zinc-800 space-y-2">
            <div className="flex items-center gap-2 text-[11px] text-blue-400 flex-wrap">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
              <span>Running <strong>{PHASE_CONFIG.find(p => p.key === normalizedPhase)?.label ?? normalizedPhase}</strong></span>
              {scan.phase?.includes(":feedback_") && <span className="text-blue-400">(Feedback loop {scan.phase.split("_")[1]})</span>}
              {scan.phase_detail && <span className="text-slate-500 dark:text-zinc-400">: {scan.phase_detail}</span>}
            </div>

            {/* Live hypothesis progress — real counts streamed from the exploit
                loop, not an indeterminate spinner. Only shown once hypotheses
                exist (i.e. from the vuln phase onward). */}
            {hypTotal > 0 && (
              <div>
                <div className="flex items-center justify-between text-[10px] mb-1">
                  <span className="text-slate-500 dark:text-zinc-400 font-medium tabular-nums">
                    <strong className="text-slate-700 dark:text-zinc-300">{hypTested}</strong> / {hypTotal} hypotheses tested
                    {hypConfirmed > 0 && (
                      <span className="text-emerald-700 dark:text-emerald-400 font-semibold"> · {hypConfirmed} confirmed</span>
                    )}
                  </span>
                  <span className="text-slate-500 dark:text-zinc-400 tabular-nums">{hypProgressPct}%</span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-100 dark:bg-zinc-800 overflow-hidden flex">
                  {/* confirmed portion sits ahead of the remaining-tested portion */}
                  <div className="h-full bg-emerald-500 transition-all duration-500"
                       style={{ width: `${hypTotal ? (hypConfirmed / hypTotal) * 100 : 0}%` }} />
                  <div className="h-full bg-blue-400 transition-all duration-500"
                       style={{ width: `${hypTotal ? (Math.max(0, hypTested - hypConfirmed) / hypTotal) * 100 : 0}%` }} />
                </div>
              </div>
            )}
          </div>
        )}
        {scan.status === "completed" && (
          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-zinc-800 flex items-center gap-2 text-[11px] text-emerald-700 dark:text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span className="font-semibold">Scan completed successfully</span>
            {scan.duration_seconds && (
              <span className="text-slate-500 dark:text-zinc-400 flex items-center gap-1">
                <Timer className="h-3 w-3" /> {formatDuration(scan.duration_seconds)}
              </span>
            )}
          </div>
        )}
        {scan.status === "failed" && (
          <div className="mt-4 pt-3 border-t border-slate-200 dark:border-zinc-800 flex items-center gap-2 text-[11px] text-red-600 dark:text-red-400">
            <XCircle className="h-3.5 w-3.5" />
            <span className="font-semibold">Scan failed</span>
            {scan.error_message && <span className="text-slate-500 dark:text-zinc-400 truncate max-w-md">: {scan.error_message}</span>}
          </div>
        )}
      </div>
    </Card>
  );
}

// ── Report types + list component ─────────────────────────────────────────────

interface ReportOut {
  id: string; scan_id: string; format: string;
  file_size_kb: number | null; generated_by: string; generated_at: string;
}


// ── Result charts (shown only once the scan has completed) ────────────────────

function ScanCharts({ findings, scan }: { findings: Finding[]; scan: Scan }) {
  const theme = useThemeStore(s => s.theme);
  const isLight = theme === "light";
  // Threat Surface Map — findings grouped by OWASP category (radar axes).
  // Threat Surface Map — fixed OWASP Top 10 (2021) axes so the radar always draws a
  // full, eye-catching shape even when findings concentrate in a few categories.
  const OWASP_2021: [string, string][] = [
    ["A01", "Broken Access Control"], ["A02", "Cryptographic Failures"], ["A03", "Injection"],
    ["A04", "Insecure Design"], ["A05", "Security Misconfig"], ["A06", "Vulnerable Components"],
    ["A07", "Auth Failures"], ["A08", "Integrity Failures"], ["A09", "Logging Failures"], ["A10", "SSRF"],
  ];
  const owaspCnt: Record<string, { count: number; high: number }> = {};
  for (const f of findings) {
    const m = (f.owasp_category || "").match(/A\d\d/i);
    if (!m) continue;
    const code = m[0].toUpperCase();
    (owaspCnt[code] ||= { count: 0, high: 0 });
    owaspCnt[code].count++;
    if (f.severity === "Critical" || f.severity === "High") owaspCnt[code].high++;
  }
  const owaspTotal = Object.values(owaspCnt).reduce((a, v) => a + v.count, 0);

  let radar: { axis: string; name: string; All: number; "Crit/High": number }[];
  let radarSub: string;
  if (owaspTotal > 0) {
    radar = OWASP_2021.map(([code, name]) => ({
      axis: code, name: `${code} · ${name}`,
      All: owaspCnt[code]?.count ?? 0, "Crit/High": owaspCnt[code]?.high ?? 0,
    }));
    radarSub = "Findings mapped to OWASP Top 10 (2021)";
  } else {
    // No OWASP tags — fall back to a radar over the top vulnerability types so the
    // panel is never empty.
    const vt: Record<string, { count: number; high: number }> = {};
    for (const f of findings) {
      const t = (f.vuln_type || f.title || "Other").slice(0, 20);
      (vt[t] ||= { count: 0, high: 0 });
      vt[t].count++;
      if (f.severity === "Critical" || f.severity === "High") vt[t].high++;
    }
    radar = Object.entries(vt).sort((a, b) => b[1].count - a[1].count).slice(0, 8)
      .map(([t, v]) => ({ axis: t, name: t, All: v.count, "Crit/High": v.high }));
    radarSub = "Findings grouped by vulnerability type";
  }

  // Derive severity counts from the SAME loaded findings as the radar so the two
  // charts can never disagree (avoids relying on possibly-stale denormalised counts).
  const sc: Record<string, number> = {};
  for (const f of findings) sc[f.severity] = (sc[f.severity] || 0) + 1;
  const sev = [
    { name: "Critical", value: sc["Critical"] || 0,      fill: "#991b1b" },
    { name: "High",     value: sc["High"] || 0,          fill: "#c2410c" },
    { name: "Medium",   value: sc["Medium"] || 0,        fill: "#D97706" },
    { name: "Low",      value: sc["Low"] || 0,           fill: "#2563EB" },
    { name: "Info",     value: sc["Informational"] || 0, fill: "#64748B" },
  ].filter(d => d.value > 0);
  const totalSev = sev.reduce((a, d) => a + d.value, 0);
  const tip = chartTooltip(isLight);
  const axisFill = isLight ? "#475569" : "#a1a1aa";
  const axisMuted = isLight ? "#64748b" : "#71717a";
  const gridStroke = isLight ? "#cbd5e1" : "#3f3f46";
  const emptyFill = isLight ? "#e2e8f0" : "#27272a";

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Threat Surface Map (radar) */}
      <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm p-4">
        <div className="flex items-center justify-between mb-1">
          <h3 className="text-[12px] font-bold uppercase tracking-wide text-slate-700 dark:text-zinc-300">Threat Surface Map</h3>
          <div className="flex gap-3 text-[9px] text-slate-500 dark:text-zinc-400">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-teal-500" />All</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500" />Crit/High</span>
          </div>
        </div>
        <p className="text-[10px] text-slate-500 dark:text-zinc-400 mb-1">{radarSub}</p>
        {radar.length < 3 ? (
          <div className="py-14 flex flex-col items-center justify-center gap-2 text-center">
            <div className="w-10 h-10 rounded-full bg-teal-50 dark:bg-teal-950/35 border border-teal-200 dark:border-teal-800/50 flex items-center justify-center">
              <Target className="h-4 w-4 text-teal-700 dark:text-teal-300" />
            </div>
            <p className="text-[11px] text-slate-500 dark:text-zinc-400 max-w-[220px]">Too few categories for a surface map. See the severity chart and findings table.</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart data={radar} margin={{ top: 16, right: 44, bottom: 16, left: 44 }} outerRadius="72%">
              <defs>
                <radialGradient id="radAll" cx="50%" cy="50%" r="65%">
                  <stop offset="0%" stopColor="#a78bfa" stopOpacity={0.6} />
                  <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0.12} />
                </radialGradient>
              </defs>
              <PolarGrid stroke={gridStroke} />
              <PolarAngleAxis dataKey="axis" tick={{ fontSize: 10, fill: axisFill, fontWeight: 600 }} />
              <PolarRadiusAxis tick={{ fontSize: 8, fill: axisMuted }} axisLine={false} />
              <Radar name="All" dataKey="All" stroke="#8b5cf6" strokeWidth={2.5} fill="url(#radAll)"
                     dot={{ r: 2.5, fill: "#8b5cf6", strokeWidth: 0 }} isAnimationActive={false} />
              <Radar name="Crit/High" dataKey="Crit/High" stroke="#dc2626" strokeWidth={1.5} fill="#dc2626" fillOpacity={0.1}
                     dot={{ r: 2, fill: "#dc2626", strokeWidth: 0 }} isAnimationActive={false} />
              <RTooltip contentStyle={tip} labelFormatter={(l) => radar.find(r => r.axis === l)?.name ?? String(l)} />
            </RadarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Findings by severity (donut) */}
      <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm p-4">
        <h3 className="text-[12px] font-bold uppercase tracking-wide text-slate-700 dark:text-zinc-300 mb-1">Findings by Severity</h3>
        <p className="text-[10px] text-slate-500 dark:text-zinc-400 mb-2">All reported findings (including Potential / unverified)</p>
        <div className="flex items-center gap-4">
          <div className="relative w-[170px] h-[170px] shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={sev.length ? sev : [{ name: "None", value: 1, fill: emptyFill }]}
                     dataKey="value" nameKey="name" cx="50%" cy="50%"
                     innerRadius={52} outerRadius={78} paddingAngle={sev.length > 1 ? 3 : 0}
                     cornerRadius={5} strokeWidth={0} isAnimationActive={false}>
                  {(sev.length ? sev : [{ fill: emptyFill }]).map((d, i) => <Cell key={i} fill={(d as any).fill} />)}
                </Pie>
                <RTooltip contentStyle={tip} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-[22px] font-black text-slate-800 dark:text-zinc-200 tabular-nums">{totalSev}</span>
              <span className="text-[9px] uppercase tracking-widest text-slate-500 dark:text-zinc-400">Findings</span>
            </div>
          </div>
          <div className="flex-1 min-w-0 space-y-1.5">
            {sev.map(d => (
              <div key={d.name} className="flex items-center gap-2 text-[12px]">
                <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: d.fill }} />
                <span className="text-slate-700 dark:text-zinc-300 flex-1 truncate">{d.name}</span>
                <span className="font-bold tabular-nums text-slate-800 dark:text-zinc-200">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}


// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const theme = useThemeStore(s => s.theme);
  const isLight = theme === "light";
  const textPrimary = isLight ? "#334155" : "#d4d4d8";
  const mutedFg = isLight ? "#64748b" : "#a1a1aa";
  const tooltipStyle = chartTooltip(isLight);
  const logEndRef = useRef<HTMLDivElement>(null);
  const [liveLogs, setLiveLogs] = useState<{ level: string; phase: string; message: string; ts: string }[]>([]);
  const [promptOpen, setPromptOpen] = useState(false);
  const [logOpen, setLogOpen] = useState(true);
  const [findingFilter, setFindingFilter] = useState<string>("all");
  const [activeTab, setActiveTab] = useState<"findings" | "workflow">("findings");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [verifFilter, setVerifFilter] = useState<string>("all");
  const [evidenceFilter, setEvidenceFilter] = useState<"all" | "with" | "without">("all");
  const [selectedFindings, setSelectedFindings] = useState<string[]>([]);
  const [bulkMenu, setBulkMenu] = useState<null | "status" | "verification">(null);
  const [findingSearch, setFindingSearch] = useState("");
  const [sortCol, setSortCol] = useState<"severity" | "cvss" | "title" | "status">("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [reportDropdownOpen, setReportDropdownOpen] = useState(false);
  const reportDropdownRef = useRef<HTMLDivElement>(null);

  const { data: scan, refetch: refetchScan } = useQuery<Scan>({
    queryKey: ["scan", id],
    queryFn: () => scansApi.get(id!),
    refetchInterval: q => {
      const d = q.state.data as Scan | undefined;
      return d?.status === "running" ? 3_000 : false;
    },
  });

  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: ["findings", id],
    queryFn: () => findingsApi.list({ scan_id: id! }),
    enabled: !!id,
  });

  const { data: historicalLogs = [] } = useQuery<ScanLog[]>({
    queryKey: ["scan-logs", id],
    queryFn: () => scansApi.getLogs(id!, { limit: 1000 }),
    enabled: !!id && !!scan && !["queued", "running"].includes(scan.status),
  });

  // Shares its cache key with AttackWorkflowPanel — one request, and the tab
  // badge shows the chain count even while the Findings tab is open.
  const { data: workflow } = useQuery<AttackWorkflow>({
    queryKey: ["workflow", id],
    queryFn: () => workflowsApi.getForScan(id!),
    enabled: !!id && !!scan && !["queued", "running"].includes(scan.status) && findings.length > 0,
  });
  const workflowChains = workflow?.chain_count;

  const { data: budget } = useQuery<{
    token_budget: number; turn_budget: number; tokens_used: number; turns_used: number;
    hitl_required: boolean; token_pct: number; turn_pct: number; wrap_up: boolean;
  }>({
    queryKey: ["scan-budget", id],
    queryFn: () => api.get(`/approvals/budgets/${id}`).then(r => r.data),
    enabled: !!id,
    refetchInterval: scan?.status === "running" ? 8_000 : 60_000,
  });

  // OWASP is optional per finding — when a scan classified none of them the column
  // is a full width of em-dashes, so drop it and give the space back to Location.
  const showOwaspCol = findings.some(f => !!f.owasp_category);
  const colCount = (showOwaspCol ? 8 : 7) + 1; // + the selection column

  const { data: reports = [] } = useQuery<ReportOut[]>({
    queryKey: ["reports", id],
    queryFn: () => api.get(`/scans/${id}/reports`).then(r => r.data),
    enabled: !!id && ["completed", "failed"].includes(scan?.status ?? ""),
  });

  const generateReport = useMutation({
    mutationFn: () => api.post(`/scans/${id}/reports`, { format: "docx" }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports", id] }),
  });

  const cancelScan = useMutation({
    mutationFn: () => scansApi.cancel(scan!.id),
    onSuccess: () => refetchScan(),
  });

  const afterBulk = () => {
    setSelectedFindings([]);
    setBulkMenu(null);
    qc.invalidateQueries({ queryKey: ["findings", id] });
    qc.invalidateQueries({ queryKey: ["scan", id] });
  };

  const bulkStatusMutation = useMutation({
    mutationFn: (status: string) => findingsApi.bulkStatus(selectedFindings, status),
    onSuccess: afterBulk,
  });

  const bulkVerifMutation = useMutation({
    mutationFn: (v: string) => findingsApi.bulkVerification(selectedFindings, v),
    onSuccess: afterBulk,
  });

  const deleteReport = useMutation({
    mutationFn: (rid: string) => api.delete(`/reports/${rid}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports", id] }),
  });

  const downloadReport = (report: ReportOut) => {
    const token = localStorage.getItem("access_token");
    fetch(`/api/v1/reports/${report.id}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }).then(r => {
      if (!r.ok) throw new Error("Download failed");
      return r.blob();
    }).then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pentest_report_${report.generated_at.slice(0, 10)}.docx`;
      a.click();
      URL.revokeObjectURL(url);
    });
  };

  const displayLogs = ["queued", "running"].includes(scan?.status ?? "")
    ? liveLogs
    : historicalLogs.map(l => ({ level: l.level, phase: l.phase, message: l.message, ts: l.ts }));

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (reportDropdownRef.current && !reportDropdownRef.current.contains(e.target as Node)) {
        setReportDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  useEffect(() => {
    if (!id || !scan || !["queued", "running"].includes(scan.status)) return;
    const ws = createScanSocket(id, (msg: WsMessage) => {
      if (msg.type === "log") {
        setLiveLogs(prev => [...prev.slice(-999), { ...msg, ts: new Date().toISOString() }]);
        logEndRef.current?.scrollIntoView({ behavior: "smooth" });
      }
      if (msg.type === "scan_complete" || msg.type === "scan_error") {
        qc.invalidateQueries({ queryKey: ["scan", id] });
        qc.invalidateQueries({ queryKey: ["findings", id] });
        qc.invalidateQueries({ queryKey: ["scan-logs", id] });
      }
    });
    return () => ws.close();
  }, [id, scan?.status]);

  if (!scan) return (
    <div className="flex items-center justify-center h-40">
      <Loader2 className="h-6 w-6 animate-spin text-slate-700 dark:text-zinc-300" />
    </div>
  );

  const totalFindings = findings.length;
  const criticalHigh  = findings.filter(f => f.severity === "Critical" || f.severity === "High").length;
  const openFindings  = findings.filter(f => f.status === "Open").length;

  const cvssFindings = findings.filter(f => f.cvss_score != null);
  const avgCvss = cvssFindings.length > 0
    ? cvssFindings.reduce((s, f) => s + f.cvss_score!, 0) / cvssFindings.length
    : null;

  const toggleSort = (col: typeof sortCol) => {
    if (sortCol === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("asc"); }
  };

  const sortedFindings = [...findings].sort((a, b) => {
    let cmp = 0;
    if (sortCol === "severity") cmp = SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity);
    else if (sortCol === "cvss")   cmp = (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    else if (sortCol === "title")  cmp = a.title.localeCompare(b.title);
    else if (sortCol === "status") cmp = a.status.localeCompare(b.status);
    return sortDir === "asc" ? cmp : -cmp;
  });

  const filteredFindings = sortedFindings.filter(f => {
    const matchSev = findingFilter === "all" || f.severity === findingFilter || (findingFilter === "Informational" && f.severity === "Informational");
    const q = findingSearch.toLowerCase();
    const matchSearch = !q || f.title.toLowerCase().includes(q) || (f.location ?? "").toLowerCase().includes(q) || (f.owasp_category ?? "").toLowerCase().includes(q);
    const matchStatus = statusFilter === "all" || f.status === statusFilter;
    const matchVerif  = verifFilter === "all" || (f.verification_status ?? "Unverified") === verifFilter;
    const matchEvidence =
      evidenceFilter === "all" ? true
      : evidenceFilter === "with" ? f.has_poc
      :                            !f.has_poc;
    return matchSev && matchSearch && matchStatus && matchVerif && matchEvidence;
  });

  // Selection is scoped to what is currently visible: "select all" must never
  // silently act on rows hidden by a filter.
  const visibleIds = filteredFindings.map(f => f.id);
  const selectedVisible = visibleIds.filter(id => selectedFindings.includes(id));
  const allVisibleSelected = visibleIds.length > 0 && selectedVisible.length === visibleIds.length;

  const toggleSelectAll = () =>
    setSelectedFindings(allVisibleSelected
      ? selectedFindings.filter(id => !visibleIds.includes(id))
      : [...new Set([...selectedFindings, ...visibleIds])]);

  const toggleSelect = (id: string) =>
    setSelectedFindings(sel => sel.includes(id) ? sel.filter(x => x !== id) : [...sel, id]);

  const activeFilters = [
    findingFilter !== "all"  && { label: `Severity: ${findingFilter}`, clear: () => setFindingFilter("all") },
    statusFilter  !== "all"  && { label: `Status: ${statusFilter}`,    clear: () => setStatusFilter("all") },
    verifFilter   !== "all"  && { label: `Verification: ${verifFilter}`, clear: () => setVerifFilter("all") },
    evidenceFilter !== "all" && { label: evidenceFilter === "with" ? "Has PoC" : "No PoC", clear: () => setEvidenceFilter("all") },
    !!findingSearch          && { label: `Search: "${findingSearch}"`, clear: () => setFindingSearch("") },
  ].filter(Boolean) as { label: string; clear: () => void }[];

  const clearAllFilters = () => {
    setFindingFilter("all"); setStatusFilter("all");
    setVerifFilter("all");   setEvidenceFilter("all"); setFindingSearch("");
  };

  const exportCSV = () => {
    const rows = [
      ["Ref", "Title", "Severity", "CVSS", "OWASP", "Location", "Status"],
      ...filteredFindings.map(f => [
        f.finding_ref ?? "",
        f.title,
        f.severity,
        f.cvss_score?.toFixed(1) ?? "",
        f.owasp_category ? `${f.owasp_category}${f.owasp_name ? `: ${f.owasp_name}` : ""}` : "",
        f.location ?? "",
        f.status,
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings_${scan.id.slice(0, 8)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const providerMeta: Record<string, { label: string; color: string; bg: string }> = {
    openai:    { label: "OpenAI",    color: "text-emerald-700 dark:text-emerald-300",  bg: "bg-teal-50/90 border-teal-200/90 dark:bg-teal-950/40 dark:border-teal-800/45 dark:bg-emerald-950/40 dark:border-emerald-800/50" },
    anthropic: { label: "Anthropic", color: "text-orange-700 dark:text-orange-300", bg: "bg-orange-50 border-orange-200 dark:bg-orange-950/40 dark:border-orange-800/50" },
    openrouter:{ label: "OpenRouter", color: "text-sky-700 dark:text-sky-300", bg: "bg-sky-50 border-sky-200 dark:bg-sky-950/40 dark:border-sky-800/50" },
    ollama:    { label: "Ollama",    color: "text-purple-700 dark:text-purple-300", bg: "bg-purple-50 border-purple-200 dark:bg-purple-950/40 dark:border-purple-800/50" },
    mistral:   { label: "Mistral",   color: "text-orange-700 dark:text-orange-300", bg: "bg-orange-50 border-orange-200 dark:bg-orange-950/40 dark:border-orange-800/50" },
    groq:      { label: "Groq",      color: "text-amber-700 dark:text-amber-300", bg: "bg-amber-50 border-amber-200 dark:bg-amber-950/40 dark:border-amber-800/50" },
    xai:       { label: "xAI",       color: "text-slate-700 dark:text-zinc-200", bg: "bg-slate-100 border-slate-200 dark:bg-zinc-800/40 dark:border-zinc-700" },
    deepseek:  { label: "DeepSeek",  color: "text-blue-700 dark:text-blue-300", bg: "bg-blue-50 border-blue-200 dark:bg-blue-950/40 dark:border-blue-800/50" },
    zai:       { label: "Z.AI",      color: "text-indigo-700 dark:text-indigo-300", bg: "bg-indigo-50 border-indigo-200 dark:bg-indigo-950/40 dark:border-indigo-800/50" },
    kimi:      { label: "Kimi",      color: "text-teal-700 dark:text-teal-300", bg: "bg-teal-50 border-teal-200 dark:bg-teal-950/40 dark:border-teal-800/50" },
  };
  const pm = providerMeta[scan.llm_provider] ?? { label: scan.llm_provider, color: "text-slate-700 dark:text-zinc-300", bg: "bg-slate-100 dark:bg-zinc-800/40 border-slate-200 dark:border-zinc-800" };
  const modelName = scan.llm_model || (scan.llm_provider === "openai" ? "gpt-5.1" : scan.llm_provider === "anthropic" ? "claude-sonnet-5" : "default");

  const statusAccent: Record<string, string> = {
    running: "#3b82f6", completed: "#16a34a", failed: "#dc2626",
    cancelled: "#a1a1aa", queued: "#6366f1",
  };
  const headerAccent = statusAccent[scan.status] ?? "#a1a1aa";

  const SEV_RIBBON = (["Critical", "High", "Medium", "Low", "Informational"] as const).map(key => ({
    key,
    label: key === "Informational" ? "Info" : key,
    color: SEV_HEX[key],
    bg: isLight ? SEV_SOFT[key].light : SEV_SOFT[key].dark,
  }));

  // Timing label
  const timingLabel = () => {
    if (scan.status === "running" && scan.started_at)
      return { text: `Started ${relativeTime(scan.started_at)}`, cls: "text-blue-400" };
    if (scan.status === "completed")
      return { text: `Completed ${scan.completed_at ? relativeTime(scan.completed_at) : ""}${scan.duration_seconds != null ? ` · ${formatDuration(scan.duration_seconds)}` : ""}`, cls: "text-emerald-700 dark:text-emerald-400" };
    if (scan.status === "failed")
      return { text: `Failed ${scan.completed_at ? relativeTime(scan.completed_at) : ""}`, cls: "text-red-600 dark:text-red-400" };
    if (scan.status === "cancelled")
      return { text: `Cancelled ${scan.completed_at ? relativeTime(scan.completed_at) : ""}`, cls: "text-slate-500 dark:text-zinc-400" };
    if (scan.status === "queued" && scan.created_at)
      return { text: `Queued ${relativeTime(scan.created_at)}`, cls: "text-indigo-600" };
    return null;
  };
  const timing = timingLabel();

  const hypTotal     = scan.hypotheses_total ?? 0;
  const hypConfirmed = scan.hypotheses_confirmed ?? 0;
  const hypRate      = hypTotal > 0 ? Math.round((hypConfirmed / hypTotal) * 100) : 0;

  // Remediation values (for unified sidebar)
  const remOpen       = findings.filter(f => f.status === "Open").length;
  const remInProgress = findings.filter(f => f.status === "Partially Resolved").length;
  const remResolved   = findings.filter(f => ["Resolved", "Closed"].includes(f.status)).length;
  const remAccepted   = findings.filter(f => f.status === "Risk Accepted").length;
 const remDonePct = totalFindings > 0 ? Math.round(((remResolved + remAccepted) / totalFindings) * 100) : 0;

 // Trust summary - the anti-hallucination signals, aggregated. Evidence-backed
 // (has_poc) vs the rest, and how many an analyst has actually confirmed. This
 // is the number that tells you how much of the report you can hand to a client
 // as-is versus what still needs a human pass.
 const trustEvidence = findings.filter(f => f.has_poc).length;
 const trustVerified = findings.filter(f => f.verification_status === "Verified").length;
  const trustFalsePos = findings.filter(f => f.verification_status === "False Positive").length;
  const trustNeedsReview = findings.filter(
    f => !f.has_poc && f.verification_status === "Unverified",
  ).length;
  const trustPct = totalFindings > 0 ? Math.round((trustEvidence / totalFindings) * 100) : 0;

  return (
    <div className="space-y-3 pb-8">

 {/* ══════════════════════════════════════════════════════════════════════
 TOP CARD - header + severity ribbon + stats + config (all in one)
 ══════════════════════════════════════════════════════════════════════ */}
 <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">

        {/* Status top line */}
        <div className="h-[3px]" style={{ backgroundColor: headerAccent }} />

        {/* Header row */}
        <div className="px-5 py-4 flex items-center justify-between gap-4 border-b border-slate-200 dark:border-zinc-800">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-zinc-400 mb-1.5">
              <button onClick={() => navigate("/scans")} className="hover:text-teal-500 transition-colors">Scans</button>
              <ChevronRight className="h-3 w-3" />
              <span className="text-slate-500 dark:text-zinc-400 truncate max-w-md">{scan.target_url}</span>
            </div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-[15px] font-bold text-slate-800 dark:text-zinc-200 truncate leading-tight">{scan.target_url}</h1>
              <CopyUrlButton url={scan.target_url} />
              <StatusBadge status={scan.status} />
              {timing && <span className={`text-[11px] ${timing.cls}`}>{timing.text}</span>}
            </div>
            {scan.target_description && (
              <p className="text-[11px] text-slate-500 dark:text-zinc-400 mt-0.5">{scan.target_description}</p>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {scan.status === "running" && (
              <button onClick={() => cancelScan.mutate()} disabled={cancelScan.isPending}
                className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:bg-red-50 dark:hover:bg-red-950/40 hover:border-red-800/50 hover:text-red-600 dark:text-red-400 disabled:opacity-60 transition-colors">
                {cancelScan.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <XCircle className="h-3.5 w-3.5" />}
                {cancelScan.isPending ? "Cancelling…" : "Cancel"}
              </button>
            )}
            {["completed", "failed", "cancelled"].includes(scan.status) && (
              <button onClick={() => scansApi.rerun(scan.id).then(s => navigate(`/scans/${s.id}`))}
                className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors">
                <RotateCcw className="h-3.5 w-3.5" /> Rerun
              </button>
            )}
            {["completed", "failed"].includes(scan.status) && (
              <div className="relative" ref={reportDropdownRef}>
                <div className="flex items-stretch rounded-lg overflow-hidden border border-teal-600">
                  <button
                    onClick={() => generateReport.mutate()}
                    disabled={generateReport.isPending}
                    className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 bg-teal-600 text-white hover:bg-teal-700 disabled:opacity-50 transition-colors"
                  >
                    {generateReport.isPending
                      ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      : <FileText className="h-3.5 w-3.5" />}
                    {generateReport.isPending ? "Generating…" : "Generate Report"}
                  </button>
                  <button
                    onClick={() => setReportDropdownOpen(o => !o)}
                    className="flex items-center gap-0.5 px-2 bg-teal-600 text-white hover:bg-teal-700 transition-colors border-l border-teal-500"
                  >
                    {reports.length > 0 && (
                      <span className="text-[9px] font-black tabular-nums bg-teal-500/50 rounded px-1 py-px">{reports.length}</span>
                    )}
                    <ChevronDown className={`h-3.5 w-3.5 transition-transform ${reportDropdownOpen ? "rotate-180" : ""}`} />
                  </button>
                </div>

                {reportDropdownOpen && (
                  <div className="absolute right-0 top-full mt-1.5 w-[340px] bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-xl z-50 overflow-hidden">
                    <div className="px-3 py-2 border-b border-slate-200 dark:border-zinc-800 flex items-center justify-between">
                      <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Generated Reports</p>
                      {reports.length > 0 && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400">{reports.length} report{reports.length !== 1 ? "s" : ""}</span>
                      )}
                    </div>
                    {reports.length === 0 ? (
                      <div className="flex flex-col items-center py-6 gap-1.5">
                        <FileText className="h-5 w-5 text-slate-200" />
                        <p className="text-[11px] text-slate-500 dark:text-zinc-400">No reports yet. Click Generate Report.</p>
                      </div>
                    ) : (
                      <div className="divide-y divide-slate-200 dark:divide-zinc-800 max-h-[280px] overflow-y-auto">
                        {reports.map(r => (
                          <div key={r.id} className="px-3 py-2.5 flex items-center gap-2.5 hover:bg-slate-100 dark:hover:bg-zinc-800/50 transition-colors group">
                            <span className={`inline-flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded border shrink-0 ${TONE_BADGE.teal}`}>
                              <FileText className="h-2.5 w-2.5" /> DOCX
                            </span>
                            <div className="flex-1 min-w-0">
                              <p className="text-[11px] text-slate-700 dark:text-zinc-300 truncate">
                                {new Date(r.generated_at).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}
                              </p>
                              {r.file_size_kb && <p className="text-[9px] text-slate-500 dark:text-zinc-400 mt-0.5">{r.file_size_kb} KB</p>}
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              <button
                                onClick={() => { downloadReport(r); setReportDropdownOpen(false); }}
                                className="flex items-center gap-1 text-[10px] font-medium px-2 py-1 rounded-lg border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:bg-teal-50 dark:hover:bg-teal-950/40 hover:border-teal-700/50 hover:text-teal-700 dark:text-teal-400 transition-colors"
                              >
                                <Download className="h-2.5 w-2.5" /> Download
                              </button>
                              <button
                                onClick={() => deleteReport.mutate(r.id)}
                                disabled={deleteReport.isPending}
                                className="flex items-center p-1 rounded-lg border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:border-red-800/50 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors disabled:opacity-40"
                              >
                                <Trash2 className="h-3 w-3" />
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    {generateReport.isError && (
                      <div className="px-3 py-2 border-t border-red-100 bg-red-50">
                        <p className="text-[10px] text-red-600 dark:text-red-400">{(generateReport.error as any)?.response?.data?.detail ?? "Generation failed"}</p>
                      </div>
                    )}
                    {generateReport.isPending && (
                      <div className="px-3 py-2 border-t border-teal-200 dark:border-zinc-800 bg-teal-50 dark:bg-teal-950/35 flex items-center gap-1.5">
                        <Loader2 className="h-3 w-3 animate-spin text-teal-600" />
                        <p className="text-[10px] text-teal-800 dark:text-teal-400">Generating report…</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Severity ribbon */}
        <div className="grid grid-cols-5 divide-x divide-slate-200 dark:divide-zinc-700/60 border-b border-slate-200 dark:border-zinc-800">
          {SEV_RIBBON.map(s => {
            const count = findings.filter(f => f.severity === s.key).length;
            const active = count > 0;
            const selected = findingFilter === s.key;
            return (
              <button
                key={s.key}
                onClick={() => { setFindingFilter(selected ? "all" : s.key); setActiveTab("findings"); }}
                className="flex flex-col items-center py-4 px-3 transition-all focus:outline-none relative group"
                style={{ backgroundColor: selected ? s.bg : active ? `${s.bg}80` : undefined }}
              >
                {selected && <div className="absolute bottom-0 left-0 right-0 h-[2px]" style={{ backgroundColor: s.color }} />}
                <span className="text-[28px] font-black leading-none tabular-nums" style={{ color: active ? s.color : "#94a3b8" }}>{count}</span>
                <span className="text-[9px] font-bold uppercase tracking-widest mt-1" style={{ color: active ? s.color : "#94a3b8" }}>{s.label}</span>
              </button>
            );
          })}
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-4 divide-x divide-slate-200 dark:divide-zinc-700/60 border-b border-slate-200 dark:border-zinc-800">
          {[
            { label: "Total Findings", value: String(totalFindings),                          color: textPrimary },
            { label: "Open",           value: String(openFindings),                            color: openFindings > 0 ? "#b45309" : textPrimary },
            { label: "Hypotheses",     value: `${hypConfirmed} / ${hypTotal}`,                 color: textPrimary },
            { label: "Avg CVSS",       value: avgCvss != null ? avgCvss.toFixed(1) : "-",      color: avgCvss != null && avgCvss >= 7 ? "#b91c1c" : textPrimary },
          ].map(s => (
            <div key={s.label} className="px-4 py-3">
              <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">{s.label}</p>
              <p className="text-[18px] font-black tabular-nums mt-0.5" style={{ color: s.color }}>{s.value}</p>
            </div>
          ))}
        </div>

        {budget && (
          <div className="px-4 py-3 border-b border-slate-200 dark:border-zinc-800 grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Token budget</p>
                <span className="text-[11px] font-bold tabular-nums text-slate-700 dark:text-zinc-300">
                  {(budget.tokens_used / 1000).toFixed(1)}k / {(budget.token_budget / 1000).toFixed(0)}k
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-slate-100 dark:bg-zinc-800 overflow-hidden">
                <div
                  className={`h-full ${budget.wrap_up || budget.token_pct >= 90 ? "bg-amber-500" : "bg-teal-600"}`}
                  style={{ width: `${Math.min(100, budget.token_pct)}%` }}
                />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Turn budget</p>
                <span className="text-[11px] font-bold tabular-nums text-slate-700 dark:text-zinc-300">
                  {budget.turns_used} / {budget.turn_budget}
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-slate-100 dark:bg-zinc-800 overflow-hidden">
                <div className="h-full bg-indigo-500" style={{ width: `${Math.min(100, budget.turn_pct)}%` }} />
              </div>
            </div>
            <div className="flex items-center gap-2 sm:justify-end">
              <span className={`text-[10px] font-semibold px-2 py-1 rounded-full border ${
                budget.hitl_required
                  ? "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/40 dark:text-amber-200 dark:border-amber-800/50"
                  : "bg-slate-50 text-slate-600 border-slate-200 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700"
              }`}>
                HITL {budget.hitl_required ? "on" : "off"}
              </span>
              {budget.wrap_up && (
                <span className="text-[10px] font-semibold px-2 py-1 rounded-full border bg-orange-50 text-orange-800 border-orange-200 dark:bg-orange-950/40 dark:text-orange-200 dark:border-orange-800/50">
                  Wrap-up
                </span>
              )}
              <button
                onClick={() => navigate("/approvals")}
                className="text-[10px] font-semibold text-teal-700 dark:text-teal-400 hover:underline"
 >
 Approvals →
 </button>
 </div>
 </div>
 )}

 {/* Trust summary - foregrounds the anti-hallucination signals that make
 this tool's output credible: how much is evidence-backed and what
 still needs a human pass before it goes to a client. */}
 {totalFindings > 0 && (
 <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
              <span className="text-[11px] font-bold text-slate-700 dark:text-zinc-300 tabular-nums">{trustEvidence}</span>
              <span className="text-[11px] text-slate-500 dark:text-zinc-400">of {totalFindings} evidence-backed</span>
              <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full border tabular-nums ${TONE_BADGE.emerald}`}>
                {trustPct}%
              </span>
            </div>
            {/* proportion bar */}
            <div className="h-1.5 flex-1 min-w-[120px] max-w-[280px] rounded-full bg-slate-100 dark:bg-zinc-800 overflow-hidden">
              <div className="h-full bg-emerald-500" style={{ width: `${trustPct}%` }} />
            </div>
            <div className="flex items-center gap-3 text-[10px] text-slate-500 dark:text-zinc-400 ml-auto flex-wrap">
              {trustVerified > 0 && (
                <span className="flex items-center gap-1">
                  <Check className="h-3 w-3 text-emerald-700 dark:text-emerald-400" />
                  <span className="font-semibold text-slate-700 dark:text-zinc-300 tabular-nums">{trustVerified}</span> analyst-verified
                </span>
              )}
              <button
                onClick={() => { setActiveTab("findings"); setVerifFilter("all"); setEvidenceFilter("without"); }}
                className={`flex items-center gap-1 transition-colors ${
                  trustNeedsReview > 0 ? "text-amber-600 hover:text-amber-800 dark:text-amber-300" : "text-slate-500 dark:text-zinc-400"
                }`}
                title="Show findings with no PoC evidence that are still unverified"
              >
                <AlertTriangle className="h-3 w-3" />
                <span className="font-semibold tabular-nums">{trustNeedsReview}</span> need manual verification
              </button>
              {trustFalsePos > 0 && (
                <span className="flex items-center gap-1 text-slate-500 dark:text-zinc-400">
                  <Ban className="h-3 w-3" />
                  <span className="font-semibold tabular-nums">{trustFalsePos}</span> false positive
 </span>
 )}
 </div>
 </div>
 )}

 {/* Progress strip - remediation + hypothesis confirmation.
 The old sidebar showed these next to two donuts that only restated the
 severity ribbon and the Open counter above, so the donuts are gone and
 only the non-duplicated signal survives, as two slim bars. */}
 {totalFindings > 0 && (
 <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-zinc-700/60 border-b border-slate-200 dark:border-zinc-800">
            <div className="px-4 py-3">
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Remediation</p>
                <span className="text-[11px] font-black tabular-nums text-emerald-700 dark:text-emerald-400">{remDonePct}%</span>
              </div>
              <div className="h-1.5 bg-slate-100 dark:bg-zinc-800 rounded-full overflow-hidden flex gap-px">
                {[
                  { v: remOpen,       c: "#dc2626" },
                  { v: remInProgress, c: "#d97706" },
                  { v: remResolved,   c: "#16a34a" },
                  { v: remAccepted,   c: "#2563eb" },
                ].filter(r => r.v > 0).map((r, i) => (
                  <div key={i} className="h-full transition-all duration-500"
                       style={{ width: `${Math.round((r.v / totalFindings) * 100)}%`, backgroundColor: r.c }} />
                ))}
              </div>
              <div className="flex items-center gap-x-3 gap-y-1 flex-wrap mt-1.5">
                {[
                  { label: "Open",        v: remOpen,       c: "#dc2626" },
                  { label: "In Progress", v: remInProgress, c: "#d97706" },
                  { label: "Resolved",    v: remResolved,   c: "#16a34a" },
                  { label: "Accepted",    v: remAccepted,   c: "#2563eb" },
                ].map(r => (
                  <span key={r.label} className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-sm" style={{ backgroundColor: r.c }} />
                    <span className="text-[10px] text-slate-500 dark:text-zinc-400">{r.label}</span>
                    <span className="text-[10px] font-bold text-slate-700 dark:text-zinc-300 tabular-nums">{r.v}</span>
                  </span>
                ))}
              </div>
            </div>

            <div className="px-4 py-3">
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Hypothesis Confirmation</p>
                <span className="text-[11px] font-black tabular-nums text-slate-700 dark:text-zinc-300">{hypRate}%</span>
              </div>
              <div className="h-1.5 bg-slate-100 dark:bg-zinc-800 rounded-full overflow-hidden">
                <div className="h-full bg-emerald-500 rounded-full transition-all duration-700" style={{ width: `${hypRate}%` }} />
              </div>
              <p className="text-[10px] text-slate-500 dark:text-zinc-400 mt-1.5">
                <span className="font-bold text-emerald-700 dark:text-emerald-400 tabular-nums">{hypConfirmed}</span> of{" "}
                <span className="font-bold text-slate-700 dark:text-zinc-300 tabular-nums">{hypTotal}</span> hypotheses reproduced against the target
              </p>
            </div>
          </div>
        )}

        {/* Config row */}
        <div className="px-4 py-2.5 flex items-center gap-2 flex-wrap">
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${pm.color} ${pm.bg}`}>{pm.label}</span>
          <span className="text-[10px] font-mono text-slate-500 dark:text-zinc-400 truncate max-w-[200px]" title={modelName}>{modelName}</span>
          <span className="h-3 w-px bg-slate-200" />
          <span className="flex items-center gap-1 text-[11px] text-slate-500 dark:text-zinc-400">
            <ScanLine className="h-3 w-3 text-slate-500 dark:text-zinc-400" />
            {scan.scan_mode === "full" ? "Full Scan" : "Static Only"}
          </span>
          <span className="h-3 w-px bg-slate-200" />
          <span className="flex items-center gap-1 text-[11px] text-slate-500 dark:text-zinc-400">
            <GitBranch className="h-3 w-3 text-slate-500 dark:text-zinc-400" />
            {scan.max_hypotheses} hyp · {scan.max_parallel}w · {scan.feedback_iter} iter
          </span>
          {scan.custom_prompt && (
            <>
              <span className="h-3 w-px bg-slate-200" />
              <button onClick={() => setPromptOpen(!promptOpen)}
                className="flex items-center gap-1 text-[11px] text-amber-600 hover:text-amber-800 dark:text-amber-300 transition-colors">
                <MessageSquareText className="h-3 w-3" />
                Context
                {promptOpen ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              </button>
            </>
          )}
        </div>
        {scan.custom_prompt && promptOpen && (
          <div className="px-4 py-3 bg-amber-50 dark:bg-amber-950/40 border-t border-amber-200 dark:border-amber-900/50">
            <p className="text-[10px] font-bold text-amber-900 dark:text-amber-300 uppercase tracking-wide mb-1">Operator Context</p>
            <p className="text-[11px] font-mono text-amber-900 dark:text-amber-200/90 whitespace-pre-wrap leading-relaxed">{scan.custom_prompt}</p>
          </div>
        )}
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          PHASE STEPPER
          ══════════════════════════════════════════════════════════════════════ */}
      <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
 <PhaseStepper scan={scan} />
 </div>

 {/* ══════════════════════════════════════════════════════════════════════
 RESULT CHARTS - shown only once the scan has completed
 ══════════════════════════════════════════════════════════════════════ */}
 {scan.status === "completed" && findings.length > 0 && (
 <ScanCharts findings={findings} scan={scan} />
 )}

 {/* ══════════════════════════════════════════════════════════════════════
 RESULTS - Findings table and the derived Attack Workflow, as tabs
 ══════════════════════════════════════════════════════════════════════ */}
 {findings.length > 0 && (
 <div className="flex items-center gap-1 border-b border-slate-200 dark:border-zinc-800 px-1">
          {([
            { key: "findings" as const, label: "Findings",        icon: ShieldAlert, count: findings.length, color: "#dc2626" },
            { key: "workflow" as const, label: "Attack Workflow", icon: Workflow,    count: workflowChains, color: "#6366f1" },
          ]).map(t => {
            const active = activeTab === t.key;
            const Icon = t.icon;
            return (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={`flex items-center gap-2 px-4 py-2.5 text-[12px] font-semibold border-b-2 -mb-px transition-colors ${
                  active ? "text-slate-800 dark:text-zinc-200" : "border-transparent text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300"
                }`}
                style={active ? { borderColor: t.color } : undefined}
              >
                <Icon className="h-3.5 w-3.5" style={{ color: active ? t.color : undefined }} />
                {t.label}
                {t.count != null && (
                  <span
                    className="text-[10px] font-bold px-1.5 py-0.5 rounded-full border tabular-nums"
                    style={active
                      ? { color: t.color, backgroundColor: `${t.color}14`, borderColor: `${t.color}40` }
                      : { color: "#a1a1aa", backgroundColor: "#27272a", borderColor: "#3f3f46" }}
                  >
                    {t.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}

      {/* ── Attack Workflow tab ───────────────────────────────────────────── */}
      {findings.length > 0 && activeTab === "workflow" && (
        <AttackWorkflowPanel
          scanId={scan.id}
          enabled={!["queued", "running"].includes(scan.status)}
        />
      )}

      {/* ── Findings tab ──────────────────────────────────────────────────── */}
      {findings.length > 0 && activeTab === "findings" && (
        <>
          {/* Section header + toolbar combined */}
          <div className="bg-white dark:bg-zinc-900 rounded-lg border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
            {/* Top accent */}
            <div className="w-full h-[2px] bg-red-500" />
 {/* Header row */}
 {/* The tab above already names this section - the header row is just the toolbar */}
 <div className="px-4 py-3 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-3 flex-wrap">
              {/* Severity filter */}
              <div className="flex items-center gap-0.5 bg-slate-100 dark:bg-zinc-800 rounded-lg p-0.5">
                {(["all", ...SEV_ORDER] as const).map(sev => {
                  const count = sev === "all" ? findings.length : findings.filter(f => f.severity === sev).length;
                  const active = findingFilter === sev;
                  const color = sev !== "all" ? SEV[sev]?.color : undefined;
                  return (
                    <button
                      key={sev}
                      onClick={() => setFindingFilter(sev)}
                      className={`flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-semibold transition-all ${
                        active ? "bg-white dark:bg-zinc-900 shadow-sm" : "text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300"
                      }`}
                      style={active && color ? { color } : active ? { color: "#334155" } : undefined}
                    >
                      {sev === "all" ? "All" : sev === "Informational" ? "Info" : sev}
                      <span className="tabular-nums opacity-70">{count}</span>
                    </button>
                  );
                })}
              </div>
              {/* Search */}
              <div className="flex items-center gap-1.5 border border-slate-200 dark:border-zinc-800 rounded-lg px-2.5 py-1.5 bg-white dark:bg-zinc-900 w-44">
                <Search className="h-3 w-3 text-slate-500 dark:text-zinc-400 shrink-0" />
                <input
                  type="text"
                  value={findingSearch}
                  onChange={e => setFindingSearch(e.target.value)}
                  placeholder="Search…"
                  className="flex-1 bg-transparent text-[11px] text-slate-700 dark:text-zinc-300 placeholder:text-slate-500 dark:text-zinc-400 outline-none min-w-0"
 />
 </div>
 {/* Triage filters - the questions an analyst actually asks of a big
 scan: what is still unverified, what has no evidence, what is open */}
 <FilterSelect
 label="Status"
                value={statusFilter}
                onChange={setStatusFilter}
                options={["all", ...Array.from(new Set(findings.map(f => f.status)))]}
              />
              <FilterSelect
                label="Verification"
                value={verifFilter}
                onChange={setVerifFilter}
                options={["all", "Unverified", "Verified", "False Positive"]}
              />
              <FilterSelect
                label="Evidence"
                value={evidenceFilter}
                onChange={v => setEvidenceFilter(v as "all" | "with" | "without")}
                options={["all", "with", "without"]}
                render={v => v === "all" ? "Any evidence" : v === "with" ? "Has PoC" : "No PoC"}
              />

              <div className="flex-1" />

              {/* Export */}
              <button
                onClick={exportCSV}
                className="flex items-center gap-1 text-[10px] font-semibold px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors"
              >
                <Download className="h-3 w-3" /> CSV
              </button>
            </div>

            {/* Active filter chips */}
            {activeFilters.length > 0 && (
              <div className="px-4 py-2 border-b border-slate-200 dark:border-zinc-800 bg-slate-100 dark:bg-zinc-800/50 flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 dark:text-zinc-400">Filtered by</span>
                {activeFilters.map(f => (
                  <button
                    key={f.label}
                    onClick={f.clear}
                    className="group flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:border-slate-300 dark:border-zinc-600 transition-colors"
                  >
                    {f.label}
                    <X className="h-2.5 w-2.5 text-slate-700 dark:text-zinc-300 group-hover:text-slate-700 dark:text-zinc-300 transition-colors" />
                  </button>
                ))}
                <button onClick={clearAllFilters} className="text-[10px] font-semibold text-teal-700 dark:text-teal-400 hover:text-teal-800 ml-1">
                  Clear all
                </button>
                <span className="text-[10px] text-slate-500 dark:text-zinc-400 ml-auto tabular-nums">
 {filteredFindings.length} of {findings.length} shown
 </span>
 </div>
 )}

 {/* Bulk triage bar - appears only with a selection */}
 {selectedVisible.length > 0 && (
 <div className="px-4 py-2 border-b border-teal-800/40 bg-teal-50/70 flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-bold text-teal-700 dark:text-teal-300 tabular-nums">
                  {selectedVisible.length} selected
                </span>
                <button onClick={() => setSelectedFindings([])}
                        className="text-[10px] text-teal-700 dark:text-teal-400 hover:text-teal-800 font-medium">
                  Clear
                </button>
                <span className="h-3 w-px bg-teal-200" />

                <BulkMenu
                  label="Set status"
                  open={bulkMenu === "status"}
                  onToggle={() => setBulkMenu(bulkMenu === "status" ? null : "status")}
                  options={["Open", "In Progress", "Resolved", "Accepted"]}
                  pending={bulkStatusMutation.isPending}
                  onPick={v => bulkStatusMutation.mutate(v)}
                />
                <BulkMenu
                  label="Set verification"
                  open={bulkMenu === "verification"}
                  onToggle={() => setBulkMenu(bulkMenu === "verification" ? null : "verification")}
                  options={["Unverified", "Verified", "False Positive"]}
                  pending={bulkVerifMutation.isPending}
                  onPick={v => bulkVerifMutation.mutate(v)}
                />

                {(bulkStatusMutation.isError || bulkVerifMutation.isError) && (
                  <span className="text-[10px] text-red-600 dark:text-red-400">
                    {((bulkStatusMutation.error ?? bulkVerifMutation.error) as any)?.response?.data?.detail
                      ?? "Bulk update failed"}
 </span>
 )}
 </div>
 )}

 {/* Table - compact, sticky header, zebra rows, sortable */}
 <div className="overflow-auto max-h-[600px]">
              <table className="w-full text-xs table-fixed">
                <colgroup>
                  <col style={{ width: 32 }} />
                  <col style={{ width: 72 }} />
                  <col />
                  <col style={{ width: 90 }} />
                  <col style={{ width: 160 }} />
                  {showOwaspCol && <col style={{ width: 88 }} />}
                  <col style={{ width: 220 }} />
                  <col style={{ width: 110 }} />
                  <col style={{ width: 34 }} />
                </colgroup>
                <thead className="sticky top-0 z-10">
                  <tr className="bg-slate-100 dark:bg-zinc-800/40 border-b border-slate-200 dark:border-zinc-800">
                    <th className="py-2 pl-2 pr-0">
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        onChange={toggleSelectAll}
                        aria-label="Select all visible findings"
                        title={allVisibleSelected ? "Clear selection" : "Select all rows matching the current filters"}
                        className="ml-1 h-3 w-3 rounded border-slate-300 dark:border-zinc-600 text-teal-700 dark:text-teal-400 focus:ring-teal-500 cursor-pointer"
                      />
                    </th>
                    {[
                      { key: "ref",      label: "REF",      sortable: false  },
                      { key: "title",    label: "TITLE",    sortable: true,  col: "title"    as const },
                      { key: "severity", label: "SEVERITY", sortable: true,  col: "severity" as const },
                      { key: "cvss",     label: "CVSS",     sortable: true,  col: "cvss"     as const },
                      ...(showOwaspCol ? [{ key: "owasp", label: "OWASP", sortable: false as const }] : []),
                      { key: "location", label: "LOCATION", sortable: false  },
                      { key: "status",   label: "STATUS",   sortable: true,  col: "status"   as const },
                      { key: "expand",   label: "",         sortable: false  },
                    ].map(h => (
                      <th
                        key={h.key}
                        onClick={h.sortable && h.col ? () => toggleSort(h.col!) : undefined}
                        className={`text-left py-2 px-3 text-[10px] font-bold text-slate-500 dark:text-zinc-400 uppercase tracking-[0.12em] select-none ${h.sortable ? "cursor-pointer hover:text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors" : ""}`}
                      >
                        <span className="flex items-center gap-1">
                          {h.label}
                          {h.sortable && h.col && (
                            <span className={`text-[9px] leading-none ${sortCol === h.col ? "text-teal-500" : "text-slate-700 dark:text-zinc-300"}`}>
                              {sortCol === h.col ? (sortDir === "asc" ? "↑" : "↓") : "↕"}
                            </span>
                          )}
                        </span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan={colCount} className="py-10 text-center">
                        <div className="flex flex-col items-center gap-2">
                          <div className="w-8 h-8 rounded-full border-2 border-dashed border-slate-200 dark:border-zinc-800 flex items-center justify-center">
                            <ShieldAlert className="h-3.5 w-3.5 text-slate-700 dark:text-zinc-300" />
                          </div>
                          <p className="text-[11px] text-slate-500 dark:text-zinc-400">No findings match current filters</p>
                        </div>
                      </td>
                    </tr>
                  ) : filteredFindings.map((f, idx) => {
                    const sevCfg = SEV[f.severity] ?? SEV.Informational;
                    const open = expandedFinding === f.id;
                    const chains = workflow?.chains.filter(
                      c => f.finding_ref && c.finding_refs.includes(f.finding_ref)
                    ) ?? [];
                    return (
                      <Fragment key={f.id}>
                      <tr
                        onClick={() => navigate(`/findings/${f.id}`)}
                        className={`border-b border-slate-200 dark:border-zinc-800 cursor-pointer transition-colors group ${
                          open
                            ? "bg-teal-50 dark:bg-teal-950/35"
                            : idx % 2 === 0
                              ? "bg-white dark:bg-zinc-900 hover:bg-teal-50 dark:hover:bg-teal-950/30"
                              : "bg-slate-50 dark:bg-zinc-900/60 hover:bg-teal-50 dark:hover:bg-teal-950/30"
                        }`}
                      >
                        <td className="py-2 pl-2 pr-0 align-top relative overflow-hidden">
                          <div className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ backgroundColor: sevCfg.color }} />
                          <input
                            type="checkbox"
                            checked={selectedFindings.includes(f.id)}
                            onChange={() => toggleSelect(f.id)}
                            onClick={e => e.stopPropagation()}
                            aria-label={`Select ${f.finding_ref ?? f.title}`}
                            className="ml-1 mt-0.5 h-3 w-3 rounded border-slate-300 dark:border-zinc-600 text-teal-700 dark:text-teal-400 focus:ring-teal-500 cursor-pointer"
                          />
                        </td>
                        <td className="py-2 px-3 font-mono text-[10px] text-slate-500 dark:text-zinc-400 align-top">
                          <span className="truncate block pt-0.5">{f.finding_ref || "-"}</span>
                        </td>
                        <td className="py-2 px-3 overflow-hidden">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <p className="text-[11px] font-semibold text-slate-800 dark:text-zinc-200 group-hover:text-teal-700 dark:text-teal-300 transition-colors truncate leading-snug">{f.title}</p>
                            {(f.title.toLowerCase().startsWith("potential ") || (f.confidence_score < 40 && !f.raw_request)) && (
                              <span className={`text-[8px] font-bold px-1 py-px rounded border uppercase shrink-0 ${TONE_BADGE.amber}`} title="Weak or unconfirmed evidence. Treat as possible, not confirmed.">
                                Potential
                              </span>
                            )}
                            {!f.has_poc && (
                              <span className={`text-[8px] font-bold px-1 py-px rounded border uppercase shrink-0 ${TONE_BADGE.red}`}>
                                No PoC
                              </span>
                            )}
                            {chains.length > 0 && (
                              <span
                                className={`flex items-center gap-0.5 text-[8px] font-bold px-1 py-px rounded border uppercase shrink-0 ${TONE_BADGE.indigo}`}
                                title={chains.map(c => c.name).join("\n")}
                              >
                                <Workflow className="h-2 w-2" />{chains.length}
 </span>
 )}
 </div>
 {/* One-line summary - the "what is this actually about" the table was missing */}
                          {f.description
                            ? <p className="text-[9px] text-slate-500 dark:text-zinc-400 truncate mt-0.5 leading-snug">{f.description}</p>
                            : f.vuln_type && <p className="text-[9px] text-slate-500 dark:text-zinc-400 truncate mt-0.5">{f.vuln_type}</p>}
                        </td>
                        <td className="py-2 px-3 align-top"><SevBadge severity={f.severity} /></td>
                        <td className="py-2 px-3 align-top">
                          <CvssCell score={f.cvss_score} vector={f.cvss_vector} score4={f.cvss4_score} vector4={f.cvss4_vector} />
                        </td>
                        {showOwaspCol && (
                          <td className="py-2 px-3 align-top">
                            {f.owasp_category ? (
                              <div title={f.owasp_name ?? f.owasp_category}>
                                <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-100 dark:bg-zinc-800 text-slate-700 dark:text-zinc-300 border border-slate-200 dark:border-zinc-800 block w-fit">{f.owasp_category}</span>
                                {f.owasp_name && <p className="text-[8px] text-slate-500 dark:text-zinc-400 truncate mt-0.5 max-w-[80px]">{f.owasp_name}</p>}
                              </div>
                            ) : <span className="text-slate-700 dark:text-zinc-300 text-[10px]">-</span>}
                          </td>
                        )}
                        <td className="py-2 px-3 overflow-hidden align-top">
                          <p className="text-[10px] text-slate-500 dark:text-zinc-400 font-mono truncate" title={f.location ?? ""}>{f.location || "-"}</p>
                        </td>
                        <td className="py-2 px-3 align-top">
                          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border" style={{
                            backgroundColor: (STATUS_COLORS_CHART[f.status] ?? "#a1a1aa") + "15",
                            color: STATUS_COLORS_CHART[f.status] ?? "#a1a1aa",
                            borderColor: (STATUS_COLORS_CHART[f.status] ?? "#a1a1aa") + "40",
                          }}>{f.status}</span>
                        </td>
                        <td className="py-2 px-1 align-top">
                          <button
                            onClick={e => { e.stopPropagation(); setExpandedFinding(open ? null : f.id); }}
                            title={open ? "Collapse" : "Show details"}
                            aria-expanded={open}
                            className="p-1 rounded text-slate-700 dark:text-zinc-300 hover:text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors"
                          >
                            <ChevronDown className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
                          </button>
                        </td>
                      </tr>

                      {open && (
                        <tr className="border-b border-slate-200 dark:border-zinc-800 bg-teal-50/80 dark:bg-teal-950/25">
                          <td colSpan={colCount} className="px-0 py-0">
                            <div className="px-4 py-3 border-l-[3px]" style={{ borderColor: sevCfg.color }}>
                              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                <FindingPreviewBlock label="Description" body={f.description} />
                                <FindingPreviewBlock label="Implications" body={f.implications} />
                                <FindingPreviewBlock label="Recommendation" body={f.recommendations} />
                              </div>

                              <div className="flex items-center gap-2 flex-wrap mt-3 pt-2.5 border-t border-slate-200 dark:border-zinc-800/70">
                                <EvidenceChip finding={f} />
                                {f.source_tool && (
                                  <span className="text-[9px] text-slate-500 dark:text-zinc-400">
                                    via <span className="font-semibold text-slate-500 dark:text-zinc-400">{f.source_tool}</span>
                                  </span>
                                )}
                                {chains.map(c => (
                                  <span
                                    key={c.id}
                                    className={`text-[9px] font-medium px-1.5 py-0.5 rounded border max-w-[280px] truncate ${TONE_BADGE.indigo}`}
                                    title={c.name}
                                  >
                                    {c.name}
                                  </span>
                                ))}
                                <button
                                  onClick={e => { e.stopPropagation(); navigate(`/findings/${f.id}`); }}
                                  className="ml-auto text-[10px] font-semibold text-teal-700 dark:text-teal-400 hover:text-teal-800 flex items-center gap-1"
                                >
                                  Open full detail <ChevronRight className="h-3 w-3" />
                                </button>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Footer */}
            <div className="px-4 py-2 border-t border-slate-200 dark:border-zinc-800 bg-slate-50 dark:bg-zinc-900/50 flex items-center justify-between">
              <span className="text-[10px] text-slate-500 dark:text-zinc-400">
                {filteredFindings.length !== findings.length
                  ? <>Showing <strong className="text-slate-700 dark:text-zinc-300">{filteredFindings.length}</strong> of <strong className="text-slate-700 dark:text-zinc-300">{findings.length}</strong> findings</>
                  : <><strong className="text-slate-700 dark:text-zinc-300">{findings.length}</strong> findings total</>
                }
              </span>
              <span className="text-[10px] text-slate-500 dark:text-zinc-400">
                Sorted by <strong className="text-slate-700 dark:text-zinc-300">{sortCol}</strong> {sortDir === "asc" ? "↑" : "↓"}
 </span>
 </div>
 </div>
 </>
 )}



 {/* ══════════════════════════════════════════════════════════════════════
 SCAN OUTPUT - full width, below the results it explains
 ══════════════════════════════════════════════════════════════════════ */}
 <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800">
            <div className="flex items-center gap-2.5">
              <Terminal className="h-3.5 w-3.5 text-slate-500 dark:text-zinc-400" />
              <span className="text-[12px] font-semibold text-slate-700 dark:text-zinc-300">Scan Output</span>
              {scan.status === "running" && (
                <span className="flex items-center gap-1 text-[10px] text-blue-500">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" /> Live
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500 dark:text-zinc-400 tabular-nums">{displayLogs.length} lines</span>
              <button onClick={() => setLogOpen(o => !o)}
                className="flex items-center gap-1 text-[10px] text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300 transition-colors px-2 py-0.5 rounded border border-slate-200 dark:border-zinc-800">
                {logOpen ? <><ChevronUp className="h-3 w-3" />Hide</> : <><ChevronDown className="h-3 w-3" />Show</>}
              </button>
            </div>
          </div>
          {logOpen ? (
            /* Light log viewer: numbered gutter, phase chip, severity-tinted rows.
               Errors and warnings carry a coloured row + left rule so they can be
               spotted while scrolling instead of relying on text colour alone. */
            <div className="bg-white dark:bg-zinc-900 h-[420px] overflow-y-auto font-mono text-[11px]">
              {displayLogs.map((log, i) => {
                const isError = log.level === "ERROR";
                const isWarn  = log.level === "WARN" || log.message.includes("[!]");
                const text =
                  isError                       ? "text-red-600 dark:text-red-400"
                  : isWarn                      ? "text-amber-800 dark:text-amber-300"
                  : log.message.includes("[+]") ? "text-emerald-700"
                  : log.message.includes("[*]") ? "text-blue-700 dark:text-blue-300"
                  :                               "text-slate-700 dark:text-zinc-300";
                const row =
                  isError ? "bg-red-50/70 border-l-2 border-red-400"
                  : isWarn ? "bg-amber-50/60 border-l-2 border-amber-400"
                  :          "border-l-2 border-transparent hover:bg-slate-50 dark:hover:bg-zinc-900/60";

                return (
                  <div key={i} className={`flex gap-2.5 px-3 py-[3px] leading-relaxed transition-colors ${row}`}>
                    <span className="w-7 shrink-0 text-right text-slate-700 dark:text-zinc-300 select-none tabular-nums">{i + 1}</span>
                    {/* Wide enough for the longest phase name ("static_analysis") */}
                    <span className="shrink-0 w-[84px] truncate text-[9px] text-slate-500 dark:text-zinc-400 uppercase tracking-wide pt-px select-none"
                          title={log.phase}>
                      {log.phase}
                    </span>
                    <span className={`${text} whitespace-pre-wrap break-words min-w-0`}>{log.message}</span>
                  </div>
                );
              })}
              {displayLogs.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full gap-2">
                  <Terminal className="h-5 w-5 text-slate-200" />
                  <span className="text-[11px] text-slate-500 dark:text-zinc-400 font-sans">
                    {scan.status === "running" ? "Waiting for output…" : "No scan logs recorded."}
                  </span>
                </div>
              )}
              <div ref={logEndRef} />
            </div>
          ) : (
            <div className="h-10 bg-slate-100 dark:bg-zinc-800/40 flex items-center px-4">
              <span className="text-[11px] text-slate-500 dark:text-zinc-400">Log collapsed ({displayLogs.length} lines)</span>
            </div>
          )}
        </div>

    </div>
  );
}
