import { useState, useMemo, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Plus, RefreshCw, Trash2, RotateCcw, XCircle,
  CheckCircle2, AlertTriangle, Loader2,
  ChevronLeft, ChevronRight, MessageSquareText,
  Target, Activity, ScanLine, Search, ExternalLink, Timer, GitBranch,
} from "lucide-react";
import { scansApi, type Scan } from "@/api/scans";

// ── Design tokens ─────────────────────────────────────────────────────────────

const SEV_CFG = [
  { key: "findings_critical" as const, color: "#b91c1c", title: "Critical" },
  { key: "findings_high"     as const, color: "#c2410c", title: "High"     },
  { key: "findings_medium"   as const, color: "#a16207", title: "Medium"   },
  { key: "findings_low"      as const, color: "#1d4ed8", title: "Low"      },
  { key: "findings_info"     as const, color: "#64748b", title: "Info"     },
];

const STATUS_CFG: Record<string, { label: string; dot: string; text: string; bg: string; border: string }> = {
  running:   { label: "Running",   dot: "bg-blue-500 animate-pulse", text: "text-blue-800 dark:text-blue-300",    bg: "bg-blue-50 dark:bg-blue-950/40",    border: "border-blue-200 dark:border-blue-800/50"    },
  queued:    { label: "Queued",    dot: "bg-indigo-400",             text: "text-indigo-800 dark:text-indigo-300",  bg: "bg-indigo-50 dark:bg-indigo-950/40",  border: "border-indigo-200 dark:border-indigo-800/50"  },
  completed: { label: "Completed", dot: "bg-emerald-500",            text: "text-emerald-800 dark:text-emerald-300", bg: "bg-emerald-50 dark:bg-emerald-950/40", border: "border-emerald-200 dark:border-emerald-800/50" },
  failed:    { label: "Failed",    dot: "bg-red-500",                text: "text-red-800 dark:text-red-300",     bg: "bg-red-50 dark:bg-red-950/40",     border: "border-red-200 dark:border-red-800/50"     },
  cancelled: { label: "Cancelled", dot: "bg-slate-400",              text: "text-slate-600 dark:text-zinc-400",   bg: "bg-slate-100 dark:bg-zinc-800",  border: "border-slate-200 dark:border-zinc-800"   },
};

const PROVIDER_CFG: Record<string, { label: string; color: string; border: string }> = {
  openai:    { label: "OpenAI",    color: "text-emerald-800 dark:text-emerald-300",  border: "border-teal-200/90 bg-teal-50/90 dark:border-teal-800/45 dark:bg-teal-950/40 dark:border-emerald-800/50 dark:bg-emerald-950/40"  },
  anthropic: { label: "Anthropic", color: "text-orange-800 dark:text-orange-300", border: "border-orange-200 bg-orange-50 dark:border-orange-800/50 dark:bg-orange-950/40" },
  ollama:    { label: "Ollama",    color: "text-purple-800 dark:text-purple-300", border: "border-purple-200 bg-purple-50 dark:border-purple-800/50 dark:bg-purple-950/40" },
};

const PROVIDER_DEFAULT_MODEL: Record<string, string> = {
  openai: "gpt-5.1", anthropic: "claude-sonnet-5", ollama: "default",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function relTime(dateStr: string | null): string {
  if (!dateStr) return "-";
  const norm = dateStr.endsWith("Z") || dateStr.includes("+") ? dateStr : dateStr + "Z";
  const diff = Date.now() - new Date(norm).getTime();
  if (isNaN(diff)) return "-";
  const s = Math.floor(diff / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
  return new Date(norm).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

function highestSev(scan: Scan): string | null {
  if (scan.findings_critical > 0) return "Critical";
  if (scan.findings_high > 0)     return "High";
  if (scan.findings_medium > 0)   return "Medium";
  if (scan.findings_low > 0)      return "Low";
  if (scan.findings_info > 0)     return "Info";
  return null;
}

const RISK_BADGE: Record<string, string> = {
  Critical: "bg-red-50 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900/60",
  High:     "bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900/60",
  Medium:   "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900/60",
  Low:      "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900/60",
  Info:     "bg-slate-100 text-slate-600 border-slate-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700",
};

// ── Compact components ────────────────────────────────────────────────────────

function StatusPill({ status, phase }: { status: string; phase?: string | null }) {
  const cfg = STATUS_CFG[status] ?? STATUS_CFG.cancelled;
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${cfg.dot}`} />
      {cfg.label}
      {status === "running" && phase && <span className="opacity-70 ml-0.5 font-normal">· {phase}</span>}
    </span>
  );
}

function RiskPill({ scan }: { scan: Scan }) {
  const sev = highestSev(scan);
  if (!sev) return null;
  return (
    <span className={`inline-block text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${RISK_BADGE[sev]}`}>
      {sev}
    </span>
  );
}

function VulnBar({ scan }: { scan: Scan }) {
  const vals = SEV_CFG.map(s => ({ ...s, v: scan[s.key] ?? 0 }));
  const total = vals.reduce((a, b) => a + b.v, 0);
  const active = vals.filter(s => s.v > 0);

  if (total === 0) {
    return (
      <div className="w-full">
        <div className="h-4 rounded bg-slate-100 dark:bg-zinc-800 flex items-center justify-center">
          <span className="text-[9px] text-slate-500 dark:text-zinc-400">No findings</span>
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-1 w-full">
      <div className="flex h-4 rounded overflow-hidden w-full" style={{ gap: 1 }}>
        {active.map(s => {
          const pct = (s.v / total) * 100;
          return (
            <div
              key={s.key}
              className="flex items-center justify-center overflow-hidden shrink-0"
              style={{ width: `${pct}%`, minWidth: 16, backgroundColor: s.color }}
              title={`${s.title}: ${s.v}`}
            >
              <span className="text-[9px] font-bold text-white leading-none select-none">{s.v}</span>
            </div>
          );
        })}
      </div>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 flex-wrap">
          {active.map(s => (
            <span key={s.key} className="flex items-center gap-0.5 text-[9px] text-slate-500 dark:text-zinc-400">
              <span className="w-1.5 h-1.5 rounded-sm shrink-0" style={{ backgroundColor: s.color }} />
              {s.title === "Informational" ? "Info" : s.title}
            </span>
          ))}
        </div>
        <span className="text-[9px] font-bold text-slate-500 dark:text-zinc-400 tabular-nums">{total} total</span>
      </div>
    </div>
  );
}

// ── Scan metrics cell ─────────────────────────────────────────────────────────

const SEV_SHORT = ["findings_critical","findings_high","findings_medium","findings_low","findings_info"] as const;
const SEV_LETTER: Record<string, string> = {
  findings_critical: "C", findings_high: "H", findings_medium: "M",
  findings_low: "L", findings_info: "I",
};

function MetricsCell({ scan }: { scan: Scan }) {
  const total     = scan.hypotheses_total     ?? 0;
  const confirmed = scan.hypotheses_confirmed ?? 0;
  const rate      = total > 0 ? Math.round((confirmed / total) * 100) : 0;

  return (
    <div className="space-y-2.5 w-full">
      {/* Severity count grid */}
      <div className="flex items-end gap-1">
        {SEV_CFG.map(s => {
          const v = scan[s.key] ?? 0;
          return (
            <div key={s.key} className="flex flex-col items-center gap-0.5" title={`${s.title}: ${v}`}>
              <span
                className="text-[9px] font-black tabular-nums w-6 h-6 rounded flex items-center justify-center"
                style={{ backgroundColor: v > 0 ? `${s.color}18` : "#27272a", color: v > 0 ? s.color : "#71717a", border: `1px solid ${v > 0 ? s.color + "30" : "#3f3f46"}` }}
              >
                {v}
              </span>
              <span className="text-[8px] font-bold text-slate-500 dark:text-zinc-400">{SEV_LETTER[s.key]}</span>
            </div>
          );
        })}
      </div>

      {/* Hypotheses progress */}
      {total > 0 ? (
        <div>
          <div className="flex items-center justify-between mb-0.5">
            <span className="text-[9px] text-slate-500 dark:text-zinc-400">Hypotheses</span>
            <span className="text-[9px] font-bold text-slate-700 dark:text-zinc-300 tabular-nums">{confirmed}/{total} <span className="text-slate-500 dark:text-zinc-400 font-normal">({rate}%)</span></span>
          </div>
          <div className="h-1 bg-slate-100 dark:bg-zinc-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{ width: `${rate}%`, backgroundColor: rate >= 50 ? "#16a34a" : rate >= 25 ? "#d97706" : "#a1a1aa" }}
            />
          </div>
        </div>
      ) : (
        <p className="text-[9px] text-slate-500 dark:text-zinc-400 italic">No hypotheses</p>
      )}
    </div>
  );
}

function ProfileCell({ scan }: { scan: Scan }) {
  const p = PROVIDER_CFG[scan.llm_provider] ?? { label: scan.llm_provider, color: "text-slate-700 dark:text-zinc-300", border: "border-slate-200 dark:border-zinc-800 bg-slate-50 dark:bg-zinc-900/60" };
  const model = scan.llm_model || PROVIDER_DEFAULT_MODEL[scan.llm_provider] || "default";
  return (
    <div className="space-y-1 w-full">
      <div className="flex items-center gap-1 flex-wrap">
        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${p.color} ${p.border}`}>{p.label}</span>
        {scan.source_repo_url ? (
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-indigo-200 bg-indigo-50 text-indigo-800 dark:bg-indigo-950/40 dark:text-indigo-300 dark:border-indigo-800/50 font-bold">
            Source Review
          </span>
        ) : (
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-slate-200 dark:border-zinc-800 bg-slate-100 dark:bg-zinc-800/40 text-slate-700 dark:text-zinc-300 font-medium">
            {scan.scan_mode === "full" ? "Full" : "Static"}
          </span>
        )}
      </div>
      <p className="text-[10px] font-mono text-slate-500 dark:text-zinc-400 truncate w-full" title={model}>{model}</p>
      <p className="text-[9px] text-slate-500 dark:text-zinc-400">{scan.max_hypotheses} hyp · {scan.max_parallel}w · {scan.feedback_iter} iter</p>
      {scan.custom_prompt && (
        <div className="flex items-center gap-0.5" title={scan.custom_prompt}>
          <MessageSquareText className="h-2.5 w-2.5 text-amber-500 shrink-0" />
          <span className="text-[9px] text-amber-600 truncate w-full">{scan.custom_prompt}</span>
        </div>
      )}
    </div>
  );
}

// ── Constants ─────────────────────────────────────────────────────────────────

const PAGE_SIZES = [10, 20, 50];
const STATUSES = ["", "queued", "running", "completed", "failed", "cancelled"] as const;

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScanListPage() {
  const [statusFilter, setStatusFilter] = useState("");
  // Pre-fill from ?target= (Dashboard link OR the topbar search). useEffect re-syncs
  // when the param changes while already on this page (component does not remount).
  const [searchParams] = useSearchParams();
  const [search, setSearch] = useState(() => searchParams.get("target") || "");
  useEffect(() => {
    const t = searchParams.get("target");
    if (t !== null) setSearch(t);
  }, [searchParams]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: allScans = [], isLoading, refetch, isFetching } = useQuery({
    queryKey: ["scans", statusFilter],
    queryFn: () => scansApi.list({ status: statusFilter || undefined, limit: 200 }),
    refetchInterval: 5_000,
  });

  const filtered = useMemo(() => {
    let list = statusFilter ? allScans.filter(s => s.status === statusFilter) : allScans;
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(s =>
        s.target_url.toLowerCase().includes(q) ||
        (s.target_description ?? "").toLowerCase().includes(q),
      );
    }
    return list;
  }, [allScans, statusFilter, search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageScans  = filtered.slice((page - 1) * pageSize, page * pageSize);

  const statusCounts = useMemo(() => {
    const c: Record<string, number> = { "": allScans.length };
    STATUSES.slice(1).forEach(s => { c[s] = allScans.filter(sc => sc.status === s).length; });
    return c;
  }, [allScans]);

  const deleteMutation = useMutation({
    mutationFn: scansApi.delete,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scans"] }); setSelected(new Set()); },
  });
  const rerunMutation = useMutation({
    mutationFn: scansApi.rerun,
    onSuccess: scan => { qc.invalidateQueries({ queryKey: ["scans"] }); navigate(`/scans/${scan.id}`); },
  });
  const cancelMutation = useMutation({
    mutationFn: scansApi.cancel,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });

  const allSelected = pageScans.length > 0 && pageScans.every(s => selected.has(s.id));
  const toggleAll = () => {
    const next = new Set(selected);
    if (allSelected) pageScans.forEach(s => next.delete(s.id));
    else pageScans.forEach(s => next.add(s.id));
    setSelected(next);
  };
  const toggleOne = (id: string) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };

  const start = filtered.length === 0 ? 0 : (page - 1) * pageSize + 1;
  const end   = Math.min(page * pageSize, filtered.length);

  const running   = allScans.filter(s => s.status === "running").length;
  const completed = allScans.filter(s => s.status === "completed").length;
  const failed    = allScans.filter(s => s.status === "failed").length;

  return (
    <div className="space-y-3 pb-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[15px] font-bold text-slate-800 dark:text-zinc-200 flex items-center gap-2">
            <ScanLine className="h-4 w-4 text-slate-500 dark:text-zinc-400" />
            Scans
          </h1>
          <p className="text-[11px] text-slate-500 dark:text-zinc-400 mt-0.5">Manage and monitor all penetration test scans</p>
        </div>
        <div className="flex items-center gap-2">
          {selected.size > 0 && (
            <button
              onClick={() => { if (confirm(`Delete ${selected.size} scan(s)?`)) selected.forEach(id => deleteMutation.mutate(id)); }}
              className="flex items-center gap-1.5 text-[11px] px-3 py-1.5 rounded-lg border border-red-200 dark:border-red-800/50 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors font-medium"
            >
              <Trash2 className="h-3 w-3" /> Delete ({selected.size})
            </button>
          )}
          <button
            onClick={() => refetch()}
            className={`p-1.5 rounded-lg border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors ${isFetching ? "animate-spin" : ""}`}
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={() => navigate("/scans/new")}
            className="flex items-center gap-1.5 bg-teal-600 hover:bg-teal-700 dark:hover:bg-teal-500 text-white text-[11px] font-bold px-3 py-1.5 rounded-lg transition-colors"
          >
            <Plus className="h-3.5 w-3.5" /> New Scan
          </button>
        </div>
      </div>

      {/* ── KPI Strip ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { label: "Total",     value: allScans.length, icon: Target,        accent: "#6366f1" },
          { label: "Running",   value: running,          icon: Activity,      accent: "#3b82f6" },
          { label: "Completed", value: completed,        icon: CheckCircle2,  accent: "#059669" },
          { label: "Failed",    value: failed,           icon: AlertTriangle, accent: "#dc2626" },
        ].map(({ label, value, icon: Icon, accent }) => (
          <div key={label} className="bg-white dark:bg-zinc-900 rounded-lg border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden flex">
            <div className="w-[3px] shrink-0 self-stretch" style={{ backgroundColor: accent }} />
            <div className="flex-1 px-3 py-2.5 flex items-center justify-between gap-2">
              <div>
                <p className="text-[9px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">{label}</p>
                <p className="text-xl font-black tabular-nums leading-tight" style={{ color: accent }}>{value}</p>
              </div>
              <Icon className="h-4 w-4 shrink-0" style={{ color: `${accent}60` }} />
            </div>
          </div>
        ))}
      </div>

      {/* ── Search + Filter bar ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-[320px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500 dark:text-zinc-400 pointer-events-none" />
          <input
            type="text"
            placeholder="Search targets…"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            className="w-full pl-8 pr-3 py-1.5 text-[11px] border border-slate-200 dark:border-zinc-800 rounded-lg bg-white dark:bg-zinc-900 text-slate-700 dark:text-zinc-300 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-teal-500 focus:border-teal-400"
          />
        </div>

        {/* Status filter tabs */}
        {STATUSES.map(s => {
          const count = statusCounts[s] ?? 0;
          const isActive = statusFilter === s;
          const cfg = s ? STATUS_CFG[s] : null;
          return (
            <button
              key={s || "all"}
              onClick={() => { setStatusFilter(s); setPage(1); }}
              className={`flex items-center gap-1 text-[11px] px-2.5 py-1.5 rounded-lg border font-medium transition-all ${
                isActive
                  ? "bg-teal-600 text-white border-teal-600"
                  : "bg-white dark:bg-zinc-900 text-slate-500 dark:text-zinc-400 border-slate-200 dark:border-zinc-800 hover:bg-slate-50 dark:hover:bg-zinc-900/60"
              }`}
            >
              {s && cfg && (
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${isActive ? "bg-white dark:bg-zinc-900" : cfg.dot}`} />
              )}
              <span className="capitalize">{s || "All"}</span>
              <span className={`text-[9px] font-bold px-1 py-0.5 rounded-full ${isActive ? "bg-white/25 text-white" : "bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400"}`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* ── Table ──────────────────────────────────────────────────────────── */}
      <div className="bg-white dark:bg-zinc-900 rounded-lg border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
        <table className="w-full table-fixed">
          <colgroup>
            <col style={{ width: 36 }} />
            <col style={{ width: 220 }} />
            <col style={{ width: 180 }} />
            <col style={{ width: 230 }} />
            <col style={{ width: 170 }} />
            <col style={{ width: 120 }} />
          </colgroup>
          <thead>
            <tr className="bg-slate-100 dark:bg-zinc-800/40 border-b border-slate-200 dark:border-zinc-800">
              <th className="py-2 px-3">
                <input type="checkbox" checked={allSelected} onChange={toggleAll}
                  className="rounded border-slate-300 dark:border-zinc-600 accent-blue-600 w-3.5 h-3.5" />
              </th>
              <th className="text-left py-2 px-3 text-[10px] font-bold text-slate-500 dark:text-zinc-400 uppercase tracking-[0.12em]">Target</th>
              <th className="text-left py-2 px-3 text-[10px] font-bold text-slate-500 dark:text-zinc-400 uppercase tracking-[0.12em]">Scan Profile</th>
              <th className="text-left py-2 px-3 text-[10px] font-bold text-slate-500 dark:text-zinc-400 uppercase tracking-[0.12em]">Vulnerabilities</th>
              <th className="text-left py-2 px-3 text-[10px] font-bold text-slate-500 dark:text-zinc-400 uppercase tracking-[0.12em]">Metrics</th>
              <th className="text-right py-2 px-3 text-[10px] font-bold text-slate-500 dark:text-zinc-400 uppercase tracking-[0.12em]">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500 dark:text-zinc-400">
                  <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2 text-slate-700 dark:text-zinc-300" />
                  <p className="text-[11px]">Loading…</p>
                </td>
              </tr>
            )}
            {!isLoading && pageScans.length === 0 && (
              <tr>
                <td colSpan={6} className="py-12 text-center">
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-9 h-9 rounded-full border-2 border-dashed border-slate-200 dark:border-zinc-800 flex items-center justify-center">
                      <ScanLine className="h-3.5 w-3.5 text-slate-700 dark:text-zinc-300" />
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-zinc-400">
                      {search ? `No scans match "${search}"` : "No scans found"}
                    </p>
                  </div>
                </td>
              </tr>
            )}
            {pageScans.map(scan => {
              const isActive   = scan.status === "queued" || scan.status === "running";
              const isSelected = selected.has(scan.id);
              const total      = SEV_CFG.reduce((a, s) => a + (scan[s.key] ?? 0), 0);

              return (
                <tr
                  key={scan.id}
                  onClick={() => navigate(`/scans/${scan.id}`)}
                  className={`border-b border-slate-50 last:border-0 cursor-pointer transition-colors ${
                    isSelected ? "bg-teal-50 dark:bg-teal-950/30" : "hover:bg-slate-100 dark:hover:bg-zinc-800/50"
                  }`}
                >
                  {/* Checkbox */}
                  <td className="py-2.5 px-3" onClick={e => e.stopPropagation()}>
                    <input type="checkbox" checked={isSelected} onChange={() => toggleOne(scan.id)}
                      className="rounded border-slate-300 dark:border-zinc-600 accent-blue-600 w-3.5 h-3.5" />
                  </td>

                  {/* Target + meta */}
                  <td className="py-2.5 px-3 overflow-hidden">
                    <p className="text-teal-700 dark:text-teal-400 text-[12px] font-semibold truncate hover:underline leading-tight flex items-center gap-1" title={scan.target_url}>
                      {scan.source_repo_url && <GitBranch className="h-3 w-3 text-indigo-500 shrink-0" />}
                      <span className="truncate">{scan.target_url}</span>
                    </p>
                    {scan.target_description && (
                      <p className="text-[9px] text-slate-500 dark:text-zinc-400 truncate mt-0.5" title={scan.target_description}>
                        {scan.target_description}
                      </p>
                    )}
                    <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                      <StatusPill status={scan.status} phase={scan.phase} />
                      <RiskPill scan={scan} />
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[9px] text-slate-500 dark:text-zinc-400">
                        {relTime(scan.completed_at || scan.started_at || scan.created_at)}
                      </span>
                      {scan.duration_seconds != null && scan.duration_seconds > 0 && (
                        <span className="flex items-center gap-0.5 text-[9px] text-slate-500 dark:text-zinc-400">
                          <Timer className="h-2.5 w-2.5" />
                          {scan.duration_seconds < 60
                            ? `${scan.duration_seconds}s`
                            : scan.duration_seconds < 3600
                            ? `${Math.floor(scan.duration_seconds / 60)}m`
                            : `${Math.floor(scan.duration_seconds / 3600)}h ${Math.floor((scan.duration_seconds % 3600) / 60)}m`}
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Scan profile */}
                  <td className="py-2.5 px-3 overflow-hidden">
                    <ProfileCell scan={scan} />
                  </td>

                  {/* Vulnerabilities */}
                  <td className="py-2.5 px-3 overflow-hidden">
                    <VulnBar scan={scan} />
                    {total > 0 && (
                      <button
                        onClick={e => { e.stopPropagation(); navigate(`/findings?scan_id=${scan.id}`); }}
                        className="mt-1.5 flex items-center gap-1 text-[9px] text-teal-500 hover:text-teal-700 dark:text-teal-300 font-medium transition-colors"
                      >
                        <ExternalLink className="h-2.5 w-2.5" /> View Findings
                      </button>
                    )}
                  </td>

                  {/* Metrics */}
                  <td className="py-2.5 px-3">
                    <MetricsCell scan={scan} />
                  </td>

                  {/* Actions */}
                  <td className="py-2.5 px-3 text-right" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1">
                      {!isActive && (
                        <button
                          onClick={() => rerunMutation.mutate(scan.id)}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-teal-50 dark:hover:bg-teal-950/40 hover:border-teal-700/50 hover:text-teal-700 dark:text-teal-400 transition-colors font-medium"
                        >
                          <RotateCcw className="h-2.5 w-2.5" /> Rerun
                        </button>
                      )}
                      {isActive && (
                        <button
                          onClick={() => cancelMutation.mutate(scan.id)}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-amber-200 dark:border-amber-800/50 text-amber-700 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-950/40 transition-colors font-medium"
                        >
                          <XCircle className="h-2.5 w-2.5" /> Cancel
                        </button>
                      )}
                      <button
                        onClick={() => { if (confirm("Delete this scan?")) deleteMutation.mutate(scan.id); }}
                        className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-red-50 dark:hover:bg-red-950/40 hover:border-red-800/50 hover:text-red-600 dark:text-red-400 transition-colors font-medium"
                      >
                        <Trash2 className="h-2.5 w-2.5" /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* ── Pagination ─────────────────────────────────────────────────── */}
        {filtered.length > 0 && (
          <div className="flex items-center justify-between px-3 py-2 border-t border-slate-200 dark:border-zinc-800 bg-slate-50 dark:bg-zinc-900/50">
            <span className="text-[10px] text-slate-500 dark:text-zinc-400">
              <span className="font-semibold text-slate-700 dark:text-zinc-300">{start}-{end}</span> of <span className="font-semibold text-slate-700 dark:text-zinc-300">{filtered.length}</span>
              {search && <span className="ml-1 text-teal-500">· filtered</span>}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1 rounded border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-white dark:bg-zinc-900 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>

              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter(p => p === 1 || p === totalPages || Math.abs(p - page) <= 1)
                .reduce<(number | "…")[]>((acc, p, i, arr) => {
                  if (i > 0 && p - (arr[i - 1] as number) > 1) acc.push("…");
                  acc.push(p);
                  return acc;
                }, [])
                .map((p, i) =>
                  p === "…" ? (
                    <span key={`e-${i}`} className="text-[10px] text-slate-500 dark:text-zinc-400 px-1">…</span>
                  ) : (
                    <button
                      key={p}
                      onClick={() => setPage(p as number)}
                      className={`w-6 h-6 rounded text-[10px] font-bold transition-colors ${
                        page === p ? "bg-teal-600 text-white" : "text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800"
                      }`}
                    >
                      {p}
                    </button>
                  )
                )}

              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-1 rounded border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-white dark:bg-zinc-900 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>

              <select
                value={pageSize}
                onChange={e => { setPageSize(+e.target.value); setPage(1); }}
                className="text-[10px] border border-slate-200 dark:border-zinc-800 rounded px-1.5 py-1 bg-white dark:bg-zinc-900 text-slate-500 dark:text-zinc-400 ml-1 focus:outline-none"
              >
                {PAGE_SIZES.map(n => <option key={n} value={n}>{n}/page</option>)}
              </select>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
