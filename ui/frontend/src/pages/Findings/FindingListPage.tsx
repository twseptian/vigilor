import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ShieldAlert, Search, X, ChevronDown } from "lucide-react";
import { findingsApi, type Finding } from "@/api/findings";
import { SEVERITY_COLORS, FINDING_STATUS_HEX } from "@/lib/utils";
import { SEV_BADGE, SEV_HEX, TONE_BADGE } from "@/lib/badges";
import { useThemeStore } from "@/store/themeStore";

// ── Design tokens ─────────────────────────────────────────────────────────────

const SEV_SOFT = {
  Critical: { light: "#fef2f2", dark: "#2a1414" },
  High: { light: "#fff7ed", dark: "#2a1c12" },
  Medium: { light: "#fefce8", dark: "#282210" },
  Low: { light: "#eff6ff", dark: "#121a28" },
  Informational: { light: "#f8fafc", dark: "#1f1f23" },
} as const;

const SEV: Record<string, { color: string; badgeCls: string }> = {
  Critical:      { color: SEV_HEX.Critical, badgeCls: SEV_BADGE.Critical },
  High:          { color: SEV_HEX.High, badgeCls: SEV_BADGE.High },
  Medium:        { color: SEV_HEX.Medium, badgeCls: SEV_BADGE.Medium },
  Low:           { color: SEV_HEX.Low, badgeCls: SEV_BADGE.Low },
  Informational: { color: SEV_HEX.Informational, badgeCls: SEV_BADGE.Informational },
};

const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

const STATUSES = ["Open", "Partially Resolved", "Risk Accepted", "Resolved", "Closed", "NA"] as const;

const STATUS_COLORS: Record<string, string> = {
  "Open":               "#dc2626",
  "Partially Resolved": "#2563eb",
  "Risk Accepted":      "#d97706",
  "Resolved":           "#16a34a",
  "Closed":             "#a1a1aa",
  "NA":                 "#a1a1aa",
};

// ── Confidence Pill ───────────────────────────────────────────────────────────

function ConfidencePill({ score }: { score: number }) {
  if (score >= 80) return (
    <span className={`text-[8px] font-bold px-1 py-0.5 rounded border shrink-0 ${TONE_BADGE.emerald}`}>
      HIGH
    </span>
  );
  if (score >= 40) return (
    <span className={`text-[8px] font-bold px-1 py-0.5 rounded border shrink-0 ${TONE_BADGE.amber}`}>
      MED
    </span>
  );
  return (
    <span className={`text-[8px] font-bold px-1 py-0.5 rounded border shrink-0 ${TONE_BADGE.orange}`}>
      LOW
    </span>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function FindingListPage() {
  const theme = useThemeStore(s => s.theme);
  const isLight = theme === "light";
  const mutedFg = isLight ? "#64748b" : "#a1a1aa";

  // Pre-fill the severity filter when arriving from the Dashboard severity strip
  // (/findings?severity=High).
  const [sevFilter, setSevFilter]       = useState(
    () => new URLSearchParams(window.location.search).get("severity") || "");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch]             = useState("");
  const [selected, setSelected]         = useState<string[]>([]);
  const [bulkMenuOpen, setBulkMenuOpen] = useState(false);
  const [verifMenuOpen, setVerifMenuOpen] = useState(false);
  const [verifFilter, setVerifFilter]   = useState("");
  const [evidenceFilter, setEvidenceFilter] = useState<"" | "with" | "without">("");
  const [sortCol, setSortCol]           = useState<"severity" | "cvss" | "title" | "status" | "ref">("severity");
  const [sortDir, setSortDir]           = useState<"asc" | "desc">("asc");
  const navigate = useNavigate();
  const qc = useQueryClient();
  // When arriving from a scan's "View Findings", scope the list to that scan.
  const [searchParams, setSearchParams] = useSearchParams();
  const scanId = searchParams.get("scan_id") || undefined;

  // Keep the severity filter in sync with the URL param so in-app navigation
  // (e.g. Dashboard severity strip, back/forward) reactively updates it — not
  // just the initial mount. Fires only when the ?severity value itself changes,
  // so a manual UI selection is never clobbered.
  const sevParam = searchParams.get("severity") || "";
  useEffect(() => { setSevFilter(sevParam); }, [sevParam]);

  const toggleSort = (col: typeof sortCol) => {
    if (sortCol === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("asc"); }
  };

  // Severity is filtered CLIENT-SIDE (below) so the severity ribbon keeps showing
  // the true per-severity counts even when one severity is selected. Only status +
  // scan scoping are server-side.
  const { data: rawFindings = [], isLoading } = useQuery({
    queryKey: ["findings-all", statusFilter, scanId],
    queryFn: () => findingsApi.list({
      status: statusFilter || undefined,
      scan_id: scanId,
      limit: 500,
    }),
  });

  const findings = [...rawFindings].sort((a, b) => {
    let cmp = 0;
    if (sortCol === "severity") cmp = SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity);
    else if (sortCol === "cvss")   cmp = ((b.cvss4_score ?? b.cvss_score ?? 0)) - ((a.cvss4_score ?? a.cvss_score ?? 0));
    else if (sortCol === "title")  cmp = a.title.localeCompare(b.title);
    else if (sortCol === "status") cmp = a.status.localeCompare(b.status);
    else if (sortCol === "ref")    cmp = (a.finding_ref ?? "").localeCompare(b.finding_ref ?? "");
    return sortDir === "asc" ? cmp : -cmp;
  });

  const filtered = findings.filter(f => {
    if (sevFilter && f.severity !== sevFilter) return false;
    if (verifFilter && (f.verification_status ?? "Unverified") !== verifFilter) return false;
    if (evidenceFilter === "with" && !f.has_poc) return false;
    if (evidenceFilter === "without" && f.has_poc) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      (f.finding_ref ?? "").toLowerCase().includes(q) ||
      (f.location ?? "").toLowerCase().includes(q) ||
      (f.owasp_category ?? "").toLowerCase().includes(q) ||
      (f.vuln_type ?? "").toLowerCase().includes(q)
    );
  });

  const verifMutation = useMutation({
    mutationFn: ({ ids, value }: { ids: string[]; value: string }) =>
      findingsApi.bulkVerification(ids, value),
    onSuccess: () => {
      setSelected([]);
      setVerifMenuOpen(false);
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const bulkMutation = useMutation({
    mutationFn: ({ ids, newStatus }: { ids: string[]; newStatus: string }) =>
      findingsApi.bulkStatus(ids, newStatus),
    onSuccess: () => {
      setSelected([]);
      setBulkMenuOpen(false);
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const toggleAll = () => {
    if (selected.length === filtered.length) setSelected([]);
    else setSelected(filtered.map(f => f.id));
  };

  const toggleOne = (id: string) =>
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

  // Severity counts for ribbon
  const sevCounts = SEV_ORDER.map(s => ({
    key: s,
    count: findings.filter(f => f.severity === s).length,
  }));

  const totalOpen = findings.filter(f => f.status === "Open").length;
  const totalCritHigh = findings.filter(f => f.severity === "Critical" || f.severity === "High").length;

  return (
    <div className="space-y-3 pb-8">

      {/* ══════════════════════════════════════════════════════════════════════
          TOP CARD — title + KPI strip + severity ribbon + filter bar
          ══════════════════════════════════════════════════════════════════════ */}
      <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
        <div className="h-[3px] bg-red-500" />

        {/* Title + search row */}
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-100 dark:border-red-900/40">
              <ShieldAlert className="h-4 w-4 text-red-500" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-[15px] font-bold text-slate-800 dark:text-zinc-200 leading-tight">Findings</h1>
                {!isLoading && (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400 tabular-nums">
                    {findings.length}
                  </span>
                )}
                {scanId && (
                  <button
                    onClick={() => setSearchParams({})}
                    className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full border transition-colors hover:opacity-90 ${TONE_BADGE.teal}`}
                    title="Clear the scan filter and show all findings"
                  >
                    Scoped to scan · Show all ✕
                  </button>
                )}
              </div>
              <p className="text-[10px] text-slate-500 dark:text-zinc-400 mt-0.5">
                {scanId ? "Findings from the selected scan" : "All vulnerability findings across scans"}
              </p>
            </div>
          </div>

          <div className="flex-1" />

          {/* KPIs */}
          <div className="hidden lg:flex items-center gap-4 border-r border-slate-200 dark:border-zinc-800 pr-4 mr-1">
            <div className="text-center">
              <p className="text-[9px] font-semibold uppercase tracking-[0.1em] text-slate-500 dark:text-zinc-400">Open</p>
              <p className="text-[16px] font-black tabular-nums leading-tight" style={{ color: totalOpen > 0 ? "#b45309" : "#94a3b8" }}>{totalOpen}</p>
            </div>
            <div className="text-center">
              <p className="text-[9px] font-semibold uppercase tracking-[0.1em] text-slate-500 dark:text-zinc-400">Crit/High</p>
              <p className="text-[16px] font-black tabular-nums leading-tight" style={{ color: totalCritHigh > 0 ? "#b91c1c" : "#94a3b8" }}>{totalCritHigh}</p>
            </div>
            <div className="text-center">
              <p className="text-[9px] font-semibold uppercase tracking-[0.1em] text-slate-500 dark:text-zinc-400">Total</p>
              <p className="text-[16px] font-black tabular-nums leading-tight text-slate-800 dark:text-zinc-200">{findings.length}</p>
            </div>
          </div>

          {/* Search */}
          <div className="flex items-center gap-1.5 border border-slate-200 dark:border-zinc-800 rounded-lg px-2.5 py-1.5 bg-slate-100 dark:bg-zinc-800/50 w-52">
            <Search className="h-3 w-3 text-slate-500 dark:text-zinc-400 shrink-0" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search findings…"
              className="flex-1 bg-transparent text-[11px] text-slate-700 dark:text-zinc-300 placeholder:text-slate-500 dark:text-zinc-400 outline-none min-w-0"
            />
            {search && (
              <button onClick={() => setSearch("")}>
                <X className="h-3 w-3 text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300" />
              </button>
            )}
          </div>

          {/* Triage filters — same questions the scan-detail table answers */}
          <label className={`flex items-center gap-1.5 border rounded-lg pl-2 pr-1 py-1 bg-white dark:bg-zinc-900 transition-colors ${
            verifFilter ? "border-teal-600/50" : "border-slate-200 dark:border-zinc-800"
          }`}>
            <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 dark:text-zinc-400">Verification</span>
            <select
              value={verifFilter}
              onChange={e => setVerifFilter(e.target.value)}
              className={`bg-transparent text-[11px] outline-none cursor-pointer pr-1 ${
                verifFilter ? "text-teal-700 dark:text-teal-300 font-semibold" : "text-slate-700 dark:text-zinc-300"
              }`}
            >
              <option value="">All</option>
              <option value="Unverified">Unverified</option>
              <option value="Verified">Verified</option>
              <option value="False Positive">False Positive</option>
            </select>
          </label>

          <label className={`flex items-center gap-1.5 border rounded-lg pl-2 pr-1 py-1 bg-white dark:bg-zinc-900 transition-colors ${
            evidenceFilter ? "border-teal-600/50" : "border-slate-200 dark:border-zinc-800"
          }`}>
            <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 dark:text-zinc-400">Evidence</span>
            <select
              value={evidenceFilter}
              onChange={e => setEvidenceFilter(e.target.value as "" | "with" | "without")}
              className={`bg-transparent text-[11px] outline-none cursor-pointer pr-1 ${
                evidenceFilter ? "text-teal-700 dark:text-teal-300 font-semibold" : "text-slate-700 dark:text-zinc-300"
              }`}
            >
              <option value="">Any evidence</option>
              <option value="with">Has PoC</option>
              <option value="without">No PoC</option>
            </select>
          </label>
        </div>

        {/* Severity ribbon */}
        <div className="grid grid-cols-5 divide-x divide-slate-200 dark:divide-zinc-700/60 border-b border-slate-200 dark:border-zinc-800">
          {sevCounts.map(({ key, count }) => {
            const cfg = SEV[key];
            const soft = SEV_SOFT[key as keyof typeof SEV_SOFT];
            const softBg = isLight ? soft.light : soft.dark;
            const active = count > 0;
            const selected_ = sevFilter === key;
            return (
              <button
                key={key}
                onClick={() => setSevFilter(selected_ ? "" : key)}
                className="flex flex-col items-center py-3 px-2 transition-all focus:outline-none relative group"
                style={{ backgroundColor: selected_ ? softBg : active ? `${softBg}cc` : undefined }}
              >
                {selected_ && <div className="absolute bottom-0 left-0 right-0 h-[2px]" style={{ backgroundColor: cfg.color }} />}
                <span className="text-[24px] font-black leading-none tabular-nums" style={{ color: active ? cfg.color : mutedFg }}>{count}</span>
                <span className="text-[9px] font-bold uppercase tracking-widest mt-0.5" style={{ color: active ? cfg.color : mutedFg }}>
                  {key === "Informational" ? "Info" : key}
                </span>
              </button>
            );
          })}
        </div>

        {/* Status filter bar */}
        <div className="px-4 py-2 flex items-center gap-1.5 flex-wrap">
          <span className="text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500 dark:text-zinc-400 mr-1">Status</span>
          <button
            onClick={() => setStatusFilter("")}
            className={`text-[10px] font-semibold px-2.5 py-1 rounded-lg border transition-all ${
              statusFilter === ""
                ? "bg-slate-800 text-white border-slate-800"
                : "border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-slate-50 dark:hover:bg-zinc-900/60"
            }`}
          >
            All
          </button>
          {STATUSES.map(s => {
            const active = statusFilter === s;
            const color = STATUS_COLORS[s] ?? "#a1a1aa";
            return (
              <button
                key={s}
                onClick={() => setStatusFilter(active ? "" : s)}
                className="text-[10px] font-semibold px-2.5 py-1 rounded-lg border transition-all"
                style={active
                  ? { backgroundColor: color, color: "#27272a", borderColor: color }
                  : { borderColor: "#3f3f46", color: "#a1a1aa" }
                }
              >
                {s}
              </button>
            );
          })}
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════════
          TABLE CARD
          ══════════════════════════════════════════════════════════════════════ */}
      <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">

        {/* Bulk triage bar */}
        {selected.length > 0 && (
          <div className="px-4 py-2 bg-teal-50 dark:bg-teal-950/35 border-b border-teal-200 dark:border-teal-800/40 flex items-center gap-2.5">
            <span className="text-[11px] font-bold text-teal-800 dark:text-teal-300">{selected.length} selected</span>
            <span className="h-3 w-px bg-teal-200 dark:bg-teal-800" />
            <span className="text-[10px] text-teal-700 dark:text-teal-400">Mark as:</span>
            <div className="relative">
              <button
                onClick={() => setBulkMenuOpen(o => !o)}
                disabled={bulkMutation.isPending}
                className="flex items-center gap-1 text-[10px] font-semibold px-2.5 py-1 rounded-lg border border-teal-300 dark:border-teal-600/50 bg-white dark:bg-zinc-900 text-teal-800 dark:text-teal-300 hover:bg-teal-50 dark:hover:bg-teal-950/40 transition-colors disabled:opacity-50"
              >
                Change status <ChevronDown className="h-3 w-3" />
              </button>
              {bulkMenuOpen && (
                <div className="absolute left-0 top-full mt-1 w-48 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl shadow-lg z-30 py-1 overflow-hidden">
                  {STATUSES.map(s => (
                    <button
                      key={s}
                      onClick={() => bulkMutation.mutate({ ids: selected, newStatus: s })}
                      className="w-full text-left px-3 py-2 text-[11px] font-medium hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors flex items-center gap-2"
                    >
                      <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: STATUS_COLORS[s] }} />
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="relative">
              <button
                onClick={() => setVerifMenuOpen(o => !o)}
                disabled={verifMutation.isPending}
                className="flex items-center gap-1 text-[10px] font-semibold px-2.5 py-1 rounded-lg border border-teal-300 dark:border-teal-600/50 bg-white dark:bg-zinc-900 text-teal-800 dark:text-teal-300 hover:bg-teal-50 dark:hover:bg-teal-950/40 transition-colors disabled:opacity-50"
              >
                Set verification <ChevronDown className="h-3 w-3" />
              </button>
              {verifMenuOpen && (
                <div className="absolute left-0 top-full mt-1 w-48 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl shadow-lg z-30 py-1 overflow-hidden">
                  {["Unverified", "Verified", "False Positive"].map(v => (
                    <button
                      key={v}
                      onClick={() => verifMutation.mutate({ ids: selected, value: v })}
                      className="w-full text-left px-3 py-2 text-[11px] font-medium hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors"
                    >
                      {v}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              onClick={() => setSelected([])}
              className="ml-auto text-[10px] text-teal-700 dark:text-teal-400 hover:text-teal-700 dark:text-teal-300 font-medium flex items-center gap-1"
            >
              <X className="h-3 w-3" /> Clear
            </button>
          </div>
        )}

        {/* Table */}
        <div className="overflow-auto max-h-[calc(100vh-320px)]">
          <table className="w-full text-xs table-fixed">
            <colgroup>
              <col style={{ width: 36 }} />
              <col style={{ width: 80 }} />
              <col />
              <col style={{ width: 96 }} />
              <col style={{ width: 76 }} />
              <col style={{ width: 200 }} />
              <col style={{ width: 120 }} />
              <col style={{ width: 160 }} />
            </colgroup>
            <thead className="sticky top-0 z-10">
              <tr className="bg-slate-100 dark:bg-zinc-800/40 border-b border-slate-200 dark:border-zinc-800">
                <th className="py-2 px-3 text-left">
                  <input
                    type="checkbox"
                    checked={selected.length === filtered.length && filtered.length > 0}
                    onChange={toggleAll}
                    className="rounded border-slate-300 dark:border-zinc-600 w-3.5 h-3.5"
                  />
                </th>
                {([
                  { label: "REF",      col: "ref"      as const, sortable: true  },
                  { label: "TITLE",    col: "title"    as const, sortable: true  },
                  { label: "SEVERITY", col: "severity" as const, sortable: true  },
                  { label: "CVSS",     col: "cvss"     as const, sortable: true  },
                  { label: "LOCATION", col: null,                sortable: false },
                  { label: "STATUS",   col: "status"   as const, sortable: true  },
                  { label: "OWASP",    col: null,                sortable: false },
                ] as const).map(h => (
                  <th
                    key={h.label}
                    onClick={h.sortable && h.col ? () => toggleSort(h.col!) : undefined}
                    className={`text-left py-2 px-3 text-[10px] font-bold text-slate-500 dark:text-zinc-400 uppercase tracking-[0.12em] select-none ${
                      h.sortable ? "cursor-pointer hover:text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors" : ""
                    }`}
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
              {isLoading && (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[11px] text-slate-500 dark:text-zinc-400">
                    Loading findings…
                  </td>
                </tr>
              )}
              {!isLoading && filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-14 text-center">
                    <div className="flex flex-col items-center gap-2">
                      <div className="w-9 h-9 rounded-full border-2 border-dashed border-slate-200 dark:border-zinc-800 flex items-center justify-center">
                        <ShieldAlert className="h-4 w-4 text-slate-700 dark:text-zinc-300" />
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-zinc-400 font-medium">No findings match current filters</p>
                      <p className="text-[10px] text-slate-700 dark:text-zinc-300">Try adjusting severity, status, or search query</p>
                    </div>
                  </td>
                </tr>
              )}
              {filtered.map((f: Finding, idx) => {
                const sevCfg = SEV[f.severity] ?? SEV.Informational;
                const isSelected = selected.includes(f.id);
                return (
                  <tr
                    key={f.id}
                    className={`border-b border-slate-200 dark:border-zinc-800 last:border-0 cursor-pointer transition-colors group ${
                      isSelected
                        ? "bg-teal-50 dark:bg-teal-950/35"
                        : idx % 2 === 0
                        ? "bg-white dark:bg-zinc-900 hover:bg-teal-50 dark:hover:bg-teal-950/30"
                        : "bg-slate-50 dark:bg-zinc-900/30 hover:bg-teal-50 dark:hover:bg-teal-950/30"
                    }`}
                  >
                    {/* Checkbox */}
                    <td className="py-2.5 px-3" onClick={e => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleOne(f.id)}
                        className="rounded border-slate-300 dark:border-zinc-600 w-3.5 h-3.5"
                      />
                    </td>

                    {/* REF — with severity accent bar */}
                    <td className="py-2.5 px-3 relative overflow-hidden" onClick={() => navigate(`/findings/${f.id}`)}>
                      <div className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ backgroundColor: sevCfg.color }} />
                      <span className="font-mono text-[10px] text-slate-500 dark:text-zinc-400 truncate block pl-1">{f.finding_ref || "-"}</span>
                    </td>

                    {/* Title */}
                    <td className="py-2.5 px-3 overflow-hidden" onClick={() => navigate(`/findings/${f.id}`)}>
                      <p className="text-[11px] font-semibold text-slate-800 dark:text-zinc-200 group-hover:text-teal-700 dark:text-teal-300 transition-colors truncate leading-snug">{f.title}</p>
                      {/* One-line summary, mirroring the scan-detail findings table */}
                      {f.description && (
                        <p className="text-[9px] text-slate-500 dark:text-zinc-400 truncate mt-0.5 leading-snug">{f.description}</p>
                      )}
                      <div className="flex items-center gap-1 mt-0.5 flex-wrap">
                        {f.vuln_type && (
                          <span className="text-[9px] text-slate-500 dark:text-zinc-400 truncate">{f.vuln_type}</span>
                        )}
                        {f.source_repo_url && (
                          <span className={`text-[8px] font-bold px-1 py-0.5 rounded border shrink-0 ${TONE_BADGE.indigo}`}>
                            Source Review
                          </span>
                        )}
                        <ConfidencePill score={f.confidence_score ?? 0} />
                        {!(f.has_poc ?? false) && (
                          <span className={`text-[8px] font-bold px-1 py-0.5 rounded border shrink-0 ${TONE_BADGE.red}`}>
                            No PoC
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Severity */}
                    <td className="py-2.5 px-3" onClick={() => navigate(`/findings/${f.id}`)}>
                      <span className={`inline-block text-[9px] font-bold px-2 py-0.5 rounded border ${sevCfg.badgeCls}`}>
                        {f.severity === "Informational" ? "Info" : f.severity}
                      </span>
                    </td>

                    {/* CVSS */}
                    <td className="py-2.5 px-3" onClick={() => navigate(`/findings/${f.id}`)}>
                      {f.cvss4_score != null || f.cvss_score != null ? (
                        <div className="space-y-0.5">
                          {f.cvss_score != null && (
                            <div className="flex items-center gap-0.5">
                              <span className="text-[8px] font-mono font-bold text-slate-500 dark:text-zinc-400">3.1</span>
                              <span className="text-[12px] font-black tabular-nums leading-none"
                                style={{ color: f.cvss_score >= 9 ? "#dc2626" : f.cvss_score >= 7 ? "#ea580c" : f.cvss_score >= 4 ? "#d97706" : "#2563eb" }}>
                                {f.cvss_score.toFixed(1)}
                              </span>
                            </div>
                          )}
                          {f.cvss4_score != null && (
                            <div className="flex items-center gap-0.5">
                              <span className="text-[8px] font-mono font-bold text-indigo-400">4.0</span>
                              <span className="text-[12px] font-black tabular-nums leading-none"
                                style={{ color: f.cvss4_score >= 9 ? "#dc2626" : f.cvss4_score >= 7 ? "#ea580c" : f.cvss4_score >= 4 ? "#d97706" : "#2563eb" }}>
                                {f.cvss4_score.toFixed(1)}
                              </span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-700 dark:text-zinc-300 text-[10px]">-</span>
                      )}
                    </td>

                    {/* Location */}
                    <td className="py-2.5 px-3 overflow-hidden" onClick={() => navigate(`/findings/${f.id}`)}>
                      <p className="text-[10px] text-slate-500 dark:text-zinc-400 font-mono truncate" title={f.location ?? ""}>{f.location || "-"}</p>
                      {f.source_repo_url && (
                        <p className="text-[9px] text-indigo-400 font-mono truncate" title={f.source_repo_url}>
                          {f.source_repo_url.replace(/^https?:\/\/(www\.)?/, "").replace(/\.git$/, "")}
                        </p>
                      )}
                    </td>

                    {/* Status */}
                    <td className="py-2.5 px-3" onClick={() => navigate(`/findings/${f.id}`)}>
                      <span
                        className="text-[9px] font-bold px-1.5 py-0.5 rounded border whitespace-nowrap"
                        style={{
                          backgroundColor: (STATUS_COLORS[f.status] ?? "#a1a1aa") + "15",
                          color: STATUS_COLORS[f.status] ?? "#a1a1aa",
                          borderColor: (STATUS_COLORS[f.status] ?? "#a1a1aa") + "40",
                        }}
                      >
                        {f.status}
                      </span>
                    </td>

                    {/* OWASP */}
                    <td className="py-2.5 px-3 overflow-hidden" onClick={() => navigate(`/findings/${f.id}`)}>
                      {f.owasp_category ? (
                        <div title={f.owasp_name ?? f.owasp_category}>
                          <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-100 dark:bg-zinc-800 text-slate-700 dark:text-zinc-300 border border-slate-200 dark:border-zinc-800 block w-fit">{f.owasp_category}</span>
                          {f.owasp_name && (
                            <p className="text-[8px] text-slate-500 dark:text-zinc-400 truncate mt-0.5 max-w-[140px]">{f.owasp_name}</p>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-700 dark:text-zinc-300 text-[10px]">-</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        {!isLoading && filtered.length > 0 && (
          <div className="px-4 py-2 border-t border-slate-200 dark:border-zinc-800 bg-slate-50 dark:bg-zinc-900/50 flex items-center justify-between">
            <span className="text-[10px] text-slate-500 dark:text-zinc-400">
              {filtered.length !== findings.length
                ? <>Showing <strong className="text-slate-700 dark:text-zinc-300">{filtered.length}</strong> of <strong className="text-slate-700 dark:text-zinc-300">{findings.length}</strong> findings</>
                : <><strong className="text-slate-700 dark:text-zinc-300">{findings.length}</strong> findings total</>
              }
            </span>
            <div className="flex items-center gap-3">
              <span className="text-[10px] text-slate-500 dark:text-zinc-400">
                Sorted by <strong className="text-slate-700 dark:text-zinc-300">{sortCol}</strong> {sortDir === "asc" ? "↑" : "↓"}
              </span>
              {selected.length > 0 && (
                <span className="text-[10px] font-semibold text-teal-700 dark:text-teal-400">{selected.length} selected</span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
