import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Plus, RefreshCw, Trash2, RotateCcw, XCircle,
  CheckCircle2, AlertTriangle, Ban, Loader2, Clock, ChevronLeft,
  ChevronRight, AlertCircle, MessageSquareText,
} from "lucide-react";
import { scansApi, type Scan } from "@/api/scans";

// ── Status icon + label ────────────────────────────────────────────────────────

function StatusCell({ scan }: { scan: Scan }) {
  const hasFindings = (scan.findings_critical + scan.findings_high) > 0;
  const hasAny = (scan.findings_critical + scan.findings_high + scan.findings_medium + scan.findings_low + scan.findings_info) > 0;

  if (scan.status === "running") return (
    <span className="flex items-center gap-1.5 text-blue-600 text-xs font-medium">
      <Loader2 className="h-4 w-4 animate-spin shrink-0" />
      Running{scan.phase ? ` · ${scan.phase}` : ""}
    </span>
  );
  if (scan.status === "queued") return (
    <span className="flex items-center gap-1.5 text-indigo-600 text-xs font-medium">
      <Clock className="h-4 w-4 shrink-0" /> Queued
    </span>
  );
  if (scan.status === "failed") return (
    <span className="flex items-center gap-1.5 text-red-600 text-xs font-medium">
      <AlertCircle className="h-4 w-4 shrink-0" /> Failed
    </span>
  );
  if (scan.status === "cancelled") return (
    <span className="flex items-center gap-1.5 text-gray-500 text-xs font-medium">
      <Ban className="h-4 w-4 shrink-0" /> Cancelled
    </span>
  );
  // completed
  if (hasFindings) return (
    <span className="flex items-center gap-1.5 text-orange-500 text-xs font-medium">
      <AlertTriangle className="h-4 w-4 shrink-0" /> Completed
    </span>
  );
  if (hasAny) return (
    <span className="flex items-center gap-1.5 text-yellow-500 text-xs font-medium">
      <AlertTriangle className="h-4 w-4 shrink-0" /> Completed
    </span>
  );
  return (
    <span className="flex items-center gap-1.5 text-green-600 text-xs font-medium">
      <CheckCircle2 className="h-4 w-4 shrink-0" /> Completed
    </span>
  );
}

// ── Vulnerability circles ──────────────────────────────────────────────────────

function VulnCircles({ scan }: { scan: Scan }) {
  const pills = [
    { v: scan.findings_critical, bg: "bg-red-500",    title: "Critical" },
    { v: scan.findings_high,     bg: "bg-orange-400", title: "High" },
    { v: scan.findings_medium,   bg: "bg-yellow-400", title: "Medium" },
    { v: scan.findings_low,      bg: "bg-blue-400",   title: "Low" },
    { v: scan.findings_info,     bg: "bg-gray-400",   title: "Info" },
  ];
  return (
    <div className="flex items-center gap-1">
      {pills.map(({ v, bg, title }) => (
        <span
          key={title}
          title={`${title}: ${v}`}
          className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-white ${bg}`}
        >
          {v}
        </span>
      ))}
    </div>
  );
}

// ── Date formatter — force UTC parse so local timezone is applied correctly ────

function formatLastRun(dateStr: string | null): string {
  if (!dateStr) return "—";
  // Backend returns naive UTC strings (no Z). Append Z so JS parses as UTC
  // then toLocaleString converts to the browser's local timezone.
  const normalized = dateStr.endsWith("Z") || dateStr.includes("+") ? dateStr : dateStr + "Z";
  const d = new Date(normalized);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", year: "numeric",
    hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true,
  });
}

// ── Provider label + model ─────────────────────────────────────────────────────

const PROVIDER_LABEL: Record<string, string> = {
  openai: "OpenAI", anthropic: "Anthropic", ollama: "Ollama",
};

const PROVIDER_DEFAULT_MODEL: Record<string, string> = {
  openai: "gpt-4o",
  anthropic: "claude-sonnet-4-6",
  ollama: "default",
};

const PROVIDER_BADGE_COLOR: Record<string, string> = {
  openai:    "bg-green-50 text-green-700 border border-green-200",
  anthropic: "bg-orange-50 text-orange-700 border border-orange-200",
  ollama:    "bg-purple-50 text-purple-700 border border-purple-200",
};

function ScanProfileCell({ scan }: { scan: Scan }) {
  const provider = PROVIDER_LABEL[scan.llm_provider] ?? scan.llm_provider;
  const model = scan.llm_model || PROVIDER_DEFAULT_MODEL[scan.llm_provider] || "default";
  const isDefault = !scan.llm_model;
  const modeLabel = scan.scan_mode === "full" ? "Full Scan" : "Static Only";
  const badgeColor = PROVIDER_BADGE_COLOR[scan.llm_provider] ?? "bg-gray-100 text-gray-600 border border-gray-200";

  return (
    <div className="space-y-1.5 min-w-[160px]">
      {/* Scan mode */}
      <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded font-medium">{modeLabel}</span>

      {/* Provider badge + model */}
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${badgeColor}`}>
          {provider}
        </span>
        <span className={`text-xs font-mono truncate max-w-[130px] ${isDefault ? "text-gray-400 italic" : "text-gray-700"}`}
          title={model}>
          {model}
        </span>
      </div>

      {/* Config */}
      <div className="text-[10px] text-gray-400">
        {scan.max_hypotheses} hyp · {scan.max_parallel} workers · {scan.feedback_iter} iter
      </div>

      {/* Custom prompt indicator */}
      {scan.custom_prompt && (
        <div
          className="flex items-start gap-1 group relative cursor-default"
          title={scan.custom_prompt}
        >
          <MessageSquareText className="h-3 w-3 text-amber-500 shrink-0 mt-0.5" />
          <span className="text-[10px] text-amber-600 truncate max-w-[160px]">
            {scan.custom_prompt}
          </span>
        </div>
      )}
    </div>
  );
}

// ── Page size selector ────────────────────────────────────────────────────────

const PAGE_SIZES = [10, 20, 50];

// ── Main page ─────────────────────────────────────────────────────────────────

const STATUSES = ["", "queued", "running", "completed", "failed", "cancelled"];

export default function ScanListPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: allScans = [], isLoading, refetch } = useQuery({
    queryKey: ["scans", statusFilter],
    queryFn: () => scansApi.list({ status: statusFilter || undefined, limit: 200 }),
    refetchInterval: 5_000,
  });

  const filtered = useMemo(
    () => (statusFilter ? allScans.filter((s) => s.status === statusFilter) : allScans),
    [allScans, statusFilter],
  );
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageScans = filtered.slice((page - 1) * pageSize, page * pageSize);

  const deleteMutation = useMutation({
    mutationFn: scansApi.delete,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scans"] }); setSelected(new Set()); },
  });
  const rerunMutation = useMutation({
    mutationFn: scansApi.rerun,
    onSuccess: (scan) => { qc.invalidateQueries({ queryKey: ["scans"] }); navigate(`/scans/${scan.id}`); },
  });
  const cancelMutation = useMutation({
    mutationFn: scansApi.cancel,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });

  const allSelected = pageScans.length > 0 && pageScans.every((s) => selected.has(s.id));
  const toggleAll = () => {
    if (allSelected) {
      const next = new Set(selected);
      pageScans.forEach((s) => next.delete(s.id));
      setSelected(next);
    } else {
      const next = new Set(selected);
      pageScans.forEach((s) => next.add(s.id));
      setSelected(next);
    }
  };
  const toggleOne = (id: string) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    setSelected(next);
  };

  const deleteSelected = () => {
    if (!confirm(`Delete ${selected.size} selected scan(s)?`)) return;
    selected.forEach((id) => deleteMutation.mutate(id));
  };

  const start = filtered.length === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, filtered.length);

  return (
    <div className="space-y-4">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Scans</h1>
          <p className="text-xs text-gray-400 mt-0.5">Manage and monitor all penetration test scans</p>
        </div>
        <div className="flex items-center gap-2">
          {selected.size > 0 && (
            <button
              onClick={deleteSelected}
              className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg border border-red-200 text-red-600 hover:bg-red-50"
            >
              <Trash2 className="h-3.5 w-3.5" /> Delete ({selected.size})
            </button>
          )}
          <button
            onClick={() => refetch()}
            className="p-2 rounded-lg border border-border hover:bg-accent text-muted-foreground"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <button
            onClick={() => navigate("/scans/new")}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg"
          >
            <Plus className="h-4 w-4" /> New Scan
          </button>
        </div>
      </div>

      {/* ── Status filter ───────────────────────────────────────────────────── */}
      <div className="flex gap-2">
        {STATUSES.map((s) => (
          <button
            key={s}
            onClick={() => { setStatusFilter(s); setPage(1); }}
            className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
              statusFilter === s
                ? "bg-blue-600 text-white border-blue-600"
                : "border-border text-muted-foreground hover:bg-accent"
            }`}
          >
            {s || "All"}
          </button>
        ))}
      </div>

      {/* ── Table ───────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50/80">
              <th className="py-3 px-4 w-8">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={toggleAll}
                  className="rounded border-gray-300 accent-blue-600"
                />
              </th>
              <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 uppercase tracking-wide">Target</th>
              <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 uppercase tracking-wide">Target Description</th>
              <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 uppercase tracking-wide">Scan Profile</th>
              <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 uppercase tracking-wide">Schedule</th>
              <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 uppercase tracking-wide">Vulnerabilities</th>
              <th className="text-left py-3 px-4 text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
              <th className="text-right py-3 px-4 text-xs font-semibold text-gray-500 uppercase tracking-wide">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={8} className="py-12 text-center text-muted-foreground text-sm">
                  <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2 text-gray-300" />
                  Loading scans…
                </td>
              </tr>
            )}
            {!isLoading && pageScans.length === 0 && (
              <tr>
                <td colSpan={8} className="py-12 text-center text-muted-foreground text-sm">No scans found</td>
              </tr>
            )}
            {pageScans.map((scan) => {
              const isActive = scan.status === "queued" || scan.status === "running";
              return (
                <tr
                  key={scan.id}
                  onClick={() => navigate(`/scans/${scan.id}`)}
                  className={`border-b border-gray-50 last:border-0 hover:bg-blue-50/30 cursor-pointer transition-colors ${selected.has(scan.id) ? "bg-blue-50/40" : ""}`}
                >
                  {/* Checkbox */}
                  <td className="py-3.5 px-4" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selected.has(scan.id)}
                      onChange={() => toggleOne(scan.id)}
                      className="rounded border-gray-300 accent-blue-600"
                    />
                  </td>

                  {/* Target */}
                  <td className="py-3.5 px-4 max-w-[200px]">
                    <span className="text-blue-600 hover:underline text-sm font-medium truncate block">
                      {scan.target_url}
                    </span>
                  </td>

                  {/* Target description */}
                  <td className="py-3.5 px-4 max-w-[220px]">
                    {scan.target_description ? (
                      <span className="text-xs text-gray-500 truncate block" title={scan.target_description}>
                        {scan.target_description}
                      </span>
                    ) : (
                      <span className="text-xs text-gray-300">—</span>
                    )}
                  </td>

                  {/* Scan profile */}
                  <td className="py-3.5 px-4">
                    <ScanProfileCell scan={scan} />
                  </td>

                  {/* Schedule / last run */}
                  <td className="py-3.5 px-4">
                    <span className="text-xs text-gray-500 leading-snug">
                      Last run on<br />
                      <span className="text-gray-700 font-medium">{formatLastRun(scan.completed_at || scan.started_at || scan.created_at)}</span>
                    </span>
                  </td>

                  {/* Vulnerabilities */}
                  <td className="py-3.5 px-4">
                    <VulnCircles scan={scan} />
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-4 min-w-[120px]">
                    <StatusCell scan={scan} />
                  </td>

                  {/* Actions */}
                  <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1">
                      {!isActive && (
                        <button
                          onClick={() => rerunMutation.mutate(scan.id)}
                          title="Rerun scan"
                          className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg border border-gray-200 text-gray-600 hover:bg-blue-50 hover:border-blue-200 hover:text-blue-600 transition-colors"
                        >
                          <RotateCcw className="h-3 w-3" />
                          Rerun
                        </button>
                      )}
                      {isActive && (
                        <button
                          onClick={() => cancelMutation.mutate(scan.id)}
                          title="Cancel scan"
                          className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg border border-yellow-200 text-yellow-700 hover:bg-yellow-50 transition-colors"
                        >
                          <XCircle className="h-3 w-3" />
                          Cancel
                        </button>
                      )}
                      <button
                        onClick={() => { if (confirm("Delete this scan?")) deleteMutation.mutate(scan.id); }}
                        title="Delete scan"
                        className="flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg border border-gray-200 text-gray-600 hover:bg-red-50 hover:border-red-200 hover:text-red-600 transition-colors"
                      >
                        <Trash2 className="h-3 w-3" />
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* ── Pagination ──────────────────────────────────────────────────── */}
        {filtered.length > 0 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100 bg-gray-50/50">
            <span className="text-xs text-gray-500">
              {start} – {end} of {filtered.length}
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1.5 rounded-lg border border-gray-200 text-gray-500 hover:bg-white disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>

              {/* Page numbers */}
              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter((p) => p === 1 || p === totalPages || Math.abs(p - page) <= 1)
                .reduce<(number | "…")[]>((acc, p, i, arr) => {
                  if (i > 0 && p - (arr[i - 1] as number) > 1) acc.push("…");
                  acc.push(p);
                  return acc;
                }, [])
                .map((p, i) =>
                  p === "…" ? (
                    <span key={`ellipsis-${i}`} className="text-xs text-gray-400 px-1">…</span>
                  ) : (
                    <button
                      key={p}
                      onClick={() => setPage(p as number)}
                      className={`w-7 h-7 rounded-full text-xs font-semibold transition-colors ${
                        page === p
                          ? "bg-blue-600 text-white shadow-sm"
                          : "text-gray-600 hover:bg-gray-100"
                      }`}
                    >
                      {p}
                    </button>
                  )
                )}

              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-1.5 rounded-lg border border-gray-200 text-gray-500 hover:bg-white disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronRight className="h-4 w-4" />
              </button>

              <select
                value={pageSize}
                onChange={(e) => { setPageSize(+e.target.value); setPage(1); }}
                className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white text-gray-600 ml-2"
              >
                {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
