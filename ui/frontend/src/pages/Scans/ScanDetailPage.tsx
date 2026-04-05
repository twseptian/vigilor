import { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import {
  XCircle, RotateCcw, ChevronRight, Search, Code2,
  ShieldAlert, Zap, FileText, Check, ChevronDown, ChevronUp,
  Cpu, ScanLine, GitBranch, MessageSquareText, Clock, CheckCircle2,
  AlertTriangle, Ban, Timer, Download, Loader2, Trash2,
} from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { scansApi, type Scan } from "@/api/scans";
import { findingsApi, type Finding } from "@/api/findings";
import { createScanSocket, type WsMessage } from "@/lib/websocket";
import { STATUS_COLORS, SEVERITY_COLORS, formatDuration, relativeTime } from "@/lib/utils";
import api from "@/api/client";

const SEV_COLORS: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#d97706",
  Low: "#2563eb",
  Informational: "#6b7280",
};
const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

const STATUS_COLORS_CHART: Record<string, string> = {
  "Open":             "#dc2626",
  "Partially Resolved": "#2563eb",
  "Risk Accepted":    "#d97706",
  "Resolved":         "#16a34a",
  "Closed":           "#6b7280",
  "NA":               "#94a3b8",
};
const STATUS_ORDER = ["Open", "Partially Resolved", "Risk Accepted", "Resolved", "Closed", "NA"];

// ── Phase config ──────────────────────────────────────────────────────────────

const PHASE_CONFIG = [
  { key: "recon",           label: "Recon",           icon: Search,     desc: "Crawl & fingerprint" },
  { key: "static_analysis", label: "Static Analysis", icon: Code2,      desc: "Source & header checks" },
  { key: "vuln",            label: "Vuln Analysis",   icon: ShieldAlert, desc: "Hypothesis generation" },
  { key: "exploit",         label: "Exploit",         icon: Zap,        desc: "Automated exploitation" },
  { key: "report",          label: "Report",          icon: FileText,   desc: "Findings compilation" },
];

// ── Pie charts ────────────────────────────────────────────────────────────────

function MiniPieChart({
  data,
  colors,
  total,
  centerLabel,
}: {
  data: { name: string; value: number }[];
  colors: Record<string, string>;
  total: number;
  centerLabel: string;
}) {
  return (
    <div>
      <ResponsiveContainer width="100%" height={148}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={40} outerRadius={64}
            paddingAngle={2} dataKey="value" strokeWidth={0}>
            {data.map((entry) => <Cell key={entry.name} fill={colors[entry.name] ?? "#cbd5e1"} />)}
          </Pie>
          <Tooltip
            formatter={(v: number, n: string) => [`${v} (${Math.round((v / total) * 100)}%)`, n]}
            contentStyle={{ fontSize: "11px", borderRadius: "8px", border: "1px solid #e5e7eb", boxShadow: "0 4px 12px rgba(0,0,0,0.08)" }}
          />
          <text x="50%" y="44%" textAnchor="middle" dominantBaseline="middle"
            style={{ fontSize: 20, fontWeight: 700, fill: "#111827" }}>{total}</text>
          <text x="50%" y="60%" textAnchor="middle" dominantBaseline="middle"
            style={{ fontSize: 9, fill: "#9ca3af" }}>{centerLabel}</text>
        </PieChart>
      </ResponsiveContainer>
      <div className="mt-1 space-y-1">
        {data.map((entry) => (
          <div key={entry.name} className="flex items-center justify-between text-[11px]">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: colors[entry.name] ?? "#cbd5e1" }} />
              <span className="text-muted-foreground truncate max-w-[110px]">{entry.name}</span>
            </div>
            <div className="flex items-center gap-1.5 font-medium shrink-0">
              <span>{entry.value}</span>
              <span className="text-muted-foreground w-7 text-right">{Math.round((entry.value / total) * 100)}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsOverviewCard({ findings }: { findings: Finding[] }) {
  const [tab, setTab] = useState<"severity" | "status">("severity");
  const total = findings.length;

  const sevData = SEV_ORDER
    .map((s) => ({ name: s, value: findings.filter((f) => f.severity === s).length }))
    .filter((d) => d.value > 0);

  const statusData = STATUS_ORDER
    .map((s) => ({ name: s, value: findings.filter((f) => f.status === s).length }))
    .filter((d) => d.value > 0);

  const critical = findings.filter((f) => f.severity === "Critical").length;
  const high     = findings.filter((f) => f.severity === "High").length;
  const open     = findings.filter((f) => f.status === "Open").length;

  return (
    <div className="bg-white border border-border rounded-xl overflow-hidden">
      {/* Summary metrics */}
      <div className="grid grid-cols-3 divide-x divide-border border-b border-border">
        <div className="px-3 py-2.5 text-center">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Total</p>
          <p className="text-xl font-bold text-gray-900">{total}</p>
        </div>
        <div className="px-3 py-2.5 text-center">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Critical/High</p>
          <p className="text-xl font-bold text-red-600">{critical + high}</p>
        </div>
        <div className="px-3 py-2.5 text-center">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Open</p>
          <p className="text-xl font-bold text-orange-600">{open}</p>
        </div>
      </div>

      {/* Tab toggle */}
      <div className="flex border-b border-border bg-muted/20">
        {(["severity", "status"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`flex-1 py-2 text-xs font-medium transition-colors ${
              tab === t
                ? "text-blue-600 border-b-2 border-blue-500 bg-white"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t === "severity" ? "By Severity" : "By Status"}
          </button>
        ))}
      </div>

      <div className="p-3">
        {total === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-4">No findings yet</p>
        ) : tab === "severity" ? (
          <MiniPieChart data={sevData} colors={SEV_COLORS} total={total} centerLabel="findings" />
        ) : (
          <MiniPieChart data={statusData} colors={STATUS_COLORS_CHART} total={total} centerLabel="findings" />
        )}
      </div>
    </div>
  );
}

// ── Scan info card ────────────────────────────────────────────────────────────

function ScanInfoCard({ scan }: { scan: Scan }) {
  const [promptOpen, setPromptOpen] = useState(false);

  const providerMeta: Record<string, { label: string; color: string; desc: string }> = {
    openai:    { label: "OpenAI",    color: "text-green-600",  desc: "GPT model via OpenAI API" },
    anthropic: { label: "Anthropic", color: "text-orange-600", desc: "Claude model via Anthropic API" },
    ollama:    { label: "Ollama",    color: "text-purple-600", desc: "Local self-hosted LLM via Ollama" },
  };
  const pm = providerMeta[scan.llm_provider] ?? { label: scan.llm_provider, color: "text-gray-700", desc: "Language model provider" };
  const modelName = scan.llm_model || (scan.llm_provider === "openai" ? "gpt-4o" : scan.llm_provider === "anthropic" ? "claude-sonnet-4-6" : "default");

  return (
    <div className="bg-white border border-border rounded-xl overflow-hidden">
      <div className="grid grid-cols-2 md:grid-cols-4 divide-x divide-border border-b border-border">

        {/* ── AI Provider ─────────────────────────────────────────────── */}
        <div className="px-4 py-3 flex items-start gap-3">
          <Cpu className="h-4 w-4 text-blue-500 mt-0.5 shrink-0" />
          <div className="min-w-0">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">AI Provider</p>
            <p className={`text-sm font-bold truncate ${pm.color}`}>{pm.label}</p>
            <p className="text-xs text-muted-foreground font-mono truncate">{modelName}</p>
            <p className="text-[10px] text-muted-foreground/60 mt-0.5">{pm.desc}</p>
          </div>
        </div>

        {/* ── Attack Strategy ──────────────────────────────────────────── */}
        <div className="px-4 py-3 flex items-start gap-3">
          <ScanLine className="h-4 w-4 text-indigo-500 mt-0.5 shrink-0" />
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">Attack Strategy</p>
            <p className="text-sm font-semibold">{scan.scan_mode === "full" ? "Full Scan" : "Static Only"}</p>
            <p className="text-[10px] text-muted-foreground/60 mt-0.5">
              {scan.scan_mode === "full"
                ? "Crawl → analyze → actively exploit"
                : "Header & source code review only"}
            </p>
          </div>
        </div>

        {/* ── Agent Configuration ───────────────────────────────────────── */}
        <div className="px-4 py-3 flex items-start gap-3">
          <GitBranch className="h-4 w-4 text-violet-500 mt-0.5 shrink-0" />
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">Agent Config</p>
            <p className="text-sm font-semibold">{scan.max_hypotheses} hypotheses</p>
            <p className="text-xs text-muted-foreground">{scan.max_parallel} workers · {scan.feedback_iter} iter</p>
            <p className="text-[10px] text-muted-foreground/60 mt-0.5">Parallel exploits · feedback refinement</p>
          </div>
        </div>

        {/* ── Context Prompt ────────────────────────────────────────────── */}
        <div className="px-4 py-3 flex items-start gap-3">
          <MessageSquareText className={`h-4 w-4 mt-0.5 shrink-0 ${scan.custom_prompt ? "text-amber-500" : "text-muted-foreground/40"}`} />
          <div className="min-w-0">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">Context Prompt</p>
            {scan.custom_prompt ? (
              <>
                <button
                  onClick={() => setPromptOpen(!promptOpen)}
                  className="text-sm font-semibold text-amber-600 hover:underline flex items-center gap-1"
                >
                  Active {promptOpen ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </button>
                <p className="text-[10px] text-muted-foreground/60 mt-0.5 truncate max-w-[160px]" title={scan.custom_prompt}>
                  {scan.custom_prompt.slice(0, 60)}{scan.custom_prompt.length > 60 ? "…" : ""}
                </p>
              </>
            ) : (
              <>
                <p className="text-sm text-muted-foreground">Not set</p>
                <p className="text-[10px] text-muted-foreground/60 mt-0.5">No operator context added</p>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Context prompt expanded */}
      {scan.custom_prompt && promptOpen && (
        <div className="px-4 py-3 bg-amber-50 border-t border-amber-100">
          <p className="text-[10px] text-amber-700 font-semibold uppercase tracking-wide mb-1.5">Operator Context</p>
          <p className="text-xs font-mono text-amber-800 whitespace-pre-wrap leading-relaxed">
            {scan.custom_prompt}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Phase stepper ─────────────────────────────────────────────────────────────

function PhaseStepper({ scan }: { scan: Scan }) {
  // Normalize feedback loop phases e.g. "exploit:feedback_1" → "exploit"
  const normalizedPhase = scan.phase?.split(":")[0] ?? "";
  const phaseIdx = PHASE_CONFIG.findIndex((p) => p.key === normalizedPhase);
  const isCompleted = scan.status === "completed";
  const isFailed = scan.status === "failed";

  return (
    <div className="bg-white border border-border rounded-xl px-6 py-5">
      <div className="relative flex items-start justify-between">
        {/* Connector line */}
        <div className="absolute top-5 left-0 right-0 h-0.5 bg-border mx-[10%]" />
        <div
          className="absolute top-5 left-0 h-0.5 bg-blue-500 mx-[10%] transition-all duration-700"
          style={{
            width: isCompleted
              ? "80%"
              : phaseIdx <= 0
              ? "0%"
              : `${(phaseIdx / (PHASE_CONFIG.length - 1)) * 80}%`,
          }}
        />

        {PHASE_CONFIG.map((phase, i) => {
          const done = isCompleted || phaseIdx > i;
          const active = !isCompleted && phaseIdx === i && scan.status === "running";
          const failed = isFailed && phaseIdx === i;
          const Icon = phase.icon;

          return (
            <div key={phase.key} className="relative flex flex-col items-center gap-2 flex-1 z-10">
              {/* Circle */}
              <div className={`
                w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all duration-300
                ${done
                  ? "bg-blue-600 border-blue-600 text-white"
                  : active
                  ? "bg-white border-blue-500 text-blue-600 shadow-[0_0_0_4px_rgba(59,130,246,0.15)]"
                  : failed
                  ? "bg-red-50 border-red-400 text-red-500"
                  : "bg-white border-border text-muted-foreground/40"
                }
              `}>
                {active ? (
                  <div className="relative flex items-center justify-center">
                    <div className="absolute w-10 h-10 rounded-full bg-blue-500/20 animate-ping" />
                    <Icon className="h-4 w-4 relative z-10" />
                  </div>
                ) : done ? (
                  <Check className="h-4 w-4" />
                ) : (
                  <Icon className="h-4 w-4" />
                )}
              </div>

              {/* Label */}
              <div className="text-center">
                <p className={`text-xs font-semibold ${
                  done ? "text-blue-700" :
                  active ? "text-blue-600" :
                  "text-muted-foreground"
                }`}>
                  {phase.label}
                </p>
                <p className="text-[10px] text-muted-foreground/70 hidden sm:block">{phase.desc}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Status bar */}
      {scan.status === "running" && scan.phase && (
        <div className="mt-4 pt-3 border-t border-border flex items-center gap-2 text-xs text-blue-600">
          <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
          <span>
            Running <span className="font-semibold">
              {PHASE_CONFIG.find(p => p.key === normalizedPhase)?.label ?? normalizedPhase}
            </span>
            {scan.phase?.includes(":feedback_") && (
              <span className="text-blue-400 ml-1">
                (Feedback loop {scan.phase.split("_")[1]})
              </span>
            )}
            {scan.phase_detail && <span className="text-muted-foreground ml-1">— {scan.phase_detail}</span>}
          </span>
        </div>
      )}
      {scan.status === "completed" && (
        <div className="mt-4 pt-3 border-t border-border flex items-center gap-2 text-xs text-green-600">
          <Check className="h-3.5 w-3.5" />
          <span className="font-semibold">Scan completed</span>
          {scan.duration_seconds && (
            <span className="text-muted-foreground">in {formatDuration(scan.duration_seconds)}</span>
          )}
        </div>
      )}
      {scan.status === "failed" && (
        <div className="mt-4 pt-3 border-t border-border flex items-center gap-2 text-xs text-red-600">
          <XCircle className="h-3.5 w-3.5" />
          <span className="font-semibold">Scan failed</span>
          {scan.error_message && (
            <span className="text-muted-foreground truncate max-w-md">— {scan.error_message}</span>
          )}
        </div>
      )}
    </div>
  );
}

// ── Report Section ────────────────────────────────────────────────────────────

interface ReportOut {
  id: string;
  scan_id: string;
  format: string;
  file_size_kb: number | null;
  generated_by: string;
  generated_at: string;
}

function ReportSection({ scanId }: { scanId: string }) {
  const qc = useQueryClient();

  const { data: reports = [], isLoading } = useQuery<ReportOut[]>({
    queryKey: ["reports", scanId],
    queryFn: () => api.get(`/scans/${scanId}/reports`).then((r) => r.data),
  });

  const generate = useMutation({
    mutationFn: () =>
      api.post(`/scans/${scanId}/reports`, { format: "docx" }).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports", scanId] }),
  });

  const deleteReport = useMutation({
    mutationFn: (reportId: string) => api.delete(`/reports/${reportId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports", scanId] }),
  });

  const downloadReport = (report: ReportOut) => {
    const token = localStorage.getItem("access_token");
    fetch(`/api/v1/reports/${report.id}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((r) => {
        if (!r.ok) throw new Error("Download failed");
        return r.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `pentest_report_${report.generated_at.slice(0, 10)}.docx`;
        a.click();
        URL.revokeObjectURL(url);
      });
  };

  const fmt = (dt: string) =>
    new Date(dt).toLocaleString("en-GB", {
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });

  return (
    <div className="bg-white border border-border rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div>
          <p className="font-semibold text-sm flex items-center gap-2">
            <FileText className="h-4 w-4 text-blue-500" /> Reports
          </p>
          <p className="text-xs text-muted-foreground mt-0.5">Generate and download the vulnerability assessment report (DOCX)</p>
        </div>
        <button
          onClick={() => generate.mutate()}
          disabled={generate.isPending}
          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {generate.isPending
            ? <Loader2 className="h-3 w-3 animate-spin" />
            : <FileText className="h-3 w-3" />}
          Generate Report
        </button>
      </div>

      {generate.isPending && (
        <div className="px-4 py-3 bg-blue-50 border-b border-blue-100 flex items-center gap-2 text-xs text-blue-700">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Generating report… this may take a few minutes.
        </div>
      )}

      {generate.isError && (
        <div className="px-4 py-3 bg-red-50 border-b border-red-100 text-xs text-red-700">
          Generation failed: {(generate.error as any)?.response?.data?.detail ?? "Unknown error"}
        </div>
      )}

      {isLoading ? (
        <div className="px-4 py-4 text-xs text-muted-foreground">Loading reports…</div>
      ) : reports.length === 0 ? (
        <div className="px-4 py-6 text-center text-sm text-muted-foreground">
          No reports generated yet. Click "Generate Report" to create one.
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20">
              <th className="text-left py-2 px-4 text-muted-foreground font-medium text-xs">Format</th>
              <th className="text-left py-2 px-4 text-muted-foreground font-medium text-xs">Generated</th>
              <th className="text-left py-2 px-4 text-muted-foreground font-medium text-xs">Size</th>
              <th className="py-2 px-4" />
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id} className="border-b border-border/50 last:border-0 hover:bg-accent/20">
                <td className="py-2.5 px-4">
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-600 border border-blue-200">
                    <FileText className="h-3 w-3" /> DOCX
                  </span>
                </td>
                <td className="py-2.5 px-4 text-xs text-muted-foreground">{fmt(r.generated_at)}</td>
                <td className="py-2.5 px-4 text-xs text-muted-foreground">
                  {r.file_size_kb ? `${r.file_size_kb} KB` : "—"}
                </td>
                <td className="py-2.5 px-4 text-right">
                  <div className="flex items-center gap-2 justify-end">
                    <button
                      onClick={() => downloadReport(r)}
                      className="flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent"
                    >
                      <Download className="h-3 w-3" /> Download
                    </button>
                    <button
                      onClick={() => deleteReport.mutate(r.id)}
                      disabled={deleteReport.isPending}
                      className="flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg border border-red-200 text-red-600 hover:bg-red-50 disabled:opacity-50"
                    >
                      <Trash2 className="h-3 w-3" /> Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const logEndRef = useRef<HTMLDivElement>(null);
  const [liveLogs, setLiveLogs] = useState<{ level: string; phase: string; message: string; ts: string }[]>([]);

  const { data: scan, refetch: refetchScan } = useQuery<Scan>({
    queryKey: ["scan", id],
    queryFn: () => scansApi.get(id!),
    refetchInterval: (query) => {
      const data = query.state.data as Scan | undefined;
      return data?.status === "running" ? 3_000 : false;
    },
  });

  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: ["findings", id],
    queryFn: () => findingsApi.list({ scan_id: id! }),
    enabled: !!id,
  });

  useEffect(() => {
    if (!id || !scan || !["queued", "running"].includes(scan.status)) return;
    const ws = createScanSocket(id, (msg: WsMessage) => {
      if (msg.type === "log") {
        setLiveLogs((prev) => [...prev.slice(-499), { ...msg, ts: new Date().toISOString() }]);
        logEndRef.current?.scrollIntoView({ behavior: "smooth" });
      }
      if (msg.type === "scan_complete" || msg.type === "scan_error") {
        qc.invalidateQueries({ queryKey: ["scan", id] });
        qc.invalidateQueries({ queryKey: ["findings", id] });
      }
    });
    return () => ws.close();
  }, [id, scan?.status]);

  if (!scan) return <div className="text-muted-foreground">Loading...</div>;

  return (
    <div className="space-y-4">

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
            <a href="/scans" className="hover:underline">Scans</a>
            <ChevronRight className="h-3.5 w-3.5" />
            <span className="truncate max-w-xs">{scan.target_url}</span>
          </div>
          <h1 className="text-xl font-bold truncate max-w-xl">{scan.target_url}</h1>
          {scan.target_description && (
            <p className="text-sm text-muted-foreground mt-1 max-w-xl">{scan.target_description}</p>
          )}
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${STATUS_COLORS[scan.status]}`}>
              {scan.status}
            </span>

            {/* Running */}
            {scan.status === "running" && scan.started_at && (
              <span className="flex items-center gap-1.5 text-xs text-blue-600">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
                Running · started {relativeTime(scan.started_at)}
              </span>
            )}

            {/* Completed */}
            {scan.status === "completed" && (
              <span className="flex items-center gap-1.5 text-xs text-green-600">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Completed {scan.completed_at ? relativeTime(scan.completed_at) : ""}
                {scan.duration_seconds != null && (
                  <span className="flex items-center gap-1 text-muted-foreground ml-1">
                    <Timer className="h-3 w-3" />
                    {formatDuration(scan.duration_seconds)}
                  </span>
                )}
              </span>
            )}

            {/* Failed */}
            {scan.status === "failed" && (
              <span className="flex items-center gap-1.5 text-xs text-red-600">
                <AlertTriangle className="h-3.5 w-3.5" />
                Failed {scan.completed_at ? relativeTime(scan.completed_at) : ""}
                {scan.started_at && (
                  <span className="text-muted-foreground ml-1">· started {relativeTime(scan.started_at)}</span>
                )}
              </span>
            )}

            {/* Cancelled */}
            {scan.status === "cancelled" && (
              <span className="flex items-center gap-1.5 text-xs text-yellow-600">
                <Ban className="h-3.5 w-3.5" />
                Cancelled {scan.completed_at ? relativeTime(scan.completed_at) : ""}
              </span>
            )}

            {/* Queued */}
            {scan.status === "queued" && scan.created_at && (
              <span className="flex items-center gap-1.5 text-xs text-indigo-600">
                <Clock className="h-3.5 w-3.5" />
                Queued {relativeTime(scan.created_at)}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {scan.status === "running" && (
            <button
              onClick={() => scansApi.cancel(scan.id).then(() => refetchScan())}
              className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-lg border border-border hover:bg-red-50 hover:border-red-200 hover:text-red-600"
            >
              <XCircle className="h-4 w-4" /> Cancel
            </button>
          )}
          {["completed", "failed", "cancelled"].includes(scan.status) && (
            <button
              onClick={() => scansApi.rerun(scan.id).then((s) => navigate(`/scans/${s.id}`))}
              className="flex items-center gap-1.5 text-sm px-3 py-2 rounded-lg border border-border hover:bg-accent"
            >
              <RotateCcw className="h-4 w-4" /> Rerun
            </button>
          )}
        </div>
      </div>

      {/* ── Scan Info Card ───────────────────────────────────────────────── */}
      <ScanInfoCard scan={scan} />

      {/* ── Phase Stepper ────────────────────────────────────────────────── */}
      <PhaseStepper scan={scan} />

      {/* ── Log + Stats ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Live log */}
        <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-xl p-4">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                Scan Log
                {scan.status === "running" && (
                  <span className="flex items-center gap-1.5 text-xs text-blue-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                    Live
                  </span>
                )}
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">Real-time output from the scanning engine</p>
            </div>
          </div>
          <div className="log-panel h-64 overflow-y-auto font-mono text-xs space-y-0.5">
            {liveLogs.map((log, i) => (
              <div key={i} className={`${
                log.level === "ERROR" ? "text-red-400" :
                log.level === "WARN" ? "text-yellow-400" :
                log.message.includes("[+]") ? "text-green-400" :
                log.message.includes("[*]") ? "text-blue-300" :
                "text-slate-400"
              }`}>
                <span className="text-slate-600 select-none">[{log.phase}] </span>
                {log.message}
              </div>
            ))}
            {liveLogs.length === 0 && (
              <div className="text-slate-600">
                {scan.status === "running" ? "Waiting for log output..." : "No live logs."}
              </div>
            )}
            <div ref={logEndRef} />
          </div>
        </div>

        {/* Stats sidebar */}
        <div className="space-y-3">
          {/* Findings overview with severity + status charts */}
          <FindingsOverviewCard findings={findings} />

          {/* Hypotheses */}
          <div className="bg-white border border-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center gap-2">
              <Zap className="h-4 w-4 text-violet-500" />
              <div>
                <h2 className="text-sm font-semibold leading-none">Hypotheses</h2>
                <p className="text-[10px] text-muted-foreground mt-0.5">Attack vectors evaluated</p>
              </div>
            </div>
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-muted/30 rounded-lg p-2.5 text-center">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Total</p>
                  <p className="text-lg font-bold">{scan.hypotheses_total}</p>
                </div>
                <div className="bg-green-50 rounded-lg p-2.5 text-center">
                  <p className="text-[10px] text-green-600 uppercase tracking-wide">Confirmed</p>
                  <p className="text-lg font-bold text-green-700">{scan.hypotheses_confirmed}</p>
                </div>
              </div>
              {scan.hypotheses_total > 0 && (
                <div>
                  <div className="flex justify-between text-[10px] text-muted-foreground mb-1">
                    <span>Confirmation rate</span>
                    <span className="font-medium text-foreground">
                      {Math.round((scan.hypotheses_confirmed / scan.hypotheses_total) * 100)}%
                    </span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-green-400 to-green-600 rounded-full transition-all duration-700"
                      style={{ width: `${Math.round((scan.hypotheses_confirmed / scan.hypotheses_total) * 100)}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Findings table ────────────────────────────────────────────────── */}
      {findings.length > 0 && (
        <div className="bg-white border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <div>
              <p className="font-semibold text-sm flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-500" />
                Findings
                <span className="text-xs font-normal text-muted-foreground bg-muted px-2 py-0.5 rounded-full">
                  {findings.length}
                </span>
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">Click a finding to view details, evidence, and remediation steps</p>
            </div>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-gradient-to-r from-muted/30 to-muted/10">
                <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Ref</th>
                <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Title</th>
                <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Severity</th>
                <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Location</th>
                <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id} onClick={() => navigate(`/findings/${f.id}`)}
                  className="border-b border-border/40 last:border-0 hover:bg-blue-50/40 cursor-pointer transition-colors group">
                  <td className="py-3 px-4 text-muted-foreground font-mono text-xs">{f.finding_ref || "—"}</td>
                  <td className="py-3 px-4 font-medium group-hover:text-blue-700 transition-colors">{f.title}</td>
                  <td className="py-3 px-4">
                    <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold ${SEVERITY_COLORS[f.severity]}`}>{f.severity}</span>
                  </td>
                  <td className="py-3 px-4 text-muted-foreground text-xs truncate max-w-xs font-mono">{f.location || "—"}</td>
                  <td className="py-3 px-4">
                    <span className="text-xs px-2 py-0.5 rounded-full font-medium"
                      style={{
                        backgroundColor: (STATUS_COLORS_CHART[f.status] ?? "#6b7280") + "1a",
                        color: STATUS_COLORS_CHART[f.status] ?? "#6b7280",
                        border: `1px solid ${(STATUS_COLORS_CHART[f.status] ?? "#6b7280")}40`,
                      }}>
                      {f.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Reports ───────────────────────────────────────────────────────── */}
      {["completed", "failed"].includes(scan.status) && (
        <ReportSection scanId={scan.id} />
      )}
    </div>
  );
}
