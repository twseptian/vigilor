import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  LineChart, Line,
} from "recharts";
import { Activity, Shield, Target, Clock, TrendingUp } from "lucide-react";
import api from "@/api/client";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Stats {
  active_scans: number;
  queued_scans: number;
  total_scans: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  informational_findings: number;
  scans_this_week: number;
  total_targets: number;
}

interface VulnTarget {
  target_url: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface TopVuln {
  title: string;
  severity: string;
  count: number;
}

interface TrendPoint {
  month: string;
  high: number;
  medium: number;
}

interface RemediationPoint {
  month: string;
  avg_days: number;
  high_fixed: number;
  medium_fixed: number;
}

interface ScanStatusPoint {
  status: string;
  count: number;
}

interface FindingsStatusPoint {
  status: string;
  count: number;
}

// ── Severity ring card ─────────────────────────────────────────────────────────

const RING_SEVERITIES = [
  { key: "critical_findings",      title: "Critical",      label: "Severity Vulnerabilities", color: "#ef4444", bg: "from-red-50",    border: "border-red-100"   },
  { key: "high_findings",          title: "High",          label: "Severity Vulnerabilities", color: "#f97316", bg: "from-orange-50", border: "border-orange-100" },
  { key: "medium_findings",        title: "Medium",        label: "Severity Vulnerabilities", color: "#eab308", bg: "from-yellow-50", border: "border-yellow-100" },
  { key: "low_findings",           title: "Low",           label: "Severity Vulnerabilities", color: "#60a5fa", bg: "from-blue-50",   border: "border-blue-100"   },
  { key: "informational_findings", title: "Informational", label: "Severity Vulnerabilities", color: "#9ca3af", bg: "from-gray-50",   border: "border-gray-100"   },
];

function SeverityRing({ count, color, title, bg, border }: { count: number; color: string; title: string; label: string; bg: string; border: string }) {
  return (
    <div className={`flex flex-col items-center gap-2 py-6 px-4 bg-gradient-to-b ${bg} to-white transition-all hover:scale-[1.02] cursor-default`}>
      <div className="relative w-24 h-24">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={count > 0
                ? [{ value: 1, fill: color }, { value: 0.12, fill: `${color}18` }]
                : [{ value: 1, fill: "#f3f4f6" }]}
              cx="50%" cy="50%"
              innerRadius={34} outerRadius={44}
              startAngle={90} endAngle={-270}
              dataKey="value" strokeWidth={0}
            >
              {(count > 0 ? [color, `${color}18`] : ["#f3f4f6"]).map((c, i) => (
                <Cell key={i} fill={c} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-black leading-none tabular-nums" style={{ color: count > 0 ? color : "#d1d5db" }}>
            {count}
          </span>
        </div>
      </div>
      <div className="text-center">
        <p className="text-xs font-bold uppercase tracking-widest" style={{ color: count > 0 ? color : "#9ca3af" }}>{title}</p>
      </div>
    </div>
  );
}

// ── Severity badge ─────────────────────────────────────────────────────────────

const SEV_BADGE: Record<string, string> = {
  Critical:      "bg-red-100 text-red-700 border border-red-200",
  High:          "bg-orange-100 text-orange-700 border border-orange-200",
  Medium:        "bg-yellow-100 text-yellow-700 border border-yellow-200",
  Low:           "bg-blue-100 text-blue-700 border border-blue-200",
  Informational: "bg-gray-100 text-gray-600 border border-gray-200",
};

function SevBadge({ severity }: { severity: string }) {
  return (
    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full shrink-0 ${SEV_BADGE[severity] ?? SEV_BADGE.Informational}`}>
      {severity === "Informational" ? "Info" : severity}
    </span>
  );
}

// ── Target severity pills ──────────────────────────────────────────────────────

function SevPills({ c, h, m, l, i }: { c: number; h: number; m: number; l: number; i: number }) {
  return (
    <div className="flex items-center gap-1">
      {[
        { v: c, color: "bg-red-500",    title: "Critical" },
        { v: h, color: "bg-orange-400", title: "High" },
        { v: m, color: "bg-yellow-400", title: "Medium" },
        { v: l, color: "bg-blue-400",   title: "Low" },
        { v: i, color: "bg-gray-400",   title: "Info" },
      ].map(({ v, color, title }, idx) => (
        <span
          key={idx}
          title={`${title}: ${v}`}
          className={`text-[10px] font-bold text-white w-5 h-5 rounded-full flex items-center justify-center shadow-sm ${color}`}
        >
          {v}
        </span>
      ))}
    </div>
  );
}

// ── Empty chart state ─────────────────────────────────────────────────────────

function EmptyChart({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-[200px] text-center">
      <div className="w-12 h-12 rounded-full bg-gray-100 flex items-center justify-center mb-3">
        <TrendingUp className="h-5 w-5 text-gray-400" />
      </div>
      <p className="text-sm text-gray-600 font-medium">No data yet</p>
      <p className="text-xs text-gray-500 mt-1 max-w-[200px] leading-relaxed">{message}</p>
    </div>
  );
}

// ── Chart card wrapper ────────────────────────────────────────────────────────

function ChartCard({ title, subtitle, accentColor, badge, children }: {
  title: string;
  subtitle: string;
  accentColor: string;
  badge?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
      <div className="h-1 w-full" style={{ background: `linear-gradient(90deg, ${accentColor}, ${accentColor}55)` }} />
      <div className="px-5 pt-4 pb-3 border-b border-gray-50 flex items-start justify-between">
        <div>
          <h2 className="text-sm font-semibold text-gray-800 flex items-center gap-2">
            {title}
            {badge && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-gray-100 text-gray-500 uppercase tracking-wide">
                {badge}
              </span>
            )}
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">{subtitle}</p>
        </div>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

// ── Donut chart (shared) ──────────────────────────────────────────────────────

function DonutChart({
  data, unitLabel, tooltip,
}: {
  data: { status: string; count: number; name: string; fill: string }[];
  unitLabel: string;
  tooltip: string;
}) {
  const total = data.reduce((s, d) => s + d.count, 0);
  return (
    <div className="flex items-center gap-6">
      <div className="relative shrink-0 w-44 h-44">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={total > 0 ? data : [{ name: "No data", fill: "#f1f5f9", count: 1 } as any]}
              cx="50%" cy="50%"
              innerRadius={52} outerRadius={76}
              dataKey="count" strokeWidth={3} stroke="#fff"
            >
              {(total > 0 ? data : [{ fill: "#f1f5f9" }]).map((d, i) => (
                <Cell key={i} fill={(d as any).fill} />
              ))}
            </Pie>
            <Tooltip
              formatter={(val: number, name: string) => [`${val} ${tooltip}`, name]}
              contentStyle={{ fontSize: 12, borderRadius: 10, border: "none", boxShadow: "0 4px 20px rgba(0,0,0,0.08)" }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-2xl font-extrabold text-gray-700">{total}</span>
          <span className="text-[10px] text-gray-400 uppercase tracking-wide">{unitLabel}</span>
        </div>
      </div>
      <div className="flex-1 space-y-2.5">
        {data.map((d) => {
          const pct = total > 0 ? Math.round((d.count / total) * 100) : 0;
          return (
            <div key={d.status} className="flex items-center gap-3">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.fill }} />
              <span className="text-xs text-gray-600 w-24 truncate">{d.name}</span>
              <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{ width: `${pct}%`, background: `linear-gradient(to right, ${d.fill}, ${d.fill}bb)` }}
                />
              </div>
              <span className="text-xs font-semibold text-gray-700 w-5 text-right">{d.count}</span>
              <span className="text-[10px] text-gray-400 w-7 text-right">{pct}%</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Scan Status Chart ─────────────────────────────────────────────────────────

const SCAN_STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  queued:    { label: "Queued",    color: "#6366f1" },
  running:   { label: "Running",   color: "#3b82f6" },
  completed: { label: "Completed", color: "#22c55e" },
  failed:    { label: "Failed",    color: "#ef4444" },
  cancelled: { label: "Cancelled", color: "#9ca3af" },
};

function ScanStatusChart({ data }: { data: ScanStatusPoint[] }) {
  const chartData = data.map((d) => ({
    ...d,
    name: SCAN_STATUS_CONFIG[d.status]?.label ?? d.status,
    fill: SCAN_STATUS_CONFIG[d.status]?.color ?? "#94a3b8",
  }));
  return <DonutChart data={chartData} unitLabel="Total" tooltip="scans" />;
}

// ── Findings Status Chart ────────────────────────────────────────────────────

const FINDINGS_STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  "Open":               { label: "Open",               color: "#dc2626" },
  "Partially Resolved": { label: "Partially Resolved", color: "#2563eb" },
  "Risk Accepted":      { label: "Risk Accepted",      color: "#d97706" },
  "Resolved":           { label: "Resolved",           color: "#16a34a" },
  "Closed":             { label: "Closed",             color: "#6b7280" },
  "NA":                 { label: "N/A",                color: "#94a3b8" },
};

function FindingsStatusChart({ data }: { data: FindingsStatusPoint[] }) {
  const chartData = data.map((d) => ({
    ...d,
    name: FINDINGS_STATUS_CONFIG[d.status]?.label ?? d.status,
    fill: FINDINGS_STATUS_CONFIG[d.status]?.color ?? "#94a3b8",
  }));
  return <DonutChart data={chartData} unitLabel="Total" tooltip="findings" />;
}

// ── Tooltip shared style ───────────────────────────────────────────────────────
const tooltipStyle = { fontSize: 12, borderRadius: 10, border: "none", boxShadow: "0 4px 20px rgba(0,0,0,0.08)" };

// ── Dashboard ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const navigate = useNavigate();

  const { data: stats } = useQuery<Stats>({
    queryKey: ["dashboard-stats"],
    queryFn: () => api.get("/dashboard/stats").then((r) => r.data),
    refetchInterval: 10_000,
  });

  const { data: targets = [] } = useQuery<VulnTarget[]>({
    queryKey: ["dashboard-targets"],
    queryFn: () => api.get("/dashboard/most-vulnerable-targets").then((r) => r.data),
    refetchInterval: 15_000,
  });

  const { data: topVulns = [] } = useQuery<TopVuln[]>({
    queryKey: ["dashboard-top-vulns"],
    queryFn: () => api.get("/dashboard/top-vulnerabilities").then((r) => r.data),
    refetchInterval: 15_000,
  });

  const { data: vulnTrend = [] } = useQuery<TrendPoint[]>({
    queryKey: ["dashboard-vuln-trend"],
    queryFn: () => api.get("/dashboard/vuln-trend").then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: vulnPerTarget = [] } = useQuery<TrendPoint[]>({
    queryKey: ["dashboard-vuln-per-target"],
    queryFn: () => api.get("/dashboard/vuln-per-target").then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: remediationTrend = [] } = useQuery<RemediationPoint[]>({
    queryKey: ["dashboard-remediation-trend"],
    queryFn: () => api.get("/dashboard/remediation-trend").then((r) => r.data),
    refetchInterval: 30_000,
  });

  const { data: scanStatus = [] } = useQuery<ScanStatusPoint[]>({
    queryKey: ["dashboard-scan-status"],
    queryFn: () => api.get("/dashboard/scan-status").then((r) => r.data),
    refetchInterval: 10_000,
  });

  const { data: findingsStatus = [] } = useQuery<FindingsStatusPoint[]>({
    queryKey: ["dashboard-findings-status"],
    queryFn: () => api.get("/dashboard/findings-status").then((r) => r.data),
    refetchInterval: 15_000,
  });

  const s = stats;

  return (
    <div className="space-y-5 pb-6">

      {/* ── Row 1: Severity Overview ─────────────────────────────────────────── */}
      <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
        {/* Header with gradient overlay */}
        <div className="relative px-5 pt-4 pb-3 border-b border-gray-100 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-r from-blue-50/60 via-white to-white pointer-events-none" />
          <div className="relative flex items-center gap-2">
            <div className="p-1.5 bg-blue-100 rounded-lg">
              <Shield className="h-3.5 w-3.5 text-blue-600" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-gray-800">Severity Overview</h2>
              <p className="text-xs text-gray-400">Open vulnerability counts by severity level</p>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-5 divide-x divide-gray-100">
          {RING_SEVERITIES.map(({ key, title, label, color, bg, border }) => (
            <SeverityRing
              key={key}
              count={s?.[key as keyof Stats] as number ?? 0}
              color={color}
              title={title}
              label={label}
              bg={bg}
              border={border}
            />
          ))}
        </div>
      </div>

      {/* ── Row 2: Stats bar ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {[
          { label: "Scans Running",       value: s?.active_scans  ?? 0, icon: Activity,   color: "text-blue-600",    bg: "bg-blue-50",    border: "border-blue-100",    accent: "#3b82f6" },
          { label: "Scans Queued",         value: s?.queued_scans  ?? 0, icon: Clock,      color: "text-indigo-600",  bg: "bg-indigo-50",  border: "border-indigo-100",  accent: "#6366f1" },
          { label: "Total Scans",          value: s?.total_scans   ?? 0, icon: TrendingUp, color: "text-violet-600",  bg: "bg-violet-50",  border: "border-violet-100",  accent: "#7c3aed" },
          { label: "Open Vulnerabilities", value: s?.open_findings ?? 0, icon: Shield,     color: "text-red-600",     bg: "bg-red-50",     border: "border-red-100",     accent: "#ef4444" },
          { label: "Total Targets",        value: s?.total_targets ?? 0, icon: Target,     color: "text-emerald-600", bg: "bg-emerald-50", border: "border-emerald-100", accent: "#10b981" },
        ].map(({ label, value, icon: Icon, color, bg, border, accent }) => (
          <div key={label} className={`bg-white rounded-2xl border ${border} shadow-sm p-4 flex items-center gap-3 hover:shadow-md transition-all hover:-translate-y-0.5`}>
            <div className={`p-2.5 rounded-xl ${bg} shrink-0`}>
              <Icon className={`h-4 w-4 ${color}`} />
            </div>
            <div className="min-w-0">
              <p className="text-[11px] text-gray-500 leading-tight truncate font-medium">{label}</p>
              <p className="text-2xl font-black leading-tight tabular-nums" style={{ color: accent }}>{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* ── Row 3: Two columns ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Most Vulnerable Targets */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="h-1 w-full bg-gradient-to-r from-red-500 to-orange-400" />
          <div className="px-5 pt-4 pb-2 border-b border-gray-50">
            <h2 className="text-sm font-semibold text-gray-800">Most Vulnerable Targets</h2>
          </div>
          <div className="p-5">
            {targets.length === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">No data yet</p>
            ) : (
              <div className="space-y-0">
                {targets.map((t) => (
                  <div
                    key={t.target_url}
                    className="flex items-center justify-between py-2.5 border-b border-gray-50 last:border-0 cursor-pointer hover:bg-blue-50/40 -mx-2 px-2 rounded-lg transition-colors"
                    onClick={() => navigate(`/scans?target=${encodeURIComponent(t.target_url)}`)}
                  >
                    <span className="text-sm text-blue-600 hover:underline truncate max-w-[58%]">{t.target_url}</span>
                    <SevPills c={t.critical} h={t.high} m={t.medium} l={t.low} i={t.info} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Top Vulnerabilities */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="h-1 w-full bg-gradient-to-r from-orange-500 to-yellow-400" />
          <div className="px-5 pt-4 pb-2 border-b border-gray-50">
            <h2 className="text-sm font-semibold text-gray-800">Top Vulnerabilities</h2>
          </div>
          <div className="p-5">
            {topVulns.length === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">No data yet</p>
            ) : (
              <div className="space-y-0">
                {topVulns.map((v, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 py-2.5 border-b border-gray-50 last:border-0 cursor-pointer hover:bg-orange-50/40 -mx-2 px-2 rounded-lg transition-colors"
                    onClick={() => navigate(`/findings?vuln_type=${encodeURIComponent(v.title)}`)}
                  >
                    <SevBadge severity={v.severity} />
                    <span className="text-xs text-gray-700 flex-1 leading-relaxed">{v.title}</span>
                    <span className="text-sm font-bold text-gray-400 shrink-0">{v.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* ── Section divider ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 pt-2">
        <div className="flex items-center gap-2 px-3 py-1 bg-gray-50 rounded-full border border-gray-100">
          <TrendingUp className="h-3 w-3 text-gray-400" />
          <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-gray-400">Trend Analysis</span>
        </div>
        <div className="flex-1 h-px bg-gradient-to-r from-gray-200 to-transparent" />
      </div>

      {/* ── Row 4: Open Vulnerabilities Trend ───────────────────────────────── */}
      <ChartCard title="Open Vulnerabilities Trend" subtitle="High & Medium open findings for the past 12 months" accentColor="#ef4444" badge="12 months">
        {vulnTrend.every(d => d.high === 0 && d.medium === 0) ? (
          <EmptyChart message="No High or Medium findings detected yet. Data will appear here once scans produce results." />
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={vulnTrend} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#f97316" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f8fafc" vertical={false} />
              <XAxis dataKey="month" tick={{ fontSize: 11, fill: "#cbd5e1" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#cbd5e1" }} tickLine={false} axisLine={false} allowDecimals={false} width={30} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
              <Area type="monotone" dataKey="high"   name="Critical / High" stroke="#ef4444" strokeWidth={2.5} fill="url(#colorHigh)"   dot={false} activeDot={{ r: 4 }} />
              <Area type="monotone" dataKey="medium" name="Medium"        stroke="#f97316" strokeWidth={2.5} fill="url(#colorMedium)" dot={false} activeDot={{ r: 4 }} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* ── Row 5: Average Vulnerabilities per Target ────────────────────────── */}
      <ChartCard title="Average Vulnerabilities per Target" subtitle="Monthly average High & Medium findings per distinct target" accentColor="#6366f1" badge="per target">
        {vulnPerTarget.every(d => d.high === 0 && d.medium === 0) ? (
          <EmptyChart message="Insufficient data. Needs multiple scans across different targets to compute averages." />
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={vulnPerTarget} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="colorHighT" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorMediumT" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#f97316" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f8fafc" vertical={false} />
              <XAxis dataKey="month" tick={{ fontSize: 11, fill: "#cbd5e1" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#cbd5e1" }} tickLine={false} axisLine={false} width={30} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
              <Area type="monotone" dataKey="high"   name="Critical / High" stroke="#ef4444" strokeWidth={2.5} fill="url(#colorHighT)"   dot={false} activeDot={{ r: 4 }} />
              <Area type="monotone" dataKey="medium" name="Medium"        stroke="#f97316" strokeWidth={2.5} fill="url(#colorMediumT)" dot={false} activeDot={{ r: 4 }} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* ── Row 6: Average Days to Remediate ─────────────────────────────────── */}
      <ChartCard title="Remediation Trend" subtitle="Resolved High & Medium findings per month" accentColor="#a855f7" badge="monthly">
        {remediationTrend.every(d => d.high_fixed === 0 && d.medium_fixed === 0) ? (
          <EmptyChart message="No resolved findings yet. Mark findings as Resolved to populate this chart." />
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={remediationTrend} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f8fafc" vertical={false} />
              <XAxis dataKey="month" tick={{ fontSize: 11, fill: "#cbd5e1" }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#cbd5e1" }} tickLine={false} axisLine={false} allowDecimals={false} width={30} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" iconSize={8} />
              <Line type="monotone" dataKey="high_fixed"   name="Critical / High Fixed" stroke="#ef4444" strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
              <Line type="monotone" dataKey="medium_fixed" name="Medium Fixed"            stroke="#f97316" strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* ── Section divider ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 pt-2">
        <div className="flex items-center gap-2 px-3 py-1 bg-gray-50 rounded-full border border-gray-100">
          <Activity className="h-3 w-3 text-gray-400" />
          <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-gray-400">Status Distribution</span>
        </div>
        <div className="flex-1 h-px bg-gradient-to-r from-gray-200 to-transparent" />
      </div>

      {/* ── Row 7: Status Distribution (2-column) ───────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="h-1 w-full bg-gradient-to-r from-indigo-500 to-blue-400" />
          <div className="px-5 pt-4 pb-2 border-b border-gray-50">
            <h2 className="text-sm font-semibold text-gray-800">Scan Status Distribution</h2>
            <p className="text-xs text-gray-400 mt-0.5">Breakdown of all scans by current status</p>
          </div>
          <div className="p-5">
            <ScanStatusChart data={scanStatus} />
          </div>
        </div>
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="h-1 w-full bg-gradient-to-r from-red-500 to-emerald-400" />
          <div className="px-5 pt-4 pb-2 border-b border-gray-50">
            <h2 className="text-sm font-semibold text-gray-800">Findings Status</h2>
            <p className="text-xs text-gray-400 mt-0.5">Distribution of findings across workflow statuses</p>
          </div>
          <div className="p-5">
            <FindingsStatusChart data={findingsStatus} />
          </div>
        </div>
      </div>

    </div>
  );
}
