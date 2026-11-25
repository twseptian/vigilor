import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
} from "recharts";
import {
  ScanSearch, Bug, Target, Activity, Clock, Plus,
  ShieldCheck, Radio, Network, TrendingUp,
} from "lucide-react";
import api from "@/api/client";
import { BRAND } from "@/brand";
import { useThemeStore } from "@/store/themeStore";
import { SEV_HEX } from "@/lib/badges";

interface Stats {
  active_scans: number; queued_scans: number; total_scans: number;
  open_findings: number; critical_findings: number; high_findings: number;
  medium_findings: number; low_findings: number; informational_findings: number;
  scans_this_week: number; total_targets: number;
}
interface TrendPoint  { month: string; high: number; medium: number; }
interface RemPoint    { month: string; avg_days: number; high_fixed: number; medium_fixed: number; }
interface StatusPoint { status: string; count: number; }
interface ActivityItem {
  id: number; hostname: string; target_url: string; status: string;
  total_findings: number; critical: number; high: number; medium: number; low: number; age_label: string;
}
interface SLAPoint { severity: string; within_sla: number; overdue: number; threshold_days: number; }

const SEV = SEV_HEX;

const STATUS_DOT: Record<string, string> = {
  completed: "bg-emerald-400", running: "bg-teal-400 animate-pulse",
  queued: "bg-sky-400", failed: "bg-red-400", cancelled: "bg-zinc-500",
};

export default function DashboardPage() {
  const navigate = useNavigate();
  const theme = useThemeStore(s => s.theme);
  const isLight = theme === "light";
  const mutedFg = isLight ? "#64748b" : "#a1a1aa";
  const gridStroke = isLight ? "#e2e8f0" : "#27272a";
  const emptyFill = isLight ? "#e2e8f0" : "#27272a";
  const pieStroke = isLight ? "#ffffff" : "#18181b";
  const tooltipStyle = {
    fontSize: 11, borderRadius: 8,
    border: isLight ? "1px solid #e2e8f0" : "1px solid #3f3f46",
    backgroundColor: isLight ? "#ffffff" : "#18181b",
    color: isLight ? "#334155" : "#d4d4d8",
  };

  const { data: stats }           = useQuery<Stats>({ queryKey: ["ds-stats"], queryFn: () => api.get("/dashboard/stats").then(r => r.data), refetchInterval: 10_000 });
  const { data: vulnTrend = [] }  = useQuery<TrendPoint[]>({ queryKey: ["ds-vtrend"], queryFn: () => api.get("/dashboard/vuln-trend").then(r => r.data), refetchInterval: 30_000 });
  const { data: remTrend = [] }   = useQuery<RemPoint[]>({ queryKey: ["ds-remtrend"], queryFn: () => api.get("/dashboard/remediation-trend").then(r => r.data), refetchInterval: 30_000 });
  const { data: scanStatus = [] } = useQuery<StatusPoint[]>({ queryKey: ["ds-scanst"], queryFn: () => api.get("/dashboard/scan-status").then(r => r.data), refetchInterval: 10_000 });
  const { data: activity = [] }   = useQuery<ActivityItem[]>({ queryKey: ["ds-activity"], queryFn: () => api.get("/dashboard/recent-activity").then(r => r.data), refetchInterval: 15_000 });
  const { data: sla = [] }        = useQuery<SLAPoint[]>({ queryKey: ["ds-sla"], queryFn: () => api.get("/dashboard/sla-compliance").then(r => r.data), refetchInterval: 30_000 });
  const { data: assets }          = useQuery<{ total: number; tested: number }>({
    queryKey: ["ds-assets-summary"],
    queryFn: () => api.get("/assets/summary").then(r => r.data),
    refetchInterval: 20_000,
  });
  const { data: usage } = useQuery<{
    total_tokens: number; estimated_cost_usd: number; events: number;
    by_provider: { provider: string; tokens: number; cost: number }[];
  }>({
    queryKey: ["ds-usage"],
    queryFn: () => api.get("/usage/summary").then(r => r.data),
    refetchInterval: 60_000,
  });
  const { data: approvalSum } = useQuery<{ pending: number }>({
    queryKey: ["approvals-summary"],
    queryFn: () => api.get("/approvals/summary").then(r => r.data),
    refetchInterval: 15_000,
  });

  const overdueTotal = sla.reduce((acc, d) => acc + (d.overdue ?? 0), 0);
  const s = stats;
  const totalFindings = (s?.critical_findings ?? 0) + (s?.high_findings ?? 0) + (s?.medium_findings ?? 0) + (s?.low_findings ?? 0) + (s?.informational_findings ?? 0);

  const backlogTrend = (() => {
    const months = [...new Set([...vulnTrend.map(p => p.month), ...remTrend.map(p => p.month)])];
    return months.map(month => {
      const o = vulnTrend.find(p => p.month === month);
      const r = remTrend.find(p => p.month === month);
      return {
        month,
        opened:   (o?.high ?? 0) + (o?.medium ?? 0),
        resolved: (r?.high_fixed ?? 0) + (r?.medium_fixed ?? 0),
      };
    });
  })();

  const sevDonut = [
    { name: "Critical", value: s?.critical_findings ?? 0, fill: SEV.Critical },
    { name: "High", value: s?.high_findings ?? 0, fill: SEV.High },
    { name: "Medium", value: s?.medium_findings ?? 0, fill: SEV.Medium },
    { name: "Low", value: s?.low_findings ?? 0, fill: SEV.Low },
    { name: "Info", value: s?.informational_findings ?? 0, fill: SEV.Informational },
  ].filter(d => d.value > 0);

  const coveragePct = assets && assets.total > 0
    ? Math.round((assets.tested / assets.total) * 100)
    : 0;

  return (
    <div className="space-y-4 pb-8">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-teal-500/80 mb-1">{BRAND.name}</p>
          <h1 className="text-[18px] font-bold text-slate-800 dark:text-zinc-200 leading-tight">Overview</h1>
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 mt-0.5">
            {s?.total_targets ?? 0} targets · {totalFindings} open findings
            {overdueTotal > 0 && <> · <span className="text-orange-600 dark:text-orange-400 font-semibold">{overdueTotal} overdue</span></>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-[10px] font-medium text-slate-500 dark:text-zinc-400 px-2 py-1 rounded-lg border border-slate-200 dark:border-zinc-800 bg-white/90 dark:bg-zinc-900/80">
            <span className="w-1.5 h-1.5 rounded-full bg-teal-400 animate-pulse" /> Live
          </span>
          <button onClick={() => navigate("/scans/new")} className="vigilor-btn-primary text-[11px] py-1.5">
            <Plus className="h-3.5 w-3.5" /> New Engagement
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        {[
          {
            label: "Active scans",
            value: s?.active_scans ?? 0,
            sub: `${s?.queued_scans ?? 0} queued · ${s?.total_scans ?? 0} total`,
            icon: Activity,
            onClick: () => navigate("/scans?status=running"),
          },
          {
            label: "Open findings",
            value: s?.open_findings ?? 0,
            sub: `C ${s?.critical_findings ?? 0} · H ${s?.high_findings ?? 0} · M ${s?.medium_findings ?? 0}`,
            icon: Bug,
            onClick: () => navigate("/findings"),
          },
          {
            label: "Assets",
            value: assets?.total ?? s?.total_targets ?? 0,
            sub: `${assets?.tested ?? 0} tested · ${coveragePct}% coverage`,
            icon: Network,
            onClick: () => navigate("/assets"),
          },
          {
            label: "This week",
            value: s?.scans_this_week ?? 0,
            sub: "scans started",
            icon: ScanSearch,
            onClick: () => navigate("/scans"),
          },
          {
            label: "SLA overdue",
            value: overdueTotal,
            sub: overdueTotal ? "past threshold" : "on track",
            icon: Clock,
            onClick: () => navigate("/findings"),
          },
        ].map(({ label, value, sub, icon: Icon, onClick }) => (
          <button key={label} onClick={onClick} className="vigilor-stat text-left group">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-zinc-400 font-semibold">{label}</span>
              <Icon className="h-3.5 w-3.5 text-teal-500/70 group-hover:text-teal-700 dark:text-teal-400" />
            </div>
            <p className="text-[28px] font-black tabular-nums text-slate-800 dark:text-zinc-200 leading-none mt-1">{value}</p>
            <p className="text-[10px] text-slate-500 dark:text-zinc-400 mt-1 truncate">{sub}</p>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="vigilor-card p-4 md:col-span-2">
          <div className="flex items-center justify-between mb-2">
            <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200">LLM usage</p>
            <span className="text-[10px] text-slate-500">last 30 days</span>
          </div>
          <div className="flex items-end gap-6 flex-wrap">
            <div>
              <p className="text-[22px] font-black tabular-nums text-slate-800 dark:text-zinc-200">
                {((usage?.total_tokens ?? 0) / 1000).toFixed(1)}k
              </p>
              <p className="text-[10px] text-slate-500">tokens</p>
            </div>
            <div>
              <p className="text-[22px] font-black tabular-nums text-teal-700 dark:text-teal-300">
                ${(usage?.estimated_cost_usd ?? 0).toFixed(2)}
              </p>
              <p className="text-[10px] text-slate-500">est. cost</p>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(usage?.by_provider ?? []).slice(0, 4).map(p => (
                <span key={p.provider} className="text-[10px] px-2 py-0.5 rounded-md border border-slate-200 dark:border-zinc-700 bg-slate-50 dark:bg-zinc-900 text-slate-600 dark:text-zinc-300">
                  {p.provider}: {(p.tokens / 1000).toFixed(0)}k
                </span>
              ))}
            </div>
          </div>
        </div>
        <button onClick={() => navigate("/approvals")} className="vigilor-card p-4 text-left hover:border-amber-400/50 transition-colors">
          <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200 mb-1">Pending approvals</p>
          <p className="text-[28px] font-black tabular-nums text-amber-700 dark:text-amber-300 leading-none">
            {approvalSum?.pending ?? 0}
          </p>
          <p className="text-[10px] text-slate-500 mt-1">awaiting review</p>
        </button>
      </div>

      {/* Severity strip */}
      <div className="vigilor-card flex divide-x divide-slate-200 dark:divide-zinc-800 overflow-hidden">
        {(["Critical", "High", "Medium", "Low", "Informational"] as const).map(sev => {
          const key = `${sev.toLowerCase()}_findings` as keyof Stats;
          const count = s ? (s[key] as number) ?? 0 : 0;
          const color = SEV[sev];
          return (
            <button
              key={sev}
              onClick={() => navigate(`/findings?severity=${sev}`)}
              className="flex-1 flex items-center gap-3 px-4 py-3 hover:bg-white/90 dark:bg-zinc-900/80 transition-colors relative"
            >
              <div className="absolute left-0 top-[22%] bottom-[22%] w-[2px] rounded-full" style={{ backgroundColor: color }} />
              <span className="text-[22px] font-black tabular-nums leading-none" style={{ color: count > 0 ? color : mutedFg }}>
                {count}
              </span>
              <div className="text-left">
                <p className="text-[11px] font-semibold" style={{ color: count > 0 ? color : mutedFg }}>
                  {sev === "Informational" ? "Info" : sev}
                </p>
                <p className="text-[9px] text-slate-500 dark:text-zinc-400">findings</p>
              </div>
            </button>
          );
        })}
        <div className="flex items-center px-4 gap-2 shrink-0 bg-slate-50 dark:bg-zinc-900/40">
          <ShieldCheck className="h-3.5 w-3.5 text-teal-500" />
          <div>
            <p className="text-[11px] font-semibold text-slate-800 dark:text-zinc-200 leading-none">{totalFindings}</p>
            <p className="text-[9px] text-slate-500 dark:text-zinc-400 mt-0.5">open total</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4 items-start">
        <div className="col-span-12 lg:col-span-8 space-y-4">
          <div className="vigilor-card">
            <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-3.5 w-3.5 text-teal-500" />
                <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200">Findings over time</p>
              </div>
              <p className="text-[10px] text-slate-500 dark:text-zinc-400">Opened vs fixed</p>
            </div>
            <div className="px-3 py-3 h-[180px]">
              {backlogTrend.length === 0 ? (
                <div className="h-full flex items-center justify-center text-[11px] text-slate-500 dark:text-zinc-400">No trend data yet</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={backlogTrend} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="openG" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#2dd4bf" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#2dd4bf" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="fixG" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#34d399" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="#34d399" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                    <XAxis dataKey="month" tick={{ fill: mutedFg, fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: mutedFg, fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Area type="monotone" dataKey="opened" stroke="#2dd4bf" fill="url(#openG)" strokeWidth={2} />
                    <Area type="monotone" dataKey="resolved" stroke="#34d399" fill="url(#fixG)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="vigilor-card">
              <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800">
                <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200">Severity mix</p>
              </div>
              <div className="p-4 h-[160px] relative">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={sevDonut.length ? sevDonut : [{ name: "Empty", value: 1, fill: emptyFill }]}
                      cx="50%" cy="50%" innerRadius={42} outerRadius={62}
                      dataKey="value" strokeWidth={2} stroke={pieStroke}
                    >
                      {(sevDonut.length ? sevDonut : [{ fill: emptyFill }]).map((d, i) => (
                        <Cell key={i} fill={(d as any).fill} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-[18px] font-black text-slate-800 dark:text-zinc-200 tabular-nums">{totalFindings}</span>
                  <span className="text-[8px] text-slate-500 dark:text-zinc-400 uppercase tracking-widest">open</span>
                </div>
              </div>
            </div>

            <div className="vigilor-card">
              <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center justify-between">
                <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200">Engagement status</p>
                <button onClick={() => navigate("/scans")} className="text-[10px] text-teal-700 dark:text-teal-400 hover:underline">View all</button>
              </div>
              <div className="p-4 space-y-2.5">
                {scanStatus.length === 0 ? (
                  <p className="text-[11px] text-slate-500 dark:text-zinc-400 py-6 text-center">No engagements yet</p>
                ) : scanStatus.map(row => {
                  const max = Math.max(...scanStatus.map(r => r.count), 1);
                  const pct = (row.count / max) * 100;
                  return (
                    <div key={row.status} className="flex items-center gap-3">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${STATUS_DOT[row.status] ?? "bg-zinc-500"}`} />
                      <span className="text-[11px] text-slate-500 dark:text-zinc-400 w-20 capitalize">{row.status}</span>
                      <div className="flex-1 h-1.5 rounded-full bg-slate-100 dark:bg-zinc-800 overflow-hidden">
                        <div className="h-full rounded-full bg-teal-500/80" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-[11px] font-semibold tabular-nums text-slate-800 dark:text-zinc-200 w-6 text-right">{row.count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div className="col-span-12 lg:col-span-4 space-y-4">
          <div className="vigilor-card">
            <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Radio className="h-3.5 w-3.5 text-teal-500" />
                <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200">Recent activity</p>
              </div>
              <button onClick={() => navigate("/activity")} className="text-[10px] text-teal-700 dark:text-teal-400 hover:underline">View all</button>
            </div>
            <div className="divide-y divide-slate-200 dark:divide-zinc-800/80 max-h-[420px] overflow-y-auto">
              {activity.length === 0 ? (
                <p className="text-[11px] text-slate-500 dark:text-zinc-400 py-10 text-center">No recent activity</p>
              ) : activity.map(item => (
                <button
                  key={item.id}
                  onClick={() => navigate(`/scans/${item.id}`)}
                  className="w-full text-left px-4 py-3 hover:bg-slate-50 dark:hover:bg-zinc-900/70 transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOT[item.status] ?? "bg-zinc-500"}`} />
                    <span className="text-[11px] font-semibold text-slate-800 dark:text-zinc-200 truncate">{item.hostname || item.target_url}</span>
                    <span className="ml-auto text-[9px] text-slate-500 dark:text-zinc-400 shrink-0">{item.age_label}</span>
                  </div>
                  <p className="text-[10px] text-slate-500 dark:text-zinc-400 truncate">{item.target_url}</p>
                  <div className="flex gap-2 mt-1.5 text-[9px] font-medium">
                    {item.critical > 0 && <span className="text-red-600 dark:text-red-400">C {item.critical}</span>}
                    {item.high > 0 && <span className="text-orange-600 dark:text-orange-400">H {item.high}</span>}
                    {item.medium > 0 && <span className="text-amber-700 dark:text-amber-400">M {item.medium}</span>}
                    <span className="text-slate-500 dark:text-zinc-400">{item.total_findings} findings</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          <div className="vigilor-card p-4">
            <div className="flex items-center gap-2 mb-2">
              <Target className="h-3.5 w-3.5 text-teal-500" />
              <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200">Asset coverage</p>
            </div>
            <div className="flex items-end gap-3 mb-2">
              <p className="text-[32px] font-black tabular-nums text-slate-800 dark:text-zinc-200 leading-none">{coveragePct}%</p>
              <p className="text-[11px] text-slate-500 dark:text-zinc-400 pb-1">
                {assets?.tested ?? 0} / {assets?.total ?? 0} tested
              </p>
            </div>
            <div className="h-2 rounded-full bg-slate-100 dark:bg-zinc-800 overflow-hidden">
              <div className="h-full rounded-full bg-gradient-to-r from-teal-600 to-teal-400 transition-all" style={{ width: `${coveragePct}%` }} />
            </div>
            <button onClick={() => navigate("/assets")} className="mt-3 text-[11px] text-teal-700 dark:text-teal-400 hover:underline">
              Open assets
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
