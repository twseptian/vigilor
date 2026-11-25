import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Network, Search, ShieldAlert, ExternalLink } from "lucide-react";
import api from "@/api/client";

interface AssetRow {
  host: string;
  target_url: string;
  scan_count: number;
  last_scan_id: string | null;
  last_status: string | null;
  last_seen: string | null;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  findings_info: number;
  tested: boolean;
}

interface AssetsResponse {
  total: number;
  tested: number;
  assets: AssetRow[];
}

const STATUS_DOT: Record<string, string> = {
  completed: "bg-emerald-400", running: "bg-teal-400 animate-pulse",
  queued: "bg-sky-400", failed: "bg-red-400", cancelled: "bg-zinc-500",
};

export default function AssetsPage() {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const { data, isLoading } = useQuery<AssetsResponse>({
    queryKey: ["assets"],
    queryFn: () => api.get("/assets").then(r => r.data),
    refetchInterval: 15_000,
  });
  const { data: graph } = useQuery<{
    nodes: { id: string; label: string; kind: string; tested: boolean; meta?: Record<string, unknown> }[];
    edges: { source: string; target: string }[];
  }>({
    queryKey: ["assets-graph"],
    queryFn: () => api.get("/assets/graph").then(r => r.data),
    refetchInterval: 30_000,
  });
  const hosts = (graph?.nodes ?? []).filter(n => n.kind === "host");
  const endpoints = (graph?.nodes ?? []).filter(n => n.kind === "endpoint");

  const filtered = useMemo(() => {
    const rows = data?.assets ?? [];
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter(a =>
      a.host.toLowerCase().includes(needle) || a.target_url.toLowerCase().includes(needle)
    );
  }, [data, q]);

  const coverage = data && data.total > 0 ? Math.round((data.tested / data.total) * 100) : 0;

  return (
    <div className="space-y-4 pb-8">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-[17px] font-bold text-slate-800 dark:text-zinc-200">Asset coverage</h1>
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 mt-0.5">
            Deduplicated hosts from engagements, with tested vs untested coverage.
          </p>
        </div>
        <div className="vigilor-chip">
          <Network className="h-3 w-3" />
          {data?.tested ?? 0}/{data?.total ?? 0} tested · {coverage}%
        </div>
      </div>

      <div className="vigilor-card p-3">
        <div className="h-2 rounded-full bg-slate-100 dark:bg-zinc-800 overflow-hidden">
          <div className="h-full bg-gradient-to-r from-teal-600 to-cyan-400" style={{ width: `${coverage}%` }} />
        </div>
      </div>

      <div className="flex items-center gap-2 max-w-md bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl px-3 py-2">
        <Search className="h-3.5 w-3.5 text-slate-500 dark:text-zinc-400" />
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder="Filter hosts…"
          className="flex-1 bg-transparent text-[13px] text-slate-800 dark:text-zinc-200 outline-none placeholder:text-slate-500 dark:text-zinc-400"
        />
      </div>

      {hosts.length > 0 && (
        <div className="vigilor-card p-4">
          <p className="text-[11px] font-bold uppercase tracking-wide text-slate-500 dark:text-zinc-400 mb-3">Coverage graph</p>
          <div className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-semibold px-2 py-1 rounded-lg bg-teal-50 text-teal-800 border border-teal-200 dark:bg-teal-950/40 dark:text-teal-300 dark:border-teal-800/50">
                Engagement scope
              </span>
              <span className="text-slate-400">→</span>
              {hosts.slice(0, 8).map(h => (
                <button
                  key={h.id}
                  onClick={() => {
                    const sid = h.meta?.last_scan_id as string | undefined;
                    if (sid) navigate(`/scans/${sid}`);
                  }}
                  className={`text-[10px] font-semibold px-2 py-1 rounded-lg border ${
                    h.tested
                      ? "bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/50"
                      : "bg-slate-100 text-slate-600 border-slate-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700"
                  }`}
                >
                  {h.label}
                </button>
              ))}
            </div>
            {endpoints.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pl-2 border-l-2 border-teal-500/30">
                {endpoints.slice(0, 16).map(e => (
                  <button
                    key={e.id}
                    onClick={() => {
                      const fid = e.meta?.finding_id as string | undefined;
                      if (fid) navigate(`/findings/${fid}`);
                    }}
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-slate-200 dark:border-zinc-700 bg-slate-50 dark:bg-zinc-900 text-slate-600 dark:text-zinc-400 max-w-[220px] truncate"
                    title={e.label}
                  >
                    {e.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="vigilor-card overflow-hidden">
        <div className="grid grid-cols-12 gap-2 px-4 py-2 border-b border-slate-200 dark:border-zinc-800 text-[10px] uppercase tracking-wider text-slate-500 dark:text-zinc-400 font-semibold">
          <div className="col-span-4">Host</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-2">Engagements</div>
          <div className="col-span-3">Findings</div>
          <div className="col-span-1 text-right">Open</div>
        </div>
        {isLoading ? (
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 py-10 text-center">Loading assets…</p>
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center">
            <ShieldAlert className="h-6 w-6 text-zinc-700 mx-auto mb-2" />
            <p className="text-[12px] text-slate-500 dark:text-zinc-400">No assets yet. Launch a scan to populate this list.</p>
          </div>
        ) : filtered.map(a => (
          <button
            key={a.host + a.target_url}
            onClick={() => a.last_scan_id && navigate(`/scans/${a.last_scan_id}`)}
            className="w-full grid grid-cols-12 gap-2 px-4 py-3 border-b border-slate-200 dark:border-zinc-800/60 hover:bg-slate-100 dark:hover:bg-zinc-800/40 text-left transition-colors"
          >
            <div className="col-span-4 min-w-0">
              <p className="text-[13px] font-semibold text-slate-800 dark:text-zinc-200 truncate">{a.host}</p>
              <p className="text-[10px] text-slate-500 dark:text-zinc-400 truncate flex items-center gap-1">
                {a.target_url} <ExternalLink className="h-2.5 w-2.5 shrink-0 opacity-50" />
              </p>
            </div>
            <div className="col-span-2 flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOT[a.last_status ?? ""] ?? "bg-zinc-600"}`} />
              <span className="text-[11px] text-slate-500 dark:text-zinc-400 capitalize">{a.last_status ?? "-"}</span>
            </div>
            <div className="col-span-2 text-[12px] tabular-nums text-slate-700 dark:text-zinc-300 self-center">{a.scan_count}</div>
            <div className="col-span-3 flex items-center gap-2 text-[10px] font-semibold self-center">
              {a.findings_critical > 0 && <span className="text-red-600 dark:text-red-400">C{a.findings_critical}</span>}
              {a.findings_high > 0 && <span className="text-orange-600 dark:text-orange-400">H{a.findings_high}</span>}
              {a.findings_medium > 0 && <span className="text-amber-700 dark:text-amber-400">M{a.findings_medium}</span>}
              {a.findings_low > 0 && <span className="text-sky-400">L{a.findings_low}</span>}
              {!a.findings_critical && !a.findings_high && !a.findings_medium && !a.findings_low && (
                <span className="text-slate-500 dark:text-zinc-400">-</span>
              )}
            </div>
            <div className="col-span-1 text-right self-center">
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${a.tested
                ? "bg-teal-50 text-teal-800 border-teal-200 dark:bg-teal-950 dark:text-teal-300 dark:border-teal-800/50"
                : "bg-slate-100 text-slate-600 border-slate-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700"}`}>
                {a.tested ? "Tested" : "Untested"}
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
