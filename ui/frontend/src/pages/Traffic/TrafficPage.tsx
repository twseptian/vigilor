import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Cable, RefreshCw, Search, Link2, Loader2 } from "lucide-react";
import api from "@/api/client";

interface TrafficItem {
  id: string;
  scan_id: string | null;
  finding_id: string | null;
  method: string;
  url: string;
  host: string | null;
  status_code: number | null;
  request_headers?: string | null;
  request_body?: string | null;
  response_headers?: string | null;
  response_body?: string | null;
  source: string;
  tags: string | null;
  created_at: string;
}

const METHODS = ["", "GET", "POST", "PUT", "PATCH", "DELETE"];
const STATUS = ["", "2xx", "3xx", "4xx", "5xx"];

export default function TrafficPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [method, setMethod] = useState("");
  const [statusClass, setStatusClass] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["traffic", q, method, statusClass],
    queryFn: () =>
      api.get("/traffic", {
        params: {
          q: q || undefined,
          method: method || undefined,
          status_class: statusClass || undefined,
          limit: 80,
        },
      }).then(r => r.data as { total: number; items: TrafficItem[] }),
    refetchInterval: 20_000,
  });

  const sync = useMutation({
    mutationFn: () => api.post("/traffic/sync-from-findings"),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["traffic"] }); },
  });

  const items = data?.items ?? [];
  const detail = useMemo(() => items.find(i => i.id === selected) ?? null, [items, selected]);

  const { data: full } = useQuery({
    queryKey: ["traffic-detail", selected],
    queryFn: () => api.get(`/traffic/${selected}`).then(r => r.data as TrafficItem),
    enabled: !!selected,
  });

  const view = full ?? detail;

  return (
    <div className="space-y-4 pb-8">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-[17px] font-bold text-slate-800 dark:text-zinc-200 flex items-center gap-2">
            <Cable className="h-4 w-4 text-teal-600" /> Traffic
          </h1>
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 mt-0.5">
            HTTP exchanges synced from findings or ingested via the session capture API.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => sync.mutate()}
            disabled={sync.isPending}
            className="vigilor-btn-ghost text-[11px] py-1.5"
          >
            {sync.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Sync from findings
          </button>
          <button onClick={() => refetch()} className="vigilor-btn-ghost text-[11px] py-1.5">
            <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 items-center">
        <div className="flex items-center gap-2 flex-1 min-w-[200px] bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-xl px-3 py-2">
          <Search className="h-3.5 w-3.5 text-slate-500" />
          <input
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Filter URL / host…"
            className="flex-1 bg-transparent text-[13px] outline-none"
          />
        </div>
        <select value={method} onChange={e => setMethod(e.target.value)} className="text-[12px] border border-slate-200 dark:border-zinc-800 rounded-lg px-2 py-2 bg-white dark:bg-zinc-900">
          {METHODS.map(m => <option key={m || "all"} value={m}>{m || "All methods"}</option>)}
        </select>
        <select value={statusClass} onChange={e => setStatusClass(e.target.value)} className="text-[12px] border border-slate-200 dark:border-zinc-800 rounded-lg px-2 py-2 bg-white dark:bg-zinc-900">
          {STATUS.map(s => <option key={s || "all"} value={s}>{s || "All status"}</option>)}
        </select>
        <span className="text-[11px] text-slate-500 dark:text-zinc-400 tabular-nums">{data?.total ?? 0} exchanges</span>
      </div>

      <div className="grid lg:grid-cols-5 gap-3">
        <div className="lg:col-span-2 vigilor-card overflow-hidden max-h-[70vh] overflow-y-auto">
          {isLoading ? (
            <div className="p-8 text-center text-[12px] text-slate-500">Loading…</div>
          ) : items.length === 0 ? (
            <div className="p-8 text-center text-[12px] text-slate-500">
              No traffic yet. Run Sync from findings or POST /api/v1/traffic/ingest.
            </div>
          ) : (
            <div className="divide-y divide-slate-200 dark:divide-zinc-800">
              {items.map(t => (
                <button
                  key={t.id}
                  onClick={() => setSelected(t.id)}
                  className={`w-full text-left px-3 py-2.5 hover:bg-slate-50 dark:hover:bg-zinc-800/40 transition-colors ${
                    selected === t.id ? "bg-teal-50 dark:bg-teal-950/30" : ""
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold font-mono text-teal-700 dark:text-teal-300 w-12">{t.method}</span>
                    <span className={`text-[10px] font-bold tabular-nums ${
                      (t.status_code ?? 0) >= 400 ? "text-red-600" : "text-slate-500 dark:text-zinc-400"
                    }`}>{t.status_code ?? "-"}</span>
                    <span className="text-[9px] px-1 rounded bg-slate-100 dark:bg-zinc-800 text-slate-500">{t.source}</span>
                  </div>
                  <p className="text-[11px] text-slate-700 dark:text-zinc-300 truncate mt-0.5 font-mono">{t.url}</p>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="lg:col-span-3 vigilor-card p-4 min-h-[320px]">
          {!view ? (
            <p className="text-[12px] text-slate-500 dark:text-zinc-400">Select an exchange to inspect request / response.</p>
          ) : (
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-2 flex-wrap">
                <div>
                  <p className="text-[12px] font-mono font-semibold text-slate-800 dark:text-zinc-200 break-all">{view.method} {view.url}</p>
                  <p className="text-[10px] text-slate-500 mt-1">{view.host} · {view.source} · {new Date(view.created_at).toLocaleString()}</p>
                </div>
                {view.finding_id && (
                  <button
                    onClick={() => navigate(`/findings/${view.finding_id}`)}
                    className="vigilor-chip"
                  >
                    <Link2 className="h-3 w-3" /> Open finding
                  </button>
                )}
              </div>
              <div className="grid md:grid-cols-2 gap-3">
                <pre className="text-[10px] font-mono bg-slate-950 text-emerald-300/90 rounded-lg p-3 overflow-auto max-h-72 whitespace-pre-wrap">
{`── Request ──\n${view.request_headers || ""}\n\n${view.request_body || ""}`}
                </pre>
                <pre className="text-[10px] font-mono bg-slate-950 text-sky-300/90 rounded-lg p-3 overflow-auto max-h-72 whitespace-pre-wrap">
{`── Response ${view.status_code ?? ""} ──\n${view.response_headers || ""}\n\n${view.response_body || ""}`}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
