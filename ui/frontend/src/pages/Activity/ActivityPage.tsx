import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Radio, Filter } from "lucide-react";
import api from "@/api/client";

interface BroadcastEvent {
  id: string;
  kind: "goal" | "intent" | "fact" | "finding" | "phase" | "digest";
  ts: string;
  title: string;
  detail: string;
  scan_id: string | null;
  target_url: string | null;
  severity: string | null;
}

const KIND_STYLE: Record<string, string> = {
  goal: "bg-sky-50 text-sky-800 border-sky-200 dark:bg-sky-950 dark:text-sky-300 dark:border-sky-800/50",
  intent: "bg-violet-50 text-violet-800 border-violet-200 dark:bg-violet-950 dark:text-violet-300 dark:border-violet-800/50",
  fact: "bg-slate-100 dark:bg-zinc-800 text-slate-700 dark:text-zinc-300 border-slate-300 dark:border-zinc-700",
  finding: "bg-red-50 text-red-800 border-red-200 dark:bg-red-950 dark:text-red-300 dark:border-red-800/50",
  phase: "bg-teal-50 text-teal-800 border-teal-200 dark:bg-teal-950 dark:text-teal-300 dark:border-teal-800/50",
  digest: "bg-amber-50 text-amber-900 border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800/50",
};

const KINDS = ["all", "phase", "finding", "goal", "intent", "fact", "digest"] as const;

export default function ActivityPage() {
  const navigate = useNavigate();
  const [kind, setKind] = useState<(typeof KINDS)[number]>("all");

  const { data: events = [], isLoading } = useQuery<BroadcastEvent[]>({
    queryKey: ["activity-broadcast"],
    queryFn: () => api.get("/activity/broadcast").then(r => r.data),
    refetchInterval: 8_000,
  });

  const filtered = useMemo(
    () => (kind === "all" ? events : events.filter(e => e.kind === kind)),
    [events, kind],
  );

  return (
    <div className="space-y-4 pb-8">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-[17px] font-bold text-slate-800 dark:text-zinc-200 flex items-center gap-2">
            <Radio className="h-4 w-4 text-teal-700 dark:text-teal-400" /> Activity broadcast
          </h1>
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 mt-0.5">
            Agent phases, findings, and digests in chronological order.
          </p>
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          <Filter className="h-3.5 w-3.5 text-slate-500 dark:text-zinc-400" />
          {KINDS.map(k => (
            <button
              key={k}
              onClick={() => setKind(k)}
              className={`vigilor-tab capitalize ${kind === k ? "vigilor-tab-active" : ""}`}
            >
              {k}
            </button>
          ))}
        </div>
      </div>

      <div className="vigilor-card overflow-hidden">
        {isLoading ? (
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 py-12 text-center">Loading broadcast…</p>
        ) : filtered.length === 0 ? (
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 py-12 text-center">No events yet. Running engagements will stream here.</p>
        ) : (
          <div className="relative">
            <div className="absolute left-[27px] top-4 bottom-4 w-px bg-slate-100 dark:bg-zinc-800" />
            <ul className="divide-y divide-slate-200 dark:divide-zinc-800/70">
              {filtered.map(ev => (
                <li key={ev.id}>
                  <button
                    onClick={() => ev.scan_id && navigate(`/scans/${ev.scan_id}`)}
                    className="w-full text-left px-4 py-3.5 hover:bg-slate-50 dark:hover:bg-zinc-900/50 transition-colors flex gap-3"
                  >
                    <div className="relative z-10 mt-1 h-2.5 w-2.5 rounded-full bg-teal-500 shadow-[0_0_8px_#2dd4bf] shrink-0 ml-1.5" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${KIND_STYLE[ev.kind] ?? KIND_STYLE.fact}`}>
                          {ev.kind}
                        </span>
                        {ev.severity && (
                          <span className="text-[9px] font-semibold text-orange-700 dark:text-orange-300">{ev.severity}</span>
                        )}
                        <span className="text-[10px] text-slate-500 dark:text-zinc-400 ml-auto shrink-0">
                          {new Date(ev.ts).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-[13px] font-medium text-slate-800 dark:text-zinc-200 truncate">{ev.title}</p>
                      <p className="text-[11px] text-slate-500 dark:text-zinc-400 mt-0.5 line-clamp-2">{ev.detail}</p>
                      {ev.target_url && (
                        <p className="text-[10px] text-teal-500/80 mt-1 truncate">{ev.target_url}</p>
                      )}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
