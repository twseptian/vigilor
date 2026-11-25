import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, Check, X, Loader2, Sparkles } from "lucide-react";
import api from "@/api/client";

interface Approval {
  id: string;
  scan_id: string | null;
  action: string;
  detail: string | null;
  risk: string;
  status: string;
  decided_by: string | null;
  decided_at: string | null;
  created_at: string;
  target_url?: string | null;
}

const RISK: Record<string, string> = {
  critical: "bg-red-50 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900/60",
  high: "bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900/60",
  medium: "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900/60",
  low: "bg-slate-100 text-slate-600 border-slate-200 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700",
};

export default function ApprovalsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data: pending = [], isLoading } = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => api.get("/approvals", { params: { status: "pending" } }).then(r => r.data as Approval[]),
    refetchInterval: 8_000,
  });
  const { data: decided = [] } = useQuery({
    queryKey: ["approvals", "decided"],
    queryFn: () => api.get("/approvals", { params: { status: "", limit: 30 } }).then(r =>
      (r.data as Approval[]).filter(a => a.status !== "pending")
    ),
    refetchInterval: 20_000,
  });

  const decide = useMutation({
    mutationFn: ({ id, ok }: { id: string; ok: boolean }) =>
      api.post(`/approvals/${id}/${ok ? "approve" : "deny"}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["approvals"] });
      qc.invalidateQueries({ queryKey: ["approvals-summary"] });
    },
  });

  const seed = useMutation({
    mutationFn: () => api.post("/approvals/seed-demo"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });

  return (
    <div className="space-y-4 pb-8 max-w-4xl">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-[17px] font-bold text-slate-800 dark:text-zinc-200 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-600" /> Intercept approvals
          </h1>
          <p className="text-[12px] text-slate-500 dark:text-zinc-400 mt-0.5">
            Approve or deny risky autonomous actions before they proceed.
          </p>
        </div>
        {pending.length === 0 && (
          <button onClick={() => seed.mutate()} disabled={seed.isPending} className="vigilor-btn-ghost text-[11px] py-1.5">
            {seed.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
            Seed demo queue
          </button>
        )}
      </div>

      <div className="space-y-2">
        <p className="text-[11px] font-bold uppercase tracking-wide text-slate-500">Pending ({pending.length})</p>
        {isLoading ? (
          <p className="text-[12px] text-slate-500">Loading…</p>
        ) : pending.length === 0 ? (
          <div className="vigilor-card p-6 text-[12px] text-slate-500 dark:text-zinc-400">
            No pending approvals. Risky tool calls will land here when HITL is enabled on an engagement.
          </div>
        ) : (
          pending.map(a => (
            <div key={a.id} className="vigilor-card p-4">
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${RISK[a.risk] ?? RISK.medium}`}>{a.risk}</span>
                    <span className="text-[13px] font-semibold text-slate-800 dark:text-zinc-200">{a.action}</span>
                  </div>
                  {a.detail && <p className="text-[12px] text-slate-500 dark:text-zinc-400 whitespace-pre-wrap">{a.detail}</p>}
                  {a.target_url && (
                    <button
                      onClick={() => a.scan_id && navigate(`/scans/${a.scan_id}`)}
                      className="text-[11px] text-teal-700 dark:text-teal-400 mt-1 hover:underline"
                    >
                      {a.target_url}
                    </button>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => decide.mutate({ id: a.id, ok: true })}
                    disabled={decide.isPending}
                    className="flex items-center gap-1 text-[11px] font-semibold px-3 py-1.5 rounded-lg bg-emerald-600 text-white hover:bg-emerald-500"
                  >
                    <Check className="h-3.5 w-3.5" /> Approve
                  </button>
                  <button
                    onClick={() => decide.mutate({ id: a.id, ok: false })}
                    disabled={decide.isPending}
                    className="flex items-center gap-1 text-[11px] font-semibold px-3 py-1.5 rounded-lg border border-red-300 text-red-700 dark:border-red-800 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-950/40"
                  >
                    <X className="h-3.5 w-3.5" /> Deny
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {decided.length > 0 && (
        <div className="space-y-2">
          <p className="text-[11px] font-bold uppercase tracking-wide text-slate-500">Recent decisions</p>
          {decided.slice(0, 12).map(a => (
            <div key={a.id} className="vigilor-card px-4 py-2.5 flex items-center justify-between gap-3 text-[12px]">
              <span className="truncate text-slate-700 dark:text-zinc-300">{a.action}</span>
              <span className={`shrink-0 font-semibold ${a.status === "approved" ? "text-emerald-600" : "text-red-600"}`}>
                {a.status}{a.decided_by ? ` · ${a.decided_by}` : ""}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
