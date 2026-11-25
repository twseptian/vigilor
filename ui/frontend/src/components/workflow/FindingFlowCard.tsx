import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Workflow, RefreshCw, Loader2, Copy, Check, ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";
import { workflowsApi, type AttackWorkflow } from "@/api/workflows";
import AttackFlowGraph from "./AttackFlowGraph";
import { TONE_BADGE } from "@/lib/badges";

const SEV_ACCENT: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#d97706",
  Low: "#2563eb",
  Informational: "#a1a1aa",
};

export default function FindingFlowCard({
  findingId, severity,
}: {
  findingId: string;
  severity: string;
}) {
  const qc = useQueryClient();
  const [graphOpen, setGraphOpen] = useState(true);
  const [copied, setCopied] = useState(false);
  const accent = SEV_ACCENT[severity] ?? SEV_ACCENT.Informational;

  const { data: workflow, isLoading } = useQuery<AttackWorkflow>({
    queryKey: ["finding-workflow", findingId],
    queryFn: () => workflowsApi.getForFinding(findingId),
    enabled: !!findingId,
  });

  const regenerate = useMutation({
    mutationFn: () => workflowsApi.generateForFinding(findingId),
    onSuccess: data => qc.setQueryData(["finding-workflow", findingId], data),
  });

  const steps = workflow?.chains?.[0]?.steps ?? [];

  const copyMermaid = () => {
    if (!workflow?.mermaid) return;
    navigator.clipboard.writeText(workflow.mermaid).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="bg-white dark:bg-zinc-900 rounded-lg border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
      <div className="w-full h-[2px]" style={{ backgroundColor: accent }} />

      <div className="px-4 py-3 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-2 flex-wrap">
        <Workflow className="h-4 w-4 text-teal-600 dark:text-teal-400" />
        <span className="text-[13px] font-bold text-slate-800 dark:text-zinc-200">Attack Flow</span>
        {steps.length > 0 && (
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border tabular-nums ${TONE_BADGE.teal}`}>
            {steps.length} steps
          </span>
        )}
        <div className="flex-1" />
        <button
          onClick={() => setGraphOpen(o => !o)}
          className="flex items-center gap-1 text-[10px] text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:hover:text-zinc-300 px-2 py-1 rounded border border-slate-200 dark:border-zinc-800 transition-colors"
        >
          {graphOpen ? <><ChevronUp className="h-3 w-3" /> Hide graph</> : <><ChevronDown className="h-3 w-3" /> Show graph</>}
        </button>
        <button
          onClick={copyMermaid}
          disabled={!workflow?.mermaid}
          className="flex items-center gap-1 text-[10px] font-semibold px-2 py-1 rounded border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800/40 disabled:opacity-40 transition-colors"
        >
          {copied ? <><Check className="h-3 w-3 text-emerald-500" /> Copied</> : <><Copy className="h-3 w-3" /> Mermaid</>}
        </button>
        <button
          onClick={() => regenerate.mutate()}
          disabled={regenerate.isPending}
          className="flex items-center gap-1 text-[10px] font-semibold px-2 py-1 rounded border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800/40 disabled:opacity-50 transition-colors"
        >
          {regenerate.isPending
            ? <Loader2 className="h-3 w-3 animate-spin" />
            : <RefreshCw className="h-3 w-3" />}
          Rebuild
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-5 w-5 animate-spin text-slate-700 dark:text-zinc-300" />
        </div>
      ) : !workflow || steps.length === 0 ? (
        <div className="py-10 text-center">
          <p className="text-[11px] text-slate-500 dark:text-zinc-400">No attack flow could be derived for this finding</p>
        </div>
      ) : (
        <>
          {graphOpen && (
            <div className="p-4 border-b border-slate-200 dark:border-zinc-800">
              <AttackFlowGraph
                graph={workflow.graph}
                exportName={`attack-flow-finding-${findingId.slice(0, 8)}`}
                height={420}
              />
            </div>
          )}

          <div className="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {steps.map(step => (
              <div key={step.order} className="flex gap-3 rounded-lg border border-slate-200 dark:border-zinc-800 bg-slate-50/80 dark:bg-zinc-950/40 p-3">
                <div className="flex flex-col items-center shrink-0">
                  <span
                    className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-black text-white"
                    style={{ backgroundColor: accent }}
                  >
                    {step.order}
                  </span>
                </div>
                <div className="min-w-0 flex-1">
                  <span className="text-[9px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">
                    {step.stage_label}
                  </span>
                  <p className="text-[11px] text-slate-700 dark:text-zinc-300 leading-relaxed mt-0.5">{step.action}</p>
                  {step.evidence && (
                    <pre className="mt-1.5 rounded-md p-2.5 text-[10px] font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap break-all max-h-36 border border-slate-200 dark:border-zinc-800 bg-white text-slate-700 dark:bg-zinc-950 dark:text-zinc-400">
                      {step.evidence}
                    </pre>
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
