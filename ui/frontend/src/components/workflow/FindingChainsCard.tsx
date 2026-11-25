/**
 * FindingChainsCard — "which attack chains does this finding take part in?"
 *
 * The scan-level workflow already knows which findings combine into a chain, but
 * that link was one-way: a chain named its findings, a finding never named its
 * chains. When writing up a finding, whether it is an isolated issue or the entry
 * point of a Critical chain changes the argument entirely — so surface it here.
 *
 * Reads the cached scan workflow (same query key as AttackWorkflowPanel, so this
 * costs no extra request) and filters the chains by this finding's ref.
 */
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Link2, ChevronRight } from "lucide-react";
import { workflowsApi, type AttackWorkflow } from "@/api/workflows";
import { TONE_BADGE } from "@/lib/badges";

const SEVERITY_COLOR: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#ca8a04",
  Low: "#2563eb",
  Informational: "#a1a1aa",
};

export default function FindingChainsCard({
  scanId,
  findingRef,
}: {
  scanId: string;
  findingRef: string | null;
}) {
  const navigate = useNavigate();

  const { data: workflow } = useQuery<AttackWorkflow>({
    queryKey: ["workflow", scanId],
    queryFn: () => workflowsApi.getForScan(scanId),
    enabled: !!scanId && !!findingRef,
  });

  if (!findingRef || !workflow) return null;

  const chains = workflow.chains.filter(c => c.finding_refs.includes(findingRef));
  if (chains.length === 0) return null;

  return (
    <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center justify-between gap-2">
        <h3 className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">
          Part of Attack Chains
        </h3>
        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full border tabular-nums ${TONE_BADGE.indigo}`}>
          {chains.length}
        </span>
      </div>

      <div className="divide-y divide-slate-200 dark:divide-zinc-700/60">
        {chains.map(chain => {
          const color = SEVERITY_COLOR[chain.severity] ?? "#a1a1aa";
          const position = chain.finding_refs.indexOf(findingRef) + 1;
          const isEntry = position === 1;

          return (
            <button
              key={chain.id}
              onClick={() => navigate(`/scans/${scanId}`)}
              className="w-full text-left px-4 py-3 hover:bg-slate-50 dark:hover:bg-zinc-800/40 transition-colors group"
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span
                  className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide border"
                  style={{ color, backgroundColor: `${color}14`, borderColor: `${color}40` }}
                >
                  {chain.severity}
                </span>
                <span className="text-[9px] font-semibold text-slate-500 dark:text-zinc-400 uppercase tracking-wide">
                  {isEntry ? "Entry point" : `Step ${position} of ${chain.finding_refs.length}`}
                </span>
                {chain.source === "llm" && (
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${TONE_BADGE.teal}`}>
                    AI
                  </span>
                )}
                <ChevronRight className="h-3 w-3 text-slate-700 dark:text-zinc-300 ml-auto group-hover:text-slate-500 dark:group-hover:text-zinc-400 transition-colors" />
              </div>

              <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200 leading-snug">{chain.name}</p>

              {/* The finding's place in the chain, with itself highlighted */}
              <div className="flex items-center gap-1 flex-wrap mt-1.5">
                {chain.finding_refs.map((ref, i) => (
                  <span key={`${ref}-${i}`} className="flex items-center gap-1">
                    {i > 0 && <Link2 className="h-2.5 w-2.5 text-slate-400 dark:text-zinc-2000" />}
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                        ref === findingRef
                          ? "bg-slate-800 text-white border-slate-800 font-bold dark:bg-zinc-200 dark:text-zinc-900 dark:border-zinc-200"
                          : "bg-slate-100 dark:bg-zinc-800/40 text-slate-600 dark:text-zinc-400 border-slate-200 dark:border-zinc-800"
                      }`}
                    >
                      {ref}
                    </span>
                  </span>
                ))}
                <span className="text-[10px] text-slate-500 dark:text-zinc-400 ml-1">→ {chain.impact}</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
