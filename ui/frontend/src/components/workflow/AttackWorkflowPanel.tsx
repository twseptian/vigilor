import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  RefreshCw, Loader2, ChevronDown, Copy, Check, Link2,
  ShieldAlert, Sparkles, Cpu, AlertTriangle, ArrowRight,
} from "lucide-react";
import { workflowsApi, type AttackWorkflow, type AttackChain } from "@/api/workflows";
import { tacticFor } from "./mitre";
import AttackFlowGraph from "./AttackFlowGraph";
import { SEV_BADGE as SEV_BADGE_SHARED, TONE_BADGE } from "@/lib/badges";

const SEV_BADGE: Record<string, string> = SEV_BADGE_SHARED;

const SEV_ACCENT: Record<string, string> = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#d97706",
  Low: "#2563eb",
  Informational: "#a1a1aa",
};

function ConfidencePill({ value }: { value: number }) {
  const cfg =
    value >= 80 ? { label: "HIGH", cls: TONE_BADGE.emerald }
    : value >= 40 ? { label: "MED", cls: TONE_BADGE.amber }
    : { label: "LOW", cls: TONE_BADGE.slate };
  return (
    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border tabular-nums ${cfg.cls}`}>
      {cfg.label} {value}%
    </span>
  );
}

function ChainCard({
  chain, active, onToggle, onOpenFinding,
}: {
  chain: AttackChain;
  active: boolean;
  onToggle: () => void;
  onOpenFinding: (id: string) => void;
}) {
  const accent = SEV_ACCENT[chain.severity] ?? SEV_ACCENT.Informational;
  return (
    <div
      className={`rounded-lg border overflow-hidden transition-all ${
        active ? "border-teal-500/60 shadow-sm ring-1 ring-teal-700/40" : "border-slate-300 dark:border-zinc-700/60 hover:border-zinc-500"
      }`}
    >
      <button onClick={onToggle} className="w-full text-left">
        <div className="flex items-stretch">
          <div className="w-[3px] shrink-0" style={{ backgroundColor: accent }} />
          <div className="flex-1 min-w-0 px-3 py-2.5">
            <div className="flex items-center gap-1.5 flex-wrap mb-1">
              <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${SEV_BADGE[chain.severity] ?? SEV_BADGE.Informational}`}>
                {chain.severity === "Informational" ? "Info" : chain.severity}
              </span>
              <ConfidencePill value={chain.confidence} />
              {!chain.evidence_backed && (
                <span className={`inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded border ${TONE_BADGE.red}`}>
                  <AlertTriangle className="h-2.5 w-2.5" /> PARTIAL EVIDENCE
                </span>
              )}
              <span className={`inline-flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded border ${
                chain.source === "llm"
                  ? TONE_BADGE.teal
                  : TONE_BADGE.slate
              }`}>
                {chain.source === "llm" ? <><Sparkles className="h-2.5 w-2.5" /> AI</> : <><Cpu className="h-2.5 w-2.5" /> RULES</>}
              </span>
              <span className="flex-1" />
              <ChevronDown className={`h-3.5 w-3.5 text-slate-700 dark:text-zinc-300 transition-transform ${active ? "rotate-180" : ""}`} />
            </div>
            <p className="text-[12px] font-semibold text-slate-800 dark:text-zinc-200 leading-snug">{chain.name}</p>
            <div className="flex items-center gap-1 flex-wrap mt-1">
              {chain.finding_refs.map((ref, i) => (
                <span key={`${ref}-${i}`} className="flex items-center gap-1">
                  {i > 0 && <ArrowRight className="h-2.5 w-2.5 text-slate-700 dark:text-zinc-300" />}
                  <span className="text-[9px] font-mono font-bold px-1 py-px rounded bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400 border border-slate-200 dark:border-zinc-800">
                    {ref}
                  </span>
                </span>
              ))}
              <span className="text-[9px] text-slate-500 dark:text-zinc-400 ml-1">→ {chain.terminal}</span>
            </div>
          </div>
        </div>
      </button>

      {active && (
        <div className="border-t border-slate-200 dark:border-zinc-800 bg-slate-100 dark:bg-zinc-800/50 px-3 py-3 space-y-2.5">
          {chain.steps.map(step => (
            <div key={step.order} className="flex gap-2.5">
              <div className="flex flex-col items-center shrink-0">
                <span
                  className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black text-white"
                  style={{ backgroundColor: accent }}
                >
                  {step.order}
                </span>
                {step.order < chain.steps.length && <span className="flex-1 w-px bg-zinc-600 my-1" />}
              </div>
              <div className="min-w-0 flex-1 pb-1">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-[9px] font-bold uppercase tracking-[0.1em] text-slate-500 dark:text-zinc-400">
                    {step.stage_label}
                  </span>
                  {/* ATT&CK tactic for this stage — reports are expected to map to
                      the framework. Tactic only; we never assert a technique ID. */}
                  {(() => {
                    const tactic = tacticFor(step.stage_label);
                    return tactic ? (
                      <a
                        href={tactic.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        onClick={e => e.stopPropagation()}
                        title={`MITRE ATT&CK tactic ${tactic.id}: ${tactic.name}`}
                        className="text-[8px] font-bold font-mono px-1 py-px rounded border border-slate-200 dark:border-zinc-800 bg-slate-100 dark:bg-zinc-800/40 text-slate-500 dark:text-zinc-400 hover:border-slate-300 dark:border-zinc-600 hover:text-slate-700 dark:text-zinc-300 transition-colors"
                      >
                        {tactic.id}
                      </a>
                    ) : null;
                  })()}
                  {step.finding_ref && (
                    <button
                      onClick={() => step.finding_id && onOpenFinding(step.finding_id)}
                      className={`inline-flex items-center gap-1 text-[9px] font-mono font-bold px-1 py-px rounded border hover:opacity-90 transition-colors ${TONE_BADGE.teal}`}
                    >
                      <Link2 className="h-2.5 w-2.5" /> {step.finding_ref}
                    </button>
                  )}
                  {step.evidence === "No PoC evidence" && (
                    <span className="text-[9px] font-bold text-red-500">no PoC</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-700 dark:text-zinc-300 leading-relaxed mt-0.5">{step.action}</p>
                {step.location && (
                  <p className="text-[9px] font-mono text-slate-500 dark:text-zinc-400 truncate mt-0.5" title={step.location}>
                    {step.location}
                  </p>
                )}
              </div>
            </div>
          ))}

          {chain.impact && (
            <div className="pt-2 border-t border-slate-200 dark:border-zinc-800">
              <p className="text-[9px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400 mb-1">Impact</p>
              <p className="text-[11px] text-slate-700 dark:text-zinc-300 leading-relaxed">{chain.impact}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackWorkflowPanel({
  scanId, enabled = true,
}: {
  scanId: string;
  enabled?: boolean;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [activeChain, setActiveChain] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  const { data: workflow, isLoading, isError } = useQuery<AttackWorkflow>({
    queryKey: ["workflow", scanId],
    queryFn: () => workflowsApi.getForScan(scanId),
    enabled,
  });

  // "15 nodes" is meaningless without saying what a node is — spell it out on hover.
  const nodeBreakdown = (() => {
    const nodes = workflow?.graph?.nodes ?? [];
    const count = (kind: string) => nodes.filter(n => n.kind === kind).length;
    return `${count("target")} target, ${count("finding")} findings, ${count("impact")} impact outcomes`;
  })();

  const regenerate = useMutation({
    mutationFn: (useLlm: boolean) => workflowsApi.generateForScan(scanId, useLlm),
    onSuccess: data => {
      qc.setQueryData(["workflow", scanId], data);
      setActiveChain(null);
      setMenuOpen(false);
    },
  });

  const copyMermaid = () => {
    if (!workflow?.mermaid) return;
    navigator.clipboard.writeText(workflow.mermaid).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  if (!enabled) return null;

  return (
    <div className="bg-white dark:bg-zinc-900 rounded-lg border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
      <div className="w-full h-[2px] bg-teal-500" />

      {/* Header — the tab above names this section, so this row is metadata + tools */}
      <div className="px-4 py-3 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-3 flex-wrap">
        {workflow && (
          /* Read-only counters. `cursor-default` + tooltips so they read as facts
             about the graph, not as chips waiting to be clicked. */
          <div className="flex items-center gap-2 text-[10px] text-slate-500 dark:text-zinc-400 cursor-default">
            <span
              className="tabular-nums font-semibold text-slate-500 dark:text-zinc-400"
              title="Attack chains derived from these findings (listed on the right)"
            >
              {workflow.chain_count} chain{workflow.chain_count !== 1 ? "s" : ""}
            </span>
            <span className="w-px h-3 bg-slate-300 dark:bg-zinc-600" />
            <span className="tabular-nums" title={`Boxes in the graph: ${nodeBreakdown}`}>
              {workflow.node_count} nodes
            </span>
            <span className="w-px h-3 bg-slate-300 dark:bg-zinc-600" />
            <span className="tabular-nums" title="Arrows connecting the nodes: chain steps plus standalone exposures">
              {workflow.edge_count} edges
            </span>
            <span className="w-px h-3 bg-slate-300 dark:bg-zinc-600" />
            <span
              className={`inline-flex items-center gap-1 font-semibold ${
                workflow.generator.includes("llm") ? "text-teal-500" : "text-slate-500 dark:text-zinc-400"
              }`}
              title={workflow.generator.includes("llm")
                ? "Chains matched by rules; the narrative and any extra chains were written by the LLM. AI-proposed chains carry an AI badge."
                : "Built from deterministic chain templates only (no LLM). Use Regenerate > Rules + AI narrative for an AI summary."}
            >
              {workflow.generator.includes("llm")
                ? <><Sparkles className="h-2.5 w-2.5" /> rules + AI{workflow.llm_model ? ` · ${workflow.llm_model}` : ""}</>
                : <><Cpu className="h-2.5 w-2.5" /> rules only</>}
            </span>
          </div>
        )}

        <div className="flex-1" />

        <button
          onClick={copyMermaid}
          disabled={!workflow?.mermaid}
          className="flex items-center gap-1 text-[10px] font-semibold px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-zinc-800 text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800/40 disabled:opacity-40 transition-colors"
        >
          {copied ? <><Check className="h-3 w-3 text-emerald-500" /> Copied</> : <><Copy className="h-3 w-3" /> Mermaid</>}
        </button>

        <div className="relative">
          <div className="flex items-stretch rounded-lg overflow-hidden border border-slate-200 dark:border-zinc-800">
            <button
              onClick={() => regenerate.mutate(true)}
              disabled={regenerate.isPending}
              className="flex items-center gap-1.5 text-[10px] font-semibold px-2.5 py-1.5 text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800/40 disabled:opacity-50 transition-colors"
            >
              {regenerate.isPending
                ? <Loader2 className="h-3 w-3 animate-spin" />
                : <RefreshCw className="h-3 w-3" />}
              {regenerate.isPending ? "Generating…" : "Regenerate"}
            </button>
            <button
              onClick={() => setMenuOpen(o => !o)}
              className="px-1.5 text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800/40 border-l border-slate-200 dark:border-zinc-800 transition-colors"
            >
              <ChevronDown className={`h-3 w-3 transition-transform ${menuOpen ? "rotate-180" : ""}`} />
            </button>
          </div>
          {menuOpen && (
            <div className="absolute right-0 top-full mt-1 w-56 bg-white dark:bg-zinc-900 rounded-lg border border-slate-200 dark:border-zinc-800 shadow-lg z-20 overflow-hidden">
              <button
                onClick={() => regenerate.mutate(true)}
                className="w-full text-left px-3 py-2 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors"
              >
                <p className="text-[11px] font-semibold text-slate-700 dark:text-zinc-300 flex items-center gap-1.5">
                  <Sparkles className="h-3 w-3 text-teal-500" /> Rules + AI narrative
                </p>
                <p className="text-[9px] text-slate-500 dark:text-zinc-400 mt-0.5">Uses the scan's LLM (costs tokens)</p>
              </button>
              <button
                onClick={() => regenerate.mutate(false)}
                className="w-full text-left px-3 py-2 hover:bg-slate-100 dark:hover:bg-zinc-800/40 border-t border-slate-200 dark:border-zinc-800 transition-colors"
              >
                <p className="text-[11px] font-semibold text-slate-700 dark:text-zinc-300 flex items-center gap-1.5">
                  <Cpu className="h-3 w-3 text-slate-500 dark:text-zinc-400" /> Rules only
                </p>
                <p className="text-[9px] text-slate-500 dark:text-zinc-400 mt-0.5">Deterministic, no LLM call</p>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Body */}
      {isLoading ? (
        <div className="flex items-center justify-center py-14">
          <Loader2 className="h-5 w-5 animate-spin text-slate-700 dark:text-zinc-300" />
        </div>
      ) : isError || !workflow ? (
        <div className="flex flex-col items-center py-12 gap-2">
          <div className="w-9 h-9 rounded-full border-2 border-dashed border-slate-200 dark:border-zinc-800 flex items-center justify-center">
            <ShieldAlert className="h-4 w-4 text-slate-700 dark:text-zinc-300" />
          </div>
          <p className="text-[11px] text-slate-500 dark:text-zinc-400">No attack workflow available for this scan</p>
        </div>
      ) : (
        <>
          {workflow.summary && (
            <div className="px-4 py-3 bg-teal-50 dark:bg-teal-950/30 border-b border-teal-200 dark:border-teal-800/40">
              <p className="text-[9px] font-bold uppercase tracking-[0.12em] text-teal-700 dark:text-teal-400 mb-1">Attack Narrative</p>
              <p className="text-[11px] text-slate-700 dark:text-zinc-300 leading-relaxed">{workflow.summary}</p>
            </div>
          )}

          {/* Full-width graph — chains listed below so the path is never squeezed */}
          <div className="p-4 border-b border-slate-200 dark:border-zinc-800">
            <AttackFlowGraph
              graph={workflow.graph}
              activeChain={activeChain}
              exportName={`attack-flow-${scanId.slice(0, 8)}`}
              height={520}
              onNodeClick={node => node.finding_id && navigate(`/findings/${node.finding_id}`)}
            />
          </div>

          <div className="p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Attack Chains</p>
              {activeChain && (
                <button
                  onClick={() => setActiveChain(null)}
                  className="text-[9px] font-semibold text-teal-600 dark:text-teal-400 hover:text-teal-800 dark:hover:text-teal-300 transition-colors"
                >
                  Clear highlight
                </button>
              )}
            </div>
            {workflow.chains.length === 0 ? (
              <div className="flex flex-col items-center py-10 gap-2 border border-dashed border-slate-200 dark:border-zinc-800 rounded-lg">
                <ShieldAlert className="h-4 w-4 text-slate-500 dark:text-zinc-400" />
                <p className="text-[11px] text-slate-500 dark:text-zinc-400 text-center px-4">
                  No multi-step chain derived. Findings look like independent exposures.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                {workflow.chains.map(chain => (
                  <ChainCard
                    key={chain.id}
                    chain={chain}
                    active={activeChain === chain.id}
                    onToggle={() => setActiveChain(activeChain === chain.id ? null : chain.id)}
                    onOpenFinding={id => navigate(`/findings/${id}`)}
                  />
                ))}
              </div>
            )}
          </div>

          {regenerate.isError && (
            <div className="px-4 py-2 border-t border-red-100 bg-red-50">
              <p className="text-[10px] text-red-600 dark:text-red-400">
                {(regenerate.error as any)?.response?.data?.detail ?? "Workflow generation failed"}
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
