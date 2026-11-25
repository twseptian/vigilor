import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import {
  Eye, Zap, Brain, FileText, Globe, Lock,
  ChevronDown, ChevronUp, BookOpen, ShieldCheck, Workflow,
  GitBranch, BarChart3, Network, Radio, RotateCcw,
} from "lucide-react";
import { BRAND } from "@/brand";

const FEATURES = [
  {
    icon: Globe,
    title: "Browser recon",
    desc: "Playwright crawls endpoints, forms, JS routes, and APIs in a real browser session.",
  },
  {
    icon: Brain,
    title: "Hypothesis to exploit",
    desc: "Agents propose attacks from recon data, then validate them with live payloads and request/response proof.",
  },
  {
    icon: GitBranch,
    title: "Source code review",
    desc: "Point at a public GitHub/GitLab repo for static patterns, LLM triage, file:line evidence, and a suggested fix.",
  },
  {
    icon: Workflow,
    title: "Attack chains + MITRE",
    desc: "Findings can form multi-step paths mapped to ATT&CK tactics in the engagement view and reports.",
  },
  {
    icon: Network,
    title: "Asset coverage",
    desc: "Hosts are deduplicated across scans so you can see what was tested versus what was only discovered.",
  },
  {
    icon: Radio,
    title: "Activity feed",
    desc: "Goals, phases, findings, and digests in one timeline instead of raw chat logs.",
  },
  {
    icon: RotateCcw,
    title: "Finding retest",
    desc: "Retest a single finding in a focused scan and keep the original evidence for Still reproducible / Fixed.",
  },
  {
    icon: Lock,
    title: "Evidence gates",
    desc: "PoC binding, confidence scores, and analyst verification keep weak claims out of client reports.",
  },
  {
    icon: FileText,
    title: "Client reports",
    desc: "DOCX and PDF with CVSS, PoC, impact, and remediation for web pentest or source review.",
  },
  {
    icon: BarChart3,
    title: "Ops analytics",
    desc: "Severity mix, SLA ageing, finding trends, and active scan status on the dashboard.",
  },
  {
    icon: Network,
    title: "HTTP traffic store",
    desc: "Browse exchanges synced from findings or ingested via the session-capture API.",
  },
  {
    icon: Lock,
    title: "Approval gates",
    desc: "Risky autonomous actions wait in a queue until an analyst approves or denies them.",
  },
  {
    icon: Zap,
    title: "Token and turn budgets",
    desc: "Per-scan spend limits with usage totals on the dashboard.",
  },
];

const DIFFERENTIATORS = [
  {
    title: "Web-first agents",
    body: "Built for Playwright recon, hypothesis generation, and exploit validation on web apps, with an optional source-review mode.",
  },
  {
    title: "Proof over chat logs",
    body: "Findings can carry request/response evidence, confidence scoring, and human verification before export.",
  },
  {
    title: "Attack chains in-product",
    body: "Multi-finding paths and MITRE mapping appear in the UI and the report.",
  },
  {
    title: "Multi-user ops",
    body: "Analyst, reviewer, and admin roles with triage audit trails for a team workflow.",
  },
];

const FAQS = [
  {
    q: `What is ${BRAND.name}?`,
    a: `${BRAND.name} is a self-hosted autonomous web VAPT platform. Agents crawl, hypothesize, exploit, and report, with verification gates, asset coverage, activity history, and finding retests.`,
  },
  {
    q: "How is VIGILOR different from ARTEX or Strix?",
    a: "VIGILOR is a self-hosted web VAPT console: Playwright recon, hypothesis/exploit loops, attack-chain + MITRE graphs, coverage tracking, finding retests, and DOCX/PDF reports. It is not ARTEX (general multi-agent/MITM) and not Strix (usestrix/strix CLI/cloud agents).",
  },
  {
    q: "Which LLM providers are supported?",
    a: "Anthropic, OpenAI, OpenRouter, Mistral, Groq, xAI, DeepSeek, Z.AI (GLM), Kimi, and Ollama for offline models. Configure under Settings > LLM Providers."
  },
  {
    q: "Is this only for authorized testing?",
    a: "Yes. Use VIGILOR only against systems you are authorized to test. Scope, credentials, and budgets are operator-controlled.",
  },
];

function FaqItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="vigilor-card overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50 dark:hover:bg-zinc-900/50"
      >
        <span className="text-[13px] font-semibold text-slate-800 dark:text-zinc-200">{q}</span>
        {open ? <ChevronUp className="h-4 w-4 text-slate-500 dark:text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-slate-500 dark:text-zinc-400" />}
      </button>
      {open && <p className="px-4 pb-4 text-[12px] text-slate-500 dark:text-zinc-400 leading-relaxed">{a}</p>}
    </div>
  );
}

export default function AboutPage() {
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: async () => {
      try {
        const r = await axios.get("/health");
        return r.data;
      } catch {
        return { status: "unknown", version: BRAND.version };
      }
    },
  });

  return (
    <div className="space-y-6 pb-10 max-w-5xl">
      <div className="vigilor-card p-6 relative overflow-hidden">
        <div className="absolute -right-10 -top-10 w-48 h-48 rounded-full bg-teal-500/10 blur-3xl" />
        <div className="relative flex items-start gap-4">
          <div className="h-14 w-14 rounded-2xl bg-teal-700 dark:bg-teal-800 border border-teal-800/30 flex items-center justify-center">
            <Eye className="h-7 w-7 text-teal-50" />
          </div>
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-teal-700 dark:text-teal-400 mb-1">{BRAND.name}</p>
            <h1 className="text-[22px] font-bold text-slate-800 dark:text-zinc-200">{BRAND.fullName}</h1>
            <p className="text-[13px] text-slate-500 dark:text-zinc-400 mt-1 max-w-2xl">{BRAND.description}</p>
            <div className="flex flex-wrap gap-2 mt-3">
              <span className="vigilor-chip">v{health?.version ?? BRAND.version}</span>
              <span className="vigilor-chip"><ShieldCheck className="h-3 w-3" /> Evidence-first</span>
              <span className="vigilor-chip"><Zap className="h-3 w-3" /> Self-hosted</span>
            </div>
          </div>
        </div>
      </div>

      <div>
        <h2 className="text-[14px] font-bold text-slate-800 dark:text-zinc-200 mb-3 flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-teal-700 dark:text-teal-400" /> Capabilities
        </h2>
        <div className="grid sm:grid-cols-2 gap-3">
          {FEATURES.map(({ icon: Icon, title, desc }) => (
            <div key={title} className="vigilor-card p-4">
              <div className="flex items-center gap-2 mb-1.5">
                <Icon className="h-4 w-4 text-teal-700 dark:text-teal-400" />
                <p className="text-[13px] font-semibold text-slate-800 dark:text-zinc-200">{title}</p>
              </div>
              <p className="text-[12px] text-slate-500 dark:text-zinc-400 leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-[14px] font-bold text-slate-800 dark:text-zinc-200 mb-3">Why VIGILOR (vs ARTEX-style platforms)</h2>
        <div className="space-y-2">
          {DIFFERENTIATORS.map(d => (
            <div key={d.title} className="vigilor-card px-4 py-3">
              <p className="text-[13px] font-semibold text-teal-700 dark:text-teal-300">{d.title}</p>
              <p className="text-[12px] text-slate-500 dark:text-zinc-400 mt-1">{d.body}</p>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-[14px] font-bold text-slate-800 dark:text-zinc-200 mb-3">FAQ</h2>
        <div className="space-y-2">
          {FAQS.map(f => <FaqItem key={f.q} q={f.q} a={f.a} />)}
        </div>
      </div>
    </div>
  );
}
