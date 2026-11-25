import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, Send, ExternalLink, Shield, Pencil, Check, X, ChevronDown,
  AlertCircle, CheckCircle2, GitMerge, ShieldAlert, Archive, MinusCircle, RotateCcw, Loader2 } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { findingsApi, type Finding } from "@/api/findings";
import FindingFlowCard from "@/components/workflow/FindingFlowCard";
import FindingChainsCard from "@/components/workflow/FindingChainsCard";
import { SEVERITY_COLORS } from "@/lib/utils";
import { TONE_BADGE } from "@/lib/badges";

const SEV_ACCENT: Record<string, string> = {
  Critical: "#dc2626", High: "#ea580c", Medium: "#d97706",
  Low: "#2563eb", Informational: "#a1a1aa",
};

// ── Finding statuses ──────────────────────────────────────────────────────────

const FINDING_STATUSES: Array<{
  value: Finding["status"];
  label: string;
  description: string;
  icon: React.ElementType;
  color: string;
  bg: string;
  border: string;
}> = [
  {
    value: "Open",
    label: "Open",
    description: "The vulnerability has been identified and poses a security risk. Further action is required to remediate.",
    icon: AlertCircle,
    color: "text-red-700 dark:text-red-300",
    bg: "bg-red-50 dark:bg-red-950/50",
    border: "border-red-200 dark:border-red-900/60",
  },
  {
    value: "Resolved",
    label: "Resolved",
    description: "The issue has been fully remediated with minimal residual risk.",
    icon: CheckCircle2,
    color: "text-emerald-700 dark:text-emerald-300",
    bg: "bg-emerald-50 dark:bg-emerald-950/50",
    border: "border-emerald-200 dark:border-emerald-900/60",
  },
  {
    value: "Partially Resolved",
    label: "Partially Resolved",
    description: "Some remediation measures have been implemented, but further action is needed.",
    icon: GitMerge,
    color: "text-blue-700 dark:text-blue-300",
    bg: "bg-blue-50 dark:bg-blue-950/50",
    border: "border-blue-200 dark:border-blue-900/60",
  },
  {
    value: "Risk Accepted",
    label: "Risk Accepted",
    description: "Management has acknowledged the risk and chosen to accept it based on cost-benefit considerations.",
    icon: ShieldAlert,
    color: "text-orange-700 dark:text-orange-300",
    bg: "bg-orange-50 dark:bg-orange-950/50",
    border: "border-orange-200 dark:border-orange-900/60",
  },
  {
    value: "Closed",
    label: "Closed",
    description: "Management has evaluated and determined the risk finding to be irrelevant, not applicable, or a false positive and poses no threat to the organization. No further action is required.",
    icon: Archive,
    color: "text-slate-700 dark:text-zinc-300",
    bg: "bg-slate-100 dark:bg-zinc-800",
    border: "border-slate-200 dark:border-zinc-700",
  },
  {
    value: "NA",
    label: "N/A",
    description: "Not applicable. The risk finding has a severity rating of None.",
    icon: MinusCircle,
    color: "text-slate-500 dark:text-zinc-400",
    bg: "bg-slate-50 dark:bg-zinc-900/60",
    border: "border-slate-200 dark:border-zinc-800",
  },
];

// ── Status Dropdown ───────────────────────────────────────────────────────────

function StatusDropdown({
  value,
  onChange,
  saving,
}: {
  value: Finding["status"];
  onChange: (v: Finding["status"]) => void;
  saving: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = FINDING_STATUSES.find((s) => s.value === value) ?? FINDING_STATUSES[0];
  const Icon = current.icon;

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        disabled={saving}
        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium transition-colors hover:opacity-80 disabled:opacity-50 ${current.bg} ${current.color} ${current.border}`}
      >
        <Icon className="h-3.5 w-3.5 shrink-0" />
        <span>{current.label}</span>
        <ChevronDown className={`h-3.5 w-3.5 shrink-0 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1.5 w-80 bg-white dark:bg-zinc-900 border border-border rounded-xl shadow-xl z-50 overflow-hidden">
          <div className="px-3 py-2 border-b border-border bg-muted/40">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Finding Status</p>
          </div>
          <div className="py-1">
            {FINDING_STATUSES.map((s) => {
              const SIcon = s.icon;
              const isActive = s.value === value;
              return (
                <button
                  key={s.value}
                  type="button"
                  onClick={() => { onChange(s.value); setOpen(false); }}
                  className={`w-full text-left px-3 py-2.5 flex items-start gap-3 hover:bg-muted/50 transition-colors ${isActive ? "bg-muted/30" : ""}`}
                >
                  <div className={`mt-0.5 h-6 w-6 rounded-full flex items-center justify-center shrink-0 ${s.bg} ${s.border} border`}>
                    <SIcon className={`h-3.5 w-3.5 ${s.color}`} />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-semibold ${s.color}`}>{s.label}</span>
                      {isActive && <span className="text-[10px] bg-primary/10 text-primary px-1.5 py-0.5 rounded font-medium">Current</span>}
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed mt-0.5">{s.description}</p>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── CVSS 3.1 metric definitions ───────────────────────────────────────────────

const CVSS3_METRICS: Array<{
  key: string;
  label: string;
  tooltip: string;
  options: Array<{ value: string; label: string }>;
}> = [
  {
    key: "AV", label: "Attack Vector",
    tooltip: "Describes how the vulnerability is exploited. Network = remotely exploitable over internet. Adjacent = requires access to the same network/segment. Local = requires local access. Physical = requires physical access to device.",
    options: [{ value: "N", label: "Network" }, { value: "A", label: "Adjacent" }, { value: "L", label: "Local" }, { value: "P", label: "Physical" }],
  },
  {
    key: "AC", label: "Attack Complexity",
    tooltip: "Describes the conditions beyond the attacker's control that must exist to exploit the vulnerability. Low = no special conditions. High = specific circumstances must exist (race condition, specific config, etc).",
    options: [{ value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "PR", label: "Privileges Required",
    tooltip: "Describes the level of privileges the attacker must have before exploiting this vulnerability. None = no privileges needed. Low = basic user. High = admin-level access.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "UI", label: "User Interaction",
    tooltip: "Indicates whether the vulnerability requires participation by a human user other than the attacker. None = no user interaction needed. Required = a user must take some action.",
    options: [{ value: "N", label: "None" }, { value: "R", label: "Required" }],
  },
  {
    key: "S", label: "Scope",
    tooltip: "Indicates whether the vulnerability impacts components beyond its authorization scope. Unchanged = only the vulnerable component is affected. Changed = other components can be impacted (e.g. privilege escalation, container escape).",
    options: [{ value: "U", label: "Unchanged" }, { value: "C", label: "Changed" }],
  },
  {
    key: "C", label: "Confidentiality",
    tooltip: "Measures the impact on confidentiality of information if the vulnerability is exploited. None = no impact. Low = limited disclosure. High = total loss of confidentiality or attacker can read all files.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "I", label: "Integrity",
    tooltip: "Measures the impact on integrity if the vulnerability is exploited. None = no impact. Low = limited modification possible. High = total loss of integrity (attacker can modify any data).",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "A", label: "Availability",
    tooltip: "Measures the impact on availability of the impacted component. None = no impact. Low = reduced performance or intermittent outages. High = total loss of availability.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
];

// ── CVSS 4.0 metric definitions ───────────────────────────────────────────────

const CVSS4_METRICS: Array<{
  key: string;
  label: string;
  tooltip: string;
  options: Array<{ value: string; label: string }>;
}> = [
  {
    key: "AV", label: "Attack Vector",
    tooltip: "How the vulnerability is exploited. Network = exploitable remotely with no physical proximity. Adjacent = requires access to the same physical/logical network (e.g. Bluetooth, Wi-Fi). Local = requires local account or physical access. Physical = requires physical interaction with the device.",
    options: [{ value: "N", label: "Network" }, { value: "A", label: "Adjacent" }, { value: "L", label: "Local" }, { value: "P", label: "Physical" }],
  },
  {
    key: "AC", label: "Attack Complexity",
    tooltip: "Conditions beyond the attacker's control that must exist. Low = the attacker can exploit at will without special circumstances. High = specific target configuration or race conditions are required.",
    options: [{ value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "AT", label: "Attack Requirements",
    tooltip: "Prerequisites for the attack to succeed related to the target system. None = no special prerequisites. Present = the attack requires a specific deployment condition (e.g. shared cache, specific memory layout).",
    options: [{ value: "N", label: "None" }, { value: "P", label: "Present" }],
  },
  {
    key: "PR", label: "Privileges Required",
    tooltip: "Level of privileges the attacker must already have. None = unauthenticated. Low = standard user. High = administrator or superuser access required before exploitation.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "UI", label: "User Interaction",
    tooltip: "Whether a human other than the attacker must take an action for exploitation. None = no user interaction. Passive = user activity is required but nothing beyond normal use. Active = the user must perform specific steps (e.g. click a malicious link, open a file).",
    options: [{ value: "N", label: "None" }, { value: "P", label: "Passive" }, { value: "A", label: "Active" }],
  },
  {
    key: "VC", label: "Confidentiality (Vuln. System)",
    tooltip: "Impact on confidentiality of the directly vulnerable component. None = no confidentiality impact. Low = some data exposed but not full control. High = total information disclosure of the vulnerable component.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "VI", label: "Integrity (Vuln. System)",
    tooltip: "Impact on integrity of the directly vulnerable component. None = no modification possible. Low = partial modification. High = attacker has full write access to the vulnerable component.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "VA", label: "Availability (Vuln. System)",
    tooltip: "Impact on availability of the directly vulnerable component. None = no impact. Low = reduced performance. High = complete unavailability of the vulnerable component.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "SC", label: "Confidentiality (Subseq. System)",
    tooltip: "Impact on confidentiality of systems other than the directly vulnerable one. None = no impact on subsequent systems. Low = some data disclosure. High = total information disclosure across other components.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "SI", label: "Integrity (Subseq. System)",
    tooltip: "Impact on integrity of subsequent systems. None = no modification possible on other components. Low = partial modification. High = attacker can modify any data in subsequent systems.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
  {
    key: "SA", label: "Availability (Subseq. System)",
    tooltip: "Impact on availability of subsequent systems. None = no impact on other components. Low = reduced performance elsewhere. High = other systems completely unavailable.",
    options: [{ value: "N", label: "None" }, { value: "L", label: "Low" }, { value: "H", label: "High" }],
  },
];

// ── CVSS 3.1 metric groups ────────────────────────────────────────────────────

const CVSS3_GROUPS = [
  {
    label: "Exploitability Metrics",
    tooltip: "Describes how the vulnerability can be accessed and the conditions required for exploitation, including network reach, complexity, privileges needed, and user interaction.",
    keys: ["AV", "AC", "PR", "UI", "S"],
  },
  {
    label: "Impact Metrics",
    tooltip: "Measures the direct consequences to confidentiality, integrity, and availability if the vulnerability is successfully exploited in the vulnerable component.",
    keys: ["C", "I", "A"],
  },
];

// ── CVSS 4.0 metric groups ────────────────────────────────────────────────────

const CVSS4_GROUPS = [
  {
    label: "Exploitability Metrics",
    tooltip: "Characterizes how the vulnerability is accessed, the attack conditions required, the level of privileges needed, and whether a human user must participate in the exploitation.",
    keys: ["AV", "AC", "AT", "PR", "UI"],
  },
  {
    label: "Vulnerable System Impact",
    tooltip: "Measures the direct impact on confidentiality, integrity, and availability of the system that contains the vulnerability itself.",
    keys: ["VC", "VI", "VA"],
  },
  {
    label: "Subsequent System Impact",
    tooltip: "Measures the impact on other systems that depend on or interact with the vulnerable system, such as downstream services, shared infrastructure, or connected components.",
    keys: ["SC", "SI", "SA"],
  },
];

// ── CVSS 3.1 score calculator ─────────────────────────────────────────────────

function roundup31(x: number): number {
  const intInput = Math.round(x * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function calcCvss31Score(m: Record<string, string>): number {
  const AV: Record<string, number>  = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC: Record<string, number>  = { L: 0.77, H: 0.44 };
  const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 };
  const UI: Record<string, number>  = { N: 0.85, R: 0.62 };
  const CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

  const scope = m.S;
  const av  = AV[m.AV]  ?? 0;
  const ac  = AC[m.AC]  ?? 0;
  const pr  = (scope === "C" ? PR_C : PR_U)[m.PR] ?? 0;
  const ui  = UI[m.UI]  ?? 0;
  const c   = CIA[m.C]  ?? 0;
  const i   = CIA[m.I]  ?? 0;
  const a   = CIA[m.A]  ?? 0;

  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
  const isc = scope === "U"
    ? 6.42 * iscBase
    : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

  if (isc <= 0) return 0.0;

  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scope === "U"
    ? Math.min(isc + exploitability, 10)
    : Math.min(1.08 * (isc + exploitability), 10);

  return roundup31(raw);
}

// ── CVSS 4.0 score calculator ─────────────────────────────────────────────────
// Full implementation per FIRST CVSS v4.0 specification with interpolation
// Reference: https://github.com/FIRSTdotorg/cvss-v4-calculator

// Metric severity levels (0.0 = highest severity)
const AV40: Record<string, number> = { N:0.0, A:0.1, L:0.2, P:0.3 };
const PR40: Record<string, number> = { N:0.0, L:0.1, H:0.2 };
const UI40: Record<string, number> = { N:0.0, P:0.1, A:0.2 };
const AC40: Record<string, number> = { L:0.0, H:0.1 };
const AT40: Record<string, number> = { N:0.0, P:0.1 };
const VC40: Record<string, number> = { H:0.0, L:0.1, N:0.2 };
const VI40: Record<string, number> = { H:0.0, L:0.1, N:0.2 };
const VA40: Record<string, number> = { H:0.0, L:0.1, N:0.2 };
const SC40: Record<string, number> = { H:0.1, L:0.2, N:0.3 };
const SI40: Record<string, number> = { S:0.0, H:0.1, L:0.2, N:0.3 };
const SA40: Record<string, number> = { S:0.0, H:0.1, L:0.2, N:0.3 };
const CR40: Record<string, number> = { H:0.0, M:0.1, L:0.2 };
const IR40: Record<string, number> = { H:0.0, M:0.1, L:0.2 };
const AR40: Record<string, number> = { H:0.0, M:0.1, L:0.2 };

// Max severity distances per EQ level combination (used for normalization)
const CVSS40_MAX_SEV: Record<string, Record<number, any>> = {
  eq1:    { 0:1, 1:4, 2:5 },
  eq2:    { 0:1, 1:2 },
  eq3eq6: { 0:{ 0:7, 1:6 }, 1:{ 0:8, 1:8 }, 2:{ 1:10 } },
  eq4:    { 0:6, 1:5, 2:4 },
  eq5:    { 0:1, 1:1, 2:1 },
};

// Highest-severity partial vectors per EQ level (used for severity distance)
const CVSS40_MAX_VECS: Record<string, Record<number, any>> = {
  eq1: {
    0: ["AV:N/PR:N/UI:N/"],
    1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
  },
  eq2: {
    0: ["AC:L/AT:N/"],
    1: ["AC:H/AT:N/", "AC:L/AT:P/"],
  },
  // eq3 is keyed by [eq3_level][eq6_level]
  eq3: {
    0: {
      0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
      1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
    },
    1: {
      0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
      1: [
        "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
        "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
        "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
        "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
        "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
      ],
    },
    2: {
      1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
    },
  },
  eq4: {
    0: ["SC:H/SI:S/SA:S/"],
    1: ["SC:H/SI:H/SA:H/"],
    2: ["SC:L/SI:L/SA:L/"],
  },
  eq5: {
    0: ["E:A/"],
    1: ["E:P/"],
    2: ["E:U/"],
  },
};

// 6-digit macro-vector score lookup (FIRST CVSS 4.0 official table)
// Key format: "${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}"
const CVSS40_LOOKUP: Record<string, number> = {
  "000000":10.0,"000001":9.9, "000010":9.8, "000011":9.5, "000020":9.5, "000021":9.2,
  "000100":10.0,"000101":9.6, "000110":9.3, "000111":8.7, "000120":9.1, "000121":8.1,
  "000200":9.3, "000201":9.0, "000210":8.9, "000211":8.0, "000220":8.1, "000221":6.8,
  "001000":9.8, "001001":9.5, "001010":9.5, "001011":9.2, "001020":9.0, "001021":8.4,
  "001100":9.3, "001101":9.2, "001110":8.9, "001111":8.1, "001120":8.1, "001121":6.5,
  "001200":8.8, "001201":8.0, "001210":7.8, "001211":7.0, "001220":6.9, "001221":4.8,
  "002001":9.2, "002011":8.2, "002021":7.2, "002101":7.9, "002111":6.9, "002121":5.0,
  "002201":6.9, "002211":5.5, "002221":2.7,
  "010000":9.9, "010001":9.7, "010010":9.5, "010011":9.2, "010020":9.2, "010021":8.5,
  "010100":9.5, "010101":9.1, "010110":9.0, "010111":8.3, "010120":8.4, "010121":7.1,
  "010200":9.2, "010201":8.1, "010210":8.2, "010211":7.1, "010220":7.2, "010221":5.3,
  "011000":9.5, "011001":9.3, "011010":9.2, "011011":8.5, "011020":8.5, "011021":7.3,
  "011100":9.2, "011101":8.2, "011110":8.0, "011111":7.2, "011120":7.0, "011121":5.9,
  "011200":8.4, "011201":7.0, "011210":7.1, "011211":5.2, "011220":5.0, "011221":3.0,
  "012001":8.6, "012011":7.5, "012021":5.2, "012101":7.1, "012111":5.2, "012121":2.9,
  "012201":6.3, "012211":2.9, "012221":1.7,
  "100000":9.8, "100001":9.5, "100010":9.4, "100011":8.7, "100020":9.1, "100021":8.1,
  "100100":9.4, "100101":8.9, "100110":8.6, "100111":7.4, "100120":7.7, "100121":6.4,
  "100200":8.7, "100201":7.5, "100210":7.4, "100211":6.3, "100220":6.3, "100221":4.9,
  "101000":9.4, "101001":8.9, "101010":8.8, "101011":7.7, "101020":7.6, "101021":6.7,
  "101100":8.6, "101101":7.6, "101110":7.4, "101111":5.8, "101120":5.9, "101121":5.0,
  "101200":7.2, "101201":5.7, "101210":5.7, "101211":5.2, "101220":5.2, "101221":2.5,
  "102001":8.3, "102011":7.0, "102021":5.4, "102101":6.5, "102111":5.8, "102121":2.6,
  "102201":5.3, "102211":2.1, "102221":1.3,
  "110000":9.5, "110001":9.0, "110010":8.8, "110011":7.6, "110020":7.6, "110021":7.0,
  "110100":9.0, "110101":7.7, "110110":7.5, "110111":6.2, "110120":6.1, "110121":5.3,
  "110200":7.7, "110201":6.6, "110210":6.8, "110211":5.9, "110220":5.2, "110221":3.0,
  "111000":8.9, "111001":7.8, "111010":7.6, "111011":6.7, "111020":6.2, "111021":5.8,
  "111100":7.4, "111101":5.9, "111110":5.7, "111111":5.7, "111120":4.7, "111121":2.3,
  "111200":6.1, "111201":5.2, "111210":5.7, "111211":2.9, "111220":2.4, "111221":1.6,
  "112001":7.1, "112011":5.9, "112021":3.0, "112101":5.8, "112111":2.6, "112121":1.5,
  "112201":2.3, "112211":1.3, "112221":0.6,
  "200000":9.3, "200001":8.7, "200010":8.6, "200011":7.2, "200020":7.5, "200021":5.8,
  "200100":8.6, "200101":7.4, "200110":7.4, "200111":6.1, "200120":5.6, "200121":3.4,
  "200200":7.0, "200201":5.4, "200210":5.2, "200211":4.0, "200220":4.0, "200221":2.2,
  "201000":8.5, "201001":7.5, "201010":7.4, "201011":5.5, "201020":6.2, "201021":5.1,
  "201100":7.2, "201101":5.7, "201110":5.5, "201111":4.1, "201120":4.6, "201121":1.9,
  "201200":5.3, "201201":3.6, "201210":3.4, "201211":1.9, "201220":1.9, "201221":0.8,
  "202001":6.4, "202011":5.1, "202021":2.0, "202101":4.7, "202111":2.1, "202121":1.1,
  "202201":2.4, "202211":0.9, "202221":0.4,
  "210000":8.8, "210001":7.5, "210010":7.3, "210011":5.3, "210020":6.0, "210021":5.0,
  "210100":7.3, "210101":5.5, "210110":5.9, "210111":4.0, "210120":4.1, "210121":2.0,
  "210200":5.4, "210201":4.3, "210210":4.5, "210211":2.2, "210220":2.0, "210221":1.1,
  "211000":7.5, "211001":5.5, "211010":5.8, "211011":4.5, "211020":4.0, "211021":2.1,
  "211100":6.1, "211101":5.1, "211110":4.8, "211111":1.8, "211120":2.0, "211121":0.9,
  "211200":4.6, "211201":1.8, "211210":1.7, "211211":0.7, "211220":0.8, "211221":0.2,
  "212001":5.3, "212011":2.4, "212021":1.4, "212101":2.4, "212111":1.2, "212121":0.5,
  "212201":1.0, "212211":0.3, "212221":0.1,
};

function calcCvss40Score(m: Record<string, string>): number {
  // All impact metrics None → score 0
  if (["VC","VI","VA","SC","SI","SA"].every(k => (m[k] ?? "N") === "N")) return 0.0;

  // Metric value getter with base-scoring defaults
  const get = (k: string): string => {
    if (k === "E")  return m[k] ?? "A";
    if (k === "CR") return m[k] ?? "H";
    if (k === "IR") return m[k] ?? "H";
    if (k === "AR") return m[k] ?? "H";
    return m[k] ?? "";
  };

  const av=get("AV"), pr=get("PR"), ui=get("UI"), ac=get("AC"), at=get("AT");
  const vc=get("VC"), vi=get("VI"), va=get("VA");
  const sc=get("SC"), si=get("SI"), sa=get("SA");
  const cr=get("CR"), ir=get("IR"), ar=get("AR");
  const e=get("E");

  // EQ level computation
  const eq1 = (av==="N"&&pr==="N"&&ui==="N") ? 0 : ((av==="N"||pr==="N"||ui==="N")&&av!=="P") ? 1 : 2;
  const eq2 = (ac==="L"&&at==="N") ? 0 : 1;
  const eq3 = (vc==="H"&&vi==="H") ? 0 : (vc==="H"||vi==="H"||va==="H") ? 1 : 2;
  const eq4 = (m["MSI"]==="S"||m["MSA"]==="S") ? 0 : (sc==="H"||si==="H"||sa==="H") ? 1 : 2;
  const eq5 = e==="A" ? 0 : e==="P" ? 1 : 2;
  const eq6 = ((cr==="H"&&vc==="H")||(ir==="H"&&vi==="H")||(ar==="H"&&va==="H")) ? 0 : 1;

  const macroVec = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const value = CVSS40_LOOKUP[macroVec];
  if (value === undefined) return 0.0;

  // Next-lower macro vectors (increment one EQ at a time)
  const n1 = `${eq1+1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const n2 = `${eq1}${eq2+1}${eq3}${eq4}${eq5}${eq6}`;
  const n4 = `${eq1}${eq2}${eq3}${eq4+1}${eq5}${eq6}`;
  const n5 = `${eq1}${eq2}${eq3}${eq4}${eq5+1}${eq6}`;

  // EQ3+EQ6 jointly decremented
  let n3_key: string | undefined;
  let n3_left: string | undefined;
  let n3_right: string | undefined;
  if (eq3===0 && eq6===0) {
    n3_left  = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`;
    n3_right = `${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`;
  } else if ((eq3===1&&eq6===1)||(eq3===0&&eq6===1)) {
    n3_key = `${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`;
  } else if (eq3===1&&eq6===0) {
    n3_key = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`;
  } else {
    n3_key = `${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6+1}`;
  }

  const s1 = CVSS40_LOOKUP[n1];
  const s2 = CVSS40_LOOKUP[n2];
  const s4 = CVSS40_LOOKUP[n4];
  const s5 = CVSS40_LOOKUP[n5];
  let s3: number | undefined;
  if (eq3===0 && eq6===0) {
    const sl = CVSS40_LOOKUP[n3_left!];
    const sr = CVSS40_LOOKUP[n3_right!];
    s3 = (sl!==undefined && sr!==undefined) ? Math.max(sl,sr) : (sl ?? sr);
  } else {
    s3 = CVSS40_LOOKUP[n3_key!];
  }

  // Highest-severity partial vectors for this macro-vector
  const vecs1 = CVSS40_MAX_VECS.eq1[eq1] ?? [];
  const vecs2 = CVSS40_MAX_VECS.eq2[eq2] ?? [];
  const vecs3 = ((CVSS40_MAX_VECS.eq3[eq3] ?? {}) as Record<number,string[]>)[eq6] ?? [];
  const vecs4 = CVSS40_MAX_VECS.eq4[eq4] ?? [];
  const vecs5 = CVSS40_MAX_VECS.eq5[eq5] ?? [];

  const maxVecs: string[] = [];
  for (const v1 of vecs1) for (const v2 of vecs2) for (const v3 of vecs3)
    for (const v4 of vecs4) for (const v5 of vecs5) maxVecs.push(v1+v2+v3+v4+v5);

  const extract = (metric: string, vec: string): string => {
    const pfx = metric + ":";
    const i = vec.indexOf(pfx);
    if (i < 0) return "";
    const rest = vec.slice(i + pfx.length);
    const s = rest.indexOf("/");
    return s >= 0 ? rest.slice(0, s) : rest;
  };

  // Find the max vector where all severity distances are >= 0
  let dAV=0,dPR=0,dUI=0,dAC=0,dAT=0;
  let dVC=0,dVI=0,dVA=0,dSC=0,dSI=0,dSA=0,dCR=0,dIR=0,dAR=0;

  for (const mv of maxVecs) {
    dAV=(AV40[av]??0)-(AV40[extract("AV",mv)]??0);
    dPR=(PR40[pr]??0)-(PR40[extract("PR",mv)]??0);
    dUI=(UI40[ui]??0)-(UI40[extract("UI",mv)]??0);
    dAC=(AC40[ac]??0)-(AC40[extract("AC",mv)]??0);
    dAT=(AT40[at]??0)-(AT40[extract("AT",mv)]??0);
    dVC=(VC40[vc]??0)-(VC40[extract("VC",mv)]??0);
    dVI=(VI40[vi]??0)-(VI40[extract("VI",mv)]??0);
    dVA=(VA40[va]??0)-(VA40[extract("VA",mv)]??0);
    dSC=(SC40[sc]??0)-(SC40[extract("SC",mv)]??0);
    dSI=(SI40[si]??0)-(SI40[extract("SI",mv)]??0);
    dSA=(SA40[sa]??0)-(SA40[extract("SA",mv)]??0);
    dCR=(CR40[cr]??0)-(CR40[extract("CR",mv)]??0);
    dIR=(IR40[ir]??0)-(IR40[extract("IR",mv)]??0);
    dAR=(AR40[ar]??0)-(AR40[extract("AR",mv)]??0);
    if ([dAV,dPR,dUI,dAC,dAT,dVC,dVI,dVA,dSC,dSI,dSA,dCR,dIR,dAR].every(d=>d>=0)) break;
  }

  const dist1    = dAV + dPR + dUI;
  const dist2    = dAC + dAT;
  const dist3eq6 = dVC + dVI + dVA + dCR + dIR + dAR;
  const dist4    = dSC + dSI + dSA;

  const step = 0.1;
  const maxSev1    = CVSS40_MAX_SEV.eq1[eq1] * step;
  const maxSev2    = CVSS40_MAX_SEV.eq2[eq2] * step;
  const maxSev3eq6 = CVSS40_MAX_SEV.eq3eq6[eq3][eq6] * step;
  const maxSev4    = CVSS40_MAX_SEV.eq4[eq4] * step;

  let n = 0, normSum = 0;
  if (s1 !== undefined) { n++; normSum += (value - s1) * (dist1 / maxSev1); }
  if (s2 !== undefined) { n++; normSum += (value - s2) * (dist2 / maxSev2); }
  if (s3 !== undefined) { n++; normSum += (value - s3) * (dist3eq6 / maxSev3eq6); }
  if (s4 !== undefined) { n++; normSum += (value - s4) * (dist4 / maxSev4); }
  if (s5 !== undefined) { n++; /* E=A in base scoring, distance=0 */ }

  const result = n === 0 ? value : value - normSum / n;
  return Math.round(Math.max(0, Math.min(10, result)) * 10) / 10;
}

// ── Severity from score ───────────────────────────────────────────────────────

function severityFromScore(score: number): string {
  if (score === 0)   return "None";
  if (score < 4.0)   return "Low";
  if (score < 7.0)   return "Medium";
  if (score < 9.0)   return "High";
  return "Critical";
}

// Maps CVSS score → Finding severity (5-level enum used in DB)
function findingSeverityFromScore(score: number): Finding["severity"] {
  if (score === 0)  return "Informational";
  if (score < 4.0)  return "Low";
  if (score < 7.0)  return "Medium";
  if (score < 9.0)  return "High";
  return "Critical";
}

// ── Vector builders ───────────────────────────────────────────────────────────

function buildVector31(m: Record<string, string>): string {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

function buildVector40(m: Record<string, string>): string {
  return `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}/VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`;
}

// ── Vector parsers ────────────────────────────────────────────────────────────

function parseMetrics(vector: string): Record<string, string> {
  const cleaned = vector.replace(/^CVSS:[0-9.]+\//, "");
  const result: Record<string, string> = {};
  for (const part of cleaned.split("/")) {
    const [k, v] = part.split(":");
    if (k && v) result[k] = v;
  }
  return result;
}

const DEFAULT_CVSS31: Record<string, string> = {
  AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N",
};
const DEFAULT_CVSS40: Record<string, string> = {
  AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
  VC: "N", VI: "N", VA: "N", SC: "N", SI: "N", SA: "N",
};

// ── Value display colors ──────────────────────────────────────────────────────

const VALUE_COLORS: Record<string, string> = {
  Network:   "bg-red-50 text-red-700 border border-red-200/70 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900/60",
  Adjacent:  "bg-orange-50 text-orange-700 border border-orange-200/70 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900/60",
  Local:     "bg-amber-50 text-amber-800 border border-amber-200/70 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900/60",
  Physical:  "bg-emerald-50 text-emerald-700 border border-emerald-200/70 dark:bg-emerald-950/50 dark:text-emerald-300 dark:border-emerald-900/60",
  High:      "bg-red-50 text-red-700 border border-red-200/70 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900/60",
  Medium:    "bg-orange-50 text-orange-700 border border-orange-200/70 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900/60",
  Low:       "bg-amber-50 text-amber-800 border border-amber-200/70 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900/60",
  None:      "bg-slate-100 text-slate-600 border border-slate-200/70 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700",
  Changed:   "bg-orange-50 text-orange-700 border border-orange-200/70 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900/60",
  Unchanged: "bg-slate-100 text-slate-600 border border-slate-200/70 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700",
  Required:  "bg-amber-50 text-amber-800 border border-amber-200/70 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900/60",
  Passive:   "bg-amber-50 text-amber-800 border border-amber-200/70 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-900/60",
  Active:    "bg-red-50 text-red-700 border border-red-200/70 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900/60",
  Present:   "bg-orange-50 text-orange-700 border border-orange-200/70 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900/60",
};

// ── Tooltip component ─────────────────────────────────────────────────────────

function Tooltip({ text }: { text: string }) {
  const [show, setShow] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  return (
    <div className="relative inline-flex" ref={ref}>
      <button
        type="button"
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        onFocus={() => setShow(true)}
        onBlur={() => setShow(false)}
        className="h-4 w-4 rounded-full bg-slate-200 text-slate-700 dark:text-zinc-300 text-[10px] font-bold flex items-center justify-center hover:bg-teal-100 dark:hover:bg-teal-900/50 hover:text-teal-700 dark:text-teal-300 transition-colors shrink-0"
        aria-label="Info"
      >
        !
      </button>
      {show && (
        <div className="absolute z-50 left-5 top-0 w-64 bg-slate-900 text-white text-xs rounded-lg p-2.5 shadow-xl leading-relaxed">
          {text}
          <div className="absolute top-1.5 -left-1 w-2 h-2 bg-slate-900 rotate-45" />
        </div>
      )}
    </div>
  );
}

// ── CVSS Editor ───────────────────────────────────────────────────────────────

function CvssEditor({
  version,
  metricDefs,
  groups,
  initialVector,
  onSave,
  isSaving,
}: {
  version: "3.1" | "4.0";
  metricDefs: typeof CVSS3_METRICS;
  groups: Array<{ label: string; tooltip: string; keys: string[] }>;
  initialVector: string | null;
  onSave: (vector: string, score: number) => void;
  isSaving: boolean;
}) {
  const defaults = version === "3.1" ? DEFAULT_CVSS31 : DEFAULT_CVSS40;
  const [editing, setEditing] = useState(false);

  const [metrics, setMetrics] = useState<Record<string, string>>(() => {
    if (initialVector) {
      const parsed = parseMetrics(initialVector);
      return { ...defaults, ...parsed };
    }
    return { ...defaults };
  });

  // Re-sync when finding data loads
  useEffect(() => {
    if (initialVector) {
      const parsed = parseMetrics(initialVector);
      setMetrics({ ...defaults, ...parsed });
    }
  }, [initialVector]);

  const liveScore = version === "3.1" ? calcCvss31Score(metrics) : calcCvss40Score(metrics);
  const liveVector = version === "3.1" ? buildVector31(metrics) : buildVector40(metrics);
  const liveSeverity = severityFromScore(liveScore);

  const handleSave = () => {
    onSave(liveVector, liveScore);
    setEditing(false);
  };

  const handleCancel = () => {
    if (initialVector) {
      const parsed = parseMetrics(initialVector);
      setMetrics({ ...defaults, ...parsed });
    } else {
      setMetrics({ ...defaults });
    }
    setEditing(false);
  };

  const scoreColor =
    liveScore >= 9.0 ? "bg-red-600 text-white" :
    liveScore >= 7.0 ? "bg-orange-500 text-white" :
    liveScore >= 4.0 ? "bg-yellow-500 text-white" :
    liveScore > 0    ? "bg-green-500 text-white" :
                       "bg-gray-300 text-slate-700 dark:text-zinc-300";

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-bold uppercase tracking-[0.1em] text-slate-500 dark:text-zinc-400">CVSS {version} Calculator</span>
        <div className="flex items-center gap-2">
          <span className={`text-xs font-bold px-2 py-0.5 rounded font-mono ${scoreColor}`}>
            {liveScore.toFixed(1)} {liveSeverity}
          </span>
          {!editing ? (
            <button
              onClick={() => setEditing(true)}
              className="flex items-center gap-1 text-xs text-teal-700 dark:text-teal-400 hover:text-teal-800 transition-colors"
              title="Edit metrics"
            >
              <Pencil className="h-3 w-3" />
              Edit
            </button>
          ) : (
            <div className="flex items-center gap-1">
              <button
                onClick={handleSave}
                disabled={isSaving}
                className="flex items-center gap-1 text-xs bg-teal-600 text-white px-2 py-0.5 rounded hover:bg-teal-700 disabled:opacity-50 transition-colors"
              >
                <Check className="h-3 w-3" />
                Save
              </button>
              <button
                onClick={handleCancel}
                className="flex items-center gap-1 text-xs text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300 transition-colors px-1"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Vector string */}
      <p className="text-[10px] text-slate-500 dark:text-zinc-400 font-mono break-all mb-2 leading-snug select-all">
        {liveVector}
      </p>

      {/* Metrics grouped */}
      <div className="space-y-0">
        {groups.map((group) => (
          <div key={group.label}>
            {/* Group header with ! tooltip */}
            <div className="flex items-center gap-1.5 mt-3 mb-1.5">
              <span className="text-[10px] font-semibold text-slate-500 dark:text-zinc-400 uppercase tracking-wide leading-none">
                {group.label}
              </span>
              <Tooltip text={group.tooltip} />
            </div>
            <div className="space-y-1.5">
              {metricDefs.filter(m => group.keys.includes(m.key)).map(({ key, label, tooltip, options }) => {
                const currentVal = metrics[key] ?? options[0].value;
                const currentLabel = options.find(o => o.value === currentVal)?.label ?? currentVal;
                return (
                  <div key={key} className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="text-xs text-slate-500 dark:text-zinc-400 leading-tight truncate">{label}</span>
                      <Tooltip text={tooltip} />
                    </div>
                    {editing ? (
                      <select
                        value={currentVal}
                        onChange={e => setMetrics(prev => ({ ...prev, [key]: e.target.value }))}
                        className="text-xs border border-teal-600/50 rounded px-1.5 py-0.5 bg-white dark:bg-zinc-900 focus:outline-none focus:ring-1 focus:ring-teal-400 shrink-0 max-w-[130px]"
                      >
                        {options.map(o => (
                          <option key={o.value} value={o.value}>{o.label}</option>
                        ))}
                      </select>
                    ) : (
                      <span className={`text-xs font-medium px-2 py-0.5 rounded shrink-0 ${VALUE_COLORS[currentLabel] ?? "bg-slate-100 text-slate-600 border border-slate-200/70 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700"}`}>
                        {currentLabel}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Markdown content renderer ─────────────────────────────────────────────────

function MarkdownContent({ children, dark = false }: { children: string; dark?: boolean }) {
  if (!children?.trim()) {
    return <span className={`italic text-[12px] ${dark ? "text-slate-500 dark:text-zinc-400" : "text-slate-500 dark:text-zinc-400"}`}>Not available</span>;
  }
  const prose = dark ? "text-slate-700 dark:text-zinc-300" : "text-slate-700 dark:text-zinc-300";
  const strong = dark ? "text-white" : "text-slate-800 dark:text-zinc-200";
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        code({ inline, children: c, ...props }: any) {
          if (inline) {
            return (
              <code className={`text-[11px] font-mono px-1 py-0.5 rounded ${dark ? "bg-slate-700 text-green-300" : "bg-slate-100 dark:bg-zinc-800 text-slate-700 dark:text-zinc-300"}`} {...props}>
                {c}
              </code>
            );
          }
          return (
            <pre className="my-2 bg-[#0d1117] text-[#7ee787] text-[11px] font-mono px-3 py-2.5 rounded-lg overflow-x-auto whitespace-pre-wrap leading-relaxed border border-slate-700/40">
              <code>{c}</code>
            </pre>
          );
        },
        p({ children: c }) { return <p className={`text-[12px] leading-relaxed mb-2 last:mb-0 ${prose}`}>{c}</p>; },
        ul({ children: c }) { return <ul className={`list-disc list-outside pl-4 space-y-0.5 text-[12px] my-1.5 ${prose}`}>{c}</ul>; },
        ol({ children: c }) { return <ol className={`list-decimal list-outside pl-4 space-y-0.5 text-[12px] my-1.5 ${prose}`}>{c}</ol>; },
        li({ children: c }) { return <li className="leading-relaxed">{c}</li>; },
        strong({ children: c }) { return <strong className={`font-semibold ${strong}`}>{c}</strong>; },
        h1({ children: c }) { return <h1 className={`text-[14px] font-bold mt-3 mb-1.5 ${strong}`}>{c}</h1>; },
        h2({ children: c }) { return <h2 className={`text-[12px] font-bold mt-2 mb-1 ${strong}`}>{c}</h2>; },
        h3({ children: c }) { return <h3 className={`text-[11px] font-bold uppercase tracking-wide mt-2 mb-1 ${dark ? "text-slate-700 dark:text-zinc-300" : "text-slate-700 dark:text-zinc-300"}`}>{c}</h3>; },
        a({ href, children: c }) { return <a href={href} target="_blank" rel="noopener noreferrer" className="text-teal-500 hover:underline">{c}</a>; },
        blockquote({ children: c }) { return <blockquote className={`border-l-2 pl-3 italic my-2 ${dark ? "border-slate-600 text-slate-500 dark:text-zinc-400" : "border-slate-300 dark:border-zinc-600 text-slate-500 dark:text-zinc-400"}`}>{c}</blockquote>; },
        hr() { return <hr className={`my-3 border-0 border-t ${dark ? "border-slate-700" : "border-slate-200 dark:border-zinc-800"}`} />; },
      }}
    >
      {children}
    </ReactMarkdown>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [comment, setComment] = useState("");

  const { data: finding } = useQuery<Finding>({
    queryKey: ["finding", id],
    queryFn: () => findingsApi.get(id!),
  });

  const { data: comments = [] } = useQuery({
    queryKey: ["comments", id],
    queryFn: () => findingsApi.listComments(id!),
  });

  const invalidateFinding = () => {
    qc.invalidateQueries({ queryKey: ["finding", id] });
    // Also refresh the findings list on ScanDetailPage and FindingListPage
    if (finding?.scan_id) {
      qc.invalidateQueries({ queryKey: ["findings", finding.scan_id] });
    }
    qc.invalidateQueries({ queryKey: ["findings"] });
  };

  const statusMutation = useMutation({
    mutationFn: (status: Finding["status"]) => findingsApi.update(id!, { status }),
    onSuccess: invalidateFinding,
  });

  const cvssMutation = useMutation({
    mutationFn: (data: Partial<Finding>) => findingsApi.update(id!, data),
    onSuccess: invalidateFinding,
  });

  const verificationMutation = useMutation({
    mutationFn: (verification_status: Finding["verification_status"]) =>
      findingsApi.update(id!, { verification_status }),
    onSuccess: invalidateFinding,
  });

  const evidenceMutation = useMutation({
    mutationFn: (data: { raw_request: string; raw_response: string }) =>
      findingsApi.update(id!, data),
    onSuccess: invalidateFinding,
  });

  const commentMutation = useMutation({
    mutationFn: (body: string) => findingsApi.addComment(id!, body),
    onSuccess: () => {
      setComment("");
      qc.invalidateQueries({ queryKey: ["comments", id] });
    },
  });

  const deleteCommentMutation = useMutation({
    mutationFn: (commentId: string) => findingsApi.deleteComment(id!, commentId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["comments", id] }),
  });

  const retestMutation = useMutation({
    mutationFn: () => findingsApi.retest(id!),
    onSuccess: (data) => {
      navigate(`/scans/${data.scan_id}`);
    },
  });

  if (!finding) return <div className="text-slate-500 dark:text-zinc-400 text-sm p-8">Loading…</div>;

  const refUrls = finding.references
    ? finding.references.split("\n").map((u) => u.trim()).filter(Boolean)
    : [];
  const accent = SEV_ACCENT[finding.severity] ?? "#a1a1aa";

  return (
    <div className="space-y-3 pb-8">

      {/* ── Header card ─────────────────────────────────────────────────────── */}
      <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm">
        <div className="h-[3px] rounded-t-xl" style={{ backgroundColor: accent }} />
        <div className="px-5 py-4">
          {/* Breadcrumb */}
          <div className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-zinc-400 mb-3">
            <button onClick={() => navigate("/findings")} className="hover:text-teal-700 dark:text-teal-400 transition-colors">Findings</button>
            <ChevronRight className="h-3 w-3" />
            <span className="text-slate-700 dark:text-zinc-300 font-medium">{finding.finding_ref || finding.id.slice(0, 8)}</span>
          </div>

          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              {/* Badge row */}
              <div className="flex flex-wrap items-center gap-1.5 mb-2">
                <span className={`text-[11px] px-2 py-0.5 rounded font-bold ${SEVERITY_COLORS[finding.severity]}`}>
                  {finding.severity}
                </span>
                {finding.cvss_score != null && (
                  <span className="text-[11px] bg-slate-100 dark:bg-zinc-800 text-slate-700 dark:text-zinc-300 px-2 py-0.5 rounded font-mono">
                    CVSS 3.1: {finding.cvss_score.toFixed(1)}
                  </span>
                )}
                {finding.cvss4_score != null && (
                  <span className={`text-[11px] px-2 py-0.5 rounded font-mono border ${TONE_BADGE.indigo}`}>
                    CVSS 4.0: {finding.cvss4_score.toFixed(1)}
                  </span>
                )}
                {finding.owasp_category && (
                  <span className="text-[11px] bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400 px-2 py-0.5 rounded font-mono">
                    {finding.owasp_category}
                  </span>
                )}
                {finding.cve && (
                  <a href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`} target="_blank" rel="noopener noreferrer"
                    className={`text-[11px] px-2 py-0.5 rounded flex items-center gap-1 border hover:opacity-90 transition-colors ${TONE_BADGE.teal}`}>
                    {finding.cve} <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
                <ConfidenceBadge score={finding.confidence_score ?? 0} hasPoc={finding.has_poc ?? false} />
                <VerificationPill status={finding.verification_status ?? "Unverified"} />
              </div>

              <h1 className="text-[20px] font-bold text-slate-800 dark:text-zinc-200 leading-snug">{finding.title}</h1>

              {finding.location && (
                <div className="mt-2 flex items-center gap-2 flex-wrap">
                  {finding.source_repo_url && (
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${TONE_BADGE.indigo}`}>
                      {finding.source_repo_url ? "Vulnerable Code" : ""}
                    </span>
                  )}
                  <code className="text-[11px] bg-slate-100 dark:bg-zinc-800 text-slate-700 dark:text-zinc-300 px-2 py-1 rounded inline-block break-all font-mono">
                    {finding.location}
                  </code>
                  {finding.source_repo_url && (
                    <code className="text-[10px] text-indigo-400 font-mono break-all"
                          title={finding.source_repo_url}>
                      {finding.source_repo_url.replace(/^https?:\/\/(www\.)?/, "").replace(/\.git$/, "")}
                    </code>
                  )}
                </div>
              )}
            </div>

            <div className="shrink-0 text-right space-y-2">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500 dark:text-zinc-400 mb-1.5">Status</p>
                <StatusDropdown value={finding.status} onChange={(v) => statusMutation.mutate(v)} saving={statusMutation.isPending} />
              </div>
              <button
                onClick={() => retestMutation.mutate()}
                disabled={retestMutation.isPending}
                title="Spawn a focused engagement to re-validate this finding"
                className="inline-flex items-center gap-1.5 text-[11px] font-semibold px-3 py-1.5 rounded-lg
                  bg-teal-700 text-white dark:bg-teal-700 dark:text-teal-50 hover:bg-teal-700 dark:hover:bg-teal-500 disabled:opacity-50 transition-colors
                  shadow-[0_0_16px_-6px_rgba(45,212,191,0.55)]"
              >
                {retestMutation.isPending
                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  : <RotateCcw className="h-3.5 w-3.5" />}
                {retestMutation.isPending ? "Queuing…" : "Retest"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Flow — full bleed (not squeezed by the classification sidebar) */}
      <FindingFlowCard findingId={finding.id} severity={finding.severity} />

      {/* ── Content grid ────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-12 gap-3">

        {/* Left: main content */}
        <div className="col-span-8 space-y-3">

          {/* Description */}
          <SectionCard title="Description">
            <MarkdownContent>{finding.description || ""}</MarkdownContent>
          </SectionCard>

          {/* Proof of Concept */}
          <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
            <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center justify-between">
              <h3 className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">
                {finding.source_repo_url ? "Vulnerable Code & Fix" : "Proof of Concept"}
              </h3>
              {finding.proof_of_concept && (
                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${TONE_BADGE.emerald}`}>
                  {finding.source_repo_url ? "Code Review" : "Evidence"}
                </span>
              )}
            </div>
            <div className="bg-[#0d1117] px-4 py-3.5 min-h-[80px]">
              {finding.proof_of_concept
                ? <MarkdownContent dark>{finding.proof_of_concept}</MarkdownContent>
                : <p className="text-zinc-500 text-[12px] italic">No proof of concept recorded.</p>
              }
            </div>
          </div>

          {/* Which scan-level attack chains this finding takes part in */}
          <FindingChainsCard scanId={finding.scan_id} findingRef={finding.finding_ref ?? null} />

          {/* Implications */}
          {finding.implications && (
            <SectionCard title="Implications">
              <MarkdownContent>{finding.implications}</MarkdownContent>
            </SectionCard>
          )}

          {/* Recommendations */}
          {finding.recommendations && (
            <SectionCard title="Recommendations">
              <MarkdownContent>{finding.recommendations}</MarkdownContent>
            </SectionCard>
          )}

          {/* Screenshots */}
          {(finding.screenshot_before || finding.screenshot_after) && (
            <SectionCard title="Evidence Screenshots">
              <div className="grid grid-cols-2 gap-3">
                {finding.screenshot_before && <ScreenshotCard label="Before: normal state" path={finding.screenshot_before} />}
                {finding.screenshot_after  && <ScreenshotCard label="After: exploit result" path={finding.screenshot_after} />}
              </div>
            </SectionCard>
          )}

          {/* Raw HTTP Evidence */}
          <RawEvidenceCard
            rawRequest={finding.raw_request ?? null}
            rawResponse={finding.raw_response ?? null}
            evidenceSource={finding.evidence_source ?? null}
            evidenceAddedBy={finding.evidence_added_by ?? null}
            evidenceAddedAt={finding.evidence_added_at ?? null}
            onSave={(raw_request, raw_response) => evidenceMutation.mutate({ raw_request, raw_response })}
            saving={evidenceMutation.isPending}
          />

          {/* Discussion */}
          <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
            <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-2">
              <h3 className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Discussion</h3>
              {comments.length > 0 && (
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400">{comments.length}</span>
              )}
            </div>
            <div className="p-4">
              {comments.length === 0 && (
                <div className="flex flex-col items-center justify-center py-6 border border-dashed border-slate-200 dark:border-zinc-800 rounded-lg mb-3 bg-slate-50 dark:bg-zinc-900/50">
                  <Send className="h-4 w-4 text-slate-700 dark:text-zinc-300 mb-1.5" />
                  <p className="text-[12px] text-slate-500 dark:text-zinc-400">No comments yet. Start the discussion below.</p>
                </div>
              )}
              <div className="space-y-2 mb-3">
                {comments.map((c) => (
                  <div key={c.id} className="group bg-slate-100 dark:bg-zinc-800/50 border border-slate-200 dark:border-zinc-800 rounded-lg p-3 hover:border-teal-700/50 transition-colors">
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2">
                        <div className="w-5 h-5 rounded-full bg-gradient-to-br from-teal-400 to-teal-600 flex items-center justify-center text-white text-[9px] font-bold shrink-0">
                          {c.author_name.slice(0, 1).toUpperCase()}
                        </div>
                        <span className="text-[11px] font-semibold text-slate-700 dark:text-zinc-300">{c.author_name}</span>
                        <span className="text-[10px] text-slate-500 dark:text-zinc-400">
                          {new Date(c.created_at).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}
                        </span>
                      </div>
                      <button onClick={() => deleteCommentMutation.mutate(c.id)} disabled={deleteCommentMutation.isPending}
                        className="opacity-0 group-hover:opacity-100 p-1 rounded text-slate-500 dark:text-zinc-400 hover:text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-all">
                        <X className="h-3 w-3" />
                      </button>
                    </div>
                    <p className="text-[12px] text-slate-700 dark:text-zinc-300 leading-relaxed ml-7">{c.body}</p>
                  </div>
                ))}
              </div>
              <div className="flex gap-2 items-center">
                <input
                  type="text"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter" && comment.trim()) commentMutation.mutate(comment.trim()); }}
                  placeholder="Add a comment… (Enter to send)"
                  className="flex-1 text-[12px] border border-slate-200 dark:border-zinc-800 rounded-lg px-3 py-2 focus:outline-none focus:ring-1 focus:ring-teal-300 focus:border-teal-400 bg-white dark:bg-zinc-900 placeholder:text-slate-500 dark:text-zinc-400"
                />
                <button
                  onClick={() => comment.trim() && commentMutation.mutate(comment.trim())}
                  disabled={!comment.trim() || commentMutation.isPending}
                  className="px-3 py-2 bg-teal-600 text-white rounded-lg disabled:opacity-40 hover:bg-teal-700 transition-colors flex items-center gap-1.5 text-[12px] font-medium shrink-0"
                >
                  <Send className="h-3 w-3" />
                  Send
                </button>
              </div>
            </div>
          </div>

        </div>

        {/* Right: sidebar */}
        <div className="col-span-4">
          <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">

            {/* Classification */}
            <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center gap-2">
              <Shield className="h-3.5 w-3.5 text-teal-500" />
              <h3 className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">Classification</h3>
            </div>
            <div className="px-4 py-3 space-y-1.5">
              <MetaRow label="Type"  value={finding.vuln_type || "-"} />
              <MetaRow label="OWASP" value={finding.owasp_name ? `${finding.owasp_category}: ${finding.owasp_name}` : " - "} />
              <MetaRow label="Scan"  value={<a href={`/scans/${finding.scan_id}`} className="text-teal-700 dark:text-teal-400 hover:underline text-[11px]">{finding.scan_id.slice(0, 8)}</a>} />
              <MetaRow label="Phase" value={finding.source_phase ? <span className="capitalize">{finding.source_phase}</span> : " - "} />
              <MetaRow label="Tool"  value={finding.source_tool || "-"} />
              {finding.cve && (
                <MetaRow label="CVE" value={
                  <a href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`} target="_blank" rel="noopener noreferrer"
                    className="text-teal-700 dark:text-teal-400 hover:underline flex items-center gap-1 text-[11px]">
                    {finding.cve} <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                } />
              )}
            </div>

            {/* Verification */}
            <div className="border-t border-slate-200 dark:border-zinc-800 px-4 py-3">
              <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400 mb-2">Verification</p>
              <VerificationDropdown
                value={finding.verification_status ?? "Unverified"}
                onChange={(v) => verificationMutation.mutate(v)}
                saving={verificationMutation.isPending}
              />
            </div>

            {/* CVSS 3.1 */}
            <div className="border-t border-slate-200 dark:border-zinc-800 px-4 py-3">
              <CvssEditor version="3.1" metricDefs={CVSS3_METRICS} groups={CVSS3_GROUPS}
                initialVector={finding.cvss_vector ?? null} isSaving={cvssMutation.isPending}
                onSave={(vector, score) => cvssMutation.mutate({ cvss_vector: vector, cvss_score: score, severity: findingSeverityFromScore(score) })}
              />
            </div>

            {/* CVSS 4.0 */}
            <div className="border-t border-slate-200 dark:border-zinc-800 px-4 py-3">
              <CvssEditor version="4.0" metricDefs={CVSS4_METRICS} groups={CVSS4_GROUPS}
                initialVector={finding.cvss4_vector ?? null} isSaving={cvssMutation.isPending}
                onSave={(vector, score) => cvssMutation.mutate({ cvss4_vector: vector, cvss4_score: score, severity: findingSeverityFromScore(score) })}
              />
            </div>

            {/* References */}
            {refUrls.length > 0 && (
              <div className="border-t border-slate-200 dark:border-zinc-800 px-4 py-3">
                <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400 mb-2">References</p>
                <div className="space-y-1.5">
                  {refUrls.map((url, i) => (
                    <a key={i} href={url} target="_blank" rel="noopener noreferrer"
                      className="flex items-start gap-1.5 text-[11px] text-teal-700 dark:text-teal-400 hover:text-teal-800 hover:underline">
                      <ExternalLink className="h-2.5 w-2.5 shrink-0 mt-0.5" />
                      <span className="break-all leading-snug">{url}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}

          </div>
        </div>

      </div>
    </div>
  );
}

// ── Confidence Badge ───────────────────────────────────────────────────────────

function ConfidenceBadge({ score, hasPoc }: { score: number; hasPoc: boolean }) {
  let label: string;
  let cls: string;
  if (score >= 80) {
    label = "HIGH CONFIDENCE";
    cls = TONE_BADGE.emerald;
  } else if (score >= 40) {
    label = "MED CONFIDENCE";
    cls = TONE_BADGE.amber;
  } else {
    label = hasPoc ? "LOW CONFIDENCE" : "NO EVIDENCE";
    cls = hasPoc ? TONE_BADGE.orange : TONE_BADGE.red;
  }
  return (
    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide ${cls}`}>
      {label}
    </span>
  );
}

// ── Verification Pill ──────────────────────────────────────────────────────────

function VerificationPill({ status }: { status: Finding["verification_status"] }) {
  const cfg: Record<Finding["verification_status"], { label: string; cls: string }> = {
    "Unverified":    { label: "Unverified",    cls: TONE_BADGE.slate },
    "Verified":      { label: "Verified",      cls: TONE_BADGE.emerald },
    "False Positive":{ label: "False Positive",cls: "bg-purple-50 text-purple-800 border border-purple-200 dark:bg-purple-950/50 dark:text-purple-300 dark:border-purple-800/50" },
  };
  const { label, cls } = cfg[status] ?? cfg["Unverified"];
  return (
    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide ${cls}`}>
      {label}
    </span>
  );
}

// ── Verification Dropdown ──────────────────────────────────────────────────────

const VERIFICATION_OPTIONS: Array<{
  value: Finding["verification_status"];
  label: string;
  cls: string;
}> = [
  { value: "Unverified",     label: "Unverified",     cls: "text-slate-700 dark:text-zinc-300" },
  { value: "Verified",       label: "Verified",       cls: "text-emerald-700" },
  { value: "False Positive", label: "False Positive", cls: "text-purple-700" },
];

function VerificationDropdown({
  value,
  onChange,
  saving,
}: {
  value: Finding["verification_status"];
  onChange: (v: Finding["verification_status"]) => void;
  saving: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = VERIFICATION_OPTIONS.find((o) => o.value === value) ?? VERIFICATION_OPTIONS[0];

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        disabled={saving}
        className="w-full flex items-center justify-between gap-2 border border-slate-200 dark:border-zinc-800 rounded-lg px-3 py-2 text-[11px] font-semibold bg-white dark:bg-zinc-900 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors disabled:opacity-60"
      >
        <span className={current.cls}>{current.label}</span>
        <ChevronDown className="h-3 w-3 text-slate-500 dark:text-zinc-400 shrink-0" />
      </button>
      {open && (
        <div className="absolute left-0 right-0 top-full mt-1 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 rounded-lg shadow-lg z-20 overflow-hidden">
          {VERIFICATION_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => { onChange(opt.value); setOpen(false); }}
              className={`w-full text-left px-3 py-2 text-[11px] font-semibold hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors ${opt.cls} ${opt.value === value ? "bg-slate-50 dark:bg-zinc-900/60" : ""}`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Raw HTTP Evidence Card ─────────────────────────────────────────────────────

function RawEvidenceCard({
  rawRequest,
  rawResponse,
  evidenceSource,
  evidenceAddedBy,
  evidenceAddedAt,
  onSave,
  saving,
}: {
  rawRequest: string | null;
  rawResponse: string | null;
  evidenceSource: string | null;
  evidenceAddedBy: string | null;
  evidenceAddedAt: string | null;
  onSave: (req: string, res: string) => void;
  saving: boolean;
}) {
  const hasEvidence = !!(rawRequest || rawResponse);
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing] = useState(false);
  const [req, setReq] = useState(rawRequest ?? "");
  const [res, setRes] = useState(rawResponse ?? "");
  const isManual = evidenceSource === "manual";

  // Re-seed the editor whenever the server copy changes (e.g. after a save).
  useEffect(() => {
    if (!editing) {
      setReq(rawRequest ?? "");
      setRes(rawResponse ?? "");
    }
  }, [rawRequest, rawResponse, editing]);

  const startEdit = () => { setEditing(true); setExpanded(true); };
  const cancel = () => { setEditing(false); setReq(rawRequest ?? ""); setRes(rawResponse ?? ""); };
  const dirty = req !== (rawRequest ?? "") || res !== (rawResponse ?? "");

  return (
    <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800 flex items-center justify-between gap-2">
        <h3 className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">HTTP Evidence</h3>
        <div className="flex items-center gap-2">
          {hasEvidence ? (
            isManual ? (
              <span
                className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${TONE_BADGE.amber}`}
                title="Supplied by an analyst, not captured by the agent"
              >
                Analyst-supplied
              </span>
            ) : (
              <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${TONE_BADGE.emerald}`}>
                Agent-captured
              </span>
            )
          ) : (
            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${TONE_BADGE.red}`}>
              No Evidence
            </span>
          )}
          {hasEvidence && !editing && (
            <button
              onClick={() => setExpanded((e) => !e)}
              className="text-[10px] text-teal-700 dark:text-teal-400 hover:text-teal-800 font-medium"
            >
              {expanded ? "Collapse" : "Expand"}
            </button>
          )}
          {!editing && (
            <button
              onClick={startEdit}
              className="flex items-center gap-1 text-[10px] text-slate-500 dark:text-zinc-400 hover:text-slate-800 dark:text-zinc-200 font-medium"
            >
              <Pencil className="h-3 w-3" />
              {hasEvidence ? "Edit" : "Add"}
            </button>
          )}
        </div>
      </div>

      {/* Attribution line — who supplied what is on record, never inferred */}
      {isManual && evidenceAddedBy && !editing && (
        <div className="px-4 py-1.5 bg-amber-50/60 dark:bg-amber-950/30 border-b border-amber-100 dark:border-amber-900/40">
          <p className="text-[10px] text-amber-800 dark:text-amber-300">
            Reproduced manually by <span className="font-semibold">{evidenceAddedBy}</span>
            {evidenceAddedAt && ` · ${new Date(evidenceAddedAt).toLocaleString()}`}
          </p>
        </div>
      )}

      {editing ? (
        <div className="px-4 py-3 space-y-3">
          <p className="text-[10px] text-slate-500 dark:text-zinc-400 leading-relaxed">
            Paste the request and response you reproduced by hand. This is stored as
            analyst-supplied evidence and never counts as agent-captured proof. The
            confidence score stays untouched.
          </p>
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wide text-slate-500 dark:text-zinc-400">Request</label>
            <textarea
              value={req}
              onChange={(e) => setReq(e.target.value)}
              rows={6}
              spellCheck={false}
              placeholder={"POST /login HTTP/1.1\nHost: target\n\nuid=1' OR '1'='1"}
              className="mt-1 w-full text-[10px] font-mono bg-[#0d1117] text-green-300 rounded p-2.5 border border-slate-700 focus:outline-none focus:ring-1 focus:ring-teal-500 placeholder:text-slate-700 dark:text-zinc-300"
            />
          </div>
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wide text-slate-500 dark:text-zinc-400">Response</label>
            <textarea
              value={res}
              onChange={(e) => setRes(e.target.value)}
              rows={6}
              spellCheck={false}
              placeholder={"HTTP/1.1 200 OK\n\nWelcome back, admin"}
              className="mt-1 w-full text-[10px] font-mono bg-[#0d1117] text-blue-700 dark:text-blue-300 rounded p-2.5 border border-slate-700 focus:outline-none focus:ring-1 focus:ring-teal-500 placeholder:text-slate-700 dark:text-zinc-300"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => { onSave(req, res); setEditing(false); }}
              disabled={saving || !dirty}
              className="text-[11px] font-semibold px-3 py-1.5 rounded bg-teal-600 text-white hover:bg-teal-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {saving ? "Saving…" : "Save evidence"}
            </button>
            <button
              onClick={cancel}
              className="text-[11px] font-medium px-3 py-1.5 rounded border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors"
            >
              Cancel
            </button>
            {(rawRequest || rawResponse) && !req.trim() && !res.trim() && (
              <span className="text-[10px] text-red-500">Saving empty fields removes the evidence.</span>
            )}
          </div>
        </div>
      ) : hasEvidence && expanded ? (
        <div className="divide-y divide-zinc-700/60">
          {rawRequest && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wide text-slate-500 dark:text-zinc-400 px-4 pt-2.5 pb-1">Request</p>
              <pre className="px-4 pb-3 text-[10px] font-mono text-green-300 bg-[#0d1117] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {rawRequest}
              </pre>
            </div>
          )}
          {rawResponse && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wide text-slate-500 dark:text-zinc-400 px-4 pt-2.5 pb-1">Response</p>
              <pre className="px-4 pb-3 text-[10px] font-mono text-blue-700 dark:text-blue-300 bg-[#0d1117] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {rawResponse}
              </pre>
            </div>
          )}
        </div>
      ) : !hasEvidence ? (
        <div className="px-4 py-3">
          <p className="text-[11px] text-slate-500 dark:text-zinc-400 italic">
            No raw HTTP request/response was captured for this finding. Reproduce it by hand
            and use <span className="font-medium not-italic text-slate-500 dark:text-zinc-400">Add</span> to attach the proof.
          </p>
        </div>
      ) : null}
    </div>
  );
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-zinc-900 rounded-xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden">
      <div className="px-4 py-2.5 border-b border-slate-200 dark:border-zinc-800">
        <h3 className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-zinc-400">{title}</h3>
      </div>
      <div className="px-4 py-3">{children}</div>
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[4.5rem_1fr] gap-x-2 items-start">
      <span className="text-[10px] text-slate-500 dark:text-zinc-400 pt-0.5 shrink-0 font-medium">{label}</span>
      <span className="text-[11px] font-medium text-slate-700 dark:text-zinc-300 break-words leading-snug">{value}</span>
    </div>
  );
}

function ScreenshotCard({ label, path }: { label: string; path: string }) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [lightbox, setLightbox] = useState(false);

  useEffect(() => {
    const encodedPath = path.split("/").map(encodeURIComponent).join("/");
    const token = localStorage.getItem("access_token");
    fetch(`/api/v1/evidence/${encodedPath}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status}`);
        return r.blob();
      })
      .then((blob) => setBlobUrl(URL.createObjectURL(blob)))
      .catch(() => setError(true));
    return () => { if (blobUrl) URL.revokeObjectURL(blobUrl); };
  }, [path]);

  return (
    <>
      <div className="border border-border rounded-lg overflow-hidden">
        <div className="text-xs font-medium text-slate-700 dark:text-zinc-300 px-2 py-1.5 border-b border-border bg-muted/40">{label}</div>
        {error ? (
          <div className="text-xs text-muted-foreground px-3 py-6 text-center">Screenshot not available</div>
        ) : blobUrl ? (
          <div className="relative group cursor-zoom-in" onClick={() => setLightbox(true)}>
            <img src={blobUrl} alt={label} className="w-full object-cover" />
            <div className="absolute inset-0 bg-black/0 group-hover:bg-black/20 transition-colors flex items-center justify-center">
              <span className="opacity-0 group-hover:opacity-100 text-white text-xs font-medium bg-black/60 px-2 py-1 rounded transition-opacity">
                Click to enlarge
              </span>
            </div>
          </div>
        ) : (
          <div className="text-xs text-muted-foreground px-3 py-6 text-center animate-pulse">Loading screenshot…</div>
        )}
      </div>

      {lightbox && blobUrl && (
        <div
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
          onClick={() => setLightbox(false)}
        >
          <div className="relative max-w-5xl max-h-full" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-white text-sm font-medium">{label}</span>
              <button
                onClick={() => setLightbox(false)}
                className="text-white/70 hover:text-white text-xl leading-none ml-4"
              >
                ✕
              </button>
            </div>
            <img src={blobUrl} alt={label} className="max-w-full max-h-[80vh] rounded-lg object-contain shadow-2xl" />
          </div>
        </div>
      )}
    </>
  );
}
