import api from "./client";

export interface WorkflowNode {
  id: string;
  kind: "target" | "finding" | "impact";
  label: string;
  detail: string;
  stage: string;
  stage_label: string;
  column: number;
  row: number;
  severity: string | null;
  category?: string;
  finding_id: string | null;
  finding_ref: string | null;
  has_poc?: boolean;
  confidence?: number;
  chains: string[];
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  kind: "chain" | "standalone";
  chains: string[];
}

export interface WorkflowColumn {
  column: number;
  key: string;
  label: string;
}

export interface WorkflowGraph {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  columns: WorkflowColumn[];
}

export interface ChainStep {
  order: number;
  stage: string;
  stage_label: string;
  action: string;
  finding_id: string | null;
  finding_ref: string | null;
  finding_title: string;
  severity: string;
  location: string;
  evidence: string;
}

export interface AttackChain {
  id: string;
  name: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  confidence: number;
  evidence_backed: boolean;
  source: "heuristic" | "llm";
  order: number;
  terminal: string;
  impact: string;
  finding_ids: string[];
  finding_refs: string[];
  steps: ChainStep[];
}

export interface AttackWorkflow {
  id: string;
  scan_id: string;
  finding_id: string | null;
  kind: "scan" | "finding";
  generator: string;
  llm_model: string | null;
  summary: string;
  graph: WorkflowGraph;
  chains: AttackChain[];
  mermaid: string;
  node_count: number;
  edge_count: number;
  chain_count: number;
  stages: { key: string; label: string }[];
  created_at: string | null;
  updated_at: string | null;
}

export const workflowsApi = {
  getForScan: async (scanId: string) => {
    const res = await api.get<AttackWorkflow>(`/scans/${scanId}/workflow`);
    return res.data;
  },

  generateForScan: async (scanId: string, useLlm = true) => {
    const res = await api.post<AttackWorkflow>(
      `/scans/${scanId}/workflow`, null, { params: { use_llm: useLlm } },
    );
    return res.data;
  },

  getForFinding: async (findingId: string) => {
    const res = await api.get<AttackWorkflow>(`/findings/${findingId}/workflow`);
    return res.data;
  },

  generateForFinding: async (findingId: string) => {
    const res = await api.post<AttackWorkflow>(`/findings/${findingId}/workflow`);
    return res.data;
  },
};
