import api from "./client";

export interface ScanCreate {
  target_url: string;
  scan_mode?: "full" | "static_only";
  llm_provider?:
    | "anthropic" | "openai" | "openrouter" | "ollama"
    | "mistral" | "groq" | "xai" | "deepseek" | "kimi" | "zai";
  llm_model?: string;
  /** Source Code Review: a public GitHub/GitLab repo URL. When set, the backend
   *  clones and analyses the code instead of crawling target_url. */
  source_repo_url?: string;
  project_id?: string;
  scope_include?: string[];
  scope_exclude?: string[];
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  max_hypotheses?: number;
  max_parallel?: number;
  feedback_iter?: number;
  repo_path?: string;
  custom_prompt?: string;
  target_description?: string;
  exploit_hypo_timeout?: number;
  exploit_max_turns?: number;
  exploit_hypo_cap?: number;
  token_budget?: number;
  turn_budget?: number;
  hitl_required?: boolean;
  scope_deny?: string[];
}

export interface Scan {
  id: string;
  target_url: string;
  scan_mode: string;
  /** Set when this scan is a Source Code Review (a cloned GitHub/GitLab repo). */
  source_repo_url?: string | null;
  llm_provider: string;
  llm_model: string | null;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  phase: string | null;
  phase_detail: string | null;
  project_id: string | null;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  findings_info: number;
  hypotheses_total: number;
  hypotheses_confirmed: number;
  hypotheses_tested: number;
  duration_seconds: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  error_message: string | null;
  custom_prompt: string | null;
  target_description: string | null;
  max_hypotheses: number;
  max_parallel: number;
  feedback_iter: number;
  exploit_hypo_timeout: number;
  exploit_max_turns: number;
  exploit_hypo_cap: number;
}

export interface ScanLog {
  id: number;
  ts: string;
  level: string;
  phase: string;
  message: string;
}

export const scansApi = {
  list: async (params?: { status?: string; project_id?: string; limit?: number }) => {
    const res = await api.get<Scan[]>("/scans", { params });
    return res.data;
  },

  get: async (id: string) => {
    const res = await api.get<Scan>(`/scans/${id}`);
    return res.data;
  },

  create: async (data: ScanCreate) => {
    const res = await api.post<Scan>("/scans", data);
    return res.data;
  },

  cancel: async (id: string) => {
    await api.post(`/scans/${id}/cancel`);
  },

  rerun: async (id: string) => {
    const res = await api.post<Scan>(`/scans/${id}/rerun`);
    return res.data;
  },

  delete: async (id: string) => {
    await api.delete(`/scans/${id}`);
  },

  getLogs: async (id: string, params?: { limit?: number; offset?: number }) => {
    const res = await api.get<ScanLog[]>(`/scans/${id}/logs`, { params });
    return res.data;
  },
};
