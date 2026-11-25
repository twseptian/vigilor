import api from "./client";

export interface Finding {
  id: string;
  scan_id: string;
  finding_ref: string | null;
  title: string;
  vuln_type: string | null;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss4_score: number | null;
  cvss4_vector: string | null;
  status: "Open" | "Resolved" | "Partially Resolved" | "Risk Accepted" | "Closed" | "NA";
  location: string | null;
  description: string | null;
  proof_of_concept: string | null;
  implications: string | null;
  recommendations: string | null;
  owasp_category: string | null;
  owasp_name: string | null;
  cve: string | null;
  references: string | null;
  screenshot_before: string | null;
  screenshot_after: string | null;
  created_at: string;
  // Evidence quality / anti-hallucination fields
  has_poc: boolean;
  confidence_score: number;
  source_phase: string | null;
  source_tool: string | null;
  raw_request: string | null;
  raw_response: string | null;
  verification_status: "Unverified" | "Verified" | "False Positive";
  /** null = captured by the agent, "manual" = supplied by an analyst */
  evidence_source: string | null;
  evidence_added_by: string | null;
  evidence_added_at: string | null;
  // Scan context — the originating scan's target/repo, for Web vs Source Review.
  scan_target?: string | null;
  source_repo_url?: string | null;
}

export interface FindingComment {
  id: string;
  finding_id: string;
  author_id: string;
  author_name: string;
  body: string;
  created_at: string;
}

export const findingsApi = {
  list: async (params?: {
    severity?: string;
    status?: string;
    vuln_type?: string;
    scan_id?: string;
    limit?: number;
  }) => {
    const res = await api.get<Finding[]>("/findings", { params });
    return res.data;
  },

  get: async (id: string) => {
    const res = await api.get<Finding>(`/findings/${id}`);
    return res.data;
  },

  update: async (id: string, data: Partial<Finding>) => {
    const res = await api.patch<Finding>(`/findings/${id}`, data);
    return res.data;
  },

  bulkVerification: async (ids: string[], verification_status: string) => {
    await api.post("/findings/bulk-verification", { ids, verification_status });
  },

  bulkStatus: async (ids: string[], status: string) => {
    await api.post("/findings/bulk-status", { ids, status });
  },

  listComments: async (id: string) => {
    const res = await api.get<FindingComment[]>(`/findings/${id}/comments`);
    return res.data;
  },

  addComment: async (id: string, body: string) => {
    const res = await api.post<FindingComment>(`/findings/${id}/comments`, { body });
    return res.data;
  },

  deleteComment: async (findingId: string, commentId: string) => {
    await api.delete(`/findings/${findingId}/comments/${commentId}`);
  },

  retest: async (id: string) => {
    const res = await api.post<{ scan_id: string; finding_id: string; message: string }>(
      `/findings/${id}/retest`,
    );
    return res.data;
  },
};
