import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, Filter, CheckSquare } from "lucide-react";
import { findingsApi, type Finding } from "@/api/findings";
import { SEVERITY_COLORS, FINDING_STATUS_HEX } from "@/lib/utils";

const SEVERITIES = ["", "Critical", "High", "Medium", "Low", "Informational"];
const STATUSES   = ["", "Open", "Partially Resolved", "Risk Accepted", "Resolved", "Closed", "NA"];

const SEV_FILTER_COLORS: Record<string, string> = {
  Critical:      "bg-red-50 text-red-700 border-red-200 hover:bg-red-100",
  High:          "bg-orange-50 text-orange-700 border-orange-200 hover:bg-orange-100",
  Medium:        "bg-yellow-50 text-yellow-700 border-yellow-200 hover:bg-yellow-100",
  Low:           "bg-blue-50 text-blue-700 border-blue-200 hover:bg-blue-100",
  Informational: "bg-gray-50 text-gray-600 border-gray-200 hover:bg-gray-100",
};

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4,
};

export default function FindingListPage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus]     = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: rawFindings = [], isLoading } = useQuery({
    queryKey: ["findings-all", severity, status],
    queryFn: () => findingsApi.list({ severity: severity || undefined, status: status || undefined }),
  });

  const findings = [...rawFindings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99),
  );

  const bulkMutation = useMutation({
    mutationFn: ({ ids, newStatus }: { ids: string[]; newStatus: string }) =>
      findingsApi.bulkStatus(ids, newStatus),
    onSuccess: () => {
      setSelected([]);
      qc.invalidateQueries({ queryKey: ["findings-all"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const toggleAll = () => {
    if (selected.length === findings.length) setSelected([]);
    else setSelected(findings.map((f) => f.id));
  };

  const toggleOne = (id: string) =>
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );

  return (
    <div className="space-y-4">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-red-500" />
            Findings
            {!isLoading && (
              <span className="text-xs font-normal text-muted-foreground bg-muted px-2 py-0.5 rounded-full">
                {findings.length}
              </span>
            )}
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">All vulnerability findings across scans</p>
        </div>
      </div>

      {/* ── Filters ─────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-border rounded-xl p-3 flex flex-wrap gap-4 items-center">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-medium shrink-0">
          <Filter className="h-3.5 w-3.5" /> Filter
        </div>

        {/* Severity */}
        <div className="flex items-center gap-1 flex-wrap">
          <span className="text-xs text-muted-foreground mr-1">Severity:</span>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={`text-xs px-2.5 py-1 rounded-full border font-medium transition-all ${
                severity === s
                  ? s
                    ? SEV_FILTER_COLORS[s]
                    : "bg-gray-800 text-white border-gray-800"
                  : "border-border text-muted-foreground hover:bg-accent"
              }`}
            >
              {s || "All"}
            </button>
          ))}
        </div>

        <div className="w-px h-4 bg-border" />

        {/* Status */}
        <div className="flex items-center gap-1 flex-wrap">
          <span className="text-xs text-muted-foreground mr-1">Status:</span>
          {STATUSES.map((s) => (
            <button
              key={s}
              onClick={() => setStatus(s)}
              className={`text-xs px-2.5 py-1 rounded-full border font-medium transition-all ${
                status === s && s
                  ? "border-transparent text-white"
                  : status === s
                  ? "bg-gray-800 text-white border-gray-800"
                  : "border-border text-muted-foreground hover:bg-accent"
              }`}
              style={
                status === s && s
                  ? { backgroundColor: FINDING_STATUS_HEX[s] ?? "#6b7280", borderColor: FINDING_STATUS_HEX[s] ?? "#6b7280" }
                  : {}
              }
            >
              {s || "All"}
            </button>
          ))}
        </div>
      </div>

      {/* ── Bulk triage bar ─────────────────────────────────────────────────── */}
      {selected.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap bg-blue-50 border border-blue-200 rounded-xl px-4 py-2.5">
          <CheckSquare className="h-4 w-4 text-blue-600 shrink-0" />
          <span className="text-sm font-semibold text-blue-700">{selected.length} selected</span>
          <span className="text-blue-300 mx-1">|</span>
          <span className="text-xs text-blue-600 mr-1">Mark as:</span>
          {STATUSES.slice(1).map((s) => (
            <button
              key={s}
              onClick={() => bulkMutation.mutate({ ids: selected, newStatus: s })}
              disabled={bulkMutation.isPending}
              className="text-xs px-2.5 py-1 rounded-full font-medium text-white transition-opacity hover:opacity-80 disabled:opacity-40"
              style={{ backgroundColor: FINDING_STATUS_HEX[s] ?? "#6b7280" }}
            >
              {s}
            </button>
          ))}
          <button
            onClick={() => setSelected([])}
            className="ml-auto text-xs text-blue-500 hover:text-blue-700 font-medium"
          >
            Clear
          </button>
        </div>
      )}

      {/* ── Table ───────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-gradient-to-r from-muted/30 to-muted/10">
              <th className="py-2.5 px-4 w-8">
                <input
                  type="checkbox"
                  checked={selected.length === findings.length && findings.length > 0}
                  onChange={toggleAll}
                  className="rounded"
                />
              </th>
              <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Ref</th>
              <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Title</th>
              <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Severity</th>
              <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">CVSS</th>
              <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Location</th>
              <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">Status</th>
              <th className="text-left py-2.5 px-4 text-muted-foreground font-medium text-xs uppercase tracking-wide">OWASP</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={8} className="py-12 text-center text-muted-foreground text-sm">
                  Loading findings…
                </td>
              </tr>
            )}
            {!isLoading && findings.length === 0 && (
              <tr>
                <td colSpan={8} className="py-12 text-center">
                  <ShieldAlert className="h-8 w-8 text-muted-foreground/20 mx-auto mb-2" />
                  <p className="text-sm text-muted-foreground">No findings found</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">Try adjusting the filters or run a new scan</p>
                </td>
              </tr>
            )}
            {findings.map((f: Finding) => (
              <tr
                key={f.id}
                className="border-b border-border/40 last:border-0 hover:bg-blue-50/40 cursor-pointer transition-colors group"
              >
                <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={selected.includes(f.id)}
                    onChange={() => toggleOne(f.id)}
                    className="rounded"
                  />
                </td>
                <td
                  className="py-3 px-4 text-muted-foreground font-mono text-xs whitespace-nowrap"
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  {f.finding_ref || "—"}
                </td>
                <td
                  className="py-3 px-4 font-medium group-hover:text-blue-700 transition-colors max-w-xs"
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  {f.title}
                </td>
                <td className="py-3 px-4" onClick={() => navigate(`/findings/${f.id}`)}>
                  <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${SEVERITY_COLORS[f.severity] ?? ""}`}>
                    {f.severity}
                  </span>
                </td>
                <td
                  className="py-3 px-4 text-muted-foreground text-xs font-mono"
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  {f.cvss4_score != null
                    ? <span title="CVSS 4.0">{f.cvss4_score.toFixed(1)}</span>
                    : f.cvss_score != null
                    ? <span title="CVSS 3.1">{f.cvss_score.toFixed(1)}</span>
                    : "—"}
                </td>
                <td
                  className="py-3 px-4 text-muted-foreground text-xs font-mono truncate max-w-[180px]"
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  {f.location || "—"}
                </td>
                <td className="py-3 px-4" onClick={() => navigate(`/findings/${f.id}`)}>
                  <span
                    className="text-xs px-2.5 py-0.5 rounded-full font-medium whitespace-nowrap"
                    style={{
                      backgroundColor: (FINDING_STATUS_HEX[f.status] ?? "#6b7280") + "1a",
                      color: FINDING_STATUS_HEX[f.status] ?? "#6b7280",
                      border: `1px solid ${(FINDING_STATUS_HEX[f.status] ?? "#6b7280")}40`,
                    }}
                  >
                    {f.status}
                  </span>
                </td>
                <td className="py-3 px-4" onClick={() => navigate(`/findings/${f.id}`)}>
                  {f.owasp_category ? (
                    <div>
                      <span className="text-xs font-semibold text-blue-600">{f.owasp_category}</span>
                      {f.owasp_name && (
                        <p className="text-[10px] text-muted-foreground truncate max-w-[160px] mt-0.5">{f.owasp_name}</p>
                      )}
                    </div>
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
