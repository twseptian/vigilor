package com.ensign.burp.api.model;

public class ScanResponse {
    public String id;
    public String target_url;
    public String status;          // queued | running | completed | failed | cancelled
    public String phase;
    public String phase_detail;
    public String llm_provider;
    public String llm_model;
    public int    findings_critical;
    public int    findings_high;
    public int    findings_medium;
    public int    findings_low;
    public int    findings_info;
    public int    hypotheses_total;
    public int    hypotheses_confirmed;
    public String error_message;
    public String created_at;
    public String started_at;
    public String completed_at;
    public String target_description;

    /** Human-readable severity summary, e.g. "2C 3H 1M" */
    public String severitySummary() {
        StringBuilder sb = new StringBuilder();
        if (findings_critical > 0) sb.append(findings_critical).append("C ");
        if (findings_high     > 0) sb.append(findings_high).append("H ");
        if (findings_medium   > 0) sb.append(findings_medium).append("M ");
        if (findings_low      > 0) sb.append(findings_low).append("L ");
        if (findings_info     > 0) sb.append(findings_info).append("I");
        String s = sb.toString().trim();
        return s.isEmpty() ? "—" : s;
    }

    public int totalFindings() {
        return findings_critical + findings_high + findings_medium + findings_low + findings_info;
    }
}
