package com.ensign.burp.api.model;

public class FindingResponse {
    public String id;
    public String scan_id;
    public String finding_ref;
    public String title;
    public String vuln_type;
    public String severity;
    public double cvss_score;
    public String cvss_vector;
    public String status;          // Open | In Progress | Resolved | Accepted Risk
    public String location;
    public String description;
    public String proof_of_concept;
    public String implications;
    public String recommendations;
    public String owasp_category;
    public String owasp_name;
    public String cve;
    public String screenshot_before;
    public String screenshot_after;
    public String created_at;
}
