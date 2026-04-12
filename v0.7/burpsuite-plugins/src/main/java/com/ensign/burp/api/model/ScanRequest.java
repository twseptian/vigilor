package com.ensign.burp.api.model;

import java.util.ArrayList;
import java.util.List;

public class ScanRequest {
    public String       target_url;
    public String       scan_mode = "full";
    public String       llm_provider = "anthropic";
    public String       llm_model;
    public int          max_hypotheses = 8;
    public int          max_parallel   = 3;
    public int          feedback_iter  = 2;
    public String       custom_prompt;
    public String       target_description;
    public List<String> scope_include = new ArrayList<>();
    public List<String> scope_exclude = new ArrayList<>();

    public ScanRequest(String targetUrl) {
        this.target_url = targetUrl;
    }
}
