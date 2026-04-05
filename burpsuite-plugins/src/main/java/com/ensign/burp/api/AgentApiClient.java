package com.ensign.burp.api;

import com.ensign.burp.api.model.*;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.List;

/**
 * REST client for the Agentic Pentest AI FastAPI backend.
 * Thread-safe: HttpClient is reused across calls.
 */
public class AgentApiClient {

    private final Gson gson = new Gson();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .version(java.net.http.HttpClient.Version.HTTP_1_1)
            .build();

    private volatile String baseUrl;
    private volatile String authToken;

    public AgentApiClient(String baseUrl, String authToken) {
        this.baseUrl    = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.authToken  = authToken;
    }

    // ── Configuration ──────────────────────────────────────────────────────────

    public void setBaseUrl(String url) {
        this.baseUrl = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public void setAuthToken(String token) {
        this.authToken = token;
    }

    public String getBaseUrl()   { return baseUrl;    }
    public String getAuthToken() { return authToken;  }
    public boolean isAuthenticated() { return authToken != null && !authToken.isBlank(); }

    // ── Auth ──────────────────────────────────────────────────────────────────

    /**
     * Login with username/password. Stores the JWT token on success.
     * Uses OAuth2 form-encoded body as required by the backend.
     */
    public LoginResponse login(String username, String password) throws IOException, InterruptedException {
        String body = "username=" + encode(username) + "&password=" + encode(password);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/auth/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IOException("Login failed (" + resp.statusCode() + "): " + resp.body());
        }
        LoginResponse lr = gson.fromJson(resp.body(), LoginResponse.class);
        this.authToken = lr.access_token;
        return lr;
    }

    // ── Scans ─────────────────────────────────────────────────────────────────

    public List<ScanResponse> listScans() throws IOException, InterruptedException {
        HttpResponse<String> resp = get("/scans?limit=100");
        if (resp.statusCode() == 401) {
            this.authToken = null;
            throw new AuthExpiredException("Session expired — please re-login in Settings.");
        }
        if (resp.statusCode() != 200) throw new IOException("listScans: " + resp.statusCode());
        Type listType = new TypeToken<List<ScanResponse>>() {}.getType();
        return gson.fromJson(resp.body(), listType);
    }

    /** Thrown when the backend returns 401 — token expired or invalid. */
    public static class AuthExpiredException extends IOException {
        public AuthExpiredException(String msg) { super(msg); }
    }

    public ScanResponse getScan(String scanId) throws IOException, InterruptedException {
        HttpResponse<String> resp = get("/scans/" + scanId);
        if (resp.statusCode() != 200) throw new IOException("getScan: " + resp.statusCode());
        return gson.fromJson(resp.body(), ScanResponse.class);
    }

    public ScanResponse createScan(ScanRequest request) throws IOException, InterruptedException {
        HttpResponse<String> resp = post("/scans", gson.toJson(request));
        if (resp.statusCode() != 200 && resp.statusCode() != 201) {
            throw new IOException("createScan (" + resp.statusCode() + "): " + resp.body());
        }
        return gson.fromJson(resp.body(), ScanResponse.class);
    }

    public void cancelScan(String scanId) throws IOException, InterruptedException {
        HttpResponse<String> resp = postEmpty("/scans/" + scanId + "/cancel");
        if (resp.statusCode() != 200) throw new IOException("cancelScan: " + resp.statusCode());
    }

    // ── Settings / Models ─────────────────────────────────────────────────────

    /** Fetch available Ollama models from the backend. */
    public List<String> detectOllamaModels() throws IOException, InterruptedException {
        HttpResponse<String> resp = post("/settings/detect-ollama-models", "{}");
        if (resp.statusCode() == 401) {
            this.authToken = null;
            throw new AuthExpiredException("Session expired.");
        }
        if (resp.statusCode() != 200) throw new IOException("detectOllamaModels: " + resp.statusCode());
        Type listType = new TypeToken<List<String>>() {}.getType();
        List<String> result = gson.fromJson(resp.body(), listType);
        return result != null ? result : Collections.emptyList();
    }

    // ── Findings ─────────────────────────────────────────────────────────────

    public List<FindingResponse> getFindings(String scanId) throws IOException, InterruptedException {
        String path = scanId != null ? "/findings?scan_id=" + scanId + "&limit=200" : "/findings?limit=200";
        HttpResponse<String> resp = get(path);
        if (resp.statusCode() != 200) throw new IOException("getFindings: " + resp.statusCode());
        Type listType = new TypeToken<List<FindingResponse>>() {}.getType();
        List<FindingResponse> result = gson.fromJson(resp.body(), listType);
        return result != null ? result : Collections.emptyList();
    }

    // ── HTTP helpers ─────────────────────────────────────────────────────────

    private HttpResponse<String> get(String path) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + authToken)
                .header("Accept", "application/json")
                .GET()
                .timeout(Duration.ofSeconds(20))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String jsonBody) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + authToken)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .timeout(Duration.ofSeconds(20))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postEmpty(String path) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + authToken)
                .POST(HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(20))
                .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
