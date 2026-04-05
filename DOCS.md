# Pentest AI Agent — Full Technical Documentation

**Version:** v0.4.0
**Date:** 2026-03-24

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [System Requirements](#3-system-requirements)
4. [Installation & Setup](#4-installation--setup)
5. [Configuration Reference](#5-configuration-reference)
6. [CLI Reference](#6-cli-reference)
7. [Pipeline Deep Dive](#7-pipeline-deep-dive)
   - 7.1 [Phase 1 — Reconnaissance](#71-phase-1--reconnaissance)
   - 7.2 [Phase 1.5 — Static Source Code Analysis](#72-phase-15--static-source-code-analysis)
   - 7.3 [Phase 2 — Vulnerability Analysis](#73-phase-2--vulnerability-analysis)
   - 7.4 [Phase 3 — Active Exploitation](#74-phase-3--active-exploitation)
   - 7.5 [Phase 4 — Reporting](#75-phase-4--reporting)
8. [Vulnerability Coverage Reference](#8-vulnerability-coverage-reference)
   - 8.1 [URL Path Keywords](#81-url-path-keywords)
   - 8.2 [Query Parameter Keywords](#82-query-parameter-keywords)
   - 8.3 [Form Input Detection](#83-form-input-detection)
   - 8.4 [Security Header Checks](#84-security-header-checks)
   - 8.5 [Static Analysis Patterns](#85-static-analysis-patterns)
   - 8.6 [Attack Chain Detection](#86-attack-chain-detection)
   - 8.7 [Exploit Auto-Detection](#87-exploit-auto-detection)
9. [Payload Corpus Reference](#9-payload-corpus-reference)
10. [Scope Rules Reference](#10-scope-rules-reference)
11. [Report Format Reference](#11-report-format-reference)
12. [LLM Provider Reference](#12-llm-provider-reference)
13. [WorkspaceManager Reference](#13-workspacemanager-reference)
14. [Troubleshooting](#14-troubleshooting)
15. [Extending the Agent](#15-extending-the-agent)

---

## 1. Overview

Pentest AI Agent is an autonomous, AI-driven web application penetration testing
framework. It models how a human penetration tester works: first understanding the
target, then forming attack hypotheses, then actively trying to exploit them, and
finally producing a professional report.

The agent runs as a **5-phase pipeline**. Each phase is handled by a specialised
agent class that reads from and writes to a central `WorkspaceManager` instance.
No inter-agent communication happens outside of the workspace — the data flow is
strictly sequential.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Pentest AI Agent v0.4.0                          │
│                                                                         │
│  CLI (main.py)                                                          │
│       │                                                                 │
│       ▼                                                                 │
│  PentestOrchestrator                                                    │
│       │                                                                 │
│       ├─► [Phase 1]   ReconAgent            ──► WorkspaceManager       │
│       │                                              │                  │
│       ├─► [Phase 1.5] StaticAnalysisAgent   ──► WorkspaceManager       │
│       │                                              │                  │
│       ├─► [Phase 2]   VulnAnalyzerAgent     ──► WorkspaceManager       │
│       │                                              │                  │
│       ├─► [Phase 3]   ExploitAgent          ──► WorkspaceManager       │
│       │                                              │                  │
│       └─► [Phase 4]   ReportingAgent        ──► WorkspaceManager       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key design principles:**

- **LLM-agnostic** — swap between Claude, GPT-4o, or a local Ollama model with one flag.
- **Deterministic core, AI-enhanced** — structural analysis (path patterns, param names,
  static code) runs without any LLM call; the LLM layer adds contextual reasoning on top.
- **Self-learning** — successful payloads are persisted to disk and reused in future scans.
- **Scope-safe** — configurable allow/deny URL patterns prevent out-of-scope crawling.

---

## 2. Architecture

### 2.1 Component Map

```
main.py
├── ClaudeEngine / OpenAIEngine / OllamaEngine    (src/core/llm.py)
├── PentestOrchestrator                           (src/core/orchestrator.py)
│   └── WorkspaceManager                         (src/core/workspace.py)
│       └── PayloadCorpus                        (src/core/corpus.py)
├── ReconAgent                                   (src/agents/recon.py)
├── StaticAnalysisAgent                          (src/agents/static_analysis.py)
├── VulnAnalyzerAgent                            (src/agents/vuln.py)
├── ExploitAgent                                 (src/agents/exploit.py)
└── ReportingAgent                               (src/agents/report.py)
    Tools:
    ├── BrowserTool                              (src/tools/browser.py)
    ├── TerminalTool                             (src/tools/terminal.py)
    └── tool_defs.py                             (src/tools/tool_defs.py)
```

### 2.2 Data Flow

```
ReconAgent
  └── writes → workspace.recon_data["structured"]       (links, forms, params, tech)
             → workspace.recon_data["surface_map"]       (LLM attack surface summary)
             → workspace.recon_data["http_headers"]       (raw response headers)
             → workspace.recon_data["missing_security_headers"]
             → workspace.recon_data["cookie_security"]
             → workspace.page_contexts[url]              (per-page context dict)

StaticAnalysisAgent
  └── writes → workspace.recon_data["static_findings"]  (list of file:line matches)
             → workspace.hypotheses[]                    (file:line hypotheses)

VulnAnalyzerAgent
  └── reads  → workspace.recon_data["structured"]
             → workspace.recon_data["surface_map"]
             → workspace.page_contexts                   (for chain detection)
  └── writes → workspace.hypotheses[]                    (all hypotheses)

ExploitAgent
  └── reads  → workspace.hypotheses[]
             → workspace.corpus.get_candidates()
  └── writes → workspace.findings[]                      (confirmed exploits)
             → workspace.corpus.record_success()

ReportingAgent
  └── reads  → workspace.findings[]
             → workspace.hypotheses[]
             → workspace.recon_data["structured"]
             → workspace.recon_data["static_findings"]
  └── writes → reports/<hostname>/pentest_report_<timestamp>.docx
```

### 2.3 LLM Engine Layer

All three engines implement the same interface:

| Method | Description |
|---|---|
| `generate_response(messages, system_prompt, tools, max_tokens, temperature)` | Call the LLM |
| `extract_text(response)` | Extract the text block from a response |
| `extract_tool_calls(response)` | Extract tool use blocks from a response |
| `extract_tool_call_name(tool_call)` | Get tool name from a tool call object |
| `extract_tool_call_input(tool_call)` | Get the input dict from a tool call object |

Engines are selected at startup and injected into all agents. Swapping providers requires
only changing `--provider` — no agent code changes.

---

## 3. System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| Python | 3.10 | 3.12+ |
| RAM | 2 GB | 4 GB |
| Disk | 500 MB | 1 GB (Playwright + Chromium) |
| Network | Required for target + LLM API | — |
| OS | Linux / macOS / Windows (WSL) | Kali Linux |

### Python Dependencies

| Package | Version | Purpose |
|---|---|---|
| `anthropic` | ≥ 0.35.0 | Claude API client |
| `openai` | ≥ 1.0.0 | OpenAI + Ollama API client |
| `playwright` | ≥ 1.47.0 | Browser automation |
| `pydantic` | ≥ 2.9.0 | Data validation |
| `python-dotenv` | ≥ 1.0.0 | `.env` file loading |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing |
| `jinja2` | ≥ 3.1.4 | Template rendering |
| `pyyaml` | ≥ 6.0.1 | YAML parsing |
| `rich` | ≥ 13.8.0 | Terminal output formatting |
| `python-docx` | ≥ 1.1.0 | DOCX report generation |
| `httpx` | (transitive) | Async HTTP for header audit |

---

## 4. Installation & Setup

### Step 1 — Clone and enter the directory

```bash
git clone https://github.com/youruser/pentest-ai-agent.git
cd pentest-ai-agent
```

### Step 2 — Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Install Playwright browser

```bash
playwright install chromium
```

### Step 5 — Configure credentials

```bash
cp .env.example .env
nano .env                         # fill in your API keys
```

### Step 6 — Verify installation

```bash
python3 main.py --url https://example.com --repo . --mock-llm
```

Expected output:
```
[Corpus] No corpus file found at ~/.pentest-ai-agent/corpus.json — starting fresh.
Starting pentest pipeline against https://example.com
[*] Phase 1: Reconnaissance
...
```

---

## 5. Configuration Reference

All configuration is via the `.env` file in the project root. Variables are
loaded at startup before any agent runs.

### Full `.env` Reference

```env
# ── LLM Provider API Keys ──────────────────────────────────────────────────────
# Required for --provider claude (default)
ANTHROPIC_API_KEY=sk-ant-...

# Required for --provider openai
OPENAI_API_KEY=sk-proj-...

# ── Ollama Local Model (used when --provider ollama) ───────────────────────────
# URL of your running Ollama server
OLLAMA_BASE_URL=http://127.0.0.1:11434

# Model name — must be pulled first via `ollama pull <model>`
OLLAMA_MODEL=qwen2.5-coder:7b-instruct

# Context window in tokens (increase for larger apps, max depends on model)
OLLAMA_NUM_CTX=8192

# LLM temperature — 0.1 recommended for deterministic JSON output
OLLAMA_TEMPERATURE=0.1

# ── Optional ───────────────────────────────────────────────────────────────────
# MAX_CONCURRENT_AGENTS=3
# TARGET_URL=http://localhost:3000
```

### Variable Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | For `--provider claude` | — | Anthropic API key |
| `OPENAI_API_KEY` | For `--provider openai` | — | OpenAI API key |
| `OLLAMA_BASE_URL` | For `--provider ollama` | `http://127.0.0.1:11434` | Ollama server URL |
| `OLLAMA_MODEL` | For `--provider ollama` | `qwen2.5-coder:7b-instruct` | Model name |
| `OLLAMA_NUM_CTX` | No | `8192` | Context window (tokens) |
| `OLLAMA_TEMPERATURE` | No | `0.1` | LLM temperature |

---

## 6. CLI Reference

### Synopsis

```
python3 main.py --url URL --repo PATH [OPTIONS]
```

### Arguments

| Argument | Type | Required | Default | Description |
|---|---|---|---|---|
| `--url` | string | Yes | — | Full target URL including scheme (e.g. `https://target.com`) |
| `--repo` | path | Yes | — | Local source repo path for static analysis. Use `.` to skip. |
| `--provider` | choice | No | `claude` | LLM backend: `claude`, `openai`, or `ollama` |
| `--mock-llm` | flag | No | off | Offline mode — synthetic responses, no API calls |
| `--headers` | JSON | No | `{}` | HTTP headers to inject into all requests |
| `--cookies` | JSON | No | `{}` | Cookies to inject into all requests |
| `--scope-include` | regex* | No | *(none)* | URL allow-list patterns (repeatable) |
| `--scope-exclude` | regex* | No | *(none)* | URL deny-list patterns (repeatable) |

\* Python `re` syntax. Can be specified multiple times.

### Usage Examples

#### Basic scan

```bash
python3 main.py --url https://target.com --repo /path/to/source
```

#### Scan with OpenAI GPT-4o

```bash
python3 main.py --url https://target.com --repo . --provider openai
```

#### Scan with local Ollama model

```bash
# Pull a model first
ollama pull qwen2.5-coder:7b-instruct

python3 main.py --url https://target.com --repo . --provider ollama
```

#### Authenticated scan (session cookie)

```bash
python3 main.py --url https://target.com --repo . \
    --cookies '{"session": "eyJhbGci...", "CSRF": "abc123"}' \
    --headers '{"X-Custom-Header": "value"}'
```

#### Scope-limited scan — API only

```bash
python3 main.py --url https://target.com --repo . \
    --scope-include '/api/' \
    --scope-include '/graphql'
```

#### Exclude noise paths

```bash
python3 main.py --url https://target.com --repo . \
    --scope-exclude '\.(css|js|png|jpg|gif|svg|woff2?|ttf|ico|map)(\?.*)?$' \
    --scope-exclude '/logout' \
    --scope-exclude '/static/'
```

#### Source code analysis only (skip live exploitation)

```bash
# Provide a dummy URL and your actual source repo
python3 main.py --url https://localhost --repo /path/to/source --mock-llm
```

#### Offline mock test

```bash
python3 main.py --url https://target.com --repo . --mock-llm
```

---

## 7. Pipeline Deep Dive

### 7.1 Phase 1 — Reconnaissance

**Agent:** `ReconAgent`
**File:** `src/agents/recon.py`
**Tools used:** Playwright (browser), httpx (passive header audit)

#### Steps

1. **Navigate to root** — Playwright opens the target URL in a Chromium browser with
   the provided headers and cookies. Authentication status is checked immediately.

2. **HTML parsing** — BeautifulSoup extracts:
   - Same-origin anchor links (`<a href>`) — scope-filtered
   - File-serving media URLs (`<img src>`, `<source src>`, `data-src`, `data-lazy-src`)
     that contain file-serving query parameters — scope-filtered
   - All forms: action, method, input names/types
   - Query parameters from anchor links

3. **JS endpoint discovery** — Fetches same-origin `<script src>` files via Playwright
   (preserving cookies/auth). Applies a regex to extract path-like strings from JS content.
   Also analyses inline scripts (first 5).

4. **Passive HTTP header audit** — Uses `httpx.AsyncClient` to make a direct GET to the
   target and inspect response headers:
   - Missing security headers: `X-Frame-Options`, `Content-Security-Policy`,
     `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`,
     `Permissions-Policy`, `X-XSS-Protection`
   - Cookie flag analysis: `HttpOnly`, `Secure`, `SameSite` per cookie

5. **One-level crawl** — Navigates to each discovered link (up to 15). For each sub-page:
   - Collects additional forms
   - Collects page-level query params
   - Stores **per-page context** into `workspace.add_page_context()`:

     ```python
     {
         "title":           str,          # <title> text
         "forms":           list[dict],   # forms on this page
         "params":          list[str],    # query param names
         "links":           list[str],    # same-origin links found
         "has_file_upload": bool,         # any <input type="file">
         "has_admin_path":  bool,         # URL contains /admin /dashboard etc.
         "auth_indicators": list[str],    # "logout", "my account", etc. found in HTML
     }
     ```

6. **LLM attack surface summary** — All collected data is serialised to JSON and sent
   to the LLM with a prompt to summarise the attack surface in markdown. Output stored
   in `workspace.recon_data["surface_map"]`.

7. **Structured data storage** — Full structured dict stored in
   `workspace.recon_data["structured"]`.

#### Workspace outputs

| Key | Type | Content |
|---|---|---|
| `structured` | dict | `links_found`, `forms`, `query_params_seen`, `hidden_js_endpoints`, `technologies_hint`, `server_header`, `x_powered_by`, `missing_security_headers`, `cookie_security_issues` |
| `surface_map` | str | LLM-generated markdown attack surface summary |
| `http_headers` | dict | Raw response headers |
| `missing_security_headers` | list | Header names that are absent |
| `cookie_security` | list | Per-cookie flag analysis dicts |
| `server_info` | str | Server header value |
| `auth_status` | dict | Authentication indicators |

---

### 7.2 Phase 1.5 — Static Source Code Analysis

**Agent:** `StaticAnalysisAgent`
**File:** `src/agents/static_analysis.py`
**Tools used:** None (pure Python file walk + regex)

This phase runs only if `workspace.repo_path` is a valid directory.
It requires **no LLM call** — all detection is deterministic.

#### Process

1. `os.walk(repo_path)` with noise directories pruned:
   `.git`, `node_modules`, `__pycache__`, `vendor`, `venv`, `.venv`, `dist`, `build`

2. For each file with a supported extension (`.py`, `.php`, `.js`, `.ts`, `.java`, `.rb`, `.go`):
   - Skip files > 512 KB
   - Stop after 1000 files
   - Read with UTF-8 encoding (errors ignored)
   - Match each line against all applicable patterns from the pattern registry

3. Deduplicate by `(vuln_type, file:line)` pair

4. Store raw findings in `workspace.recon_data["static_findings"]`

5. Convert each finding to a hypothesis with:
   - `location` = `relative/path/to/file.py:42`
   - `details` = descriptive detail + source location + matched snippet
   - `cvss_score`, `cvss_vector`, `severity` from the pattern definition

#### Workspace outputs

| Key | Type | Content |
|---|---|---|
| `static_findings` | list | `[{type, location, cvss, vector, detail, snippet}]` |
| `hypotheses` | list | Appended with file:line hypotheses |

---

### 7.3 Phase 2 — Vulnerability Analysis

**Agent:** `VulnAnalyzerAgent`
**File:** `src/agents/vuln.py`
**Tools used:** LLM (Phase B only)

#### Phase A — Deterministic Structural Analysis

Runs four independent classifiers:

| Classifier | Input | Method |
|---|---|---|
| `_classify_links(links)` | Discovered URLs | Match path segments against `PATH_KEYWORD_MAP` |
| `_classify_forms(forms)` | Form definitions | Match input names against `FORM_INPUT_MAP` |
| `_classify_headers(...)` | Missing headers + server info | Lookup in `HEADER_VULN_MAP` |
| `_classify_cookies_deserialization(...)` | Set-Cookie values | `_detect_serial_cookie()` for 7 formats |

All matching hypotheses are added to `workspace.hypotheses` before the LLM is called.

#### Phase A.5 — Multi-page Chain Detection

`_detect_attack_chains(page_contexts)` correlates signals across all pages crawled
in Phase 1. See [Section 8.6](#86-attack-chain-detection) for the full chain table.

#### Phase B — LLM Contextual Analysis

The LLM receives:
- Full list of already-generated hypotheses (so it doesn't repeat them)
- All crawled links, forms, query params, JS endpoints
- Server technology hints
- LLM attack surface summary from recon

The LLM is instructed to generate **additional** hypotheses covering:
- Business logic flaws
- App-specific attack vectors
- Any uncovered links or parameters

Output is parsed from a JSON array. On parse failure, one automatic retry is attempted
with a stricter prompt. Final count typically 12–25 hypotheses total.

**Ollama optimisation:** Context is trimmed aggressively (10 links, 8 params,
5 JS endpoints, 800-char surface map, temperature 0.1) to stay within small
context windows and reduce hallucination.

---

### 7.4 Phase 3 — Active Exploitation

**Agent:** `ExploitAgent`
**File:** `src/agents/exploit.py`
**Tools used:** Playwright (browser), curl/nmap (terminal)

#### Available Tools

| Tool | Description |
|---|---|
| `browser_navigate` | Navigate to a URL |
| `browser_get_dom` | Get page HTML (body only, head/script/style stripped) |
| `browser_fill` | Fill an input field by CSS selector |
| `browser_click` | Click an element by CSS selector |
| `browser_take_screenshot` | Capture current page as PNG |
| `run_terminal_command` | Execute a shell command (curl, nmap, etc.) |

#### Execution Model

Each hypothesis is tested sequentially. Per hypothesis:

1. **Scope check** — If the target URL fails `workspace.in_scope()`, the hypothesis
   is skipped.

2. **Informational fast-path** — Hypotheses with `severity = "Informational"` (CVSS 0.0)
   skip the LLM loop entirely. Evidence is collected from cached recon data:
   missing headers, server version, X-Powered-By, cookie flags. No tool calls made.

3. **PATH TRAVERSAL fast-path** — Activated for any hypothesis whose `type` contains
   `path traversal`, `lfi`, or `local file`. Steps:
   - Navigate to the hypothesis URL and extract image/file paths from DOM
   - Prepend corpus-learned probe URLs (proven payloads from previous scans)
   - Build traversal probe list from 3 strategies:
     - **Strategy A**: Replace query param values with traversal payloads
     - **Strategy B**: Replace path dir/mount segments
     - **Strategy C**: Common file-serving endpoints (`/image?filename=`, `/file?filename=`, etc.)
   - Run each probe via `curl -s -k -L --max-time 8`
   - Confirm on `/etc/passwd` indicators (`root:x:0:0:`, `daemon:x:`, etc.)
   - If confirmed → record, screenshot, done. If not → pass hint to LLM loop.

4. **Auto-detection blocks** — During the LLM tool-call loop, after each tool call
   result, 20+ pattern matchers run to detect confirmations without waiting for the
   LLM to decide (see [Section 8.7](#87-exploit-auto-detection)).

5. **LLM tool-call loop** — The LLM receives the hypothesis details and available tools.
   It issues tool calls (browser navigation, DOM inspection, form filling, curl commands).
   The loop continues until:
   - Auto-detection fires (exploit confirmed)
   - LLM explicitly states success/failure
   - Maximum turn limit reached

6. **Corpus recording** — Every confirmed exploit calls
   `workspace.corpus.record_success(vuln_type, payload, location)`.

7. **Screenshot** — Playwright takes a screenshot of the current page state.

#### DOM Loop Protection

`_last_dom_hash` and `_dom_repeat_count` track identical `browser_get_dom` results.
After 2 identical DOM hashes the LLM receives an inline hint to stop re-calling the
tool, preventing infinite loops on dynamic pages.

#### Smart DOM Extraction

`_smart_dom(html)` strips `<head>`, `<script>`, and `<style>` tags before sending
DOM content to the LLM. This ensures the model always sees forms and interactive
elements rather than CSS/JS metadata.

---

### 7.5 Phase 4 — Reporting

**Agent:** `ReportingAgent`
**File:** `src/agents/report.py`
**Tools used:** LLM (narrative generation), python-docx (DOCX output)

#### DOCX Structure

The report is saved to `reports/<hostname>/pentest_report_<timestamp>.docx`.

| Section | Content |
|---|---|
| Title Page | Target, date, classification |
| Executive Summary | Risk overview, confirmed finding count by severity |
| Attack Surface Overview | Technology stack, endpoint inventory, JS endpoints, form list, query params, missing headers, cookie issues |
| Findings Summary Table | All confirmed findings: severity, CVSS score, location |
| Detailed Findings | Per-finding: description, reproduction steps, PoC, screenshots, remediation |
| Remediation Roadmap | Prioritised fix plan by severity |
| Conclusion | Overall risk assessment |

#### Narrative Generation

- **Claude / OpenAI**: LLM generates all narrative prose from a structured JSON prompt.
  On JSON parse failure, falls back to `_generate_narrative_fallback()`.
- **Ollama**: `_generate_narrative_fallback()` used directly — bypasses LLM entirely
  to guarantee consistent professional output regardless of local model quality.

#### Proof of Concept Format

Each confirmed finding includes a 7-section structured PoC:

```
CLASSIFICATION
  Vulnerability : SQL Injection
  Severity      : Critical (CVSS 9.8)
  CVSS Vector   : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  URL           : https://target.com/login
  HTTP Method   : POST

VULNERABILITY DESCRIPTION
  [Class-specific technical prose from _POC_DESC lookup table]

REPRODUCTION STEPS
  1. Navigate to the login page
  2. Inject the payload into the username field: ' OR 1=1--
  3. Submit the form
  → [Exploitation indicators]

ATTACK REQUEST (cURL)
  curl -s -X POST 'https://target.com/login' \
    -d 'username=%27+OR+1%3D1--&password=x'

OBSERVED EVIDENCE
  [Up to 25 lines of cleaned server response]

EXPECTED vs ACTUAL BEHAVIOUR
  Expected : The application rejects invalid credentials
  Actual   : [Class-specific actual outcome description]

TECHNICAL NOTES
  [Raw hypothesis details from workspace]
```

---

## 8. Vulnerability Coverage Reference

### 8.1 URL Path Keywords

The following URL path segment patterns trigger automatic hypotheses:

| Pattern | Vulnerability Type | Severity | CVSS |
|---|---|---|---|
| `login`, `signin`, `auth`, `logon` | Authentication Bypass / Brute Force | High | 7.5 |
| `register`, `signup`, `create-account` | Insecure Registration / Account Enumeration | Medium | 5.3 |
| `upload`, `attach`, `import`, `file` | Unrestricted File Upload | Critical | 9.0 |
| `admin`, `manage`, `dashboard`, `panel`, `backoffice`, `staff`, `superuser` | Broken Access Control | Critical | 9.1 |
| `search`, `find`, `query`, `filter`, `lookup` | XSS / SQL Injection via Search | High | 7.2 |
| `api`, `v1`, `v2`, `v3`, `graphql`, `rest`, `endpoint` | API Security (IDOR / Auth / Injection) | High | 8.1 |
| `redirect`, `goto`, `return`, `next`, `callback`, `forward` | Open Redirect / SSRF | Medium | 6.1 |
| `download`, `export`, `report`, `backup` | Path Traversal / Sensitive File Exposure | High | 8.1 |
| `/image`, `/img`, `/images`, `/static`, `/assets`, `/files`, `/media`, `/uploads`, `/serve`, `/fetch` | Path Traversal via File-Serving Endpoint | High | 7.5 |
| `comment`, `message`, `post`, `feedback`, `guestbook`, `review`, `forum`, `board` | Stored XSS | High | 8.2 |
| `password`, `reset`, `forgot`, `recover` | Account Takeover / Weak Password Reset | High | 8.1 |
| `profile`, `account`, `settings`, `preferences`, `user` | IDOR / Privilege Escalation | High | 8.1 |
| `webhook`, `notify`, `hook`, `ping` | SSRF via Webhook | High | 8.6 |
| `include`, `template`, `render`, `view`, `layout`, `theme` | SSTI / Local File Inclusion | Critical | 9.8 |
| `debug`, `test`, `dev`, `status`, `health`, `trace`, `info` | Information Disclosure | Medium | 5.3 |
| `exec`, `execute`, `run`, `cmd`, `shell`, `command`, `ping` | Command Injection / RCE | Critical | 9.8 |
| `sql`, `query`, `db`, `database` | SQL Injection | Critical | 9.8 |
| `csrf`, `token`, `nonce` | Cross-Site Request Forgery | Medium | 6.5 |
| `cart`, `order`, `checkout`, `payment`, `purchase`, `price` | Business Logic / Price Tampering | High | 7.5 |
| `captcha`, `recaptcha` | Insecure CAPTCHA | Medium | 5.3 |
| `xml`, `soap`, `wsdl`, `xmlrpc`, `rss`, `atom`, `stock-check` | XXE Injection | Critical | 9.1 |
| `graphql`, `gql`, `__schema`, `introspect` | GraphQL API Injection / Introspection | High | 8.1 |
| `oauth`, `authorize`, `openid`, `.well-known` | OAuth / OIDC Misconfiguration | High | 8.1 |
| `cache`, `purge`, `cdn`, `varnish`, `surrogate` | Web Cache Poisoning / Deception | High | 8.0 |
| `2fa`, `mfa`, `otp`, `totp`, `authenticator`, `two-factor` | 2FA / MFA Bypass | High | 8.1 |
| `websocket`, `socket.io`, `sockjs` | WebSocket Security | High | 7.5 |
| `llm`, `ai-chat`, `copilot`, `assistant`, `prompt`, `generate`, `completion` | LLM / AI Prompt Injection | High | 8.0 |
| `nosql`, `mongo`, `dynamo`, `couchdb`, `firebase` | NoSQL Injection | High | 8.1 |
| `prototype`, `__proto__`, `gadget`, `marshal` | Prototype Pollution / Deserialization | High | 7.5 |
| `smuggl`, `tunnel`, `desync`, `h2`, `cl.te`, `te.cl` | HTTP Request Smuggling | High | 8.1 |
| `race`, `concurrent`, `parallel`, `simultaneous` | Race Condition | High | 7.5 |

---

### 8.2 Query Parameter Keywords

| Pattern | Vulnerability Type | Severity | CVSS |
|---|---|---|---|
| `id`, `uid`, `user_id`, `object_id`, `item_id`, `pid`, `oid` | IDOR / SQL Injection via ID Parameter | High | 8.1 |
| `page`, `file`, `filename`, `path`, `include`, `dir`, `folder`, `template`, `doc`, `load`, `download`, `serve` | Local File Inclusion / Path Traversal | High | 8.1 |
| `img`, `image`, `photo`, `pic`, `picture`, `avatar`, `thumb`, `banner`, `media`, `asset`, `resource` | Path Traversal via Image / Media Parameter | High | 7.5 |
| `url`, `redirect`, `next`, `return`, `goto`, `target`, `callback`, `dest` | Open Redirect / SSRF | Medium | 6.1 |
| `cmd`, `exec`, `command`, `shell`, `run`, `ping`, `ip`, `host` | Command Injection | Critical | 9.8 |
| `q`, `search`, `query`, `keyword`, `name`, `input`, `text`, `msg`, `message`, `subject` | XSS / SQL Injection via Input | High | 7.2 |
| `username`, `user`, `login`, `email` | SQL Injection / Brute Force via Credentials | High | 7.5 |
| `sort`, `order`, `orderby`, `column`, `field`, `by` | SQL Injection via ORDER BY | High | 7.5 |
| `format`, `type`, `output`, `mode`, `lang`, `locale` | Content Injection / Parameter Tampering | Medium | 5.3 |
| `xml`, `data`, `body`, `payload`, `content`, `soap`, `entity`, `dtd` | XXE / XML Injection via Parameter | Critical | 9.1 |
| `redirect_uri`, `client_id`, `response_type`, `grant_type`, `access_token`, `code`, `state`, `nonce`, `scope` | OAuth / OIDC Parameter Tampering | High | 8.1 |
| `host`, `x-forwarded-host`, `x-original-url`, `x-host` | HTTP Host Header Injection | High | 7.5 |
| `__proto__`, `prototype`, `constructor` | Prototype Pollution | High | 7.5 |
| `$where`, `$ne`, `$gt`, `$lt`, `$in`, `$nin`, `$regex`, `$exists` | NoSQL Injection via Operator | High | 8.1 |
| `kid`, `jwk`, `jku`, `alg`, `typ`, `x5u`, `x5c` | JWT Header Injection | High | 8.1 |
| `mutation`, `subscription`, `query`, `__typename`, `fragment` | GraphQL Injection | High | 8.1 |

---

### 8.3 Form Input Detection

| Input Name Pattern | Input Type | Vulnerability Type |
|---|---|---|
| `username`, `user`, `login`, `email` + `password`, `pass` | text / password | Authentication Bypass / Brute Force / SQLi |
| `file`, `upload`, `attach` | any | Unrestricted File Upload |
| `message`, `comment`, `body`, `content`, `text`, `post` | any | Stored XSS |
| `url`, `link`, `href`, `src`, `target` | any | SSRF / Open Redirect |
| `cmd`, `command`, `exec`, `shell`, `ping`, `ip` | any | Command Injection |
| `id`, `uid`, `user_id`, `account_id` | any | IDOR / Parameter Tampering |
| `price`, `amount`, `qty`, `quantity`, `discount` | any | Business Logic / Price Tampering |
| `token`, `csrf`, `nonce`, `_token` | hidden | CSRF Token Exposure |
| `otp`, `totp`, `code`, `verification`, `2fa`, `mfa`, `pin` | any | 2FA / MFA Bypass |
| `query`, `mutation`, `graphql`, `__typename` | any | GraphQL Injection |
| `prompt`, `instruction`, `context`, `system_msg`, `ai_input` | any | LLM Prompt Injection |
| `redirect_uri`, `client_id`, `scope`, `grant_type` | any | OAuth Parameter Tampering |
| `race`, `coupon`, `voucher`, `promo`, `apply`, `claim` | any | Race Condition / Coupon Abuse |

---

### 8.4 Security Header Checks

| Header | Vulnerability | Severity | CVSS |
|---|---|---|---|
| `X-Frame-Options` | Clickjacking | Medium | 4.3 |
| `Content-Security-Policy` | XSS amplification | Medium | 5.4 |
| `X-Content-Type-Options` | MIME sniffing | Medium | 4.3 |
| `Strict-Transport-Security` | SSL stripping / downgrade | Medium | 6.5 |
| `Referrer-Policy` | Referrer leakage | Low | 3.7 |
| `Permissions-Policy` | Browser feature abuse | Low | 3.1 |
| `X-XSS-Protection` | Missing legacy XSS filter | Medium | 4.3 |

Additionally:
- **Server version disclosure** — if `Server` header reveals version string
- **X-Powered-By disclosure** — if `X-Powered-By` header is present
- **Cookie flag issues** — missing `HttpOnly` or `Secure` flags per cookie

---

### 8.5 Static Analysis Patterns

All patterns match against single lines of source code.

| Category | Language | Pattern Description | CVSS |
|---|---|---|---|
| SQL Injection | Python | `cursor.execute(f"..."` or `execute("... %s")` | 9.8 |
| SQL Injection | PHP | `mysql_query/mysqli_query` with `$_GET/$_POST` | 9.8 |
| SQL Injection | JS | Template-literal SQL: `` db.query(`SELECT ${val}`) `` | 9.8 |
| SQL Injection | Java | `prepareStatement("..." + request.getParameter(...))` | 9.8 |
| Command Injection | Python | `subprocess.run(... shell=True)`, `os.system(...)` | 9.8 |
| Command Injection | PHP | `exec/shell_exec/system/passthru($_GET[...])` | 9.8 |
| Command Injection | Ruby | `system/exec/backtick with params[...]` | 9.8 |
| Path Traversal | Python | `open(os.path.join(...request...))` | 7.5 |
| Path Traversal | PHP | `file_get_contents/include/require($_GET[...])` | 7.5 |
| Insecure Deserialization | Python | `pickle.loads(...)` | 9.8 |
| Insecure Deserialization | Python | `yaml.load()` without `Loader=yaml.SafeLoader` | 9.8 |
| Insecure Deserialization | PHP | `unserialize($_GET[...])` | 9.8 |
| Insecure Deserialization | Java | `new ObjectInputStream(...)` | 9.8 |
| XXE | Python | `etree.parse()`, `lxml.etree.parse()`, `minidom.parse()` | 7.5 |
| XXE | PHP | `simplexml_load_string()`, `DOMDocument` | 7.5 |
| SSTI | Python | `render_template_string(request...)` | 9.8 |
| SSTI | PHP | `Twig/Smarty/Blade->render($_GET[...])` | 9.8 |
| Weak Cryptography | Python | `hashlib.md5(...)`, `hashlib.sha1(...)` | 5.3 |
| Insecure Randomness | Python | `random.random/randint/choice(...)` | 5.3 |
| Insecure Randomness | JS | `Math.random()` | 5.3 |
| Hardcoded Secret | All | `password = "..."`, `api_key = "..."` (≥8 chars) | 7.5 |
| XSS | Python | `Markup(request...)`, `mark_safe(request...)` | 6.1 |
| DOM XSS | JS | `innerHTML = location.search`, `document.write(...)` | 6.1 |
| JWT Weak Secret | All | `jwt.encode(..., "secret"/"changeme"/"123456"...)` | 8.1 |
| Prototype Pollution | JS | `Object.assign(req.body, ...)` | 6.5 |
| CORS Misconfiguration | All | `Access-Control-Allow-Origin: *` in source | 6.5 |
| Mass Assignment | Python | `Model.create(**request.form)` | 8.8 |
| Mass Assignment | JS | `new Model(req.body)`, `.create(req.body)` | 8.8 |
| SSRF | Python | `requests.get(request.args["url"])` | 8.6 |
| SSRF | PHP | `file_get_contents($_GET["url"])` | 8.6 |

---

### 8.6 Attack Chain Detection

`VulnAnalyzerAgent._detect_attack_chains()` correlates signals across all pages
crawled during Phase 1. The following chains are detected:

| Chain | Trigger A | Trigger B | CVSS | Severity |
|---|---|---|---|---|
| **File Upload → RCE** | Page has `<input type="file">` | Page has `?file=` / `?filename=` param | 9.8 | Critical |
| **XSS → Admin ATO** | URL matches `/search`, `/comment`, `/feedback`, `/review`, `/post` | URL contains `/admin`, `/dashboard`, `/manage`, `/panel`, `/staff` | 8.8 | High |
| **Cross-Page IDOR → Privesc** | URL has `?id=`, `?uid=`, `?user_id=`, `?item_id=` | Another URL also has ID params | 8.1 | High |
| **Open Redirect → OAuth Token Theft** | URL has `?redirect=`, `?next=`, `?return=`, `?url=`, `?callback=`, `?goto=` | URL matches `/oauth`, `/authorize`, `/auth`, `/login`, `/sso`, `/oidc` | 8.1 | High |
| **SSRF → Cloud Credentials** | URL has `?url=`, `?uri=`, `?endpoint=`, `?host=`, `?target=`, `?fetch=`, `?proxy=` | Any page discovered | 9.0 | Critical |
| **Debug Info Leak → Privesc** | URL/title contains `traceback`, `exception`, `stack trace`, `debug=true`, `werkzeug` | URL contains `/admin`, `/dashboard`, etc. | 8.6 | High |

Each chain hypothesis includes step-by-step exploitation instructions and specific payloads.

---

### 8.7 Exploit Auto-Detection

During the LLM tool-call loop, every tool call result is scanned for confirmation
indicators. Confirmed exploits skip waiting for the LLM's verdict.

| Vuln Type | Confirmation Pattern |
|---|---|
| SQL Injection | SQL error strings: `sql syntax`, `you have an error in your sql`, `ora-`, `unclosed quotation mark`, etc. |
| SQLi Login Bypass | Dashboard/admin keywords in response after SQLi payload |
| XSS Reflected | `<script`, `alert(`, `onerror=`, `javascript:`, `document.cookie` in response |
| XSS Stored | Same patterns in response to subsequent GET request |
| Path Traversal / LFI | `root:x:0:0:`, `daemon:x:`, `/bin/bash`, `/sbin/nologin`, `[boot loader]`, `win.ini` |
| XXE | `root:x:0:0:`, `daemon:x:`, `/bin/bash`, `169.254.169.254`, `failed to load external entity` |
| SSRF | `internal`, `localhost`, `127.0.0.1`, `169.254.169.254`, `metadata`, `aws`, `cloud` |
| IDOR | Email, address, phone, credit card, dashboard keywords in response (no login redirect) |
| Information Disclosure | Version strings, DB error, API key, password, `-----BEGIN`, `environment`, `config` |
| CORS Misconfiguration | `Access-Control-Allow-Origin` reflecting attacker origin + `Access-Control-Allow-Credentials: true` |
| Host Header Injection | Response body contains injected host value in password reset links or redirects |
| Web Cache Poisoning | Injected header value reflected in cached response to different user |
| Web Cache Deception | Sensitive data returned in response to cache-busting URL |
| NoSQL Injection | All records returned, authentication bypassed with `[$ne]` operator |
| Prototype Pollution | Server-side property pollution confirmed via observable behaviour change |
| GraphQL Exposure | `__schema`, `__types`, full introspection response |
| HTTP Request Smuggling | Timeout or content-length desync indicator |
| 2FA Bypass | Authenticated session without valid OTP |
| Web LLM Prompt Injection | LLM output contains injected instruction or exfiltrated data |

---

## 9. Payload Corpus Reference

### 9.1 How It Works

The `PayloadCorpus` class (`src/core/corpus.py`) tracks successful payloads across scans.

**File location:** `~/.pentest-ai-agent/corpus.json`

**Format:**
```json
{
  "sql_injection": [
    {
      "payload": "' OR 1=1--",
      "url_pattern": "https://target.com/login",
      "param": "username",
      "success_count": 3,
      "last_used": 1742812234
    }
  ],
  "path_traversal": [
    {
      "payload": "https://target.com/image?filename=../../../../etc/passwd",
      "url_pattern": "https://target.com/image?filename=40.jpg",
      "param": "filename",
      "success_count": 1,
      "last_used": 1742810000
    }
  ]
}
```

### 9.2 Prioritisation Algorithm

`get_candidates(vuln_type, url, param)` scores each stored entry:

```
score = success_count
      + 5  (if stored url_pattern path appears in current url path)
      + 3  (if stored param name matches current param, case-insensitive)
```

Entries are returned sorted by score descending. The highest-scored payloads are
tried first — within the PATH TRAVERSAL fast-path they are prepended to the probe
list ahead of generic depth-3/4/5 variants.

### 9.3 Recording Success

`record_success(vuln_type, payload, url, param)` is called at 5 points in `ExploitAgent`:

1. PATH TRAVERSAL fast-path confirmation
2. Claude/OpenAI auto-detection block (first)
3. Ollama tool-call auto-detection block
4. Claude/OpenAI auto-detection block (second)
5. LLM final confirmation via `CONFIRMED` keyword

### 9.4 Managing the Corpus

```bash
# View current corpus
cat ~/.pentest-ai-agent/corpus.json

# Reset corpus (start fresh)
rm ~/.pentest-ai-agent/corpus.json

# Back up corpus
cp ~/.pentest-ai-agent/corpus.json ~/corpus_backup_$(date +%Y%m%d).json
```

Vuln types are normalised to lowercase with non-alphanumeric characters replaced
by underscores: `"SQL Injection (Source)"` → `"sql_injection__source_"`.

---

## 10. Scope Rules Reference

### 10.1 How Scope Evaluation Works

Scope is evaluated by `WorkspaceManager.in_scope(url)`:

```
1. If scope_exclude patterns exist:
      → if ANY pattern matches url: REJECT (out of scope)
2. If scope_include patterns exist:
      → if NO pattern matches url: REJECT (out of scope)
3. Otherwise: ACCEPT (default-permit)
```

Patterns use Python `re.search()` with `re.IGNORECASE` — they match anywhere in the URL,
not just at the start.

### 10.2 Where Scope is Applied

| Location | Effect |
|---|---|
| `ReconAgent` anchor link collection | Out-of-scope URLs never enter `links` set |
| `ReconAgent` media tag collection | Out-of-scope file-serving URLs excluded |
| `ReconAgent` sub-page crawl | Out-of-scope links excluded from page context |

> **Note:** `ExploitAgent` currently does not enforce scope on LLM-generated tool calls
> (the LLM may navigate to any URL it discovers). Scope filtering is primarily a
> recon-time control.

### 10.3 Pattern Examples

```bash
# Allow only /api/ subtree
--scope-include '/api/'

# Allow specific subdomain only
--scope-include 'app\.example\.com'

# Allow multiple subtrees
--scope-include '/api/' --scope-include '/graphql' --scope-include '/admin'

# Exclude static files (CSS, JS, images, fonts)
--scope-exclude '\.(css|js|png|jpg|gif|svg|ico|woff2?|ttf|eot|map)(\?.*)?$'

# Exclude logout and static directories
--scope-exclude '/logout' --scope-exclude '/static/' --scope-exclude '/assets/'

# Exclude external CDN links
--scope-exclude 'cdn\.' --scope-exclude 'fonts\.googleapis'

# Combined: API-only scan, no static assets
--scope-include '/api/' \
--scope-exclude '\.(css|js|png|jpg|svg)$'
```

---

## 11. Report Format Reference

### 11.1 Output Location

```
reports/
└── <hostname>/
    └── pentest_report_<YYYY-MM-DD_HHMMSS>.docx
```

### 11.2 DOCX Section Breakdown

| Section | Generated By | Content |
|---|---|---|
| Title Page | Template | Target URL, scan date, classification |
| Executive Summary | LLM / `_generate_narrative_fallback()` | Risk narrative, finding count by severity |
| Attack Surface Overview | LLM / `_generate_narrative_fallback()` | Endpoint inventory, tech stack, form list, header/cookie issues |
| Findings Summary Table | Deterministic | All findings: severity, CVSS, location, title |
| Detailed Findings | Deterministic | Per finding: description + PoC + screenshot |
| Static Analysis Findings | Deterministic (if `static_findings` present) | File:line findings from source code scan |
| Remediation Roadmap | LLM / `_generate_narrative_fallback()` | Prioritised remediation steps |
| Conclusion | LLM / `_generate_narrative_fallback()` | Overall risk assessment |

### 11.3 CVSS 3.1 Severity Bands

| Score Range | Severity |
|---|---|
| 0.0 | Informational |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

---

## 12. LLM Provider Reference

### 12.1 Claude (Anthropic) — `--provider claude`

| Setting | Value |
|---|---|
| Default model | `claude-sonnet-4-6` |
| Tool calling | Native Anthropic `tool_use` blocks |
| Max tokens | 4096 (vuln analysis), 8192 (exploitation) |
| Retry | 5 attempts, exponential backoff (2→4→8→16→32 s) |
| Streaming | No |

**When to use:** Best for complex reasoning, multi-step exploitation, and high-quality
narrative in reports. Recommended for engagements.

### 12.2 OpenAI GPT-4o — `--provider openai`

| Setting | Value |
|---|---|
| Default model | `gpt-4o` |
| Tool calling | OpenAI function calling (Anthropic schema auto-converted) |
| Max tokens | 4096 (vuln analysis) |
| Retry | 5 attempts, exponential backoff |
| Streaming | No |

**When to use:** Alternative to Claude with comparable reasoning capability.

### 12.3 Ollama (Local) — `--provider ollama`

| Setting | Value |
|---|---|
| API | OpenAI-compatible `/v1` endpoint |
| Default model | `qwen2.5-coder:7b-instruct` (configurable via `.env`) |
| Pre-flight check | GET `/api/tags` on startup |
| Max tokens | 2048 (reduced for small models) |
| Temperature | 0.1 (fixed for determinism) |
| Retry | 3 attempts |
| Report narrative | Pure Python fallback (bypasses LLM) |

**Context trimming for Ollama:**
- Links: first 10 only
- Params: first 8 only
- JS endpoints: first 5 only
- Surface map: first 800 chars only

**When to use:** Air-gapped environments, cost-sensitive testing, offline labs.
Quality of exploitation depends heavily on model capability — larger models (13B+)
produce significantly better results.

**Recommended models (tested):**
- `qwen2.5-coder:7b-instruct` — best for structured JSON output
- `deepseek-coder:6.7b` — good code reasoning
- `mistral:7b-instruct` — general purpose
- `llama3.1:8b` — balanced

**Setup:**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull qwen2.5-coder:7b-instruct

# Start server (if not auto-started)
ollama serve

# Run agent
python3 main.py --url https://target.com --repo . --provider ollama
```

---

## 13. WorkspaceManager Reference

`WorkspaceManager` is the shared state object passed to every agent.

### Constructor

```python
WorkspaceManager(
    target_url: str,
    repo_path: str,
    headers: dict = None,
    cookies: dict = None,
    scope_include: list[str] = None,   # regex allow-list
    scope_exclude: list[str] = None,   # regex deny-list
)
```

### Properties

| Property | Type | Description |
|---|---|---|
| `target_url` | str | Scan target URL |
| `repo_path` | str | Source repository path |
| `headers` | dict | HTTP headers injected into all requests |
| `cookies` | dict | Cookies injected into all requests |
| `recon_data` | dict | All recon data keyed by string |
| `hypotheses` | list | All vulnerability hypotheses |
| `findings` | list | Confirmed exploits with PoC |
| `page_contexts` | dict | Per-URL page context from crawl |
| `corpus` | PayloadCorpus | Payload learning instance |

### Methods

| Method | Signature | Description |
|---|---|---|
| `add_recon_data` | `(key, data)` | Store recon data |
| `get_recon_data` | `(key) → any` | Retrieve recon data |
| `add_hypothesis` | `(vuln_type, details, location, cvss_score, cvss_vector, severity)` | Add hypothesis |
| `add_exploit_result` | `(hypothesis_index, success, proof, screenshot_path)` | Record exploit result |
| `add_page_context` | `(url, context)` | Store per-page context |
| `get_page_contexts` | `() → dict` | Retrieve all page contexts |
| `in_scope` | `(url) → bool` | Check if URL passes scope rules |

### Hypothesis Schema

```python
{
    "type":       str,    # e.g. "SQL Injection"
    "details":    str,    # exploitation guidance and payload hints
    "location":   str,    # URL or file:line
    "cvss_score": float,  # CVSS 3.1 base score
    "cvss_vector": str,   # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    "severity":   str,    # "Critical" | "High" | "Medium" | "Low" | "Informational"
    "status":     str,    # "pending" | "exploited" | "failed"
}
```

### Finding Schema

```python
{
    "hypothesis":      dict,   # the hypothesis object
    "proof":           str,    # structured PoC text
    "screenshot_path": str,    # path to PNG screenshot (or None)
}
```

---

## 14. Troubleshooting

### Agent fails with `ModuleNotFoundError`

Ensure the virtual environment is activated and dependencies are installed:

```bash
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

### `playwright._impl._errors.Error: Executable doesn't exist`

```bash
playwright install chromium
```

### `ANTHROPIC_API_KEY not found` / `OpenAI API key not found`

Ensure `.env` is in the project root and contains the correct key:

```bash
cat .env | grep API_KEY
```

### Ollama: `Connection refused` at startup

The Ollama server is not running. Start it:

```bash
ollama serve
```

Or check if it's running on a different port and update `OLLAMA_BASE_URL` in `.env`.

### Ollama: model not found

```bash
ollama pull qwen2.5-coder:7b-instruct
```

### Hypothesis count is 0 after recon

The target may be blocking automated requests. Try:

```bash
# Add cookies from a logged-in browser session
python3 main.py --url https://target.com --repo . \
    --cookies '{"session": "<your-session-cookie>"}' \
    --headers '{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}'
```

### PATH TRAVERSAL not detected for `/image?filename=`

Ensure the image URL is reachable from the crawled HTML. Check that `<img src="/image?filename=...">` is present in the root page DOM. The agent automatically detects file-serving media URLs with query parameters.

### Report not generated / report is empty

Check that `reports/<hostname>/` directory is writable:

```bash
ls -la reports/
```

Also verify that at least one finding was confirmed (status = `exploited`):

```python
# In Python
import json
# Run with --mock-llm and check workspace output
```

### JSON parse error in VulnAnalyzer

The LLM returned malformed JSON. The agent automatically retries once with a stricter prompt. If both attempts fail, structural hypotheses (from Phase A) are still available.

### LLM rate limit / timeout

All engines implement exponential backoff. If errors persist, check your API quota and billing status. For Ollama, increase `OLLAMA_NUM_CTX` only if you have sufficient VRAM.

---

## 15. Extending the Agent

### Adding a New Agent Phase

1. Create `src/agents/my_agent.py` inheriting from `BaseAgent`:

   ```python
   from src.agents.base import BaseAgent
   from src.core.workspace import WorkspaceManager

   class MyAgent(BaseAgent):
       def __init__(self, engine):
           super().__init__(engine)

       async def execute(self, workspace: WorkspaceManager) -> None:
           # read from workspace, write results back
           pass
   ```

2. Register in `main.py`:

   ```python
   from src.agents.my_agent import MyAgent
   orchestrator.register_agent("my_phase", MyAgent(engine))
   ```

3. Add the phase slot in `orchestrator.py`:

   ```python
   if "my_phase" in self.agents:
       await self.agents["my_phase"].execute(self.workspace)
   ```

### Adding a Static Analysis Pattern

Edit `src/agents/static_analysis.py` and call `_reg()`:

```python
_reg(
    "*.py",                                   # file glob
    r'eval\s*\(\s*.*request\.',               # regex pattern
    "Eval Injection (Source)",                # vuln type name
    9.8,                                      # CVSS base score
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # CVSS vector
    "eval() called with request data — arbitrary code execution possible."  # detail
)
```

### Adding a New LLM Provider

1. Create a class in `src/core/llm.py` implementing the engine interface
   (same methods as `ClaudeEngine`, `OpenAIEngine`, `OllamaEngine`)
2. Add a `elif args.provider == "myprovider":` branch in `main.py`

### Adding a Vulnerability to the Path Keyword Map

Edit `src/agents/vuln.py` and add an entry to `PATH_KEYWORD_MAP`:

```python
(r"my_endpoint|my_path",
 "My Vulnerability Type",    "High",  7.5,
 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
