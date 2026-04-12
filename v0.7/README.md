# Agentic Web Pentest — v0.7.0 (+ Burp Suite Extension)

An autonomous, AI-driven web application penetration testing agent that performs **reconnaissance**, **static source code analysis**, **vulnerability analysis**, **active exploitation**, and **professional report generation** — powered by **Claude**, **OpenAI GPT-4o**, or a **local Ollama server**.

---

## Features

| Feature | Detail |
|---|---|
| **Burp Suite Extension** | Native Montoya API plugin — launch scans & review findings without leaving Burp |
| **Multi-Provider LLM** | `--provider anthropic` (default), `openai`, or `ollama` (local) |
| **5-Phase Agentic Pipeline** | Recon → Static Analysis → Vuln Analysis → Exploitation → Reporting |
| **Static Source Code Analysis** | 71 patterns aligned to OWASP Top 10 (2021) across Python, PHP, JS, Java, Ruby, Go — no LLM required |
| **PHP Taint Tracking** | Detects two-step patterns (`$var = $_GET[...]` → `shell_exec(... . $var)`) — catches DVWA-style vulns |
| **Multi-page Chain Detection** | Cross-page signals generate chained attack hypotheses (File Upload→RCE, XSS→ATO, IDOR, OAuth Token Theft, SSRF→Cloud, Debug Leak) |
| **Payload Corpus Learning** | Successful payloads persisted to `~/.pentest-ai-agent/corpus.json` and prioritised on future scans |
| **Configurable Scope Rules** | `--scope-include` / `--scope-exclude` regex filters control which URLs are crawled and tested |
| **Static-Only Mode** | `--static-only` runs Phase 1.5 + report only — no URL or active exploitation required |
| **Separate Source Path** | `--source` points specifically to the source code directory for static analysis |
| **JS Endpoint Discovery** | Hidden API endpoints extracted from same-origin JavaScript files |
| **Authenticated Scanning** | Custom headers and cookies injected into all browser and curl requests |
| **Playwright Exploitation** | Browser-native payload injection via `browser_fill`, `browser_click`, `browser_get_dom` |
| **Professional DOCX Reports** | Vendor-ready `.docx` with CVSS 3.1 scoring, severity tables, PoC sections, and screenshots |
| **API Retry Logic** | Exponential backoff (5 attempts, up to 32s) for transient API errors |

---

## Agentic Pipeline

All agents share state through a central `WorkspaceManager`.

```
Phase 1    ──  ReconAgent            Playwright crawl, JS analysis, header/cookie audit
Phase 1.5  ──  StaticAnalysisAgent  Source code scan (30+ vuln patterns, file:line output)
Phase 2    ──  VulnAnalyzerAgent     Structural + LLM + chain hypothesis generation
Phase 3    ──  ExploitAgent          LLM tool-calling exploit loop with corpus learning
Phase 4    ──  ReportingAgent        DOCX report with PoC, CVSS 3.1, screenshots
```

### Phase 1 — Reconnaissance (`recon.py`)
- Playwright-based crawl of the target and all discovered same-origin sub-pages.
- Extracts forms, query parameters, same-origin links, and file-serving URLs (`<img src>`, `<video src>`, etc.).
- Fetches and analyses JS files to uncover hidden API endpoints.
- Performs passive HTTP header audit (missing security headers, cookie flags, server version disclosure).
- Stores per-page context (forms, params, file-upload presence, admin-path indicators, auth indicators) for chain analysis in Phase 2.
- All link collection is scope-filtered via `workspace.in_scope()`.

### Phase 1.5 — Static Source Code Analysis (`static_analysis.py`)
- Walks `--source` path (skips `.git`, `node_modules`, `venv`, `vendor`, `dist`, `build`).
- **71 patterns** aligned to **OWASP Top 10 (2021)** across Python, PHP, JS/TS, Java, Ruby, Go.
- **PHP two-step taint detection**: detects `$var = $_GET[...]` (taint source) and dangerous sinks separately — catches DVWA-style patterns where user input is assigned to a variable before use.
- Each match adds a hypothesis with `file:line` location, matched snippet, CVSS score, and vector.
- Runs deterministically — no LLM call required.

#### OWASP Top 10 Coverage

| OWASP | Category | What is Detected |
|---|---|---|
| **A01** | Broken Access Control | IDOR direct queries, missing auth decorators, session fixation, open redirect |
| **A02** | Cryptographic Failures | TLS/SSL disabled, weak password hashing (MD5/SHA1), cleartext HTTP, insecure random |
| **A03** | Injection | SQL, NoSQL (MongoDB), Command, LDAP, XPath, SSTI, XXE, Path Traversal/LFI, eval() code injection |
| **A05** | Security Misconfiguration | Debug mode enabled, verbose PHP errors, default credentials, directory listing |
| **A07** | Auth Failures | Plaintext password storage, insecure cookie flags (no HttpOnly/Secure), JWT weak secret |
| **A08** | Software Integrity | Insecure deserialization: `pickle.loads`, `yaml.load`, PHP `unserialize`, Java `ObjectInputStream` |
| **A09** | Logging Failures | Passwords/tokens written to logs, raw exception messages returned in HTTP response |
| **A10** | SSRF | Python `requests`/`httpx`, PHP `curl`/`file_get_contents` with user-controlled URL |

### Phase 2 — Vulnerability Analysis (`vuln.py`)
- **Phase A** — Deterministic structural analysis: path keywords, query param names, form input types, security headers, serialised cookies.
- **Phase A.5** — Multi-page chain detection: correlates signals across all crawled pages to emit 6 chained-attack hypothesis types.
- **Phase B** — LLM contextual analysis: Claude / GPT-4o / Ollama reasons about the full attack surface.

#### Chained Attack Hypotheses

| Chain | Severity |
|---|---|
| File Upload + Path Traversal → RCE | Critical |
| XSS + Admin Panel → Session Hijacking / ATO | High |
| Cross-Page IDOR → Privilege Escalation | High |
| Open Redirect + OAuth → Token Theft | High |
| SSRF + Any page → Cloud Metadata Theft | Critical |
| Debug Info Leak + Admin Panel → Privesc | High |

### Phase 3 — Active Exploitation (`exploit.py`)
- LLM acts as an interactive attacker using `browser_navigate`, `browser_get_dom`, `browser_fill`, `browser_click`, and `run_terminal_command`.
- **Fast-paths**: PATH TRAVERSAL and Informational blocks bypass the LLM loop for known patterns.
- **Corpus learning**: corpus-proven payloads are prepended to probe lists; every confirmed exploit is recorded to `~/.pentest-ai-agent/corpus.json`.
- Takes a Playwright screenshot on every confirmed exploit.

### Phase 4 — Reporting (`report.py`)
- Generates a professional `.docx` report with CVSS 3.1 scoring, PoC sections, and screenshots.
- **Static-only mode**: builds findings from `workspace.hypotheses` directly (IDs prefixed `SA-`).
- Supports Claude, OpenAI, and Ollama narrative generation.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/youruser/pentest-ai-agent.git
cd pentest-ai-agent/development

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

---

## Configuration

```bash
cp .env.example .env
```

```env
# LLM Provider API Keys
ANTHROPIC_API_KEY=your_anthropic_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Ollama Local Model (used when --provider ollama)
OLLAMA_BASE_URL=http://172.30.48.1:11434
OLLAMA_MODEL=qwen2.5-coder:7b-infosec
OLLAMA_NUM_CTX=8192
OLLAMA_TEMPERATURE=0.1
```

Only the key for the selected `--provider` is required.

---

## Usage

```bash
source venv/bin/activate

# Full pipeline — Claude (default)
python3 main.py --url http://target.com --source /path/to/webapp

# Full pipeline — source code in a subdirectory
python3 main.py --url http://target.com --repo . --source ./src

# Static analysis only — no URL needed
python3 main.py --static-only --source /path/to/dvwa

# Static analysis only — with Ollama
python3 main.py --static-only --source /var/www/html --provider ollama

# Run with OpenAI GPT-4o
python3 main.py --url http://target.com --source . --provider openai

# Run with local Ollama
python3 main.py --url http://target.com --source . --provider ollama \
    --ollama-url http://172.30.48.1:11434 \
    --ollama-model qwen2.5-coder:7b-infosec

# Authenticated scan
python3 main.py --url http://target.com --source . \
    --cookies '{"session": "abc123"}' \
    --headers '{"Authorization": "Bearer token"}'

# Scope-limited scan — only test /api/ endpoints
python3 main.py --url http://target.com --source . \
    --scope-include '/api/'

# Exclude static assets
python3 main.py --url http://target.com --source . \
    --scope-exclude '\.(css|js|png|jpg|svg|woff2?)$' \
    --scope-exclude '/logout'

# Mock mode (no API calls)
python3 main.py --url http://target.com --source . --mock-llm
```

### CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `--url` | *(required)* | Target URL to scan (not required when `--static-only`) |
| `--repo` | `.` | Project root / working directory |
| `--source` | same as `--repo` | Source code directory for static analysis |
| `--static-only` | off | Run Phase 1.5 + Phase 4 only — no crawl or exploitation |
| `--provider` | `anthropic` | LLM backend: `anthropic`, `openai`, or `ollama` |
| `--ollama-url` | `http://172.30.48.1:11434` | Ollama server URL (overrides `OLLAMA_BASE_URL`) |
| `--ollama-model` | `qwen2.5-coder:7b-infosec` | Ollama model name (overrides `OLLAMA_MODEL`) |
| `--mock-llm` | off | Offline mode — no API calls |
| `--headers` | `{}` | JSON string of HTTP headers to inject |
| `--cookies` | `{}` | JSON string of cookies to inject |
| `--scope-include` | *(none)* | Regex allow-list: only crawl/test URLs matching at least one pattern |
| `--scope-exclude` | *(none)* | Regex deny-list: skip URLs matching any of these patterns |
| `--max-hypotheses` | `8` | Maximum LLM-generated hypotheses per scan |

---

## Scope Rules

Rules use Python `re` syntax and are evaluated in order:

1. **Exclude first** — if any `--scope-exclude` pattern matches, the URL is skipped.
2. **Include filter** — if `--scope-include` patterns are set, the URL must match at least one.
3. **Default permit** — if no patterns are set, all same-origin URLs are in scope.

```bash
# Only test /app/ or /api/
--scope-include '/app/' --scope-include '/api/'

# Skip known-safe paths
--scope-exclude '/logout' --scope-exclude '/static/'
```

---

## Payload Corpus

Successful exploit payloads are saved to:

```
~/.pentest-ai-agent/corpus.json
```

On subsequent scans, proven payloads are tried first, prioritised by success count and URL/parameter similarity. The corpus grows passively — no manual management required.

---

## Project Structure

```
development/
├── main.py                         # Entry point + CLI argument parsing
├── requirements.txt
├── .env.example
├── src/
│   ├── agents/
│   │   ├── base.py                 # BaseAgent class
│   │   ├── recon.py                # Phase 1   — Playwright web crawl + header audit
│   │   ├── static_analysis.py      # Phase 1.5 — Source code static analysis
│   │   ├── vuln.py                 # Phase 2   — Structural + chain + LLM hypothesis generation
│   │   ├── exploit.py              # Phase 3   — LLM tool-calling exploitation engine
│   │   └── report.py               # Phase 4   — DOCX report generation
│   ├── core/
│   │   ├── llm.py                  # ClaudeEngine, OpenAIEngine, OllamaEngine
│   │   ├── orchestrator.py         # 5-phase pipeline coordination
│   │   ├── workspace.py            # Shared state (scope, page contexts, corpus)
│   │   └── corpus.py               # Payload learning persistence
│   └── tools/
│       ├── browser.py              # Playwright browser tool
│       ├── terminal.py             # Shell command execution (curl, nmap)
│       ├── filesystem.py           # Filesystem access tool
│       └── tool_defs.py            # Tool JSON schema definitions
└── reports/
    └── <hostname>/
        └── pentest_report_<timestamp>.docx
```

---

## Burp Suite Extension

The `burpsuite-plugins/` directory contains a native Burp Suite extension (Montoya API) that connects to the Web UI backend, allowing you to launch scans and review findings directly from Burp.

### Requirements

- Burp Suite Professional / Community 2023.10+
- Java 17+ (for building)
- Agentic Pentest AI Web UI backend running (`docker compose up`)

### Build & Install

```bash
cd burpsuite-plugins
./gradlew shadowJar
# Output: build/libs/agentic-pentest-burp-0.7.0.jar
```

In Burp Suite: **Extensions → Add → Java → select the JAR**

### Features

- **Context menu** — Right-click any request in Proxy / Repeater / Target → "Send to Agentic Pentest AI"
- **Scans tab** — Live scan list with auto-refresh every 5 seconds, cancel button
- **Findings tab** — Colour-coded severity table with full detail pane (description, PoC, recommendations)
- **Settings tab** — Backend URL + credentials, JWT token persisted across Burp restarts

See `burpsuite-plugins/README.md` for full documentation.

---

## Disclaimer

This tool is for **authorized penetration testing and educational purposes only**.
Always obtain explicit written permission from the system owner before testing.
Unauthorized use is illegal and unethical.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
