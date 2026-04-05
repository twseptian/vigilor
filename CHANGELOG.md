# Changelog

All notable changes to **Pentest AI Agent** are documented in this file.

---

## [v0.7.0] — 2026-04-05

### Bug Fixes — Web UI

- **Scan severity counters not updating after finding edit** (`routers/findings.py`):
  `findings_critical/high/medium/low/info` on the `Scan` row were only written by
  the scanning engine and never updated when a user manually changed a finding's
  severity or CVSS from the UI. Added `_sync_scan_severity_counts()` helper that
  re-aggregates all finding severities via `GROUP BY` and updates the scan row.
  Called after every `PATCH /findings/{id}` and `POST /findings/bulk-status`.
  The coloured severity circles on the Scans list page now reflect live user edits.

- **Stale findings cache on ScanDetailPage** (`frontend/src/main.tsx`, `FindingDetailPage.tsx`, `FindingListPage.tsx`):
  React Query `staleTime: 30_000` caused the findings list and overview chart on
  `ScanDetailPage` to show old data for up to 30 seconds after a finding was edited.
  Fixed by:
  - Lowering global `staleTime` to `0` so data is always considered stale on mount.
  - `FindingDetailPage` mutations now call `invalidateFinding()` which also
    invalidates `["findings", scan_id]` and `["findings"]` — not just the single
    `["finding", id]` key.
  - `FindingListPage` bulk-status mutation also invalidates `["findings"]`.

### New Features — Burp Suite Extension

- **Burp Suite plugin** (`burpsuite-plugins/`):
  A native Burp Suite extension (Montoya API, Java 17) that connects directly
  to the Agentic Pentest AI FastAPI backend, enabling scan management and
  findings review without leaving Burp.

  **Components:**
  - `AgenticPentestExtension.java` — Extension entry point; registers suite tab
    and context menu "Send to Agentic Pentest AI" in Proxy, Repeater, Target, Logger.
  - `AgentApiClient.java` — Thread-safe REST client (Java 11 `HttpClient`, forced
    HTTP/1.1 to avoid h2c upgrade failures against uvicorn).
  - `ScansPanel.java` — Scan list table with auto-poll every 5 seconds, cancel
    button, double-click / "View Findings" button, race-condition-safe
    `lastSelectedScanId` to survive poll rebuilds.
  - `FindingsPanel.java` — Findings table with severity colour-coding
    (Critical / High / Medium / Low) and full detail pane below.
  - `SettingsPanel.java` — Backend URL + credentials; JWT token persisted in
    Burp preferences across restarts.
  - `NewScanDialog.java` — Modal dialog pre-filled with selected request URL;
    configures LLM provider, model, hypotheses, parallel workers, custom prompt.

  **Build:** Gradle shadow JAR bundles Gson (relocated to avoid conflicts).
  Output: `build/libs/agentic-pentest-burp-0.7.0.jar` (~320 KB).

  **Bug fixes applied during development:**
  - Forced `HTTP_1_1` on `HttpClient` — Java's default HTTP/2 h2c upgrade
    caused uvicorn to return 400 "Invalid HTTP request received".
  - `scope_include` / `scope_exclude` changed from `String "[]"` to
    `List<String>` — backend expected JSON array, not a string literal.
  - `lastSelectedScanId` field in `ScansPanel` — poll-rebuild cleared table
    selection causing "View Findings" to silently no-op; now falls back to
    last recorded selection.
  - Direct `JTabbedPane` reference wired via `setTabbedPane()` — `getParent()`
    traversal was unreliable for tab switching.
  - **JWT expiry handling** (`AgentApiClient`, `ScansPanel`): 401 response now
    throws `AuthExpiredException`, stops the poll timer, shows
    "Session expired — please re-login in Settings tab". Re-login in
    Settings automatically restarts polling via `onLoginSuccess` callback.
  - **LLM model detection** (`NewScanDialog`): Model field replaced with
    provider-aware `JComboBox`. Anthropic/OpenAI show curated model lists.
    Ollama auto-detects models via `POST /settings/detect-ollama-models` on
    dialog open with a manual "Detect" refresh button. OpenRouter uses editable
    combobox for free-text entry.

---

## [v0.7.0] — 2026-04-03

### New Features — Learning & Corpus

- **Corpus extended to all vulnerability types** (`exploit.py`):
  Previously, corpus-learned payloads were only injected for path traversal.
  All hypothesis types (XSS, SQLi, IDOR, SSRF, auth bypass, etc.) now receive
  a `[CORPUS HINT]` block in the initial LLM exploit prompt listing the top-6
  historically successful payloads ranked by `success_count` + URL/param bonuses.
  The LLM is instructed to try these payloads first before generating new ones.

- **Dynamic WSTG hints per tech stack** (`vuln.py`):
  New `_build_tech_wstg_hints(tech_stack)` function maps 15 detected technologies
  to WSTG-specific test cases injected into the vulnerability analysis prompt:

  | Technology | WSTG Hints Injected |
  |---|---|
  | PHP | LFI `php://filter`, SQLi `SLEEP(5)`, PHPSESSID manipulation |
  | WordPress / WooCommerce | User enumeration, xmlrpc SSRF, order IDOR |
  | Django / Flask | SSTI `{{7*7}}`, debug mode, SECRET_KEY brute |
  | Node.js / Express | Prototype pollution `__proto__`, SSRF quirks |
  | React / SPA | DOM XSS sinks, hidden admin routes in JS bundle |
  | Spring / Java | SpEL injection, Actuator endpoints, deserialization |
  | Ruby on Rails | SSTI, mass assignment, CSRF bypass |
  | GraphQL | Introspection, batch abuse, nested query DoS |
  | MySQL / PostgreSQL | Dialect-specific SQLi payloads |
  | JWT / OAuth | alg:none, weak secret, state CSRF |
  | AWS / Cloud | SSRF to metadata `169.254.169.254` |
  | Nginx / Apache | Alias traversal, server-status, verb tampering |

  Hints are only injected when technology is detected from server headers or
  cross-scan memory — no noise for unknown stacks.

### New Features — Broken Access Control & Business Logic

- **BAC forced-browsing fast-path** (`exploit.py`):
  Before entering the LLM exploit loop, the agent navigates to the hypothesis
  endpoint plus 8 common admin paths (`/admin`, `/dashboard`, `/manage`, etc.)
  **without authentication cookies/headers** and checks for admin-content
  indicators. Bypasses the LLM loop entirely if access is confirmed, taking a
  screenshot and recording to corpus/memory.

- **JWT role manipulation fast-path** (`exploit.py`):
  Scans workspace cookies, headers, and page DOM for JWT tokens (`eyJ...`).
  Forges a new token using the **alg:none attack** with elevated role claims
  (`role=admin`, `admin=true`). Tests the forged token against the target
  endpoint. Falls back to the LLM loop with a hint if alg:none fails.

- **Business logic deterministic probes** (`exploit.py`):
  Before the LLM loop, fires URL parameter tampering probes tailored to the
  hypothesis type:
  - Price tampering: `price=0`, `price=-1`, `amount=0`, `total=0.01`
  - Negative quantity: `quantity=-1`, `qty=-1`, `quantity=99999`
  - Coupon abuse: scans page for coupon codes, tests reuse + `SAVE100`
  - Subscription bypass: `plan=enterprise`, `tier=premium`, `trial=true`

  New `_detect_business_logic_success()` method confirms exploitation by
  checking for "order confirmed", "discount applied", "$0.00", etc.

- **Race condition concurrent handler** (`exploit.py`):
  For race/coupon hypotheses, fires **10 concurrent HTTP POST requests** via
  `asyncio.gather` + `httpx.AsyncClient`. If ≥2 requests return a success
  response, race condition is confirmed with evidence.

- **E-commerce / business logic attack vectors** (`vuln.py`):
  New `PATH_KEYWORD_MAP`, `PARAM_KEYWORD_MAP`, and `FORM_INPUT_MAP` entries for
  refund/chargeback, coupon/voucher, inventory/stock, shipping/billing, and
  subscription/plan endpoints. System prompt extended with
  `=== E-COMMERCE / BUSINESS LOGIC (WSTG-BUSL) ===` section covering price
  tampering, coupon stacking, workflow bypass, IDOR on cart/order/address,
  refund abuse, and subscription bypass.

- **Auto-detect wired for BAC and business logic** (`exploit.py`):
  All three auto-detect blocks (Ollama text, OpenAI native tool-call, final
  text) now call `_detect_broken_access_control()`, `_detect_business_logic_success()`,
  and `_detect_race_condition()` alongside existing detectors.

### New Features — Ollama Reliability

- **Ollama context overflow auto-trim** (`core/llm.py`):
  `OllamaEngine.generate_response()` now calculates a character budget from
  `(num_ctx - max_tokens - 800) * 4` before each API call. If the accumulated
  message history exceeds the budget, the oldest non-system messages are dropped
  (preserving the first user message as anchor). Prevents HTTP 500 context
  overflow errors on local models. Logs when trimming occurs.

- **Ollama max_tokens configurable from Settings** (`models/settings.py`, `routers/settings.py`, `scan_runner.py`, `exploit.py`):
  New `ollama_max_tokens` field (default 512) added to `global_settings` table.
  Exposed in the Settings UI under Ollama section as "Max Output Tokens".
  Flows through to `OLLAMA_MAX_TOKENS` env var → `exploit.py` exploit loop.
  Alembic migration `0002_add_ollama_max_tokens.py` handles existing installs.

### New Features — Recon

- **SPA route discovery** (`recon.py`):
  Step 3.5 extracts client-side routes from JavaScript bundles using patterns
  for React Router (`path:`), Vue Router, Angular `loadChildren`, and API paths
  (`/api/`, `/v1/`, `/rest/`).

- **Navigation interaction crawl** (`recon.py`):
  Step 3.7 clicks nav/sidebar/header/menu links to trigger dynamic menu
  rendering and collect additional endpoints not visible in initial DOM.

- **2-level deep page crawl** (`recon.py`):
  Step 4 crawls up to 30 pages at L1 and 20 at L2. High-value pages (login,
  admin, checkout, API) are flagged via `_HIGH_VALUE_KW` regex. Inline JS is
  extracted from each visited page for endpoint discovery.

### New Features — Backup & Restore

- **ZIP backup with evidence screenshots** (`routers/backup.py`):
  Backup format upgraded from JSON (v1.0) to ZIP (v2.0):
  - `database.json` — all projects, scans, findings, comments
  - `evidence/<scan_id>/evidence/*.png` — all screenshot files

  Import restores both database records and evidence files to
  `/app/data/scans/<scan_id>/evidence/`. Legacy v1.0 `.json` files remain
  supported for import. Export/import buttons in Settings → Backup now
  accept `.zip` and `.json`. Import result shows `evidence_restored` count.

### Bug Fixes

- **Custom prompt not reaching Ollama ExploitAgent** (`services/scan_runner.py`):
  `_inject_prompt()` only injected into `system_prompt` but `ExploitAgent`
  for Ollama uses a separate `ollama_system_prompt` attribute.
  Fixed to inject into both attributes.

- **Custom prompt not reaching ReportingAgent** (`agents/report.py`):
  Report generation functions used the hardcoded `_CLOUD_SYSTEM_PROMPT`
  constant, ignoring any operator context. `_generate_narrative_cloud()` and
  `_generate_narrative_ollama()` now accept `operator_context` and prepend it
  to the effective system prompt.

- **Dashboard charts empty** (`routers/dashboard.py`):
  `datetime.now(timezone.utc)` used as WHERE clause cutoff caused PostgreSQL
  comparison failures. All occurrences replaced with `datetime.utcnow()`.

---

## [v0.6.0] — 2026-04-02

### Security Fixes (Web UI)

- **Rate limiting on login endpoint** (`auth/router.py`, `limiter.py`):
  Login endpoint is now capped at **5 requests/minute per IP** via `slowapi`.
  A standalone `backend/limiter.py` module was introduced to avoid a circular
  import between `auth/router.py` and `main.py`.

- **SSRF guard on scan creation** (`routers/scans.py`):
  `_validate_target_url()` resolves the target hostname via `socket.getaddrinfo`
  and rejects any IP that falls in RFC-1918 / loopback / link-local ranges
  (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16,
  ::1/128, fc00::/7, fe80::/10). Returns HTTP 422 with a descriptive error.

- **Cancel ownership check** (`routers/scans.py`):
  Only the scan creator or a user with `admin`/`superadmin` role can cancel a
  running scan. Returns HTTP 403 for unauthorised callers.

- **Approval workflow for finding resolution** (`routers/findings.py`):
  Setting a finding status to `"Resolved"` requires the `reviewer` role or
  higher. Analysts can update other fields but cannot mark findings resolved.

### New Features (Web UI)

- **Reviewer role** (`models/user.py`, `dependencies.py`, `migrations/`):
  Added `reviewer` between `analyst` and `admin` in the role hierarchy
  (`viewer=0, analyst=1, reviewer=2, admin=3, superadmin=4`).
  An Alembic migration (`0001_add_reviewer_role.py`) handles the PostgreSQL
  `ALTER TYPE user_role ADD VALUE` DDL safely (skips on fresh installs, commits
  before the DDL to avoid transaction conflicts).

- **Export findings** (`routers/findings.py`):
  `GET /api/v1/findings/export?format=csv|json|burp` streams findings in three
  formats:
  - **CSV** — spreadsheet-ready with all fields
  - **JSON** — structured array with full finding details
  - **Burp XML** — Burp Suite-compatible issue list for import into Burp's
    findings scanner

- **Report retention job** (`main.py`):
  `APScheduler AsyncIOScheduler` runs `_purge_old_reports()` every 24 hours.
  Deletes report files and DB rows older than `GlobalSettings.report_retention_days`
  (default 90 days). Fires on startup so the first purge runs immediately.

- **Audit log on finding changes** (`services/audit.py`, `routers/findings.py`):
  Every `PATCH /findings/{id}` and bulk status update writes an `AuditLog` row
  recording actor, action, resource type/id, old/new JSON value, IP address,
  and User-Agent. Helper `write_audit_log()` extracted to `services/audit.py`.

- **WebSocket auto-reconnect** (`frontend/src/lib/websocket.ts`):
  Complete rewrite of the WebSocket helper with exponential backoff reconnect:
  `delay = min(BASE * 2^attempt + jitter, 30s)`.
  A `destroyed` flag stops reconnect after explicit `close()` or terminal
  scan events (`completed`, `failed`, `cancelled`). Keep-alive ping interval
  re-registered after each successful reconnect.

- **Database backup & restore** (`routers/backup.py`, `SettingsPage.tsx`):
  - `GET /api/v1/admin/backup/export` — streams a timestamped JSON file
    containing all projects, scans, findings, and comments (admin+ only).
  - `POST /api/v1/admin/backup/import` — accepts a `.json` backup file,
    inserts missing records (skips existing by ID), remaps owner/author to
    the importing user.
  - **Backup tab** added to Settings UI with one-click Export button and
    file-picker Import with per-table inserted-count result grid.

- **Persistent memory & corpus** (`services/scan_runner.py`):
  `workspace.memory` and `workspace.corpus` are now re-pointed to
  `/app/data/memory.json` and `/app/data/corpus.json` — the Docker volume
  mount — so cross-scan knowledge survives container restarts.

  | What is persisted | Benefit in next scan |
  |---|---|
  | `known_endpoints` | Recon skips already-crawled URLs, highlights new attack surface |
  | `tech_stack` | Technology fingerprint reused without re-detection |
  | `confirmed_vulns` | Prior confirmed findings annotated "previously confirmed" |
  | `potential_vulns` | Exploit agent retries harder on partial-evidence hypotheses |
  | `false_positives` | Known-FP hypotheses skipped immediately |
  | `payload corpus` | Successful payloads ranked first by `success_count` + URL/param bonuses |

### Bug Fixes (Web UI)

- **Scan stuck in `queued` status** (`services/scan_runner.py`):
  `datetime.now(timezone.utc)` produces a timezone-aware datetime that
  PostgreSQL `TIMESTAMP WITHOUT TIME ZONE` rejects with
  `can't subtract offset-naive and offset-aware datetimes`.
  All usages changed to `datetime.utcnow()` (naive UTC) throughout
  `scan_runner.py`, `auth/service.py`, `auth/router.py`, and `models/finding.py`.

- **Findings INSERT failure after scan completion** (`models/finding.py`):
  `FindingComment.created_at` and `Finding.created_at` column defaults used
  `lambda: datetime.now(timezone.utc)`, causing every finding INSERT to fail.
  Changed to `default=datetime.utcnow` (naive UTC).

- **Dashboard PostgreSQL compatibility** (`routers/dashboard.py`):
  `func.strftime("%Y-%m", col)` is SQLite-only. All date-grouping queries
  migrated to `func.to_char(col, "YYYY-MM")` for PostgreSQL.

- **`ForwardRef` error on login** (`auth/router.py`):
  `from __future__ import annotations` + bare `Depends()` caused FastAPI to
  see `ForwardRef('OAuth2PasswordRequestForm')`. Fixed with explicit
  `Depends(OAuth2PasswordRequestForm)`.

### Infrastructure

- **PostgreSQL migration** (`docker-compose.yml`, `Dockerfile.backend`):
  Backend now depends on `postgres:16-alpine` with a `pg_isready` healthcheck.
  `DATABASE_URL` uses `postgresql+asyncpg://`.
  Dockerfile CMD runs `alembic upgrade head` before `uvicorn` on every start.

---

## [v0.5.0] — 2026-03-26

### Bug Fixes

- **Post-login screenshot wired to all three LLM paths** (`exploit.py`).
- **Compound vuln-type names now match all detection blocks** (`exploit.py`).
- **False-positive `_check_possible_success` after browser_fill** (`exploit.py`).
- **Consecutive fill/click failure abort — MISC worker timeout fix** (`exploit.py`).
- **Payload-form screenshot before submission** (`exploit.py`).
- **Duplicate findings with same proof / different type names** (`orchestrator.py`).
- **Informational/header findings incorrectly deduped** (`orchestrator.py`).
- **Before/after screenshot labels in report** (`report.py`).

### New Features

- **Maximum PortSwigger Academy Coverage** — 10 new `_detect_*` methods and
  22 new static analysis patterns covering SSTI, CORS, Host Header Injection,
  Cache Poisoning, NoSQL Injection, Open Redirect, File Upload RCE, Prototype
  Pollution, GraphQL, and Race Conditions.
- **Web Application UI — Report Management** (`ScanDetailPage.tsx`, `reports.py`).
- **Web Application UI — Evidence Screenshots lightbox** (`FindingDetailPage.tsx`).
- **Web Application UI — Settings consolidation** (`SettingsPage.tsx`).

### New Components

- `ExploitDispatcher` — parallel category workers (auth, injection, xss, info, misc).
- `EventBus` — async pub/sub for inter-agent events.
- `ScanTracer` — per-phase timing and hypothesis stats.
- `ScanMemory` — persistent JSON store for cross-scan target knowledge.
- `PayloadCorpus` — cross-scan payload success tracker.
- `OutputSanitizer` — strips ANSI codes, truncates oversized LLM outputs.

---

## [v0.4.0] — 2026-03-24

### New Features

- **Multi-page Context Awareness for Chained Attacks** (`recon.py`, `vuln.py`).
- **Source Code Static Analysis — Phase 1.5** (`static_analysis.py`).
- **Payload Corpus Learning** (`corpus.py`, `exploit.py`, `workspace.py`).
- **Configurable Scope Rules** (`workspace.py`, `orchestrator.py`, `main.py`, `recon.py`).
- **`--provider` Flag** (`main.py`).

---

## [v0.3.1] — 2026-03-23

### New Features

- Full PortSwigger Web Security Academy Coverage (`vuln.py`).
- Insecure Deserialization Detection (`vuln.py`).
- XXE Auto-Detection (`exploit.py`).
- Modern SQL Injection Payloads (`exploit.py`).
- DOM Loop Detection & Smart DOM Extraction (`exploit.py`).
- Ollama Local Model Support (`llm.py`).
- Structured Python Narrative Generator (`report.py`).
- 9 new auto-detection blocks (`exploit.py`).

---

## [v0.3.0] — 2026-03-18

### New Features

- OWASP Top 10 Compliance.
- CVSS 3.1 Severity Scoring.
- DOCX Reporting Engine.
- Automated Proof of Concept Screenshots.
- Informational Finding Tracking.

---

## [v0.2.0] — 2026-03-11

### New Features

- Multi-Provider LLM Support (OpenAI GPT-4o).
- Self-Learning Hypothesis Generation.
- Playwright-Driven Exploitation.
- Structured Report Template.
- API Retry with Exponential Backoff.

---

## [v0.1.0] — 2026-03-10

### Initial Release

- 4-phase AI-driven penetration testing pipeline.
- Anthropic Claude as sole LLM backend.
- Basic Playwright browser tools.
- Terminal tool (curl/nmap wrapper).
