# Agentic Pentest AI — Burp Suite Plugin

A Burp Suite extension (Montoya API) that connects directly to the **Agentic Pentest AI** FastAPI backend, letting you launch agentic web-application pentest scans, monitor progress, and review findings — all without leaving Burp.

---

## Features

- **Send to Agentic Pentest AI** context menu in Proxy, Repeater, Target, Logger
- Pre-fills scan dialog with the selected request's URL
- Configure LLM provider, model, hypotheses count, parallel workers, custom prompt
- Live scan status table — auto-refreshes every 5 seconds
- Cancel running scans from within Burp
- Findings table with severity colour-coding (Critical / High / Medium / Low / Info)
- Full finding detail pane: description, proof-of-concept, implications, recommendations
- Settings tab: backend URL + credentials, JWT token persisted across Burp restarts

---

## Requirements

| Component | Version |
|-----------|---------|
| Burp Suite Professional / Community | 2023.10+ |
| Java (JDK) | 11+ (for building) |
| Agentic Pentest AI backend | v0.7.0+ running at `http://localhost:8000` |

---

## Building

```bash
cd burpsuite-plugins
./gradlew shadowJar
```

The fat JAR is written to:
```
build/libs/agentic-pentest-burp-0.7.0.jar
```

On Windows:
```
gradlew.bat shadowJar
```

---

## Installation in Burp Suite

1. Open Burp Suite → **Extensions** → **Installed** → **Add**
2. Extension type: **Java**
3. Extension file: select `build/libs/agentic-pentest-burp-0.7.0.jar`
4. Click **Next** — the extension loads and the **Agentic Pentest AI** tab appears

---

## Usage

### 1. Configure backend connection

1. Click the **Agentic Pentest AI** suite tab
2. Open the **Settings** sub-tab
3. Enter the backend URL (default `http://localhost:8000/api/v1`)
4. Enter your username and password → **Login & Save**

The JWT token is persisted in Burp preferences so you only need to log in once per installation.

### 2. Start a scan from Burp

1. Right-click any request in **Proxy**, **Repeater**, **Target**, or **Logger**
2. Click **Send to Agentic Pentest AI**
3. Review / edit the scan parameters in the dialog
4. Click **Start Scan**

### 3. Monitor progress

Switch to the **Scans** sub-tab — the table polls every 5 seconds.

Columns: ID · Target · Status (colour-coded) · Findings summary · Provider · Model · Started

Click **Cancel Scan** to abort a running scan.

### 4. Review findings

Either click **View Findings** on a selected scan row, or open the **Findings** sub-tab directly.

Click any finding row to expand the full detail pane below the table.

---

## Project layout

```
burpsuite-plugins/
├── build.gradle                          # Gradle shadow-JAR build
├── settings.gradle
├── gradle/wrapper/
│   └── gradle-wrapper.properties
└── src/main/java/com/ensign/burp/
    ├── AgenticPentestExtension.java      # BurpExtension entry point
    ├── api/
    │   ├── AgentApiClient.java           # REST client (Java 11 HttpClient)
    │   └── model/
    │       ├── LoginRequest.java
    │       ├── LoginResponse.java
    │       ├── ScanRequest.java
    │       ├── ScanResponse.java
    │       └── FindingResponse.java
    └── ui/
        ├── MainTab.java                  # Root JPanel with JTabbedPane
        ├── ScansPanel.java               # Scan list + polling + actions
        ├── FindingsPanel.java            # Findings table + detail pane
        ├── SettingsPanel.java            # Backend URL + login
        └── NewScanDialog.java            # Modal dialog for new scan config
```

---

## Backend API endpoints used

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/login` | Obtain JWT token |
| GET | `/scans?limit=100` | List scans |
| POST | `/scans` | Create new scan |
| POST | `/scans/{id}/cancel` | Cancel scan |
| GET | `/findings?scan_id={id}&limit=200` | Get findings for scan |

---

## Troubleshooting

**Extension fails to load**
- Ensure you built with `./gradlew shadowJar` (not just `./gradlew jar`)
- Check Burp → Extensions → Errors tab for the stack trace

**"Not authenticated" after Burp restart**
- The token is cached — click **Test Connection** in Settings
- If expired, click **Login & Save** again

**Backend connection refused**
- Confirm the Agentic Pentest AI Docker stack is running: `docker compose ps`
- Default backend URL: `http://localhost:8000/api/v1`
