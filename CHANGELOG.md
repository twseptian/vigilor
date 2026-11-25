# Changelog

All notable changes to **VIGILOR** are documented in this file.

---

## [v1.0.0] - 2026-11-25

Product name: **VIGILOR**. Package path: `release/vigilor-v1.0.0/`.

### False-positive reduction

- Confirmation evidence gate (`_validate_confirmed_evidence`) before marking exploited
- Detector-only OWASP fallbacks (no loose keyword confirms)
- Stricter broken-access-control detector
- Narrative-only findings demote to Potential (severity capped, low confidence)
- DeepSeek / Z.AI exploit temperature forced to 0.2

### Providers

- DeepSeek + Z.AI (GLM) OpenAI-compatible providers
- Clear fail-fast on Z.AI `1113` insufficient balance / no resource pack (no useless 429 retries)

### UI / product

- VIGILOR branding (reports, API, CLI, Docker banners)
- Dual light/dark themes, attack-flow graphs, ops surfaces
- Potential / No PoC badges

### Layout

| Path | Contents |
|---|---|
| `cli/` | Terminal agent |
| `ui/` | Docker Web UI + engine `src/` |
| `docs/screenshots/` | UI screenshots for README |

### Fixes

- Nginx: exact `/assets` serves the SPA Assets page (Vite static files remain under `/assets/*`)

Burp Suite plugins are shipped separately (not part of VIGILOR).
