# VIGILOR — Autonomous Web VAPT

Self-hosted AI agents for **authorized** web penetration testing and source-code review.
Evidence-first findings, attack-chain graphs, coverage ledger, activity broadcast, and finding retests.

Inspired by ops consoles like [ARTEX](https://github.com/BaaRai/ARTEX), but built as a **different product**:
web-first Playwright agents, hypothesis → exploit loops, MITRE attack chains, verification gates, and client DOCX/PDF reports — with a teal dark ops UI (not a clone).

## Quick Start

### Docker

```bash
cd development-ui-version
cp .env.example .env   # set SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD
docker compose up -d --build
```

Open http://localhost:3000 — default `admin` / value from `.env`.

### Development

```bash
# Backend
cd development-ui-version/backend
pip install -r requirements.txt
playwright install chromium
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd development-ui-version/frontend
npm install && npm run dev
```

## What VIGILOR adds (vs a generic scanner / chat wrapper)

| Capability | Notes |
|------------|--------|
| Engagement cockpit | Live phases, workflow graph, findings, reports |
| Coverage ledger | Deduplicated hosts + tested/untested status |
| Activity broadcast | Goals / phases / findings / digests timeline |
| Finding retest | One-click focused re-validation engagement |
| Evidence gates | PoC binding, confidence, analyst verification |
| Attack chains | Multi-step paths + MITRE ATT&CK in UI & report |
| Dual modes | Live web pentest **or** public repo source review |
| RBAC | superadmin / admin / analyst / viewer |

## Architecture

```
development-ui-version/
├── backend/          FastAPI + SQLAlchemy async + JWT + WebSocket
├── frontend/         React + Vite + Tailwind (VIGILOR ops console)
└── docker/           Backend + nginx frontend images
```

## License / authorization

Use only on systems you are authorized to test. Operators own scope, credentials, and budgets.
