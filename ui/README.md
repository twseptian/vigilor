# Pentest AI Agent — Web Dashboard

A full-stack web dashboard for managing AI-powered penetration testing scans, similar to Acunetix.

## Quick Start (Development)

### Backend

```bash
cd development-ui-version/backend
pip install -r requirements.txt
playwright install chromium

# Copy and edit .env
cp .env.example .env

# Run
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd development-ui-version/frontend
npm install
npm run dev
```

Open http://localhost:5173 — login with `admin` / `changeme123`

### Docker (Production)

```bash
cd development-ui-version
cp .env.example .env   # edit SECRET_KEY, ENCRYPTION_KEY, ADMIN_PASSWORD
docker compose up -d
```

Open http://localhost:3000

---

## Features

| Feature | Status |
|---------|--------|
| Login / JWT auth | ✅ |
| Dashboard with charts | ✅ |
| Start / monitor scans (live WebSocket log) | ✅ |
| Findings list with bulk triage | ✅ |
| Finding detail with CVSS, OWASP, screenshots | ✅ |
| Comments on findings | ✅ |
| Report download (DOCX) | ✅ |
| Settings — API keys (Anthropic, OpenAI) | ✅ |
| Settings — Ollama URL + auto-detect models | ✅ |
| Multi-user + RBAC (superadmin/admin/analyst/viewer) | ✅ |
| Project management | ✅ |
| Scan cancel / rerun | ✅ |
| Docker Compose deployment | ✅ |

### Planned (Phase 2)
- Scan scheduling (cron)
- Email / Slack notifications
- Audit log
- CI/CD webhook API
- PDF report export
- TOTP MFA
- SSO (SAML/OIDC)

---

## Architecture

```
development-ui-version/
├── backend/          FastAPI + SQLAlchemy async + JWT
│   ├── auth/         Login, refresh, /me
│   ├── models/       SQLAlchemy ORM (User, Scan, Finding, …)
│   ├── routers/      REST API endpoints
│   ├── services/     scan_runner, llm_detector, crypto
│   └── websocket/    Real-time scan progress
├── frontend/         React 18 + TypeScript + Vite
│   └── src/
│       ├── pages/    Login, Dashboard, Scans, Findings, Settings, Users
│       ├── api/      Axios client wrappers
│       ├── store/    Zustand (auth state)
│       └── lib/      utils, WebSocket factory
└── docker/           Dockerfile.backend, Dockerfile.frontend, nginx.conf
```

## API Docs

After starting the backend, visit http://localhost:8000/api/docs

## Default Credentials

Username: `admin`
Password: `changeme123` (change immediately in production)
