# AGENTS.md

Repository guide for AI agents working on TFS Daily Updates.

## Repo layout
- `agent/` PowerShell sync agent (TFS -> API).
- `api/` Express + Postgres API (Node 18, ESM).
- `web/` Static UI (single `index.html`, vanilla JS).
- Docs: `DATA-FLOW.md` (sync + integrity), `FRONTEND-REVIEW.md` (dev/PM UI filtering).

## Local setup
### Agent (PowerShell)
- Edit variables in `agent/agent.ps1` (TFS URL/collection/project, PAT, API base, API key).
- Run: `powershell -NoProfile -ExecutionPolicy Bypass -File .\agent.ps1`
- State: `agent/last_sync.json` is the watermark; delete only if you want a full backfill.

### API (Node 18+)
- `cd api`
- `npm install`
- Copy `api/.env.example` to `api/.env` and set `DATABASE_URL`, `API_KEY`, and mail settings.
- Start: `npm run start` (or `node server-pg.js`).

### Web UI
- Open `web/index.html` directly (no build step).

## Behavior and data flow
- Sync and presence sweep expectations live in `DATA-FLOW.md`. Keep these invariants when changing the agent or API.
- Dev vs PM filtering and security rules are documented in `FRONTEND-REVIEW.md`. Preserve these rules in both UI and API.

## Coding guidelines
- API: keep SQL parameterized, preserve role-based access checks and default filters (iteration + type).
- Agent: keep sanitization and watermark/full-push logic intact; avoid hardcoding secrets.
- Web: keep vanilla JS, avoid adding build tooling unless requested.

## Safety and ops
- Avoid running the agent or email/PDF flows against production without explicit request.
- Do not commit secrets (`api/.env`, PATs) or local state (`agent/last_sync.json`).

## Tests
- No automated tests. Suggested smoke checks:
  - API: `GET /health` should return 200.
  - Web: log in as dev and PM; verify ticket filters and progress submission flow.
  - Agent: run once against a test API endpoint when possible.
