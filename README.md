# TFS Daily Updates System

A comprehensive sync and reporting system for tracking TFS work items, team progress updates, and generating developer snapshots.

## Documentation

- **[Data Flow Map](DATA-FLOW.md)** - Complete system architecture, data flow stages, and integrity mechanisms
- **[Frontend Review](FRONTEND-REVIEW.md)** - Dev user ticket display, filtering logic, and security validation

## System Components

### 1. PowerShell Agent (`agent/`)

- Syncs TFS work items every 5-10 minutes
- Uses WIQL queries to fetch current sprint tickets
- Implements watermark-based delta sync with full push every 24 hours
- Sends data to API via JSON payloads

### 2. Express.js API (`api/`)

- REST API hosted on Render
- Handles ticket upserts with conditional field updates
- Implements presence sweep (tombstoning) for moved tickets
- Role-based access control (dev vs PM roles)

### 3. Web UI (`web/`)

- Single-page application (vanilla JS)
- Dev view: Submit progress updates on assigned tickets
- PM view: Team dashboard, blockers, reports, developer snapshots
- AI-powered triage and suggestions

## Quick Start

### Agent Setup

```powershell
cd agent
# Edit agent.ps1 to configure TFS credentials and API endpoint
# Run manually or via Task Scheduler every 5-10 minutes
powershell -NoProfile -ExecutionPolicy Bypass -File .\agent.ps1
```

### API Deployment

```bash
cd api
npm install
# Set environment variables: DATABASE_URL, OPENAI_API_KEY, etc.
node server-pg.js
```

### Web UI

Open `web/index.html` in browser or deploy to static hosting.

## Key Features

- **Automated Sync**: Continuous TFS work item synchronization with watermark tracking
- **Presence Sweep**: Automatic detection and tombstoning of moved/deleted tickets
- **Progress Tracking**: Daily progress updates with code/note system
- **Role-Based Views**: Separate dev and PM interfaces
- **Weekly Dev Summary**: Last 7 days rollup (updates, unique tickets, code mix, blockers, lock compliance)
- **Pre-Lock Check**: Warns about assigned tickets missing updates before locking
- **AI Integration**: OpenAI-powered triage, chase messages, next steps, and RAG-backed snapshot insights (stored in `ai_snapshot_runs`)
- **PDF Reports**: Automated developer snapshot generation with email delivery

## AI Snapshot History

- Snapshot runs are stored in `ai_snapshot_runs` for grounding and delta comparisons.
- Retention is controlled by `SNAPSHOT_RUN_RETENTION` (default: 50 runs per developer).

## Notable API Endpoints

- `GET /api/updates/locks/range?from=YYYY-MM-DD&to=YYYY-MM-DD` (auth; current user only)

## System Requirements

- **Agent**: Windows with PowerShell 5.1+, TFS 2017+ API access
- **API**: Node.js 18+, PostgreSQL 12+
- **Web**: Modern browser with ES6+ support

## Recent Fixes (January 2026)

✅ Fixed empty `System.Id` field handling in TFS API responses  
✅ Implemented conditional `iteration_path` updates to prevent stale data  
✅ Added presence sweep with authoritative path from agent  
✅ Defaulted UI to current iteration (prevents showing all sprints)  
✅ Fixed PowerShell array concatenation errors  
✅ Added full push flag support for periodic field refresh

See [DATA-FLOW.md](DATA-FLOW.md) for detailed technical documentation.
