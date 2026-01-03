# Data Flow Map - TFS Daily Updates System

**Last Updated**: January 3, 2026  
**System Version**: v1.0 (Production)

---

## System Overview

```
┌────────────────────┐
│   TFS 2017 API     │  Source of Truth
│ (remote.spdev.us)  │  REST API + WIQL
└─────────┬──────────┘
          │ HTTPS + NTLM Auth
          │ Every 5-10 minutes
          ▼
┌────────────────────┐
│  PowerShell Agent  │  Sync Engine
│   (agent.ps1)      │  Windows Task Scheduler
└─────────┬──────────┘
          │ POST /api/sync/tickets
          │ JSON payload (batch)
          ▼
┌────────────────────┐
│  Express.js API    │  Business Logic Layer
│  (server-pg.js)    │  Hosted on Render
│  Render.com        │
└─────────┬──────────┘
          │ SQL (pg driver)
          │ Transactional upserts
          ▼
┌────────────────────┐
│  Neon Postgres     │  Data Persistence
│  (Cloud DB)        │  Serverless Postgres
└─────────┬──────────┘
          │ HTTP API (GET)
          │ Bearer token auth
          ▼
┌────────────────────┐
│  Web UI (SPA)      │  Frontend
│  (index.html)      │  Vanilla JS + Fetch API
└────────────────────┘
```

---

## Core Data Entities

### 1. **Tickets Table** (Primary entity)

**Schema**: `tickets`

| Column                | Type        | Constraint    | Purpose                                        |
| --------------------- | ----------- | ------------- | ---------------------------------------------- |
| `id`                  | INTEGER     | PRIMARY KEY   | TFS work item ID                               |
| `type`                | TEXT        |               | Work item type (Bug, PBI, Task, etc.)          |
| `title`               | TEXT        |               | Work item title                                |
| `state`               | TEXT        |               | Current state (Active, QA Testing, Done, etc.) |
| `assigned_to`         | TEXT        |               | Full name or DOMAIN\alias                      |
| `area_path`           | TEXT        |               | TFS area path                                  |
| `iteration_path`      | TEXT        |               | TFS iteration/sprint path                      |
| `created_date`        | TIMESTAMPTZ |               | When ticket was created in TFS                 |
| `changed_date`        | TIMESTAMPTZ |               | Last modification in TFS                       |
| `state_change_date`   | TIMESTAMPTZ |               | When state last changed                        |
| `tags`                | TEXT        |               | Comma-separated tags                           |
| `priority`            | INTEGER     |               | 1-4 (1=highest)                                |
| `severity`            | TEXT        |               | Critical, High, Medium, Low                    |
| `reason`              | TEXT        |               | Reason for state transition                    |
| `found_in_build`      | TEXT        |               | Build where bug was found                      |
| `integrated_in_build` | TEXT        |               | Build where fix was integrated                 |
| `related_link_count`  | INTEGER     |               | Count of related links/dependencies            |
| `effort`              | NUMERIC     |               | Story points/effort estimate                   |
| `deleted`             | BOOLEAN     | DEFAULT false | Soft-delete flag (presence sweep)              |
| `last_seen_at`        | TIMESTAMPTZ |               | Last time agent synced this ticket             |

**Indexes**:

- Primary: `id`
- Query optimization: `iteration_path`, `assigned_to`, `state`

---

### 2. **Progress Updates Table** (User notes)

**Schema**: `progress_updates`

| Column        | Type        | Purpose                                           |
| ------------- | ----------- | ------------------------------------------------- |
| `ticket_id`   | TEXT        | References ticket ID                              |
| `email`       | TEXT        | User's email (authenticated)                      |
| `user_id`     | INTEGER     | FK to users.id (NOT NULL)                         |
| `code`        | TEXT        | Progress code (e.g., 600_started, 700_inprogress) |
| `note`        | TEXT        | User's note/comment                               |
| `risk_level`  | TEXT        | Risk assessment (low/medium/high)                 |
| `impact_area` | TEXT        | Impact area description                           |
| `date`        | DATE        | Date of update (local timezone)                   |
| `at`          | TIMESTAMPTZ | Timestamp of update (UTC)                         |

**Business Rules**:

- Users can submit multiple updates per ticket per day
- Latest update (`ORDER BY at DESC`) shown in UI
- PM role can view all users' updates; dev role sees only their own

---

### 3. **Meta Table** (System configuration)

**Schema**: `meta`

| Key                 | Value                     | Purpose                                  |
| ------------------- | ------------------------- | ---------------------------------------- |
| `current_iteration` | `Project\Sprint 2026-412` | Active sprint path for UI default filter |

**Usage**:

- Updated by agent when detecting sprint transition
- UI falls back to this value when no explicit `iterationPath` filter provided
- **CRITICAL FIX**: Prevents UI from showing tickets across all sprints (stale data issue)

---

## Data Flow Stages

### Stage 1: TFS → Agent (Data Extraction)

**Agent Location**: `agent/agent.ps1`  
**Trigger**: Windows Task Scheduler (every 5-10 minutes)  
**Authentication**: NTLM (credentials in script)

#### Process:

1. **Watermark Check**

   - Reads `agent/last_sync.json` for last successful sync timestamp
   - Subtracts 5 minutes for overlap window (prevents missed tickets)

2. **WIQL Query Execution**

   ```sql
   -- Query A: Current iteration tickets
   SELECT [System.Id] FROM WorkItems
   WHERE [System.IterationPath] UNDER 'Project\Sprint 2026-412'
     AND [System.ChangedDate] >= @watermark

   -- Query B: Parent items (for relations/dependencies)
   SELECT [System.Id] FROM WorkItemLinks
   WHERE ...
   ```

3. **Batch Details Fetch**

   - Chunks IDs into batches of 200
   - POST to TFS API: `/tfs/DefaultCollection/_apis/wit/workitems?ids=...&$expand=relations&api-version=5.0`
   - **KEY FIX**: Uses `$it.id` (work item object) instead of `$f."System.Id"` (field hash) because TFS sometimes returns empty System.Id field

4. **Timestamp Filtering**

   - **Delta Sync** (default): Filter by `changedDate >= watermark`
   - **Full Push** (every 24 hours): Skip filter, send all tickets
   - Full push ensures stale fields (e.g., `iteration_path` from old cached data) get refreshed

5. **Presence ID Collection**
   - Collect all ticket IDs visible to current iteration WIQL
   - Used for tombstoning absent tickets (see Stage 3)

---

### Stage 2: Agent → API (Data Transport)

**Endpoint**: `POST /api/sync/tickets`  
**Authentication**: Bearer token (hardcoded in agent)  
**Payload Structure**:

```json
{
  "source": "agent",
  "tickets": [
    {
      "id": 189879,
      "type": "Bug",
      "title": "Fix login timeout",
      "state": "Done",
      "assignedTo": "John Doe <DOMAIN\\jdoe>",
      "iterationPath": "Project\\Sprint 2026-412",
      "changedDate": "2025-12-27T05:31:12.807Z",
      "stateChangeDate": "2025-12-26T14:22:00Z",
      "tags": "release-3.2.1, hotfix",
      "priority": 1,
      "severity": "High",
      // ... 10+ more fields
    }
    // ... up to 500 tickets per chunk
  ],
  "pushedAt": "2026-01-03T12:45:00Z",
  "presentIds": [189879, 189880, 189881, ...],  // All IDs from WIQL
  "presentIteration": "Sprint 2026-412",
  "presentIterationPath": "Project\\Sprint 2026-412"
}
```

**Chunking Strategy**:

- Max 500 tickets per POST (prevents timeout/memory issues)
- Sends multiple chunks sequentially if needed

---

### Stage 3: API → Database (Data Persistence)

**Location**: `api/server-pg.js` lines 950-1150  
**Transaction**: PostgreSQL transaction for atomicity

#### 3.1 Upsert Logic (Lines 1010-1050)

```sql
INSERT INTO tickets (
  id, type, title, state, assigned_to, iteration_path,
  changed_date, state_change_date, tags, priority, severity,
  ... 15+ columns, last_seen_at
)
VALUES ($1, $2, $3, ...)
ON CONFLICT (id) DO UPDATE SET
  type = EXCLUDED.type,
  title = EXCLUDED.title,
  state = EXCLUDED.state,
  assigned_to = EXCLUDED.assigned_to,
  changed_date = EXCLUDED.changed_date,
  state_change_date = EXCLUDED.state_change_date,
  tags = EXCLUDED.tags,
  priority = EXCLUDED.priority,
  severity = EXCLUDED.severity,
  ... (always update these fields from agent)

  -- CONDITIONAL UPDATE (HIGH PRIORITY FIX):
  iteration_path = CASE
    WHEN EXCLUDED.changed_date >= COALESCE(tickets.changed_date, '1900-01-01'::timestamptz)
    THEN EXCLUDED.iteration_path
    ELSE tickets.iteration_path
  END,

  deleted = false,  -- Un-tombstone if seen again
  last_seen_at = now()
```

**Business Rules**:

- **Unconditional updates**: `state`, `changed_date`, `assigned_to`, `title`, etc. (always trust agent's fresh data)
- **Conditional update**: `iteration_path` (only if `changed_date` is newer or equal)
  - **Rationale**: Agent may fetch ticket from cross-sprint query with old cached `iteration_path`, but newer `state`/`changed_date`. Don't overwrite newer path with stale path.

#### 3.2 Presence Sweep (Lines 1085-1150)

**Purpose**: Tombstone tickets that disappeared from current iteration (moved to other sprints, deleted, etc.)

```sql
UPDATE tickets
SET deleted = true, last_seen_at = now()
WHERE lower(iteration_path) = lower($authPath)
  AND NOT (id = ANY($presentIds))
  AND coalesce(deleted, false) = false
```

**Key Parameters**:

- `$authPath`: **Authoritative path from agent** (`presentIterationPath` from payload)
  - **HIGH PRIORITY FIX**: Uses agent's path instead of deriving from DB's potentially stale data
- `$presentIds`: Array of all IDs agent saw in current iteration WIQL
- Only tombstones tickets not in present list (soft delete)

**Fallback**:

- If `presentIterationPath` is empty, derives scope from existing DB data (less accurate)

---

### Stage 4: Database → Web UI (Data Consumption)

#### 4.1 Main Tickets View (`GET /api/tickets`)

**Endpoint**: `api/server-pg.js` lines 1309-1530  
**Authentication**: Optional (Bearer token for personalized view)

**Query Parameters**:
| Param | Type | Purpose | Default |
|-------|------|---------|---------|
| `assignedTo` | string | Filter by assignee (alias/name) | None |
| `state` | string | Filter by state | None |
| `iterationPath` | string | Filter by sprint | **current_iteration from meta** |
| `types` | string | Filter by type | `Bug,Product Backlog Item` |
| `includeDeleted` | boolean | Include tombstoned tickets | `false` |
| `updatesBy` | string | Show progress for specific user (PM only) | Requester's email |
| `q` | string | Search in title/ID | None |

**CRITICAL DEFAULT FILTER** (Lines 1329-1347):

```javascript
// If no iterationPath provided, default to current iteration from meta
if (!effectiveIterationPath) {
  const currIter = await pool.query(
    `select value from meta where key='current_iteration'`
  );
  effectiveIterationPath = currIter.rows[0]?.value || null;
}
```

**Rationale**: Without this, UI would load tickets from ALL sprints (including completed/archived), showing stale data. This was a **CRITICAL** data accuracy finding.

#### 4.2 Role-Based Data Access

**Dev Role** (`role='dev'`):

- **Tickets endpoint**: Filtered by `assignedTo = <self>` (enforced by API)
- **Progress updates**: Can only see/edit own updates
- **Locking**: Can submit daily lock for own updates
- **UI restrictions** (Lines 1520-1530 in `index.html`):
  ```javascript
  // Show "Select" button only if role='dev' AND day not locked
  window.__role !== 'dev' || window.__lockedToday
    ? ''
    : '<button onclick="openSPModal(' + t.id + ')">Select</button>';
  ```

**PM Role** (`role='pm'`):

- **Tickets endpoint**: Can request updates for any user via `?updatesBy=<email>`
- **Progress updates**: Can view all users' updates
- **Locking**: Can unlock other users' days
- **UI access**: Full visibility to "Today" view (all team updates), blockers, triage

#### 4.3 Data Flow for Dev User

**Scenario**: Dev user "jdoe" loads their tickets

1. **Frontend Request** (`web/index.html` line 1478):

   ```javascript
   fetch('/api/tickets?assignedTo=' + assigned.value, {
     headers: { Authorization: 'Bearer ' + token },
   });
   ```

2. **API Processing**:

   - Extracts `assignedTo` = "jdoe" (or alias from dropdown)
   - Applies filters:
     - `lower(assigned_to) LIKE '%jdoe%'`
     - `iteration_path LIKE '%Sprint 2026-412%'` (default from meta)
     - `type IN ('bug', 'product backlog item')` (default)
     - `deleted = false` (exclude tombstoned)
   - Joins `progress_updates` via LATERAL:
     ```sql
     LEFT JOIN LATERAL (
       SELECT code, note
       FROM progress_updates
       WHERE ticket_id = t.id
         AND email = 'jdoe@company.com'  -- requester's email
       ORDER BY at DESC
       LIMIT 1
     ) u ON true
     ```
   - Returns tickets with user's latest code/note

3. **Frontend Rendering** (Lines 1510-1540):

   ```javascript
   tr.innerHTML =
     '<td>' +
     t.id +
     '</td>' +
     '<td>' +
     t.type +
     '</td>' +
     '<td>' +
     t.title +
     '</td>' +
     '<td>' +
     t.state +
     '</td>' +
     '<td>' +
     t.lastCode +
     '</td>' + // From progress_updates join
     '<td>' +
     t.lastNote +
     '</td>' +
     '<td><button onclick="openSPModal(' +
     t.id +
     ')">Select</button></td>';
   ```

4. **User Actions**:
   - Click "Select" → Opens modal to submit progress update
   - Submit update → `POST /api/progress` with `{ ticketId, code, note }`
   - Lock day → `POST /api/updates/lock` (prevents further edits)

---

## Data Integrity Mechanisms

### 1. Watermark-Based Sync

**File**: `agent/last_sync.json`

```json
{
  "last": "2026-01-03T12:40:00Z"
}
```

**Logic**:

- After successful sync, writes current timestamp
- Next run uses `last - 5 minutes` as WIQL filter
- 5-minute overlap ensures no missed tickets (race condition safety)

### 2. Presence Sweep (Tombstoning)

**Purpose**: Mark tickets that moved out of current iteration as `deleted=true`

**Trigger**: Every agent sync (every 5-10 minutes)

**Algorithm**:

1. Agent sends `presentIds` = all IDs from current iteration WIQL
2. API tombstones tickets where:
   - `iteration_path` matches current iteration
   - `id` NOT IN `presentIds`
   - `deleted = false` (already tombstoned tickets are skipped)

**Un-tombstoning**: If ticket reappears in future sync (e.g., moved back to current sprint), `deleted` is set back to `false`

### 3. Conditional Field Updates

**Field**: `iteration_path`  
**Rule**: Only update if agent's `changed_date >= DB's changed_date`

**Scenario**: Ticket 189879 moved from Sprint 2025-398 → 2026-412 on Dec 27. On Jan 3:

- Agent fetches from 45-day lookback query (includes old sprint)
- TFS returns: `iteration_path="2025-398"` (cached), `changed_date="2025-12-27"`, `state="Done"`
- DB has: `iteration_path="2026-412"` (updated earlier), `changed_date="2025-12-27"`
- **Result**: `state` and `changed_date` update (unconditional), but `iteration_path` preserved (conditional, same timestamp)

### 4. Full Push Refresh

**Trigger**: Every 24 hours (configurable in agent)  
**Flag**: `$IsFullPush = $true`

**Purpose**: Refresh all fields without timestamp filtering

**Logic**:

```powershell
if ($IsFullPush) {
  $exactDelta = $tickets  # Skip changedDate filter
} else {
  $exactDelta = $tickets | Where-Object {
    $_.changedDate -ge $startTime
  }
}
```

**Rationale**: Catches stale fields that haven't changed but need refreshing (e.g., `tags` added in TFS but not synced because `changedDate` didn't update)

---

## Known Issues & Fixes

### ✅ FIXED: Empty System.Id Field

**Issue**: TFS API sometimes returns work items where `.id` property exists but `.fields['System.Id']` is empty/null  
**Impact**: Tickets silently dropped from sync payload (created with `id=""`, failed debug checks)  
**Example**: Ticket 189879 showed stale data in DB despite agent fetching it  
**Root Cause**: `id = $f."System.Id"` in line 538 of agent.ps1  
**Fix**: Changed to `id = $it.id` (uses work item object property instead of field hash)  
**Date**: January 3, 2026

### ✅ FIXED: Array Concatenation Error

**Issue**: PowerShell error "Method invocation failed because [System.Object[]] does not contain a method named 'op_Addition'"  
**Root Cause**: Null array handling in `$ids = $idsA + $idsB`  
**Fix**: `$ids = @($idsA) + @($idsB)` with explicit array constructors  
**Date**: January 2, 2026

### ✅ FIXED: Missing presentIterationPath Variable

**Issue**: API runtime error "presentIterationPath is not defined"  
**Root Cause**: Agent payload included field but API destructuring didn't extract it  
**Fix**: Added `presentIterationPath = ''` to line 953 in server-pg.js  
**Date**: January 2, 2026

### ✅ FIXED: UI Shows All Sprints

**Issue**: Web UI loaded tickets from all iterations (current + archived), showing thousands of stale tickets  
**Root Cause**: GET /api/tickets had no default `iterationPath` filter  
**Fix**: Default to `current_iteration` from meta table (lines 1329-1347)  
**Date**: January 2, 2026

### ✅ FIXED: Stale iteration_path Propagation

**Issue**: Agent's outdated cached `iteration_path` overwrites DB's newer correct path  
**Root Cause**: Unconditional upsert of `iteration_path` field  
**Fix**: Conditional update based on `changed_date` comparison (line 1031)  
**Date**: January 2, 2026

### ✅ FIXED: Presence Sweep Using Stale Path

**Issue**: Tombstoning logic derived scope from DB's potentially stale `iteration_path`  
**Root Cause**: Presence sweep query didn't use agent's authoritative path  
**Fix**: Use `presentIterationPath` from agent payload (lines 1085-1150)  
**Date**: January 2, 2026

### ✅ FIXED: Full Push Flag Ignored

**Issue**: Agent's `$IsFullPush` flag existed but wasn't honored in filtering logic  
**Root Cause**: Timestamp filter always applied regardless of flag  
**Fix**: `if ($IsFullPush) { $exactDelta = $tickets }` (lines 606-643)  
**Date**: January 2, 2026

---

## Performance Characteristics

- **Agent Runtime**: 2-5 minutes (typical), 10-15 minutes (full push)
- **API Latency**: 200-500ms (single ticket upsert), 2-5s (batch of 500)
- **UI Load Time**: 300-800ms (50-100 tickets)
- **Database Size**: ~50K tickets, 200K progress updates (production)
- **Sync Frequency**: Every 5-10 minutes (configurable)

---

## Security Model

1. **TFS Authentication**: NTLM (Windows credentials embedded in agent)
2. **Agent → API**: Bearer token (static, hardcoded in agent script)
3. **Web → API**: Bearer token (session-based, stored in localStorage)
4. **Database Access**: Connection string with SSL (environment variable)
5. **Role Enforcement**: API layer enforces dev/pm permissions (not frontend)

---

## Monitoring & Observability

- **Agent Logs**: Console output (captured by Task Scheduler)
- **API Logs**: Console.log statements (Render dashboard)
- **Error Tracking**: HTTP status codes, try/catch blocks
- **Data Quality**: `last_seen_at` timestamp for freshness checks
- **Presence Sweep**: `deleted` flag for tombstone tracking

---

## Future Enhancements

1. Add defensive logging for empty `System.Id` field (track frequency)
2. Implement retry logic for transient TFS API failures
3. Add Prometheus metrics for sync success/failure rates
4. Create admin UI for manual presence sweep triggers
5. Add automated tests for conditional upsert logic

---

_This document is maintained as system architecture evolves. For implementation details, see source code comments in agent.ps1 and server-pg.js._
