# Standup AI Review

**Status:** Implemented
**Prompt/cache version:** `standup_review_v9`
**Audit date:** July 11, 2026
**Primary implementation:** [API](api/server-pg.js) and [web UI](web/index.html)

## Purpose

Standup AI Review gives the PM a daily, advisory review of developer-owned Bugs and Product Backlog Items. It compares the current update with the latest prior update, assigns one primary category per ticket, identifies diagnostic exceptions, and drafts Team Lead or PM follow-up items.

The AI does not make management decisions. Server-side normalization is authoritative for payload ticket coverage, workflow exemptions, progress-code movement, priority, Bug severity, exception lists, and validation counts. Shared reliability helpers provide the production weekday, hashing, batching, coverage, and authorization rules.

## Entry Points and Access

- UI controls: **Pre-Meeting Updates > Standup AI Review** and the adjacent force-refresh icon.
- Review endpoint: `GET /api/ai/standup-review`; append `?refresh=1` to bypass a valid cache.
- History endpoint: `GET /api/ai/standup-review/history`.
- UI and both endpoints permit only `pm` and `admin` roles. Leads and developers are rejected by the API even if they call it directly.
- Review generation is available Monday-Friday. Weekend requests return `409 non_working_day`; history remains readable.
- OpenAI must be configured or the review endpoint returns `501 ai_not_configured`.

## End-to-End Flow

1. The API resolves the local review date and rejects weekend generation.
2. It resolves each ticket's canonical `users.role = 'dev'` owner, then selects only that developer's current and latest prior progress rows.
3. It builds the canonical review payload and computes a SHA-256 `input_hash`.
4. Unless force refresh was requested, it reuses a recent v8 snapshot only when its date, prompt version, and `input_hash` match.
5. It splits the complete payload into batches of 25 and processes at most two OpenAI calls concurrently. Any failed batch fails the whole run.
6. Batch classifications and follow-up questions are merged; `normalizeStandupReviewResult()` then runs once against the complete payload.
7. Normalization deterministically ensures one classification per eligible ticket, applies business rules, and rebuilds all derived lists, counts, and the summary.
8. The response records `coverage.eligible`, `coverage.reviewed`, `coverage.omitted`, and `coverage.complete`, then stores the normalized snapshot in `ai_snapshot_runs`.
9. The UI displays coverage, groups tickets by developer, and renders summaries, exceptions, questions, TL items, and PM items.

## Ticket Scope

A ticket is eligible when it is:

- Not soft-deleted.
- Not in `Done` state.
- A `Bug` or `Product Backlog Item`.
- Assigned to a registered application user whose role is exactly `dev`.

Eligible tickets are ordered by numeric ticket ID. There is no silent ticket cap; all eligible tickets are included through bounded AI batches and the final response discloses coverage.

## Input and Comparison Rules

For each reviewed ticket, the payload includes:

- Ticket ID, title, type, state, assignee, priority, and severity.
- TFS `state_change_date`.
- Canonical assigned-developer email.
- Today's latest code and note authored by that developer.
- Latest code, note, and date before today authored by that developer.
- Local review date and immediately preceding Monday-Friday workday.

Comparison behavior:

- Exact unchanged `200_xx`/`300_xx` code plus no meaningful note change becomes `No Movement`.
- Movement from `400_xx` or higher back to `300_xx` or lower is a mismatch.
- State/code mismatches are routed to Team Lead review unless current delivery evidence supports PM escalation.
- Monday compares with Friday. Company holidays are not modeled.
- Review generation is blocked on weekends, so weekend dates cannot create missing-update or persistence escalation.

## Update-Author Ownership

- TFS `assigned_to` is resolved to one canonical registered developer email.
- Current and prior maps are keyed by both ticket ID and canonical developer email.
- Only that developer's `progress_updates` rows can establish a current update, movement, blocker, or prior comparison.
- PM-, admin-, and lead-authored progress rows remain stored in `progress_updates` but are excluded from Standup evidence.
- Dedicated PM annotations remain in `pm_dev_notes`; dedicated lead annotations remain in `lead_dev_notes`. Neither annotation table is sent to the Standup AI.
- If only a PM/admin/lead progress row exists for an active ticket, the workflow treats the developer update as absent.

## Workflow Ownership

Daily developer updates are not required for:

- `New`
- `Approved`
- `Shelved`
- `Branch Check-in` / `Branch Checkin`
- `Resolved`
- `Ready for QA`
- `QA Testing`
- `Done`

When one of these states has no current update, normalization forces `On Track`. Workflow-handoff states with a current `500_xx` update also remain `On Track` even when the note is blank. QA states receive `Ready for QA`; release/handoff states receive the appropriate visibility tag. A current update can still create a blocker or escalation when it explicitly identifies delivery impact.

## Primary Categories

Every ticket receives exactly one primary lane:

| Category | Meaning |
| --- | --- |
| `On Track` | Clear progress or a normal workflow handoff with no actionable risk. |
| `Blocked` | Work cannot continue because of a current dependency or `800_xx` delay. |
| `Missing Update` | A required current update is absent or unusable under the normal rules. |
| `Needs Team Lead Clarification` | Technical, scope, code/status, first-stage severity miss, or incomplete-update clarification is required. |
| `Needs PM Escalation` | Priority, repeated severity miss, blocker, release, schedule, or coordination risk needs PM action. |

Exception lists are diagnostic and can overlap. A ticket still has only one primary category.

## Priority and Bug Severity

Priority applies to Bugs and PBIs:

- P1/P2 plus Blocked, no update, or No Movement becomes `Needs PM Escalation`.
- P1/P2 submitted-but-incomplete updates go to Team Lead review first unless current delivery impact is explicit. P3/P4 follows normal rules unless another deterministic or explicit delivery signal applies.

Severity applies only to Bugs:

- Severity 1/Critical adds `Critical Severity` for visibility.
- Severity 2/High adds `High Severity`.
- Severity alone never creates TL or PM escalation.
- P3/P4 Critical/High plus Blocked or No Movement becomes PM escalation.
- First required weekday missed by a P3/P4 Critical/High Bug goes to TL review and the missing-update exception list.
- A second consecutive weekday miss becomes PM escalation with `Persistent Missing Update` and High delivery risk.
- Missing `state_change_date` conservatively remains first-stage TL review.
- PBIs ignore severity even if malformed source data supplies a value.

Critical and High severity tags have distinct red and amber UI badges. An On Track Critical Bug is also mentioned in the deterministic standup summary.

## Output Integrity

`classifications` is the normalized source of truth. The server rebuilds:

- `exceptions`
- `tl_review_items`
- `pm_escalation_items`
- `validation`
- `standup_summary`

`validation` counts primary categories. Diagnostic exception counts may be higher because one ticket can appear in multiple exception lists.

Follow-up questions are model-drafted, limited to five, filtered to known ticket IDs, and removed for workflow-exempt tickets with no current update.

## Cache, History, and Retention

- Reviews are cached for 30 minutes by review date, prompt version, and canonical source `input_hash`.
- A changed eligible ticket, canonical developer owner, TFS state, priority/severity value, assigned-developer current update, or assigned-developer prior update changes the payload hash and prevents stale-cache reuse.
- Admin users can force a fresh review with the UI refresh control or `?refresh=1`.
- Every uncached run inserts a normalized JSON snapshot into `ai_snapshot_runs`.
- History only lists snapshots matching the current `STANDUP_REVIEW_PROMPT_VERSION`.
- `STANDUP_REVIEW_RETENTION` defaults to 30 and is enforced separately for the current prompt version.
- A prompt-version bump invalidates the active cache and hides older-version snapshots from the current history endpoint; it does not delete ticket or progress data.

## Failure Behavior

- OpenAI unavailable: `501 ai_not_configured`.
- Any batch output truncated: the complete request fails with `response_truncated`; no partial review is cached.
- Invalid/refused structured output: request fails with `bad_ai_response`.
- Coverage ID/count mismatch after normalization: request fails with `standup_coverage_mismatch`; no snapshot is cached.
- Database/OpenAI errors: endpoint returns an error and does not cache a successful review.
- Cleanup failure: review still succeeds; cleanup logs a warning asynchronously.
- The UI displays the returned error message and re-enables both review controls.

## P0 Reliability Safeguards

The v7 implementation resolves the four conditions that previously made a successful result unsafe to trust:

- **Complete coverage:** the former first-50 cap is removed. All eligible tickets are chunked, globally normalized, and reported with explicit coverage metadata.
- **Freshness-aware cache:** cached results are reused only when the canonical source hash matches. Admin users can force refresh.
- **Consistent authorization:** UI and API both use admin-only access; PM and lead users cannot retrieve the team-wide review.
- **Working-day boundary:** weekend generation is rejected before ticket classification begins.

A result is operationally complete when `coverage.complete === true`, `coverage.reviewed === coverage.eligible`, and `coverage.omitted === 0`.

## P1 Update-Ownership Safeguard

The v8 implementation closes the update-attribution gap:

- SQL resolves one canonical developer account for every eligible ticket.
- Current and historical queries match both ticket ID and developer email.
- Payload indexing repeats the same composite-key check as defense in depth.
- PM, admin, and lead annotations remain separate and are not reclassified as developer updates.
- Table-driven Node tests cover manager/lead exclusion, case-insensitive email matching, latest-row selection, and per-ticket isolation.

## P2 Reliability and Maintainability

The P2 implementation extracts operational invariants into `api/standup-review-reliability.js`, which is imported directly by the production route:

- Monday-Friday review dates and preceding-weekday calculation.
- SHA-256 source-payload hashing for cache invalidation.
- Complete-payload batching with a validated positive batch size.
- Fail-closed coverage validation for missing, duplicate, blank, or unknown ticket IDs.
- Admin-only authorization shared by the Standup middleware and tests.
- Table-driven Node tests for calendar boundaries, hash changes, 70-ticket batching, coverage failure modes, and role access.

P2 did not change classification policy, the public response shape, or the prompt/cache version at the time; later handoff and incomplete-update policy changes moved the current version to `standup_review_v9`.

## Remaining Practical Gaps

### Medium: History disappears across prompt versions

The history endpoint filters snapshots to v8. Policy/version changes therefore make older reviews appear absent even though their database rows remain.

**Recommended correction:** list history across versions, include `prompt_version` in the response, and render older snapshots read-only with a version badge.

### Medium: Primary and diagnostic missing counts can look contradictory

A first-stage Critical/High miss has primary category `Needs Team Lead Clarification` and also appears in `exceptions.missing_updates`. `validation.missing_update` counts only the primary Missing Update lane, so the summary can say zero primary Missing Update tickets while the diagnostic group is non-empty.

**Recommended correction:** label the UI count as `Missing primary lane`, or add a separate diagnostic missing count derived from missing-update tags.

### Medium: Explicit delivery risk depends on exact AI tags

For non-`800_xx` cases, direct PM escalation requires a current update, model category `Needs PM Escalation`, and one of a fixed set of exact sub-tags. A semantically correct but differently worded tag can be downgraded to TL clarification.

**Recommended correction:** constrain `sub_tags` with schema enums or normalize model synonyms before applying deterministic risk rules.

### Practical: Normalizer regression coverage remains incomplete

The repository now tests ownership, weekday logic, hashing, batching, coverage, and role scope, but still lacks table-driven tests for the complete classification normalizer and derived response integrity.

**Recommended correction:** extract or export the deterministic normalizer and test workflow exemptions, priority/severity precedence, exception derivation, TL/PM items, and validation totals.

## Recommended Next Order

1. Add table-driven deterministic-normalizer and response-integrity tests.
2. Clarify diagnostic versus primary counts.
3. Preserve cross-version history with visible version metadata.
4. Schema-enforce or normalize explicit-risk tags.
