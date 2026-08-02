# Standup AI Review

**Status:** Implemented
**Prompt/cache version:** standup_review_v10
**Last updated:** July 31, 2026
**Primary implementation:** [API](api/server-pg.js), [delivery policy](api/standup-review-delivery.js), and [web UI](web/index.html)

## Purpose

Standup AI Review gives administrators a daily advisory review of developer-owned Bugs and Product Backlog Items. It compares the assigned developer's current update with the latest prior update, assigns one primary category per ticket, evaluates the developer's Expected Delivery forecast, and derives Team Lead or PM follow-up.

Expected Delivery is the developer's mutable best estimate of when work will become development-complete. It is not a TFS resolved, closed, or finish date.

The AI interprets update language. Server-side normalization is authoritative for coverage, workflow ownership, progress movement, priority, Bug severity, date calculations, escalation, exception lists, and validation counts.

## Access and Entry Points

- UI: **Pre-Meeting Updates > Standup AI Review** and its force-refresh control.
- Review: **GET /api/ai/standup-review**; use **?refresh=1** to bypass a valid cache.
- History: **GET /api/ai/standup-review/history**.
- The UI and API permit only the **admin** role.
- Review generation is available Monday-Friday. Weekend generation returns **409 non_working_day**; history remains readable.
- Missing OpenAI configuration returns **501 ai_not_configured**.

## End-to-End Flow

1. The API resolves the local review date and preceding Monday-Friday workday.
2. It resolves one registered **users.role = dev** owner for every eligible ticket.
3. It selects only that assigned developer's current and latest prior progress rows.
4. It loads the current Expected Delivery date and any date-change audit event observed since the preceding successful Standup review.
5. It builds the canonical payload and computes a SHA-256 **input_hash**.
6. A cached review is reused only when date, prompt version, and input hash match.
7. The complete payload is processed in batches of 25 with at most two OpenAI calls in flight.
8. AI classifications are merged, then **normalizeStandupReviewResult()** applies authoritative policy to the full payload.
9. Normalization guarantees one classification per ticket and rebuilds exceptions, TL items, PM items, validation, follow-up questions, and summary.
10. Coverage is verified before the normalized result is cached in **ai_snapshot_runs**.

## Ticket Scope

A ticket is eligible when it is not soft-deleted, is not Done, is a Bug or Product Backlog Item, and is assigned to a registered application user whose role is exactly dev.

All eligible tickets are reviewed through bounded batches; there is no silent ticket limit.

## Canonical Input

Each ticket includes:

- ID, title, type, TFS state, assignee, priority, and Bug severity.
- TFS **state_change_date**.
- Current and latest prior progress code, note, and date from the assigned developer only.
- Review date and preceding weekday.
- **expected_delivery_date**.
- **previous_expected_delivery_date**.
- **expected_delivery_changed**.
- **reforecast_direction**: later, earlier, set, cleared, or unchanged.
- **delivery_date_status**: not_required, missing_required, scheduled, due_soon, due_today, overdue, or development_complete.
- **working_days_to_expected_delivery**.

All canonical fields participate in **input_hash**, so a date-only source change invalidates cached results.

## Expected Delivery Sync and Audit

The PowerShell agent sends TFS **SupplyPro.SPApplication.ExpectedDeliveryDate** as **expectedDeliveryDate**. The API stores the current value in **tickets.expected_delivery_date**.

The API also creates **ticket_expected_delivery_history** with:

- ticket_id
- previous_expected_delivery_date
- expected_delivery_date
- change_direction
- tfs_changed_date
- observed_at

An audit row is inserted only when the incoming property is present and differs from the stored value. Omitted properties from older agents do not clear the date. Explicit null or blank values record a clear. A **where not exists** guard and current-value comparison make sync retries idempotent.

History begins when v10 is deployed. Existing dates are retained, but changes that occurred before deployment are not reconstructed.

## Comparison and Workflow Rules

- Exact unchanged **200_xx** or **300_xx** plus no meaningful note change becomes **No Movement**.
- Movement from **400_xx** or higher back to **300_xx** or lower is a mismatch.
- Active TFS states carrying **500_xx** are development-complete for date escalation, but receive Team Lead state-sync advice.
- Monday compares with Friday. Company holidays are not modeled.
- Weekend generation is blocked.

No current developer update is required in New, Approved, Shelved, Branch Check-in, Resolved, Ready for QA, QA Testing, or Done.

**500_xx** or a recognized handoff state is development-complete evidence. These tickets cannot receive developer-owned Expected Delivery escalation. Workflow-handoff states with a current blank-note **500_xx** remain On Track.

Code Review is shared unfinished work. An overdue Code Review waiting for a reviewer goes to Team Lead review with **Review Queue Risk**. Standard developer overdue rules apply when today's note identifies developer rework.

## Expected Delivery Policy

Expected Delivery is required in In Development, Code Review, and Re-Opened.

1. Missing a required date adds **Expected Delivery Missing** and routes to Team Lead review unless a stronger blocker, no-update, or priority rule applies.
2. Healthy due-soon or due-today work stays On Track with **Delivery Due Soon** or **Delivery Due Today**.
3. Due-soon or due-today plus blocker, no daily update, or No Movement becomes PM escalation.
4. Due-soon or due-today plus an incomplete update or mismatch remains TL-first unless current evidence explicitly shows delivery impact.
5. First-working-day overdue with usable non-blocked progress goes to Team Lead review to refresh the forecast.
6. Overdue plus blocker, no update, No Movement, explicit delivery impact, or persistence from the preceding weekday becomes PM escalation.
7. Moving a date earlier is informational.
8. Moving a date later adds **Expected Delivery Reforecasted**. A supported same-day explanation preserves the otherwise applicable category.
9. A blank, vague, or unverifiable later-reforecast rationale adds **Reforecast Needs Rationale** and routes to Team Lead first.
10. Reforecasting alone never causes PM escalation.
11. Clearing a required date is treated as a missing required date.

Date-related diagnostics feed **exceptions.delayed_at_risk**. PM risk text includes the exact date and starts with **High -** for overdue/due-today or **Medium -** for due-soon.

## AI Reforecast Interpretation

Only the assigned developer's same-day **today_note** can support a later reforecast. Prior notes, PM/lead annotations, and TFS System.Reason are not evidence.

The AI returns:

- **reforecast_explanation_status**: Supported, Missing, Ambiguous, or Not Applicable.
- **reforecast_reason_type**: Blocker, Scope Change, Investigation Finding, Unexpected Complexity, Dependency, Environment or Access, Other Supported Reason, or None.
- **reforecast_evidence**: a short excerpt from today_note.

The normalizer verifies that evidence occurs in the sanitized current note. Unsupported evidence is downgraded to Ambiguous. When a later reforecast lacks supported evidence, the response adds a ticket-specific follow-up question, subject to the global five-question cap.

The AI cannot calculate date status, persistence, or escalation.

## Existing Priority and Severity Rules

Priority applies to Bugs and PBIs:

- P1/P2 plus Blocked, no update, or No Movement becomes PM escalation.
- P1/P2 submitted-but-incomplete updates go to Team Lead first unless current evidence has explicit delivery impact.

Severity applies only to Bugs:

- Critical and High add visibility tags but never escalate by severity alone.
- P3/P4 Critical/High plus Blocked or No Movement becomes PM escalation.
- First missed required weekday goes to TL; the second consecutive weekday goes to PM.
- PBIs ignore severity.

These existing rules run before Expected Delivery rules; stronger existing outcomes are preserved.

## Public Output and UI

Every normalized classification includes the date fields from the canonical payload plus the validated reforecast assessment. Existing list shapes remain unchanged.

Validation also contains:

- delivery_overdue
- delivery_due_today
- delivery_due_soon
- expected_delivery_missing
- expected_delivery_reforecasted

The deterministic summary adds one delivery-forecast sentence when any delivery count is nonzero.

The Standup table displays **Expected Delivery** and **Forecast Status**. It renders restrained badges for overdue, due today, due soon, missing, and reforecasted cases. Within each developer, rows sort by primary category, delivery urgency, then ticket ID. Validated reforecast rationale appears inline with the reason.

## Output Integrity

**classifications** is the normalized source of truth. The server derives exceptions, TL review items, PM escalation items, validation, and standup summary. Exception lists are diagnostic and may overlap. Each ticket still has exactly one primary category.

## Cache, History, and Failure Behavior

- Reviews cache for 30 minutes by review date, v10 prompt version, and canonical input hash.
- Force refresh bypasses a matching cached review.
- History is a cross-version, read-only archive. It shows the newest team snapshot for each review date and labels the prompt version used.
- A prompt-version bump invalidates cache reuse but does not hide or delete older history. Older results are labeled as previous-policy snapshots.
- Truncated, refused, malformed, batch-failed, or coverage-incomplete AI output is not cached.
- Database/OpenAI failure returns an error and does not create a successful snapshot.

## Tests

Run **npm test** from the **api/** directory.

Coverage includes identity ownership, reliability helpers, handoff rules, priority/severity behavior, Expected Delivery audit direction, weekday calculations, required states, due/overdue escalation, Code Review ownership, reforecast evidence validation, cross-version history isolation, derived response integrity, and UI wiring.

## Known Limitations

- Monday-Friday working days do not model company holidays.
- Reforecast audit history starts at deployment; no historical backfill is attempted.
- Same-day notes must contain enough detail to support a later reforecast.
- Non-800_xx explicit delivery risk still depends on constrained AI risk tags.
