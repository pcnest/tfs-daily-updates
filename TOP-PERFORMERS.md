# Top Performers Table — How to Read It (Admin Only)

This table ranks developers using only the data we already collect (`progress_updates` and `tickets`). No new telemetry or AI scoring is introduced.

## What the score means

- Composite z-score with fixed weights: throughput (0.35), completion % (0.25), cycle time — lower is better (0.20), blocker rate — lower is better (0.20).
- Scores are relative to the team in the selected window (last 4 weeks or custom date range). A 0.00 score is team average; positive means above team average.
- Developers with fewer than **3 finished tickets** in the window are marked **“low sample”** and excluded from ranking order (but still shown for transparency).

## Columns at a glance

- **#**: Rank among eligible devs; shows “—” for low-sample rows.
- **Dev**: Email.
- **Score**: Weighted composite (see above); higher is better.
- **Throughput**: Count of tickets whose latest status code in-window is `500_xx` (finished).
- **Completion %**: Finished / touched tickets within the window.
- **Cycle time (h)**: Average hours spent in `200/300/400` families between progress updates (lower is better).
- **Blocker rate**: (`600_xx` + `800_xx` transitions) divided by ticket volume (lower is better).
- **Consistency σ**: Std. dev. of daily finishes; lower means steadier delivery. Displayed only (not weighted).
- **Update coverage**: Progress updates per weekday in the window. Displayed only; not part of the score.
- **Notes**: Flags for low sample or other guardrails.

## How to read it

1. **Start with Score, then Throughput and Completion %.** These drive most of the ranking.
2. **Check Cycle time vs Blocker rate** to see _how_ the throughput was achieved (fast and unblocked vs. slow or blocked).
3. **Use Consistency as a tie-breaker** to spot steadier delivery among similar scores.
4. **Scan Update coverage** to judge data quality. Low coverage can understate a dev’s activity.
5. **Low-sample rows**: Treat as informational only; do not compare to ranked rows.

## Scope and fairness

- Scope selector controls the window:
  - **Last 4 weeks**: rolling 28 days.
  - **Custom date range**: any date range between 7 and 90 days.
- Window dates are displayed beside the Refresh button for transparency.
- All metrics are computed only from updates and tickets inside that window.

## Drill-down to see the underlying work

You can view the existing developer snapshot for the same window:

1. Click the **"View snapshot"** button in any developer's row to open their snapshot in a modal viewer
2. The snapshot will automatically use the same date range as the Top Performers window
3. Alternatively, you can call the snapshots endpoint directly (PM auth required):
   - HTML: `/api/reports/snapshots?format=html&developer=<email>&from=<YYYY-MM-DD>&to=<YYYY-MM-DD>`
   - PDF: `/api/reports/snapshots?format=pdf&developer=<email>&from=<YYYY-MM-DD>&to=<YYYY-MM-DD>`

## Bonus Eligibility Evaluation (AI-assisted)

The Top Performers table now includes an **AI-assisted bonus eligibility evaluation** to help managers and stakeholders make informed compensation decisions.

### How it works

- Click "View Insight" for any developer → then click "View Bonus Eligibility"
- The system analyzes the same metrics as the Top Performers ranking, plus **1-2 PBI contexts** (work items with developer progress notes)
- An AI generates a qualitative narrative that:
  - **Status**: Eligible / Not Eligible / Needs Review
  - **Reasoning**: A stakeholder-friendly story about the developer's work patterns, woven naturally with specific PBI examples (no ticket IDs or raw metric citations)
  - References displayed signals like "steady delivery cadence" (Consistency σ) and "thorough progress updates" (Update coverage)

### Example reasoning (Eligible):

> "Consistently delivers finished work with minimal rework. Recent efforts on authentication refactor and payment gateway integration show strong follow-through—work gets unblocked quickly and stays on track. Daily progress is steady and predictable, making sprint planning reliable."

### Example reasoning (Not Eligible):

> "Good effort, but completion slips when work stretches too long. Multi-tenant refactoring shows promise but stalls in mid-flight. Breaking features into smaller, testable increments would help finish more consistently."

### Example reasoning (Needs Review):

> "Mixed signals this period. Throughput is lower than usual, possibly due to complex migration work requiring deep investigation. Needs manager context before drawing conclusions."

### Audit trail

- All evaluations are stored in the `bonus_evaluations` database table for compliance/historical review
- Evaluations are cached for 1 hour to avoid redundant AI calls
- Admins can access the **Bonus Eligibility Audit Log** card to view all historical evaluations (toggle to expand)

### Important notes

- **This evaluation is advisory only.** Final bonus decisions require manager review and organizational context.
- **No raw metrics or ticket IDs** appear in the reasoning—only qualitative descriptions and PBI context suitable for product owners/stakeholders.
- **Needs OpenAI API key:** Set `OPENAI_API_KEY` in `api/.env` to enable AI evaluation (defaults to `gpt-4o-mini` model).
