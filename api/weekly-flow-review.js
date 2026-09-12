export const WEEKLY_FLOW_POLICY_VERSION = 'weekly_flow_v1';

const COMPLETE_STATES = new Set(['resolved', 'ready for qa', 'qa testing', 'done']);
const HANDOFF_STATES = new Set(['resolved', 'ready for qa', 'qa testing']);
const WAITING_STATES = new Set(['new', 'approved', 'on-hold', 'on hold', 'shelved', 'branch checkin']);
const WAITING_TAGS = new Set([
  'Review Queue Risk',
  'Awaiting Routine Review',
  'Waiting for Access',
  'Waiting for Data',
  'Waiting for Decision',
  'Waiting for Environment',
  'Cross-Team Dependency',
]);
const DELIVERY_RISK_TAGS = new Set([
  'Delivery Risk',
  'Expected Delivery Overdue',
  'Delivery Due Today',
  'Reforecast Needs Rationale',
  'Release Risk',
  'Schedule Risk',
]);
const CORRECTION_TAGS = new Set([
  'Wrong or Mismatched Progress Code',
  'Missing Progress Code',
  'Missing Notes',
  'Vague Update',
]);

const lower = (value) => String(value || '').trim().toLowerCase();
const tagsOf = (item) => (Array.isArray(item?.sub_tags) ? item.sub_tags.map(String) : []);
const codeOf = (item) => String(item?.current_code || item?.code || '').trim();
const stateOf = (item) => String(item?.state || '').trim();
const noteOf = (item) => String(item?.update_summary || item?.note || '').trim();

function addDays(date, count) {
  const parsed = new Date(`${date}T00:00:00.000Z`);
  parsed.setUTCDate(parsed.getUTCDate() + count);
  return parsed.toISOString().slice(0, 10);
}

export function expectedWorkdays(startDate, endDate, today = endDate) {
  const limit = endDate < today ? endDate : today;
  if (limit < startDate) return [];
  const dates = [];
  for (let date = startDate; date <= limit; date = addDays(date, 1)) {
    const day = new Date(`${date}T00:00:00.000Z`).getUTCDay();
    if (day >= 1 && day <= 5) dates.push(date);
  }
  return dates;
}

export function weeklyCoverage({ startDate, endDate, today, observedDates }) {
  const expected = expectedWorkdays(startDate, endDate, today);
  const expectedSet = new Set(expected);
  const observed = [...new Set(observedDates || [])].filter((date) => expectedSet.has(date)).sort();
  const missing = expected.filter((date) => !observed.includes(date));
  const status = observed.length < 3 ? 'insufficient' : missing.length ? 'partial' : 'complete';
  return {
    status,
    expected_days: expected.length,
    observed_days: observed.length,
    observed_dates: observed,
    missing_dates: missing,
  };
}

function isComplete(item) {
  const tags = tagsOf(item);
  return (
    COMPLETE_STATES.has(lower(stateOf(item))) ||
    tags.includes('Ready for QA') ||
    tags.includes('Done') ||
    lower(item?.delivery_date_status) === 'development_complete'
  );
}

function isWaiting(item) {
  const tags = tagsOf(item);
  return (
    WAITING_STATES.has(lower(stateOf(item))) ||
    HANDOFF_STATES.has(lower(stateOf(item))) ||
    tags.some((tag) => WAITING_TAGS.has(tag))
  );
}

function isActive(item) {
  return !item?.workflow_update_exempt && !isComplete(item) && !isWaiting(item);
}

function meaningfulMovement(previous, current) {
  if (!previous || !current) return false;
  if (lower(stateOf(previous)) !== lower(stateOf(current)) && stateOf(previous) && stateOf(current)) return true;
  const tags = tagsOf(current);
  if (tags.includes('No Movement') || tags.includes('Wrong or Mismatched Progress Code')) return false;
  const previousCode = codeOf(previous);
  const currentCode = codeOf(current);
  const exceptionalCode = /^(600|700|800)_/.test(previousCode) || /^(600|700|800)_/.test(currentCode);
  return Boolean(
    (previousCode && currentCode && previousCode !== currentCode && !exceptionalCode) ||
      (noteOf(previous) && noteOf(current) && noteOf(previous) !== noteOf(current)),
  );
}

function consecutiveObservedWorkdays(firstDate, secondDate) {
  return expectedWorkdays(firstDate, secondDate, secondDate).length === 2;
}

function ticketKey(item) {
  return String(item?.ticket_id || item?.ticketId || '').trim();
}

function ticketIdentity(item) {
  return {
    ticket_id: ticketKey(item),
    title: String(item?.title || ''),
    type: String(item?.type || ''),
  };
}

function adverseDelivery(item) {
  const status = lower(item?.delivery_date_status);
  const tags = tagsOf(item);
  return (
    ['overdue', 'due_today'].includes(status) ||
    (lower(item?.reforecast_direction) === 'later' && lower(item?.reforecast_explanation_status) !== 'supported') ||
    tags.some((tag) => DELIVERY_RISK_TAGS.has(tag))
  );
}

function materialBlocker(item) {
  return item?.category === 'Blocked' || tagsOf(item).some((tag) => ['Possible Risk', 'Delivery Risk'].includes(tag));
}

function correction(item) {
  return tagsOf(item).some((tag) => CORRECTION_TAGS.has(tag));
}

function describeMovement(history) {
  const first = history[0]?.item || {};
  const last = history[history.length - 1]?.item || {};
  const from = stateOf(first) || codeOf(first) || 'first observation';
  const to = stateOf(last) || codeOf(last) || 'latest observation';
  return from === to ? `${from} throughout observed days` : `${from} → ${to}`;
}

function concernFor(item, stalled, repeatedCorrection) {
  if (Number(item?.escalation?.tier || 0) >= 3 || item.category === 'Needs PM Escalation') return 'PM escalation remains unresolved at period end.';
  if (materialBlocker(item)) return 'A blocker or material delivery risk remains unresolved.';
  if (item.category === 'Needs Team Lead Clarification') return 'Team Lead clarification remains unresolved.';
  if (adverseDelivery(item)) return 'The delivery forecast needs attention.';
  if (stalled) return 'The ticket shows repeated no movement.';
  if (repeatedCorrection) return 'The update needed repeated correction.';
  return String(item.reason || 'The ticket needs review.');
}

function actionFor(item, stalled) {
  if (Number(item?.escalation?.tier || 0) >= 3 || item.category === 'Needs PM Escalation' || materialBlocker(item)) {
    return String(item.recommended_action || 'Confirm the unblock owner and decision needed.');
  }
  if (item.category === 'Needs Team Lead Clarification') {
    return String(item.recommended_action || 'Clarify the technical next step and update the ticket.');
  }
  if (stalled) return 'Finish the current slice, or split and pause it before starting more work.';
  return String(item.recommended_action || 'Confirm the next concrete step and forecast.');
}

function rankAttention(item, stalled, repeatedCorrection) {
  if (Number(item?.escalation?.tier || 0) >= 3 || item.category === 'Needs PM Escalation') return 1;
  if (materialBlocker(item)) return 2;
  if (Number(item?.escalation?.tier || 0) === 2 || item.category === 'Needs Team Lead Clarification') return 3;
  if (adverseDelivery(item)) return 4;
  if (stalled) return 5;
  if (repeatedCorrection) return 6;
  return 99;
}

function emptyMetrics() {
  return {
    ending_wip: 0,
    peak_wip: 0,
    waiting_handoff: 0,
    entered_wip: 0,
    newly_observed: 0,
    meaningful_movement: 0,
    development_completed: 0,
    left_review_scope: 0,
    stalled: 0,
    delivery_risk: 0,
  };
}

export function buildWeeklyFlowReview({ period, developer, days, baselineDay = null, today, priorMetrics = null }) {
  const orderedDays = (days || []).slice().sort((a, b) => String(a.date).localeCompare(String(b.date)));
  const coverage = weeklyCoverage({
    startDate: period.start_date,
    endDate: period.end_date,
    today,
    observedDates: orderedDays.map((day) => day.date),
  });
  const metrics = emptyMetrics();
  const historyByTicket = new Map();
  const baseline = new Map((baselineDay?.items || []).map((item) => [ticketKey(item), item]));
  const seen = new Set();
  const movementTickets = new Set();
  const completionTickets = new Set();
  const enteredTickets = new Set();
  const newlyObserved = new Set();

  for (const day of orderedDays) {
    const items = (day.items || []).filter((item) => ticketKey(item));
    metrics.peak_wip = Math.max(metrics.peak_wip, items.filter(isActive).length);
    for (const item of items) {
      const id = ticketKey(item);
      const history = historyByTicket.get(id) || [];
      const previous = history.length ? history[history.length - 1].item : baseline.get(id);
      if (!seen.has(id)) {
        if (previous) {
          if (!isActive(previous) && isActive(item)) enteredTickets.add(id);
        } else {
          newlyObserved.add(id);
        }
      } else if (previous && !isActive(previous) && isActive(item)) {
        enteredTickets.add(id);
      }
      if (previous && meaningfulMovement(previous, item)) movementTickets.add(id);
      if (previous && !isComplete(previous) && isComplete(item)) completionTickets.add(id);
      history.push({ date: day.date, item });
      historyByTicket.set(id, history);
      seen.add(id);
    }
  }

  const finalItems = orderedDays.length ? orderedDays[orderedDays.length - 1].items || [] : [];
  const finalIds = new Set(finalItems.map(ticketKey));
  metrics.ending_wip = finalItems.filter(isActive).length;
  metrics.waiting_handoff = finalItems.filter(isWaiting).length;
  metrics.entered_wip = enteredTickets.size;
  metrics.newly_observed = newlyObserved.size;
  metrics.meaningful_movement = movementTickets.size;
  metrics.development_completed = completionTickets.size;
  metrics.left_review_scope = [...seen].filter((id) => !finalIds.has(id)).length;

  const attention = [];
  for (const item of finalItems) {
    const id = ticketKey(item);
    const history = historyByTicket.get(id) || [];
    const lastTwo = history.slice(-2);
    const stalled = isActive(item) && (
      tagsOf(item).includes('No Movement') ||
      (lastTwo.length === 2 &&
        consecutiveObservedWorkdays(lastTwo[0].date, lastTwo[1].date) &&
        !meaningfulMovement(lastTwo[0].item, lastTwo[1].item))
    );
    const correctionDays = history.filter(({ item: observed }) => correction(observed)).length;
    const repeatedCorrection = correctionDays >= 2;
    if (stalled) metrics.stalled += 1;
    if (adverseDelivery(item)) metrics.delivery_risk += 1;
    const rank = rankAttention(item, stalled, repeatedCorrection);
    if (rank < 99) {
      attention.push({
        ...ticketIdentity(item),
        rank,
        movement: describeMovement(history),
        evidence: noteOf(item) || String(item.reason || ''),
        concern: concernFor(item, stalled, repeatedCorrection),
        owner: Number(item?.escalation?.tier || 0) >= 3 || item.category === 'Needs PM Escalation' ? 'PM' : Number(item?.escalation?.tier || 0) === 2 || item.category === 'Needs Team Lead Clarification' ? 'Team Lead' : 'Developer',
        action: actionFor(item, stalled),
        checkpoint: 'Next standup',
      });
    }
  }
  attention.sort((a, b) => a.rank - b.rank || a.ticket_id.localeCompare(b.ticket_id, undefined, { numeric: true }));
  const attentionItems = attention.slice(0, 5).map(({ rank, ...item }) => item);

  let assessment = 'Healthy';
  if (coverage.status === 'insufficient') assessment = 'Insufficient Data';
  else if (finalItems.some((item) => Number(item?.escalation?.tier || 0) >= 3 || item.category === 'Needs PM Escalation' || materialBlocker(item))) assessment = 'Needs Support';
  else if (finalItems.some((item) => Number(item?.escalation?.tier || 0) === 2 || item.category === 'Needs Team Lead Clarification' || adverseDelivery(item)) || metrics.stalled > 0 || attention.some((item) => item.rank === 6)) assessment = 'Watch';

  const actions = [];
  if (coverage.status !== 'insufficient') {
    const support = attentionItems.find((item) => item.owner === 'PM' || /block|risk/i.test(item.concern));
    const activeIds = new Set(finalItems.filter(isActive).map(ticketKey));
    const finishCandidate = attentionItems.find((item) => activeIds.has(item.ticket_id))?.ticket_id || [...activeIds][0] || null;
    if (metrics.ending_wip > 0) actions.push({ type: 'finish_first', wording: finishCandidate ? `Finish #${finishCandidate} before pulling another item.` : 'Finish the highest-value active ticket before pulling another item.', ticket_id: finishCandidate });
    if (support) actions.push({ type: 'unblock_escalate', wording: `Resolve or escalate #${support.ticket_id}: ${support.action}`, ticket_id: support.ticket_id });
    if (metrics.stalled > 0 || metrics.ending_wip > 2) actions.push({ type: 'continue_split_pause', wording: 'Continue only the work with a clear next step; split or pause the rest.', ticket_id: null });
  }

  const comparison = priorMetrics
    ? Object.fromEntries(Object.keys(metrics).map((key) => [key, metrics[key] - Number(priorMetrics[key] || 0)]))
    : null;
  const summary = assessment === 'Insufficient Data'
    ? `Only ${coverage.observed_days} expected workdays were observed, so the sprint cannot be assessed reliably. Missing days are excluded rather than treated as zero activity.`
    : `${developer.display_name || developer.email} ends the observed sprint with ${metrics.ending_wip} active and ${metrics.waiting_handoff} waiting/handoff ticket(s). ${attentionItems.length ? `${attentionItems.length} item(s) need focused follow-up.` : 'No unresolved flow concerns were found.'}`;

  return {
    policy_version: WEEKLY_FLOW_POLICY_VERSION,
    period,
    developer,
    coverage,
    assessment,
    summary,
    flow_snapshot: { ...metrics, prior_period_delta: comparison },
    tickets_needing_attention: attentionItems,
    next_period_actions: actions.slice(0, 3),
    advisory: 'Advisory only. Review the source tickets before changing ownership, scope, or forecasts.',
  };
}
