export const STANDUP_ESCALATION_POLICY_VERSION = 'standup_escalation_v2';

export const STANDUP_STATE_ADVANCEMENT_ISSUE_TYPE =
  'tfs_state_may_need_advancement';
export const STANDUP_STATE_ADVANCEMENT_LABEL =
  'TFS State May Need Advancement';
export const STANDUP_STATE_ADVANCEMENT_ACTION =
  'Confirm the completion or handoff and advance the TFS state; if work is still active, correct the progress code.';

export const STANDUP_CORRECTION_ACTIONS = Object.freeze([
  ['No Daily Update', "Submit today's progress update with the current code, completed work, blocker status, and next step."],
  ['Missing Progress Code', 'Select the progress code that matches the work currently being performed.'],
  ['Missing Notes', 'Add a concise note describing progress, blockers, and the next step.'],
  ['Vague Update', 'Clarify the current status and next executable step. When reporting no progress, delay, or a blocker, include the reason.'],
  ['Wrong or Mismatched Progress Code', 'Align the progress code with the current TFS workflow state, or ask your lead to confirm the correct state.'],
  ['Expected Delivery Missing', 'Set the Expected Delivery date in TFS for development completion.'],
  ['Reforecast Needs Rationale', "Update today's note with the reason for the later forecast and its delivery impact."],
]);

const CORRECTION_KEYS = new Set(STANDUP_CORRECTION_ACTIONS.map(([key]) => key));
const IMMEDIATE_LEAD_TAGS = new Set([
  'No Movement',
  'Review Queue Risk',
  'Expected Delivery Overdue',
  'Waiting for Access',
  'Waiting for Data',
  'Waiting for Decision',
  'Waiting for Environment',
  'Cross-Team Dependency',
]);

export const STANDUP_ESCALATION_SCHEMA_SQL = `
create table if not exists standup_review_policy_runs (
  policy_version text not null,
  review_date date not null,
  prompt_version text not null,
  input_hash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (policy_version, review_date)
);

create table if not exists standup_review_correction_observations (
  policy_version text not null,
  review_date date not null,
  ticket_id text not null,
  developer_email text not null,
  correction_key text not null,
  active boolean not null default true,
  streak_count integer not null default 1 check (streak_count >= 0),
  tier integer not null default 1 check (tier between 0 and 3),
  streak_started_on date,
  input_hash text not null,
  first_observed_at timestamptz not null default now(),
  last_observed_at timestamptz not null default now(),
  resolved_at timestamptz,
  primary key (policy_version, review_date, ticket_id, correction_key)
);

create index if not exists standup_review_correction_observations_lookup
  on standup_review_correction_observations
  (policy_version, review_date, active, ticket_id);
`;

function text(value) {
  return String(value ?? '').trim();
}

const BENIGN_STANDUP_ISSUES = new Set([
  'normal progress',
  'on track',
  'no issue',
  'no issues',
  'no issue identified',
  'no issues identified',
  'none',
  'n/a',
  'not applicable',
  'no action required',
]);

export function isStandupBenignIssue(value) {
  const normalized = text(value)
    .toLowerCase()
    .replace(/[.!]+$/g, '')
    .trim();
  return BENIGN_STANDUP_ISSUES.has(normalized);
}

export function standupActionableIssue(value, fallback = '') {
  const candidate = text(value);
  return candidate && !isStandupBenignIssue(candidate)
    ? candidate
    : text(fallback);
}

function email(value) {
  return text(value).toLowerCase();
}

function unique(values) {
  return Array.from(new Set(values));
}

export function standupCorrectionDisplay(correctionKey, classification = {}) {
  const key = text(correctionKey);
  const defaultAction = STANDUP_CORRECTION_ACTIONS.find(
    ([candidate]) => candidate === key,
  )?.[1] || '';
  if (
    key === 'Wrong or Mismatched Progress Code' &&
    text(classification?.progress_code_issue_type) ===
      STANDUP_STATE_ADVANCEMENT_ISSUE_TYPE
  ) {
    return {
      key,
      label: STANDUP_STATE_ADVANCEMENT_LABEL,
      action: text(classification?.state_advancement_action) ||
        STANDUP_STATE_ADVANCEMENT_ACTION,
    };
  }
  return { key, label: key, action: defaultAction };
}

function tierForStreak(streak) {
  return Math.min(3, Math.max(1, Number(streak) || 1));
}

export function standupCorrectionKeys(classification) {
  return unique(
    (Array.isArray(classification?.sub_tags) ? classification.sub_tags : [])
      .map(text)
      .filter((tag) => CORRECTION_KEYS.has(tag)),
  );
}

export function buildStandupCorrectionState({
  classifications,
  reviewDate,
  previousObservations = [],
  todayObservations = [],
}) {
  const prior = new Map(
    previousObservations
      .filter((row) => row?.active !== false)
      .map((row) => [`${text(row.ticket_id)}|${text(row.correction_key)}`, row]),
  );
  const today = new Map(
    todayObservations.map((row) => [
      `${text(row.ticket_id)}|${text(row.correction_key)}`,
      row,
    ]),
  );
  const active = [];
  const activeKeys = new Set();

  for (const classification of Array.isArray(classifications)
    ? classifications
    : []) {
    const ticketId = text(classification?.ticket_id);
    const developerEmail = email(classification?.developer_email);
    for (const correctionKey of standupCorrectionKeys(classification)) {
      const key = `${ticketId}|${correctionKey}`;
      const sameDay = today.get(key);
      const previous = prior.get(key);
      let streakCount = 1;
      let streakStartedOn = reviewDate;

      if (sameDay && email(sameDay.developer_email) === developerEmail) {
        streakCount = Math.max(1, Number(sameDay.streak_count) || 1);
        streakStartedOn = text(sameDay.streak_started_on) || reviewDate;
      } else if (
        previous &&
        email(previous.developer_email) === developerEmail
      ) {
        streakCount = Math.max(1, Number(previous.streak_count) || 1) + 1;
        streakStartedOn = text(previous.streak_started_on) ||
          text(previous.review_date) ||
          reviewDate;
      }

      active.push({
        ticket_id: ticketId,
        developer_email: developerEmail,
        correction_key: correctionKey,
        active: true,
        streak_count: streakCount,
        tier: tierForStreak(streakCount),
        streak_started_on: streakStartedOn,
      });
      activeKeys.add(key);
    }
  }

  const resolved = [];
  for (const row of [...previousObservations, ...todayObservations]) {
    const key = `${text(row.ticket_id)}|${text(row.correction_key)}`;
    if (!activeKeys.has(key) && !resolved.some((item) =>
      `${item.ticket_id}|${item.correction_key}` === key)) {
      resolved.push({
        ticket_id: text(row.ticket_id),
        developer_email: email(row.developer_email),
        correction_key: text(row.correction_key),
        active: false,
        streak_count: Math.max(1, Number(row.streak_count) || 1),
        tier: tierForStreak(row.streak_count),
        streak_started_on: text(row.streak_started_on) || null,
      });
    }
  }

  return { active, resolved };
}

function byTicket(items) {
  return new Map(
    (Array.isArray(items) ? items : []).map((item) => [text(item.ticket_id), item]),
  );
}

function correctionDescription(corrections) {
  return corrections
    .map((correction) => `${correction.label || correction.key} (day ${correction.consecutive_review_days})`)
    .join('; ');
}

function hasImmediateLeadSignal(classification, correctionKeys) {
  const tags = new Set(
    (Array.isArray(classification?.sub_tags) ? classification.sub_tags : []).map(text),
  );
  if (
    classification?.workflow_update_exempt === true &&
    classification?.category === 'On Track' &&
    correctionKeys.length === 0
  ) {
    return false;
  }
  if (classification?.category === 'Blocked') return true;
  if (Array.from(tags).some((tag) => IMMEDIATE_LEAD_TAGS.has(tag))) return true;
  return classification?.category === 'Needs Team Lead Clarification' &&
    correctionKeys.length === 0;
}

function highestCorrectionTier(corrections) {
  return corrections.reduce((highest, correction) =>
    Math.max(highest, correction.tier), 0);
}

function uniqueQueue(items) {
  const result = new Map();
  for (const item of items) {
    const id = text(item.ticket_id);
    if (id && !result.has(id)) result.set(id, item);
  }
  return Array.from(result.values());
}

export function applyStandupEscalationOverlay(review, observations = []) {
  const observationMap = new Map();
  for (const row of observations.filter((item) => item?.active !== false)) {
    const ticketId = text(row.ticket_id);
    if (!observationMap.has(ticketId)) observationMap.set(ticketId, []);
    observationMap.get(ticketId).push({
      key: text(row.correction_key),
      consecutive_review_days: Math.max(1, Number(row.streak_count) || 1),
      tier: tierForStreak(row.streak_count),
    });
  }

  const baseLead = byTicket(review?.tl_review_items);
  const basePm = byTicket(review?.pm_escalation_items);
  const tlReviewItems = [];
  const pmWatchItems = [];
  const pmEscalationItems = [];
  const classifications = (Array.isArray(review?.classifications)
    ? review.classifications
    : []).map((classification) => {
    const ticketId = text(classification.ticket_id);
    const corrections = (observationMap.get(ticketId) || [])
      .map((correction) => ({
        ...correction,
        label: standupCorrectionDisplay(correction.key, classification).label,
      }))
      .sort((a, b) => a.key.localeCompare(b.key));
    const correctionKeys = corrections.map((item) => item.key);
    const correctionTier = highestCorrectionTier(corrections);
    const immediatePm = classification.category === 'Needs PM Escalation';
    const immediateLead = !immediatePm &&
      hasImmediateLeadSignal(classification, correctionKeys);
    const route = immediatePm
      ? 'immediate_pm'
      : immediateLead
        ? 'immediate_lead'
        : corrections.length
          ? 'routine_correction'
          : 'none';
    const tier = immediatePm ? 3 : immediateLead ? 2 : correctionTier;
    const owner = tier >= 3 ? 'pm' : tier === 2 ? 'lead' : tier === 1 ? 'developer' : 'none';
    const escalation = {
      tier,
      owner,
      route,
      consecutive_review_days: corrections.reduce(
        (highest, correction) => Math.max(highest, correction.consecutive_review_days),
        0,
      ),
      corrections,
    };
    const enriched = { ...classification, escalation };
    const correctionText = correctionDescription(corrections);

    const pmAlsoNeedsLead = immediatePm &&
      (baseLead.has(ticketId) ||
        classification.category === 'Blocked' ||
        corrections.length > 0);
    if (immediateLead || pmAlsoNeedsLead || correctionTier >= 2) {
      const base = baseLead.get(ticketId) || {};
      tlReviewItems.push({
        ticket_id: ticketId,
        title: text(base.title) || text(classification.title),
        developer: text(base.developer) || text(classification.developer),
        developer_email: email(base.developer_email) || email(classification.developer_email),
        issue: text(base.issue) || text(classification.reason),
        why_tl_needed: correctionTier >= 2 && !immediateLead
          ? `The same developer correction remains after ${escalation.consecutive_review_days} reviewed workdays: ${correctionText}.`
          : text(base.why_tl_needed) || 'A Team Lead should confirm the blocker owner and unblock path before standup.',
        suggested_action: text(base.suggested_action) ||
          (classification.category === 'Blocked'
            ? 'Confirm the blocker owner, next action, and expected unblock timing.'
            : 'Confirm the correction with the developer during standup.'),
        tier: Math.max(2, correctionTier),
        consecutive_review_days: escalation.consecutive_review_days,
        corrections,
      });
    }

    if (!immediatePm && correctionTier === 2) {
      pmWatchItems.push({
        ticket_id: ticketId,
        title: text(classification.title),
        developer: text(classification.developer),
        developer_email: email(classification.developer_email),
        issue: correctionText,
        monitoring_reason: 'The same correction remains on a second reviewed workday and is assigned to the Team Lead.',
        lead_action: 'Monitor the Team Lead follow-up; no PM action is required unless the issue persists or delivery risk emerges.',
        tier: 2,
        consecutive_review_days: escalation.consecutive_review_days,
        corrections,
      });
    }

    if (immediatePm || correctionTier >= 3) {
      const base = basePm.get(ticketId) || {};
      const immediatePmIssue = standupActionableIssue(
        base.issue,
        standupActionableIssue(
          classification.reason,
          'Current evidence requires PM visibility to confirm delivery risk, ownership, and next action.',
        ),
      );
      pmEscalationItems.push({
        ticket_id: ticketId,
        title: text(base.title) || text(classification.title),
        developer: text(base.developer) || text(classification.developer),
        developer_email: email(base.developer_email) || email(classification.developer_email),
        issue: correctionTier >= 3 && !immediatePm
          ? `Correction remains after ${escalation.consecutive_review_days} reviewed workdays: ${correctionText}.`
          : immediatePmIssue,
        evidence: text(base.evidence) || text(classification.update_summary) || text(classification.reason),
        delivery_risk: text(base.delivery_risk) ||
          'Medium - The correction remains after Team Lead follow-up and now needs PM visibility.',
        recommended_pm_action: text(base.recommended_pm_action) ||
          'Confirm the owner, resolution timing, and whether the repeated issue affects delivery.',
        tier: 3,
        consecutive_review_days: escalation.consecutive_review_days,
        corrections,
      });
    }

    return enriched;
  });

  const validation = { ...(review?.validation || {}) };
  validation.tier_1_developer = classifications.filter((item) =>
    item.escalation?.tier === 1).length;
  validation.tier_2_lead = classifications.filter((item) =>
    item.escalation?.tier === 2).length;
  validation.tier_3_pm = classifications.filter((item) =>
    item.escalation?.tier === 3).length;
  validation.pm_watch = uniqueQueue(pmWatchItems).length;

  return {
    ...review,
    classifications,
    tl_review_items: uniqueQueue(tlReviewItems),
    pm_watch_items: uniqueQueue(pmWatchItems),
    pm_escalation_items: uniqueQueue(pmEscalationItems),
    validation,
    escalation_policy_version: STANDUP_ESCALATION_POLICY_VERSION,
  };
}
