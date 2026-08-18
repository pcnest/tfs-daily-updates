import {
  standupDateOnly,
  standupPreviousWeekday,
} from './standup-review-reliability.js';

const DEVELOPMENT_COMPLETE_STATES = new Set([
  'resolved',
  'ready for qa',
  'qa testing',
  'done',
]);

const EXPECTED_DELIVERY_REQUIRED_STATES = new Set([
  'in development',
  'code review',
  'branch checkin',
  're-opened',
]);

const SANDBOX_VALIDATION_STATUSES = new Set([
  'Pending',
  'In Progress',
  'Rework Required',
  'Passed',
  'Unknown',
  'Not Applicable',
]);

const REFORECAST_REASON_TYPES = new Set([
  'Blocker',
  'Scope Change',
  'Investigation Finding',
  'Unexpected Complexity',
  'Dependency',
  'Environment or Access',
  'Other Supported Reason',
  'None',
]);

function normalizeText(value) {
  return String(value || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

export function standupDeliveryStateKey(value) {
  const text = normalizeText(value).replace(/[\u2010-\u2015]/g, '-');
  if (['reopened', 're-opened', 're opened'].includes(text)) {
    return 're-opened';
  }
  return text;
}

export function standupWorkingDaysUntil(reviewValue, targetValue) {
  const reviewDate = standupDateOnly(reviewValue);
  const targetDate = standupDateOnly(targetValue);
  if (!reviewDate || !targetDate) return null;
  if (reviewDate === targetDate) return 0;

  const review = new Date(`${reviewDate}T00:00:00Z`);
  const target = new Date(`${targetDate}T00:00:00Z`);
  const direction = target > review ? 1 : -1;
  const cursor = new Date(review);
  let weekdays = 0;

  while (cursor.getTime() !== target.getTime()) {
    cursor.setUTCDate(cursor.getUTCDate() + direction);
    const day = cursor.getUTCDay();
    if (day >= 1 && day <= 5) weekdays += 1;
  }

  return weekdays * direction;
}

export function standupReforecastDirection({
  changed,
  previousExpectedDeliveryDate,
  expectedDeliveryDate,
}) {
  if (!changed) return 'unchanged';
  const previous = standupDateOnly(previousExpectedDeliveryDate);
  const current = standupDateOnly(expectedDeliveryDate);
  if (!previous && current) return 'set';
  if (previous && !current) return 'cleared';
  if (!previous || !current || previous === current) return 'unchanged';
  return current > previous ? 'later' : 'earlier';
}

export function deriveStandupDeliveryContext(ticket = {}) {
  const state = standupDeliveryStateKey(ticket.state);
  const currentCode = ticket.today_code || ticket.prev_code || '';
  const expectedDeliveryDate = standupDateOnly(
    ticket.expected_delivery_date || ticket.expectedDeliveryDate,
  );
  const previousExpectedDeliveryDate = standupDateOnly(
    ticket.previous_expected_delivery_date ||
      ticket.previousExpectedDeliveryDate,
  );
  const expectedDeliveryChanged = Boolean(
    ticket.expected_delivery_changed ?? ticket.expectedDeliveryChanged,
  );
  const reforecastDirection = standupReforecastDirection({
    changed: expectedDeliveryChanged,
    previousExpectedDeliveryDate,
    expectedDeliveryDate,
  });
  const developmentComplete = DEVELOPMENT_COMPLETE_STATES.has(state);
  const expectedDeliveryRequired =
    EXPECTED_DELIVERY_REQUIRED_STATES.has(state);
  const workingDaysToExpectedDelivery = expectedDeliveryDate
    ? standupWorkingDaysUntil(ticket.review_date, expectedDeliveryDate)
    : null;

  const reviewDate = standupDateOnly(ticket.review_date);
  let status = 'not_required';
  if (developmentComplete) {
    status = 'development_complete';
  } else if (!expectedDeliveryDate) {
    status = expectedDeliveryRequired ? 'missing_required' : 'not_required';
  } else if (reviewDate && expectedDeliveryDate < reviewDate) {
    status = 'overdue';
  } else if (reviewDate && expectedDeliveryDate === reviewDate) {
    status = 'due_today';
  } else if (
    workingDaysToExpectedDelivery !== null &&
    workingDaysToExpectedDelivery <= 2
  ) {
    status = 'due_soon';
  } else {
    status = 'scheduled';
  }

  const previousWorkday = standupDateOnly(
    ticket.previous_workday_date ||
      standupPreviousWeekday(ticket.review_date),
  );
  const persistentOverdue =
    status === 'overdue' &&
    Boolean(previousWorkday) &&
    expectedDeliveryDate < previousWorkday;
  const noteText = normalizeText(ticket.today_note);
  const developerRework = [
    'addressing feedback',
    'changes requested',
    'review feedback',
    'rework',
    'fixing comments',
    'fixing review',
  ].some((phrase) => noteText.includes(phrase));

  return {
    expectedDeliveryDate: expectedDeliveryDate || null,
    previousExpectedDeliveryDate: previousExpectedDeliveryDate || null,
    expectedDeliveryChanged,
    expectedDeliveryRequired,
    reforecastDirection,
    status,
    workingDaysToExpectedDelivery,
    developmentComplete,
    persistentOverdue,
    isCodeReview: state === 'code review',
    developerRework,
  };
}

function sandboxEvidenceIndicatesPass(value) {
  const evidence = normalizeText(value);
  if (!evidence || !/\b(?:sandbox|sbx)\b/.test(evidence)) return false;
  if (
    /\b(?:not|hasn't|has not|didn't|did not|failed|failing|failure|blocked|issue|rework)\b/.test(
      evidence,
    )
  ) {
    return false;
  }
  return /\b(?:pass(?:ed|es)?|validated|validation complete|successful(?:ly)?|green)\b/.test(
    evidence,
  );
}

export function validateStandupSandboxAssessment(source = {}, ticket = {}) {
  if (standupDeliveryStateKey(ticket.state) !== 'branch checkin') {
    return { status: 'Not Applicable', evidence: '' };
  }

  const todayNote = String(ticket.today_note || '').trim();
  if (!todayNote) return { status: 'Unknown', evidence: '' };

  const requestedStatus = String(
    source.sandbox_validation_status || 'Unknown',
  );
  if (!SANDBOX_VALIDATION_STATUSES.has(requestedStatus)) {
    return { status: 'Unknown', evidence: '' };
  }
  if (requestedStatus === 'Unknown' || requestedStatus === 'Not Applicable') {
    return { status: 'Unknown', evidence: '' };
  }

  const evidence = String(source.sandbox_validation_evidence || '').trim();
  const validEvidence = Boolean(evidence) &&
    normalizeText(todayNote).includes(normalizeText(evidence));
  if (!validEvidence) return { status: 'Unknown', evidence: '' };
  if (requestedStatus === 'Passed' && !sandboxEvidenceIndicatesPass(evidence)) {
    return { status: 'Unknown', evidence: '' };
  }

  return { status: requestedStatus, evidence };
}

export function validateStandupReforecastAssessment(source = {}, ticket = {}) {
  const direction = String(ticket.reforecast_direction || 'unchanged');
  if (direction !== 'later') {
    return {
      status: 'Not Applicable',
      reasonType: 'None',
      evidence: '',
    };
  }

  const todayNote = String(ticket.today_note || '').trim();
  if (!todayNote) {
    return { status: 'Missing', reasonType: 'None', evidence: '' };
  }

  const requestedStatus = String(
    source.reforecast_explanation_status || '',
  );
  const requestedReason = String(source.reforecast_reason_type || 'None');
  const evidence = String(source.reforecast_evidence || '').trim();
  const validEvidence =
    Boolean(evidence) && normalizeText(todayNote).includes(normalizeText(evidence));

  if (
    requestedStatus === 'Supported' &&
    validEvidence &&
    REFORECAST_REASON_TYPES.has(requestedReason) &&
    requestedReason !== 'None'
  ) {
    return {
      status: 'Supported',
      reasonType: requestedReason,
      evidence,
    };
  }

  return {
    status: 'Ambiguous',
    reasonType: 'None',
    evidence: validEvidence ? evidence : '',
  };
}
