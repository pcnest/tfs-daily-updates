import crypto from 'node:crypto';

export function standupDateOnly(value) {
  const text = String(value || '');
  const match = text.match(/^(\d{4}-\d{2}-\d{2})/);
  if (match) {
    const parsedMatch = new Date(`${match[1]}T00:00:00Z`);
    if (
      Number.isFinite(parsedMatch.getTime()) &&
      parsedMatch.toISOString().slice(0, 10) === match[1]
    ) {
      return match[1];
    }
    return '';
  }
  const parsed = Date.parse(text);
  return Number.isFinite(parsed)
    ? new Date(parsed).toISOString().slice(0, 10)
    : '';
}

export function standupIsWeekday(dateValue) {
  const date = standupDateOnly(dateValue);
  if (!date) return false;
  const day = new Date(`${date}T00:00:00Z`).getUTCDay();
  return day >= 1 && day <= 5;
}

export function standupPreviousWeekday(dateValue) {
  const date = standupDateOnly(dateValue);
  if (!date) return '';
  const cursor = new Date(`${date}T00:00:00Z`);
  do {
    cursor.setUTCDate(cursor.getUTCDate() - 1);
  } while ([0, 6].includes(cursor.getUTCDay()));
  return cursor.toISOString().slice(0, 10);
}

export function standupReviewInputHash(payload) {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(payload || []))
    .digest('hex');
}

export function chunkStandupReviewPayload(payload, batchSize = 25) {
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    throw new TypeError('batchSize must be a positive integer');
  }
  const items = Array.isArray(payload) ? payload : [];
  const chunks = [];
  for (let i = 0; i < items.length; i += batchSize) {
    chunks.push(items.slice(i, i + batchSize));
  }
  return chunks;
}

export function hasCompleteStandupCoverage(payload, classifications) {
  const eligible = Array.isArray(payload) ? payload : [];
  const reviewed = Array.isArray(classifications) ? classifications : [];
  const eligibleIds = eligible.map((item) =>
    String(item?.ticket_id ?? ''),
  );
  const reviewedIds = reviewed.map((item) =>
    String(item?.ticket_id ?? ''),
  );
  if (
    eligibleIds.some((id) => !id) ||
    reviewedIds.some((id) => !id) ||
    eligibleIds.length !== reviewedIds.length
  ) {
    return false;
  }
  const eligibleSet = new Set(eligibleIds);
  const reviewedSet = new Set(reviewedIds);
  return (
    eligibleSet.size === eligibleIds.length &&
    reviewedSet.size === reviewedIds.length &&
    eligibleSet.size === reviewedSet.size &&
    eligibleIds.every((id) => reviewedSet.has(id))
  );
}

export function isStandupReviewRoleAllowed(role) {
  return String(role || '').trim().toLowerCase() === 'admin';
}
