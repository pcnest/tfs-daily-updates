export function normalizeStandupEmail(value) {
  return String(value || '').trim().toLowerCase();
}

export function standupUpdateKey(ticketId, email) {
  return String(ticketId || '').trim() + '|' + normalizeStandupEmail(email);
}

function standupUpdateTime(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function indexLatestStandupUpdates(updates) {
  const latest = new Map();
  for (const update of updates || []) {
    const ticketId = String(
      update?.ticketId || update?.ticket_id || '',
    ).trim();
    const email = normalizeStandupEmail(update?.email);
    if (!ticketId || !email) continue;
    const key = standupUpdateKey(ticketId, email);

    const previous = latest.get(key);
    if (
      !previous ||
      standupUpdateTime(update?.at) > standupUpdateTime(previous?.at)
    ) {
      latest.set(key, update);
    }
  }
  return latest;
}

export function getAssignedDeveloperUpdate(index, ticketId, developerEmail) {
  if (!developerEmail) return undefined;
  return index.get(standupUpdateKey(ticketId, developerEmail));
}
