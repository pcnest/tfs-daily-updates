const FIELD_NAMES = Object.freeze({
  changedDate: 'System.ChangedDate',
  state: 'System.State',
  title: 'System.Title',
  type: 'System.WorkItemType',
  severity: 'Microsoft.VSTS.Common.Severity',
  stateChangeDate: 'Microsoft.VSTS.Common.StateChangeDate',
});

function optionalText(value) {
  return value == null ? null : String(value);
}

function optionalDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function normalizeTfsRevisions(rawRevisions) {
  const sorted = [...(Array.isArray(rawRevisions) ? rawRevisions : [])].sort(
    (a, b) => Number(a?.rev || 0) - Number(b?.rev || 0),
  );
  const current = {
    state: null,
    title: null,
    type: null,
    severity: null,
  };
  let derivedStateChangeDate = null;
  let previousState = null;

  return sorted
    .map((revision) => {
      const fields = revision?.fields || {};
      const changedDate = optionalDate(fields[FIELD_NAMES.changedDate]);
      if (!changedDate) return null;

      for (const name of ['state', 'title', 'type', 'severity']) {
        const fieldName = FIELD_NAMES[name];
        if (Object.prototype.hasOwnProperty.call(fields, fieldName)) {
          current[name] = optionalText(fields[fieldName]);
        }
      }

      if (current.state !== previousState) {
        derivedStateChangeDate = changedDate;
        previousState = current.state;
      }
      const explicitStateChangeDate = optionalDate(
        fields[FIELD_NAMES.stateChangeDate],
      );

      return {
        rev: Number(revision?.rev || 0),
        changedDate,
        stateChangeDate: explicitStateChangeDate || derivedStateChangeDate,
        state: current.state,
        title: current.title,
        type: current.type,
        severity: current.severity,
      };
    })
    .filter(Boolean);
}

export function selectRevisionAt(revisions, timestamp) {
  const target = optionalDate(timestamp);
  if (!target) return null;

  let selected = null;
  for (const revision of Array.isArray(revisions) ? revisions : []) {
    if (revision.changedDate.getTime() > target.getTime()) break;
    selected = revision;
  }
  return selected;
}

export function buildSnapshotProposal(update, revisions) {
  const selected = selectRevisionAt(revisions, update?.at);
  if (!selected) {
    return {
      updateId: String(update?.id || ''),
      ticketId: String(update?.ticketId || ''),
      status: 'unresolved',
      reason: 'no_revision_at_or_before_update',
    };
  }
  const missingFields = ['state', 'title', 'type'].filter(
    (field) => !String(selected[field] || '').trim(),
  );
  if (missingFields.length) {
    return {
      updateId: String(update?.id || ''),
      ticketId: String(update?.ticketId || ''),
      status: 'unresolved',
      reason: 'missing_required_revision_fields',
      revision: selected.rev,
      missingFields,
    };
  }

  return {
    updateId: String(update.id),
    ticketId: String(update.ticketId),
    updateDate: String(update.date || ''),
    updateAt: new Date(update.at).toISOString(),
    status: 'resolved',
    revision: selected.rev,
    ticketState: selected.state,
    ticketTitle: selected.title,
    ticketType: selected.type,
    ticketSeverity: selected.severity,
    ticketChangedDate: selected.changedDate.toISOString(),
    ticketStateChangeDate: selected.stateChangeDate
      ? selected.stateChangeDate.toISOString()
      : null,
  };
}

export function validateDateRange(from, to) {
  const datePattern = /^\d{4}-\d{2}-\d{2}$/;
  if (!datePattern.test(String(from || '')) || !datePattern.test(String(to || ''))) {
    throw new Error('from and to must use YYYY-MM-DD');
  }
  const fromDate = new Date(`${from}T00:00:00Z`);
  const toDate = new Date(`${to}T00:00:00Z`);
  if (Number.isNaN(fromDate.getTime()) || Number.isNaN(toDate.getTime())) {
    throw new Error('from and to must be valid dates');
  }
  if (fromDate > toDate) throw new Error('from must not be after to');
  return { from, to };
}
