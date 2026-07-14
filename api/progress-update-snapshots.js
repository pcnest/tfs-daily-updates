const SNAPSHOT_FIELDS = Object.freeze({
  type: { snapshot: 'ticket_type', current: 'type' },
  title: { snapshot: 'ticket_title', current: 'title' },
  state: { snapshot: 'ticket_state', current: 'state' },
  severity: { snapshot: 'ticket_severity', current: 'severity' },
});

export const PROGRESS_UPDATE_SNAPSHOT_SCHEMA_SQL = `
  alter table progress_updates
    add column if not exists ticket_state text,
    add column if not exists ticket_title text,
    add column if not exists ticket_type text,
    add column if not exists ticket_severity text,
    add column if not exists ticket_changed_date timestamptz,
    add column if not exists ticket_state_change_date timestamptz,
    add column if not exists ticket_snapshot_at timestamptz
`;

export const PROGRESS_UPDATE_WITH_SNAPSHOT_INSERT_SQL = `
  insert into progress_updates (
    ticket_id, email, user_id, code, note, risk_level, impact_area, date, at,
    ticket_state, ticket_title, ticket_type, ticket_severity,
    ticket_changed_date, ticket_state_change_date, ticket_snapshot_at
  )
  select
    $1, $2, $3, $4, $5, $6, $7, $8, now(),
    t.state, t.title, t.type, t.severity,
    t.changed_date, t.state_change_date, now()
  from tickets t
  where t.id = $1
  returning ticket_id
`;

function sqlIdentifier(value, label) {
  const identifier = String(value || '');
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
    throw new Error(`invalid ${label}`);
  }
  return identifier;
}

export function historicalTicketFieldSql(
  field,
  { updateAlias = 'u', ticketAlias = 't', outputAlias = field } = {},
) {
  const columns = SNAPSHOT_FIELDS[field];
  if (!columns) throw new Error(`unsupported historical ticket field: ${field}`);

  const update = sqlIdentifier(updateAlias, 'update alias');
  const ticket = sqlIdentifier(ticketAlias, 'ticket alias');
  const output = sqlIdentifier(outputAlias, 'output alias');

  // The marker distinguishes a deliberately captured null (for example, a PBI
  // with no severity) from a legacy row that has never been snapshotted.
  return `case when ${update}.ticket_snapshot_at is not null then ${update}.${columns.snapshot} else ${ticket}.${columns.current} end as "${output}"`;
}

export function historicalTicketSelectSql(
  fields = ['type', 'title', 'state', 'severity'],
  aliases = {},
) {
  return fields
    .map((field) => historicalTicketFieldSql(field, aliases))
    .join(',\n    ');
}
