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
  if (!columns)
    throw new Error(`unsupported historical ticket field: ${field}`);

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

export function historicalReportStateSql(
  { updateAlias = 'u', ticketAlias = 't', outputAlias = 'state' } = {},
) {
  const update = sqlIdentifier(updateAlias, 'update alias');
  const ticket = sqlIdentifier(ticketAlias, 'ticket alias');
  const output = sqlIdentifier(outputAlias, 'output alias');

  // A progress update can race ahead of the TFS sync agent. Correct that
  // bounded case only when the currently synchronized state became effective
  // before the update was submitted. Later TFS transitions must not rewrite
  // an older report row.
  return `case
      when ${update}.ticket_snapshot_at is null then ${ticket}.state
      when ${ticket}.state_change_date is distinct from ${update}.ticket_state_change_date
        and ${ticket}.state_change_date is not null
        and ${ticket}.state_change_date <= ${update}.at then ${ticket}.state
      else ${update}.ticket_state
    end as "${output}"`;
}

export function historicalRangeTicketSelectSql(aliases = {}) {
  return [
    historicalTicketFieldSql('type', aliases),
    historicalTicketFieldSql('title', aliases),
    historicalReportStateSql(aliases),
    historicalTicketFieldSql('severity', aliases),
  ].join(',\n    ');
}

export const PROGRESS_RANGE_SQL = `
  WITH ranked_updates AS (
    SELECT
      u.*,
      row_number() over (
        partition by u.date, u.ticket_id
        order by u.at desc, u.id desc
      ) AS report_rank
    FROM progress_updates u
    WHERE u.date BETWEEN $1::date AND $2::date
      AND (
        ($3::text IS NULL AND $4::text IS NULL)
        OR lower(u.email) = $3
        OR split_part(lower(u.email),'@',1) = $4
      )
  )
  SELECT
    u.date             AS "date",
    u.ticket_id        AS "ticketId",
    ${historicalRangeTicketSelectSql()},
    u.code,
    u.risk_level       AS "riskLevel",
    u.note
  FROM ranked_updates u
  JOIN tickets t ON t.id = u.ticket_id
  WHERE u.report_rank = 1
  ORDER BY u.date DESC, u.ticket_id
`;
