export const EXPECTED_DELIVERY_DATE_SCHEMA_SQL = `
  alter table tickets
    add column if not exists expected_delivery_date date
`;

export const EXPECTED_DELIVERY_DATE_HISTORY_SCHEMA_SQL = `
  create table if not exists ticket_expected_delivery_history (
    id bigserial primary key,
    ticket_id text not null,
    previous_expected_delivery_date date,
    expected_delivery_date date,
    change_direction text not null
      check (change_direction in ('later', 'earlier', 'set', 'cleared')),
    tfs_changed_date timestamptz,
    observed_at timestamptz not null default now()
  );
  create index if not exists ticket_expected_delivery_history_ticket_observed_idx
    on ticket_expected_delivery_history (ticket_id, observed_at desc, id desc)
`;

export const EXPECTED_DELIVERY_DATE_HISTORY_INSERT_SQL = `
  insert into ticket_expected_delivery_history
    (ticket_id, previous_expected_delivery_date,
     expected_delivery_date, change_direction, tfs_changed_date)
  select $1, $2::date, $3::date, $4, $5::timestamptz
   where not exists (
     select 1
       from ticket_expected_delivery_history
      where ticket_id = $1
        and previous_expected_delivery_date is not distinct from $2::date
        and expected_delivery_date is not distinct from $3::date
        and change_direction = $4
        and tfs_changed_date is not distinct from $5::timestamptz
   )
`;

export function expectedDeliveryDateChangeDirection(previousValue, nextValue) {
  const previous = previousValue || null;
  const next = nextValue || null;
  if (!previous && next) return 'set';
  if (previous && !next) return 'cleared';
  if (previous && next && next > previous) return 'later';
  if (previous && next && next < previous) return 'earlier';
  return null;
}

export function expectedDeliveryDateSyncValue(ticket) {
  const provided = Object.prototype.hasOwnProperty.call(
    ticket || {},
    'expectedDeliveryDate',
  );
  if (!provided) return { provided: false, value: null };

  const raw = ticket?.expectedDeliveryDate;
  if (raw == null || String(raw).trim() === '') {
    return { provided: true, value: null };
  }

  const match = String(raw)
    .trim()
    .match(/^(\d{4})-(\d{2})-(\d{2})(?:$|T)/);
  if (!match) throw new Error('expectedDeliveryDate must be an ISO date');

  const value = `${match[1]}-${match[2]}-${match[3]}`;
  const parsed = new Date(`${value}T00:00:00Z`);
  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.toISOString().slice(0, 10) !== value
  ) {
    throw new Error('expectedDeliveryDate must be a valid calendar date');
  }

  return { provided: true, value };
}
