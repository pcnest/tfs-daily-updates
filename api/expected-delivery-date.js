export const EXPECTED_DELIVERY_DATE_SCHEMA_SQL = `
  alter table tickets
    add column if not exists expected_delivery_date date
`;

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
