import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PROGRESS_UPDATE_SNAPSHOT_SCHEMA_SQL,
  PROGRESS_UPDATE_WITH_SNAPSHOT_INSERT_SQL,
  historicalTicketFieldSql,
  historicalTicketSelectSql,
} from './progress-update-snapshots.js';

test('snapshot schema is additive and includes historical report metadata', () => {
  for (const column of [
    'ticket_state',
    'ticket_title',
    'ticket_type',
    'ticket_severity',
    'ticket_changed_date',
    'ticket_state_change_date',
    'ticket_snapshot_at',
  ]) {
    assert.match(PROGRESS_UPDATE_SNAPSHOT_SCHEMA_SQL, new RegExp(column));
  }
  assert.doesNotMatch(PROGRESS_UPDATE_SNAPSHOT_SCHEMA_SQL, /not null/i);
});

test('progress insert captures the ticket snapshot in one insert-select statement', () => {
  assert.match(
    PROGRESS_UPDATE_WITH_SNAPSHOT_INSERT_SQL,
    /insert into progress_updates[\s\S]+select[\s\S]+from tickets t/i,
  );
  assert.match(
    PROGRESS_UPDATE_WITH_SNAPSHOT_INSERT_SQL,
    /t\.state, t\.title, t\.type, t\.severity/i,
  );
  assert.match(PROGRESS_UPDATE_WITH_SNAPSHOT_INSERT_SQL, /where t\.id = \$1/i);
});

test('historical readers use snapshots when marked and fall back only for legacy rows', () => {
  assert.equal(
    historicalTicketFieldSql('state'),
    'case when u.ticket_snapshot_at is not null then u.ticket_state else t.state end as "state"',
  );

  const select = historicalTicketSelectSql();
  assert.match(
    select,
    /case when u\.ticket_snapshot_at is not null then u\.ticket_type else t\.type end as "type"/,
  );
  assert.match(
    select,
    /case when u\.ticket_snapshot_at is not null then u\.ticket_title else t\.title end as "title"/,
  );
  assert.match(
    select,
    /case when u\.ticket_snapshot_at is not null then u\.ticket_state else t\.state end as "state"/,
  );
  assert.match(
    select,
    /case when u\.ticket_snapshot_at is not null then u\.ticket_severity else t\.severity end as "severity"/,
  );
});

test('historical SQL helper rejects unsupported fields and unsafe aliases', () => {
  assert.throws(() => historicalTicketFieldSql('priority'), /unsupported/);
  assert.throws(
    () =>
      historicalTicketFieldSql('state', {
        updateAlias: 'u; drop table tickets',
      }),
    /invalid update alias/,
  );
});
