import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  chunkStandupReviewPayload,
  hasCompleteStandupCoverage,
  isStandupReviewRoleAllowed,
  standupDateOnly,
  standupDateInTimeZone,
  standupIsWeekday,
  standupPreviousWeekday,
  standupReviewInputHash,
} from './standup-review-reliability.js';

const serverSource = await readFile(
  new URL('./server-pg.js', import.meta.url),
  'utf8',
);

test('normalizes dates and applies the Monday-Friday calendar', () => {
  assert.equal(standupDateOnly('2026-07-10T09:00:00Z'), '2026-07-10');
  assert.equal(standupDateOnly('not-a-date'), '');
  assert.equal(standupDateOnly('2026-02-30'), '');
  assert.equal(standupIsWeekday('2026-07-10'), true);
  assert.equal(standupIsWeekday('2026-07-11'), false);
  assert.equal(standupIsWeekday('2026-07-12'), false);
  assert.equal(standupPreviousWeekday('2026-07-13'), '2026-07-10');
  assert.equal(standupPreviousWeekday('2026-07-14'), '2026-07-13');
  assert.equal(standupPreviousWeekday('2026-02-30'), '');
});

test('normalizes state transitions to the configured application timezone', () => {
  assert.equal(
    standupDateInTimeZone('2026-08-17T16:30:00Z', 'Asia/Shanghai'),
    '2026-08-18',
  );
  assert.equal(
    standupDateInTimeZone('2026-08-17T15:30:00Z', 'Asia/Shanghai'),
    '2026-08-17',
  );
  assert.equal(
    standupDateInTimeZone('2026-08-18', 'Asia/Shanghai'),
    '2026-08-18',
  );
  assert.equal(standupDateInTimeZone('invalid', 'Asia/Shanghai'), '');
  assert.equal(standupDateInTimeZone('2026-08-18T00:00:00Z', 'Bad/Zone'), '');
});

test('hash is stable for the same payload and changes with source data', () => {
  const payload = [
    {
      ticket_id: '101',
      assigned_developer_email: 'dev@example.com',
      today_code: '200_01',
      today_note: 'working',
    },
  ];
  const original = standupReviewInputHash(payload);

  assert.equal(standupReviewInputHash(structuredClone(payload)), original);
  assert.notEqual(
    standupReviewInputHash([{ ...payload[0], today_note: 'completed' }]),
    original,
  );
  assert.notEqual(
    standupReviewInputHash([
      { ...payload[0], assigned_developer_email: 'other@example.com' },
    ]),
    original,
  );
  assert.notEqual(
    standupReviewInputHash([
      { ...payload[0], expected_delivery_date: '2026-07-20' },
    ]),
    original,
  );
});

test('chunks the complete payload without truncation', () => {
  const payload = Array.from({ length: 70 }, (_, index) => ({
    ticket_id: String(index + 1),
  }));
  const chunks = chunkStandupReviewPayload(payload, 25);

  assert.deepEqual(chunks.map((chunk) => chunk.length), [25, 25, 20]);
  assert.deepEqual(chunks.flat(), payload);
  assert.throws(
    () => chunkStandupReviewPayload(payload, 0),
    /positive integer/,
  );
});

test('coverage requires one matching classification per eligible ticket', () => {
  const payload = [{ ticket_id: '1' }, { ticket_id: '2' }];

  assert.equal(
    hasCompleteStandupCoverage(payload, [
      { ticket_id: '2' },
      { ticket_id: '1' },
    ]),
    true,
  );
  assert.equal(
    hasCompleteStandupCoverage(payload, [{ ticket_id: '1' }]),
    false,
  );
  assert.equal(
    hasCompleteStandupCoverage(payload, [
      { ticket_id: '1' },
      { ticket_id: '1' },
    ]),
    false,
  );
  assert.equal(
    hasCompleteStandupCoverage(payload, [
      { ticket_id: '1' },
      { ticket_id: '3' },
    ]),
    false,
  );
});

test('Standup eligibility excludes Done and Removed tickets', () => {
  const queryStart = serverSource.indexOf(
    'async function queryStandupReviewInput',
  );
  const queryEnd = serverSource.indexOf(
    'async function loadStandupReviewInput',
    queryStart,
  );
  const querySource = serverSource.slice(queryStart, queryEnd);

  assert.ok(queryStart >= 0 && queryEnd > queryStart);
  assert.match(
    querySource,
    /and lower\(t\.state\) not in \('done', 'removed'\)/,
  );
});

test('canonical Standup input localizes the TFS state transition date', () => {
  const payloadStart = serverSource.indexOf(
    'function buildStandupReviewPayload',
  );
  const payloadEnd = serverSource.indexOf(
    'function buildStandupModelPayload',
    payloadStart,
  );
  const payloadSource = serverSource.slice(payloadStart, payloadEnd);

  assert.ok(payloadStart >= 0 && payloadEnd > payloadStart);
  assert.match(
    payloadSource,
    /standupDateInTimeZone\([\s\S]*stateChangeDate[\s\S]*APP_TZ/,
  );
});

test('v21 model contract includes evidence-backed Sandbox and update-quality rules', () => {
  assert.match(serverSource, /standup_review_v21/);
  assert.match(serverSource, /sandbox_validation_status/);
  assert.match(serverSource, /sandbox_validation_evidence/);
  assert.match(serverSource, /'Pending',[\s\S]*'In Progress',[\s\S]*'Rework Required',[\s\S]*'Passed'/);
  assert.match(serverSource, /The title supplies the work-item scope/);
  assert.match(serverSource, /An overdue forecast does not make an otherwise usable note vague/);
  assert.match(serverSource, /No progress was made because build-release tickets were prioritized/);
});

test('Standup Review authorization is limited to admin', () => {
  assert.equal(isStandupReviewRoleAllowed('pm'), false);
  assert.equal(isStandupReviewRoleAllowed('ADMIN'), true);
  assert.equal(isStandupReviewRoleAllowed('lead'), false);
  assert.equal(isStandupReviewRoleAllowed('dev'), false);
  assert.equal(isStandupReviewRoleAllowed(''), false);
});
