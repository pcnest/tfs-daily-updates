import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chunkStandupReviewPayload,
  hasCompleteStandupCoverage,
  isStandupReviewRoleAllowed,
  standupDateOnly,
  standupIsWeekday,
  standupPreviousWeekday,
  standupReviewInputHash,
} from './standup-review-reliability.js';

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

test('Standup Review authorization is limited to admin', () => {
  assert.equal(isStandupReviewRoleAllowed('pm'), false);
  assert.equal(isStandupReviewRoleAllowed('ADMIN'), true);
  assert.equal(isStandupReviewRoleAllowed('lead'), false);
  assert.equal(isStandupReviewRoleAllowed('dev'), false);
  assert.equal(isStandupReviewRoleAllowed(''), false);
});
