import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getAssignedDeveloperUpdate,
  indexLatestStandupUpdates,
} from './standup-review-identity.js';

test('selects only the assigned developer update', () => {
  const updates = [
    {
      ticketId: '101',
      email: 'pm@example.com',
      code: '500_01',
      at: '2026-07-10T09:30:00Z',
    },
    {
      ticketId: '101',
      email: 'dev@example.com',
      code: '200_01',
      at: '2026-07-10T09:00:00Z',
    },
  ];

  const index = indexLatestStandupUpdates(updates);
  const selected = getAssignedDeveloperUpdate(
    index,
    '101',
    'DEV@example.com',
  );

  assert.equal(selected.code, '200_01');
});

test('does not use PM, admin, or lead rows without a developer update', () => {
  const roles = ['pm', 'admin', 'lead'];
  const updates = roles.map((role, index) => ({
    ticketId: '202',
    email: role + '@example.com',
    code: '500_0' + String(index + 1),
    at: '2026-07-10T0' + String(index + 7) + ':00:00Z',
  }));

  const selected = getAssignedDeveloperUpdate(
    indexLatestStandupUpdates(updates),
    '202',
    'developer@example.com',
  );

  assert.equal(selected, undefined);
});

test('selects the latest assigned-developer row per ticket', () => {
  const updates = [
    {
      ticket_id: '303',
      email: 'dev@example.com',
      code: '100_01',
      at: '2026-07-10T08:00:00Z',
    },
    {
      ticket_id: '303',
      email: 'dev@example.com',
      code: '200_01',
      at: '2026-07-10T10:00:00Z',
    },
    {
      ticket_id: '304',
      email: 'dev@example.com',
      code: '300_01',
      at: '2026-07-10T11:00:00Z',
    },
  ];

  const index = indexLatestStandupUpdates(updates);

  assert.equal(
    getAssignedDeveloperUpdate(index, '303', 'dev@example.com').code,
    '200_01',
  );
  assert.equal(
    getAssignedDeveloperUpdate(index, '304', 'dev@example.com').code,
    '300_01',
  );
});
