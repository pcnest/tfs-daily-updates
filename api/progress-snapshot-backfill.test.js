import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSnapshotProposal,
  normalizeTfsRevisions,
  selectRevisionAt,
  validateDateRange,
} from './progress-snapshot-backfill.js';

const raw = [
  {
    rev: 1,
    fields: {
      'System.ChangedDate': '2026-06-25T21:22:57.407Z',
      'System.State': 'Committed',
      'System.Title': 'Example title',
      'System.WorkItemType': 'Product Backlog Item',
    },
  },
  {
    rev: 2,
    fields: {
      'System.ChangedDate': '2026-07-02T14:40:33.787Z',
      'System.State': 'In Development',
    },
  },
  {
    rev: 3,
    fields: {
      'System.ChangedDate': '2026-07-07T20:50:24.680Z',
      'System.State': 'Shelved',
    },
  },
];

test('normalizes revisions and carries forward historical metadata', () => {
  const revisions = normalizeTfsRevisions(raw);
  assert.equal(revisions.length, 3);
  assert.equal(revisions[1].title, 'Example title');
  assert.equal(revisions[1].type, 'Product Backlog Item');
  assert.equal(
    revisions[1].stateChangeDate.toISOString(),
    '2026-07-02T14:40:33.787Z',
  );
});

test('selects the latest revision at or before the exact update timestamp', () => {
  const revisions = normalizeTfsRevisions(raw);
  assert.equal(
    selectRevisionAt(revisions, '2026-07-02T14:00:00Z').state,
    'Committed',
  );
  assert.equal(
    selectRevisionAt(revisions, '2026-07-02T15:00:00Z').state,
    'In Development',
  );
  assert.equal(
    selectRevisionAt(revisions, '2026-07-07T21:00:00Z').state,
    'Shelved',
  );
});

test('builds a resolved proposal without modifying progress content', () => {
  const proposal = buildSnapshotProposal(
    {
      id: '42',
      ticketId: '214663',
      date: '2026-07-06',
      at: '2026-07-06T22:30:00Z',
    },
    normalizeTfsRevisions(raw),
  );
  assert.equal(proposal.status, 'resolved');
  assert.equal(proposal.ticketState, 'In Development');
  assert.equal(proposal.revision, 2);
  assert.equal(Object.hasOwn(proposal, 'note'), false);
  assert.equal(Object.hasOwn(proposal, 'code'), false);
});

test('reports updates that predate all available revisions as unresolved', () => {
  const proposal = buildSnapshotProposal(
    {
      id: '7',
      ticketId: '214663',
      date: '2026-06-01',
      at: '2026-06-01T10:00:00Z',
    },
    normalizeTfsRevisions(raw),
  );
  assert.equal(proposal.status, 'unresolved');
  assert.equal(proposal.reason, 'no_revision_at_or_before_update');
});

test('does not resolve a revision missing required ticket metadata', () => {
  const proposal = buildSnapshotProposal(
    {
      id: '8',
      ticketId: '999',
      date: '2026-07-01',
      at: '2026-07-01T10:00:00Z',
    },
    normalizeTfsRevisions([
      {
        rev: 1,
        fields: {
          'System.ChangedDate': '2026-07-01T09:00:00Z',
          'System.State': 'Committed',
        },
      },
    ]),
  );
  assert.equal(proposal.status, 'unresolved');
  assert.equal(proposal.reason, 'missing_required_revision_fields');
  assert.deepEqual(proposal.missingFields, ['title', 'type']);
});

test('validates bounded ISO date inputs', () => {
  assert.deepEqual(validateDateRange('2026-07-01', '2026-07-14'), {
    from: '2026-07-01',
    to: '2026-07-14',
  });
  assert.throws(() => validateDateRange('07/01/2026', '2026-07-14'));
  assert.throws(() => validateDateRange('2026-07-15', '2026-07-14'));
});
