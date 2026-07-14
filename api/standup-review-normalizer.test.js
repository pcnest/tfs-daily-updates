import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';
const { normalizeStandupReviewResult } = await import('./server-pg.js');

function baseTicket(overrides = {}) {
  return {
    ticket_id: '1001',
    title: 'Ticket under review',
    type: 'Bug',
    state: 'Committed',
    assigned_to: 'Developer <DSANTFS01\\dev>',
    assigned_developer_email: 'dev@example.com',
    priority: 2,
    severity: '3 - Medium',
    state_change_date: '2026-07-10',
    review_date: '2026-07-13',
    previous_workday_date: '2026-07-10',
    today_code: '100_01',
    today_note: '',
    prev_code: '100_01',
    prev_note: '',
    prev_date: '2026-07-10',
    has_today_update: true,
    ...overrides,
  };
}

function sourceClassification(ticketId, overrides = {}) {
  return {
    ticket_id: ticketId,
    title: 'Ticket under review',
    developer: 'Developer <DSANTFS01\\dev>',
    current_code: '100_01',
    update_summary: '',
    category: 'Needs PM Escalation',
    sub_tags: ['Normal Progress', 'Missing Notes', 'Possible Risk'],
    reason: 'AI source classification',
    recommended_action: 'Review before standup.',
    ...overrides,
  };
}

function classify(ticket, source = sourceClassification(ticket.ticket_id)) {
  return normalizeStandupReviewResult(
    { classifications: [source], follow_up_questions: [] },
    [ticket],
  );
}

test('Branch Checkin 500_xx blank-note handoff remains On Track', () => {
  const ticket = baseTicket({
    ticket_id: '187114',
    type: 'Product Backlog Item',
    state: 'Branch Checkin',
    priority: 2,
    severity: '',
    today_code: '500_01',
    today_note: '',
    prev_code: '400_01',
    prev_note: '',
  });

  const result = classify(ticket);
  const item = result.classifications[0];

  assert.equal(item.category, 'On Track');
  assert.equal(result.pm_escalation_items.length, 0);
  assert.equal(result.validation.needs_pm_escalation, 0);
  assert.equal(item.sub_tags.includes('Ready for Release'), true);
  assert.equal(item.sub_tags.includes('Missing Notes'), false);
  assert.equal(item.sub_tags.includes('Possible Risk'), false);
});

test('Branch Check-in spelling variant maps to the same handoff behavior', () => {
  const ticket = baseTicket({
    ticket_id: '187115',
    type: 'Product Backlog Item',
    state: 'Branch Check-in',
    today_code: '500_01',
    today_note: '',
    prev_code: '400_01',
  });

  const result = classify(ticket);
  const item = result.classifications[0];

  assert.equal(item.category, 'On Track');
  assert.equal(item.sub_tags.includes('Ready for Release'), true);
  assert.equal(item.sub_tags.includes('Missing Notes'), false);
});

test('QA workflow 500_xx blank-note handoff remains On Track', () => {
  for (const state of ['QA Testing', 'Ready for QA']) {
    const ticket = baseTicket({
      ticket_id: `qa-${state}`,
      state,
      today_code: '500_01',
      today_note: '',
      prev_code: '400_01',
    });

    const result = classify(ticket);
    const item = result.classifications[0];

    assert.equal(item.category, 'On Track');
    assert.equal(item.sub_tags.includes('Ready for QA'), true);
    assert.equal(item.sub_tags.includes('Missing Notes'), false);
    assert.equal(result.pm_escalation_items.length, 0);
  }
});

test('P1/P2 active-state submitted blank note goes to Team Lead first', () => {
  const ticket = baseTicket({
    ticket_id: '216430',
    state: 'Committed',
    priority: 2,
    today_code: '100_01',
    today_note: '',
    prev_code: '100_01',
  });

  const result = classify(ticket);
  const item = result.classifications[0];

  assert.equal(item.category, 'Needs Team Lead Clarification');
  assert.equal(item.sub_tags.includes('Missing Notes'), true);
  assert.equal(item.sub_tags.includes('Normal Progress'), false);
  assert.equal(result.tl_review_items.length, 1);
  assert.equal(result.pm_escalation_items.length, 0);
  assert.equal(result.validation.needs_tl_clarification, 1);
});

test('P1/P2 active-state no-update still escalates to PM', () => {
  const ticket = baseTicket({
    ticket_id: 'missing-p2',
    state: 'Committed',
    priority: 2,
    today_code: null,
    today_note: null,
    prev_code: '100_01',
    prev_note: '',
    has_today_update: false,
  });

  const result = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'Missing Update',
    sub_tags: [],
  }));
  const item = result.classifications[0];

  assert.equal(item.category, 'Needs PM Escalation');
  assert.equal(item.sub_tags.includes('No Daily Update'), true);
  assert.equal(item.sub_tags.includes('Possible Risk'), true);
  assert.equal(result.pm_escalation_items.length, 1);
});

test('P1/P2 incomplete update with explicit delivery impact escalates to PM', () => {
  const ticket = baseTicket({
    ticket_id: 'risk-p2',
    state: 'Committed',
    priority: 2,
    today_code: '100_01',
    today_note: '',
  });
  const source = sourceClassification(ticket.ticket_id, {
    category: 'Needs PM Escalation',
    sub_tags: ['Normal Progress', 'Missing Notes', 'Release Risk'],
  });

  const result = classify(ticket, source);
  const item = result.classifications[0];

  assert.equal(item.category, 'Needs PM Escalation');
  assert.equal(item.sub_tags.includes('Missing Notes'), true);
  assert.equal(item.sub_tags.includes('Release Risk'), true);
  assert.equal(item.sub_tags.includes('Normal Progress'), false);
  assert.equal(result.pm_escalation_items.length, 1);
});

test('derived counts and lists follow normalized classifications', () => {
  const payload = [
    baseTicket({
      ticket_id: 'handoff',
      type: 'Product Backlog Item',
      state: 'Branch Checkin',
      today_code: '500_01',
      today_note: '',
    }),
    baseTicket({
      ticket_id: 'tl',
      state: 'Committed',
      today_code: '100_01',
      today_note: '',
    }),
    baseTicket({
      ticket_id: 'pm',
      state: 'Committed',
      has_today_update: false,
      today_code: null,
      today_note: null,
      prev_code: '100_01',
    }),
  ];
  const result = normalizeStandupReviewResult(
    {
      classifications: payload.map((ticket) =>
        sourceClassification(ticket.ticket_id),
      ),
      follow_up_questions: [],
    },
    payload,
  );

  assert.equal(result.validation.total_reviewed, 3);
  assert.equal(result.validation.on_track, 1);
  assert.equal(result.validation.needs_tl_clarification, 1);
  assert.equal(result.validation.needs_pm_escalation, 1);
  assert.equal(result.tl_review_items.length, 1);
  assert.equal(result.pm_escalation_items.length, 1);
  assert.equal(result.exceptions.needs_tl_clarification.length, 1);
  assert.equal(result.exceptions.needs_pm_escalation.length, 1);
});