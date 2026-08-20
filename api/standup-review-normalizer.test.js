import test from 'node:test';
import assert from 'node:assert/strict';
import {
  STANDUP_ESCALATION_POLICY_VERSION,
  applyStandupEscalationOverlay,
  buildStandupCorrectionState,
  standupCorrectionDisplay,
} from './standup-review-escalation.js';
import {
  renderStandupNotificationEmail,
  routeStandupNotifications,
  standupDeveloperCorrectionItems,
} from './standup-review-notifications.js';

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

test('Branch Checkin transition-day 500_01 blank note gets Sandbox grace', () => {
  const ticket = baseTicket({
    ticket_id: '187114',
    type: 'Product Backlog Item',
    state: 'Branch Checkin',
    priority: 2,
    severity: '',
    state_change_date: '2026-07-13',
    expected_delivery_date: '2026-07-20',
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
  assert.equal(item.sub_tags.includes('Sandbox Validation'), true);
  assert.equal(item.sub_tags.includes('Ready for Release'), false);
  assert.equal(item.sub_tags.includes('Missing Notes'), false);
  assert.equal(item.sub_tags.includes('Possible Risk'), false);
  assert.equal(item.delivery_date_status, 'scheduled');
});

test('Branch Checkin transition-day grace covers no update but requires a valid state date', () => {
  const transitionTicket = baseTicket({
    ticket_id: 'branch-transition-no-update',
    type: 'Bug',
    state: 'Branch Checkin',
    priority: 3,
    state_change_date: '2026-07-13',
    expected_delivery_date: '2026-07-20',
    today_code: null,
    today_note: null,
    prev_code: '400_01',
    has_today_update: false,
  });
  const transitionItem = classify(transitionTicket).classifications[0];
  assert.equal(transitionItem.category, 'On Track');
  assert.equal(transitionItem.sub_tags.includes('No Daily Update'), false);
  assert.equal(transitionItem.sub_tags.includes('Sandbox Validation'), true);

  const missingDateTicket = {
    ...transitionTicket,
    ticket_id: 'branch-missing-state-date',
    state_change_date: null,
  };
  const missingDateItem = classify(missingDateTicket, sourceClassification(
    missingDateTicket.ticket_id,
    { category: 'On Track', sub_tags: ['Normal Progress'] },
  )).classifications[0];
  assert.equal(missingDateItem.category, 'Missing Update');
  assert.equal(missingDateItem.sub_tags.includes('No Daily Update'), true);
});

test('Branch Checkin requires a Sandbox update after the transition date', () => {
  const noUpdate = baseTicket({
    ticket_id: 'branch-no-update',
    type: 'Product Backlog Item',
    state: 'Branch Checkin',
    priority: 3,
    state_change_date: '2026-07-10',
    expected_delivery_date: '2026-07-20',
    today_code: null,
    today_note: null,
    prev_code: '500_01',
    prev_note: '',
    has_today_update: false,
  });
  const noUpdateItem = classify(noUpdate, sourceClassification(
    noUpdate.ticket_id,
    { category: 'On Track', sub_tags: ['Normal Progress'] },
  )).classifications[0];
  assert.equal(noUpdateItem.category, 'Missing Update');
  assert.equal(noUpdateItem.sub_tags.includes('No Daily Update'), true);
  assert.equal(noUpdateItem.sub_tags.includes('Sandbox Validation'), true);

  const blankNote = baseTicket({
    ...noUpdate,
    ticket_id: 'branch-blank-note',
    today_code: '500_01',
    today_note: '   ',
    has_today_update: true,
  });
  const blankItem = classify(blankNote, sourceClassification(
    blankNote.ticket_id,
    { category: 'On Track', sub_tags: ['Normal Progress'] },
  )).classifications[0];
  assert.equal(blankItem.category, 'Needs Team Lead Clarification');
  assert.equal(blankItem.sub_tags.includes('Missing Notes'), true);
  assert.equal(blankItem.sub_tags.includes('Sandbox Validation'), true);
});

test('Branch Checkin with a current Sandbox-status note remains On Track', () => {
  const ticket = baseTicket({
    ticket_id: 'branch-in-progress',
    type: 'Product Backlog Item',
    state: 'Branch Checkin',
    priority: 3,
    state_change_date: '2026-07-10',
    expected_delivery_date: '2026-07-20',
    today_code: '500_01',
    today_note: 'Sandbox validation is in progress for the checkout flow.',
    prev_code: '500_01',
    prev_note: 'Changes were checked in.',
  });
  const source = sourceClassification(ticket.ticket_id, {
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Wrong or Mismatched Progress Code', 'Ready for Release'],
    sandbox_validation_status: 'In Progress',
    sandbox_validation_evidence: 'Sandbox validation is in progress',
  });
  const item = classify(ticket, source).classifications[0];

  assert.equal(item.category, 'On Track');
  assert.equal(item.sub_tags.includes('Sandbox Validation'), true);
  assert.equal(item.sub_tags.includes('Ready for Release'), false);
  assert.equal(
    item.sub_tags.includes('Wrong or Mismatched Progress Code'),
    false,
  );
  assert.equal(item.sandbox_validation_status, 'In Progress');
});

test('Branch Checkin grace does not suppress explicit current delivery risk', () => {
  const ticket = baseTicket({
    ticket_id: 'branch-transition-risk',
    type: 'Bug',
    state: 'Branch Checkin',
    priority: 3,
    state_change_date: '2026-07-13',
    expected_delivery_date: '2026-07-13',
    today_code: '500_01',
    today_note: '',
    prev_code: '400_01',
  });
  const source = sourceClassification(ticket.ticket_id, {
    category: 'Needs PM Escalation',
    sub_tags: ['Release Risk'],
  });
  const item = classify(ticket, source).classifications[0];

  assert.equal(item.category, 'Needs PM Escalation');
  assert.equal(item.sub_tags.includes('Release Risk'), true);
  assert.equal(item.sub_tags.includes('Missing Notes'), true);
  assert.equal(item.sub_tags.includes('Sandbox Validation'), true);
});

test('Sandbox pass in Branch Checkin recommends the type-specific next state', () => {
  for (const [type, target, noun] of [
    ['Bug', 'Resolved', 'Bug'],
    ['Product Backlog Item', 'Ready for QA', 'PBI'],
  ]) {
    const ticket = baseTicket({
      ticket_id: `sandbox-passed-${type}`,
      type,
      state: 'Branch Checkin',
      priority: 3,
      state_change_date: '2026-07-10',
      expected_delivery_date: '2026-07-20',
      today_code: '500_01',
      today_note: 'Sandbox validation passed successfully; ready for handoff.',
      prev_code: '500_01',
      prev_note: 'Sandbox validation was in progress.',
    });
    const source = sourceClassification(ticket.ticket_id, {
      category: 'On Track',
      sub_tags: ['Normal Progress'],
      sandbox_validation_status: 'Passed',
      sandbox_validation_evidence: 'Sandbox validation passed successfully',
    });
    const item = classify(ticket, source).classifications[0];

    assert.equal(item.category, 'Needs Team Lead Clarification');
    assert.equal(item.progress_code_issue_type, 'tfs_state_may_need_advancement');
    assert.equal(item.state_advancement_target, target);
    assert.equal(
      item.state_advancement_action,
      `Advance the ${noun} from Branch Checkin to ${target}.`,
    );
    assert.equal(item.sandbox_validation_status, 'Passed');
    assert.match(item.reason, /Sandbox validation passed/);
    assert.equal(item.recommended_action, item.state_advancement_action);
  }
});

test('Sandbox advancement rejects prior, fabricated, or non-pass evidence', () => {
  const ticket = baseTicket({
    ticket_id: 'sandbox-unverified-pass',
    type: 'Bug',
    state: 'Branch Checkin',
    priority: 3,
    state_change_date: '2026-07-10',
    expected_delivery_date: '2026-07-20',
    today_code: '500_01',
    today_note: 'Sandbox validation remains in progress.',
    prev_code: '500_01',
    prev_note: 'Sandbox validation passed yesterday.',
  });
  const source = sourceClassification(ticket.ticket_id, {
    category: 'On Track',
    sub_tags: ['Normal Progress'],
    sandbox_validation_status: 'Passed',
    sandbox_validation_evidence: 'Sandbox validation passed yesterday',
  });
  const item = classify(ticket, source).classifications[0];

  assert.equal(item.category, 'On Track');
  assert.equal(item.sandbox_validation_status, 'Unknown');
  assert.equal(item.sandbox_validation_evidence, '');
  assert.equal(item.progress_code_issue_type, null);
  assert.equal(
    item.sub_tags.includes('Wrong or Mismatched Progress Code'),
    false,
  );
});

test('noncanonical Branch Check-in spelling is not treated as Branch Checkin', () => {
  const ticket = baseTicket({
    ticket_id: '187115',
    type: 'Product Backlog Item',
    state: 'Branch Check-in',
    today_code: '500_01',
    today_note: '',
    prev_code: '400_01',
  });

  const result = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'On Track',
    sub_tags: ['Normal Progress'],
  }));
  const item = result.classifications[0];

  assert.equal(item.category, 'Needs Team Lead Clarification');
  assert.equal(item.sub_tags.includes('Ready for Release'), false);
  assert.equal(item.sub_tags.includes('Missing Notes'), true);
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
    assert.equal(item.delivery_date_status, 'development_complete');
    assert.equal(result.pm_escalation_items.length, 0);
  }
});

test('New, Approved, and Done use authoritative state-specific tags', () => {
  const cases = [
    {
      state: 'New',
      expectedTag: 'New',
      expectedReason: 'The ticket is New and active development has not started.',
    },
    {
      state: 'Approved',
      expectedTag: 'Pending Development',
      expectedReason: 'The ticket is Approved and pending development.',
    },
    {
      state: 'Done',
      expectedTag: 'Done',
      expectedReason: 'The ticket is Done in TFS; no QA or production release status is inferred.',
    },
  ];

  for (const { state, expectedTag, expectedReason } of cases) {
    const ticket = baseTicket({
      ticket_id: `state-tag-${state}`,
      state,
      today_code: '',
      today_note: '',
      has_today_update: false,
    });
    const source = sourceClassification(ticket.ticket_id, {
      category: 'Needs PM Escalation',
      sub_tags: ['Ready for Release', 'Ready for QA', 'Possible Risk'],
    });

    const item = classify(ticket, source).classifications[0];

    assert.equal(item.category, 'On Track');
    assert.equal(item.sub_tags.includes(expectedTag), true);
    assert.equal(item.sub_tags.includes('Ready for Release'), false);
    assert.equal(item.sub_tags.includes('Ready for QA'), false);
    assert.equal(item.sub_tags.includes('Possible Risk'), false);
    assert.equal(item.reason, expectedReason);
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
  assert.equal(item.developer_email, 'dev@example.com');
  assert.equal(result.tl_review_items.length, 1);
  assert.equal(result.tl_review_items[0].developer_email, 'dev@example.com');
  assert.equal(result.tl_review_items[0].title, 'Ticket under review');
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
  assert.equal(result.pm_escalation_items[0].developer_email, 'dev@example.com');
  assert.equal(result.pm_escalation_items[0].title, 'Ticket under review');
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
      state_change_date: '2026-07-13',
      expected_delivery_date: '2026-07-20',
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
  assert.equal(result.validation.sub_tag_sandbox_validation, 1);
  assert.equal(result.tl_review_items.length, 1);
  assert.equal(result.pm_escalation_items.length, 1);
  assert.equal(result.exceptions.needs_tl_clarification.length, 1);
  assert.equal(result.exceptions.needs_pm_escalation.length, 1);
});

test('status families returning to active progress are not backward movement', () => {
  for (const previousFamily of ['600', '700', '800']) {
    for (const currentFamily of ['100', '200', '300']) {
      const ticket = baseTicket({
        ticket_id: `${previousFamily}-${currentFamily}`,
        priority: 3,
        today_code: `${currentFamily}_01`,
        today_note: 'Work has resumed in the active delivery flow.',
        prev_code: `${previousFamily}_01`,
        prev_note: 'Exception status was being assessed.',
      });
      const source = sourceClassification(ticket.ticket_id, {
        category: 'Needs Team Lead Clarification',
        sub_tags: ['Wrong or Mismatched Progress Code'],
        reason: 'The numeric code family moved backward.',
      });

      const item = classify(ticket, source).classifications[0];

      assert.equal(item.category, 'On Track');
      assert.equal(
        item.sub_tags.includes('Wrong or Mismatched Progress Code'),
        false,
      );
      assert.equal(item.progress_code_issue_type, null);
    }
  }
});

test('400_xx and 500_xx moving to compatible active progress become a workflow-return signal', () => {
  for (const previousFamily of ['400', '500']) {
    for (const currentFamily of ['200', '300']) {
      const ticket = baseTicket({
        ticket_id: `${previousFamily}-${currentFamily}`,
        state: 'In Development',
        expected_delivery_date: '2026-07-20',
        priority: 3,
        today_code: `${currentFamily}_01`,
        today_note: 'Returned to active implementation.',
        prev_code: `${previousFamily}_01`,
        prev_note: 'Work had reached review or completion.',
      });
      const source = sourceClassification(ticket.ticket_id, {
        category: 'On Track',
        sub_tags: ['Normal Progress'],
      });

      const result = classify(ticket, source);
      const item = result.classifications[0];

      assert.equal(item.category, 'Needs Team Lead Clarification');
      assert.equal(
        item.sub_tags.includes('Wrong or Mismatched Progress Code'),
        false,
      );
      assert.equal(
        item.sub_tags.includes('Returned to Active Development'),
        true,
      );
      assert.equal(
        item.progress_code_issue_type,
        'returned_to_active_development',
      );
      assert.match(item.reason, /^Returned to Active Development:/);
      assert.match(item.recommended_action, /Team Lead should confirm why/);
      assert.equal(standupDeveloperCorrectionItems([item]).length, 0);
      assert.equal(result.tl_review_items.length, 1);
      assert.match(result.tl_review_items[0].why_tl_needed, /returned from review or handoff/);
    }
  }
});

test('backward active-family movement that conflicts with the current state remains a correction', () => {
  const ticket = baseTicket({
    ticket_id: '500-200-code-review',
    state: 'Code Review',
    priority: 3,
    today_code: '200_04',
    today_note: 'Returned to active implementation.',
    prev_code: '500_01',
    prev_note: 'Work had reached completion or handoff.',
  });

  const item = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'On Track',
    sub_tags: ['Normal Progress'],
  })).classifications[0];

  assert.equal(item.category, 'Needs Team Lead Clarification');
  assert.equal(
    item.sub_tags.includes('Wrong or Mismatched Progress Code'),
    true,
  );
  assert.equal(
    item.sub_tags.includes('Returned to Active Development'),
    false,
  );
  assert.equal(item.progress_code_issue_type, 'state_code_mismatch');
  assert.equal(standupDeveloperCorrectionItems([item]).length, 1);
});

test('217803-style return keeps overdue PM visibility without creating a developer correction', () => {
  const ticket = baseTicket({
    ticket_id: '217803',
    type: 'Product Backlog Item',
    state: 'In Development',
    priority: 2,
    review_date: '2026-08-18',
    previous_workday_date: '2026-08-17',
    expected_delivery_date: '2026-07-24',
    today_code: '200_04',
    today_note: 'development @ 80%',
    prev_code: '500_01',
    prev_note: 'checked in sandbox for nextgen testing/consumption',
    prev_date: '2026-07-28',
  });
  const result = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'On Track',
    sub_tags: ['Normal Progress'],
  }));
  const item = result.classifications[0];

  assert.equal(item.category, 'Needs PM Escalation');
  assert.equal(item.progress_code_issue_type, 'returned_to_active_development');
  assert.equal(item.sub_tags.includes('Returned to Active Development'), true);
  assert.equal(
    item.sub_tags.includes('Wrong or Mismatched Progress Code'),
    false,
  );
  assert.equal(item.sub_tags.includes('Expected Delivery Overdue'), true);
  assert.equal(item.sub_tags.includes('Delivery Risk'), true);
  assert.equal(standupDeveloperCorrectionItems([item]).length, 0);
  assert.equal(buildStandupCorrectionState({
    classifications: [item],
    reviewDate: ticket.review_date,
  }).active.length, 0);
  assert.equal(result.pm_escalation_items.length, 1);
  assert.equal(result.tl_review_items.length, 1);
  assert.match(item.recommended_action, /PM should confirm the owner/);
  assert.match(item.recommended_action, /Team Lead should confirm why/);
});

test('allowed status transition still flags an independent TFS state mismatch', () => {
  const ticket = baseTicket({
    ticket_id: 'status-to-code-review-mismatch',
    state: 'Code Review',
    priority: 3,
    expected_delivery_date: '2026-07-20',
    today_code: '200_01',
    today_note: 'Implementation resumed after investigation.',
    prev_code: '700_01',
    prev_note: 'Investigating the reported behavior.',
  });
  const source = sourceClassification(ticket.ticket_id, {
    category: 'On Track',
    sub_tags: ['Wrong or Mismatched Progress Code'],
  });

  const item = classify(ticket, source).classifications[0];

  assert.equal(item.category, 'Needs Team Lead Clarification');
  assert.equal(
    item.sub_tags.includes('Wrong or Mismatched Progress Code'),
    true,
  );
  assert.equal(item.progress_code_issue_type, 'state_code_mismatch');
});

test('AI mismatch tag is removed unless deterministic validation re-adds it', () => {
  const neutralTicket = baseTicket({
    ticket_id: 'ai-only-mismatch',
    priority: 3,
    today_code: '200_01',
    today_note: 'Implemented the next step.',
    prev_code: '200_01',
    prev_note: 'Prepared the prior step.',
  });
  const neutralSource = sourceClassification(neutralTicket.ticket_id, {
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Wrong or Mismatched Progress Code'],
    reason: 'AI supplied a mismatch without deterministic evidence.',
  });

  const neutralItem = classify(neutralTicket, neutralSource).classifications[0];

  assert.equal(neutralItem.category, 'On Track');
  assert.equal(
    neutralItem.sub_tags.includes('Wrong or Mismatched Progress Code'),
    false,
  );
  assert.equal(neutralItem.progress_code_issue_type, null);
  assert.equal(
    neutralItem.reason,
    'No deterministic progress-code mismatch was identified.',
  );
  assert.equal(
    neutralItem.recommended_action,
    'No action needed beyond normal standup review.',
  );

  const independentlyActionable = classify(
    {
      ...neutralTicket,
      ticket_id: 'ai-mismatch-with-vague-update',
      today_note: 'Working on it.',
    },
    sourceClassification('ai-mismatch-with-vague-update', {
      category: 'Needs Team Lead Clarification',
      sub_tags: ['Wrong or Mismatched Progress Code', 'Vague Update'],
      reason: 'The update is independently too vague.',
    }),
  ).classifications[0];

  assert.equal(independentlyActionable.category, 'Needs Team Lead Clarification');
  assert.equal(independentlyActionable.sub_tags.includes('Vague Update'), true);
  assert.equal(
    independentlyActionable.sub_tags.includes('Wrong or Mismatched Progress Code'),
    false,
  );
});

test('clearly sufficient updates veto AI vague tags without suppressing overdue policy', () => {
  const sharedNote = 'No progress was made yesterday as the NextGen SupplyBay tickets were prioritized for the build release. Will continue debugging and testing today.';

  for (const ticketId of ['219314', '219315']) {
    const ticket = baseTicket({
      ticket_id: ticketId,
      title: 'SupplyMobile MAUI login hierarchy defect',
      state: 'In Development',
      priority: 3,
      severity: '3 - Medium',
      review_date: '2026-08-19',
      previous_workday_date: '2026-08-18',
      expected_delivery_date: '2026-08-04',
      today_code: '300_02',
      today_note: sharedNote,
      prev_code: '300_02',
      prev_note: 'Currently testing the bug fixes in the local environment.',
      prev_date: '2026-08-18',
    });
    const result = classify(ticket, sourceClassification(ticket.ticket_id, {
      category: 'Needs Team Lead Clarification',
      sub_tags: ['Vague Update'],
      reason: 'The next step is too vague.',
      recommended_action: 'Clarify the update.',
    }));
    const item = result.classifications[0];

    assert.equal(item.category, 'Needs PM Escalation');
    assert.equal(item.sub_tags.includes('Vague Update'), false);
    assert.equal(item.sub_tags.includes('No Movement'), false);
    assert.equal(item.sub_tags.includes('Expected Delivery Overdue'), true);
    assert.equal(item.sub_tags.includes('Delivery Risk'), true);
    assert.match(item.reason, /Expected Delivery 2026-08-04 has passed/);
    assert.equal(standupDeveloperCorrectionItems([item]).length, 0);
    assert.equal(buildStandupCorrectionState({
      classifications: [item],
      reviewDate: ticket.review_date,
    }).active.length, 0);
    assert.equal(result.pm_escalation_items.length, 1);
  }
});

test('clear no-progress and ongoing-work notes remove vague-only clarification', () => {
  const cases = [
    {
      id: 'sufficient-no-progress',
      note: 'No progress was made because build-release work was prioritized. Will resume debugging today.',
    },
    {
      id: 'sufficient-ongoing-test',
      note: 'Currently testing the bug fixes in the local environment.',
    },
  ];

  for (const candidate of cases) {
    const ticket = baseTicket({
      ticket_id: candidate.id,
      state: 'In Development',
      priority: 3,
      expected_delivery_date: '2026-07-20',
      today_code: '300_02',
      today_note: candidate.note,
      prev_code: '300_02',
      prev_note: 'Investigating the reported issue.',
    });
    const item = classify(ticket, sourceClassification(ticket.ticket_id, {
      category: 'Needs Team Lead Clarification',
      sub_tags: ['Vague Update'],
      reason: 'The update is too vague.',
    })).classifications[0];

    assert.equal(item.category, 'On Track');
    assert.equal(item.sub_tags.includes('Vague Update'), false);
    assert.equal(standupDeveloperCorrectionItems([item]).length, 0);
  }
});

test('genuinely vague notes remain Team Lead-first developer corrections', () => {
  for (const [ticketId, note] of [
    ['vague-working-on-it', 'Working on it.'],
    ['vague-no-progress', 'No progress yesterday.'],
    ['vague-will-continue', 'Will continue.'],
  ]) {
    const ticket = baseTicket({
      ticket_id: ticketId,
      state: 'In Development',
      priority: 3,
      expected_delivery_date: '2026-07-20',
      today_code: '300_02',
      today_note: note,
      prev_code: '300_01',
      prev_note: 'Testing the reported defect.',
    });
    const item = classify(ticket, sourceClassification(ticket.ticket_id, {
      category: 'On Track',
      sub_tags: ['Normal Progress', 'Vague Update'],
      reason: 'Required update detail is absent.',
    })).classifications[0];

    assert.equal(item.category, 'Needs Team Lead Clarification');
    assert.equal(item.sub_tags.includes('Vague Update'), true);
    assert.equal(item.sub_tags.includes('Normal Progress'), false);
    assert.equal(standupDeveloperCorrectionItems([item]).length, 1);
  }
});

test('specific missing-update corrections supersede an AI vague tag', () => {
  const ticket = baseTicket({
    ticket_id: 'blank-note-not-vague',
    state: 'In Development',
    priority: 3,
    expected_delivery_date: '2026-07-20',
    today_code: '300_02',
    today_note: '   ',
  });
  const item = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Missing Notes', 'Vague Update'],
  })).classifications[0];

  assert.equal(item.sub_tags.includes('Missing Notes'), true);
  assert.equal(item.sub_tags.includes('Vague Update'), false);
  assert.deepEqual(
    standupDeveloperCorrectionItems([item]).map((correction) => correction.issue),
    ['Missing Notes'],
  );
});

test('v21 update quality starts a v2 correction policy with aligned wording', () => {
  const display = standupCorrectionDisplay('Vague Update');

  assert.equal(STANDUP_ESCALATION_POLICY_VERSION, 'standup_escalation_v2');
  assert.equal(
    display.action,
    'Clarify the current status and next executable step. When reporting no progress, delay, or a blocker, include the reason.',
  );
});

test('Re-Opened 500_xx accepts any nonblank same-day developer note', () => {
  const ticket = baseTicket({
    ticket_id: 'reopened-supported-completion',
    state: 'Re-Opened',
    priority: 3,
    expected_delivery_date: '2026-07-20',
    today_code: '500_01',
    today_note: 'Fix completed and returned for QA verification.',
    prev_code: '700_01',
    prev_note: 'Investigating the reopened defect.',
  });
  const source = sourceClassification(ticket.ticket_id, {
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Wrong or Mismatched Progress Code'],
    reason: 'Re-Opened and completion code do not align.',
  });

  const item = classify(ticket, source).classifications[0];

  assert.equal(item.category, 'On Track');
  assert.equal(
    item.sub_tags.includes('Wrong or Mismatched Progress Code'),
    false,
  );
  assert.equal(item.progress_code_issue_type, null);
});

test('Re-Opened 500_xx with whitespace-only notes keeps generic mismatch handling', () => {
  const ticket = baseTicket({
    ticket_id: 'reopened-unsupported-completion',
    state: 'Re-Opened',
    priority: 3,
    expected_delivery_date: '2026-07-20',
    today_code: '500_01',
    today_note: '   ',
    prev_code: '700_01',
    prev_note: 'Investigating the reopened defect.',
  });
  const source = sourceClassification(ticket.ticket_id, {
    category: 'On Track',
    sub_tags: ['Normal Progress'],
  });

  const item = classify(ticket, source).classifications[0];

  assert.equal(item.category, 'Needs Team Lead Clarification');
  assert.equal(item.sub_tags.includes('Missing Notes'), true);
  assert.equal(
    item.sub_tags.includes('Wrong or Mismatched Progress Code'),
    true,
  );
  assert.equal(item.progress_code_issue_type, 'state_code_mismatch');
  assert.match(item.reason, /current Re-Opened TFS state/);
  assert.doesNotMatch(item.reason, /TFS State May Need Advancement/);
});

test('active-state 500_xx uses state-advancement display metadata', () => {
  for (const state of ['In Development', 'Code Review']) {
    const ticket = baseTicket({
      ticket_id: `advancement-${state}`,
      state,
      priority: 3,
      today_code: '500_01',
      today_note: 'Development is complete and ready for handoff.',
      prev_code: '400_01',
      prev_note: 'Awaiting final review.',
    });
    const source = sourceClassification(ticket.ticket_id, {
      category: 'On Track',
      sub_tags: ['Normal Progress'],
    });

    const item = classify(ticket, source).classifications[0];

    assert.equal(item.category, 'Needs Team Lead Clarification');
    assert.equal(
      item.sub_tags.includes('Wrong or Mismatched Progress Code'),
      true,
    );
    assert.equal(
      item.progress_code_issue_type,
      'tfs_state_may_need_advancement',
    );
    assert.match(item.reason, /^TFS State May Need Advancement:/);
    assert.equal(
      item.recommended_action,
      'Confirm the completion or handoff and advance the TFS state; if work is still active, correct the progress code.',
    );
  }
});

test('state-advancement display preserves the stable correction key and streak', () => {
  const item = {
    ticket_id: 'advancement-streak',
    title: 'Completed work in an active state',
    developer: 'Developer',
    developer_email: 'dev@example.com',
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Wrong or Mismatched Progress Code'],
    progress_code_issue_type: 'tfs_state_may_need_advancement',
    reason: 'TFS State May Need Advancement.',
    recommended_action: 'Advance the TFS state.',
  };
  const day1 = buildStandupCorrectionState({
    classifications: [item],
    reviewDate: '2026-08-17',
  });
  const day2 = buildStandupCorrectionState({
    classifications: [item],
    reviewDate: '2026-08-18',
    previousObservations: day1.active.map((observation) => ({
      ...observation,
      review_date: '2026-08-17',
    })),
  });

  assert.equal(day2.active[0].correction_key, 'Wrong or Mismatched Progress Code');
  assert.equal(day2.active[0].streak_count, 2);

  const overlay = applyStandupEscalationOverlay({
    classifications: [item],
    tl_review_items: [],
    pm_escalation_items: [],
    validation: { total_reviewed: 1 },
  }, day2.active);
  assert.equal(
    overlay.classifications[0].escalation.corrections[0].key,
    'Wrong or Mismatched Progress Code',
  );
  assert.equal(
    overlay.classifications[0].escalation.corrections[0].label,
    'TFS State May Need Advancement',
  );
  assert.match(overlay.pm_watch_items[0].issue, /TFS State May Need Advancement/);
});

test('developer notification uses advancement wording with legacy fallback', () => {
  const advancement = {
    ticket_id: 'advancement-email',
    title: 'Completed work in an active state',
    developer: 'Developer',
    developer_email: 'dev@example.com',
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Wrong or Mismatched Progress Code'],
    progress_code_issue_type: 'tfs_state_may_need_advancement',
  };
  const [item] = standupDeveloperCorrectionItems([advancement]);
  assert.equal(item.issue, 'TFS State May Need Advancement');
  assert.match(item.action, /advance the TFS state/);

  const routed = routeStandupNotifications({
    audience: 'dev',
    review: { classifications: [advancement] },
    users: [{
      email: 'dev@example.com',
      name: 'Developer',
      role: 'dev',
      team: 'Alpha',
      email_verified: true,
    }],
  });
  const rendered = renderStandupNotificationEmail({
    audience: 'dev',
    date: '2026-08-18',
    delivery: routed.deliveries[0],
    appUrl: 'https://example.com',
  });
  assert.match(rendered.html, /TFS State May Need Advancement/);
  assert.doesNotMatch(rendered.html, /why_tl_needed|Recommended PM|delivery risk/i);

  const legacy = standupCorrectionDisplay(
    'Wrong or Mismatched Progress Code',
    {},
  );
  assert.equal(legacy.label, 'Wrong or Mismatched Progress Code');
  assert.match(legacy.action, /Align the progress code/);
});

test('developer notification uses the type-specific Sandbox advancement action', () => {
  const advancement = {
    ticket_id: 'sandbox-advancement-email',
    title: 'Sandbox passed Bug',
    developer: 'Developer',
    developer_email: 'dev@example.com',
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Wrong or Mismatched Progress Code'],
    progress_code_issue_type: 'tfs_state_may_need_advancement',
    state_advancement_target: 'Resolved',
    state_advancement_action: 'Advance the Bug from Branch Checkin to Resolved.',
  };
  const [item] = standupDeveloperCorrectionItems([advancement]);

  assert.equal(item.issue, 'TFS State May Need Advancement');
  assert.equal(item.action, advancement.state_advancement_action);
});

test('v21 representative records match the intended policy outcomes', () => {
  const resumed = baseTicket({
    ticket_id: '222114',
    state: 'Committed',
    priority: 3,
    review_date: '2026-08-17',
    today_code: '200_01',
    today_note: 'Currently implementing the fix after investigation.',
    prev_code: '700_01',
    prev_note: 'Investigating the reported issue.',
    prev_date: '2026-08-14',
  });
  const resumedItem = classify(resumed, sourceClassification(resumed.ticket_id, {
    category: 'Needs Team Lead Clarification',
    sub_tags: ['Wrong or Mismatched Progress Code'],
  })).classifications[0];
  assert.equal(resumedItem.category, 'On Track');
  assert.equal(resumedItem.progress_code_issue_type, null);

  const completed = baseTicket({
    ticket_id: '222160',
    state: 'In Development',
    priority: 3,
    review_date: '2026-08-17',
    today_code: '500_01',
    today_note: 'QA and production are patched.',
    prev_code: '200_01',
    prev_note: 'Preparing the change for review.',
    prev_date: '2026-08-14',
  });
  const completedItem = classify(completed, sourceClassification(
    completed.ticket_id,
    { category: 'On Track', sub_tags: ['Normal Progress'] },
  )).classifications[0];
  assert.equal(
    completedItem.progress_code_issue_type,
    'tfs_state_may_need_advancement',
  );
  assert.equal(completedItem.delivery_date_status, 'missing_required');
  assert.equal(
    completedItem.sub_tags.includes('Expected Delivery Missing'),
    true,
  );
  assert.match(completedItem.reason, /^TFS State May Need Advancement:/);

  const regressed = baseTicket({
    ticket_id: '208080',
    state: 'In Development',
    priority: 3,
    review_date: '2026-08-17',
    expected_delivery_date: '2026-08-21',
    today_code: '200_04',
    today_note: 'Refactoring for the revised ticket requirement.',
    prev_code: '400_02',
    prev_note: 'Requirement revision returned the ticket to development.',
    prev_date: '2026-08-14',
  });
  const regressedItem = classify(regressed, sourceClassification(
    regressed.ticket_id,
    { category: 'On Track', sub_tags: ['Normal Progress'] },
  )).classifications[0];
  assert.equal(
    regressedItem.progress_code_issue_type,
    'returned_to_active_development',
  );
  assert.equal(
    regressedItem.sub_tags.includes('Wrong or Mismatched Progress Code'),
    false,
  );
  assert.equal(
    regressedItem.sub_tags.includes('Returned to Active Development'),
    true,
  );
});

test('On-Hold is a managed pause for missing updates and overdue delivery', () => {
  const ticket = baseTicket({
    ticket_id: '207882-on-hold',
    type: 'Product Backlog Item',
    state: 'On-Hold',
    priority: 2,
    review_date: '2026-08-18',
    previous_workday_date: '2026-08-17',
    expected_delivery_date: '2026-07-21',
    today_code: null,
    today_note: null,
    prev_code: '800_03',
    prev_note: 'awaiting resolution from ENT - Pag Usage revision (PBI 208080)',
    prev_date: '2026-08-17',
    has_today_update: false,
  });
  const result = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'Needs PM Escalation',
    sub_tags: [
      'No Daily Update',
      'Expected Delivery Overdue',
      'Possible Risk',
      'Delivery Risk',
    ],
  }));
  const item = result.classifications[0];

  assert.equal(item.category, 'On Track');
  assert.equal(item.current_code, '800_03');
  assert.equal(item.delivery_date_status, 'paused');
  assert.equal(item.working_days_to_expected_delivery, null);
  assert.deepEqual(item.sub_tags, ['On Hold']);
  assert.equal(result.exceptions.missing_updates.length, 0);
  assert.equal(result.exceptions.delayed_at_risk.length, 0);
  assert.equal(result.pm_escalation_items.length, 0);
});

test('On-Hold 800_xx alone does not escalate or create delayed diagnostics', () => {
  const ticket = baseTicket({
    ticket_id: 'on-hold-800',
    state: 'On-Hold',
    priority: 2,
    expected_delivery_date: '2026-07-01',
    today_code: '800_03',
    today_note: 'Awaiting the existing hold decision.',
    prev_code: '800_03',
    prev_note: 'Awaiting the existing hold decision.',
  });
  const result = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'Needs PM Escalation',
    sub_tags: ['Delayed', 'Waiting for Decision'],
  }));
  const item = result.classifications[0];

  assert.equal(item.category, 'On Track');
  assert.equal(item.delivery_date_status, 'paused');
  assert.deepEqual(item.sub_tags, ['On Hold']);
  assert.equal(result.exceptions.delayed_at_risk.length, 0);
  assert.equal(result.pm_escalation_items.length, 0);
});

test('On-Hold still escalates explicit material current risk', () => {
  const ticket = baseTicket({
    ticket_id: 'on-hold-release-risk',
    state: 'On-Hold',
    priority: 3,
    expected_delivery_date: '2026-07-01',
    today_code: '800_03',
    today_note: 'The ENT dependency now puts the committed release at risk.',
    prev_code: '800_03',
    prev_note: 'Waiting for ENT.',
  });
  const result = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'Needs PM Escalation',
    sub_tags: ['Cross-Team Dependency', 'Release Risk'],
    reason: 'The current cross-team dependency puts the release at risk.',
  }));
  const item = result.classifications[0];

  assert.equal(item.category, 'Needs PM Escalation');
  assert.equal(item.delivery_date_status, 'paused');
  assert.ok(item.sub_tags.includes('On Hold'));
  assert.ok(item.sub_tags.includes('Cross-Team Dependency'));
  assert.ok(item.sub_tags.includes('Release Risk'));
  assert.equal(item.sub_tags.includes('Expected Delivery Overdue'), false);
  assert.equal(result.pm_escalation_items.length, 1);
});

test('leaving On-Hold restores active delivery validation', () => {
  const ticket = baseTicket({
    ticket_id: 'resumed-after-hold',
    state: 'In Development',
    priority: 3,
    review_date: '2026-08-18',
    previous_workday_date: '2026-08-17',
    expected_delivery_date: '2026-07-21',
    today_code: '200_01',
    today_note: 'Development resumed after the hold was cleared.',
    prev_code: '800_03',
    prev_note: 'The ticket was waiting on a dependency.',
  });
  const result = classify(ticket, sourceClassification(ticket.ticket_id, {
    category: 'On Track',
    sub_tags: ['Normal Progress'],
  }));
  const item = result.classifications[0];

  assert.equal(item.delivery_date_status, 'overdue');
  assert.ok(item.sub_tags.includes('Expected Delivery Overdue'));
  assert.equal(item.sub_tags.includes('On Hold'), false);
  assert.equal(item.category, 'Needs PM Escalation');
  assert.equal(result.pm_escalation_items.length, 1);
});
