import crypto from 'node:crypto';

export const STANDUP_NOTIFICATION_SCHEMA_SQL = `
create table if not exists standup_review_notification_deliveries (
  id              bigserial primary key,
  review_date     date not null,
  prompt_version  text not null,
  input_hash      text not null,
  audience        text not null,
  recipient_email text not null,
  route           text not null,
  content_hash    text not null,
  status          text not null default 'sending',
  attempts        integer not null default 1,
  last_error_code text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  sent_at         timestamptz
);

create unique index if not exists standup_review_notification_delivery_key
  on standup_review_notification_deliveries
  (review_date, prompt_version, audience, lower(recipient_email), content_hash);
`;

const DEVELOPER_CORRECTION_ACTIONS = [
  ['No Daily Update', "Submit today's progress update with the current code, completed work, blocker status, and next step."],
  ['Missing Progress Code', 'Select the progress code that matches the work currently being performed.'],
  ['Missing Notes', 'Add a concise note describing progress, blockers, and the next step.'],
  ['Vague Update', 'Clarify what changed, what remains, and the next concrete step.'],
  ['Wrong or Mismatched Progress Code', 'Align the progress code with the current TFS workflow state, or ask your lead to confirm the correct state.'],
  ['Expected Delivery Missing', 'Set the Expected Delivery date in TFS for development completion.'],
  ['Reforecast Needs Rationale', 'Update today\'s note with the reason for the later forecast and its delivery impact.'],
];

function text(value) {
  return String(value ?? '').trim();
}

export function normalizeStandupNotificationEmail(value) {
  return text(value).toLowerCase();
}

function normalizeTeam(value) {
  return text(value).toLowerCase();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function ticketCompare(a, b) {
  const aId = text(a?.ticket_id);
  const bId = text(b?.ticket_id);
  const aNumber = /^\d+$/.test(aId) ? Number(aId) : Number.NaN;
  const bNumber = /^\d+$/.test(bId) ? Number(bId) : Number.NaN;
  if (Number.isFinite(aNumber) && Number.isFinite(bNumber)) {
    return aNumber - bNumber;
  }
  return aId.localeCompare(bId);
}

function uniqueItems(items) {
  const byTicket = new Map();
  for (const item of Array.isArray(items) ? items : []) {
    const id = text(item?.ticket_id);
    if (id && !byTicket.has(id)) byTicket.set(id, item);
  }
  return Array.from(byTicket.values()).sort(ticketCompare);
}

function classificationMap(review) {
  return new Map(
    (Array.isArray(review?.classifications) ? review.classifications : [])
      .map((item) => [text(item?.ticket_id), item])
      .filter(([id]) => id),
  );
}

function enrichItem(item, classifications) {
  const classification = classifications.get(text(item?.ticket_id)) || {};
  return {
    ...item,
    title: text(item?.title) || text(classification.title),
    developer: text(item?.developer) || text(classification.developer),
    developer_email:
      normalizeStandupNotificationEmail(item?.developer_email) ||
      normalizeStandupNotificationEmail(classification.developer_email),
  };
}

export function standupDeveloperCorrectionItems(classifications) {
  const items = [];
  for (const classification of Array.isArray(classifications)
    ? classifications
    : []) {
    const tags = new Set(
      (Array.isArray(classification?.sub_tags)
        ? classification.sub_tags
        : []
      ).map(text),
    );
    const corrections = DEVELOPER_CORRECTION_ACTIONS.filter(([tag]) =>
      tags.has(tag),
    );
    if (!corrections.length) continue;
    items.push({
      ticket_id: text(classification.ticket_id),
      title: text(classification.title),
      developer: text(classification.developer),
      developer_email: normalizeStandupNotificationEmail(
        classification.developer_email,
      ),
      issue: corrections.map(([tag]) => tag).join('; '),
      action: corrections.map(([, action]) => action).join(' '),
    });
  }
  return uniqueItems(items);
}

export function countStandupDeveloperCorrections(classifications) {
  return standupDeveloperCorrectionItems(classifications).length;
}

function eligibleUsers(users, role) {
  return (Array.isArray(users) ? users : [])
    .filter(
      (user) =>
        text(user?.role).toLowerCase() === role &&
        user?.email_verified === true &&
        normalizeStandupNotificationEmail(user?.email),
    )
    .map((user) => ({
      ...user,
      email: normalizeStandupNotificationEmail(user.email),
      team: normalizeTeam(user.team),
    }));
}

function groupDelivery(groups, user, route, item) {
  const key = `${route}|${user.email}`;
  if (!groups.has(key)) {
    groups.set(key, {
      recipient_email: user.email,
      recipient_name: text(user.name),
      route,
      team: user.team || '',
      items: [],
    });
  }
  groups.get(key).items.push(item);
}

export function routeStandupNotifications({ audience, review, users }) {
  const normalizedAudience = text(audience).toLowerCase();
  const classifications = classificationMap(review);
  const groups = new Map();
  const unmatched = [];
  const leads = eligibleUsers(users, 'lead');
  const pms = eligibleUsers(users, 'pm');
  const developers = eligibleUsers(users, 'dev');
  const userByEmail = new Map(
    (Array.isArray(users) ? users : []).map((user) => [
      normalizeStandupNotificationEmail(user?.email),
      user,
    ]),
  );

  if (normalizedAudience === 'lead') {
    const leadItems = uniqueItems(
      (Array.isArray(review?.tl_review_items) ? review.tl_review_items : []).map(
        (item) => enrichItem(item, classifications),
      ),
    );
    for (const item of leadItems) {
      const developer = userByEmail.get(item.developer_email);
      const team = normalizeTeam(developer?.team);
      const matchingLeads = team
        ? leads.filter((lead) => lead.team && lead.team === team)
        : [];
      if (matchingLeads.length) {
        for (const lead of matchingLeads) {
          groupDelivery(groups, lead, 'team_lead', item);
        }
      } else if (pms.length) {
        for (const pm of pms) {
          groupDelivery(groups, pm, 'pm_fallback', item);
        }
      } else {
        unmatched.push({
          ticket_id: item.ticket_id,
          reason: 'no_matching_lead_or_pm_fallback',
        });
      }
    }
    return {
      audience: normalizedAudience,
      item_count: leadItems.length,
      deliveries: Array.from(groups.values()).map((delivery) => ({
        ...delivery,
        items: uniqueItems(delivery.items),
      })),
      unmatched,
      no_items: leadItems.length === 0,
    };
  }

  if (normalizedAudience === 'pm') {
    const pmItems = uniqueItems(
      (Array.isArray(review?.pm_escalation_items)
        ? review.pm_escalation_items
        : []
      ).map((item) => enrichItem(item, classifications)),
    );
    if (pmItems.length && !pms.length) {
      unmatched.push(
        ...pmItems.map((item) => ({
          ticket_id: item.ticket_id,
          reason: 'no_verified_pm_recipient',
        })),
      );
    }
    for (const pm of pms) {
      for (const item of pmItems) groupDelivery(groups, pm, 'pm', item);
    }
    return {
      audience: normalizedAudience,
      item_count: pmItems.length,
      deliveries: Array.from(groups.values()).map((delivery) => ({
        ...delivery,
        items: uniqueItems(delivery.items),
      })),
      unmatched,
      no_items: pmItems.length === 0,
    };
  }

  if (normalizedAudience === 'dev') {
    const correctionItems = standupDeveloperCorrectionItems(
      review?.classifications,
    );
    const developerByEmail = new Map(
      developers.map((developer) => [developer.email, developer]),
    );
    for (const item of correctionItems) {
      const developer = developerByEmail.get(item.developer_email);
      if (!developer) {
        unmatched.push({
          ticket_id: item.ticket_id,
          reason: 'no_verified_developer_recipient',
        });
        continue;
      }
      groupDelivery(groups, developer, 'developer', item);
    }
    return {
      audience: normalizedAudience,
      item_count: correctionItems.length,
      deliveries: Array.from(groups.values()).map((delivery) => ({
        ...delivery,
        items: uniqueItems(delivery.items),
      })),
      unmatched,
      no_items: correctionItems.length === 0,
    };
  }

  throw new TypeError('invalid_standup_notification_audience');
}

function canonicalDelivery(delivery) {
  return {
    route: text(delivery?.route),
    recipient_email: normalizeStandupNotificationEmail(
      delivery?.recipient_email,
    ),
    items: uniqueItems(delivery?.items).map((item) => ({
      ticket_id: text(item.ticket_id),
      title: text(item.title),
      developer: text(item.developer),
      developer_email: normalizeStandupNotificationEmail(
        item.developer_email,
      ),
      issue: text(item.issue),
      why_tl_needed: text(item.why_tl_needed),
      suggested_action: text(item.suggested_action),
      evidence: text(item.evidence),
      delivery_risk: text(item.delivery_risk),
      recommended_pm_action: text(item.recommended_pm_action),
      action: text(item.action),
    })),
  };
}

export function standupNotificationContentHash({ audience, date, delivery }) {
  return crypto
    .createHash('sha256')
    .update(
      JSON.stringify({
        audience: text(audience).toLowerCase(),
        date: text(date),
        delivery: canonicalDelivery(delivery),
      }),
    )
    .digest('hex');
}

function emailTable(audience, items) {
  const header =
    audience === 'lead'
      ? '<th>Ticket</th><th>Developer</th><th>Issue</th><th>Why lead review is needed</th><th>Suggested action</th>'
      : audience === 'pm'
        ? '<th>Ticket</th><th>Developer</th><th>Issue</th><th>Evidence</th><th>Delivery risk</th><th>Recommended PM action</th>'
        : '<th>Ticket</th><th>Correction needed</th><th>What to do</th>';
  const rows = uniqueItems(items)
    .map((item) => {
      const ticket = `<strong>#${escapeHtml(item.ticket_id)}</strong>${
        item.title ? `<br><span>${escapeHtml(item.title)}</span>` : ''
      }`;
      if (audience === 'lead') {
        return `<tr><td>${ticket}</td><td>${escapeHtml(item.developer)}</td><td>${escapeHtml(item.issue)}</td><td>${escapeHtml(item.why_tl_needed)}</td><td>${escapeHtml(item.suggested_action)}</td></tr>`;
      }
      if (audience === 'pm') {
        return `<tr><td>${ticket}</td><td>${escapeHtml(item.developer)}</td><td>${escapeHtml(item.issue)}</td><td>${escapeHtml(item.evidence)}</td><td>${escapeHtml(item.delivery_risk)}</td><td>${escapeHtml(item.recommended_pm_action)}</td></tr>`;
      }
      return `<tr><td>${ticket}</td><td>${escapeHtml(item.issue)}</td><td>${escapeHtml(item.action)}</td></tr>`;
    })
    .join('');
  return `<table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr>${header}</tr></thead><tbody>${rows}</tbody></table>`;
}

export function renderStandupNotificationEmail({
  audience,
  date,
  delivery,
  appUrl,
}) {
  const normalizedAudience = text(audience).toLowerCase();
  const items = uniqueItems(delivery?.items);
  const recipientName = text(delivery?.recipient_name);
  const safeDate = escapeHtml(date);
  const route = text(delivery?.route);
  const subject =
    normalizedAudience === 'lead'
      ? `[Standup Review] Team Lead action needed - ${date} (${items.length})`
      : normalizedAudience === 'pm'
        ? `[Standup Review] PM escalation - ${date} (${items.length})`
        : `[Standup Review] Please correct your update - ${date} (${items.length})`;
  const intro =
    normalizedAudience === 'lead'
      ? route === 'pm_fallback'
        ? 'These Team Lead review items had no verified lead assigned to the developer team and were routed to PM as a fallback.'
        : 'These items need Team Lead review before standup.'
      : normalizedAudience === 'pm'
        ? 'These items need PM review for delivery, priority, release, or coordination risk.'
        : 'Please correct the update details below before standup. This message contains only your own update-quality actions.';
  const safeUrl = text(appUrl);
  const link = safeUrl
    ? `<p><a href="${escapeHtml(safeUrl)}" style="display:inline-block;padding:8px 12px;background:#2563eb;color:#fff;text-decoration:none;border-radius:5px">Open TFS Daily Updates</a></p>`
    : '';
  const html = `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1f2937;line-height:1.45"><p>Hi ${escapeHtml(recipientName || 'there')},</p><h2 style="font-size:18px;margin-bottom:4px">Standup AI Review - ${safeDate}</h2><p>${escapeHtml(intro)}</p>${emailTable(normalizedAudience, items)}${link}<p style="font-size:12px;color:#6b7280">This review is AI-generated and advisory. Verify against TFS and direct observations before acting.</p></body></html>`;
  return { subject, html };
}
