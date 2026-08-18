import crypto from 'node:crypto';
import {
  STANDUP_CORRECTION_ACTIONS,
  standupCorrectionDisplay,
} from './standup-review-escalation.js';

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
  claim_expires_at timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  sent_at         timestamptz
);

alter table standup_review_notification_deliveries
  add column if not exists claim_expires_at timestamptz;

create unique index if not exists standup_review_notification_delivery_key
  on standup_review_notification_deliveries
  (review_date, prompt_version, audience, lower(recipient_email), content_hash);

create index if not exists standup_review_notification_claim_lookup
  on standup_review_notification_deliveries (status, claim_expires_at);
`;

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
    const corrections = STANDUP_CORRECTION_ACTIONS
      .filter(([tag]) => tags.has(tag))
      .map(([tag]) => standupCorrectionDisplay(tag, classification));
    if (!corrections.length) continue;
    items.push({
      ticket_id: text(classification.ticket_id),
      title: text(classification.title),
      developer: text(classification.developer),
      developer_email: normalizeStandupNotificationEmail(
        classification.developer_email,
      ),
      issue: corrections.map((correction) => correction.label).join('; '),
      action: corrections.map((correction) => correction.action).join(' '),
    });
  }
  return uniqueItems(items);
}

export function countStandupDeveloperCorrections(classifications) {
  return standupDeveloperCorrectionItems(classifications).length;
}

export function standupNotificationCounts(review) {
  const lead = Array.isArray(review?.tl_review_items)
    ? review.tl_review_items.length
    : 0;
  const pmAction = Array.isArray(review?.pm_escalation_items)
    ? review.pm_escalation_items.length
    : 0;
  const pmWatch = Array.isArray(review?.pm_watch_items)
    ? review.pm_watch_items.length
    : 0;
  return {
    lead,
    pm: pmAction + pmWatch,
    developer: countStandupDeveloperCorrections(review?.classifications),
    pm_action: pmAction,
    pm_watch: pmWatch,
  };
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

function groupDelivery(groups, user, route, item, collection = 'items') {
  const key = `${route}|${user.email}`;
  if (!groups.has(key)) {
    groups.set(key, {
      recipient_email: user.email,
      recipient_name: text(user.name),
      route,
      team: user.team || '',
      items: [],
      watch_items: [],
    });
  }
  groups.get(key)[collection].push(item);
}

function finalizeDeliveries(groups) {
  return Array.from(groups.values()).map((delivery) => ({
    ...delivery,
    items: uniqueItems(delivery.items),
    watch_items: uniqueItems(delivery.watch_items),
  }));
}

export function routeStandupNotifications({ audience, review, users }) {
  const normalizedAudience = text(audience).toLowerCase();
  const classifications = classificationMap(review);
  const groups = new Map();
  const unmatched = [];
  const leads = eligibleUsers(users, 'lead');
  const pms = eligibleUsers(users, 'pm');
  const pmEscalationRecipients = pms.filter((pm) => pm.team !== 'qa');
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
      deliveries: finalizeDeliveries(groups),
      unmatched,
      no_items: leadItems.length === 0,
      action_item_count: leadItems.length,
      watch_item_count: 0,
    };
  }

  if (normalizedAudience === 'pm') {
    const pmItems = uniqueItems(
      (Array.isArray(review?.pm_escalation_items)
        ? review.pm_escalation_items
        : []
      ).map((item) => enrichItem(item, classifications)),
    );
    const pmActionIds = new Set(pmItems.map((item) => text(item.ticket_id)));
    const pmWatchItems = uniqueItems(
      (Array.isArray(review?.pm_watch_items) ? review.pm_watch_items : []).map(
        (item) => enrichItem(item, classifications),
      ),
    ).filter((item) => !pmActionIds.has(text(item.ticket_id)));
    const totalPmItems = uniqueItems([...pmItems, ...pmWatchItems]);
    if (totalPmItems.length && !pmEscalationRecipients.length) {
      unmatched.push(
        ...totalPmItems.map((item) => ({
          ticket_id: item.ticket_id,
          reason: 'no_verified_pm_recipient',
        })),
      );
    }
    for (const pm of pmEscalationRecipients) {
      for (const item of pmItems) groupDelivery(groups, pm, 'pm', item);
      for (const item of pmWatchItems) {
        groupDelivery(groups, pm, 'pm', item, 'watch_items');
      }
    }
    return {
      audience: normalizedAudience,
      item_count: totalPmItems.length,
      action_item_count: pmItems.length,
      watch_item_count: pmWatchItems.length,
      deliveries: finalizeDeliveries(groups),
      unmatched,
      no_items: totalPmItems.length === 0,
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
      deliveries: finalizeDeliveries(groups),
      unmatched,
      no_items: correctionItems.length === 0,
      action_item_count: correctionItems.length,
      watch_item_count: 0,
    };
  }

  throw new TypeError('invalid_standup_notification_audience');
}

function canonicalDelivery(delivery) {
  const canonicalItem = (item) => ({
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
    monitoring_reason: text(item.monitoring_reason),
    lead_action: text(item.lead_action),
    action: text(item.action),
    tier: Number(item.tier) || 0,
    consecutive_review_days: Number(item.consecutive_review_days) || 0,
  });
  return {
    route: text(delivery?.route),
    recipient_email: normalizeStandupNotificationEmail(
      delivery?.recipient_email,
    ),
    items: uniqueItems(delivery?.items).map(canonicalItem),
    watch_items: uniqueItems(delivery?.watch_items).map(canonicalItem),
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
  const headerCellStyle =
    'background:#dbeafe;color:#1e3a5f;border:1px solid #bfdbfe;padding:10px;text-align:left;font-weight:700;vertical-align:top;';
  const bodyCellStyle =
    'border:1px solid #dbe3ee;padding:10px;text-align:left;vertical-align:top;';
  const headerCell = (label) =>
    `<th style="${headerCellStyle}">${label}</th>`;
  const bodyCell = (value) =>
    `<td style="${bodyCellStyle}">${value}</td>`;
  const header =
    audience === 'lead'
      ? [
          'Ticket',
          'Developer',
          'Issue',
          'Why lead review is needed',
          'Suggested action',
        ]
          .map(headerCell)
          .join('')
      : audience === 'pm'
        ? [
            'Ticket',
            'Developer',
            'Issue',
            'Evidence',
            'Delivery risk',
            'Recommended PM action',
          ]
            .map(headerCell)
            .join('')
        : audience === 'pm_watch'
          ? [
              'Ticket',
              'Developer',
              'Correction being monitored',
              'Why it is on watch',
              'Current lead action',
            ]
              .map(headerCell)
              .join('')
        : ['Ticket', 'Correction needed', 'What to do']
            .map(headerCell)
            .join('');
  const rows = uniqueItems(items)
    .map((item) => {
      const ticket = `<strong>#${escapeHtml(item.ticket_id)}</strong>${
        item.title ? `<br><span>${escapeHtml(item.title)}</span>` : ''
      }`;
      if (audience === 'lead') {
        return `<tr>${bodyCell(ticket)}${bodyCell(escapeHtml(item.developer))}${bodyCell(escapeHtml(item.issue))}${bodyCell(escapeHtml(item.why_tl_needed))}${bodyCell(escapeHtml(item.suggested_action))}</tr>`;
      }
      if (audience === 'pm') {
        return `<tr>${bodyCell(ticket)}${bodyCell(escapeHtml(item.developer))}${bodyCell(escapeHtml(item.issue))}${bodyCell(escapeHtml(item.evidence))}${bodyCell(escapeHtml(item.delivery_risk))}${bodyCell(escapeHtml(item.recommended_pm_action))}</tr>`;
      }
      if (audience === 'pm_watch') {
        return `<tr>${bodyCell(ticket)}${bodyCell(escapeHtml(item.developer))}${bodyCell(escapeHtml(item.issue))}${bodyCell(escapeHtml(item.monitoring_reason))}${bodyCell(escapeHtml(item.lead_action))}</tr>`;
      }
      return `<tr>${bodyCell(ticket)}${bodyCell(escapeHtml(item.issue))}${bodyCell(escapeHtml(item.action))}</tr>`;
    })
    .join('');
  return `<table style="width:100%;border-collapse:collapse;border:1px solid #dbe3ee;font-size:13px"><thead><tr>${header}</tr></thead><tbody>${rows}</tbody></table>`;
}

export function renderStandupNotificationEmail({
  audience,
  date,
  delivery,
  appUrl,
}) {
  const normalizedAudience = text(audience).toLowerCase();
  const items = uniqueItems(delivery?.items);
  const watchItems = uniqueItems(delivery?.watch_items);
  const recipientName = text(delivery?.recipient_name);
  const safeDate = escapeHtml(date);
  const route = text(delivery?.route);
  const subject =
    normalizedAudience === 'lead'
      ? `[Standup Review] Team Lead action needed - ${date} (${items.length})`
      : normalizedAudience === 'pm'
        ? `[Standup Review] PM review - ${date} (${items.length} action, ${watchItems.length} watch)`
        : `[Standup Review] Please correct your update - ${date} (${items.length})`;
  const intro =
    normalizedAudience === 'lead'
      ? route === 'pm_fallback'
        ? 'These Team Lead review items had no verified lead assigned to the developer team and were routed to PM as a fallback.'
        : 'These items need Team Lead review before standup.'
      : normalizedAudience === 'pm'
        ? items.length
          ? 'The Action required section contains formal PM escalations. Watch-only items remain owned by Team Leads and do not require PM action unless their risk changes or they persist.'
          : 'These items are for PM monitoring only. They remain assigned to Team Leads and are not formal PM escalations.'
        : 'Please correct the update details below before standup. This message contains only your own update-quality actions.';
  const safeUrl = text(appUrl);
  const link = safeUrl
    ? `<p><a href="${escapeHtml(safeUrl)}" style="display:inline-block;padding:8px 12px;background:#2563eb;color:#fff;text-decoration:none;border-radius:5px">Open TFS Daily Updates</a></p>`
    : '';
  const tables = normalizedAudience === 'pm'
    ? `${items.length ? `<h3 style="font-size:15px;margin:18px 0 7px">Action required (${items.length})</h3>${emailTable('pm', items)}` : ''}${watchItems.length ? `<h3 style="font-size:15px;margin:18px 0 7px">Watch only (${watchItems.length})</h3><p style="font-size:12px;color:#6b7280">These items are being handled at Team Lead level and are shown for monitoring only.</p>${emailTable('pm_watch', watchItems)}` : ''}`
    : emailTable(normalizedAudience, items);
  const html = `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1f2937;line-height:1.45"><p>Hi ${escapeHtml(recipientName || 'there')},</p><h2 style="font-size:18px;margin-bottom:4px">Standup AI Review - ${safeDate}</h2><p>${escapeHtml(intro)}</p>${tables}${link}<p style="font-size:12px;color:#6b7280">This review is AI-generated and advisory. Verify against TFS and direct observations before acting.</p></body></html>`;
  return { subject, html };
}
