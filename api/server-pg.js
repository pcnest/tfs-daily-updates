// Public API (Postgres) — same endpoints, backed by Neon
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import nodemailer from 'nodemailer';
import { Pool } from 'pg';
import OpenAI from 'openai';

// Load environment
dotenv.config();

// OpenAI setup (optional)
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
let openai = null;
if (OPENAI_API_KEY) {
  openai = new OpenAI({ apiKey: OPENAI_API_KEY });
}

// Helper to parse JSON from OpenAI response
function parseOpenAIJson(resp) {
  try {
    // OpenAI response structure: resp.choices[0].message.content
    const content = resp?.choices?.[0]?.message?.content;
    if (!content) return null;
    return JSON.parse(content);
  } catch (e) {
    console.error('[parseOpenAIJson] Failed to parse:', e.message);
    return null;
  }
}

// Minimal mailer config and safe transport builder so server can start
const MAIL_MODE = process.env.MAIL_MODE || 'file';
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = process.env.SMTP_PORT
  ? Number(process.env.SMTP_PORT)
  : undefined;
const SMTP_SECURE = (process.env.SMTP_SECURE || 'false') === 'true';
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_REQUIRE_TLS = (process.env.SMTP_REQUIRE_TLS || 'false') === 'true';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const SNAPSHOT_CC = process.env.SNAPSHOT_CC || '';
const TEST_RECIPIENT = process.env.TEST_RECIPIENT || '';

// Brevo API key for sending emails via REST API
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';

function buildMailTransport() {
  if (MAIL_MODE === 'smtp' && SMTP_HOST) {
    console.log('[buildMailTransport] Creating SMTP transport with config:', {
      host: SMTP_HOST,
      port: SMTP_PORT || 587,
      secure: SMTP_SECURE,
      requireTLS: SMTP_REQUIRE_TLS,
      hasAuth: !!SMTP_USER,
    });
    return nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT || 587,
      secure: SMTP_SECURE,
      requireTLS: SMTP_REQUIRE_TLS,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
      connectionTimeout: 10000, // 10 seconds to connect
      greetingTimeout: 5000, // 5 seconds to receive server greeting
      socketTimeout: 30000, // 30 seconds of socket inactivity before timeout
    });
  }
  // Default to a safe JSON transport for local testing
  console.log(
    '[buildMailTransport] Using JSON transport (MAIL_MODE:',
    MAIL_MODE,
    ', SMTP_HOST:',
    SMTP_HOST,
    ')'
  );
  return nodemailer.createTransport({ jsonTransport: true });
}

// Express app + basic middleware
const app = express();
const PORT = process.env.PORT || 8080;
app.use(cors());
// Bump JSON body limit to handle larger sync batches without 502/413
app.use(express.json({ limit: '10mb' }));

// Small helper: normalize a comma/space separated list
function normalizeEmails(value) {
  if (!value) return [];
  if (Array.isArray(value))
    return value
      .map(String)
      .map((s) => s.trim())
      .filter(Boolean);
  return String(value)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}
// [PATCH-1] safe filename helper
function fileSafeSlug(s, max = 80) {
  return String(s || '')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, max);
}
// Robust resolver: accepts alias, email, or a "Display — alias · email" label.
async function resolveRecipientEmail(pool, developer, developerLabel) {
  const str = String(developer || '').trim();
  const label = String(developerLabel || '').trim();

  // 1) If `developer` already looks like an email, use it
  if (/@.+\./.test(str)) return str.toLowerCase();

  // 2) Try to extract email from the label, if present
  const emailFromLabel = (label.match(
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i
  ) || [])[0];
  if (emailFromLabel) return emailFromLabel.toLowerCase();

  // 3) Derive a candidate alias (supports "domain\alias" or simple alias)
  let alias = str.toLowerCase();
  const bs = alias.indexOf('\\');
  if (bs > -1) alias = alias.slice(bs + 1);
  alias = alias.replace(/["'`]/g, '').trim();

  // If label contains " — alias " style, capture alias token
  const aliasFromLabel = (label.match(/—\s*([A-Za-z0-9._-]+)\b/) || [])[1];
  if (!alias && aliasFromLabel) alias = aliasFromLabel.toLowerCase();

  // replaced the tryQueries array so we never reference users.alias
  const tryQueries = [
    // Prefer TFS directory: alias match (strip DOMAIN\ if ever stored that way)
    {
      sql: `
        select email
          from tfs_users
         where email is not null
           and lower(regexp_replace(alias, '^.*\\\\', '')) = $1
         limit 1
      `,
      args: [alias],
    },
    // Name match in TFS (when label was provided from your UI)
    {
      sql: `
        select email
          from tfs_users
         where email is not null
           and lower(display_name) = $1
         limit 1
      `,
      args: [label.toLowerCase()],
    },
    // Fall back to your app users: match by email local-part (alias-like)
    {
      sql: `
        select email
          from users
         where split_part(lower(email),'@',1) = $1
         limit 1
      `,
      args: [alias],
    },
    // Final fallback: match by saved display name in users table
    {
      sql: `
        select email
          from users
         where lower(name) = $1
         limit 1
      `,
      args: [label.toLowerCase()],
    },
  ];

  for (const q of tryQueries) {
    if (!q.args[0]) continue;
    const r = await pool.query(q.sql, q.args);
    if (r.rows.length && r.rows[0].email)
      return String(r.rows[0].email).toLowerCase();
  }

  return null; // not found
}

// Resolve a friendly display name for subject lines
async function resolveDeveloperDisplayName(pool, developer, developerLabel) {
  const dev = String(developer || '').trim();
  const label = String(developerLabel || '').trim();

  // 'all' stays 'all'
  if (!dev || dev.toLowerCase() === 'all') return 'all';

  // Prefer a clean name from the UI label if present (e.g., "Jane Doe — jdoe · jdoe@x")
  if (label) {
    // Take portion before an em-dash if present, and ensure it's not an email
    const beforeDash = label.split('—')[0]?.trim();
    if (beforeDash && !/@/.test(beforeDash)) return beforeDash;
  }

  // Determine an email to look up
  let email = dev.includes('@') ? dev.toLowerCase() : null;
  if (!email) {
    // Try alias → tfs_users
    const r = await pool.query(
      `select lower(email) as email,
              coalesce(nullif(display_name,''), '') as display_name
         from tfs_users
        where active=true
          and lower(regexp_replace(alias,'^.*\\\\','')) = $1
        limit 1`,
      [dev.toLowerCase()]
    );
    if (r.rowCount) {
      if (r.rows[0].display_name) return r.rows[0].display_name;
      email = r.rows[0].email;
    }
  }

  if (email) {
    // Prefer app user name
    const u = await pool.query(
      `select coalesce(nullif(name,''), '') as name
         from users where lower(email)=$1 limit 1`,
      [email]
    );
    if (u.rowCount && u.rows[0].name) return u.rows[0].name;

    // Fall back to TFS display_name
    const t = await pool.query(
      `select coalesce(nullif(display_name,''), '') as display_name
         from tfs_users where lower(email)=$1 limit 1`,
      [email]
    );
    if (t.rowCount && t.rows[0].display_name) return t.rows[0].display_name;

    // Last resort: local-part
    return email.split('@')[0];
  }

  // Couldn’t resolve → return the given token (alias) as-is
  return dev;
}

// --- Email font normalization (Gmail + Outlook/Word) -------------------------
const EMAIL_FONT_STACK =
  'Segoe UI, Arial, Helvetica, Noto Sans, Roboto, sans-serif';

function normalizeEmailHTMLFonts(html) {
  if (!html) return html || '';

  const headBits = `
<meta name="x-apple-disable-message-reformatting">
<meta http-equiv="x-ua-compatible" content="IE=edge">
<!--[if mso]>
  <xml>
    <o:OfficeDocumentSettings>
      <o:AllowPNG/>
      <o:PixelsPerInch>96</o:PixelsPerInch>
    </o:OfficeDocumentSettings>
  </xml>
  <style>
    /* Outlook desktop: force family + size for body text and lists */
    body, p, li, div, span, a, h1, h2, h3 {
      font-family: Arial, Helvetica, sans-serif !important;
      font-size: 14px !important;
      line-height: 21px !important;
      mso-line-height-rule: exactly;
    }
    table, td, th {
      font-family: Arial, Helvetica, sans-serif !important;
      mso-table-lspace:0pt; mso-table-rspace:0pt;
    }
  </style>
<![endif]-->
<style>
  /* Cross-client base (does not touch table cell font-size) */
  body, p, li, div, span, a, h1, h2, h3 {
    font-family: ${EMAIL_FONT_STACK} !important;
    font-size: 14px !important;
    line-height: 1.5 !important;
    -ms-text-size-adjust: 100%;
    -webkit-text-size-adjust: 100%;
  }
  table, td, th { font-family: ${EMAIL_FONT_STACK} !important; }
  ul, ol { margin: 0 0 0 22px; padding: 0; }
  table { border-collapse: collapse; mso-table-lspace:0pt; mso-table-rspace:0pt; }
</style>`;

  let out = String(html);

  // Ensure <head> has the resets
  if (/<head[^>]*>/i.test(out)) {
    out = out.replace(/<head[^>]*>/i, (m) => m + headBits);
  } else {
    out = `<!doctype html><html><head>${headBits}</head><body>${out}</body></html>`;
  }

  // Add an inline family on <body> if missing (helps some webmail)
  out = out.replace(/<body([^>]*)>/i, (m, attrs = '') => {
    if (/font-family\s*:/i.test(attrs)) return m;
    const sep = attrs.trim().length ? ' ' : '';
    return `<body${sep}${attrs} style="font-family:${EMAIL_FONT_STACK};">`;
  });

  return out;
}

// --- HTML -> PDF helper (used by snapshots/email) ---
async function htmlToPdfBuffer(html) {
  const puppeteer = (await import('puppeteer')).default;
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0' });
  const pdf = await page.pdf({
    format: 'A4',
    printBackground: true,
    margin: { top: '14mm', right: '12mm', bottom: '16mm', left: '12mm' },
  });
  await browser.close();
  return pdf;
}

// Strict JSON schema for suggestions
const TriageSchema = {
  name: 'TriageList',
  strict: false, // IMPORTANT: keeps optional fields optional (prevents "Missing 'slipRisk'")
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      suggestions: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            id: { type: 'string' },
            risk: { type: 'integer', minimum: 1, maximum: 5 },
            slipRisk: { type: 'string', enum: ['low', 'medium', 'high'] },
            reason: { type: 'string' },
            next_steps: {
              type: 'array',
              items: { type: 'string' },
              minItems: 1,
            },
            chase_message: { type: 'string' },
            suggest_code: { type: 'string' },
            owner_hint: { type: 'string' },
          },
          required: ['id', 'risk', 'next_steps'],
        },
      },
    },
    required: ['suggestions'],
  },
};

const UpdatesRiskSchema = {
  name: 'UpdatesRisk',
  strict: true,
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      items: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            id: { type: 'string' },
            risk_level: { type: 'string', enum: ['low', 'medium', 'high'] },
            rationale: { type: 'string' },
          },
          required: ['id', 'risk_level', 'rationale'],
        },
        minItems: 0,
        maxItems: 200,
      },
    },
    required: ['items'],
  },
};

async function aiTriage(items) {
  if (!openai)
    throw Object.assign(new Error('AI not configured'), { status: 501 });

  // Keep payload tight; cap at 10 for latency/cost
  const now = Date.now();

  function daysSince(dt) {
    const t = dt ? Date.parse(dt) : NaN;
    return Number.isFinite(t)
      ? Math.max(0, Math.round((now - t) / 86400000))
      : null;
  }

  function sevScore(s) {
    const m = String(s || '').toLowerCase();
    return m === 'critical'
      ? 4
      : m === 'high'
      ? 3
      : m === 'medium'
      ? 2
      : m === 'low'
      ? 1
      : 0; // unknown/blank
  }

  // pull (first) x.y.z pattern as our releaseTag hint
  function releaseFromTags(tags) {
    const m = String(tags || '').match(/\b\d+\.\d+\.\d+\b/);
    return m ? m[0] : null;
  }

  const trimmed = (items || []).slice(0, 10).map((r) => {
    const created = r.createdDate || null;
    const stateChanged = r.stateChangeDate || null;

    const ageDays = daysSince(created);
    const timeInStateDays = daysSince(stateChanged);

    const priority = Number.isFinite(+r.priority) ? +r.priority : null;
    const priorityBucket =
      priority === 1
        ? 'P1'
        : priority === 2
        ? 'P2'
        : priority === 3
        ? 'P3'
        : priority === 4
        ? 'P4'
        : 'unknown';

    const severity = r.severity || null;
    const severityScore = sevScore(severity);

    const relatedLinkCount = Number.isFinite(+r.relatedLinkCount)
      ? +r.relatedLinkCount
      : 0;

    return {
      // identity + basic context
      id: String(r.ticketId || r.id || ''),
      title: String(r.title || ''),
      type: String(r.type || ''),
      state: String(r.state || ''),

      // blocker context from progress row
      code: String(r.code || ''),
      note: String(r.note || ''),

      // assignment + project context
      assignedTo: String(r.assignedTo || ''),
      iterationPath: String(r.iterationPath || ''),
      areaPath: String(r.areaPath || ''),
      tags: String(r.tags || ''),

      // richer raw fields (nullable)
      priority,
      severity,
      createdDate: created,
      changedDate: r.changedDate || null,
      stateChangeDate: stateChanged,
      foundInBuild: r.foundInBuild || null,
      integratedInBuild: r.integratedInBuild || null,
      relatedLinkCount,
      effort: r.effort != null && r.effort !== '' ? String(r.effort) : null,

      // derived
      ageDays,
      timeInStateDays,
      priorityBucket,
      severityScore,
      releaseTag: releaseFromTags(r.tags),
    };
  });

  const system = `You are a senior triage PM/SE embedded in a TFS stand-up tool.
You receive per-ticket context including raw fields (priority 1-4, severity, createdDate, stateChangeDate,
relatedLinkCount, effort, tags, foundInBuild, integratedInBuild) and derived fields
(ageDays, timeInStateDays, priorityBucket, severityScore, releaseTag).
Return concrete, small next steps to UNBLOCK items.

Heuristics:
- Older items (ageDays) and long timeInStateDays increase slip risk.
- Higher priorityBucket (P1/P2) and severityScore deserve faster escalation.
- relatedLinkCount > 0 hints dependency/coordination risk: consider nudging owners of linked tickets.
- If releaseTag or found/integrated build data is present, mention that context in the recommendation.
- Keep outputs brief, practical, copy-paste ready, using team's progress codes when clear:
  300_04 (collaborating with QA), 500_01 (ready for QA), 700_xx (investigation), 800_03 (waiting on X / dependency).`;

  const user = `Analyze these blockers and produce suggestions:
${JSON.stringify(trimmed)}`;
  if (process.env.OPENAI_DEBUG === '1') {
    console.log(
      '[ai/triage] request.args',
      JSON.stringify({
        model: OPENAI_MODEL,
        inputRoleCount: 2,
        textFormatKeys: Object.keys({
          name: TriageSchema.name,
          schema: TriageSchema.schema,
          strict: !!TriageSchema.strict,
        }),
      })
    );
  }

  const resp = await openai.chat.completions.create({
    model: OPENAI_MODEL,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: TriageSchema.name,
        schema: TriageSchema.schema,
        strict: !!TriageSchema.strict,
      },
    },
    max_tokens: 1200,
  });

  const js = parseOpenAIJson(resp);
  if (!js || !Array.isArray(js.suggestions)) throw new Error('bad_ai_response');
  return js.suggestions;
}

async function aiRiskForUpdates(items) {
  if (!openai)
    throw Object.assign(new Error('AI not configured'), { status: 501 });

  const trimmed = (items || []).slice(0, 40).map((r) => ({
    id: String(r.ticketId || ''),
    title: String(r.title || ''),
    type: String(r.type || ''),
    state: String(r.state || ''),
    code: String(r.code || ''),
    note: String(r.note || ''),
    severity: String(r.severity || ''),
    impact_area: String(r.impactArea || ''),
    assigned_to: String(r.assignedTo || ''),
    iteration_path: String(r.iterationPath || ''),
    deterministic_risk: String(r.riskLevel || ''),
    deterministic_reasons: Array.isArray(r.riskReasons) ? r.riskReasons : [],
  }));

  const system = `You are a delivery PM reviewing daily progress updates.
Tag AI risk based on the update text and context, especially:
- dependency, waiting, blocked language
- customer-facing impact or high impact areas
- uncertainty, delays, or missing progress
Return a concise rationale (1 short sentence) only when meaningful.
If there is no clear risk signal, set risk_level=low and rationale="".
Do not invent facts or names not in the input.`;

  const user = `Analyze these updates and return risk tags with rationale.
Input JSON:
${JSON.stringify(trimmed)}`;

  const resp = await openai.chat.completions.create({
    model: OPENAI_MODEL,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: UpdatesRiskSchema.name,
        schema: UpdatesRiskSchema.schema,
        strict: !!UpdatesRiskSchema.strict,
      },
    },
    max_tokens: 700,
  });

  const js = parseOpenAIJson(resp);
  if (!js || !Array.isArray(js.items)) throw new Error('bad_ai_response');
  return js.items;
}

// DB pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Log which DB host we are talking to (masking secrets) to rule out DSN drift
try {
  const dbUrl = new URL(process.env.DATABASE_URL || '');
  const hostMasked = dbUrl.host || '(none)';
  const dbName = (dbUrl.pathname || '').replace(/^\//, '') || '(none)';
  const userMasked = dbUrl.username ? `${dbUrl.username}@` : '';
  console.log('[db]', { host: hostMasked, db: dbName, user: userMasked });
} catch (e) {
  console.log('[db] could not parse DATABASE_URL');
}

// Auto-export TSV at day end
const EXPORT_DIR = path.join(process.cwd(), 'exports');
if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });

// Time zone for "today" calculations (IANA zone, e.g., America/Los_Angeles)
const APP_TZ = process.env.APP_TZ || 'UTC';

// helpers
const SECRET_PATTERNS = [
  /\bpat\.[a-z0-9_\-]{20,}\b/gi, // generic PAT-like tokens
  /https?:\/\/[^ \n]*@[^ \n]*/gi, // basic auth in URLs
  /apikey[=:]\s*[a-z0-9_\-]{10,}/gi,
];
const scrub = (s) =>
  String(s || '')
    .replace(SECRET_PATTERNS[0], '[REDACTED_PAT]')
    .replace(SECRET_PATTERNS[1], 'https://[REDACTED]')
    .replace(SECRET_PATTERNS[2], 'apiKey=[REDACTED]');

// safe string normalize: handles null/undefined and non-strings
const S = (v) =>
  (typeof v === 'string' ? v : v == null ? '' : String(v)).trim();

const todayISO = () => new Date().toISOString().slice(0, 10);
const addDays = (iso, delta) => {
  const d = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return iso;
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
};
async function todayLocal(pool) {
  // Returns 'YYYY-MM-DD' based on APP_TZ (DST-safe)
  const { rows } = await pool.query(
    `select to_char(timezone($1, now())::date, 'YYYY-MM-DD') as d`,
    [APP_TZ]
  );
  return rows[0].d;
}

// Chase gate: only allow configured blocker code families
const DEFAULT_BLOCKER_CODE_FAMILIES = ['600', '700', '800'];
const blockerCodeFamilies = (process.env.BLOCKER_CODE_FAMILIES || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
if (!blockerCodeFamilies.length)
  blockerCodeFamilies.push(...DEFAULT_BLOCKER_CODE_FAMILIES);
const blockerCodePattern = blockerCodeFamilies
  .map((family) => String(family).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  .join('|');
const BLOCKER_CODE_REGEX = new RegExp(`^(${blockerCodePattern})_`);
function isBlockerCode(code) {
  return BLOCKER_CODE_REGEX.test(String(code || ''));
}

const noteRequiredPrefixes = (
  process.env.NOTE_REQUIRED_PREFIXES || '600_,700_,800_'
)
  .split(',')
  .map((prefix) => String(prefix).trim())
  .filter(Boolean);
async function isNoteRequired(pool, code) {
  // DB-driven rule
  const r = await pool.query(
    'SELECT require_note FROM progress_codes WHERE code=$1 AND active=true',
    [String(code)]
  );
  if (r.rowCount > 0) return !!r.rows[0].require_note;
  // Fallback to legacy prefix rule if code not found
  return noteRequiredPrefixes.some((p) => String(code).startsWith(p));
}

// Not used for enforcement anymore, but keep for feature-flagging UI or future use.
const HARD_LOCK = (process.env.HARD_LOCK ?? '1') === '1';

const blockerKeywords = (
  process.env.BLOCKER_KEYWORDS ||
  'blocker,blocked,access,credential,env,feedback,awaiting,dependency,waiting,stuck,timeout,failed,crash'
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const RISK_STALE_HIGH_DAYS = Math.max(
  0,
  parseInt(process.env.RISK_STALE_HIGH_DAYS || '4', 10) || 4
);
const RISK_STALE_MEDIUM_DAYS = Math.max(
  0,
  parseInt(process.env.RISK_STALE_MEDIUM_DAYS || '2', 10) || 2
);

function daysSince(ts, now = Date.now()) {
  const t = ts ? Date.parse(ts) : NaN;
  return Number.isFinite(t)
    ? Math.max(0, Math.floor((now - t) / 86400000))
    : null;
}

function normalizeSeverity(s) {
  const v = String(s || '').toLowerCase();
  if (!v) return '';
  if (v.includes('critical') || v.includes('sev1') || v === '1')
    return 'critical';
  if (v.includes('high') || v.includes('sev2') || v === '2') return 'high';
  if (v.includes('medium') || v.includes('sev3') || v === '3') return 'medium';
  if (v.includes('low') || v.includes('sev4') || v === '4') return 'low';
  return '';
}

function normalizeRiskLevel(level) {
  const v = String(level || '').toLowerCase();
  return v === 'high' || v === 'medium' || v === 'low' ? v : '';
}

function riskRank(level) {
  return level === 'high'
    ? 3
    : level === 'medium'
    ? 2
    : level === 'low'
    ? 1
    : 0;
}

function maxRisk(a, b) {
  return riskRank(a) >= riskRank(b) ? a : b;
}

function blockerKeywordHit(code, note) {
  const txt = `${code || ''} ${note || ''}`.toLowerCase();
  for (const k of blockerKeywords) {
    if (k && txt.includes(String(k).toLowerCase())) return k;
  }
  return '';
}

function deriveRiskForUpdate(row) {
  const now = Date.now();
  const reasons = [];
  let level = 'low';

  const keyword = blockerKeywordHit(row.code, row.note);
  const isBlocker = isBlockerCode(row.code) || !!keyword;
  if (isBlocker) {
    level = 'high';
    reasons.push(
      keyword ? `blocker keyword: ${keyword}` : 'blocker code family'
    );
  }

  const sev = normalizeSeverity(row.severity);
  if (sev === 'critical' || sev === 'high') {
    level = 'high';
    reasons.push(`severity ${sev}`);
  }

  const staleDays = daysSince(row.at, now);
  if (staleDays != null) {
    if (staleDays >= RISK_STALE_HIGH_DAYS) {
      level = 'high';
      reasons.push(`stale update ${staleDays}d`);
    } else if (staleDays >= RISK_STALE_MEDIUM_DAYS) {
      level = maxRisk(level, 'medium');
      reasons.push(`stale update ${staleDays}d`);
    }
  }

  const stateChanged = row.stateChangeDate || row.state_change_date;
  const at = row.at;
  if (stateChanged && at) {
    const sc = Date.parse(stateChanged);
    const atMs = Date.parse(at);
    if (Number.isFinite(sc) && Number.isFinite(atMs) && sc > atMs) {
      level = maxRisk(level, 'medium');
      reasons.push('status changed since last update');
    }
  }

  const manual = normalizeRiskLevel(row.riskLevel);
  const finalLevel = manual ? maxRisk(manual, level) : level;

  return { riskLevel: finalLevel, riskReasons: reasons, staleDays };
}

function hashPassword(pw, salt = crypto.randomBytes(16)) {
  const hash = crypto.scryptSync(pw, salt, 32);
  return `${salt.toString('base64')}:${hash.toString('base64')}`;
}
function escapeHtml(s) {
  return String(s || '').replace(
    /[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])
  );
}

function verifyPassword(pw, encoded) {
  const [saltB64, hashB64] = String(encoded).split(':');
  if (!saltB64 || !hashB64) return false;
  const salt = Buffer.from(saltB64, 'base64');
  const calc = crypto.scryptSync(pw, salt, 32).toString('base64');
  return crypto.timingSafeEqual(
    Buffer.from(calc, 'base64'),
    Buffer.from(hashB64, 'base64')
  );
}
const newToken = () => crypto.randomBytes(24).toString('hex');

function emailDomainOk(email) {
  // optional domain allowlist as a second guard
  const allow = (process.env.ALLOWED_DOMAIN || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (allow.length === 0) return true; // disabled
  const d = String(email).toLowerCase().split('@')[1] || '';
  return allow.indexOf(d) !== -1;
}

function normAliasFromEmailOrInput(email) {
  // "user@company.com" -> "user"; "DOMAIN\\user" -> "user"
  const e = String(email || '');
  if (e.indexOf('@') > -1) return e.split('@')[0].toLowerCase();
  const bs = e.indexOf('\\');
  if (bs > -1) return e.slice(bs + 1).toLowerCase();
  return e.toLowerCase();
}

function requireSyncKey(req, res, next) {
  const provided = req.header('x-api-key') || '';
  const expected = process.env.TFS_USERS_SYNC_KEY || process.env.API_KEY || '';
  if (!expected || provided !== expected) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// --- mail helpers ------------------------------------------------------------
function parseEmailList(v) {
  // Accepts string ("a@x.com, b@x.com") or array; returns deduped array
  const arr = Array.isArray(v) ? v : String(v || '').split(/[,;]+/);
  const seen = new Set();
  const out = [];
  for (const raw of arr.map((s) => s.trim()).filter(Boolean)) {
    const m = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    if (m) {
      const e = m[0].toLowerCase();
      if (!seen.has(e)) {
        seen.add(e);
        out.push(e);
      }
    }
  }
  return out;
}

// --- Snapshot email builders (reuses your existing HTML/PDF + mail helpers) ---
async function buildSnapshotEmail(req, range, { ai = false } = {}) {
  // Reuse your own HTML renderer by calling /api/reports/snapshots?format=html
  const base = buildBaseUrl(req);
  const qs = new URLSearchParams({
    from: range.from,
    to: range.to,
    developer: String(range.developer || 'all'),
    groupBy: 'month',
    format: 'html',
  });
  if (ai) qs.set('ai', '1');

  const url = `${base}/api/reports/snapshots?${qs.toString()}`;
  const auth = req.header('Authorization') || '';
  const _fetch = globalThis.fetch || (await import('node-fetch')).default;
  const resp = await _fetch(url, {
    headers: auth ? { Authorization: auth } : {},
  });
  const htmlRaw = await resp.text();

  // Normalize fonts for Outlook/Gmail
  const html = normalizeEmailHTMLFonts(htmlRaw);

  const friendlyDev = await resolveDeveloperDisplayName(
    pool,
    range.developer,
    range.developerLabel
  );
  const subject = `Developer Snapshot • ${friendlyDev || 'all'} • ${
    range.from
  } → ${range.to}`;

  return {
    subject,
    html,
    attachments: [], // PDF removed - users can download via /api/reports/snapshots endpoint
  };
}

async function sendEmail({ to, cc, subject, html, attachments }) {
  const toList = normalizeEmails(to);
  const ccList = normalizeEmails(cc);

  // Optional test override
  if (TEST_RECIPIENT) {
    console.warn(
      '[mail] TEST_RECIPIENT in use; overriding To:',
      TEST_RECIPIENT
    );
    toList.length = 0;
    toList.push(TEST_RECIPIENT);
  }
  if (!toList.length) throw new Error('no_valid_recipients');

  console.log('[sendEmail] Attempting to send email...');
  console.log('[sendEmail] To:', toList, 'CC:', ccList);

  // Use Brevo REST API if available (works better on platforms that block SMTP)
  if (BREVO_API_KEY) {
    console.log('[sendEmail] Using Brevo REST API');
    try {
      const payload = {
        sender: { email: SMTP_FROM || SMTP_USER },
        to: toList.map((email) => ({ email })),
        subject: subject || '(no subject)',
        htmlContent: html || '',
      };

      if (ccList.length) {
        payload.cc = ccList.map((email) => ({ email }));
      }

      // Handle attachments if present
      if (attachments && attachments.length > 0) {
        payload.attachment = attachments.map((att) => ({
          name: att.filename,
          content: att.content.toString('base64'),
        }));
      }

      const _fetch = globalThis.fetch || (await import('node-fetch')).default;
      const response = await _fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'api-key': BREVO_API_KEY,
          'content-type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(`Brevo API error: ${response.status} - ${errorData}`);
      }

      const result = await response.json();
      console.log(
        '[sendEmail] Brevo API success, messageId:',
        result.messageId
      );

      return {
        ok: true,
        mode: 'brevo-api',
        messageId: result.messageId,
        to: toList,
        cc: ccList,
        subject: payload.subject,
      };
    } catch (brevoError) {
      console.error('[sendEmail] Brevo API error:', brevoError);
      throw new Error(`Brevo API failed: ${brevoError.message || brevoError}`);
    }
  }

  // Fallback to SMTP or file mode
  console.log('[sendEmail] MAIL_MODE:', MAIL_MODE);
  console.log('[sendEmail] SMTP_HOST:', SMTP_HOST);

  const transporter = buildMailTransport();
  const mail = {
    from: SMTP_FROM || SMTP_USER,
    to: toList.join(', '),
    cc: ccList.length ? ccList.join(', ') : undefined,
    subject: subject || '(no subject)',
    html: html || '',
    attachments: Array.isArray(attachments) ? attachments : undefined,
  };

  try {
    const info = await transporter.sendMail(mail);
    console.log(
      '[sendEmail] Email sent successfully, messageId:',
      info?.messageId
    );

    // Base payload we want to return to callers (UI-friendly)
    const base = {
      ok: true,
      mode: MAIL_MODE, // 'smtp' or 'file'
      messageId: info?.messageId || null, // RFC-5322 Message-ID
      to: toList, // array of resolved "to" emails
      cc: ccList, // array of resolved "cc" emails
      subject: mail.subject, // final subject line
    };

    // In MAIL_MODE='file' we spool the .eml for local review
    if (MAIL_MODE === 'file' && info?.message) {
      const buf = Buffer.isBuffer(info.message)
        ? info.message
        : ArrayBuffer.isView(info.message)
        ? Buffer.from(info.message)
        : Buffer.from(String(info.message));

      const dir = path.join(EXPORT_DIR, 'emails');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const stamp = new Date()
        .toISOString()
        .replace(/[:.]/g, '')
        .replace('T', '_')
        .slice(0, 15);
      const fname =
        fileSafeSlug(`${stamp}_${subject || 'message'}`, 100) + '.eml';
      const out = path.join(dir, fname);
      fs.writeFileSync(out, buf);
      console.log('[mail][spooled]', out);
      return { ...base, eml: out };
    }

    console.log('[mail][sent]', base.messageId, '->', base.to.join(', '));
    return base;
  } catch (mailError) {
    console.error('[sendEmail] Failed to send email:', mailError);
    throw new Error(`Email send failed: ${mailError.message || mailError}`);
  }
}

function buildBaseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = (
    req.headers['x-forwarded-host'] ||
    req.headers.host ||
    ''
  ).trim();
  return `${proto}://${host}`;
}

// --- health
// --- PORT & LISTEN ---
app.get('/health', (_req, res) => res.sendStatus(200)); // keep this instant & dependency-free

// Optional readiness endpoint that checks DB and other deps
app.get('/ready', async (_req, res) => {
  try {
    await pool.query('select 1');
    res.json({ ok: true, at: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ok: false, error: String(e) });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[boot] listening on http://0.0.0.0:${PORT}`);
});

// puppeteer quick smoke test
app.get('/diag/puppeteer', async (req, res) => {
  try {
    const execPath = puppeteer.executablePath();
    const browser = await puppeteer.launch({
      headless: true,
      executablePath: execPath,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--no-zygote',
        '--single-process',
      ],
    });
    const version = await browser.version();
    await browser.close();
    res.json({ ok: true, execPath, version });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// --- auth: signup/login/me
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'email and password required' });

  // 1) optional: quick domain allowlist (set ALLOWED_DOMAIN=company.com in Render)
  if (!emailDomainOk(email)) {
    return res
      .status(403)
      .json({ error: 'sign-up is limited to approved domains' });
  }
  // 2) must exist in tfs_users (by email OR alias), and active
  const alias = normAliasFromEmailOrInput(email);
  const lowerEmail = String(email).toLowerCase().trim();

  const chk = await pool.query(
    `
  SELECT display_name
  FROM tfs_users
  WHERE active = true AND (
         lower(email) = $1
      OR lower(alias) = $2
      OR lower(regexp_replace(alias, '^.*\\\\', '')) = $2
  )
  LIMIT 1
  `,
    [lowerEmail, alias]
  );

  if (chk.rowCount === 0) {
    return res
      .status(403)
      .json({ error: 'no TFS account found for this email/alias' });
  }
  const displayName = chk.rows[0]?.display_name || '';
  const lower = lowerEmail;
  try {
    await pool.query(
      `insert into users (id, email, name, pw)
   values (gen_random_uuid(), $1, $2, $3)
   on conflict (email) do update
     set name = excluded.name,
         pw   = excluded.pw`,
      [lower, displayName, hashPassword(password)]
    );

    res.json({ status: 'ok' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'email and password required' });
  const lower = String(email).toLowerCase().trim();
  try {
    const u = await pool.query(
      'select id, email, name, pw, role from users where email=$1',
      [lower]
    );

    if (u.rowCount === 0 || !verifyPassword(password, u.rows[0].pw)) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const token = newToken();
    await pool.query(
      'insert into sessions(token, email, user_id) values ($1, $2, $3)',
      [token, lower, u.rows[0].id]
    );

    res.json({
      status: 'ok',
      token,
      email: lower,
      name: u.rows[0].name || '',
      role: u.rows[0].role || 'dev',
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function requireAuth(req, res, next) {
  const hdr = req.header('Authorization') || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const s = await pool.query(
      'select email, user_id from sessions where token=$1',
      [token]
    );
    if (s.rowCount === 0)
      return res.status(401).json({ error: 'invalid token' });

    req.userEmail = s.rows[0].email;
    req.userId = s.rows[0].user_id || null;

    // Fallback for older sessions that may not have user_id populated
    if (!req.userId) {
      const u = await pool.query(
        'select id from users where email=$1 limit 1',
        [req.userEmail]
      );
      req.userId = u.rows[0]?.id || null;
    }
    if (!req.userId)
      return res.status(401).json({ error: 'missing user_id for session' });

    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// Centralized error handler to surface body-parser and runtime errors with clear logs
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    console.error('[error] payload too large', {
      path: req.path,
      contentLength: req.header('content-length') || 'n/a',
    });
    return res.status(413).json({ error: 'payload_too_large' });
  }
  console.error('[error] unhandled', err);
  return res.status(500).json({ error: 'internal_error' });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const u = await pool.query(
    'select email,name,role from users where email=$1',
    [req.userEmail]
  );
  res.json({
    email: req.userEmail,
    name: u.rows[0]?.name || '',
    role: u.rows[0]?.role || 'dev',
  });
});

// logout current session
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  const hdr = req.header('Authorization') || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (token) await pool.query('delete from sessions where token=$1', [token]);
  res.json({ status: 'ok' });
});

// (optional) logout all sessions for me
app.post('/api/auth/logout_all', requireAuth, async (req, res) => {
  await pool.query('delete from sessions where email=$1', [req.userEmail]);
  res.json({ status: 'ok' });
});

// POST /api/sync/tickets     body: { source, tickets: [...], pushedAt, presentIds: [...] }
app.post('/api/sync/tickets', requireSyncKey, async (req, res) => {
  // The agent can send: { source, tickets: [...], pushedAt, presentIds: [...], presentIteration: "Sprint 2025-400", presentIterationPath: "SupplyPro.Core\2025\Sprint 400" }
  const {
    source = 'unknown',
    tickets = [],
    pushedAt,
    presentIds = [],
    presentIteration = '',
    presentIterationPath = '',
  } = req.body || {};
  // Debug: log batch sizes and request size to aid 502 investigation
  console.log('[sync] incoming', {
    source,
    ticketsCount: Array.isArray(tickets) ? tickets.length : 'n/a',
    presentIdsCount: Array.isArray(presentIds) ? presentIds.length : 'n/a',
    contentLength: req.header('content-length') || 'n/a',
  });

  // Defensive validation: ensure caller sent expected shapes to avoid runtime TypeErrors
  if (!Array.isArray(tickets)) {
    console.error('[sync] bad_request: tickets must be an array', {
      source,
      ticketsType: typeof tickets,
    });
    return res.status(400).json({
      status: 'error',
      error: 'bad_request',
      detail: 'tickets must be an array',
    });
  }
  if (presentIds && !Array.isArray(presentIds)) {
    console.error('[sync] bad_request: presentIds must be an array', {
      presentIdsType: typeof presentIds,
    });
    return res.status(400).json({
      status: 'error',
      error: 'bad_request',
      detail: 'presentIds must be an array',
    });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const WATCH_IDS = new Set(['154823']);

    // Upsert all tickets we just saw; set last_seen_at and clear deleted
    for (const t of tickets) {
      if (WATCH_IDS.has(String(t.id))) {
        console.log('[sync/watch]', {
          id: String(t.id),
          state: t.state,
          changedDate: t.changedDate,
          iterationPath: t.iterationPath,
        });
      }

      const seenAt = pushedAt || new Date().toISOString();
      await client.query(
        `
  INSERT INTO tickets (
    id, type, title, state, reason,
    priority, severity,
    assigned_to, area_path, iteration_path,
    created_date, changed_date, state_change_date,
    tags, found_in_build, integrated_in_build,
    related_link_count, effort,
    created_by,           -- << NEW
    last_seen_at, deleted
  )
  VALUES (
    $1,$2,$3,$4,$5,
    $6,$7,
    $8,$9,$10,
    $11,$12,$13,
    $14,$15,$16,
    $17,$18,
    $19,                 -- << NEW (created_by)
    $20,false
  )
  ON CONFLICT (id) DO UPDATE SET
    type                = EXCLUDED.type,
    title               = EXCLUDED.title,
    state               = EXCLUDED.state,
    reason              = EXCLUDED.reason,
    priority            = EXCLUDED.priority,
    severity            = EXCLUDED.severity,
    assigned_to         = EXCLUDED.assigned_to,
    area_path           = EXCLUDED.area_path,
    -- HIGH FIX: Only update iteration_path if agent data is newer (prevents stale path propagation)
    iteration_path      = CASE 
                            WHEN EXCLUDED.changed_date >= COALESCE(tickets.changed_date, '1900-01-01'::timestamptz)
                            THEN EXCLUDED.iteration_path
                            ELSE tickets.iteration_path
                          END,
    created_date        = EXCLUDED.created_date,
    changed_date        = EXCLUDED.changed_date,
    state_change_date   = EXCLUDED.state_change_date,
    tags                = EXCLUDED.tags,
    found_in_build      = EXCLUDED.found_in_build,
    integrated_in_build = EXCLUDED.integrated_in_build,
    related_link_count  = EXCLUDED.related_link_count,
    effort              = EXCLUDED.effort,
    -- keep the first non-empty creator we ever stored
    created_by          = CASE
                            WHEN tickets.created_by IS NULL OR tickets.created_by = ''
                              THEN EXCLUDED.created_by
                            ELSE tickets.created_by
                          END,
    last_seen_at        = EXCLUDED.last_seen_at,
    deleted             = false
  `,
        [
          String(t.id), // $1
          t.type || '', // $2
          t.title || '', // $3
          t.state || '', // $4
          t.reason || '', // $5

          Number.isFinite(+t.priority) ? +t.priority : null, // $6
          t.severity || null, // $7

          t.assignedTo || '', // $8
          t.areaPath || '', // $9
          t.iterationPath || '', // $10

          t.createdDate || null, // $11
          t.changedDate || null, // $12
          t.stateChangeDate || null, // $13

          t.tags || '', // $14
          t.foundInBuild || null, // $15
          t.integratedInBuild || null, // $16

          Number.isFinite(+t.relatedLinkCount) ? +t.relatedLinkCount : 0, // $17
          t.effort != null && t.effort !== '' ? String(t.effort) : null, // $18

          t.createdBy || '', // $19  << NEW
          seenAt, // $20
        ]
      );
    }

    // ---- Presence sweep (use agent's authoritative presentIterationPath) ----
    {
      const idsText = Array.isArray(presentIds)
        ? presentIds.map(String).filter(Boolean)
        : [];
      const authPath = String(presentIterationPath || '').trim();

      // 1) If we have any "present" IDs, un-delete them and bump last_seen_at
      if (idsText.length > 0) {
        await client.query(
          `UPDATE tickets
         SET deleted = false, last_seen_at = now()
       WHERE id = ANY($1::text[])`,
          [idsText]
        );

        // 2) Use agent's presentIterationPath as authoritative scope (not DB's stale paths)
        // This ensures we tombstone based on TFS current state, not historical DB state
        if (authPath) {
          // Tombstone anything whose iteration_path MATCHES the agent's current iteration
          // but wasn't in the present list
          const iterSweepResult = await client.query(
            `UPDATE tickets
           SET deleted = true
         WHERE lower(iteration_path) = lower($1)
           AND NOT (id = ANY($2::text[]))
         RETURNING id`,
            [authPath, idsText]
          );

          console.log('[sweep]', {
            presentCount: idsText.length,
            authPath,
            mode: 'agent-authoritative',
            iterTombstoned: iterSweepResult.rowCount,
          });

          // Additional sweep: tombstone items recently synced but NOT in scope
          // These are cross-iteration items (WIQL C) that were refreshed but aren't in presentIds
          // Use a 3-hour window to handle gaps in agent runs (e.g., server downtime, network issues)
          // This ensures out-of-scope items are tombstoned even if agent is delayed
          const recentResult = await client.query(
            `UPDATE tickets
           SET deleted = true
         WHERE NOT (id = ANY($1::text[]))
           AND last_seen_at >= now() - interval '3 hours'
         RETURNING id`,
            [idsText]
          );

          if (recentResult.rowCount > 0) {
            console.log('[recent-sweep]', {
              tombstoned: recentResult.rowCount,
              sampleIds: recentResult.rows
                .slice(0, 10)
                .map((r) => r.id)
                .join(', '),
            });
          } else {
            console.log('[recent-sweep]', { tombstoned: 0 });
          }
        } else {
          // Fallback: derive scope from DB (original behavior) if agent didn't provide path
          const { rows: pathRows } = await client.query(
            `SELECT DISTINCT iteration_path
         FROM tickets
        WHERE id = ANY($1::text[])`,
            [idsText]
          );

          const scopePaths = pathRows
            .map((r) => r.iteration_path)
            .filter((p) => p != null);

          if (scopePaths.length > 0) {
            await client.query(
              `UPDATE tickets
           SET deleted = true
         WHERE iteration_path = ANY($1::text[])
           AND NOT (id = ANY($2::text[]))`,
              [scopePaths, idsText]
            );
          }

          const hasNullPath = pathRows.some((r) => r.iteration_path == null);
          if (hasNullPath) {
            await client.query(
              `UPDATE tickets
           SET deleted = true
         WHERE iteration_path IS NULL
           AND NOT (id = ANY($1::text[]))`,
              [idsText]
            );
          }

          console.log('[sweep]', {
            presentCount: idsText.length,
            scopePaths: scopePaths.length,
            hasNullPath,
            mode: 'db-derived-fallback',
          });
        }
      } else {
        console.log('[sweep] skipped (no presentIds)');
      }
    }
    // ---- end presence sweep ----

    await client.query('COMMIT');
    res.json({
      status: 'ok',
      source,
      count: tickets.length,
      prunedScope: Array.isArray(presentIds) ? presentIds.length : 0,
      iteration: presentIteration || null,
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('sync error:', e);
    res
      .status(500)
      .json({ status: 'error', error: 'sync_failed', detail: e.message });
  } finally {
    client.release();
  }
});

// Team member list for PMs (used to populate Assigned-to dropdown)
app.get('/api/team-members', requireAuth, async (req, res) => {
  try {
    // only PMs can fetch
    const me = await pool.query('select role from users where email=$1', [
      req.userEmail,
    ]);
    if ((me.rows[0]?.role || 'dev') !== 'pm') {
      return res.status(403).json({ error: 'forbidden' });
    }

    // Pull registered devs from users, shaped like the old tfs_users payload
    const { rows } = await pool.query(`
      select
        -- alias: email local-part
        split_part(lower(email), '@', 1) as alias,
        -- display_name: prefer users.name, fall back to alias
        coalesce(nullif(name, ''), split_part(email, '@', 1)) as display_name,
        lower(email) as email
      from users
      where role = 'dev'
      order by display_name nulls last, alias
      limit 1000
    `);

    res.json({ items: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// store current iteration via the Agent
app.post('/api/iteration/current', requireSyncKey, async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const team = String(req.body?.team || '').trim();
    const at = req.body?.at || null;

    if (!name) return res.status(400).json({ error: 'name is required' });

    await pool.query(
      `insert into meta (key, value, extra, updated_at)
       values ('current_iteration', $1, $2, now())
       on conflict (key) do update
         set value = excluded.value,
             extra = excluded.extra,
             updated_at = now()`,
      [name, JSON.stringify({ team, at })]
    );

    res.json({ ok: true, name });
  } catch (e) {
    console.error('POST /api/iteration/current error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// read current iteration for the UI badge
app.get('/api/iteration/current', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `select value, updated_at, extra from meta where key='current_iteration'`
    );
    const row = rows[0] || null;
    res.json({
      name: row?.value || null,
      updated_at: row?.updated_at || null,
      extra: row?.extra || null,
    });
  } catch (e) {
    console.error('GET /api/iteration/current error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// GET /api/iteration/:name/live-ids
// Returns the IDs currently in our DB for that iteration (default hides deleted and limits to Bug/PBI)
app.get('/api/iteration/:name/live-ids', async (req, res) => {
  const name = req.params.name || '';
  const { includeDeleted, types } = req.query;

  const clauses = [];
  const params = [];
  let i = 1;

  // Explicit toggle required to override default Bug/PBI types filter
  const typesOverride =
    String(req.query.typesOverride || '').toLowerCase() === '1' ||
    String(req.query.typesOverride || '').toLowerCase() === 'true';

  if (!includeDeleted || String(includeDeleted) !== '1') {
    clauses.push(`coalesce(deleted, false) = false`);
  }

  if (!types || String(types).toLowerCase() === 'default') {
    clauses.push(`lower(type) in ('bug','product backlog item')`);
  } else if (String(types).toLowerCase() !== 'all') {
    const list = String(types)
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (list.length) {
      clauses.push(`lower(type) = any($${i++})`);
      params.push(list);
    }
  }

  if (name) {
    clauses.push(`lower(iteration_path) like lower($${i++})`);
    params.push(`%${name}%`);
  }

  const where = clauses.length ? `where ${clauses.join(' and ')}` : '';
  const sql = `select id from tickets ${where}`;
  const r = await pool.query(sql, params);
  res.json({ ids: r.rows.map((r) => String(r.id)), count: r.rowCount });
});

// --- tickets query (same filters as before)
function normId(v) {
  let s = String(v || '')
    .toLowerCase()
    .trim();
  if (s.includes('\\')) s = s.split('\\').pop();
  if (s.includes('@')) s = s.split('@')[0];
  return s;
}
app.get('/api/tickets', async (req, res) => {
  const {
    assignedTo,
    state,
    iterationPath,
    areaPath,
    q,
    types,
    includeDeleted,
    updatesBy,
  } = req.query;
  const clauses = [];
  const params = [];
  let i = 1;

  // Explicit toggle required to override default Bug/PBI types filter
  const typesOverride =
    String(req.query.typesOverride || '').toLowerCase() === '1' ||
    String(req.query.typesOverride || '').toLowerCase() === 'true';

  // Exclude soft-deleted rows by default. Override with ?includeDeleted=1 if you ever need to audit.
  if (!includeDeleted || String(includeDeleted) !== '1') {
    // coalesce handles legacy rows where 'deleted' might be null
    clauses.push(`coalesce(t.deleted, false) = false`);
  }

  // Note: We intentionally do NOT default to current iteration here.
  // The agent (WIQL A+B + presence sweep) already ensures only correct items are in DB:
  //   - WIQL A: Bugs/PBIs directly in @CurrentIteration
  //   - WIQL B: Parents (Bugs/PBIs) with child Tasks in @CurrentIteration (even if parent is in old sprint)
  //   - Presence sweep: Sets deleted=true for items no longer in scope
  // The deleted=false filter above is sufficient to show only current items.
  let effectiveIterationPath = iterationPath; // Only used if explicitly provided by caller

  // Default: only Bug + Product Backlog Item.
  // Override requires explicit toggle via ?typesOverride=1 and then:
  //   ?types=all OR ?types=Bug,Product Backlog Item
  const typesParam = String(types || '')
    .toLowerCase()
    .trim();
  if (!typesOverride || !typesParam || typesParam === 'default') {
    clauses.push(`lower(t.type) in ('bug','product backlog item')`);
  } else if (typesParam !== 'all') {
    const list = typesParam
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (list.length) {
      // pg will serialize JS array to Postgres text[]
      clauses.push(`lower(t.type) = any($${i++})`);
      params.push(list);
    }
  }

  // same filters, but prefix columns with t.
  if (assignedTo) {
    // Match against both the full assigned_to field (may contain display name)
    // and the alias-only portion (after stripping domain prefix)
    clauses.push(
      `(lower(t.assigned_to) like $${i++} OR lower(regexp_replace(t.assigned_to,'^.*\\\\','')) like $${i++})`
    );
    const normalized = normId(assignedTo);
    params.push(`%${assignedTo.toLowerCase().trim()}%`, `%${normalized}%`);
  }
  if (state) {
    clauses.push(`lower(t.state)=lower($${i++})`);
    params.push(state);
  } else {
    // Default noise-reduction: hide Done items unless explicitly requested
    clauses.push(`lower(t.state) <> 'done'`);
  }
  // Iteration filter logic per requirements:
  // 1. Show Bug/PBI only (Tasks excluded via type filter above)
  // 2. Show if EITHER:
  //    a) The Bug/PBI is in current sprint (any state), OR
  //    b) The Bug/PBI has child Task in current sprint (parent may be in old sprint)
  //
  // CRITICAL: The agent (WIQL A+B + presence sweep) ensures correct items are in DB:
  //   - WIQL A: Bugs/PBIs with iteration_path = @CurrentIteration
  //   - WIQL B: Parents with iteration_path = old sprint BUT have child Task in @CurrentIteration
  //   - Presence sweep: Sets deleted=true for items no longer in scope
  //
  // Therefore: We rely on deleted=false filter (applied above) instead of iteration_path.
  // Only apply iteration_path filter if explicitly requested by caller.
  if (effectiveIterationPath) {
    clauses.push(`lower(t.iteration_path) like lower($${i++})`);
    params.push(`%${effectiveIterationPath}%`);
  }
  if (areaPath) {
    clauses.push(`lower(t.area_path) like lower($${i++})`);
    params.push(`%${areaPath}%`);
  }
  if (q) {
    clauses.push(`(lower(t.title) like lower($${i++}) or t.id like $${i++})`);
    params.push(`%${q}%`, `%${q}%`);
  }
  const where = clauses.length ? `where ${clauses.join(' and ')}` : '';

  // if caller is authenticated, include their latest code/note via LATERAL join
  // Decide whose updates to surface (email):
  // - PM can pass ?updatesBy=<alias or email>
  // - otherwise fall back to the requester (if authenticated)
  const requester = await tryGetAuthEmail(req);
  let updatesEmail = null;
  let updatesAlias = null; // keep the alias around for a local-part fallback

  if (requester) {
    // If a target is provided, try to resolve it to an email
    if (updatesBy && String(updatesBy).trim()) {
      const ub = String(updatesBy).trim().toLowerCase();
      if (ub.includes('@')) {
        // treat as email; optionally validate against tfs_users
        const chk = await pool.query(
          `select lower(email) as email from tfs_users
            where active=true and lower(email)=$1 limit 1`,
          [ub]
        );
        updatesEmail = chk.rowCount ? chk.rows[0].email : ub;
      } else {
        // treat as alias (DOMAIN\alias or alias)
        const aliasOnly = normId(ub);
        updatesAlias = aliasOnly;

        // 1) Try TFS users (email present)
        const tfs = await pool.query(
          `select lower(email) as email, lower(coalesce(display_name,'')) as display_name
             from tfs_users
            where active=true
              and lower(regexp_replace(alias,'^.*\\\\','')) = $1
            limit 1`,
          [aliasOnly]
        );
        const tfsRow = tfs.rows[0];
        if (tfsRow?.email) {
          updatesEmail = tfsRow.email;
        } else if (tfsRow?.display_name) {
          // 2) Match by display name captured at signup (users.name)
          const byName = await pool.query(
            `select lower(email) as email
               from users
              where lower(name) = $1
              limit 1`,
            [tfsRow.display_name]
          );
          if (byName.rowCount) updatesEmail = byName.rows[0].email;
        }

        if (!updatesEmail) {
          // 3) Fallback: local-part == alias
          const byLocal = await pool.query(
            `select lower(email) as email
               from users
              where lower(split_part(email,'@',1)) = $1
              limit 1`,
            [aliasOnly]
          );
          if (byLocal.rowCount) updatesEmail = byLocal.rows[0].email;
        }
      }
    }

    // PMs may view others; non-PMs are limited to themselves
    if (updatesEmail && updatesEmail !== requester) {
      const roleRow = await pool.query(
        'select role from users where email=$1 limit 1',
        [requester]
      );
      const isPM = roleRow.rows[0]?.role === 'pm';
      if (!isPM) updatesEmail = requester;
    }

    if (!updatesEmail) updatesEmail = requester;
  }

  let sql;
  if (updatesEmail || updatesAlias) {
    // Build lateral predicate that can match on exact email OR local-part (alias) if needed
    let emailParam = null,
      aliasParam = null;
    if (updatesEmail) {
      params.push(updatesEmail);
      emailParam = `$${i++}`;
    }
    if (updatesAlias) {
      params.push(updatesAlias);
      aliasParam = `$${i++}`;
    }

    const lateralPred =
      updatesEmail && updatesAlias
        ? `email = ${emailParam} OR split_part(email,'@',1) = ${aliasParam}`
        : updatesEmail
        ? `email = ${emailParam}`
        : `split_part(email,'@',1) = ${aliasParam}`;

    sql = `
      select
        t.id,
        t.type,
        t.title,
        t.state,
        t.assigned_to as "assignedTo",
        t.area_path   as "areaPath",
        t.iteration_path as "iterationPath",
        t.changed_date   as "changedDate",
        t.severity,
        t.tags,
        u.code as "lastCode",
        u.note as "lastNote"
      from tickets t
      left join lateral (
        select code, note
        from progress_updates
        where ticket_id = t.id and (${lateralPred})
        order by at desc
        limit 1
      ) u on true
      ${where}
      order by t.changed_date desc nulls last, t.id::bigint nulls last
    `;
  } else {
    // original behavior (no extra columns)
    sql = `
      select
        t.id, t.type, t.title, t.state,
        t.assigned_to as "assignedTo",
        t.area_path   as "areaPath",
        t.iteration_path as "iterationPath",
        t.changed_date   as "changedDate",
        t.severity,
        t.tags
      from tickets t
      ${where}
      order by t.changed_date desc nulls last, t.id::bigint nulls last
    `;
  }

  const r = await pool.query(sql, params);
  res.json({ items: r.rows, count: r.rowCount });
});

// --- progress submit (with note requirement and optional hard lock)
app.post('/api/progress', requireAuth, async (req, res) => {
  const { ticketId, code, note, riskLevel, impactArea } = req.body || {};
  if (!ticketId || !code)
    return res.status(400).json({ error: 'ticketId and code are required' });

  const date = await todayLocal(pool);

  const locked = await pool.query(
    'select 1 from progress_locks where email=$1 and date=$2',
    [req.userEmail, date]
  );
  // Always block changes after locking, regardless of env flags.
  if (locked.rowCount)
    return res.status(403).json({ error: 'update already submitted (locked)' });

  if (await isNoteRequired(pool, code)) {
    if (!note || !String(note).trim())
      return res.status(400).json({ error: `note required for code ${code}` });
  }

  // Guard: we must have a userId now that user_id is NOT NULL in DB
  if (!req.userId) {
    return res.status(500).json({ error: 'server_missing_user_id' });
  }

  await pool.query(
    `insert into progress_updates
       (ticket_id, email, user_id, code, note, risk_level, impact_area, date, at)
     values
       ($1,        $2,    $3,      $4,   $5,   $6,         $7,          $8,   now())`,
    [
      String(ticketId), // $1
      req.userEmail, // $2
      req.userId, // $3  <-- NEW
      code, // $4
      note || '', // $5
      riskLevel || 'low', // $6
      impactArea || '', // $7
      date, // $8
    ]
  );
  res.json({ status: 'ok' });
});

// Add a helper to read the auth token without enforcing it
async function tryGetAuthEmail(req) {
  const hdr = req.header('Authorization') || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return null;
  try {
    const s = await pool.query('select email from sessions where token=$1', [
      token,
    ]);
    return s.rowCount ? s.rows[0].email : null;
  } catch (_e) {
    return null;
  }
}

// --- lock / unlock / lock status
app.post('/api/updates/lock', requireAuth, async (req, res) => {
  const date = await todayLocal(pool);

  await pool.query(
    `insert into progress_locks(email, user_id, date, at)
   values ($1, $2, $3, now())
   on conflict (email, date) do nothing`,
    [req.userEmail, req.userId, date]
  );

  res.json({ status: 'ok', locked: true, date });
});
app.post('/api/updates/unlock', requireAuth, async (req, res) => {
  const me = await pool.query('select role from users where email=$1', [
    req.userEmail,
  ]);
  if (me.rows[0]?.role !== 'pm')
    return res.status(403).json({ error: 'pm only' });

  const date = await todayLocal(pool);

  const target = (req.body?.email || '').trim().toLowerCase();
  if (!target) return res.status(400).json({ error: 'target email required' });

  await pool.query(`delete from progress_locks where email=$1 and date=$2`, [
    target,
    date,
  ]);
  res.json({ status: 'ok', locked: false, date, target });
});

app.get('/api/updates/lock', requireAuth, async (req, res) => {
  const date = await todayLocal(pool);

  const r = await pool.query(
    `select 1 from progress_locks where email=$1 and date=$2`,
    [req.userEmail, date]
  );

  // Also return the count of progress updates for today
  const progressCount = await pool.query(
    `select count(*) as count from progress_updates where email=$1 and date=$2`,
    [req.userEmail, date]
  );

  res.json({
    date,
    locked: r.rowCount > 0,
    progressCount: parseInt(progressCount.rows[0]?.count || 0, 10),
  });
});

// --- lock range (current user only)
app.get('/api/updates/locks/range', requireAuth, async (req, res) => {
  try {
    const today = await todayLocal(pool);
    const from = parseDateParam(req.query.from, today);
    const to = parseDateParam(req.query.to, today);

    const MAX_DAYS = 90;
    const spanDays = Math.floor(
      (Date.parse(to) - Date.parse(from)) / 86400000
    );
    if (!Number.isFinite(spanDays) || spanDays < 0 || spanDays > MAX_DAYS) {
      return res
        .status(400)
        .json({ error: `Range too large (max ${MAX_DAYS} days)` });
    }

    const r = await pool.query(
      `select date from progress_locks
       where email=$1 and date between $2::date and $3::date
       order by date`,
      [req.userEmail, from, to]
    );

    const dates = r.rows.map((row) => {
      const d = row.date;
      if (d && typeof d.toISOString === 'function')
        return d.toISOString().slice(0, 10);
      return String(d).slice(0, 10);
    });

    res.json({
      from,
      to,
      email: req.userEmail,
      count: r.rowCount,
      dates,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- collation (enriched)
app.get('/api/updates/today', async (_req, res) => {
  const date = await todayLocal(pool);

  const updates = await pool.query(
    `select u.ticket_id as "ticketId", u.email, u.code, u.note, u.risk_level as "riskLevel",
            u.impact_area as "impactArea", u.at,
            t.title, t.state, t.type, t.severity,
            t.state_change_date as "stateChangeDate",
            t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
     from progress_updates u
     left join tickets t on t.id = u.ticket_id
     where u.date = $1`,
    [date]
  );
  const locks = await pool.query(
    `select email from progress_locks where date=$1`,
    [date]
  );

  const lockedSet = new Set(locks.rows.map((x) => x.email));
  // keep latest per (email,ticket)
  const byUser = new Map();
  for (const r of updates.rows) {
    const derived = deriveRiskForUpdate(r);
    r.riskLevel = derived.riskLevel;
    r.riskReasons = derived.riskReasons;
    r.riskStaleDays = derived.staleDays;

    const email = r.email;
    if (!byUser.has(email))
      byUser.set(email, {
        email,
        name: '',
        locked: lockedSet.has(email),
        tickets: new Map(),
      });
    const m = byUser.get(email).tickets;
    const prev = m.get(r.ticketId);
    if (!prev || r.at > prev.at) m.set(r.ticketId, r);
  }
  // load names in one shot
  const emails = Array.from(byUser.keys());
  let names = new Map();
  if (emails.length) {
    const rNames = await pool.query(
      `select lower(email) as email, coalesce(nullif(name,''), '') as name
       from users
       where lower(email) = any($1)`,
      [emails.map((e) => e.toLowerCase())]
    );
    names = new Map(rNames.rows.map((x) => [x.email, x.name || '']));
  }
  const users = Array.from(byUser.values())
    .map((u) => {
      const nm = names.get(String(u.email).toLowerCase()) || '';
      return {
        email: u.email,
        name: nm,
        locked: u.locked,
        tickets: Array.from(u.tickets.values()).sort((a, b) =>
          String(a.ticketId).localeCompare(String(b.ticketId))
        ),
      };
    })
    .map((u) => ({
      email: u.email,
      name: u.name,
      locked: u.locked,
      tickets: Array.from(u.tickets.values()).sort((a, b) =>
        String(a.ticketId).localeCompare(String(b.ticketId))
      ),
      ...u,
    }))
    .sort((a, b) => a.email.localeCompare(b.email));

  res.json({ date, users });
});

// --- AI risk rationale (PM only)
app.get('/api/updates/today/ai', requireAuth, async (req, res) => {
  try {
    // PMs only
    const me = await pool.query('select role from users where email=$1', [
      req.userEmail,
    ]);
    if (me.rows[0]?.role !== 'pm')
      return res.status(403).json({ error: 'pm only' });

    if (!openai) return res.status(501).json({ error: 'ai_not_configured' });

    const date = await todayLocal(pool);
    const updates = await pool.query(
      `select u.ticket_id as "ticketId", u.email, u.code, u.note, u.risk_level as "riskLevel",
              u.impact_area as "impactArea", u.at,
              t.title, t.state, t.type, t.severity,
              t.state_change_date as "stateChangeDate",
              t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
       from progress_updates u
       left join tickets t on t.id = u.ticket_id
       where u.date = $1`,
      [date]
    );

    const latest = new Map();
    for (const r of updates.rows) {
      const key = `${r.email}|${r.ticketId}`;
      const prev = latest.get(key);
      if (!prev || r.at > prev.at) {
        const derived = deriveRiskForUpdate(r);
        r.riskLevel = derived.riskLevel;
        r.riskReasons = derived.riskReasons;
        r.riskStaleDays = derived.staleDays;
        latest.set(key, r);
      }
    }

    const items = Array.from(latest.values());
    if (!items.length) return res.json({ date, items: [] });

    const aiItems = await aiRiskForUpdates(items);
    res.json({ date, count: aiItems.length, items: aiItems });
  } catch (e) {
    const http = e?.status || e?.response?.status || 500;
    console.error('[ai/today-risk] error:', {
      status: http,
      code: e?.code,
      message: e?.message,
      data: e?.response?.data,
      raw: e?.error || null,
    });
    res.status(http).json({
      status: 'error',
      error: e?.message || 'server_error',
      code: e?.code || null,
      openai: e?.response?.data || e?.error || null,
    });
  }
});

// show a green dot when db_up is true and counts.last7 > 0
app.get('/api/exports/status', async (req, res) => {
  try {
    // 1) last tfs_users sync
    const syncRow = await pool.query(
      `select max(synced_at) as last_sync from tfs_users`
    );

    // 2) progress window & counts
    const stats = await pool.query(
      `
      with pu as (
  select timezone($1, at)::date as d
  from progress_updates
)

      select
  min(d) as first_day,
  max(d) as last_day,
  count(*) filter (where d = timezone($1, now())::date) as today_count,
  count(*) filter (where d >= (timezone($1, now())::date - 6)) as last7_count,
  count(*) as rows_total
from pu
      `,
      [APP_TZ]
    );

    const lastSync = syncRow.rows[0]?.last_sync || null;
    const s = stats.rows[0] || {};
    const hasData = !!s.last_day;

    // Recommend default range = last 7 days (or today if empty)
    const todayStr = todayISO();
    const toISO = hasData ? String(s.last_day).slice(0, 10) : todayStr;
    const fromISO = hasData
      ? new Date(Date.parse(toISO) - 6 * 24 * 3600 * 1000)
          .toISOString()
          .slice(0, 10)
      : todayStr;

    res.json({
      api_up: true,
      db_up: true,
      last_sync_tfs_users: lastSync, // e.g., "2025-10-09T03:50:12.123Z"
      first_progress_day: s.first_day || null,
      last_progress_day: s.last_day || null,
      counts: {
        today: Number(s.today_count || 0),
        last7: Number(s.last7_count || 0),
        total: Number(s.rows_total || 0),
      },
      suggested_ranges: {
        from: fromISO,
        to: toISO,
      },
      // Handy URLs your PM UI can link to
      urls: {
        json_range: `/api/updates/range?from=${fromISO}&to=${toISO}`,
        tsv_range: `/api/updates/range.tsv?from=${fromISO}&to=${toISO}`,
      },
    });
  } catch (e) {
    res.status(500).json({ api_up: true, db_up: false, error: e.message });
  }
});

// “No updates yet today” (PM signal)
app.get('/api/updates/missing', requireAuth, async (req, res) => {
  // PMs only
  const me = await pool.query('select role from users where email=$1', [
    req.userEmail,
  ]);
  if (me.rows[0]?.role !== 'pm')
    return res.status(403).json({ error: 'pm only' });

  const date = await todayLocal(pool);
  // All devs who have an account…
  // …minus those who posted at least one update today.
  const sql = `
    with devs as (
      select email, coalesce(nullif(name,''), email) as label
      from users where role='dev'
    ),
    posters as (
      select distinct email from progress_updates where date=$1
    )
    select d.email, d.label
    from devs d
    left join posters p on p.email = d.email
    where p.email is null
    order by d.email;
  `;
  const r = await pool.query(sql, [date]);
  res.json({ date, count: r.rowCount, missing: r.rows });
});

// utils: parse YYYY-MM-DD or default to today
function parseDateParam(s, def) {
  if (!s) return def;
  // very strict YYYY-MM-DD
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return def;
  return s;
}
// --- unified range helpers (used by JSON + TSV) ------------------------------
function parseRangeFilters(req) {
  const today = new Date().toISOString().slice(0, 10);
  const from = parseDateParam(req.query.from, today);
  const to = parseDateParam(req.query.to, today);

  // normalize developer filter (email or alias/local-part or "all")
  const raw = S(req.query.developer || '').toLowerCase();
  let devEmail = null,
    devLocal = null,
    devFilter = 'all';
  if (raw && raw !== 'all') {
    let cand = raw.includes('\\') ? raw.split('\\').pop() : raw;
    if (cand.includes('@')) {
      devEmail = cand;
      devLocal = cand.split('@')[0];
    } else {
      devLocal = cand;
    }
    devFilter = devEmail || devLocal || raw;
  }

  return { from, to, devEmail, devLocal, devFilter };
}

const RANGE_SQL = `
  SELECT
    u.at::date        AS "date",
    t.assigned_to     AS "assignedTo",
    u.ticket_id       AS "ticketId",
    t.type            AS "type",
    t.title,
    t.state,
    u.code,
    u.note
  FROM progress_updates u
  JOIN tickets t ON t.id = u.ticket_id
  WHERE timezone($3, u.at)::date BETWEEN $1::date AND $2::date
    AND (
      ($4::text IS NULL AND $5::text IS NULL)
      OR lower(u.email) = $4
      OR split_part(lower(u.email),'@',1) = $5
    )
  ORDER BY u.at::date DESC, t.assigned_to NULLS LAST, u.ticket_id
`;

async function selectRangeRows({ from, to, devEmail, devLocal }) {
  const r = await pool.query(RANGE_SQL, [from, to, APP_TZ, devEmail, devLocal]);
  return r.rows;
}

// JSON: /api/updates/range?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/updates/range', async (req, res) => {
  const q = parseRangeFilters(req);
  const rows = await selectRangeRows(q);
  res.json({
    from: q.from,
    to: q.to,
    developer: q.devFilter,
    items: rows,
    count: rows.length,
  });
});

// TSV: /api/updates/range.tsv?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/updates/range.tsv', async (req, res) => {
  const q = parseRangeFilters(req);
  const rows = await selectRangeRows(q);

  const safeDev =
    q.devFilter && q.devFilter !== 'all'
      ? q.devFilter.replace(/[^a-z0-9._-]+/gi, '-').slice(0, 120)
      : '';

  const cell = (x) =>
    String(x == null ? '' : x)
      .replace(/\t/g, ' ')
      .replace(/\r?\n/g, ' ');
  let out = 'date\tassignedTo\tticketId\ttitle\ttype\tstate\tcode\tnote\n';
  for (const r of rows) {
    out +=
      [
        cell(r.date),
        cell(r.assignedTo),
        cell(r.ticketId),
        cell(r.title),
        cell(r.type),
        cell(r.state),
        cell(r.code),
        cell(r.note),
      ].join('\t') + '\n';
  }

  res.setHeader('Content-Type', 'text/tab-separated-values; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="progress_${q.from}_to_${q.to}${
      safeDev ? '_' + safeDev : ''
    }.tsv"`
  );
  res.send(out);
});

// --- Developer Progress Snapshots (PDF/HTML) ---------------------------------
async function requirePMOnly(req, res, next) {
  try {
    const me = await pool.query('select role from users where email=$1', [
      req.userEmail,
    ]);
    if ((me.rows[0]?.role || 'dev') !== 'pm')
      return res.status(403).json({ error: 'pm only' });
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

app.get(
  '/api/reports/snapshots',
  requireAuth,
  requirePMOnly,
  async (req, res) => {
    try {
      const {
        from,
        to,
        groupBy = 'month',
        developer = 'all',
        format = 'pdf',
        stallHours = '12',
      } = req.query;
      // Record if caller asked for AI; we'll enable only for a targeted dev (not "all")
      const aiRequested = String(req.query.ai || '') === '1';

      // Normalize developer (email or alias/local-part)
      const rawDev = S(developer || 'all').toLowerCase();
      let devEmail = null,
        devLocal = null; // email like "a@b" and local-part like "a"
      if (rawDev && rawDev !== 'all') {
        let candidate = rawDev.includes('\\')
          ? rawDev.split('\\').pop()
          : rawDev;
        if (candidate.includes('@')) {
          devEmail = candidate;
          devLocal = candidate.split('@')[0];
        } else {
          // alias → try resolve email; still keep alias as local-part fallback
          const r = await pool.query(
            `select lower(email) as email
          from tfs_users
         where active=true
           and lower(regexp_replace(alias,'^.*\\\\','')) = $1
         limit 1`,
            [candidate]
          );
          devEmail = r.rowCount ? r.rows[0].email : null;
          devLocal = candidate;
        }
      }
      let devFilter =
        rawDev && rawDev !== 'all' ? devEmail || devLocal || rawDev : 'all';

      // limit developer filter length defensively
      if (devFilter && devFilter.length > 120)
        devFilter = devFilter.slice(0, 120);
      // Enable AI only for targeted dev requests (ignore for developer=all)
      const useAI = aiRequested && (devEmail || devLocal);

      const today = todayISO();
      const d7 = new Date(Date.now() - 6 * 24 * 3600 * 1000)
        .toISOString()
        .slice(0, 10);
      const fromISO = parseDateParam(from, d7);
      const toISO = parseDateParam(to, today);

      // Cap window at 90 days to avoid runaway PDFs
      const MAX_DAYS = 90;
      const spanDays = Math.floor(
        (Date.parse(toISO) - Date.parse(fromISO)) / 86400000
      );
      if (!Number.isFinite(spanDays) || spanDays < 0 || spanDays > MAX_DAYS) {
        return res
          .status(400)
          .json({ error: `Range too large (max ${MAX_DAYS} days)` });
      }

      // limit developer filter length defensively
      if (devFilter && devFilter.length > 120)
        devFilter = devFilter.slice(0, 120);

      // SQL: durations per dev per progress family (Aggregate & Average)
      // credit time from an update by DEV until next update on the same ticket (any author)
      const sql = `
      with windowed as (
        select
          email as dev,
          ticket_id,
          code,
          at AT TIME ZONE $3 as ts_local,
          lead(at) over (partition by ticket_id order by at) AT TIME ZONE $3 as next_ts_local
        from progress_updates
        where at >= ($1::timestamptz - interval '7 days')
          and at <  ($2::timestamptz + interval '1 day')
           and (
   ($5::text is null and $6::text is null)
   or lower(email) = $5::text      -- exact email match
   or split_part(lower(email),'@',1) = $6::text  -- local-part match
 )


      ),
      segments as (
        select
          dev, ticket_id, code,
          greatest(ts_local, $1::date AT TIME ZONE $3) as seg_start,
          least(coalesce(next_ts_local, $2::date AT TIME ZONE $3), $2::date AT TIME ZONE $3) as seg_end
        from windowed
      ),
      usable as (
        select *,
               case when seg_end > seg_start
                 then extract(epoch from (seg_end - seg_start))/3600.0
                 else 0 end as hours
        from segments
        where seg_end > seg_start
      ),
      coded as (
        select
          dev, ticket_id,
          split_part(code,'_',1) || '_xx' as family,
          hours
        from usable
      ),
      per_dev_family as (
        select dev, family,
               count(*) as transitions,
               sum(hours) as hours_sum,
               case when count(*)>0 then sum(hours)/count(*) else 0 end as hours_avg
        from coded
        group by dev, family
      ),
      ticket_touch as (
        select dev, count(distinct ticket_id) as ticket_volume
        from coded
        group by dev
      ),
      completion as (
        select dev,
               count(distinct ticket_id) filter (where family='500_xx') as completed_tickets,
               count(distinct ticket_id) as touched_tickets
        from coded
        group by dev
      ),
      latest_ticket as (
        -- latest update per ticket up to report end
        select distinct on (ticket_id)
          ticket_id,
          at AT TIME ZONE $3 as last_ts_local,
          split_part(code,'_',1) || '_xx' as last_family
        from progress_updates
        where at <= ($2::timestamptz)
        order by ticket_id, at desc
      ),
      stalled as (
        -- count tickets that ended the window in 200/600/800 and are "old" vs end
        select c.dev, count(distinct c.ticket_id) as stalled_tickets
        from coded c
        join latest_ticket lt on lt.ticket_id = c.ticket_id
        where lt.last_ts_local between ($1::date AT TIME ZONE $3) and ($2::date AT TIME ZONE $3)
          and lt.last_family in ('200_xx','600_xx','800_xx')
          and (($2::date AT TIME ZONE $3) - lt.last_ts_local) >= (interval '1 hour' * $4::int)
        group by c.dev
      )
      select
        p.dev as email,
        jsonb_object_agg(p.family, jsonb_build_object(
          'transitions', p.transitions,
          'hours_sum', round(p.hours_sum::numeric, 2),
          'hours_avg', round(p.hours_avg::numeric, 2)
        )) as families,
        coalesce(t.ticket_volume,0) as ticket_volume,
        coalesce(c.completed_tickets,0) as completed_tickets,
        coalesce(c.touched_tickets,0) as touched_tickets,
        case when coalesce(c.touched_tickets,0)>0
             then round(100.0*c.completed_tickets/c.touched_tickets,1) else 0 end as completion_pct,
        coalesce(s.stalled_tickets,0) as stalled_tickets
      from per_dev_family p
      left join ticket_touch t on t.dev = p.dev
      left join completion   c on c.dev = p.dev
      left join stalled      s on s.dev = p.dev
      group by p.dev, t.ticket_volume, c.completed_tickets, c.touched_tickets, s.stalled_tickets
      order by p.dev;
    `;

      const { rows } = await pool.query(sql, [
        fromISO,
        toISO,
        APP_TZ,
        parseInt(stallHours, 10) || 12,
        devEmail, // $5
        devLocal, // $6
      ]);

      // optional filter by a specific developer (email)
      const rowsF =
        devEmail || devLocal
          ? rows.filter((r) => {
              const e = S(r.email).toLowerCase();
              const lp = e.split('@')[0];
              return (
                (devEmail && e === devEmail) || (devLocal && lp === devLocal)
              );
            })
          : rows;

      const SNAPSHOT_CSS = `
  body{font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#111;margin:0;padding:24px;}
  h1{font-size:20px;margin:0 0 6px;}
  .muted{color:#6b7280}
  .card{border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:12px 0;background:#fff;}
  .kpi{display:flex;gap:12px;flex-wrap:wrap}
  .pill{background:#f6f6f6;border:1px solid #eee;border-radius:999px;padding:8px 12px;font-weight:600}
  table{width:100%;border-collapse:collapse;margin-top:6px}
  th,td{border-bottom:1px solid #f0f0f0;padding:8px;text-align:left;font-size:12.5px}
  th{background:#fafafa}
  .lbl{width:40%}
  .num{text-align:right;font-variant-numeric:tabular-nums}
  .h2{font-size:14px;margin:14px 0 6px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .section-title{font-weight:700;margin-top:8px}
  .kb ul{margin:6px 0 0 16px;padding:0}
  .kb li{margin:4px 0}
  @media print {
  .card{page-break-inside:avoid}
  .kb ul, .kb li { break-inside: avoid; page-break-inside: avoid; }
  }
  @media (max-width: 1024px), print {
  .grid { grid-template-columns: 1fr; }
  .grid .card { margin: 0 0 12px 0; }
    }

`;

      // No data → show a helpful HTML page instead of a blank response
      if (format === 'html' && rowsF.length === 0) {
        const safe = (x) => (x ? String(x) : '—');
        const emptyHtml = `<!doctype html>
<meta charset="utf-8">
<style>${SNAPSHOT_CSS}</style>
<h1>Developer Progress Snapshot</h1>
<div class="muted">No progress data found for the selected filters.</div>
<ul>
  <li><strong>Range:</strong> ${safe(fromISO)} → ${safe(toISO)}</li>
  <li><strong>Developer:</strong> ${
    safe(devFilter) === '—' ? 'all' : safe(devFilter)
  }</li>
  <li><strong>Group:</strong> ${safe(groupBy)}</li>
  <li><strong>Stall threshold (hours):</strong> ${safe(stallHours)}</li>
  </ul>
<div class="tips">
  <p>Try one of these:</p>
  <ul>
    <li>Expand the date range (e.g., last 7–30 days).</li>
    <li>Remove the developer filter (use <code>developer=all</code>).</li>
    <li>Confirm there are any <code>progress_updates</code> in that window.</li>
  </ul>
</div>`;
        return res.type('html').send(emptyHtml);
      }

      // if (process.env.SNAPSHOTS_DEBUG === '1') {
      console.log('[snapshots]', {
        rawDev,
        devFilter,
        rows: rows.length,
        rowsF: rowsF.length,
      });
      //}

      // label like "Oct 1 – Oct 31, 2025" or "October 2025"
      function labelPeriod(f, t) {
        const fd = new Date(f),
          td = new Date(t);
        const sameDay = f === t;
        const month = (d) => d.toLocaleString('en', { month: 'short' });
        const longMonth = (d) => d.toLocaleString('en', { month: 'long' });

        // If the window is the full month, show "October 2025"
        const firstOfMonth = new Date(fd.getFullYear(), fd.getMonth(), 1);
        const lastOfMonth = new Date(fd.getFullYear(), fd.getMonth() + 1, 0);
        const isFullMonth =
          fd.getTime() === firstOfMonth.getTime() &&
          td.getTime() === lastOfMonth.getTime();

        if (isFullMonth) return `${longMonth(fd)} ${fd.getFullYear()}`;
        if (sameDay)
          return `${longMonth(fd)} ${fd.getDate()}, ${fd.getFullYear()}`;

        return `${month(fd)} ${fd.getDate()} – ${month(
          td
        )} ${td.getDate()}, ${td.getFullYear()}`;
      }

      const periodLabel = labelPeriod(fromISO, toISO, groupBy);
      // slug used in the PDF filename (prefer email local-part, else alias, else nothing)
      const aliasSlugRaw = devEmail ? devEmail.split('@')[0] : devLocal || '';
      const aliasSlug = fileSafeSlug(aliasSlugRaw);
      const fileDevPart = aliasSlug ? `${aliasSlug}_` : '';

      // If AI is requested, precompute insights ONLY for targeted dev(s)
      const insightsByEmail = new Map();
      if (useAI && openai && rowsF.length > 0) {
        for (const r of rowsF) {
          try {
            const got = await aiSnapshotInsightsForDev({
              periodLabel,
              metrics: r,
              fromISO,
              toISO,
              devEmail: String(r.email || '').toLowerCase(),
              devLocal: toLocalPart(String(r.email || '').toLowerCase()),
            });
            insightsByEmail.set(String(r.email || '').toLowerCase(), got);
          } catch (e) {
            console.warn(
              '[snapshots][ai] insight error for',
              r.email,
              e.message
            );
          }
        }
      }

      // HTML renderer
      function pct(n) {
        const x = Number(n);
        return Number.isFinite(x) ? `${x.toFixed(1)}%` : '0%';
      }
      function h(n) {
        const x = Number(n);
        return Number.isFinite(x) ? x.toFixed(2) : '0.00';
      }
      function v(obj, key) {
        return (
          (obj && obj[key]) || { transitions: 0, hours_sum: 0, hours_avg: 0 }
        );
      }

      function renderSnapshotHTML({
        name,
        email,
        period,
        ticketVolume,
        completionPct,
        stalled,
        families,
        insights, // NEW
      }) {
        const famKeys = [
          '100_xx',
          '200_xx',
          '300_xx',
          '400_xx',
          '500_xx',
          '600_xx',
          '700_xx',
          '800_xx',
        ];
        const totalTransitions =
          famKeys.reduce((s, k) => s + (v(families, k).transitions || 0), 0) ||
          0;
        const totalHours = famKeys.reduce(
          (s, k) => s + (v(families, k).hours_sum || 0),
          0
        );
        const weightedAvg = totalTransitions
          ? totalHours / totalTransitions
          : 0;
        const makeRow = (label, code) => {
          const f = v(families, code);
          const pctOfTotal = totalTransitions
            ? Math.round((100 * (f.transitions || 0)) / totalTransitions)
            : 0;
          return `
          <tr>
            <td class="lbl">${label}</td>
            <td class="num">${f.transitions || 0}</td>
            <td class="num">${pctOfTotal}%</td>
            <td class="num">${h(f.hours_sum)}h</td>
            <td class="num">${h(f.hours_avg)}h</td>
          </tr>`;
        };
        const starts = v(families, '100_xx').transitions || 0;
        const finishes = v(families, '500_xx').transitions || 0;
        const blockers =
          (v(families, '600_xx').transitions || 0) +
          (v(families, '800_xx').transitions || 0);
        const reviews = v(families, '400_xx').transitions || 0;
        const testing = v(families, '300_xx').transitions || 0;

        const I = insights || null;
        const stallWhy =
          I && I.risk && I.risk.stall_why
            ? I.risk.stall_why
            : `Blocker/delay footprint ${blockers} (600/800) and elevated 200_xx avg of ${h(
                v(families, '200_xx').hours_avg
              )}h.`;

        const slipWhy =
          I && I.risk && I.risk.slip_why
            ? I.risk.slip_why
            : `Starts ${starts} vs finishes ${finishes}; completion ${pct(
                completionPct
              )}.`;
        const list = (arr) =>
          Array.isArray(arr) && arr.length
            ? arr.map((x) => `<li>${escapeHtml(x)}</li>`).join('')
            : '<li class="muted">—</li>';
        // NEW: attach a KPI to each action by pulling from suggested_kpis
        function focusRows(focusAreas, suggestedKpis = []) {
          const kpisPool = Array.isArray(suggestedKpis)
            ? suggestedKpis.slice()
            : [];

          const toks = (s) =>
            String(s || '')
              .toLowerCase()
              .match(/[a-z0-9_]+/g) || [];

          // choose a KPI that shares tokens with this focus row; else take first unused
          const takeKpiFor = (fa) => {
            if (!kpisPool.length) return '';
            const hay = new Set(
              toks(`${fa.focus} ${fa.why || ''} ${fa.action || ''}`)
            );
            let idx = kpisPool.findIndex((k) =>
              toks(k).some((w) => hay.has(w))
            );
            if (idx < 0) idx = 0;
            return kpisPool.splice(idx, 1)[0] || '';
          };

          if (!Array.isArray(focusAreas) || !focusAreas.length) {
            return `<tr><td class="muted">—</td><td class="muted">—</td><td class="muted">—</td></tr>`;
          }

          return focusAreas
            .map((x) => {
              const f = escapeHtml(x.focus || '');
              const y = escapeHtml(x.why || '');
              const a = escapeHtml(x.action || '');
              const kpi = takeKpiFor(x);
              const actionWithKpi = kpi
                ? `${a} <span class="muted">KPI: ${escapeHtml(kpi)}</span>`
                : a;
              return `<tr><td>${f}</td><td>${
                y || '—'
              }</td><td>${actionWithKpi}</td></tr>`;
            })
            .join('');
        }

        return `<!doctype html>
<html><head><meta charset="utf-8">
<style>
  body{font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;color:#111;margin:0;padding:24px;}
  h1{font-size:20px;margin:0 0 6px;}
  .muted{color:#6b7280}
  .card{border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:12px 0;background:#fff;}
  .kpi{display:flex;gap:12px;flex-wrap:wrap}
  .pill{background:#f6f6f6;border:1px solid #eee;border-radius:999px;padding:8px 12px;font-weight:600}
  table{width:100%;border-collapse:collapse;margin-top:6px}
  th,td{border-bottom:1px solid #f0f0f0;padding:8px;text-align:left;font-size:12.5px}
  th{background:#fafafa}
  .lbl{width:40%}
  .num{text-align:right;font-variant-numeric:tabular-nums}
  .h2{font-size:14px;margin:14px 0 6px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .section-title{font-weight:700;margin-top:8px}
  .kb ul{margin:6px 0 0 16px;padding:0}
  .kb li{margin:4px 0}
  @media print {.card{page-break-inside:avoid}}
</style>
</head>
<body>
  <h1>Developer Progress Snapshot</h1>
  <div class="muted">Developer: <strong>${
    name || email || '—'
  }</strong> &nbsp;|&nbsp; Report Period: <strong>${period}</strong></div>

  <div class="card">
    <div class="kpi">
      <div class="pill">Ticket Volume: ${ticketVolume}</div>
      <div class="pill">Completion Rate: ${pct(completionPct)}</div>
      <div class="pill">Stalled Tickets: ${stalled}</div>
      <div class="pill">Total Transitions: ${totalTransitions}</div>
      <div class="pill">Avg Cycle-Time: ${h(weightedAvg)}h</div>
    </div>
  </div>

  <div class="card">
    <div class="section-title">Progress Status (Aggregate & Average)</div>
    <table>
      <thead>
        <tr><th class="lbl">Status Codes</th><th class="num">Transitions</th><th class="num">% of Total</th><th class="num">Aggregate Hours</th><th class="num">Avg Cycle-Time</th></tr>
      </thead>
      <tbody>
        ${makeRow('100_xx - Discovery / Starting Work', '100_xx')}
        ${makeRow('200_xx - In-Progress Development', '200_xx')}
        ${makeRow('300_xx - Testing / Debugging', '300_xx')}
        ${makeRow('400_xx - Peer / Code Review', '400_xx')}
        ${makeRow('500_xx - Completion / Handoffs', '500_xx')}
        ${makeRow('600_xx - Challenges', '600_xx')}
        ${makeRow('700_xx - Investigation', '700_xx')}
        ${makeRow('800_xx - Delays', '800_xx')}
      </tbody>
    </table>
    <div class="muted" style="margin-top:6px; font-size: 0.8rem;">Average cycle-time = Aggregate Hours ÷ Transitions per family; durations clipped to the report window.</div>
  </div>

  <div class="grid">
  <div class="card kb">
  <div class="section-title">Key Takeaways</div>
  <ul>
    ${(() => {
      // Reuse escapeHtml, v(), h(), I, families, and the computed starts/finishes/blockers/reviews/testing in scope.

      const pickInsight = (regexes, fallback) => {
        const pool = [];
        if (I?.key_findings?.length) pool.push(...I.key_findings);
        if (I?.strengths?.length) pool.push(...I.strengths);
        if (I?.focus_areas?.length) {
          pool.push(
            ...I.focus_areas.map(
              (f) => `${f.focus} ${f.why || ''} ${f.action || ''}`
            )
          );
        }
        if (I?.risk) {
          pool.push(`stall ${I.risk.stall_risk}`, `slip ${I.risk.slip_risk}`);
        }
        const found = pool.find((s) => {
          const t = String(s || '').toLowerCase();
          return regexes.some((re) => re.test(t));
        });
        return escapeHtml(found || fallback);
      };

      // Baselines for numbers we show:
      const inprog = v(families, '200_xx').transitions || 0;
      const avg200 = h(v(families, '200_xx').hours_avg || 0);
      const avg300 = h(v(families, '300_xx').hours_avg || 0);

      // Themed AI tails (fallbacks keep it sensible if no AI insight was produced)
      const tail1 = pickInsight(
        [/finish|500_xx|throughput|complete|conversion|delivery/],
        finishes >= starts
          ? 'throughput kept pace'
          : 'consider more pushes to 500_xx'
      );
      const tail2 = pickInsight(
        [/600|800|block|delay|stall|unblock|dependency/],
        'target reduction'
      );
      const fallbackRT = `${
        reviews > 0 ? 'Code reviews visible' : 'Surface PR reviews (400_xx)'
      }; Testing ${testing > 0 ? 'active' : 'light'}`;
      const tail3 = pickInsight(
        [/review|400_xx|\bpr\b|testing|qa|300_xx/],
        fallbackRT
      );
      const tail4 = pickInsight(
        [/200|wip|in[- ]progress|flow|context|multitask|batch|queue/],
        'keep WIP small to improve flow'
      );
      const tail5 = pickInsight(
        [/cycle|lead[- ]?time|avg|aging|wait|stall|slip|flow time|latency/],
        I?.risk
          ? `risk — stall ${escapeHtml(I.risk.stall_risk)}, slip ${escapeHtml(
              I.risk.slip_risk
            )}`
          : 'watch cycle-time averages'
      );
      // If AI is active (I exists) -> overall; else -> per-family 200/300
      const cycleLine = I
        ? `overall avg ${h(weightedAvg)}h; ${tail5}`
        : `200_xx avg ${avg200}h, 300_xx avg ${avg300}h; ${tail5}`;

      return `
        <li><b>Starts vs Finishes:</b> ${starts} vs ${finishes}; ${tail1}.</li>
        <li><b>Blocked/Delays footprint:</b> ${blockers} transitions (600/800); ${tail2}.</li>
        <li><b>Reviews/Testing:</b> ${tail3}.</li>
        <li><b>WIP/Flow balance:</b> ${inprog} transitions (200_xx); ${tail4}.</li>
        <li><b>Cycle-time signals:</b> ${cycleLine}.</li>

      `;
    })()}
  </ul>
</div>



      <div class="card kb">
    <div class="section-title">What's Working Well</div>
    <ul>
      ${
        I
          ? list(I.strengths)
          : `
      <li>${
        finishes > 0
          ? 'Conversion to 500_xx completions is consistent'
          : 'Good groundwork in early stages (100/200)'
      }.</li>
      <li>${
        testing > 0
          ? 'Testing cadence (300_xx) present'
          : 'Primary dev flow focus is clear'
      }.</li>
      `
      }
    </ul>
  </div>

  </div>

    <div class="card kb">
    <div class="section-title">Focus Areas</div>
    <table>
      <thead><tr><th>Focus</th><th>Why it Matters</th><th>Concrete Action (Next Month)</th></tr></thead>
      <tbody>
        ${
          I
            ? focusRows(I.focus_areas, I.suggested_kpis)
            : `
        <tr><td>Limit WIP</td><td>High time in 200_xx inflates cycle-time.</td><td>Cap concurrent tickets at 3; KPI: reduce 200_xx avg to ≤ 6h.</td></tr>
        <tr><td>Unblock Faster</td><td>600/800 footprint increases stall risk.</td><td>Daily chase with owners; KPI: cut 800_xx transitions by 25%.</td></tr>
        <tr><td>Make Reviews Visible</td><td>Low 400_xx hinders flow.</td><td>Post PR links; KPI: ≥ 1 review transition per completed ticket.</td></tr>
        `
        }
      </tbody>
    </table>


    
  </div>


    <div class="card kb">
    <div class="section-title">Support from Team Leads</div>
    <ul>
      ${
        I &&
        Array.isArray(I.support_from_team_leads) &&
        I.support_from_team_leads.length
          ? list(I.support_from_team_leads)
          : '<li>WIP coaching, shared escalation path, daily 15-min review window.</li>'
      }
    </ul>
  </div>

  <div class="card kb">
    <div class="section-title">Risk Signals</div>
    ${
      I && I.risk
        ? `<ul>
            <li><strong>Stall:</strong> ${escapeHtml(
              I.risk.stall_risk
            )} — <span class="muted">${escapeHtml(stallWhy)}</span></li>
            <li><strong>Slip:</strong> ${escapeHtml(
              I.risk.slip_risk
            )} — <span class="muted">${escapeHtml(slipWhy)}</span></li>
           </ul>`
        : `<ul>
            <li><strong>Stall:</strong> — <span class="muted">${escapeHtml(
              stallWhy
            )}</span></li>
            <li><strong>Slip:</strong> — <span class="muted">${escapeHtml(
              slipWhy
            )}</span></li>
           </ul>`
    }
  </div>

</body></html>`;
      }

      // Load display names (nice header)
      const namesByEmail = new Map();
      const emails = rowsF.map((r) => S(r.email).toLowerCase()).filter(Boolean);

      if (emails.length) {
        const { rows: users } = await pool.query(
          `select lower(email) as email, coalesce(nullif(name,''), '') as name from users where lower(email) = any($1)`,
          [emails]
        );
        users.forEach((u) => namesByEmail.set(u.email, u.name || ''));
      }

      const docs = rowsF.map((r) =>
        renderSnapshotHTML({
          name: namesByEmail.get((r.email || '').toLowerCase()) || '',
          email: r.email,
          period: periodLabel,
          ticketVolume: Number(r.ticket_volume) || 0,
          completionPct: Number(r.completion_pct) || 0,
          stalled: Number(r.stalled_tickets) || 0,
          families: r.families || {},
          insights:
            insightsByEmail.get(String(r.email || '').toLowerCase()) || null, // NEW
        })
      );

      if (format === 'html') {
        return res
          .type('html')
          .send(docs.join("<div style='page-break-after:always'></div>"));
      }

      // PDF (one multi-page file)
      const puppeteer = await import('puppeteer');
      const browser = await puppeteer.launch({
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
        ],
      });

      const stripOuter = (html) =>
        String(html || '')
          .replace(/^<!doctype html>/i, '')
          .replace(/<\/body>\s*<\/html>\s*$/i, '')
          .replace(/^[\s\S]*?<body[^>]*>/i, ''); // keep only <body> inner

      const pages = docs
        .map(stripOuter)
        .join("<div style='page-break-after:always'></div>");

      const shell = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    @page { size: A4; margin: 20mm 16mm; }
    body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    ${SNAPSHOT_CSS}
  </style>
</head>
<body>${pages}</body>
</html>`;

      const page = await browser.newPage();
      await page.setContent(shell, { waitUntil: 'networkidle0' });
      const pdfRaw = await page.pdf({
        format: 'A4',
        printBackground: true,
        margin: { top: '20mm', right: '16mm', bottom: '20mm', left: '16mm' },
      });
      await browser.close();

      // Coerce to a Node Buffer (Puppeteer can return a Uint8Array in some setups)
      const buf = Buffer.isBuffer(pdfRaw)
        ? pdfRaw
        : ArrayBuffer.isView(pdfRaw)
        ? Buffer.from(pdfRaw)
        : Buffer.from(pdfRaw ?? []);

      // Signature + header check
      if (buf.length < 5 || buf.toString('ascii', 0, 5) !== '%PDF-') {
        console.error(
          '[snapshots] invalid PDF payload, first bytes:',
          Array.from(buf.slice(0, 16)).join(',')
        );
        return res.status(500).json({ error: 'pdf_generation_failed' });
      }

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="Developer-Snapshots_${fileDevPart}${fromISO}_to_${toISO}.pdf"`
      );

      res.setHeader('Cache-Control', 'no-store, no-transform');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Length', String(buf.length));
      return res.end(buf); // avoid implicit string conversion
    } catch (e) {
      console.error('[snapshots] error:', e);
      res.status(500).json({ error: 'snapshot_failed', detail: String(e) });
    }
  }
);

// --- Helper: derive last N iterations from current_iteration path ------------
function deriveIterationPaths(currentPath, count) {
  if (!currentPath || !count) return [];
  const trimmed = String(currentPath).trim();
  const match = trimmed.match(/^(.*?)(\d+)\s*$/);
  if (!match) return [];
  const prefix = match[1];
  const baseNum = parseInt(match[2], 10);
  if (!Number.isFinite(baseNum)) return [];
  const out = [];
  for (let i = 0; i < count; i += 1) {
    out.push(`${prefix}${baseNum - i}`);
  }
  return out;
}

// --- Helper: count weekdays inclusive (Mon–Fri) ------------------------------
function countWeekdays(fromISO, toISO) {
  const start = new Date(`${fromISO}T00:00:00Z`);
  const end = new Date(`${toISO}T00:00:00Z`);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return 0;
  let days = 0;
  for (
    let d = new Date(start.getTime());
    d <= end;
    d = new Date(d.getTime() + 24 * 3600 * 1000)
  ) {
    const dow = d.getUTCDay(); // 0=Sun, 6=Sat
    if (dow !== 0 && dow !== 6) days += 1;
  }
  return days;
}

// --- PM: Top Developers ranking ---------------------------------------------
async function computeTopDevs({ mode = 'iterations', windowCount = 4, stallHours = 12 } = {}) {
  const today = todayISO();
  const MAX_DAYS = 90;
  let fromISO = addDays(today, -27); // default 28-day window
  let iterationPaths = null;
  let windowModeUsed = 'weeks';

  if (mode === 'iterations') {
    const currIter = await pool.query(
      `select value from meta where key='current_iteration' limit 1`
    );
    const currPath = currIter.rows[0]?.value || '';
    const derived = deriveIterationPaths(currPath, windowCount);
    if (derived.length) {
      iterationPaths = derived.map((s) => s.toLowerCase());
      windowModeUsed = 'iterations';
      fromISO = addDays(today, -MAX_DAYS); // keep within 90-day cap
    }
  }

  const spanDays = Math.floor(
    (Date.parse(today) - Date.parse(fromISO)) / 86400000
  );
  if (!Number.isFinite(spanDays) || spanDays < 0 || spanDays > MAX_DAYS) {
    const err = new Error(`Range too large (max ${MAX_DAYS} days)`);
    err.status = 400;
    throw err;
  }

  const sql = `
      with windowed as (
        select
          email as dev,
          ticket_id,
          code,
          at AT TIME ZONE $3 as ts_local,
          lead(at) over (partition by ticket_id order by at) AT TIME ZONE $3 as next_ts_local
        from progress_updates
        where at >= ($1::timestamptz - interval '7 days')
          and at <  ($2::timestamptz + interval '1 day')
          and (
            $5::text[] is null
            or exists (
              select 1 from tickets t
              where t.id = progress_updates.ticket_id
                and lower(t.iteration_path) = any($5)
            )
          )
      ),
      segments as (
        select
          dev, ticket_id, code, ts_local,
          greatest(ts_local, $1::date AT TIME ZONE $3) as seg_start,
          least(coalesce(next_ts_local, $2::date AT TIME ZONE $3), $2::date AT TIME ZONE $3) as seg_end
        from windowed
      ),
      usable as (
        select *,
               case when seg_end > seg_start
                 then extract(epoch from (seg_end - seg_start))/3600.0
                 else 0 end as hours
        from segments
        where seg_end > seg_start
      ),
      coded as (
        select
          dev, ticket_id,
          split_part(code,'_',1) || '_xx' as family,
          hours,
          ts_local::date as day
        from usable u
        where ($5::text[] is null
          or exists (
            select 1 from tickets t where t.id = u.ticket_id and lower(t.iteration_path)=any($5)
          ))
      ),
      per_dev_family as (
        select dev, family,
               count(*) as transitions,
               sum(hours) as hours_sum,
               case when count(*)>0 then sum(hours)/count(*) else 0 end as hours_avg
        from coded
        group by dev, family
      ),
      ticket_touch as (
        select dev, count(distinct ticket_id) as ticket_volume
        from coded
        group by dev
      ),
      completion as (
        select dev,
               count(distinct ticket_id) filter (where family='500_xx') as completed_tickets,
               count(distinct ticket_id) as touched_tickets
        from coded
        group by dev
      ),
      latest_ticket as (
        select distinct on (ticket_id)
          ticket_id,
          at AT TIME ZONE $3 as last_ts_local,
          split_part(code,'_',1) || '_xx' as last_family
        from progress_updates
        where at <= ($2::timestamptz)
          and (
            $5::text[] is null
            or exists (
              select 1 from tickets t where t.id = progress_updates.ticket_id and lower(t.iteration_path)=any($5)
            )
          )
        order by ticket_id, at desc
      ),
      stalled as (
        select c.dev, count(distinct c.ticket_id) as stalled_tickets
        from coded c
        join latest_ticket lt on lt.ticket_id = c.ticket_id
        where lt.last_ts_local between ($1::date AT TIME ZONE $3) and ($2::date AT TIME ZONE $3)
          and lt.last_family in ('200_xx','600_xx','800_xx')
          and (($2::date AT TIME ZONE $3) - lt.last_ts_local) >= (interval '1 hour' * $4::int)
        group by c.dev
      ),
      blockers as (
        select dev, sum(transitions) as blocker_transitions
        from per_dev_family
        where family in ('600_xx','800_xx')
        group by dev
      ),
      daily_finishes as (
        select dev, day, count(distinct ticket_id) as finishes
        from coded
        where family='500_xx'
        group by dev, day
      ),
      finish_variance as (
        select dev, stddev_pop(finishes) as finish_stddev
        from daily_finishes
        group by dev
      ),
      updates as (
        select email as dev, count(*) as updates_count
        from progress_updates
        where at >= ($1::timestamptz) and at <= ($2::timestamptz + interval '1 day')
          and (
            $5::text[] is null
            or exists (
              select 1 from tickets t where t.id = progress_updates.ticket_id and lower(t.iteration_path)=any($5)
            )
          )
        group by email
      )
      select
        p.dev as email,
        jsonb_object_agg(p.family, jsonb_build_object(
          'transitions', p.transitions,
          'hours_sum', round(p.hours_sum::numeric, 2),
          'hours_avg', round(p.hours_avg::numeric, 2)
        )) as families,
        coalesce(t.ticket_volume,0) as ticket_volume,
        coalesce(c.completed_tickets,0) as completed_tickets,
        coalesce(c.touched_tickets,0) as touched_tickets,
        case when coalesce(c.touched_tickets,0)>0
             then round(100.0*c.completed_tickets/c.touched_tickets,1) else 0 end as completion_pct,
        coalesce(s.stalled_tickets,0) as stalled_tickets,
        coalesce(b.blocker_transitions,0) as blocker_transitions,
        coalesce(u.updates_count,0) as updates_count,
        coalesce(f.finish_stddev,0) as finish_stddev
      from per_dev_family p
      left join ticket_touch t on t.dev = p.dev
      left join completion   c on c.dev = p.dev
      left join stalled      s on s.dev = p.dev
      left join blockers     b on b.dev = p.dev
      left join updates      u on u.dev = p.dev
      left join finish_variance f on f.dev = p.dev
      group by p.dev, t.ticket_volume, c.completed_tickets, c.touched_tickets,
               s.stalled_tickets, b.blocker_transitions, u.updates_count, f.finish_stddev
      order by p.dev;
      `;

  const { rows } = await pool.query(sql, [
    fromISO,
    today,
    APP_TZ,
    stallHours,
    iterationPaths,
  ]);

  const eligible = rows.filter((r) => Number(r.completed_tickets || 0) >= 3);

  const metricArray = (fn) => eligible.map(fn).filter((v) => v != null);
  const meanStd = (arr) => {
    if (!arr.length) return { mean: 0, std: 0 };
    const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
    const variance =
      arr.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / arr.length;
    return { mean, std: Math.sqrt(variance) };
  };

  const cycleValue = (r) => {
    const fam = r.families || {};
    const keys = ['200_xx', '300_xx', '400_xx'];
    const sum = keys.reduce(
      (s, k) => s + (Number(fam[k]?.hours_sum) || 0),
      0
    );
    const trans = keys.reduce(
      (s, k) => s + (Number(fam[k]?.transitions) || 0),
      0
    );
    return trans > 0 ? sum / trans : null;
  };

  const blockerRateVal = (r) => {
    const vol = Math.max(Number(r.ticket_volume) || 0, 1);
    return (Number(r.blocker_transitions) || 0) / vol;
  };

  const stats = {
    throughput: meanStd(metricArray((r) => Number(r.completed_tickets) || 0)),
    completion: meanStd(metricArray((r) => Number(r.completion_pct) || 0)),
    cycle: meanStd(metricArray(cycleValue)),
    blocker: meanStd(metricArray(blockerRateVal)),
  };

  const weights = {
    throughput: 0.35,
    completion: 0.25,
    cycle: 0.2,
    blocker: 0.2,
  };

  const workingDays = countWeekdays(fromISO, today) || 0;

  const scored = rows.map((r) => {
    const families = r.families || {};
    const finished = Number(r.completed_tickets) || 0;
    const ticketVolume = Number(r.ticket_volume) || 0;
    const completionPct = Number(r.completion_pct) || 0;

    const cycleTime = cycleValue(r);
    const blockerRate = blockerRateVal(r);

    const z = (val, mean, std) =>
      std > 0 && val != null ? (val - mean) / std : 0;

    const zThroughput = z(finished, stats.throughput.mean, stats.throughput.std);
    const zCompletion = z(completionPct, stats.completion.mean, stats.completion.std);
    const zCycle =
      cycleTime != null ? -z(cycleTime, stats.cycle.mean, stats.cycle.std) : 0;
    const zBlocker = -z(blockerRate, stats.blocker.mean, stats.blocker.std);

    const score =
      weights.throughput * zThroughput +
      weights.completion * zCompletion +
      weights.cycle * zCycle +
      weights.blocker * zBlocker;

    const updatesCount = Number(r.updates_count) || 0;
    const updateCoverage =
      workingDays > 0 ? +(updatesCount / workingDays).toFixed(2) : 0;

    const consistency = Number(r.finish_stddev) || 0;

    return {
      email: r.email,
      score: Number.isFinite(score) ? +score.toFixed(3) : 0,
      zScores: {
        throughput: +zThroughput.toFixed(3),
        completion: +zCompletion.toFixed(3),
        cycle: +zCycle.toFixed(3),
        blocker: +zBlocker.toFixed(3),
      },
      metrics: {
        throughput: finished,
        completion_pct: completionPct,
        cycle_time_hours: cycleTime != null ? +cycleTime.toFixed(2) : null,
        blocker_rate: +blockerRate.toFixed(3),
        blocker_transitions: Number(r.blocker_transitions) || 0,
        ticket_volume: ticketVolume,
        touched_tickets: Number(r.touched_tickets) || 0,
        stalled_tickets: Number(r.stalled_tickets) || 0,
        consistency_stddev: +consistency.toFixed(3),
        update_coverage: updateCoverage,
        updates_count: updatesCount,
      },
      lowSample: finished < 3,
    };
  });

  const eligibleScored = scored.filter((r) => !r.lowSample);
  eligibleScored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return (a.metrics.consistency_stddev || 0) - (b.metrics.consistency_stddev || 0);
  });

  const result = eligibleScored.concat(scored.filter((r) => r.lowSample));

  return {
    items: result,
    weights,
    windowUsed: {
      mode: windowModeUsed,
      from: fromISO,
      to: today,
      iterations: iterationPaths || [],
    },
    eligibleCount: eligibleScored.length,
  };
}

app.get(
  '/api/reports/top-devs',
  requireAuth,
  requirePMOnly,
  async (req, res) => {
    try {
      const mode = (req.query.mode || 'iterations').toLowerCase();
      const windowCount = Math.max(parseInt(req.query.window, 10) || 4, 1);
      const stallHours = parseInt(req.query.stallHours, 10) || 12;

      const computed = await computeTopDevs({ mode, windowCount, stallHours });

      if (computed.eligibleCount < 3) {
        return res.status(400).json({
          error: 'insufficient_data',
          detail: 'Not enough finished tickets to rank reliably',
          windowUsed: computed.windowUsed,
        });
      }

      res.json({
        items: computed.items,
        weights: computed.weights,
        windowUsed: computed.windowUsed,
      });
    } catch (e) {
      const status = e.status || 500;
      console.error('[top-devs] error', e);
      res.status(status).json({
        error: 'top_devs_failed',
        detail: String(e.message || e),
      });
    }
  }
);

// PM: Insight per developer (plain-language, AI-backed with fallback)
app.get(
  '/api/reports/top-devs/insight',
  requireAuth,
  requirePMOnly,
  async (req, res) => {
    try {
      const mode = (req.query.mode || 'iterations').toLowerCase();
      const developer = String(req.query.developer || '').toLowerCase().trim();
      const windowCount = Math.max(parseInt(req.query.window, 10) || 4, 1);
      const stallHours = parseInt(req.query.stallHours, 10) || 12;

      if (!developer)
        return res.status(400).json({ error: 'developer_required' });

      const computed = await computeTopDevs({ mode, windowCount, stallHours });
      const item = (computed.items || []).find(
        (r) => String(r.email || '').toLowerCase() === developer
      );

      if (!item)
        return res.status(404).json({ error: 'developer_not_found', windowUsed: computed.windowUsed });

      const coverage = item.metrics.update_coverage;
      const lowCoverage = coverage < 0.5;

      const fallbackInsight = () => {
        const lines = [];
        if (item.lowSample) {
          lines.push('Not ranked because fewer than 3 finished items in this window; treat as informational.');
        } else {
          lines.push('Overall: Score relative to team average; higher is better.');
        }
        lines.push(`Throughput: ${item.metrics.throughput} finished items; completion ${item.metrics.completion_pct.toFixed(1)}%.`);
        if (item.metrics.cycle_time_hours != null)
          lines.push(`Speed: Typical cycle time about ${item.metrics.cycle_time_hours.toFixed(1)} hours.`);
        lines.push(`Blockers: Blocker rate ${item.metrics.blocker_rate.toFixed(3)} (lower is better).`);
        lines.push(`Consistency: Daily finish variability σ = ${item.metrics.consistency_stddev.toFixed(2)} (lower = steadier).`);
        lines.push(`Update coverage: ${coverage.toFixed(2)} updates/weekday${lowCoverage ? ' (low — data may understate activity)' : ''}.`);
        lines.push('Next step: Focus on clearing blockers early and finishing a higher share of started items.');
        return lines;
      };

      let insightLines = fallbackInsight();
      let usedAI = false;

      if (!item.lowSample && openai) {
        try {
          const prompt = [
            `You are writing a short status for managers (non-technical).`,
            `Keep it concise and factual. No buzzwords. No invented data.`,
            `Window: ${computed.windowUsed.from} to ${computed.windowUsed.to}. Mode: ${computed.windowUsed.mode}.`,
            `Metrics (already calculated, do not recompute):`,
            `- score: ${item.score}`,
            `- throughput: ${item.metrics.throughput}`,
            `- completion_pct: ${item.metrics.completion_pct}`,
            `- cycle_time_hours: ${item.metrics.cycle_time_hours}`,
            `- blocker_rate: ${item.metrics.blocker_rate}`,
            `- consistency_stddev: ${item.metrics.consistency_stddev}`,
            `- update_coverage: ${coverage}`,
            `- low_sample: ${item.lowSample}`,
            `Guidelines:`,
            `- Start with Overall. Then Throughput/Completion, Speed, Blockers, Consistency, Update coverage.`,
            `- Use plain language; keep each bullet short.`,
            `- If data quality is low (low_sample=true or update_coverage<0.5), say so explicitly.`,
            `- Include one clear next step tailored to the metrics (e.g., reduce blockers, raise completion, improve updates).`,
          ].join('\n');

          const resp = await openai.chat.completions.create({
            model: OPENAI_MODEL,
            messages: [
              { role: 'system', content: 'You write concise status bullets for managers. 4-7 bullets max.' },
              { role: 'user', content: prompt },
            ],
            max_tokens: 250,
          });

          const text = (resp.choices?.[0]?.message?.content || '').trim();
          if (text) {
            insightLines = text
              .split('\n')
              .map((s) => s.replace(/^[\-\*\u2022]\s*/, '').trim())
              .filter(Boolean);
            usedAI = true;
          }
        } catch (e) {
          console.warn('[top-devs/insight] AI fallback', e.message);
          usedAI = false;
        }
      }

      res.json({
        insight: insightLines,
        usedAI,
        item,
        windowUsed: computed.windowUsed,
      });
    } catch (e) {
      const status = e.status || 500;
      console.error('[top-devs/insight] error', e);
      res.status(status).json({
        error: 'top_dev_insight_failed',
        detail: String(e.message || e),
      });
    }
  }
);

// Email Developer Progress Snapshot
app.post(
  '/api/reports/snapshots/email',
  requireAuth,
  requirePMOnly,
  async (req, res) => {
    try {
      console.log('[/api/reports/snapshots/email] Request received');
      const {
        developer = 'all',
        developerLabel = '',
        fromDate,
        toDate,
        ai = '0',
        cc = [],
      } = req.body || {};

      const from = parseDateParam(fromDate, todayISO());
      const to = parseDateParam(toDate, from);

      console.log('[snapshot/email] Building email content...');
      // Build the HTML & PDF via existing helper
      const { subject, html, attachments } = await buildSnapshotEmail(
        req,
        { from, to, developer, developerLabel },
        { ai: String(ai) === '1' }
      );
      console.log('[snapshot/email] Email content built successfully');

      // Resolve main recipient from dev/label using your DB (tfs_users/users)
      const toEmail = await resolveRecipientEmail(
        pool,
        developer,
        developerLabel
      );
      const toList = toEmail ? [toEmail] : []; // no-op if "all"
      // Merge CCs from the request and from env; dedupe
      const ccFromBody = normalizeEmails(cc);
      const ccFromEnv = normalizeEmails(SNAPSHOT_CC);
      const ccList = Array.from(new Set([...ccFromEnv, ...ccFromBody]));

      console.log('[snapshot/email] Recipients - to:', toList, 'cc:', ccList);

      // If developer=all and no toEmail, just send to CCs (PM/team leads)
      if (!toList.length && !ccList.length) {
        return res.status(400).json({
          error: 'no recipients (developer unresolved and no CC provided)',
        });
      }

      console.log('[snapshot/email] Sending email via', MAIL_MODE, 'mode...');
      const info = await sendEmail({
        to: toList,
        cc: ccList,
        subject,
        html,
        attachments,
      });
      console.log('[snapshot/email] Email sent successfully');
      res.json(info);
    } catch (e) {
      console.error('[snapshot/email] Error:', e);
      res.status(500).json({ error: String(e.message || e) });
    }
  }
);

// --- blockers radar
app.get('/api/updates/blockers', async (_req, res) => {
  const date = await todayLocal(pool);
  const r = await pool.query(
    `select u.ticket_id as "ticketId", u.email, u.code, u.note, u.at, u.risk_level as "riskLevel",
         t.title, t.state, t.type, t.severity,
         t.state_change_date as "stateChangeDate",
         t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
     from progress_updates u
     left join tickets t on t.id = u.ticket_id
     where u.date = $1`,
    [date]
  );
  // const isBlockerCode = (c) => c && /^(600|700|800)_/.test(String(c));
  const hits = [];
  for (const x of r.rows) {
    const txt = `${x.code} ${x.note || ''}`.toLowerCase();
    const kw = blockerKeywords.find((k) => k && txt.includes(k));
    if (isBlockerCode(x.code) || kw) {
      const derived = deriveRiskForUpdate(x);
      x.riskLevel = derived.riskLevel;
      x.riskReasons = derived.riskReasons;
      x.riskStaleDays = derived.staleDays;
      hits.push({ ...x, keyword: isBlockerCode(x.code) ? 'code' : kw || '' });
    }
  }
  // latest per ticket
  const byTicket = new Map();
  for (const h of hits) {
    const prev = byTicket.get(String(h.ticketId));
    if (!prev || h.at > prev.at) byTicket.set(String(h.ticketId), h);
  }
  const items = Array.from(byTicket.values());
  res.json({ date, keywords: blockerKeywords, items });
});

// --- progress codes (dynamic)

// JSON: return codes + metadata
app.get('/api/progress-codes', async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT code, label, family,
           require_note AS "requireNote",
           active, sort_order AS "order",
           updated_at AS "updatedAt"
    FROM progress_codes
    WHERE active = true
    ORDER BY sort_order, code
  `);
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json({ version: new Date().toISOString(), items: rows });
});

// HTMX: return just the <option> HTML (grouped by family)
app.get('/api/ui/progress-codes/options', async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT code, label, family, require_note
    FROM progress_codes
    WHERE active = true
    ORDER BY sort_order, code
  `);

  const byFam = rows.reduce((acc, r) => {
    (acc[r.family] ||= []).push(r);
    return acc;
  }, {});

  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.type('html');

  let html = '';
  Object.keys(byFam)
    .sort()
    .forEach((fam) => {
      html += `<optgroup label="${fam}">`;
      byFam[fam].forEach((r) => {
        html += `<option value="${r.code}" data-requirenote="${
          r.require_note ? 'true' : 'false'
        }">${r.code} — ${escapeHtml(r.label)}</option>`;
      });
      html += `</optgroup>`;
    });
  res.send(html);
});

// --- AI triage for blockers (per-row or bulk). PM section already gated in UI, but require auth.
// --- AI triage (explicit list only; "triage-all" fallback removed)
app.post('/api/ai/triage', requireAuth, async (req, res) => {
  try {
    if (!openai) return res.status(501).json({ error: 'ai_not_configured' });

    // Require an explicit list of items; no implicit DB fallback anymore.
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    if (!items.length) {
      return res.status(400).json({
        status: 'error',
        error: 'items_required',
        message:
          'Provide items:[...] with ticket context to triage. Bulk/implicit triage has been removed.',
      });
    }

    const suggestions = await aiTriage(items);
    return res.json({ status: 'ok', count: suggestions.length, suggestions });
  } catch (e) {
    const http = e?.status || e?.response?.status || 500;
    console.error('[ai/triage] error:', {
      status: http,
      code: e?.code,
      message: e?.message,
      data: e?.response?.data,
      raw: e?.error || null,
    });
    return res.status(http).json({
      status: 'error',
      error: e?.message || 'server_error',
      code: e?.code || null,
      openai: e?.response?.data || e?.error || null,
    });
  }
});

// --- AI: Dev Assist (chase draft + next steps) -------------------------------

// If you already declared a scrub() helper, we reuse it. Otherwise define a no-op.
const __hasScrub = typeof scrub === 'function';
const _scrub = __hasScrub ? scrub : (s) => String(s || '');

// Small schemas for strict JSON output
const ChaseDraftSchema = {
  name: 'ChaseDraft',
  strict: false, // allow optional fields
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      chase_text: { type: 'string' },
      who: { type: 'string' },
      tone: { type: 'string', enum: ['neutral', 'friendly', 'polite'] },
    },
    required: ['chase_text'],
  },
};

const NextStepsSchema = {
  name: 'NextSteps',
  strict: true,
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      next_steps: {
        type: 'array',
        items: { type: 'string' },
        minItems: 2,
        maxItems: 6,
      },
    },
    required: ['next_steps'],
  },
};
// --- AI: Snapshot Insights (used by /api/reports/snapshots?ai=1) -------------
const SnapshotInsightsSchema = {
  name: 'SnapshotInsights',
  strict: false,
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      key_findings: {
        type: 'array',
        items: { type: 'string' },
        minItems: 3,
        maxItems: 6,
      },
      strengths: {
        type: 'array',
        items: { type: 'string' },
        minItems: 1,
        maxItems: 5,
      },
      focus_areas: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            focus: { type: 'string' },
            why: { type: 'string' },
            action: { type: 'string' },
          },
          required: ['focus', 'action'],
        },
        minItems: 1,
        maxItems: 5,
      },
      suggested_kpis: {
        type: 'array',
        items: { type: 'string' },
        minItems: 1,
        maxItems: 5,
      },
      risk: {
        type: 'object',
        additionalProperties: false,
        properties: {
          stall_risk: { type: 'string', enum: ['low', 'medium', 'high'] },
          slip_risk: { type: 'string', enum: ['low', 'medium', 'high'] },
          stall_why: { type: 'string' }, // NEW (optional)
          slip_why: { type: 'string' }, // NEW (optional)
        },
        required: ['stall_risk', 'slip_risk'],
      },
      // Optional, not required to keep compatibility
      support_from_team_leads: {
        type: 'array',
        items: { type: 'string' },
        minItems: 1,
        maxItems: 3,
      },
    },
    required: ['key_findings', 'strengths', 'focus_areas', 'risk'],
  },
};
const SNAPSHOT_PROMPT_VERSION = 'snapshot_v3_rag_delta_2025-03-08';
const SNAPSHOT_EVIDENCE_MAX_TICKETS = 12;
const SNAPSHOT_RUN_RETENTION = Math.max(
  0,
  parseInt(process.env.SNAPSHOT_RUN_RETENTION || '50', 10) || 50
);

// Minimal helper to call OpenAI for one developer's metrics + evidence
async function aiSnapshotInsightsForDev({
  periodLabel,
  metrics,
  fromISO,
  toISO,
  devEmail,
  devLocal,
}) {
  if (!openai)
    throw Object.assign(new Error('AI not configured'), { status: 501 });

  const fams = metrics.families || {};
  const famKeys = [
    '100_xx',
    '200_xx',
    '300_xx',
    '400_xx',
    '500_xx',
    '600_xx',
    '700_xx',
    '800_xx',
  ];
  const totH = famKeys.reduce((s, k) => s + (fams[k]?.hours_sum || 0), 0);
  const totT = famKeys.reduce((s, k) => s + (fams[k]?.transitions || 0), 0);
  const overallAvg = totT ? +(totH / totT).toFixed(2) : 0;
  const metricsSummary = summarizeSnapshotMetrics(metrics, overallAvg);

  const emailKey = String(devEmail || metrics.email || '').toLowerCase();
  const localKey = String(devLocal || toLocalPart(emailKey) || '').toLowerCase();
  let evidence = null;
  let priorInsights = null;
  let deltaSummary = null;
  if (fromISO && toISO && (emailKey || localKey)) {
    evidence = await buildSnapshotEvidence({
      fromISO,
      toISO,
      devEmail: emailKey || null,
      devLocal: localKey || null,
    });
    const history = await loadSnapshotHistory(emailKey, fromISO);
    const priorAny = history.priorAny ? history.priorAny : null;
    const priorPeriod = history.priorPeriod ? history.priorPeriod : null;
    if (priorAny?.ai_output) {
      priorInsights = trimSnapshotInsights(parseJsonMaybe(priorAny.ai_output));
    }
    if (priorPeriod?.metrics_summary) {
      const prevMetrics = parseJsonMaybe(priorPeriod.metrics_summary);
      deltaSummary = buildSnapshotDelta(
        metricsSummary,
        prevMetrics,
        priorPeriod.period_label
      );
    }
  }

  // Keep payload tidy and grounded on your computed aggregates
  const trimmed = {
    period: periodLabel,
    email: String(metrics.email || ''),
    ticket_volume: Number(metrics.ticket_volume || 0),
    completion_pct: Number(metrics.completion_pct || 0),
    stalled_tickets: Number(metrics.stalled_tickets || 0),
    families: metrics.families || {}, // { '100_xx': { transitions, hours_sum, hours_avg }, ... }
    overall_avg_cycle_time: overallAvg,
  };

  const system = `You are a delivery PM analyzing a developer's progress snapshot.
You receive per-family metrics (100_xx..800_xx: transitions, hours_sum, hours_avg), ticket_volume, completion_pct, stalled_tickets,
plus evidence_summary (top tickets + last updates + blocker themes), delta_summary (changes vs prior snapshot), and prior_insights.

Write concise outputs:
- key_findings: 3-5 bullets (throughput, bottlenecks, balance across 100/200/300/400/500, blocker footprint 600/800).
- strengths: 2-5 bullets.
- focus_areas: 1-5 (each with <focus>, optional <why>, and concrete <action> for next month).
- suggested_kpis: <=5 compact KPI statements (e.g., "Reduce 800_xx transitions by 25%").
- risk: stall_risk & slip_risk = low/medium/high inferred from metrics, plus stall_why and slip_why (one-line, data-grounded reasons).
- support_from_team_leads: 1-3 bullets, written as actions for the team lead/manager (not the developer), each <=20 words, concrete, next-week scope (cadence, escalations, pairing, env access, PR gates, 10-15 min unblock huddles).

Grounding rules (strict):
- If you mention a specific ticket, include its ID in parentheses.
- Use evidence_summary or metrics; do NOT invent facts.
- Use delta_summary to highlight changes; avoid repeating prior_insights unless a metric regressed or a ticket remains stalled.
- If evidence is thin, say so briefly and focus on metrics only.

You also receive overall_avg_cycle_time (weighted across all families). Prefer it when summarizing "Cycle-time signals" and risk rationales.
Keep outputs brief and practical, using the team's progress families.`;

  const user = `Developer period: ${trimmed.period}
Input JSON:
${JSON.stringify({
  metrics: trimmed,
  evidence_summary: evidence,
  delta_summary: deltaSummary,
  prior_insights: priorInsights,
})}`;

  const resp = await openai.chat.completions.create({
    model: OPENAI_MODEL,
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: user },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: SnapshotInsightsSchema.name,
        schema: SnapshotInsightsSchema.schema,
        strict: !!SnapshotInsightsSchema.strict,
      },
    },
    max_tokens: 600,
  });

  let js = parseOpenAIJson(resp);
  if (!js) {
    console.warn('[snapshots][ai] invalid JSON response; using fallback');
    js = buildSnapshotFallbackInsights({ metrics: trimmed, evidence });
  } else {
    const validation = validateSnapshotInsights(js, evidence);
    if (!validation.ok) {
      console.warn('[snapshots][ai] invalid insight output; using fallback', {
        reason: validation.reason,
        detail: validation.detail || null,
      });
      js = buildSnapshotFallbackInsights({ metrics: trimmed, evidence });
    }
  }
  if (emailKey && fromISO && toISO) {
    try {
      await pool.query(
        `insert into ai_snapshot_runs
          (dev_email, period_start, period_end, period_label, prompt_version, metrics_summary, evidence_summary, ai_output)
         values
          ($1, $2::date, $3::date, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb)`,
        [
          emailKey,
          fromISO,
          toISO,
          periodLabel,
          SNAPSHOT_PROMPT_VERSION,
          JSON.stringify(metricsSummary || {}),
          JSON.stringify(evidence || {}),
          JSON.stringify(js || {}),
        ]
      );
      if (SNAPSHOT_RUN_RETENTION > 0) {
        await pool.query(
          `with to_delete as (
             select id
               from ai_snapshot_runs
              where dev_email = $1
              order by created_at desc
              offset $2
           )
           delete from ai_snapshot_runs
            where id in (select id from to_delete)`,
          [emailKey, SNAPSHOT_RUN_RETENTION]
        );
      }
    } catch (e) {
      console.warn('[snapshots][ai] failed to store snapshot run:', e.message);
    }
  }
  return js;
}
// Normalize & clamp free-form strings to keep prompts tidy
function clampText(s, max = 600) {
  s = String(s == null ? '' : s).trim();
  if (!s) return '';
  if (s.length <= max) return s;
  return s.slice(0, max - 3) + '...';
}
const SNAPSHOT_STOPWORDS = new Set([
  'a',
  'an',
  'and',
  'are',
  'as',
  'at',
  'be',
  'but',
  'by',
  'for',
  'from',
  'has',
  'have',
  'he',
  'her',
  'his',
  'i',
  'in',
  'into',
  'is',
  'it',
  'its',
  'me',
  'my',
  'not',
  'of',
  'on',
  'or',
  'our',
  'she',
  'so',
  'that',
  'the',
  'their',
  'them',
  'they',
  'this',
  'to',
  'us',
  'was',
  'we',
  'were',
  'with',
  'you',
  'your',
]);
function toLocalPart(email) {
  const e = String(email || '').toLowerCase();
  const at = e.indexOf('@');
  return at > 0 ? e.slice(0, at) : e;
}
function topTermsFromNotes(notes, max = 6) {
  const freq = new Map();
  for (const raw of notes || []) {
    const text = String(raw || '').toLowerCase();
    const tokens = text.match(/[a-z0-9_]+/g) || [];
    for (const t of tokens) {
      if (t.length < 3) continue;
      if (SNAPSHOT_STOPWORDS.has(t)) continue;
      if (/^\d+$/.test(t)) continue;
      freq.set(t, (freq.get(t) || 0) + 1);
    }
  }
  return Array.from(freq.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, max)
    .map(([w]) => w);
}
function topKeywordHits(notes, keywords, max = 6) {
  const freq = new Map();
  const pool = (notes || []).map((n) => String(n || '').toLowerCase());
  for (const raw of keywords || []) {
    const kw = String(raw || '').toLowerCase().trim();
    if (!kw) continue;
    let count = 0;
    for (const note of pool) {
      if (note.includes(kw)) count += 1;
    }
    if (count) freq.set(kw, count);
  }
  return Array.from(freq.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, max)
    .map(([k]) => k);
}
function summarizeSnapshotMetrics(metrics, overallAvg) {
  const famKeys = [
    '100_xx',
    '200_xx',
    '300_xx',
    '400_xx',
    '500_xx',
    '600_xx',
    '700_xx',
    '800_xx',
  ];
  const families = metrics.families || {};
  const outFamilies = {};
  for (const k of famKeys) {
    const f = families[k] || {};
    outFamilies[k] = {
      transitions: Number(f.transitions || 0),
      hours_avg: Number(f.hours_avg || 0),
    };
  }
  return {
    ticket_volume: Number(metrics.ticket_volume || 0),
    completion_pct: Number(metrics.completion_pct || 0),
    stalled_tickets: Number(metrics.stalled_tickets || 0),
    overall_avg_cycle_time: Number(overallAvg || 0),
    families: outFamilies,
  };
}
function buildSnapshotDelta(current, previous, priorLabel) {
  if (!current || !previous) return null;
  const round1 = (n) => Math.round((Number(n) || 0) * 10) / 10;
  const round2 = (n) => Math.round((Number(n) || 0) * 100) / 100;
  const famKeys = Object.keys(current.families || {});
  const famChanges = [];
  for (const k of famKeys) {
    const c = current.families[k] || {};
    const p = (previous.families || {})[k] || {};
    const tDelta = (Number(c.transitions) || 0) - (Number(p.transitions) || 0);
    const hDelta = round2((Number(c.hours_avg) || 0) - (Number(p.hours_avg) || 0));
    if (tDelta !== 0 || Math.abs(hDelta) >= 0.25) {
      famChanges.push({ family: k, transitions_delta: tDelta, hours_avg_delta: hDelta });
    }
  }
  famChanges.sort((a, b) => {
    const aScore = Math.abs(a.transitions_delta) + Math.abs(a.hours_avg_delta);
    const bScore = Math.abs(b.transitions_delta) + Math.abs(b.hours_avg_delta);
    return bScore - aScore;
  });
  const delta = {
    prior_period_label: priorLabel || '',
    ticket_volume_delta: (Number(current.ticket_volume) || 0) - (Number(previous.ticket_volume) || 0),
    completion_pct_delta: round1((Number(current.completion_pct) || 0) - (Number(previous.completion_pct) || 0)),
    stalled_tickets_delta: (Number(current.stalled_tickets) || 0) - (Number(previous.stalled_tickets) || 0),
    overall_avg_cycle_time_delta: round2(
      (Number(current.overall_avg_cycle_time) || 0) - (Number(previous.overall_avg_cycle_time) || 0)
    ),
    family_deltas: famChanges.slice(0, 6),
  };
  const hasDelta =
    delta.ticket_volume_delta !== 0 ||
    delta.completion_pct_delta !== 0 ||
    delta.stalled_tickets_delta !== 0 ||
    delta.overall_avg_cycle_time_delta !== 0 ||
    delta.family_deltas.length > 0;
  return hasDelta ? delta : null;
}
function extractSnapshotText(output) {
  const parts = [];
  const pushArr = (arr) => {
    if (Array.isArray(arr)) {
      for (const item of arr) parts.push(String(item || ''));
    }
  };
  pushArr(output?.key_findings);
  pushArr(output?.strengths);
  pushArr(output?.suggested_kpis);
  pushArr(output?.support_from_team_leads);
  if (Array.isArray(output?.focus_areas)) {
    for (const f of output.focus_areas) {
      parts.push(String(f?.focus || ''));
      parts.push(String(f?.why || ''));
      parts.push(String(f?.action || ''));
    }
  }
  if (output?.risk) {
    parts.push(String(output.risk.stall_why || ''));
    parts.push(String(output.risk.slip_why || ''));
  }
  return parts.join(' ');
}
function extractSnapshotIds(text) {
  const matches = String(text || '').match(/\b#?\d{4,}\b/g) || [];
  return matches.map((m) => m.replace('#', ''));
}
function isLikelyYear(id) {
  const n = parseInt(id, 10);
  return Number.isFinite(n) && n >= 1900 && n <= 2100;
}
function validateSnapshotInsights(output, evidence) {
  if (!output || typeof output !== 'object') {
    return { ok: false, reason: 'not_object' };
  }

  const reqArr = [
    ['key_findings', 3],
    ['strengths', 1],
    ['focus_areas', 1],
    ['suggested_kpis', 1],
  ];
  for (const [key, min] of reqArr) {
    const arr = output[key];
    if (!Array.isArray(arr) || arr.length < min) {
      return { ok: false, reason: `missing_${key}` };
    }
    if (arr.some((s) => !String(s || '').trim())) {
      return { ok: false, reason: `empty_${key}` };
    }
  }

  const risk = output.risk || {};
  const allowed = new Set(['low', 'medium', 'high']);
  if (!allowed.has(String(risk.stall_risk || '').toLowerCase())) {
    return { ok: false, reason: 'bad_stall_risk' };
  }
  if (!allowed.has(String(risk.slip_risk || '').toLowerCase())) {
    return { ok: false, reason: 'bad_slip_risk' };
  }

  if (Array.isArray(output.focus_areas)) {
    for (const f of output.focus_areas) {
      if (!String(f?.focus || '').trim() || !String(f?.action || '').trim()) {
        return { ok: false, reason: 'invalid_focus_area' };
      }
    }
  }

  const text = extractSnapshotText(output).toLowerCase();
  if (text.includes('undefined') || text.includes('[object object]')) {
    return { ok: false, reason: 'bad_tokens' };
  }

  if (Array.isArray(evidence?.top_tickets) && evidence.top_tickets.length) {
    const allowedIds = new Set(
      evidence.top_tickets.map((t) => String(t.id || '')).filter(Boolean)
    );
    const ids = extractSnapshotIds(text);
    const unknown = ids.filter(
      (id) => !allowedIds.has(id) && !isLikelyYear(id)
    );
    if (unknown.length) {
      return { ok: false, reason: 'unknown_ticket_id', detail: unknown[0] };
    }
  }

  return { ok: true };
}
function buildSnapshotFallbackInsights({ metrics, evidence }) {
  const fam = metrics?.families || {};
  const num = (v) => (Number.isFinite(+v) ? +v : 0);
  const get = (code, field) => num(fam?.[code]?.[field]);

  const starts = get('100_xx', 'transitions');
  const finishes = get('500_xx', 'transitions');
  const inprog = get('200_xx', 'transitions');
  const blockers = get('600_xx', 'transitions') + get('800_xx', 'transitions');
  const reviews = get('400_xx', 'transitions');
  const testing = get('300_xx', 'transitions');
  const avg200 = get('200_xx', 'hours_avg');
  const overallAvg = num(metrics?.overall_avg_cycle_time);
  const completionPct = num(metrics?.completion_pct);
  const stalled = num(metrics?.stalled_tickets);
  const staleTickets = num(evidence?.stale_ticket_count);

  const fmtPct = (v) => `${num(v).toFixed(1)}%`;
  const fmtH = (v) => `${num(v).toFixed(2)}h`;

  const key_findings = [];
  key_findings.push(
    `Starts vs finishes: ${starts} vs ${finishes}; completion ${fmtPct(
      completionPct
    )}.`
  );
  key_findings.push(
    `Blocked/delays footprint: ${blockers} transitions (600/800); stalled tickets ${stalled}.`
  );
  key_findings.push(
    overallAvg > 0
      ? `Cycle-time signals: overall avg ${fmtH(overallAvg)}; 200_xx avg ${fmtH(
          avg200
        )}.`
      : 'Cycle-time signals: insufficient timing data in this window.'
  );
  key_findings.push(
    `Reviews/testing: ${reviews} review transitions, ${testing} testing transitions.`
  );
  if (inprog > 0) {
    key_findings.push(`WIP/flow: ${inprog} in-progress (200_xx) transitions.`);
  }

  const strengths = [];
  if (finishes > 0) strengths.push(`Completions recorded (${finishes} in 500_xx).`);
  if (reviews + testing > 0)
    strengths.push(`Quality loop visible (${testing} testing, ${reviews} review).`);
  if (blockers === 0)
    strengths.push('No blocker transitions recorded (600/800).');
  if (!strengths.length) {
    strengths.push(
      `Updates logged across ${num(metrics?.ticket_volume)} tickets.`
    );
  }

  const focus_areas = [];
  if (blockers > 0 || stalled >= 2) {
    const why =
      stalled > 0 || blockers > 0
        ? `Blocker transitions ${blockers} with ${stalled} stalled tickets.`
        : 'Blocker signals present in the period.';
    focus_areas.push({
      focus: 'Unblock delays faster',
      why,
      action: 'Run daily unblock check and chase owners; reduce 600/800 transitions.',
    });
  }
  if (avg200 >= 8 || inprog > finishes) {
    focus_areas.push({
      focus: 'Reduce 200_xx cycle time',
      why: `200_xx avg ${fmtH(avg200)} with ${inprog} transitions indicates extended WIP.`,
      action: 'Limit WIP and split work; target a 20% drop in 200_xx avg.',
    });
  }
  if (reviews + testing === 0) {
    focus_areas.push({
      focus: 'Make reviews/testing visible',
      why: 'No 300_xx or 400_xx transitions recorded.',
      action: 'Post PR/test links and log review/testing updates.',
    });
  }
  if (!focus_areas.length) {
    focus_areas.push({
      focus: 'Maintain steady delivery',
      why: 'Current metrics are stable across the window.',
      action: 'Keep cadence and surface any new blockers early.',
    });
  }

  const suggested_kpis = [];
  if (blockers > 0) suggested_kpis.push('Reduce 800_xx transitions by 20%.');
  if (avg200 > 0) {
    const target = Math.max(4, Math.round(avg200 * 0.7));
    suggested_kpis.push(`Lower 200_xx avg cycle time to <= ${target}h.`);
  }
  if (reviews + testing === 0) {
    suggested_kpis.push('Add at least 1 review/testing transition per completed ticket.');
  }
  if (!suggested_kpis.length) {
    suggested_kpis.push(`Increase completion rate to ${Math.min(90, completionPct + 15).toFixed(1)}%.`);
  }

  let stall_risk = 'low';
  if (stalled >= 5 || blockers >= 4 || avg200 >= 24) stall_risk = 'high';
  else if (stalled >= 2 || blockers >= 2 || avg200 >= 12) stall_risk = 'medium';

  let slip_risk = 'low';
  if (completionPct < 30 || finishes + 2 < starts) slip_risk = 'high';
  else if (completionPct < 45 || finishes < starts) slip_risk = 'medium';

  const stallWhyParts = [];
  if (blockers > 0) stallWhyParts.push(`blocker transitions ${blockers}`);
  if (stalled > 0) stallWhyParts.push(`${stalled} stalled tickets`);
  if (staleTickets > 0) stallWhyParts.push(`${staleTickets} stale updates`);
  const stall_why = stallWhyParts.length
    ? `Signals: ${stallWhyParts.join(', ')}.`
    : 'No strong stall signals in the window.';

  const slip_why = `Completion ${fmtPct(completionPct)} with starts ${starts} vs finishes ${finishes}.`;

  const support_from_team_leads = [];
  if (blockers > 0 || stalled >= 2) {
    support_from_team_leads.push(
      'Run 15-min unblock huddles and assign owners for stalled tickets.'
    );
  }
  if (reviews + testing === 0) {
    support_from_team_leads.push('Require PR/review links in updates and track 400_xx activity.');
  }
  if (!support_from_team_leads.length) {
    support_from_team_leads.push('Maintain a weekly cadence to review WIP and blockers.');
  }

  return {
    key_findings: key_findings.slice(0, 5),
    strengths: strengths.slice(0, 5),
    focus_areas: focus_areas.slice(0, 5),
    suggested_kpis: suggested_kpis.slice(0, 5),
    risk: {
      stall_risk,
      slip_risk,
      stall_why,
      slip_why,
    },
    support_from_team_leads: support_from_team_leads.slice(0, 3),
  };
}
function trimSnapshotInsights(output) {
  if (!output) return null;
  const clampArr = (arr, max) =>
    Array.isArray(arr)
      ? arr.slice(0, max).map((s) => clampText(s, 180))
      : [];
  const focus =
    Array.isArray(output.focus_areas) && output.focus_areas.length
      ? output.focus_areas.slice(0, 3).map((f) => ({
          focus: clampText(f.focus || '', 120),
          why: clampText(f.why || '', 160),
          action: clampText(f.action || '', 160),
        }))
      : [];
  return {
    key_findings: clampArr(output.key_findings, 3),
    strengths: clampArr(output.strengths, 2),
    focus_areas: focus,
    risk: output.risk || null,
  };
}
function parseJsonMaybe(v) {
  if (!v) return null;
  if (typeof v === 'string') {
    try {
      return JSON.parse(v);
    } catch (_e) {
      return null;
    }
  }
  return v;
}
async function loadSnapshotHistory(devEmail, fromISO) {
  const email = String(devEmail || '').toLowerCase();
  if (!email) return { priorAny: null, priorPeriod: null };
  const anyRes = await pool.query(
    `select period_start, period_end, period_label, metrics_summary, ai_output
       from ai_snapshot_runs
      where lower(dev_email) = $1
      order by created_at desc
      limit 1`,
    [email]
  );
  const periodRes = await pool.query(
    `select period_start, period_end, period_label, metrics_summary, ai_output
       from ai_snapshot_runs
      where lower(dev_email) = $1
        and period_end < $2::date
      order by period_end desc
      limit 1`,
    [email, fromISO]
  );
  return {
    priorAny: anyRes.rowCount ? anyRes.rows[0] : null,
    priorPeriod: periodRes.rowCount ? periodRes.rows[0] : null,
  };
}
async function buildSnapshotEvidence({
  fromISO,
  toISO,
  devEmail,
  devLocal,
  maxTickets = SNAPSHOT_EVIDENCE_MAX_TICKETS,
}) {
  const email = devEmail ? String(devEmail).toLowerCase() : null;
  const local = devLocal ? String(devLocal).toLowerCase() : null;
  if (!email && !local) {
    return {
      window: { from: fromISO, to: toISO },
      totals: { update_count: 0, ticket_count: 0, blocker_updates: 0, high_risk_updates: 0 },
      blocker_keywords: [],
      top_terms: [],
      top_tickets: [],
      stale_ticket_count: 0,
    };
  }

  const updatesSql = `
    with updates as (
      select
        u.ticket_id as "ticketId",
        u.code,
        u.note,
        u.risk_level as "riskLevel",
        u.impact_area as "impactArea",
        u.at,
        t.title,
        t.type,
        t.state,
        t.assigned_to as "assignedTo",
        count(*) over (partition by u.ticket_id) as "updateCount"
      from progress_updates u
      left join tickets t on t.id = u.ticket_id
      where u.at >= $1::timestamptz
        and u.at < ($2::timestamptz + interval '1 day')
        and (
          ($3::text is null and $4::text is null)
          or lower(u.email) = $3::text
          or split_part(lower(u.email),'@',1) = $4::text
        )
    )
    select distinct on ("ticketId") *
      from updates
     order by "ticketId", at desc
  `;

  const totalsSql = `
    select
      count(*) as update_count,
      count(distinct ticket_id) as ticket_count,
      sum(case when split_part(code,'_',1) in ('600','800') then 1 else 0 end) as blocker_updates,
      sum(case when lower(risk_level) = 'high' then 1 else 0 end) as high_risk_updates
    from progress_updates
    where at >= $1::timestamptz
      and at < ($2::timestamptz + interval '1 day')
      and (
        ($3::text is null and $4::text is null)
        or lower(email) = $3::text
        or split_part(lower(email),'@',1) = $4::text
      )
  `;

  const [updatesRes, totalsRes] = await Promise.all([
    pool.query(updatesSql, [fromISO, toISO, email, local]),
    pool.query(totalsSql, [fromISO, toISO, email, local]),
  ]);

  const updates = updatesRes.rows || [];
  const totals = totalsRes.rows?.[0] || {};

  const notes = [];
  const tickets = updates.map((r) => {
    const note = clampText(scrub(r.note || ''), 240);
    if (note) notes.push(note);
    const lastAt =
      r.at && typeof r.at.toISOString === 'function' ? r.at.toISOString() : String(r.at || '');
    const stalenessDays = daysSince(r.at);
    const code = clampText(r.code || '', 32);
    const noteLc = note.toLowerCase();
    const blockerHit = blockerKeywords.some((k) => k && noteLc.includes(k.toLowerCase()));
    return {
      id: String(r.ticketId || ''),
      title: clampText(r.title || '', 120),
      type: clampText(r.type || '', 40),
      state: clampText(r.state || '', 40),
      assigned_to: clampText(r.assignedTo || '', 80),
      last_code: code,
      last_note: note,
      last_update_at: lastAt,
      update_count: Number(r.updateCount || 0),
      risk_level: clampText(r.riskLevel || '', 16),
      impact_area: clampText(r.impactArea || '', 40),
      staleness_days: stalenessDays,
      blocker_hint: isBlockerCode(code) || blockerHit,
    };
  });

  const staleTicketCount = tickets.filter((t) => t.staleness_days != null && t.staleness_days >= 7).length;
  const topTerms = topTermsFromNotes(notes, 6);
  const blockerHits = topKeywordHits(notes, blockerKeywords, 6);

  const scored = tickets.map((t) => {
    let score = 0;
    if (isBlockerCode(t.last_code)) score += 3;
    const risk = String(t.risk_level || '').toLowerCase();
    if (risk === 'high') score += 2;
    if (risk === 'medium') score += 1;
    if (t.blocker_hint) score += 1;
    if (t.update_count >= 3) score += 1;
    if (t.staleness_days != null) {
      if (t.staleness_days <= 2) score += 2;
      else if (t.staleness_days <= 7) score += 1;
    }
    return { ...t, _score: score };
  });

  scored.sort((a, b) => {
    if (b._score !== a._score) return b._score - a._score;
    return String(b.last_update_at || '').localeCompare(String(a.last_update_at || ''));
  });

  const topTickets = scored.slice(0, maxTickets).map(({ _score, ...t }) => t);

  return {
    window: { from: fromISO, to: toISO },
    totals: {
      update_count: Number(totals.update_count || 0),
      ticket_count: Number(totals.ticket_count || 0),
      blocker_updates: Number(totals.blocker_updates || 0),
      high_risk_updates: Number(totals.high_risk_updates || 0),
    },
    blocker_keywords: blockerHits,
    top_terms: topTerms,
    top_tickets: topTickets,
    stale_ticket_count: staleTicketCount,
  };
}
// --- explicit "who" extractor (from notes/tags) -----------------------------
function extractExplicitWho({ currentNote = '', lastNote = '', tags = '' }) {
  const raw = [currentNote, lastNote, tags].filter(Boolean).join(' ');
  const hay = raw.toLowerCase();

  // role keywords → normalized role/team
  const roleMap = [
    {
      re: /\bqa\b|\bquality\b|\bverification\b|\btester(s)?\b/,
      who: 'QA team',
    },
    { re: /\breview\b|\bcrr\b|\bcode review\b/, who: 'Team Lead' },
    { re: /\bapi\b|\bbackend\b|\bplatform\b/, who: 'API team' },
    {
      re: /\bpm\b|\bproject manager\b|\bprogram manager\b/,
      who: 'Project Manager',
    },
    { re: /\bteam lead\b|\btech( |-)lead\b/, who: 'Team Lead' },
    { re: /\boffshore\b|\bOM\b/, who: 'Offshore Manager' },
    { re: /\bSSIS\b|\bENT\b/, who: 'ENT team' },

    { re: /\bWinApp\b|\bNextGen\b/, who: 'NextGen team' },
    { re: /\bagent7\b|\bdevice?\b/, who: 'Device team' },
    {
      re: /\bdep(endency)? (owner|client)\b|\bwaiting on\b/,
      who: 'Offshore Manager',
    },
  ];
  for (const { re, who } of roleMap) if (re.test(hay)) return who;

  // light @tag capture
  const m = hay.match(
    /@(qa|api|pm|om|sre|ux|design|security|data|backend|platform|team[- ]lead)\b/i
  );
  if (m) {
    const tag = m[1].toLowerCase();
    const aliasMap = {
      qa: 'QA team',
      api: 'API team',
      pm: 'Project Manager',
      om: 'Offshore Manager',
      sre: 'Ops/SRE',
      ux: 'Design/UX',
      design: 'Design/UX',
      security: 'Security team',
      data: 'Data team',
      backend: 'API team',
      platform: 'API team',
      'team lead': 'Team Lead',
      'team-lead': 'Team Lead',
    };
    return aliasMap[tag] || 'Team Lead';
  }

  // Person/email/alias extraction (addresses “with Roland”, “ask Alice”, “cc Bob”)
  // 1) direct email
  const email = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  if (email) return email[0];
  // 2) @alias (keeps handle as target)
  const atAlias = raw.match(/@([A-Za-z0-9._-]{2,})/);
  if (atAlias) return atAlias[1];
  // 3) capitalized person name after common verbs/preps
  const person = raw.match(
    /\b(?:with|to|for|ask|ping|cc|tag|loop(?:ing)?\s+in|handoff\s+to|handover\s+to|blocked\s+by|waiting\s+on)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b/
  );
  if (person) return person[1]; // e.g., "Roland", "Alice Smith"

  return ''; // nothing explicit found
}

// Guard: dev & pm may call this; others 403
async function requireDevOrPM(req, res, next) {
  try {
    const me = await pool.query('select role from users where email=$1', [
      req.userEmail,
    ]);
    const role = me.rows[0]?.role || 'dev';
    if (role !== 'dev' && role !== 'pm') {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

app.post(
  '/api/ai/dev-assist',
  requireAuth,
  requireDevOrPM,
  async (req, res) => {
    try {
      if (!openai) return res.status(501).json({ error: 'ai_not_configured' });

      // body: { mode, ticket: {id,title,assignedTo?,state?}, context: {...} }
      const body = req.body || {};
      const mode = String(body.mode || '').toLowerCase();
      const ticket = body.ticket || {};
      const ctx = body.context || {};
      const selectedCode = clampText(
        ctx.selectedCode || ctx.code || ctx.lastCode || '',
        32
      );

      const tId = String(ticket.id || ticket.ticketId || '').trim();
      const tTitle = clampText(ticket.title || '');
      const tState = clampText(ticket.state || '');
      const tWho = clampText(ticket.assignedTo || '');

      // scrub potentially sensitive note/logs
      const lastNote = clampText(_scrub(ctx.lastNote || ctx.note || ''), 800);
      const tags = clampText(ctx.tags || '');
      const blockers = clampText(ctx.blockers || '');
      const currentNote = clampText(_scrub(ctx.currentNote || ''), 800);
      const recentErrors = clampText(_scrub(ctx.recentErrors || ''), 800);

      if (!tId) return res.status(400).json({ error: 'ticket.id required' });
      if (!mode || (mode !== 'chase' && mode !== 'next')) {
        return res
          .status(400)
          .json({ error: 'mode must be "chase" or "next"' });
      }

      // Enforce: only allow chase drafts for blocker families (600/700/800)
      if (mode === 'chase' && !isBlockerCode(selectedCode)) {
        return res.status(400).json({
          error: 'chase_not_applicable_for_code',
          code: selectedCode || null,
        });
      }

      // Build prompt per mode
      let system, user, schema;
      // who is asking for the chase (the logged-in dev/pm)
      let requesterLabel = req.userEmail;
      try {
        const meRow = await pool.query(
          `select coalesce(nullif(name,''), email) as label from users where email=$1 limit 1`,
          [req.userEmail]
        );
        requesterLabel = meRow.rows[0]?.label || req.userEmail;
      } catch (_) {}

      // Hints we may reuse after the OpenAI call (must be outer-scoped)
      let explicitWho = '';
      let defaultQATargetOk = false;

      if (mode === 'chase') {
        system = `You draft a concise “chase” message to unblock a developer.

Audience / Targeting (strict priority):
1) If an explicit target (explicit_who_hint) is provided (person name, email, alias, or team), you MUST address THEM and set who accordingly.
2) Else if default_qa_ok is true, address the QA team.
3) Else infer a sensible contact from the context (dependencies, review, ops, etc.).
NEVER address the requester and NEVER greet the ticket assignee unless they are the correct contact.

Style:
- 2-3 sentences total, copy-paste ready.
- Include: (1) specific ask, (2) why it unblocks the ticket, (3) a light time ask (today / ETA).
- Calm, professional, blame-free. Default tone: "polite".
- Start with a short salutation naming the role/person you're addressing
  (e.g., "Hi QA team,", "Hi API team,", "Hi Alice (QA),", or "Hi team,").
- Do NOT default to QA unless default_qa_ok=true or explicit_who_hint implies QA.

Heuristics you may use when inferring:
- review/CRR → Code reviewer
- dependency/API/platform/backend → API team or Dependency owner
- ops/sre/infra → Ops/SRE
- security/secops → Security team
- ux/design → Design/UX
- data/analytics → Data team`;

        // hydrate extra ticket context (includes type to control QA default)
        let assignedToDb = tWho,
          tagsDb = tags,
          relLinksDb = null,
          typeDb = (ticket.type || '').trim();
        try {
          const r = await pool.query(
            'select assigned_to, tags, related_link_count, type from tickets where id=$1 limit 1',
            [tId]
          );
          if (r.rowCount) {
            assignedToDb = clampText(r.rows[0].assigned_to || assignedToDb);
            tagsDb = clampText(r.rows[0].tags || tagsDb);
            relLinksDb = Number.isFinite(+r.rows[0].related_link_count)
              ? +r.rows[0].related_link_count
              : null;
            typeDb = clampText(r.rows[0].type || typeDb);
          }
        } catch (_) {}

        // compute explicit target + QA default flag
        explicitWho = extractExplicitWho({
          currentNote,
          lastNote,
          tags: tagsDb,
        });
        defaultQATargetOk =
          String(typeDb || '').toLowerCase() === 'bug' && !explicitWho;

        user = `Ticket #${tId} — ${tTitle || '(no title)'}
State: ${tState || '—'}
Work item type: ${typeDb || '—'}
AssignedTo (ticket): ${assignedToDb || '—'}
Requester (logged-in): ${requesterLabel}
Hints:
- explicit_who_hint: ${explicitWho || '(none)'}
- default_qa_ok: ${defaultQATargetOk ? 'true' : 'false'}

Context:
- Selected/last code: ${
          clampText(ctx.selectedCode || ctx.code || ctx.lastCode || '') || '—'
        }
- Current note: ${currentNote || '—'}
- Last note: ${lastNote || '—'}
- Tags: ${tagsDb || '—'}
- Related links: ${relLinksDb == null ? 'unknown' : String(relLinksDb)}
- Blocker hints: ${blockers || '—'}
- Recent errors/logs: ${recentErrors || '—'}

Return JSON EXACTLY in this shape:
{
  "chase_text": "<start with 'Hi <role/person>,'; then 2-3 sentences with ask/why/when>",
  "who": "<final target you addressed; role or person (e.g., 'QA team', 'API team', 'Code reviewer')>",
  "tone": "neutral|friendly|polite"
}`;
        schema = ChaseDraftSchema;
      } else {
        // mode === 'next'
        system = `You are a senior developer coach. Given a ticket, return the next 2-3 actions; each must be concrete, testable, and completable in ~30-90 minutes.

STYLE: Imperative verbs only; be specific (files/functions/endpoints/data/envs/owner); avoid vague “continue work”.

GUARDRAILS: Split anything >90 min. If blocked, include one “Chase/Unblock” (who + what to ask) and one fallback step. Prefer actions that produce an artifact.

TAILORING: If a progress_code family (100/200/300/400/500/600/700/800_xx) or acceptance criteria are provided, align steps accordingly.

OUTPUT: prefer steps should include <imperative action>; optional <objective end state> or <artifact: PR/test name/log line/screenshot/comment link> 

`;
        user = `Ticket #${tId} — ${tTitle || '(no title)'}
State: ${tState || '—'}
Notes:
- Current note: ${currentNote || '—'}
- Last note: ${lastNote || '—'}
- Tags: ${tags || '—'}
- Recent errors/logs: ${recentErrors || '—'}

Return JSON: { "next_steps": ["...", "...", "..."] }`;
        schema = NextStepsSchema;
      }

      const resp = await openai.chat.completions.create({
        model: OPENAI_MODEL,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: schema.name,
            schema: schema.schema,
            strict: !!schema.strict,
          },
        },
        max_tokens: 400,
      });

      const js = parseOpenAIJson(resp);
      if (!js) throw new Error('bad_ai_response');

      // If the model chose QA but QA wasn't allowed, nudge to neutral
      if (mode === 'chase' && js?.who) {
        const whoLower = String(js.who).toLowerCase();
        const isQAChoice = /\bqa\b/.test(whoLower);

        // Re-evaluate the flags we computed above (we're still in the same scope)
        if (
          isQAChoice &&
          !defaultQATargetOk &&
          !/\bqa\b/.test(String(explicitWho).toLowerCase())
        ) {
          // soften greeting if model defaulted to QA but that wasn't allowed
          if (typeof js.chase_text === 'string') {
            js.chase_text = js.chase_text.replace(
              /^hi\s+qa[^\w]*,\s*/i,
              'Hi team, '
            );
          }
          js.who = 'Team / owner';
        }
      }

      return res.json({ status: 'ok', mode, ticket: { id: tId }, result: js });
    } catch (e) {
      const http = e?.status || e?.response?.status || 500;
      console.error('[ai/dev-assist] error:', {
        status: http,
        code: e?.code,
        message: e?.message,
        data: e?.response?.data,
      });
      return res.status(http).json({
        status: 'error',
        error: e?.message || 'server_error',
        code: e?.code || null,
        openai: e?.response?.data || e?.error || null,
      });
    }
  }
);

// static web
app.use('/', express.static(path.join(process.cwd(), '..', 'web')));

// --- boot: ensure meta table exists (key/value store) ---
pool
  .query(
    `
  create table if not exists meta (
    key text primary key,
    value text,
    extra jsonb,
    updated_at timestamptz default now()
  )
`
  )
  .then(() => {
    console.log('[boot] meta table is ready');
  })
  .catch((e) => {
    console.error('[boot] meta table ensure failed:', e);
  });

// --- boot: ensure ai_snapshot_runs table exists (history for RAG deltas) ---
pool
  .query(
    `
  create table if not exists ai_snapshot_runs (
    id bigserial primary key,
    dev_email text not null,
    period_start date not null,
    period_end date not null,
    period_label text,
    prompt_version text,
    metrics_summary jsonb,
    evidence_summary jsonb,
    ai_output jsonb,
    created_at timestamptz default now()
  )
`
  )
  .then(() =>
    pool.query(
      `create index if not exists ai_snapshot_runs_dev_period on ai_snapshot_runs (dev_email, period_end)`
    )
  )
  .then(() => {
    console.log('[boot] ai_snapshot_runs table is ready');
  })
  .catch((e) => {
    console.error('[boot] ai_snapshot_runs table ensure failed:', e);
  });
