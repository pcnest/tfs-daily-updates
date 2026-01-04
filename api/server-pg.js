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
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_REQUIRE_TLS = (process.env.SMTP_REQUIRE_TLS || 'false') === 'true';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;

function buildMailTransport() {
  if (MAIL_MODE === 'smtp' && SMTP_HOST) {
    return nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT || 587,
      secure: SMTP_PORT === 465,
      requireTLS: SMTP_REQUIRE_TLS,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    });
  }
  // Default to a safe JSON transport for local testing
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
  strict: false, // IMPORTANT: keeps optional fields optional (prevents “Missing 'slipRisk'”)
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
async function todayLocal(pool) {
  // Returns 'YYYY-MM-DD' based on APP_TZ (DST-safe)
  const { rows } = await pool.query(
    `select to_char(timezone($1, now())::date, 'YYYY-MM-DD') as d`,
    [APP_TZ]
  );
  return rows[0].d;
}

// Chase gate: only allow 600_/700_/800_ families
const BLOCKER_CODE_REGEX = /^(600|700|800)_/;
function isBlockerCode(code) {
  return BLOCKER_CODE_REGEX.test(String(code || ''));
}

const noteRequiredPrefixes = ['600_', '700_', '800_'];
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

  // Normalize fonts for Outlook/Gmail; attach a PDF version too
  const html = normalizeEmailHTMLFonts(htmlRaw);
  const pdfBuffer = await htmlToPdfBuffer(html);

  const devSlug = fileSafeSlug(range.developer || 'all');
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
    attachments: [
      {
        filename: `Developer-Snapshot_${devSlug}_${range.from}_to_${range.to}.pdf`,
        content: pdfBuffer,
        contentType: 'application/pdf',
      },
    ],
  };
}

async function sendEmail({ to, cc, subject, html, attachments }) {
  // Reuse your nodemailer transport + helpers already defined above
  const transporter = buildMailTransport();

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

  const mail = {
    from: SMTP_FROM || SMTP_USER,
    to: toList.join(', '),
    cc: ccList.length ? ccList.join(', ') : undefined,
    subject: subject || '(no subject)',
    html: html || '',
    attachments: Array.isArray(attachments) ? attachments : undefined,
  };

  const info = await transporter.sendMail(mail);

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
          // Use a 60-minute window to catch items from recent sync runs
          const recentResult = await client.query(
            `UPDATE tickets
           SET deleted = true
         WHERE NOT (id = ANY($1::text[]))
           AND last_seen_at >= now() - interval '60 minutes'
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

// --- collation (enriched)
app.get('/api/updates/today', async (_req, res) => {
  const date = await todayLocal(pool);

  const updates = await pool.query(
    `select u.ticket_id as "ticketId", u.email, u.code, u.note, u.risk_level as "riskLevel",
            u.impact_area as "impactArea", u.at,
            t.title, t.state, t.type, t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
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

// Email Developer Progress Snapshot
app.post(
  '/api/reports/snapshots/email',
  requireAuth,
  requirePMOnly,
  async (req, res) => {
    try {
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

      // Build the HTML & PDF via existing helper
      const { subject, html, attachments } = await buildSnapshotEmail(
        req,
        { from, to, developer, developerLabel },
        { ai: String(ai) === '1' }
      );

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

      // If developer=all and no toEmail, just send to CCs (PM/team leads)
      if (!toList.length && !ccList.length) {
        return res.status(400).json({
          error: 'no recipients (developer unresolved and no CC provided)',
        });
      }

      const info = await sendEmail({
        to: toList,
        cc: ccList,
        subject,
        html,
        attachments,
      });
      res.json(info);
    } catch (e) {
      res.status(500).json({ error: String(e.message || e) });
    }
  }
);

// --- blockers radar
app.get('/api/updates/blockers', async (_req, res) => {
  const date = await todayLocal(pool);
  const r = await pool.query(
    `select u.ticket_id as "ticketId", u.email, u.code, u.note, u.at,
         t.title, t.state, t.type, t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
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
    if (isBlockerCode(x.code) || kw)
      hits.push({ ...x, keyword: isBlockerCode(x.code) ? 'code' : kw || '' });
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

// Minimal helper to call OpenAI for one developer's metrics
async function aiSnapshotInsightsForDev({ periodLabel, metrics }) {
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

  // Keep payload tidy and grounded on your computed aggregates
  const trimmed = {
    period: periodLabel,
    email: String(metrics.email || ''),
    ticket_volume: Number(metrics.ticket_volume || 0),
    completion_pct: Number(metrics.completion_pct || 0),
    stalled_tickets: Number(metrics.stalled_tickets || 0),
    families: metrics.families || {}, // { '100_xx': { transitions, hours_sum, hours_avg }, ... }
    overall_avg_cycle_time: overallAvg, // <- NEW
  };

  const system = `You are a delivery PM analyzing a developer's progress snapshot.
You receive per-family metrics (100_xx..800_xx: transitions, hours_sum, hours_avg), ticket_volume, completion_pct, stalled_tickets.
Write concise outputs:
- key_findings: 3-5 bullets (throughput, bottlenecks, balance across 100/200/300/400/500, blocker footprint 600/800).
- strengths: 2-5 bullets.
- focus_areas: 1-5 (each with <focus>, optional <why>, and concrete <action> for next month).
- suggested_kpis: ≤5 compact KPI statements (e.g., "Reduce 800_xx transitions by 25%").
- risk: stall_risk & slip_risk = low/medium/high inferred from metrics, plus stall_why and slip_why (one-line, data-grounded reasons).
- support_from_team_leads: 1-3 bullets, written as actions for the team lead/manager (not the developer), each ≤20 words, concrete, next-week scope (cadence, escalations, pairing, env access, PR gates, 10–15 min unblock huddles).
You also receive overall_avg_cycle_time (weighted across all families). Prefer it when summarizing “Cycle-time signals” and risk rationales.
Keep outputs brief and practical, using the team's progress families.`;

  const user = `Developer period: ${trimmed.period}
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
        name: SnapshotInsightsSchema.name,
        schema: SnapshotInsightsSchema.schema,
        strict: !!SnapshotInsightsSchema.strict,
      },
    },
    max_tokens: 600,
  });

  const js = parseOpenAIJson(resp);
  if (!js) throw new Error('bad_ai_response');
  return js;
}

// Normalize & clamp free-form strings to keep prompts tidy
function clampText(s, max = 600) {
  s = String(s == null ? '' : s).trim();
  if (!s) return '';
  if (s.length <= max) return s;
  return s.slice(0, max - 3) + '...';
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
