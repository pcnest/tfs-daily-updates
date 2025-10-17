// Public API (Postgres) — same endpoints, backed by Neon
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { Pool } from 'pg';
import fs from 'fs';
import path from 'path';

dotenv.config();

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(cors());

const API_KEY = process.env.API_KEY || 'CHANGE_ME_API_KEY';
const PORT = process.env.PORT || 8080;

// DB pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Auto-export TSV at day end
const EXPORT_DIR = path.join(process.cwd(), 'exports');
if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });

// helpers
const todayISO = () => new Date().toISOString().slice(0, 10);

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

const HARD_LOCK = process.env.HARD_LOCK === '1';
const blockerKeywords = (
  process.env.BLOCKER_KEYWORDS ||
  'blocker,blocked,access,credential,env,qa,review pending,dependency,waiting,stuck,timeout,failed,crash'
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
  const allow = (process.env.ALLOWED_EMAIL_DOMAINS || '')
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

// Auto-export TSV at day end
async function exportTodayTSVIfReady() {
  const date = new Date().toISOString().slice(0, 10);
  const countAll = (
    await pool.query(
      'select count(*)::int c from (select distinct email from progress_updates where date=$1) s',
      [date]
    )
  ).rows[0].c;
  if (countAll === 0) return; // nothing today

  const countLocked = (
    await pool.query(
      'select count(*)::int c from (select distinct email from progress_locks where date=$1) s',
      [date]
    )
  ).rows[0].c;
  if (countLocked < countAll) return; // not everyone locked yet

  const r = await pool.query(
    `
    select u.email, u.ticket_id as "ticketId", u.code, u.note,
           t.title, t.state, t.iteration_path as "iterationPath", t.assigned_to as "assignedTo",
           u.at
    from progress_updates u
    left join tickets t on t.id=u.ticket_id
    where u.date=$1
  `,
    [date]
  );

  // latest per (email,ticket)
  const map = new Map();
  for (const x of r.rows) {
    const k = `${x.email}:${x.ticketId}`;
    const prev = map.get(k);
    if (!prev || x.at > prev.at) map.set(k, x);
  }

  let tsv =
    'date\tuser\tticketId\ttitle\tstate\tcode\tnote\titerationPath\tassignedTo\n';
  for (const x of Array.from(map.values()).sort(
    (a, b) =>
      a.email.localeCompare(b.email) ||
      String(a.ticketId).localeCompare(String(b.ticketId))
  )) {
    const fields = [
      date,
      x.email,
      x.ticketId,
      x.title || '',
      x.state || '',
      x.code || '',
      (x.note || '').replace(/\t/g, ' ').replace(/\r?\n/g, ' '),
      x.iterationPath || '',
      x.assignedTo || '',
    ];
    tsv += fields.join('\t') + '\n';
  }
  const out = path.join(EXPORT_DIR, `updates-${date}.tsv`);
  fs.writeFileSync(out, tsv, 'utf8');
  console.log('[export]', out);
}

// --- health
app.get('/health', async (_req, res) => {
  try {
    await pool.query('select 1');
    res.json({ ok: true, at: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- auth: signup/login/me
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'email and password required' });

  // 1) optional: quick domain allowlist (set ALLOWED_EMAIL_DOMAINS=company.com in Render)
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
      `insert into users(email, name, pw) values ($1,$2,$3)
   on conflict (email) do update set name=excluded.name, pw=excluded.pw`,
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
      'select email,name,pw,role from users where email=$1',
      [lower]
    );
    if (u.rowCount === 0 || !verifyPassword(password, u.rows[0].pw)) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const token = newToken();
    await pool.query('insert into sessions(token,email) values($1,$2)', [
      token,
      lower,
    ]);
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
    const s = await pool.query('select email from sessions where token=$1', [
      token,
    ]);
    if (s.rowCount === 0)
      return res.status(401).json({ error: 'invalid token' });
    req.userEmail = s.rows[0].email;
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

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

// POST /api/sync/tfs-users   body: [{ alias, email?, displayName?, tfs_id?, project_id?, team_id? }]
app.post('/api/sync/tickets', async (req, res) => {
  // The agent can send: { source, tickets: [...], pushedAt, presentIds: [...], presentIteration: "Sprint 2025-400" }
  const {
    source = 'unknown',
    tickets = [],
    pushedAt,
    presentIds = [],
    presentIteration = '',
  } = req.body || {};
  // Require API key
  const key = req.header('x-api-key') || '';
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Upsert all tickets we just saw; set last_seen_at and clear deleted
    for (const t of tickets) {
      const seenAt = pushedAt || new Date().toISOString();
      await client.query(
        `
        INSERT INTO tickets (
          id, type, title, state, assigned_to, area_path, iteration_path,
          changed_date, tags, last_seen_at, deleted
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false)
        ON CONFLICT (id) DO UPDATE SET
          type           = EXCLUDED.type,
          title          = EXCLUDED.title,
          state          = EXCLUDED.state,
          assigned_to    = EXCLUDED.assigned_to,
          area_path      = EXCLUDED.area_path,
          iteration_path = EXCLUDED.iteration_path,
          changed_date   = EXCLUDED.changed_date,
          tags           = EXCLUDED.tags,
          last_seen_at   = EXCLUDED.last_seen_at,
          deleted        = false
        `,
        [
          String(t.id),
          t.type || '',
          t.title || '',
          t.state || '',
          t.assignedTo || '',
          t.areaPath || '',
          t.iterationPath || '',
          t.changedDate || null,
          t.tags || '',
          seenAt,
        ]
      );
    }

    // ---- Presence sweep (tombstone anything missing from this run's scope) ----
    // Run if the agent provided the iteration name; we handle empty lists too.
    if (presentIteration && presentIteration.trim()) {
      const idsText = Array.isArray(presentIds)
        ? presentIds.map(String).filter(Boolean)
        : [];

      // If there are any "present" IDs, un-delete them and bump last_seen_at
      if (idsText.length > 0) {
        await client.query(
          `UPDATE tickets
         SET deleted = false, last_seen_at = now()
       WHERE id = ANY($1::text[])`,
          [idsText]
        );
      }

      // Now mark missing rows (same iteration) as deleted.
      // If idsText is empty, this marks ALL rows in that iteration as deleted.
      // Prefer exact full path if provided; fall back to name substring
      const presentIterationPath = (
        req.body?.presentIterationPath || ''
      ).trim();
      const scopeByPath = presentIterationPath
        ? `%${presentIterationPath}%`
        : null;
      const scopeByName = (presentIteration || '').trim()
        ? `%${presentIteration}%`
        : null;

      // Un-delete all present ids (refresh last_seen_at)
      if (idsText.length > 0) {
        await client.query(
          `UPDATE tickets
       SET deleted = false, last_seen_at = now()
     WHERE id = ANY($1::text[])`,
          [idsText]
        );
      }

      // Mark missing rows as deleted, scoped by path if possible, else name, else skip
      if (scopeByPath || scopeByName) {
        await client.query(
          `
    UPDATE tickets
       SET deleted = true
     WHERE
       (
         ($1::text IS NOT NULL AND COALESCE(iteration_path,'') ILIKE $1)
         OR
         ($1::text IS NULL AND $2::text IS NOT NULL AND COALESCE(iteration_path,'') ILIKE $2)
       )
       AND (
         $3::text[] IS NULL
         OR array_length($3::text[],1) IS NULL
         OR NOT (id = ANY($3::text[]))
       )
    `,
          [scopeByPath, scopeByName, idsText.length ? idsText : null]
        );
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

    // Pull active tfs_users, sorted by display name then alias
    const { rows } = await pool.query(`
      select
        lower(alias) as alias,
        coalesce(display_name, '') as display_name,
        lower(email) as email
      from tfs_users
      where active = true
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
  } = req.query;
  const clauses = [];
  const params = [];
  let i = 1;

  // Exclude soft-deleted rows by default. Override with ?includeDeleted=1 if you ever need to audit.
  if (!includeDeleted || String(includeDeleted) !== '1') {
    // coalesce handles legacy rows where 'deleted' might be null
    clauses.push(`coalesce(t.deleted, false) = false`);
  }

  // Default: only Bug + Product Backlog Item.
  // Override with ?types=all or ?types=Bug,Product Backlog Item
  if (!types || String(types).toLowerCase() === 'default') {
    clauses.push(`lower(t.type) in ('bug','product backlog item')`);
  } else if (String(types).toLowerCase() !== 'all') {
    const list = String(types)
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (list.length) {
      // pg will serialize JS array to Postgres text[]
      clauses.push(`lower(t.type) = any($${i++})`);
      params.push(list);
    }
  }

  // same filters, but prefix columns with t.
  if (assignedTo) {
    clauses.push(
      `lower(regexp_replace(t.assigned_to,'^.*\\\\','')) like $${i++}`
    );
    params.push(`%${normId(assignedTo)}%`);
  }
  if (state) {
    clauses.push(`lower(t.state)=lower($${i++})`);
    params.push(state);
  }
  if (iterationPath) {
    clauses.push(`lower(t.iteration_path) like lower($${i++})`);
    params.push(`%${iterationPath}%`);
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
  const me = await tryGetAuthEmail(req);
  let sql, rows;
  if (me) {
    params.push(me); // $i for email in the lateral
    const emailParam = `$${i++}`;

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
        where ticket_id = t.id and email = ${emailParam}
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

  const date = todayISO();
  const locked = await pool.query(
    'select 1 from progress_locks where email=$1 and date=$2',
    [req.userEmail, date]
  );
  if (HARD_LOCK && locked.rowCount)
    return res.status(403).json({ error: 'day already submitted (locked)' });

  if (await isNoteRequired(pool, code)) {
    if (!note || !String(note).trim())
      return res.status(400).json({ error: `note required for code ${code}` });
  }

  await pool.query(
    `insert into progress_updates(ticket_id,email,code,note,risk_level,impact_area,date,at)
     values ($1,$2,$3,$4,$5,$6,$7,now())`,
    [
      String(ticketId),
      req.userEmail,
      code,
      note || '',
      riskLevel || 'low',
      impactArea || '',
      date,
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
  const date = todayISO();
  await pool.query(
    `insert into progress_locks(email,date,at) values ($1,$2,now())
     on conflict (email,date) do nothing`,
    [req.userEmail, date]
  );
  exportTodayTSVIfReady().catch(() => {});
  res.json({ status: 'ok', locked: true, date });
});
app.post('/api/updates/unlock', requireAuth, async (req, res) => {
  const me = await pool.query('select role from users where email=$1', [
    req.userEmail,
  ]);
  if (me.rows[0]?.role !== 'pm')
    return res.status(403).json({ error: 'pm only' });

  const date = todayISO();
  const target = (req.body?.email || '').trim().toLowerCase();
  if (!target) return res.status(400).json({ error: 'target email required' });

  await pool.query(`delete from progress_locks where email=$1 and date=$2`, [
    target,
    date,
  ]);
  res.json({ status: 'ok', locked: false, date, target });
});

app.get('/api/updates/lock', requireAuth, async (req, res) => {
  const date = todayISO();
  const r = await pool.query(
    `select 1 from progress_locks where email=$1 and date=$2`,
    [req.userEmail, date]
  );
  res.json({ date, locked: r.rowCount > 0 });
});

// --- collation (enriched)
app.get('/api/updates/today', async (_req, res) => {
  const date = todayISO();
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
  // load names if any
  for (const [email, obj] of byUser) {
    const u = await pool.query(`select name from users where email=$1`, [
      email,
    ]);
    obj.name = u.rows[0]?.name || '';
  }
  const users = Array.from(byUser.values())
    .map((u) => ({
      email: u.email,
      name: u.name,
      locked: u.locked,
      tickets: Array.from(u.tickets.values()).sort((a, b) =>
        String(a.ticketId).localeCompare(String(b.ticketId))
      ),
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
  select (at at time zone 'Asia/Singapore')::date as d
  from progress_updates
)

      select
        min(d) as first_day,
        max(d) as last_day,
        count(*) filter (where d = (now() at time zone 'Asia/Singapore')::date) as today_count,
        count(*) filter (where d >= ((now() at time zone 'Asia/Singapore')::date - 6)) as last7_count,
        count(*) as rows_total
      from pu
      `
    );

    const lastSync = syncRow.rows[0]?.last_sync || null;
    const s = stats.rows[0] || {};
    const hasData = !!s.last_day;

    // Recommend default range = last 7 days (or today if empty)
    const todayISO = new Date().toISOString().slice(0, 10);
    const toISO = hasData ? String(s.last_day).slice(0, 10) : todayISO;
    const fromISO = hasData
      ? new Date(Date.parse(toISO) - 6 * 24 * 3600 * 1000)
          .toISOString()
          .slice(0, 10)
      : todayISO;

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

// serve the saved TSV if it's been exported already
app.get('/api/exports/today', (_req, res) => {
  const date = todayISO();
  const file = path.join(EXPORT_DIR, `updates-${date}.tsv`);
  if (!fs.existsSync(file)) {
    return res.status(404).json({ error: 'not ready' });
  }
  res.setHeader('Content-Type', 'text/tab-separated-values; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="updates-${date}.tsv"`
  );
  res.send(fs.readFileSync(file));
});

// “No updates yet today” (PM signal)
app.get('/api/updates/missing', requireAuth, async (req, res) => {
  // PMs only
  const me = await pool.query('select role from users where email=$1', [
    req.userEmail,
  ]);
  if (me.rows[0]?.role !== 'pm')
    return res.status(403).json({ error: 'pm only' });

  const date = todayISO();
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

// JSON: /api/updates/range?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/updates/range', async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const from = parseDateParam(req.query.from, today);
  const to = parseDateParam(req.query.to, today);

  const r = await pool.query(
    `
    SELECT
      u.at::date                          AS "date",
      t.assigned_to                       AS "assignedTo",
      u.ticket_id                         AS "ticketId",
      t.title,
      t.state,
      u.code,
      u.note
    FROM progress_updates u
    JOIN tickets t ON t.id = u.ticket_id
    WHERE u.at::date BETWEEN $1 AND $2
    ORDER BY u.at::date DESC, t.assigned_to NULLS LAST, u.ticket_id
  `,
    [from, to]
  );

  res.json({ from, to, items: r.rows, count: r.rowCount });
});

// TSV: /api/updates/range.tsv?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/updates/range.tsv', async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const from = parseDateParam(req.query.from, today);
  const to = parseDateParam(req.query.to, today);

  const r = await pool.query(
    `
    SELECT
      u.at::date        AS "date",
      t.assigned_to     AS "assignedTo",
      u.ticket_id       AS "ticketId",
      t.title,
      t.state,
      u.code,
      u.note
    FROM progress_updates u
    JOIN tickets t ON t.id = u.ticket_id
    WHERE u.at::date BETWEEN $1 AND $2
    ORDER BY u.at::date DESC, t.assigned_to NULLS LAST, u.ticket_id
  `,
    [from, to]
  );

  function cell(x) {
    // basic TSV escaping: replace tabs/newlines
    return String(x == null ? '' : x)
      .replace(/\t/g, ' ')
      .replace(/\r?\n/g, ' ');
  }

  let out = 'date\tassignedTo\tticketId\ttitle\tstate\tcode\tnote\n';
  for (const row of r.rows) {
    out +=
      [
        cell(row.date),
        cell(row.assignedTo),
        cell(row.ticketId),
        cell(row.title),
        cell(row.state),
        cell(row.code),
        cell(row.note),
      ].join('\t') + '\n';
  }

  res.setHeader('Content-Type', 'text/tab-separated-values; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="progress_${from}_to_${to}.tsv"`
  );
  res.send(out);
});

// --- blockers radar
app.get('/api/updates/blockers', async (_req, res) => {
  const date = todayISO();
  const r = await pool.query(
    `select u.ticket_id as "ticketId", u.email, u.code, u.note, u.at,
         t.title, t.state, t.type, t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
     from progress_updates u
     left join tickets t on t.id = u.ticket_id
     where u.date = $1`,
    [date]
  );
  const isBlockerCode = (c) => c && /^(600|700|800)_/.test(String(c));
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

// --- TSV export
app.get('/api/updates/today.tsv', async (_req, res) => {
  const date = todayISO();
  const r = await pool.query(
    `select u.email, u.ticket_id as "ticketId", u.code, u.note,
            t.title, t.state, t.iteration_path as "iterationPath", t.assigned_to as "assignedTo",
            u.at
     from progress_updates u
     left join tickets t on t.id = u.ticket_id
     where u.date = $1`,
    [date]
  );
  // latest per (email,ticket)
  const map = new Map();
  for (const x of r.rows) {
    const k = `${x.email}:${x.ticketId}`;
    const prev = map.get(k);
    if (!prev || x.at > prev.at) map.set(k, x);
  }
  let tsv =
    'date\tuser\tticketId\ttitle\tstate\tcode\tnote\titerationPath\tassignedTo\n';
  for (const x of Array.from(map.values()).sort(
    (a, b) =>
      a.email.localeCompare(b.email) ||
      String(a.ticketId).localeCompare(String(b.ticketId))
  )) {
    const fields = [
      date,
      x.email,
      x.ticketId,
      x.title || '',
      x.state || '',
      x.code || '',
      (x.note || '').replace(/\t/g, ' ').replace(/\r?\n/g, ' '),
      x.iterationPath || '',
      x.assignedTo || '',
    ];
    tsv += fields.join('\t') + '\n';
  }
  res.setHeader('Content-Type', 'text/tab-separated-values; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="updates-${date}.tsv"`
  );
  res.send(tsv);
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

app.listen(PORT, () =>
  console.log(`API (Postgres) on http://localhost:${PORT}`)
);
