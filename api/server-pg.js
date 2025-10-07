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
  const { email, password, name } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'email and password required' });
  const lower = String(email).toLowerCase().trim();
  try {
    await pool.query(
      `insert into users(email, name, pw) values ($1,$2,$3)
       on conflict (email) do update set name=excluded.name, pw=excluded.pw`,
      [lower, name || '', hashPassword(password)]
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

// --- agent pushes tickets
app.post('/api/sync/tickets', async (req, res) => {
  const key = req.header('x-api-key');
  if (!key || key !== API_KEY)
    return res.status(401).json({ error: 'Unauthorized' });
  const { tickets, pushedAt } = req.body || {};
  if (!Array.isArray(tickets))
    return res.status(400).json({ error: 'tickets must be an array' });
  const client = await pool.connect();
  try {
    await client.query('begin');
    for (const t of tickets) {
      await client.query(
        `insert into tickets(id,type,title,state,assigned_to,area_path,iteration_path,changed_date,tags)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         on conflict (id) do update set
           type=excluded.type, title=excluded.title, state=excluded.state, assigned_to=excluded.assigned_to,
           area_path=excluded.area_path, iteration_path=excluded.iteration_path,
           changed_date=excluded.changed_date, tags=excluded.tags`,
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
        ]
      );
    }
    await client.query('commit');
    res.json({ status: 'ok', count: tickets.length, pushedAt });
  } catch (e) {
    await client.query('rollback');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
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
  const { assignedTo, state, iterationPath, areaPath, q } = req.query;
  const clauses = [];
  const params = [];
  let i = 1;

  if (assignedTo) {
    clauses.push(
      `lower(regexp_replace(assigned_to,'^.*\\\\','')) like $${i++}`
    );
    params.push(`%${normId(assignedTo)}%`);
  }
  if (state) {
    clauses.push(`lower(state)=lower($${i++})`);
    params.push(state);
  }
  if (iterationPath) {
    clauses.push(`lower(iteration_path) like lower($${i++})`);
    params.push(`%${iterationPath}%`);
  }
  if (areaPath) {
    clauses.push(`lower(area_path) like lower($${i++})`);
    params.push(`%${areaPath}%`);
  }
  if (q) {
    clauses.push(`(lower(title) like lower($${i++}) or id like $${i++})`);
    params.push(`%${q}%`, `%${q}%`);
  }

  const where = clauses.length ? `where ${clauses.join(' and ')}` : '';
  const sql = `select id,type,title,state,assigned_to as "assignedTo",area_path as "areaPath",
                      iteration_path as "iterationPath",changed_date as "changedDate",tags
               from tickets ${where} order by changed_date desc nulls last, id::bigint nulls last`;
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
            t.title, t.state, t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
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

// --- blockers radar
app.get('/api/updates/blockers', async (_req, res) => {
  const date = todayISO();
  const r = await pool.query(
    `select u.ticket_id as "ticketId", u.email, u.code, u.note, u.at,
            t.title, t.state, t.assigned_to as "assignedTo", t.iteration_path as "iterationPath"
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

app.listen(PORT, () =>
  console.log(`API (Postgres) on http://localhost:${PORT}`)
);
