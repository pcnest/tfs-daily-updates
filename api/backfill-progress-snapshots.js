import dotenv from 'dotenv';
import { Pool } from 'pg';
import os from 'os';
import path from 'path';
import fs from 'fs/promises';
import {
  buildSnapshotProposal,
  normalizeTfsRevisions,
  validateDateRange,
} from './progress-snapshot-backfill.js';

dotenv.config();

function parseArgs(argv) {
  const args = {};
  for (const token of argv) {
    if (token === '--apply') args.apply = true;
    else if (token === '--allow-unresolved') args.allowUnresolved = true;
    else if (token.startsWith('--') && token.includes('=')) {
      const [name, ...rest] = token.slice(2).split('=');
      args[name] = rest.join('=');
    } else {
      throw new Error(`unsupported argument: ${token}`);
    }
  }
  return args;
}

function required(value, name) {
  if (!String(value || '').trim()) throw new Error(`${name} is required`);
  return String(value).trim();
}

function positiveInteger(value, fallback, name) {
  const parsed = value == null ? fallback : Number.parseInt(String(value), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJsonWithRetry(url, options, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, options);
      if (response.ok) return response.json();
      const body = await response.text();
      const error = new Error(
        `TFS request failed (${response.status}): ${body.slice(0, 200)}`,
      );
      error.status = response.status;
      if (response.status !== 429 && response.status < 500) throw error;
      lastError = error;
    } catch (error) {
      lastError = error;
      if (error?.status && error.status !== 429 && error.status < 500) {
        throw error;
      }
    }
    if (attempt < attempts) await sleep(250 * 2 ** (attempt - 1));
  }
  throw lastError;
}

async function fetchTfsRevisions({ baseUrl, collection, ticketId, auth }) {
  const all = [];
  const pageSize = 200;
  for (let skip = 0; ; skip += pageSize) {
    const url = new URL(
      `${baseUrl.replace(/\/$/, '')}/${encodeURIComponent(collection)}/_apis/wit/workitems/${encodeURIComponent(ticketId)}/revisions`,
    );
    url.searchParams.set('api-version', '2.0');
    url.searchParams.set('$top', String(pageSize));
    url.searchParams.set('$skip', String(skip));
    const json = await fetchJsonWithRetry(url, {
      headers: { Authorization: auth, Accept: 'application/json' },
    });
    const page = Array.isArray(json?.value) ? json.value : [];
    all.push(...page);
    if (page.length < pageSize) break;
  }
  return normalizeTfsRevisions(all);
}

async function mapWithConcurrency(items, concurrency, mapper) {
  const results = new Array(items.length);
  let nextIndex = 0;
  async function worker() {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      results[index] = await mapper(items[index], index);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, () => worker()),
  );
  return results;
}

function auditProposal(proposal) {
  if (proposal.status !== 'resolved') return proposal;
  return {
    updateId: proposal.updateId,
    ticketId: proposal.ticketId,
    updateDate: proposal.updateDate,
    updateAt: proposal.updateAt,
    status: proposal.status,
    revision: proposal.revision,
    ticketState: proposal.ticketState,
    ticketType: proposal.ticketType,
    ticketSeverity: proposal.ticketSeverity,
    ticketChangedDate: proposal.ticketChangedDate,
    ticketStateChangeDate: proposal.ticketStateChangeDate,
  };
}

function summarize(proposals, ticketCount, from, to, mode) {
  const resolved = proposals.filter((item) => item.status === 'resolved');
  const unresolved = proposals.filter((item) => item.status !== 'resolved');
  const stateCounts = {};
  for (const item of resolved) {
    const state = item.ticketState || '(blank)';
    stateCounts[state] = (stateCounts[state] || 0) + 1;
  }
  return {
    mode,
    from,
    to,
    targetRows: proposals.length,
    targetTickets: ticketCount,
    resolvedRows: resolved.length,
    unresolvedRows: unresolved.length,
    stateCounts,
  };
}

async function writeAudit(payload, from, to, mode) {
  const directory = path.join(os.tmpdir(), 'tfs-daily-updates-backfill');
  await fs.mkdir(directory, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(
    directory,
    `progress-snapshots_${from}_${to}_${mode}_${stamp}.json`,
  );
  await fs.writeFile(file, JSON.stringify(payload, null, 2), 'utf8');
  return file;
}

async function applyProposals(pool, proposals, from, to) {
  const client = await pool.connect();
  let updatedRows = 0;
  let skippedRows = 0;
  try {
    await client.query('begin');
    for (const proposal of proposals) {
      if (proposal.status !== 'resolved') continue;
      const result = await client.query(
        `update progress_updates
            set ticket_state = $1,
                ticket_title = $2,
                ticket_type = $3,
                ticket_severity = $4,
                ticket_changed_date = $5::timestamptz,
                ticket_state_change_date = $6::timestamptz,
                ticket_snapshot_at = now()
          where id = $7::bigint
            and ticket_id = $8
            and date between $9::date and $10::date
            and ticket_snapshot_at is null`,
        [
          proposal.ticketState,
          proposal.ticketTitle,
          proposal.ticketType,
          proposal.ticketSeverity,
          proposal.ticketChangedDate,
          proposal.ticketStateChangeDate,
          proposal.updateId,
          proposal.ticketId,
          from,
          to,
        ],
      );
      if (result.rowCount === 1) updatedRows += 1;
      else skippedRows += 1;
    }
    await client.query('commit');
    return { updatedRows, skippedRows };
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { from, to } = validateDateRange(args.from, args.to);
  const mode = args.apply ? 'apply' : 'dry-run';
  const expectedConfirmation = `${from}:${to}`;
  if (args.apply && args.confirm !== expectedConfirmation) {
    throw new Error(
      `apply requires --confirm=${expectedConfirmation} for this exact batch`,
    );
  }

  const databaseUrl = required(process.env.DATABASE_URL, 'DATABASE_URL');
  const tfsPat = required(process.env.TFS_PAT, 'TFS_PAT');
  const tfsUrl = required(process.env.TFS_URL, 'TFS_URL');
  const tfsCollection = required(process.env.TFS_COLLECTION, 'TFS_COLLECTION');
  const concurrency = positiveInteger(args.concurrency, 4, 'concurrency');
  const maxRows = positiveInteger(args['max-rows'], 1000, 'max-rows');
  const ticketFilter = args.ticket ? String(args.ticket) : null;
  const auth = `Basic ${Buffer.from(`:${tfsPat}`).toString('base64')}`;
  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: { rejectUnauthorized: false },
  });

  try {
    const params = [from, to];
    let ticketClause = '';
    if (ticketFilter) {
      params.push(ticketFilter);
      ticketClause = `and ticket_id = $${params.length}`;
    }
    const target = await pool.query(
      `select id::text as id,
              ticket_id as "ticketId",
              date::text as date,
              at
         from progress_updates
        where date between $1::date and $2::date
          and ticket_id <> '0'
          and ticket_snapshot_at is null
          ${ticketClause}
        order by ticket_id, at, id`,
      params,
    );
    if (target.rowCount > maxRows) {
      throw new Error(
        `target has ${target.rowCount} rows, exceeding --max-rows=${maxRows}`,
      );
    }

    const updates = target.rows;
    const ticketIds = [...new Set(updates.map((row) => String(row.ticketId)))];
    console.log(
      JSON.stringify({ mode, from, to, rows: updates.length, tickets: ticketIds.length }),
    );

    const revisionResults = await mapWithConcurrency(
      ticketIds,
      concurrency,
      async (ticketId, index) => {
        const revisions = await fetchTfsRevisions({
          baseUrl: tfsUrl,
          collection: tfsCollection,
          ticketId,
          auth,
        });
        if ((index + 1) % 20 === 0 || index + 1 === ticketIds.length) {
          console.log(`[tfs] fetched ${index + 1}/${ticketIds.length} tickets`);
        }
        return [ticketId, revisions];
      },
    );
    const revisionsByTicket = new Map(revisionResults);
    const proposals = updates.map((update) =>
      buildSnapshotProposal(update, revisionsByTicket.get(String(update.ticketId))),
    );
    const summary = summarize(proposals, ticketIds.length, from, to, mode);
    const unresolved = proposals.filter((item) => item.status !== 'resolved');
    const sample = proposals
      .filter((item) => item.ticketId === '214663')
      .concat(proposals.filter((item) => item.ticketId !== '214663').slice(0, 10))
      .map(auditProposal);

    if (args.apply && unresolved.length && !args.allowUnresolved) {
      const auditFile = await writeAudit(
        { summary, unresolved: unresolved.map(auditProposal), sample },
        from,
        to,
        'blocked',
      );
      throw new Error(
        `${unresolved.length} rows are unresolved; review ${auditFile} or rerun with --allow-unresolved`,
      );
    }

    let applyResult = null;
    if (args.apply) {
      applyResult = await applyProposals(pool, proposals, from, to);
      const remaining = await pool.query(
        `select count(*)::int as rows
           from progress_updates
          where date between $1::date and $2::date
            and ticket_id <> '0'
            and ticket_snapshot_at is null
            ${ticketClause}`,
        params,
      );
      applyResult.remainingLegacyRows = remaining.rows[0].rows;
    }

    const audit = {
      generatedAt: new Date().toISOString(),
      summary,
      applyResult,
      unresolved: unresolved.map(auditProposal),
      proposals: proposals.map(auditProposal),
    };
    const auditFile = await writeAudit(audit, from, to, mode);
    console.log(JSON.stringify({ summary, applyResult, sample, auditFile }, null, 2));
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error(`[backfill] ${error.message}`);
  process.exitCode = 1;
});
