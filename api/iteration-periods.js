const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;

export const ITERATION_PERIODS_SCHEMA_SQL = `
create table if not exists iteration_periods (
  id bigserial primary key,
  project text not null,
  team text not null,
  iteration_name text not null,
  iteration_path text not null,
  start_date date not null,
  end_date date not null,
  first_observed_at timestamptz not null default now(),
  last_observed_at timestamptz not null default now(),
  constraint iteration_periods_valid_dates check (
    end_date >= start_date and end_date <= start_date + 30
  ),
  constraint iteration_periods_identity unique (project, team, iteration_path)
);

create index if not exists iteration_periods_team_dates
  on iteration_periods (project, team, end_date desc, start_date desc);
`;

function text(value) {
  return String(value || '').trim();
}

export function dateOnly(value) {
  const candidate = text(value).slice(0, 10);
  if (!DATE_ONLY_RE.test(candidate)) return null;
  const parsed = new Date(`${candidate}T00:00:00.000Z`);
  return Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== candidate
    ? null
    : candidate;
}

export function normalizeIterationRecord(record) {
  const iterationName = text(record?.iteration_name || record?.name);
  const iterationPath = text(record?.iteration_path || record?.path);
  const startDate = dateOnly(record?.start_date || record?.startDate);
  const endDate = dateOnly(record?.end_date || record?.endDate);
  if (!iterationName || !iterationPath || !startDate || !endDate) return null;

  const duration = Math.floor(
    (Date.parse(`${endDate}T00:00:00Z`) - Date.parse(`${startDate}T00:00:00Z`)) /
      86400000,
  ) + 1;
  if (duration < 1 || duration > 31) return null;

  return {
    iteration_name: iterationName,
    iteration_path: iterationPath,
    start_date: startDate,
    end_date: endDate,
  };
}

export function normalizeIterationSyncPayload(body) {
  const project = text(body?.project);
  const team = text(body?.team);
  const currentPath = text(body?.current_iteration_path || body?.currentIterationPath);
  const currentName = text(body?.current_iteration_name || body?.currentIterationName);
  const raw = Array.isArray(body?.iterations) ? body.iterations : [];
  if (!project || !team || !currentPath || !currentName) {
    return { ok: false, error: 'project, team, current iteration path, and current iteration name are required' };
  }
  if (!raw.length || raw.length > 12) {
    return { ok: false, error: 'iterations must contain between 1 and 12 records' };
  }

  const iterations = raw.map(normalizeIterationRecord);
  if (iterations.some((item) => !item)) {
    return { ok: false, error: 'each iteration requires a valid name, path, start date, and end date (1-31 days)' };
  }
  if (!iterations.some((item) => item.iteration_path === currentPath)) {
    return { ok: false, error: 'current iteration path must be present in iterations' };
  }

  const unique = [];
  const seen = new Set();
  for (const item of iterations) {
    if (seen.has(item.iteration_path)) continue;
    seen.add(item.iteration_path);
    unique.push(item);
  }
  return {
    ok: true,
    value: {
      project,
      team,
      current_iteration_path: currentPath,
      current_iteration_name: currentName,
      iterations: unique,
    },
  };
}

export function iterationStatus(period, today) {
  if (period.start_date > today) return 'future';
  if (period.end_date < today) return 'completed';
  return 'current';
}

