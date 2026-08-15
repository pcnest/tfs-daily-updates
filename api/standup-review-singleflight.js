export async function runStandupSingleFlight(inFlight, key, task) {
  if (!(inFlight instanceof Map)) {
    throw new TypeError('inFlight must be a Map');
  }
  if (typeof task !== 'function') {
    throw new TypeError('task must be a function');
  }

  const existing = inFlight.get(key);
  if (existing) return existing;

  const pending = Promise.resolve().then(task);
  inFlight.set(key, pending);
  try {
    return await pending;
  } finally {
    if (inFlight.get(key) === pending) inFlight.delete(key);
  }
}
