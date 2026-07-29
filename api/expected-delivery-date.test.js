import assert from 'node:assert/strict';
import test from 'node:test';

import {
  EXPECTED_DELIVERY_DATE_SCHEMA_SQL,
  expectedDeliveryDateSyncValue,
} from './expected-delivery-date.js';

test('expected delivery date schema is an additive nullable date column', () => {
  assert.match(
    EXPECTED_DELIVERY_DATE_SCHEMA_SQL,
    /add column if not exists expected_delivery_date date/i,
  );
  assert.doesNotMatch(EXPECTED_DELIVERY_DATE_SCHEMA_SQL, /not null/i);
});

test('omitted expected delivery date remains distinguishable from a clear', () => {
  assert.deepEqual(expectedDeliveryDateSyncValue({}), {
    provided: false,
    value: null,
  });
  assert.deepEqual(
    expectedDeliveryDateSyncValue({ expectedDeliveryDate: null }),
    { provided: true, value: null },
  );
  assert.deepEqual(
    expectedDeliveryDateSyncValue({ expectedDeliveryDate: '' }),
    { provided: true, value: null },
  );
});

test('expected delivery date accepts date-only and TFS ISO values', () => {
  assert.deepEqual(
    expectedDeliveryDateSyncValue({ expectedDeliveryDate: '2026-08-14' }),
    { provided: true, value: '2026-08-14' },
  );
  assert.deepEqual(
    expectedDeliveryDateSyncValue({
      expectedDeliveryDate: '2026-08-14T00:00:00Z',
    }),
    { provided: true, value: '2026-08-14' },
  );
});

test('expected delivery date rejects invalid values', () => {
  assert.throws(
    () =>
      expectedDeliveryDateSyncValue({
        expectedDeliveryDate: '08/14/2026',
      }),
    /ISO date/,
  );
  assert.throws(
    () =>
      expectedDeliveryDateSyncValue({
        expectedDeliveryDate: '2026-02-30',
      }),
    /valid calendar date/,
  );
});
