import { expect, it, vi } from 'vitest';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { producer } from './jobInvestigationFixtures';
import hashes from './jobInvestigationFixtureHashes.json';
import { createHash } from 'node:crypto';

it('fresh ordinary loader invokes checkout-local real offline producer and accounts for every artifact', () => {
  expect(Object.keys(producer.fixtures).sort()).toEqual(Object.keys(hashes).sort());
  for(const [name,raw] of Object.entries(producer.fixtures)) expect(createHash('sha256').update(raw).digest('hex')).toBe(hashes[name as keyof typeof hashes]);
  expect(producer.mode).toBe('FRESH_ASGI_PRODUCER');
  expect(producer.network_events).toEqual([]);
  expect(Object.keys(producer.fixtures)).toHaveLength(23);
  expect(producer.executable).toBe(resolve(dirname(fileURLToPath(import.meta.url)), '../../.venv/bin/python'));
  expect(producer.origins['tests.test_ai_job_investigation_fixtures']).toContain('/checkout/controller/tests/');
});
it.each(['', '/nonexistent-job-python'])('explicit invalid interpreter %j fails closed', async override => {
  vi.resetModules(); vi.stubEnv('C2HUNTER_JOB_TEST_PYTHON', override);
  try { await expect(import('./jobInvestigationFixtures')).rejects.toThrow(); }
  finally { vi.unstubAllEnvs(); vi.resetModules(); }
});
