import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import schemas from '../src/investigationSchemas.json';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

beforeEach(() => {
  vi.resetModules();
  for (const name of [
    'C2HUNTER_TEST_PYTHON',
    'C2HUNTER_INVESTIGATION_PRODUCER_ROOT',
    'C2HUNTER_INVESTIGATION_SOURCE_MANIFEST',
    'C2HUNTER_INVESTIGATION_SOURCE_SHA256',
    'C2HUNTER_INVESTIGATION_SERVICE_MANIFEST',
    'C2HUNTER_INVESTIGATION_SERVICE_SHA256',
  ]) vi.stubEnv(name, undefined);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

it('runs the real checkout-local fresh producer when CI supplies no interpreter or manifests', async () => {
  const { producer } = await import('./investigationFixtures');
  expect(producer).toMatchObject({
    mode: 'FRESH_PRODUCER',
    network_policy: 'FRESH_PROVIDER_NETWORK',
    executable: resolve(root, '.venv/bin/python'),
    prefix: resolve(root, '.venv'),
    isolated: 1,
    origin: resolve(root, 'controller/src/c2hunter_controller/ai_investigation_schema.py'),
    counts: { ai_investigation_service: 19, ai_investigation: 5 },
    additional: { mode: 'FRESH_IN_MEMORY_SCRIPTED_ACTIONS_NO_HTTP_NO_INFERENCE' },
  });
  expect(producer.schemas).toEqual(schemas);
  expect(Object.keys(producer.fixtures)).toHaveLength(24);
  expect(Object.keys(producer.additional.fixtures)).toHaveLength(35);
  expect(Object.keys(producer.origins)).toContain('tests.test_ai_investigation_service_fixtures');
  for (const origin of Object.values(producer.origins)) expect(origin.startsWith(root + '/')).toBe(true);
  for (const [name, bytes] of Object.entries(producer.fixtures)) {
    expect(bytes).toBe(readFileSync(resolve(root, 'controller/tests/fixtures', name + '.json'), 'utf8'));
  }
}, 20_000);

it('honors an explicit valid interpreter instead of choosing the default', async () => {
  const override = resolve(root, '.venv/bin/python3');
  vi.stubEnv('C2HUNTER_TEST_PYTHON', override);
  const { producer } = await import('./investigationFixtures');
  expect(producer).toMatchObject({
    executable: override,
    prefix: resolve(root, '.venv'),
    isolated: 1,
    mode: 'FRESH_PRODUCER',
    origin: resolve(root, 'controller/src/c2hunter_controller/ai_investigation_schema.py'),
    counts: { ai_investigation_service: 19, ai_investigation: 5 },
  });
  expect(producer.schemas).toEqual(schemas);
  expect(Object.keys(producer.additional.fixtures)).toHaveLength(35);
}, 20_000);

it('fails closed for an explicit nonexistent interpreter without running the default', async () => {
  const missing = resolve(root, '.venv/bin/nonexistent-investigation-python');
  vi.stubEnv('C2HUNTER_TEST_PYTHON', missing);
  await expect(import('./investigationFixtures')).rejects.toMatchObject({ code: 'ENOENT', path: missing });
});

it('fails closed for an explicit empty interpreter without running the default', async () => {
  vi.stubEnv('C2HUNTER_TEST_PYTHON', '');
  await expect(import('./investigationFixtures')).rejects.toThrow('C2HUNTER_TEST_PYTHON must name the owned producer runtime');
});
