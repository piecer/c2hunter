import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const testsDirectory = dirname(fileURLToPath(import.meta.url));
// Default only when absent; an explicit invalid override must fail, not fall back.
const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve(testsDirectory, '../../.venv/bin/python');
if (!python) throw new Error('C2HUNTER_TEST_PYTHON must name the owned producer runtime');
export const producer = JSON.parse(execFileSync(python, ['-I', '-B', resolve(testsDirectory, 'investigation_producer.py')], {
  encoding: 'utf8', maxBuffer: 2 * 1024 * 1024,
  env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
})) as { fixtures: Record<string, string>; schemas: unknown; counts: Record<string, number>; origin: string; python: string; isolated: number; origins: Record<string, string>; additional: { mode: string; fixtures: Record<string, string> } };
export function freshFixture(name: string): unknown {
  const raw = producer.additional.fixtures[name];
  if (!raw) throw new Error('Unknown fresh producer witness ' + name);
  return JSON.parse(raw);
}
export function fixture(name: string): unknown {
  const key = Object.keys(producer.fixtures).find(key => key.endsWith('/' + name));
  if (!key) throw new Error('Unknown producer fixture ' + name);
  return JSON.parse(producer.fixtures[key]);
}
