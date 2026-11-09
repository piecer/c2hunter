import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const directory = dirname(fileURLToPath(import.meta.url));
const python = process.env.C2HUNTER_JOB_TEST_PYTHON ?? resolve(directory, '../../.venv/bin/python');
if (!python) throw new Error('C2HUNTER_JOB_TEST_PYTHON must name a Python interpreter');
const bridge = resolve(directory, 'job_investigation_producer.py');
function invoke(args: string[], input?: string): string {
  return execFileSync(python, ['-I', '-B', bridge, ...args], { encoding: 'utf8', input,
    timeout: 30_000, killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
}
// Collection-time generation, once per module instance, never inside a 5s test
// body; no global/shared cache can turn ordinary runs into sealed-only tests.
export const producer = JSON.parse(invoke([])) as {
  mode: string; additional: Record<string,string>; fixtures: Record<string, string>; schemas: Record<string, unknown>;
  executable: string; prefix: string; origins: Record<string, string>; network_events: string[];
};
export const jobFixture = (name: string): unknown => JSON.parse(producer.fixtures[name]);
export function pythonAcceptance(cases: { kind: string; raw: string }[]): { accepted: boolean; exception?: string }[] {
  return JSON.parse(invoke(['--validate'], JSON.stringify(cases)));
}
