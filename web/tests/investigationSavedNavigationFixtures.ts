import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Evidence, InvestigationRun } from '../src/investigationTypes';
import type { JobRun } from '../src/jobInvestigationTypes';
const directory = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve(directory, '../../.venv/bin/python'), ['-I', '-B', resolve(directory, 'investigation_saved_navigation_producer.py')], {
  encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024,
}));
// Transport input from the real producer; actual consumers validate the wire.
export const savedNavigation = {
  ip: raw.ip as InvestigationRun,
  ipQueued: raw.ip_queued as InvestigationRun,
  job: raw.job as JobRun,
  jobQueued: raw.job_queued as JobRun,
  ipEvidence: raw.ip_evidence as Record<string, Evidence>,
  jobEvidence: raw.job_evidence as Record<string, Evidence>,
};
