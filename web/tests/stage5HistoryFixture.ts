import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The response body is captured from the real ASGI route, not reconstructed here.
const directory = dirname(fileURLToPath(import.meta.url));
export const historyProducer = JSON.parse(execFileSync(
  process.env.C2HUNTER_TEST_PYTHON ?? resolve(directory, '../../.venv/bin/python'),
  ['-I', '-B', resolve(directory, 'stage5_history_producer.py')],
  { encoding: 'utf8', timeout: 30000, killSignal: 'SIGKILL' },
)) as {
  list_path: string; detail_path: string; list_wire: string; detail_wire: string; ai_runs_wire: string;
  persisted_report: { summary: { truncated: boolean; counts_are_lower_bounds: boolean; coverage_complete: boolean }; warnings: string[] };
  producer_origins: Record<string, string>; denied_operations: string[];
};
export const historyListing = JSON.parse(historyProducer.list_wire) as {
  items: { id: string; name: string; warnings: string[]; ddos_attack_summary: Record<string, unknown> }[];
  total: number; page: number; page_size: number;
};
export const historyUnavailable = 'DDoS detail limits unavailable in this list (truncation, lower bounds, report warnings). Open the analysis name for the full report.';
