import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = dirname(fileURLToPath(import.meta.url));
export const sensorProducer = JSON.parse(execFileSync(
  process.env.C2HUNTER_TEST_PYTHON ?? resolve(directory, '../../.venv/bin/python'),
  ['-I', '-B', resolve(directory, 'stage5_sensor_producer.py')],
  { encoding: 'utf8', timeout: 30000, maxBuffer: 8 * 1024 * 1024, killSignal: 'SIGKILL' },
)) as {
  provenance: string;
  maximum: { sensor_id: string; name: string; config_version: number; agent_version: string; capture_sources: { interface: string; direction: string; bpf_filter: string; enabled: boolean; store_pcap: boolean }[]; internal_networks: string[]; interfaces: { interface: string; last_error: string }[] };
  request: { config_version: number; capture_sources: unknown[]; internal_networks: string[] };
  ack: unknown;
  pages: Record<string, { items: Record<string, unknown>[]; page: number; page_size: number; total: number }>;
  producer_origins: Record<string, string>;
  denied_operations: string[];
};
export function sensorProducerPage(url: string) {
  const parsed = new URL(url, 'http://fixture');
  const params = parsed.searchParams;
  if (!params.has('page')) params.set('page', '1');
  if (!params.has('page_size')) params.set('page_size', '50');
  const normalized = [...params].sort().map(pair => JSON.stringify(pair)).join();
  return Object.entries(sensorProducer.pages).find(([key]) => {
    const expected = new URL(key, 'http://fixture');
    return expected.pathname === parsed.pathname && [...expected.searchParams].sort().map(pair => JSON.stringify(pair)).join() === normalized;
  })?.[1];
}
