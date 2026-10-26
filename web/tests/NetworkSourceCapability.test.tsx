import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
const report = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_report_fixture.py'], { encoding: 'utf8' })).syn_reset;
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
function setup(route: string, source_type?: string, mode?: string, savedJob?: Record<string, unknown>) {
  localStorage.setItem('c2hunter-token', 'synthetic-token'); localStorage.setItem('c2hunter-report-language', 'en');
  const posts: unknown[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const path = String(input);
    if (init?.method === 'POST') { posts.push(JSON.parse(String(init.body))); return Response.json({ id: 'cap-job' }); }
    if (savedJob && path.endsWith(`/analysis-jobs/${savedJob.id}`)) return Response.json(savedJob);
    if (path.endsWith('/analysis-jobs/cap-job')) return Response.json({ id: 'cap-job', name: 'Capability job', status: 'COMPLETED', source_type, mode, packet_count: 1, source: { raw_bytes_retained: true }, analysis: { module: 'network_anomaly' }, network_anomaly: report });
    return Response.json({ items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><App/></MemoryRouter></QueryClientProvider>);
  return { posts };
}
it.skipIf(!process.env.C2HUNTER_NATIVE_CAPABILITY_BUNDLE)('consumes hash-bound actual native HISTORICAL and PCAP public jobs without relabeling their source', async () => {
  const bytes = readFileSync(process.env.C2HUNTER_NATIVE_CAPABILITY_BUNDLE!);
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(process.env.C2HUNTER_NATIVE_CAPABILITY_SHA256);
  const bundle = JSON.parse(bytes.toString());
  expect(bundle.schema_version).toBe('network-native-capability-fixture-v1');
  expect(bundle.native.job.mode).toBe('HISTORICAL'); expect(bundle.native.job.source_type).toBe('SENSOR_CAPTURE');
  expect(bundle.native.job.network_anomaly.summary).toMatchObject({ evaluated_records: 0, incomplete_records: 2, verdict: 'insufficient_evidence' });
  setup(`/analyses/${bundle.native.job.id}`, undefined, undefined, bundle.native.job);
  expect(await screen.findByRole('heading', { name: 'Insufficient data' })).toBeVisible();
  expect(screen.getByRole('region', { name: 'Source capability' })).toHaveTextContent('Historical sensor origin');
  expect(screen.getByRole('region', { name: 'Source capability' })).toHaveTextContent('does not transmit network packet-evidence');
});
it.skipIf(!process.env.C2HUNTER_NATIVE_CAPABILITY_BUNDLE)('preserves same-byte PCAP positive control alongside packet capability disclosure', async () => {
  const bundle = JSON.parse(readFileSync(process.env.C2HUNTER_NATIVE_CAPABILITY_BUNDLE!, 'utf8'));
  expect(bundle.pcap.job.mode).toBe('PCAP_UPLOAD'); expect(bundle.pcap.job.source_type).toBe('PCAP_UPLOAD');
  expect(bundle.pcap.job.network_anomaly.summary).toMatchObject({ evaluated_records: 6, verdict: 'anomaly_observed' });
  setup(`/analyses/${bundle.pcap.job.id}`, undefined, undefined, bundle.pcap.job);
  expect(await screen.findByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(screen.getByRole('region', { name: 'Source capability' })).toHaveTextContent('Uploaded PCAP origin');
});
it('updates LIVE/HISTORICAL disclosure before submission and preserves mode and capture payload', async () => {
  const { posts } = setup('/analyses/new');
  fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
  expect(screen.getByRole('region', { name: /Source capability/ })).toHaveTextContent('LIVE aggregate');
  expect(screen.getByRole('region', { name: /Source capability/ })).toHaveTextContent('패킷');
  fireEvent.change(screen.getByLabelText('Data source'), { target: { value: 'HISTORICAL' } });
  expect(screen.getByRole('region', { name: /Source capability/ })).toHaveTextContent('Historical sensor aggregates');
  fireEvent.change(screen.getByLabelText('Analysis name'), { target: { value: 'Historical check' } });
  const start = screen.getByRole('button', { name: /Start analysis/ }); expect(start).toBeEnabled(); fireEvent.click(start);
  await waitFor(() => expect(posts).toHaveLength(1));
  expect(posts[0]).toMatchObject({ mode: 'HISTORICAL', analysis: { module: 'network_anomaly' }, capture: { duration_seconds: 300, max_packets: 2000000, bpf_filter: 'ip', store_pcap: true, directions: ['INBOUND', 'OUTBOUND'] } });
});
it('shows packet-level upload capability without unconditional ICMP echo RTT promises', () => {
  setup('/analyses/upload'); fireEvent.change(screen.getByLabelText('Analysis module'), { target: { value: 'network_anomaly' } });
  expect(screen.getByRole('region', { name: /Source capability/ })).toHaveTextContent('Packet-level PCAP');
  expect(screen.queryByText(/ICMP errors and echo RTT/)).not.toBeInTheDocument();
});
it.each([
  ['SENSOR_CAPTURE', 'LIVE', 'Sensor LIVE origin'], ['SENSOR_CAPTURE', 'HISTORICAL', 'Historical sensor origin'], ['SENSOR_CAPTURE', 'REANALYSIS', 'Sensor-origin reanalysis'],
  ['PCAP_UPLOAD', 'PCAP_UPLOAD', 'Uploaded PCAP origin'], ['PCAP_UPLOAD', 'REANALYSIS', 'Uploaded-PCAP-origin reanalysis'],
  [undefined, 'LIVE', 'Unknown source capability'], ['FUTURE', 'LIVE', 'Unknown source capability'], ['PCAP_UPLOAD', 'LIVE', 'Unknown source capability'], ['SENSOR_CAPTURE', 'PCAP_UPLOAD', 'Unknown source capability'], ['SENSOR_CAPTURE', undefined, 'Unknown source capability'],
])('shows result %s/%s disclosure with details closed and preserves positive facts', async (source, mode, expected) => {
  setup('/analyses/cap-job', source, mode);
  const capability = await screen.findByRole('region', { name: /Source capability/ });
  expect(capability).toHaveTextContent(expected!);
  expect(capability).toHaveTextContent('available bidirectional packet-level PCAP');
  expect(screen.getByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(screen.getByRole('button', { name: /Job details/ })).toHaveAttribute('aria-expanded', 'false');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(within(screen.getByRole('region', { name: /입력 지원 범위/ })).getByRole('heading')).toBeVisible();
});
