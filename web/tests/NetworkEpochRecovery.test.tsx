import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import { warningLabel } from '../src/reportTranslations';
import { openCoverage, openEvidence } from './reportDisclosure';

const python = process.env.C2HUNTER_TEST_PYTHON ?? process.env.C2HUNTER_PYTHON ?? resolve('../.venv/bin/python');
const generate = () => JSON.parse(execFileSync(python, ['tests/network_epoch_fixture.py', '--projection'], { encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1024 * 1024 }));
const first = generate();
const second = generate();
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));

function setup(name: string) {
  const job = first.cases[name].job;
  localStorage.setItem('c2hunter-token', 'offline-epoch-token');
  localStorage.setItem('c2hunter-report-language', 'en');
  const fetcher = vi.fn(async (input: unknown, init?: RequestInit) => {
    expect(init?.method ?? 'GET').toBe('GET');
    return Response.json(String(input).endsWith(`/analysis-jobs/${job.id}`) ? job : { items: [] });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App /></MemoryRouter></QueryClientProvider>);
  return fetcher;
}

it('retains deterministic real producer and AI projection bytes, independently of job UUIDs/times', () => {
  expect(first.schema_version).toBe('network-epoch-fixture-v1');
  expect(first.source.live_capture_exercised).toBe(false);
  expect(first.source.model_invoked).toBe(false);
  for (const name of ['recovered', 'suppressed', 'normal']) {
    const a = first.cases[name]; const b = second.cases[name];
    for (const field of ['report', 'ai']) {
      const bytes = JSON.stringify(a[field]);
      expect(bytes).toBe(JSON.stringify(b[field]));
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(a[`${field}_sha256`]);
    }
    expect(a.typed_records_sha256).toBe(b.typed_records_sha256);
    expect(a.job.network_anomaly).toEqual(a.report);
    expect(a.ai.warnings).toEqual(a.report.warnings);
    expect(a.public_response.status_code).toBe(200);
    expect(a.job.source.sha256).toBe(a.pcap_sha256);
    expect(a.job.source_type).toBe('PCAP_UPLOAD');
    expect(a.job.mode).toBe('PCAP_UPLOAD');
  }
});

it('shows recovered SYN evidence with sticky cap and actual parser omission in the existing App', async () => {
  const { report, ai, job } = first.cases.recovered;
  expect(report.summary).toMatchObject({ verdict: 'anomaly_observed', tracking_limited_records: 1, incomplete_records: 1, counts_are_lower_bounds: true, truncated: true, coverage_complete: false });
  expect(ai.summary).toMatchObject({ tracking_limited_records: 1, counts_are_lower_bounds: true, coverage_complete: false });
  expect(report.warnings).toEqual(['CORRELATION_LIMIT_REACHED', 'PARSER_SKIPPED_PACKETS']);
  expect(job.source.skipped_packet_count).toBe(1);
  const fetcher = setup('recovered');
  expect(await screen.findByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(screen.getByRole('region', { name: 'Source capability' })).toHaveTextContent('Uploaded PCAP origin');
  expect(screen.getByText(/Incomplete or unknown coverage/)).toBeVisible();
  expect(screen.getByText(/Report truncated:/)).toBeVisible();
  openCoverage();
  for (const code of report.warnings) expect(screen.getByText(warningLabel('en', code))).toBeVisible();
  openEvidence();
  const article = within(screen.getByRole('article'));
  for (const text of [...report.issues[0].evidence, ...report.issues[0].uncertainty, ...report.issues[0].next_checks]) expect(article.getByText(text)).toBeVisible();
  expect(article.getByRole('region', { name: 'Representative flow evidence' })).toBeVisible();
  expect(article.getByRole('region', { name: 'Supporting measurements' })).toBeVisible();
  expect(report.issues[0].event_count).toBe(1);
  expect(report.issues[0].examples[0].measurements.reasons).toContain('CORRELATION_LIMIT_REACHED');
  expect(fetcher).toHaveBeenCalled();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(screen.getByRole('heading', { name: '이상 징후 관찰됨' })).toBeVisible();
});

it('does not turn the prior limited epoch into false SYN evidence or healthy coverage', async () => {
  const { report } = first.cases.suppressed;
  expect(report.issues).toEqual([]);
  expect(report.summary.tracking_limited_records).toBe(3);
  setup('suppressed');
  expect(await screen.findByRole('heading', { name: 'Insufficient data' })).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'Anomaly observed' })).not.toBeInTheDocument();
  openCoverage();
  for (const code of report.warnings) expect(screen.getByText(warningLabel('en', code))).toBeVisible();
});

it('retains the actual bidirectional normal packet countercontrol', async () => {
  const { report } = first.cases.normal;
  expect(report.summary).toMatchObject({ verdict: 'no_clear_anomaly', coverage_complete: true, tracking_limited_records: 0, incomplete_records: 0 });
  expect(report.warnings).toEqual([]);
  setup('normal');
  expect(await screen.findByRole('heading', { name: 'No clear anomaly observed' })).toBeVisible();
});
