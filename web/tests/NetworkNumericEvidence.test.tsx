import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, within, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import { parseNumericRun, currentNumericSource } from '../src/networkNumericEvidence';
import { projectNetworkReport } from '../src/networkReportValidation';
const fixture = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_numeric_fixture.py'], { encoding: 'utf8', maxBuffer: 20000000 }));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
it.each(fixture.cases as { name: string; raw: string; accepted: boolean }[])('Python JSON wire parity: $name', c => {
  expect(Boolean(parseNumericRun(JSON.parse(c.raw)))).toBe(c.accepted);
});
it.each(['value', 'unit', 'scope', 'quality', 'missing', 'extra', 'foreign-run', 'foreign-job', 'foreign-dataset'])('rejects altered envelope %s atomically', fault => {
  const run = structuredClone(fixture.run), row = run.network_numeric_evidence.items[0];
  if (fault === 'value') row.value = '1100.0';
  if (fault === 'unit') row.unit = 'raw';
  if (fault === 'scope') row.qualifiers.scope = 'issue';
  if (fault === 'quality') row.qualifiers.quality_reasons = [];
  if (fault === 'missing') run.network_numeric_evidence.items = [];
  if (fault === 'extra') row.extra = 0;
  if (fault === 'foreign-run') run.network_numeric_evidence.run_id = 'other';
  if (fault === 'foreign-job') run.network_numeric_evidence.analysis_job_id = 'other';
  if (fault === 'foreign-dataset') run.network_numeric_evidence.dataset_id = 'other';
  expect(parseNumericRun(run)).toBeUndefined();
});
it.each(['getter', 'root-getter', 'prototype', 'hole', 'toJSON'])('never invokes custom %s hooks', fault => {
  const run = structuredClone(fixture.run); let called = 0;
  const trap = () => { called++; throw new Error('hook'); };
  if (fault === 'root-getter') Object.defineProperty(run, 'network_input', { enumerable: true, get: trap });
  if (fault === 'getter') Object.defineProperty(run.network_input, 'summary', { enumerable: true, get: trap });
  if (fault === 'prototype') Object.setPrototypeOf(run.network_input, { toString: trap });
  if (fault === 'hole') delete run.network_numeric_evidence.items[0];
  if (fault === 'toJSON') run.network_input.toJSON = trap;
  expect(parseNumericRun(run)).toBeUndefined(); expect(called).toBe(0);
});
it.each(['safe', 'unsafe', 'changed', 'filtered-first', 'wrong-job', 'wrong-run'])('checks current-report binding %s without rounded Number equality', fault => {
  const run = structuredClone(fixture.run), report = structuredClone(fixture.report);
  if (fault === 'unsafe') report.issues[0].event_count = Number('9223372036854775807');
  if (fault === 'changed') report.issues[0].examples[0].measurements.observed_rtt_ms.mean = 1100;
  if (fault === 'filtered-first') report.issues[0].examples.unshift({ invalid: true });
  const context = { job: { id: fault === 'wrong-job' ? 'other' : 'numeric-job', dataset_id: 'numeric-dataset', status: 'COMPLETED' }, projection: projectNetworkReport(report), generation: {}, current: () => true, navigate: () => {} };
  const parsed = parseNumericRun(run)!;
  expect(currentNumericSource(context, run, fault === 'wrong-run' ? 'other' : run.id, parsed)).toBe(fault === 'safe');
});
it.each([false, true])('actual App numeric facts and maximum=%s preserve full scalar prose, DOM and navigation', async maximum => {
  const sample = maximum ? fixture.maximum : fixture;
  localStorage.setItem('c2hunter-token', 'fixture-token');
  localStorage.setItem('c2hunter-report-language', 'en');
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const path = String(input); calls.push(`${init?.method ?? 'GET'} ${path}`);
    if (path.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, remote: false });
    if (path.endsWith('/ai-runs/' + sample.run.id)) return Response.json(sample.run);
    if (path.endsWith('/numeric-job/ai-runs')) return Response.json({ items: [sample.run] });
    if (path.endsWith('/analysis-jobs/numeric-job')) return Response.json({ ...sample.job, name: 'Numeric investigation', mode: 'PCAP_UPLOAD', source_type: 'PCAP_UPLOAD' });
    return Response.json({ items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/numeric-job']}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading', { name: 'Numeric investigation' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
  const facts = screen.getByRole('region', { name: 'Verified numeric source facts' });
  expect(facts).toHaveTextContent('100.0 ms');
  expect(facts).not.toHaveTextContent('1100');
  if (!maximum) expect(screen.getByText('AI says 1100 ms')).toBeVisible();
  if (maximum) {
    fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
    expect(within(screen.getByRole('article', { name: 'Full AI interpretation' })).getAllByText('😀'.repeat(1200)).length).toBe(53);
    expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
  }
  expect(screen.getByText('AI prose — numerical claims are unverified.')).toBeVisible();
  const before = [...calls];
  fireEvent.click(within(facts).getAllByRole('button', { name: /Source/ }).at(-1)!);
  expect(screen.getByRole('region', { name: 'Representative flow evidence' })).toHaveFocus();
  expect(calls).toEqual(before);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
  if (!maximum) {
    fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
    const changed = structuredClone(sample.run);
    changed.network_input.summary.evaluated_records = '5';
    await act(async () => { client.setQueryData(['ai-run', sample.run.id], changed); await new Promise(resolve => setTimeout(resolve, 0)); });
    expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
    await act(async () => { client.setQueryData(['ai-run', sample.run.id], sample.run); await new Promise(resolve => setTimeout(resolve, 0)); });
    expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
    expect(screen.getByText(/integer precision cannot be confirmed/)).toBeVisible();
  }
});
