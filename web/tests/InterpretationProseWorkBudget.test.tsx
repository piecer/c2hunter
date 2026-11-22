import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import * as numeric from '../src/networkNumericEvidence';
import * as evidence from '../src/networkEvidenceContext';
import { setAuthentication } from '../src/authentication';

const fixture = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_numeric_fixture.py'], { encoding: 'utf8', maxBuffer: 20000000 }));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));

it.each(['source', 'run', 'authentication'])('keeps prose-only work local without caching validation across %s invalidation', async fault => {
  const sample = structuredClone(fixture.maximum);
  localStorage.setItem('c2hunter-token', 'fixture-token');
  localStorage.setItem('c2hunter-report-language', 'en');
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const path = String(input); calls.push(`${init?.method ?? 'GET'} ${path}`);
    if (path.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, remote: false });
    if (path.endsWith('/ai-runs/' + sample.run.id)) return Response.json(sample.run);
    if (path.endsWith('/numeric-job/ai-runs')) return Response.json({ items: [sample.run] });
    if (path.endsWith('/analysis-jobs/numeric-job')) return Response.json({ ...sample.job, name: 'Prose budget' });
    return Response.json({ items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } }); clients.push(client);
  const display = vi.spyOn(numeric, 'networkRunDisplay');
  const signature = vi.spyOn(evidence, 'evidenceSignature');
  const source = vi.spyOn(numeric, 'currentNumericSource');
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/numeric-job']}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading', { name: 'Prose budget' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  const counts = () => [display.mock.calls.length, signature.mock.calls.length, source.mock.calls.length];
  const before = counts(), requests = [...calls];
  expect(before.every(count => count > 0)).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Prioritized next checks' }));
  fireEvent.click(screen.getByRole('button', { name: 'Next AI claims' }));
  expect(within(screen.getByRole('article', { name: 'Full AI interpretation' })).getByRole('navigation', { name: 'AI claim pages' })).toHaveTextContent('2 / 4');
  expect(counts()).toEqual(before);
  expect(calls).toEqual(requests);

  if (fault === 'source') {
    const changed = structuredClone(sample.job);
    changed.network_anomaly.issues[0].examples[0].facts.tcp_sequence++;
    await act(async () => { client.setQueryData(['job', sample.job.id], changed); await new Promise(resolve => setTimeout(resolve, 0)); });
    expect(signature.mock.calls.length).toBeGreaterThan(before[1]);
    fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
    expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
    expect(screen.getByText(/integer precision cannot be confirmed/)).toBeVisible();
    await act(async () => { client.setQueryData(['job', sample.job.id], sample.job); await new Promise(resolve => setTimeout(resolve, 0)); });
    fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
    expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
    expect(screen.getByText(/integer precision cannot be confirmed/)).toBeVisible();
  } else if (fault === 'run') {
    const changed = structuredClone(sample.run);
    changed.network_interpretation.summary = '😀'.repeat(1201);
    await act(async () => { client.setQueryData(['ai-run', sample.run.id], changed); await new Promise(resolve => setTimeout(resolve, 0)); });
    expect(display.mock.calls.length).toBeGreaterThan(before[0]);
    expect(screen.queryByRole('article', { name: 'Full AI interpretation' })).toBeNull();
    expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
    await act(async () => { client.setQueryData(['ai-run', sample.run.id], sample.run); await new Promise(resolve => setTimeout(resolve, 0)); });
    expect(screen.queryByRole('article', { name: 'Full AI interpretation' })).toBeNull();
  } else {
    act(() => setAuthentication(null));
    expect(screen.queryByRole('article', { name: 'Full AI interpretation' })).toBeNull();
    expect(screen.queryByRole('region', { name: 'Verified numeric source facts' })).toBeNull();
  }
  expect(calls.filter(call => !call.startsWith('GET '))).toEqual([]);
});
