import { readFileSync } from 'node:fs';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
async function setup() {
  localStorage.setItem('c2hunter-token', 'fixture'); localStorage.setItem('c2hunter-report-language', 'en');
  const findingId = report.findings[0].id;
  const run = { id: 'saved', analysis_job_id: 'job', dataset_id: 'dataset', analysis_kind: 'DDOS_ATTACK', status: 'COMPLETED', language: 'en', ddos_interpretation: { schema_version: 'ddos-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Saved bounded hypothesis.', risk_context: [], prioritized_checks: Array.from({ length: 4 }, (_, i) => ({ priority: 'HIGH', check: `Check ${i}`, finding_ids: [findingId] })), response_considerations: [], limitations: ['Service impact is unmeasured.'] } };
  const job = { id: 'job', name: 'DDoS source', status: 'COMPLETED', dataset_id: 'dataset', analysis: { module: 'ddos_attack' }, ddos_attack: report };
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input); calls.push(`${init?.method ?? 'GET'} ${url}`);
    return Response.json(url.endsWith('/analysis-jobs/job') ? job : url.endsWith('/ai-capabilities') ? { available: false } : url.endsWith('/ai-runs/saved') ? run : { items: [run], current_page: 1, page_size: 50, total: 1 });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/job']}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('button', { name: 'Open DDoS AI interpretation' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  return { ...view, client, job, run, findingId, calls };
}
async function open() { fireEvent.click(await screen.findByRole('button', { name: 'Open DDoS AI interpretation' })); }
it.each(['metrics', 'missing dataset', 'absent report', 'ABA'])('never authenticates historical DDoS citations from matching IDs: %s', async fault => {
  const { client, job, findingId, calls } = await setup();
  await open();
  expect(screen.getAllByRole('button', { name: findingId })[0]).toBeDisabled();
  const changed = structuredClone(job);
  if (fault === 'missing dataset') delete (changed as { dataset_id?: string }).dataset_id;
  else if (fault === 'absent report') delete (changed as { ddos_attack?: unknown }).ddos_attack;
  else changed.ddos_attack.findings[0].metrics.packet_count += 1;
  await act(async () => { client.setQueryData(['job', 'job'], changed); await new Promise(resolve => setTimeout(resolve, 0)); });
  await open();
  expect(screen.getAllByRole('button', { name: findingId })[0]).toBeDisabled();
  if (fault === 'missing dataset' || fault === 'absent report') expect(screen.getAllByRole('button', { name: `Inspect current report, not verified saved evidence: ${findingId}` })[0]).toBeDisabled();
  if (fault === 'ABA') {
    await act(async () => { client.setQueryData(['job', 'job'], job); await new Promise(resolve => setTimeout(resolve, 0)); });
    await open();
    expect(screen.getAllByRole('button', { name: findingId })[0]).toBeDisabled();
  }
  expect(screen.getByText('Saved bounded hypothesis.')).toBeVisible();
  expect(screen.getByText(/Saved-source verification is unavailable/)).toBeVisible();
  expect(calls.every(call => call.startsWith('GET '))).toBe(true);
});
it('returns from separate current-report inspection to the exact saved check page and invoker', async () => {
  const { findingId } = await setup(); await open();
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  fireEvent.click(screen.getByRole('button', { name: 'Prioritized checks' }));
  fireEvent.click(screen.getByRole('button', { name: 'Next AI claims' }));
  const inspect = screen.getByRole('button', { name: `Inspect current report, not verified saved evidence: ${findingId}` });
  inspect.focus(); fireEvent.click(inspect);
  expect(screen.getByRole('region', { name: 'DDoS finding evidence' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Return to saved AI claim' }));
  const article = screen.getByRole('article', { name: 'Full DDoS AI interpretation' });
  expect(within(article).getByText('Check 3')).toBeVisible();
  expect(within(article).getByRole('navigation', { name: 'AI claim pages' })).toHaveTextContent('2 / 2');
  expect(within(article).getByRole('button', { name: `Inspect current report, not verified saved evidence: ${findingId}` })).toHaveFocus();
  expect(screen.queryByRole('region', { name: 'DDoS finding evidence' })).not.toBeInTheDocument();
});
