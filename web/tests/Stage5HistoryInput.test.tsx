import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';

it.each(['network_anomaly', 'ddos_attack'])('history uses %s summary counts, never C2 fallback, with visible qualifications', async module => {
  // Synthetic renderer controls retained unchanged; not the compact DDoS wire contract.
  // Stage5HistoryProducer covers the real public list's absent detail fields.
  const network = module === 'network_anomaly';
  const summary = { verdict: 'insufficient_evidence', confidence: 'low', finding_count: 7, issue_count: 7, coverage_complete: false, truncated: true, counts_are_lower_bounds: true };
  const result = (value: unknown) => network ? { network_anomaly: { summary: value, issues: [{ id: 'only-displayed' }] } } : { ddos_attack_summary: value };
  history([
    { analysis: { module }, ...result(summary), warnings: ['Source retention limited'] },
    { analysis: { module }, candidate_count: 0 },
    { analysis: { module }, ...result({ ...summary, finding_count: 0, issue_count: 0, coverage_complete: true, truncated: false, counts_are_lower_bounds: false }) },
    { analysis: { module }, ...result({ verdict: 'insufficient_evidence' }) },
  ]);
  const rows = within(await screen.findByRole('table', { name: 'Analysis history' })).getAllByRole('row');
  expect(rows[1]).toHaveTextContent(network ? '7 Network issues' : '7 DDoS findings');
  expect(rows[1]).toHaveTextContent('insufficient_evidence');
  expect(rows[1]).toHaveTextContent('Coverage incomplete');
  expect(rows[1]).toHaveTextContent('Source retention limited');
  if (network) { expect(rows[1]).toHaveTextContent('Truncated'); expect(rows[1]).toHaveTextContent('Counts are lower bounds'); }
  expect(rows[2]).toHaveTextContent(network ? 'Network summary unavailable' : 'DDoS summary unavailable');
  for (const row of rows.slice(1)) expect(row).not.toHaveTextContent('candidates');
  expect(rows[3]).toHaveTextContent(network ? '0 Network issues' : '0 DDoS findings');
  expect(rows[4]).toHaveTextContent(network ? 'Unavailable Network issues' : 'Unavailable DDoS findings');
  expect(rows[4]).toHaveTextContent('Coverage unavailable');
});

function history(jobs: Record<string, unknown>[]) {
  localStorage.setItem('c2hunter-token', 'stage5');
  vi.spyOn(api, 'get').mockResolvedValue({ items: jobs.map((job, index) => ({ id: String(index), name: `Result ${index}`, status: 'COMPLETED', ...job })), total: jobs.length, page: 1, page_size: 50 });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses']}><App/></MemoryRouter></QueryClientProvider>);
}

it('history distinguishes missing C2 counters from explicit zero and retains source warnings', async () => {
  history([{ analysis: { module: 'c2' }, warnings: ['Capture omitted packets'] }, { candidate_count: 0, packet_count: 0, flow_count: 0 }]);
  const table = await screen.findByRole('table', { name: 'Analysis history' });
  const rows = within(table).getAllByRole('row');
  expect(rows[1]).toHaveTextContent('C2');
  expect(rows[1]).toHaveTextContent('Unavailable candidates');
  expect(rows[1]).toHaveTextContent('Unavailable packets · Unavailable flows');
  expect(rows[1]).toHaveTextContent('Capture omitted packets');
  expect(rows[1]).not.toHaveTextContent('0 candidates');
  expect(rows[2]).toHaveTextContent('0 candidates');
  expect(rows[2]).toHaveTextContent('0 packets · 0 flows');
});
