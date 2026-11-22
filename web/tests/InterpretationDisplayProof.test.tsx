import { afterEach, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { interpretationPage, readInterpretationRuns } from '../src/interpretationRuns';
import NetworkAIInterpretation from '../src/NetworkAIInterpretation';
import { ReportLanguageContext } from '../src/reportLanguageContext';
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));
const legacy = { id: 'legacy', analysis_kind: 'NETWORK_ANOMALY', status: 'COMPLETED', network_interpretation: { schema_version: 'network-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Readable historical prose', possible_causes: [], prioritized_checks: [], correlations: [], limitations: [] } };
it('retains bounded display rows independently of row proof and valid pagination', () => {
  const rows = [legacy, { id: 'ordinary-c2', analysis_job_id: 'job', dataset_id: 'dataset', status: 'COMPLETED', candidate_limit: 20, candidate_ids: [], input_schema_version: '1.0', output_schema_version: '1.0' }];
  const page = interpretationPage({ items: rows, current_page: 1, page_size: 2, total: 4 }, 1);
  expect(page.items).toEqual(rows);
  expect(page).toMatchObject({ discovery: 'unknown', paginationValid: true });
  expect(interpretationPage({ items: Array(201).fill(legacy) }, 1).items).toHaveLength(200);
});
it('never treats a missing kind as proven C2 absence', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ items: [{ id: 'unknown', status: 'COMPLETED' }], current_page: 1, page_size: 50, total: 1 })));
  expect(await readInterpretationRuns('job', 'NETWORK_ANOMALY', new AbortController().signal)).toMatchObject({ discovery: 'unknown' });
});
it('shows legacy output without inventing requested language or admission authority', async () => {
  const posts: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') posts.push(url);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, remote: false });
    if (url.endsWith('/ai-runs/legacy')) return Response.json(legacy);
    return Response.json({ items: [legacy] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><ReportLanguageContext value="en"><NetworkAIInterpretation jobId="job" completed/></ReportLanguageContext></QueryClientProvider>);
  fireEvent.click(screen.getByRole('button', { name: 'Open AI interpretation' }));
  expect(await screen.findByText('Readable historical prose')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'AI interpretation' })).toBeDisabled());
  expect(screen.queryByText(/Requested language:/)).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Cancel AI run' })).not.toBeInTheDocument();
  expect(posts).toEqual([]);
});
