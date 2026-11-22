import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import NetworkAIInterpretation from '../src/NetworkAIInterpretation';
import DDoSAIInterpretation from '../src/DDoSAIInterpretation';
import ReportLanguageScope from '../src/ReportLanguage';
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
const variants = [{ Component: NetworkAIInterpretation, kind: 'NETWORK_ANOMALY', open: 'Open AI interpretation', submit: 'AI interpretation' }, { Component: DDoSAIInterpretation, kind: 'DDOS_ATTACK', open: 'Open DDoS AI interpretation', submit: 'Run DDoS AI interpretation' }];
it.each(variants)('$kind blocks unknown ownership, continues one page per click, and keeps manual history independent after late errors', async ({ Component, kind, open, submit }) => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const requests: string[] = [];
  const other = (i: number) => ({ id: `other-${i}`, analysis_kind: 'C2', status: 'COMPLETED', language: 'en' });
  const active = { id: 'active', analysis_kind: kind, status: 'ANALYZING', language: 'en' };
  let fail = true;
  vi.stubGlobal('fetch', vi.fn(async (input: unknown) => {
    const url = String(input); requests.push(url);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, ddos_interpretation: true, remote: false });
    if (url.endsWith('/ai-runs/active')) return Response.json(active);
    if (url.endsWith('/job/ai-runs')) return Response.json({ items: Array.from({ length: 50 }, (_, i) => other(i)), current_page: 1, page_size: 50, total: 101 });
    if (url.endsWith('page=2&page_size=50')) {
      if (fail) return Response.json({ error: { message: 'Later page unavailable' } }, { status: 503 });
      return Response.json({ items: Array.from({ length: 50 }, (_, i) => other(50 + i)), current_page: 2, page_size: 50, total: 101 });
    }
    if (url.endsWith('page=3&page_size=50')) return Response.json({ items: [active], current_page: 3, page_size: 50, total: 101 });
    throw new Error(url);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><ReportLanguageScope><Component jobId="job" completed/></ReportLanguageScope></QueryClientProvider>);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(requests.filter(url => url.includes('page='))).toEqual([]);
  fireEvent.click(screen.getByRole('button', { name: open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByRole('button', { name: submit })).toBeDisabled();
  expect(screen.getByRole('region', { name: 'Saved AI runs' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Continue latest-run lookup' }));
  expect(await screen.findByText('Latest-run lookup failed; admission remains blocked.')).toBeVisible();
  fail = false;
  fireEvent.click(screen.getByRole('button', { name: 'Next saved runs' }));
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: 'Next saved runs' }));
  expect(await screen.findByRole('button', { name: 'View saved run active' })).toBeVisible();
  expect(screen.getByRole('button', { name: submit })).toBeDisabled();
  // Manual history must not mark the independently failed discovery as resolved.
  expect(screen.getByText('Latest-run lookup failed; admission remains blocked.')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Continue latest-run lookup' }));
  await act(async () => {});
  await waitFor(() => expect(screen.getByRole('button', { name: 'Continue latest-run lookup' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Continue latest-run lookup' }));
  expect(await screen.findByRole('button', { name: 'Cancel AI run' })).toBeVisible();
  expect(screen.getByRole('button', { name: submit })).toBeDisabled();
});
it.each(variants)('$kind refuses missing pagination metadata even when the list is empty', async ({ Component, open, submit }) => {
  localStorage.setItem('c2hunter-report-language', 'en');
  vi.stubGlobal('fetch', vi.fn(async (input: unknown) => Response.json(String(input).endsWith('/ai-capabilities') ? { available: true, network_interpretation: true, ddos_interpretation: true, remote: false } : { items: [] })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><ReportLanguageScope><Component jobId="job" completed/></ReportLanguageScope></QueryClientProvider>);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: open }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByRole('button', { name: submit })).toBeDisabled();
});

it.each(['exhausted', 'changed total', 'wrong page', 'truncated'])('continuation remains bounded and treats %s truthfully', async fault => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const other = (i: number) => ({ id: `other-${i}`, analysis_kind: 'C2', status: 'COMPLETED', language: 'en' });
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown) => {
    const url = String(input); calls.push(url);
    if (url.endsWith('/ai-capabilities')) return Response.json({ available: true, ddos_interpretation: true, remote: false });
    if (url.endsWith('/job/ai-runs')) return Response.json({ items: Array.from({ length: 50 }, (_, i) => other(i)), current_page: 1, page_size: 50, total: 51 });
    return Response.json({ items: fault === 'truncated' ? [] : [other(50)], current_page: fault === 'wrong page' ? 1 : 2, page_size: 50, total: fault === 'changed total' ? 52 : 51 });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><ReportLanguageScope><DDoSAIInterpretation jobId="job" completed/></ReportLanguageScope></QueryClientProvider>);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  fireEvent.click(screen.getByRole('button', { name: 'New AI interpretation' }));
  expect(screen.getByRole('button', { name: 'Run DDoS AI interpretation' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Continue latest-run lookup' }));
  if (fault === 'exhausted') await waitFor(() => expect(screen.getByRole('button', { name: 'Run DDoS AI interpretation' })).toBeEnabled());
  else {
    expect(await screen.findByText('Latest-run lookup failed; admission remains blocked.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Run DDoS AI interpretation' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Retry latest-run lookup' })).toBeEnabled();
  }
  expect(calls.filter(url => url.includes('/job/ai-runs'))).toHaveLength(2);
  expect(client.getQueryData<{ items: unknown[] }>(['ai-runs', 'job'])?.items).toHaveLength(50);
});
