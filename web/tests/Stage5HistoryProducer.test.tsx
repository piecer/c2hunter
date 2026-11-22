import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { historyListing, historyProducer, historyUnavailable } from './stage5HistoryFixture';

it('the public list omits real persisted DDoS limits rather than publishing invented summary flags', () => {
  const row = historyListing.items[0];
  expect(historyProducer.persisted_report.summary).toMatchObject({ truncated: true, counts_are_lower_bounds: true, coverage_complete: false });
  expect(historyProducer.persisted_report.warnings.length).toBeGreaterThan(0);
  expect(Object.keys(row.ddos_attack_summary).sort()).toEqual(['confidence', 'coverage_complete', 'finding_count', 'primary_attack_type', 'primary_objective', 'verdict']);
  expect(row).not.toHaveProperty('ddos_attack');
  expect(row.ddos_attack_summary).not.toHaveProperty('warnings');
  expect(row.ddos_attack_summary).not.toHaveProperty('truncated');
  expect(row.ddos_attack_summary).not.toHaveProperty('counts_are_lower_bounds');
  expect(JSON.parse(historyProducer.detail_wire).ddos_attack).toEqual(historyProducer.persisted_report);
  expect(historyProducer.denied_operations).toEqual([]);
});

it('actual public list wire retains coverage and job warnings and explains unavailable DDoS detail', async () => {
  localStorage.setItem('c2hunter-token', 'test');
  localStorage.setItem('c2hunter-report-language', 'en');
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(init?.method ?? 'GET').toBe('GET');
    expect(String(input)).toMatch(/^\/api\/v1\/analysis-jobs\?/);
    return new Response(historyProducer.list_wire, { headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetch);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses?search=Producer%20limited%20DDoS&status=COMPLETED&sort=name&page=1']}><App/></MemoryRouter></QueryClientProvider>);
  try {
    const row = within(await screen.findByRole('table', { name: 'Analysis history' })).getAllByRole('row')[1];
    const produced = historyListing.items[0];
    expect(row).toHaveTextContent(`${produced.ddos_attack_summary.finding_count} DDoS findings`);
    expect(row).toHaveTextContent('Coverage incomplete');
    for (const warning of produced.warnings) expect(row).toHaveTextContent(warning);
    expect(within(row).getByText(historyUnavailable)).toBeVisible();
    expect(within(row).getByRole('link', { name: produced.name })).toHaveAttribute('href', `/analyses/${encodeURIComponent(produced.id)}`);
    expect(row).not.toHaveTextContent('Counts are lower bounds');
    expect(row).not.toHaveTextContent('Truncated');
    expect(fetch).toHaveBeenCalledTimes(1);
  } finally { view.unmount(); client.clear(); }
});
