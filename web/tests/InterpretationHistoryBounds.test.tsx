import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import InterpretationHistory from '../src/InterpretationHistory';
import ReportLanguageScope from '../src/ReportLanguage';
it('bounds manual history record inspection before filtering an oversized untrusted page', () => {
  localStorage.setItem('c2hunter-report-language', 'en');
  let inspected = 0;
  const item = { id: 'run', analysis_kind: 'C2', status: 'COMPLETED', language: 'en' as const };
  const items = new Proxy(Array(10000).fill(item), { get(target, key, receiver) { if (typeof key === 'string' && /^\d+$/.test(key)) inspected += 1; return Reflect.get(target, key, receiver); } });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const first = { items, current_page: 1, page_size: 50, total: 10000 };
  const view = render(<QueryClientProvider client={client}><ReportLanguageScope><InterpretationHistory first={first} jobId="job" kind="DDOS_ATTACK" select={vi.fn()}/></ReportLanguageScope></QueryClientProvider>);
  expect(inspected).toBeLessThanOrEqual(200);
  expect(screen.getByRole('region', { name: 'Saved AI runs' })).toBeVisible();
  view.unmount(); client.clear();
});
