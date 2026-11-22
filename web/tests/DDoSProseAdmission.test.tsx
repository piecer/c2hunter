import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import DDoSAIInterpretation from '../src/DDoSAIInterpretation';
import ReportLanguageScope from '../src/ReportLanguage';

const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));
const id = 'ddos-1234567890abcdef';
const valid = () => ({ schema_version: 'ddos-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Saved interpretation.', risk_context: [{ interpretation: 'Observed shape.', uncertainty: 'Impact unmeasured.', finding_ids: [id] }], prioritized_checks: [], response_considerations: [], limitations: ['No attribution.'] });
async function mount() {
  localStorage.setItem('c2hunter-report-language', 'en');
  const run = { id: 'saved', analysis_kind: 'DDOS_ATTACK', status: 'COMPLETED', language: 'en', ddos_interpretation: valid() };
  vi.stubGlobal('fetch', vi.fn(async (input: unknown) => Response.json(String(input).endsWith('/ai-capabilities') ? { available: false } : String(input).endsWith('/ai-runs/saved') ? run : { items: [run], current_page: 1, page_size: 50, total: 1 })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, structuralSharing: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><ReportLanguageScope><DDoSAIInterpretation jobId="job" completed/></ReportLanguageScope></QueryClientProvider>);
  await waitFor(() => expect(client.isFetching()).toBe(0));
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  return { client, run };
}
it('localizes DDoS latest status without translating saved prose or invoking inference', async () => {
  await mount();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(screen.getByRole('status', { name: '최신 AI 실행' })).toHaveTextContent('완료');
  expect(screen.getByText('Saved interpretation.')).toHaveAttribute('lang', 'en');
  expect(vi.mocked(fetch).mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
it.each(['long text', 'many claims', 'many IDs', 'deep text'])('rejects %s before DDoS prose serialization or DOM publication', async mutation => {
  const { client, run } = await mount();
  const output: Record<string, unknown> = valid();
  if (mutation === 'long text') output.summary = 'x'.repeat(1201);
  if (mutation === 'many claims') output.risk_context = Array.from({ length: 11 }, () => valid().risk_context[0]);
  if (mutation === 'many IDs') output.risk_context = [{ ...valid().risk_context[0], finding_ids: Array.from({ length: 21 }, () => id) }];
  if (mutation === 'deep text') output.summary = { nested: { value: 'not text' } };
  const serialize = vi.fn(() => 'UNTRUSTED SERIALIZATION');
  Object.defineProperty(output, 'toJSON', { value: serialize });
  act(() => { client.setQueryData(['ai-run', 'saved'], { ...run, ddos_interpretation: output }); });
  expect(await screen.findByText('No validated interpretation is available for this run.')).toBeVisible();
  expect(serialize).not.toHaveBeenCalled();
  expect(screen.queryByText('Saved interpretation.')).not.toBeInTheDocument();
});
it('retains every producer-bounded Unicode claim and limitation through ordinary paging, ignoring unrelated envelope data', async () => {
  const { client, run } = await mount();
  const output = { ...valid(), summary: '😀'.repeat(1200), risk_context: Array.from({ length: 10 }, (_, i) => ({ interpretation: `Claim ${i}`, uncertainty: '😀'.repeat(1200), finding_ids: Array.from({ length: 20 }, (_, n) => `ddos-${n.toString(16).padStart(16, '0')}`) })), limitations: Array.from({ length: 12 }, (_, i) => `Limit ${i}`) };
  const serialize = vi.fn();
  act(() => { client.setQueryData(['ai-run', 'saved'], { ...run, ddos_interpretation: output, ignored: { toJSON: serialize } }); });
  expect(await screen.findByText('Claim 0')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  const seen: string[] = [];
  for (let page = 0; page < 4; page += 1) {
    seen.push(...screen.getAllByText(/^Claim /).map(node => node.textContent!));
    if (page < 3) fireEvent.click(screen.getByRole('button', { name: 'Next AI claims' }));
  }
  expect(seen).toEqual(Array.from({ length: 10 }, (_, i) => `Claim ${i}`));
  fireEvent.click(screen.getByRole('button', { name: 'Limitations' }));
  const limitations: string[] = [];
  for (let page = 0; page < 4; page += 1) {
    limitations.push(...screen.getAllByText(/^Limit \d/).map(node => node.textContent!));
    if (page < 3) fireEvent.click(screen.getByRole('button', { name: 'Next AI claims' }));
  }
  expect(limitations).toEqual(output.limitations);
  expect(serialize).not.toHaveBeenCalled();
});
