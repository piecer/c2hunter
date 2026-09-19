// DDoS AI output remains manual, bounded, and visibly distinct from deterministic facts.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import DDoSAIInterpretation from '../src/DDoSAIInterpretation';
import ReportLanguageScope from '../src/ReportLanguage';

beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));

it('does not run automatically and renders a saved validated DDoS interpretation', async () => {
  const findingId = 'ddos-1234567890abcdef';
  const run = {
    id: 'ddos-ai', status: 'COMPLETED', analysis_kind: 'DDOS_ATTACK', language: 'en',
    ddos_interpretation: {
      schema_version: 'ddos-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en',
      summary: 'Traffic shape warrants analyst review.',
      risk_context: [{ interpretation: 'Observed SYN shape may exhaust state.', finding_ids: [findingId], uncertainty: 'Service impact is not measured.' }],
      prioritized_checks: [{ priority: 'HIGH', check: 'Verify service impact.', finding_ids: [findingId] }],
      response_considerations: [{ consideration: 'Review edge controls.', finding_ids: [findingId], requires_human_approval: true }],
      limitations: ['No actor attribution.'],
    },
  };
  const fetcher = vi.fn(async (input: unknown, init?: RequestInit) => {
    void init;
    return Response.json(String(input).endsWith('/ai-capabilities')
      ? { ddos_interpretation: true, available: true, provider: 'fake', model_name: 'fake', destination: null, remote: false, reason: null }
      : String(input).endsWith('/ai-runs/ddos-ai') ? run : { items: [run] });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ReportLanguageScope><DDoSAIInterpretation jobId="job" completed/></ReportLanguageScope></QueryClientProvider>);
  expect(await screen.findByRole('button', { name: 'Open DDoS AI interpretation' })).toBeVisible();
  expect(fetcher.mock.calls.every(call => String(call[1]?.method ?? 'GET') === 'GET')).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  expect(await screen.findByText('Traffic shape warrants analyst review.')).toBeVisible();
  expect(screen.getByText(/analyst review required/)).toBeVisible();
  expect(screen.getAllByText(findingId)).toHaveLength(3);
  client.clear();
});
