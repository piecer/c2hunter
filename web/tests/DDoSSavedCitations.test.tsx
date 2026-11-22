import { readFileSync } from 'node:fs';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import DDoSAIInterpretation from '../src/DDoSAIInterpretation';
import DDoSAttackPanel from '../src/DDoSAttackPanel';
const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(client => client.clear()));
it.each([true, false])('DDoS finding references use only a supported current report path (source=%s)', async source => {
  localStorage.setItem('c2hunter-report-language', 'en');
  const id = report.findings[0].id;
  const run = { id: 'ddos-saved', analysis_kind: 'DDOS_ATTACK', analysis_job_id: 'job', dataset_id: 'dataset', status: 'COMPLETED', language: 'en', ddos_interpretation: { schema_version: 'ddos-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Scoped hypothesis.', risk_context: [{ interpretation: 'Review target logs.', uncertainty: 'Impact unknown.', finding_ids: [id] }], prioritized_checks: [], response_considerations: [], limitations: ['Impact not established.'] } };
  vi.stubGlobal('fetch', vi.fn(async (input: unknown) => Response.json(String(input).endsWith('/ai-capabilities') ? { available: false } : String(input).endsWith('/ai-runs/ddos-saved') ? run : { items: [run] })));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  const ai = <DDoSAIInterpretation jobId="job" completed={source}/>;
  render(<QueryClientProvider client={client}><DDoSAttackPanel report={report} job={source ? { id: 'job', dataset_id: 'dataset' } : undefined}>{ai}</DDoSAttackPanel></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: 'Open DDoS AI interpretation' }));
  const citation = await screen.findByRole('button', { name: id });
  expect(citation).toBeDisabled();
  expect(screen.getByText('Saved-source verification is unavailable; finding IDs do not verify saved measurements.')).toBeVisible();
  const inspect = screen.getByRole('button', { name: `Inspect current report, not verified saved evidence: ${id}` });
  if (!source) { expect(inspect).toBeDisabled(); return; }
  expect(inspect).toBeEnabled(); fireEvent.click(inspect);
  expect(screen.getByRole('region', { name: 'DDoS finding evidence' })).toBeVisible();
  expect(screen.queryByText('Scoped hypothesis.')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Close detail' }));
  expect(screen.getByRole('heading', { name: 'Suspicious DDoS-shaped traffic observed' })).toHaveFocus();
});
