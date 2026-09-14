import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import NetworkAIInterpretation from '../src/NetworkAIInterpretation';
import { openAI, openEvidence } from './reportDisclosure';
import { vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';
import { patternLabel } from '../src/reportTranslations';

const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const fixtures = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py'], { encoding: 'utf8' })) as Record<string, NetworkAnomalyReport>;
const pages = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', '--pagination'], { encoding: 'utf8' })) as Record<string, NetworkAnomalyReport>;
const largeBytes = () => execFileSync(python, ['tests/network_report_fixture.py', '--glance'], { encoding: 'utf8' });
const large = JSON.parse(largeBytes()) as Record<string, NetworkAnomalyReport>;
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
it.each([...Object.entries(fixtures), ...Object.entries(large), ['twenty', pages[23]]] as [string, NetworkAnomalyReport][])('starts concise and preserves producer-ordered observations for %s', (_name, report) => {
  const { container } = render(<NetworkAnomalyPanel report={report}/>);
  const glance = screen.getByRole('region', { name: 'At a glance' });
  expect(within(glance).getByTestId('network-verdict')).toBeVisible();
  const top = within(glance).queryAllByTestId('top-observation');
  expect(top).toHaveLength(Math.min(3, report.issues!.length));
  top.forEach((item, i) => expect(item).toHaveTextContent(patternLabel('en', report.issues![i].pattern)));
  expect(screen.queryByRole('article')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  expect(container.textContent).not.toContain('Pattern scan →');
  if (!report.summary.coverage_complete) expect(screen.getByText(/Incomplete or unknown coverage/)).toBeVisible();
  if (report.summary.truncated) expect(screen.getByText(/Report truncated:/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'View all anomaly items' }));
  expect(screen.queryAllByRole('article')).toHaveLength(Math.min(8, report.issues!.length));
  expect(container.querySelectorAll('*').length).toBeLessThan(500);
});

it('bounds the full report and AI with one lazy detail owner and all three real examples', async () => {
  expect(JSON.parse(largeBytes())).toEqual(large);
  const report = large.many;
  const refs = report.issues!.map(i => i.id);
  const run = { id: 'glance-ai', status: 'COMPLETED', analysis_kind: 'NETWORK_ANOMALY', language: 'en', network_interpretation: {
    schema_version: 'network-interpretation-v1', kind: 'MODEL_INTERPRETATION', language: 'en', summary: 'Observed patterns are not a diagnosis.',
    possible_causes: Array.from({ length: 10 }, () => ({ hypothesis: 'Capture duplication is possible.', uncertainty: 'Unconfirmed.', issue_ids: refs })),
    prioritized_checks: Array.from({ length: 10 }, () => ({ priority: 'HIGH', check: 'Compare captures.', issue_ids: refs })),
    correlations: Array.from({ length: 10 }, () => ({ interpretation: 'Shared observation, not proven causality.', issue_ids: refs })),
    limitations: Array.from({ length: 12 }, () => 'Single vantage, limited samples.'),
  } };
  const fetcher = vi.fn(async (input: unknown) => Response.json(String(input).endsWith('/ai-capabilities') ? { available: false } : String(input).endsWith('/ai-runs/glance-ai') ? run : { items: [run] }));
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { container } = render(<QueryClientProvider client={client}><NetworkAnomalyPanel report={report}><NetworkAIInterpretation jobId="glance" completed/></NetworkAnomalyPanel></QueryClientProvider>);
  openEvidence();
  expect(screen.getAllByRole('region', { name: 'Supporting measurements' })).toHaveLength(3);
  await openAI(true);
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  expect(container.querySelectorAll('*').length).toBeLessThan(500);
  expect(screen.getByRole('article', { name: 'Full AI interpretation' })).toHaveTextContent(refs[19]);
  openEvidence(1);
  expect(screen.queryByRole('article', { name: 'Full AI interpretation' })).not.toBeInTheDocument();
  expect(screen.getAllByRole('region', { name: 'Supporting measurements' })).toHaveLength(3);
  expect(container.querySelectorAll('*').length).toBeLessThan(500);
  expect(fetcher.mock.calls.length).toBeGreaterThan(0);
  client.clear();
});
