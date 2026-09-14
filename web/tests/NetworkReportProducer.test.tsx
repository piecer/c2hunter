import { openGroups } from './reportDisclosure';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';

beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
import App from '../src/App';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';

const python = process.env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
const generate = () => execFileSync(python, ['tests/network_report_fixture.py'], { encoding: 'utf8' });
const bytes = generate();
const fixtures = JSON.parse(bytes) as Record<string, NetworkAnomalyReport>;

it('generates deterministic real-parser fixtures covering all six producer patterns', () => {
  expect(generate()).toBe(bytes);
  expect([...new Set(Object.values(fixtures).flatMap(report => report.issues?.map(issue => issue.pattern) ?? []))].sort()).toEqual(['data_retransmissions', 'duplicate_acks', 'icmp_errors', 'matched_resets', 'syn_retransmissions', 'udp_duplicate_candidates']);
});

it.each(Object.entries(fixtures))('renders the actual producer scenario %s without losing evidence relationships', (_name, report) => {
  render(<NetworkAnomalyPanel report={report}/>);
  const verdicts: Record<string, string> = { anomaly_observed: 'Anomaly observed', no_clear_anomaly: 'No clear anomaly observed', insufficient_evidence: 'Insufficient data' };
  expect(screen.getByRole('heading', { name: verdicts[String(report.summary.verdict)] })).toBeVisible();
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  openGroups();
  for (const [index, issue] of (report.issues ?? []).entries()) {
    const article = within(screen.getAllByRole('article')[index]);
    fireEvent.click(article.getByRole('button'));
    for (const text of [...issue.evidence, ...issue.uncertainty, ...issue.next_checks]) expect(article.getByText(text)).toBeVisible();
    expect(article.getByRole('region', { name: 'Representative flow evidence' })).toBeVisible();
  }
});

it('uses summary flow count rather than the empty compatibility flows array in the existing job page', async () => {
  localStorage.setItem('c2hunter-token', 'token');
  vi.stubGlobal('fetch', vi.fn(async input => new Response(JSON.stringify(String(input) === '/api/v1/analysis-jobs/producer-network' ? { id: 'producer-network', name: 'Producer report', status: 'COMPLETED', analysis: { module: 'network_anomaly' }, network_anomaly: fixtures.syn_reset } : { items: [] }))));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><MemoryRouter initialEntries={['/analyses/producer-network']}><App/></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(screen.queryByText(/Pattern scan →/)).not.toBeInTheDocument();
  expect(screen.queryByText('Observed bidirectional flows')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: '작업 상세 / Job details' }));
  expect(screen.getByText('Observed bidirectional flows').closest('article')).toHaveTextContent('1Observed bidirectional flows');
});
