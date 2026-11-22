import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

const python = process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const reports = JSON.parse(execFileSync(python, ['tests/network_report_fixture.py'], { encoding: 'utf8' }));
const envelope = JSON.parse(execFileSync(python, ['tests/network_public_job_fixture.py'], { input: JSON.stringify(reports.normal), encoding: 'utf8' }));
const witness = JSON.parse(execFileSync(python, ['tests/network_saved_warning_fixture.py'], { input: JSON.stringify(envelope), encoding: 'utf8' }));
const unknown = 'Unrecognized source limitation: timestamps may be incomplete.';

function mount(job = witness.job, language = 'en') {
  localStorage.setItem('c2hunter-token', 'test');
  localStorage.setItem('c2hunter-report-language', language);
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method && init.method !== 'GET') throw new Error('Unexpected write');
    return Response.json(String(input) === `/api/v1/analysis-jobs/${job.id}` ? job : { items: [] });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  return fetcher;
}

it.each(['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED'])('retains every original terminal warning outside disclosure for %s', async status => {
  const job = { ...witness.job, status, warnings: [...witness.job.warnings, unknown] };
  const fetcher = mount(job);
  const warnings = await screen.findByRole('region', { name: 'Original job warnings' });
  expect(screen.getByRole('button', { name: 'Work information' })).toHaveAttribute('aria-expanded', 'false');
  for (const text of job.warnings) expect(within(warnings).getByText(text, { exact: true, normalizer: value => value })).toBeVisible();
  expect(screen.getByText('Capture limit: 3 packets retained · 2 excluded. Excluded traffic was not analyzed.')).toBeVisible();
  expect(warnings.closest('details,[hidden],[aria-hidden="true"]')).toBeNull();
  expect(screen.queryByText(/job warnings — see Work information/)).not.toBeInTheDocument();
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});

it.each(['job', 'legacy', 'missing'] as const)('localizes known source meaning without requiring a %s report qualifier', async era => {
  const job = era === 'missing' ? { ...witness.job, network_anomaly: undefined } : witness[era];
  mount(job);
  await screen.findByRole('region', { name: 'Original job warnings' });
  fireEvent.change(screen.getByLabelText('보고서 언어 / Report language'), { target: { value: 'ko' } });
  expect(screen.getByText('캡처 제한: 패킷 3개 보존 · 2개 제외. 제외된 트래픽은 분석되지 않았습니다.')).toBeVisible();
  expect(within(screen.getByRole('region', { name: '원본 작업 경고' })).getByText(witness.warning, { exact: true })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: '작업 정보' }));
  expect(within(screen.getByRole('region', { name: '작업 정보' })).getByText(witness.warning, { exact: true })).toBeVisible();
});

it.each([
  unknown,
  'Operational warning: sensor loss is not measured.',
  'capture.max_packets warning with unknown meaning',
  witness.warning + ' Additional unknown qualifier.',
  witness.warning + '\n',
  witness.warning.replace('3 packets', '03 packets'),
  witness.warning.replace('(2 packets', '(0 packets'),
])('never guesses a concise meaning or hides an unmatched warning: %s', async warning => {
  mount({ ...witness.job, warnings: [warning] });
  const region = await screen.findByRole('region', { name: 'Original job warnings' });
  // textContent preserves the literal wire string, including a trailing newline.
  expect(region.querySelector('p')?.textContent).toBe(warning);
  expect(region.querySelector('p')).toBeVisible();
  expect(screen.queryByText(/^Capture limit:/)).not.toBeInTheDocument();
});

it('keeps full precision in producer decimal counts without Number conversion', async () => {
  const warning = witness.warning.replace('3 packets', '9007199254740993 packets').replace('(2 packets', '(12345678901234567890 packets');
  mount({ ...witness.job, warnings: [warning] });
  expect(await screen.findByText('Capture limit: 9007199254740993 packets retained · 12345678901234567890 excluded. Excluded traffic was not analyzed.')).toBeVisible();
  expect(within(screen.getByRole('region', { name: 'Original job warnings' })).getByText(warning, { exact: true })).toBeVisible();
});

it('does not invent a capture limit from terminal status or retained report alone', async () => {
  mount({ ...witness.job, warnings: [] });
  await screen.findByRole('button', { name: 'Work information' });
  expect(screen.queryByText(/^Capture limit:/)).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Original job warnings' })).not.toBeInTheDocument();
});

it('preserves active warning prose, phase, progress and cancel controls', async () => {
  mount({ ...witness.job, status: 'ANALYZING', progress_percent: 45, processing: { phase: 'ANALYSIS_RUNNING' }, warnings: [unknown] });
  expect(await screen.findByText(unknown, { exact: true })).toBeVisible();
  expect(screen.getByText('Current phase: ANALYSIS_RUNNING')).toBeVisible();
  expect(screen.getByRole('progressbar')).toHaveAttribute('value', '45');
  expect(screen.getByRole('button', { name: 'Cancel analysis' })).toBeEnabled();
});
