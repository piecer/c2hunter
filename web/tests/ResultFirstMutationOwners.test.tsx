import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';

// Actual controller builder/public projections; no model or external service.
const historicalFixture = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/historical_reference_fixture.py'], { encoding: 'utf8', timeout: 30000 })).with_reference;
const job = { id: 'mutation-job', name: 'Mutation owner fixture', status: 'COMPLETED', analysis: { module: 'c2' } };
const run = { id: 'mutation-run', analysis_job_id: job.id, status: 'COMPLETED', candidate_count: 1, created_at: '2026-01-01T00:00:00Z' };
// Presentation fixture only: no model, approval service or feedback store is run.
const assessment = { id: 'assessment-owner', candidate_id: 'candidate-owner', external_ip: '203.0.113.9', assessment: {
  candidate: { verdict: 'INCONCLUSIVE', confidence: 0, summary_en: 'Unconfirmed hypothesis', summary_ko: '미확인 가설' },
  supporting_factors: [], counter_factors: [], missing_information: [], limitations: [],
} };
function deferredResponse() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>(done => { resolve = done; });
  return { promise, resolve };
}
function mount(handler?: (path: string, init?: RequestInit) => Response | Promise<Response> | undefined, jobId = job.id) {
  localStorage.setItem('c2hunter-token', 'test');
  localStorage.setItem('c2hunter-report-language', 'en');
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input).replace('/api/v1', '');
    const response = handler?.(path, init);
    if (response) return response;
    if (path === `/analysis-jobs/${jobId}`) return Response.json({ ...job, id: jobId });
    if (path === '/ai-capabilities') return Response.json({ available: true, remote: false });
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return Response.json({ items: [run] });
    if (path === `/ai-runs/${run.id}`) return Response.json(run);
    if (path === `/ai-runs/${run.id}/assessments`) return Response.json({ items: [assessment] });
    if (path === `/ai-assessments/${assessment.id}/artifacts`) return Response.json({ items: [{ id: 'artifact-owner', artifact_type: 'SPLUNK_HUNT', validation_status: 'VALID', approved_status: 'PENDING', content: { spl: 'search fixture-only' } }] });
    return Response.json({ items: [], total: 0 });
  });
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${jobId}`]}><App/></MemoryRouter></QueryClientProvider>);
  const posts = () => fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
  return { ...view, fetcher, posts };
}
function purpose(name: 'AI investigation' | 'Results & evidence' | 'Work information') {
  fireEvent.click(within(screen.getByRole('navigation', { name: 'Analysis purpose' })).getByRole('button', { name }));
}

it.each(['approve', 'reject'])('retains a pending artifact %s owner through purpose changes and exposes its failure', async action => {
  const pending = deferredResponse();
  const { posts } = mount((path, init) => init?.method === 'POST' && path === `/ai-artifacts/artifact-owner/${action}` ? pending.promise : undefined);
  await screen.findByRole('navigation', { name: 'Analysis purpose' });
  purpose('AI investigation');
  const buttonName = action === 'approve' ? 'Approve draft' : 'Reject draft';
  fireEvent.click(await screen.findByRole('button', { name: buttonName }));
  await waitFor(() => expect(posts()).toHaveLength(1));
  expect(JSON.parse(String(posts()[0][1]?.body))).toEqual({ note: 'Reviewed from C2Hunter web console' });
  purpose('Results & evidence');
  expect(screen.queryByRole('region', { name: 'AI-generated artifacts' })).not.toBeInTheDocument();
  expect(screen.queryByText('search fixture-only')).not.toBeInTheDocument();
  purpose('AI investigation');
  const returned = await screen.findByRole('button', { name: buttonName });
  expect(returned).toBeDisabled();
  fireEvent.click(returned);
  fireEvent.click(screen.getByRole('button', { name: action === 'approve' ? 'Reject draft' : 'Approve draft' }));
  expect(posts()).toHaveLength(1);
  purpose('Work information');
  const status = screen.getByRole('region', { name: `Artifact review status ${assessment.id}` });
  expect(within(status).getByRole('status')).toHaveTextContent('artifact-owner');
  await act(async () => pending.resolve(Response.json({ error: { message: 'Artifact review rejected' } }, { status: 503 })));
  expect(await within(status).findByRole('alert')).toHaveTextContent('Artifact review rejected');
  purpose('AI investigation');
  expect(await screen.findByRole('alert')).toHaveTextContent('Artifact review rejected');
  expect(screen.getByRole('button', { name: buttonName })).toBeEnabled();
  expect(posts()).toHaveLength(1);
});

it('retains the pending feedback owner and draft through purpose switches without duplicate submission', async () => {
  const pending = deferredResponse();
  const { posts } = mount((path, init) => init?.method === 'POST' && path === `/ai-assessments/${assessment.id}/feedback` ? pending.promise : undefined);
  await screen.findByRole('navigation', { name: 'Analysis purpose' });
  purpose('AI investigation');
  const note = await screen.findByLabelText('Analyst note', { selector: 'textarea' });
  fireEvent.change(note, { target: { value: 'Retain this analyst draft' } });
  fireEvent.change(screen.getByLabelText('Confirmed assessment'), { target: { value: 'CONFIRM_BENIGN' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save confirmed feedback' }));
  await waitFor(() => expect(posts()).toHaveLength(1));
  expect(JSON.parse(String(posts()[0][1]?.body))).toEqual({ verdict: 'CONFIRM_BENIGN', note: 'Retain this analyst draft' });
  purpose('Results & evidence');
  expect(screen.queryByLabelText('Analyst note', { selector: 'textarea' })).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Analyst confirmed feedback' })).not.toBeInTheDocument();
  purpose('AI investigation');
  const returnedNote = screen.getByLabelText('Analyst note', { selector: 'textarea' });
  expect(returnedNote).toHaveValue('Retain this analyst draft');
  expect(screen.getByLabelText('Confirmed assessment')).toHaveValue('CONFIRM_BENIGN');
  expect(screen.getByRole('button', { name: 'Saving feedback…' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Saving feedback…' }));
  // Submission through the form must observe the same pending owner as the button.
  fireEvent.submit(returnedNote.closest('form')!);
  await act(async () => {});
  expect(posts()).toHaveLength(1);
  purpose('Work information');
  const status = screen.getByRole('region', { name: `Feedback status ${assessment.id}` });
  expect(within(status).getByRole('status')).toHaveTextContent('Saving feedback');
  await act(async () => pending.resolve(Response.json({ error: { message: 'Feedback write rejected' } }, { status: 503 })));
  expect(await within(status).findByRole('alert')).toHaveTextContent('Feedback write rejected');
  purpose('AI investigation');
  expect(screen.getByLabelText('Analyst note', { selector: 'textarea' })).toHaveValue('Retain this analyst draft');
  expect(screen.getByLabelText('Confirmed assessment')).toHaveValue('CONFIRM_BENIGN');
  expect(screen.getByRole('alert')).toHaveTextContent('Feedback write rejected');
  expect(screen.getByRole('button', { name: 'Save confirmed feedback' })).toBeEnabled();
  expect(posts()).toHaveLength(1);
});

it('preserves the real producer historical scope, preview warnings and submitted reference across purpose switches', async () => {
  const fixture = historicalFixture;
  const jobId = fixture.run.analysis_job_id;
  const scopeId = fixture.scope.config.scope_id;
  const pending = deferredResponse();
  const { posts, fetcher } = mount((path, init) => {
    if (path === '/historical-baselines/scopes') return Response.json({ items: [fixture.scope] });
    if (path === `/historical-baselines/scopes/${scopeId}/preview`) return Response.json(fixture.preview);
    if (path === `/analysis-jobs/${jobId}/ai-runs`) return init?.method === 'POST' ? pending.promise : Response.json({ items: [] });
    return undefined;
  }, jobId);
  await screen.findByRole('navigation', { name: 'Analysis purpose' });
  purpose('AI investigation');
  fireEvent.click(screen.getByRole('checkbox', { name: /behavioral discovery/ }));
  fireEvent.click(screen.getByRole('checkbox', { name: /Use historical reference/ }));
  await waitFor(() => expect(screen.getByLabelText('Historical scope')).toBeEnabled());
  fireEvent.change(screen.getByLabelText('Historical scope'), { target: { value: scopeId } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview reference' }));
  await screen.findByText(/Reference pinned/);
  const reference = screen.getByRole('region', { name: 'Historical reference options' });
  const displayed = reference.textContent;
  expect(within(reference).getByLabelText('Historical scope')).toHaveValue(scopeId);
  expect(within(reference).getByText(fixture.scope.active.generation_id)).toBeVisible();
  expect(within(reference).getByText(String(fixture.scope.control_revision))).toBeVisible();
  expect(fixture.preview.reasons.length).toBeGreaterThan(0);
  for (const reason of fixture.preview.reasons) expect(within(reference).getByText(reason)).toBeVisible();
  expect(within(reference).getByText(/No target quality review is asserted/)).toBeVisible();
  expect(JSON.parse(String(posts()[0][1]?.body))).toEqual({ source_job_id: jobId, expected_revision: fixture.scope.control_revision, purpose: 'COMPARISON' });
  purpose('Work information');
  expect(screen.queryByLabelText('Historical scope')).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Historical reference options' })).not.toBeInTheDocument();
  purpose('AI investigation');
  expect(screen.getByLabelText('Historical scope')).toHaveValue(scopeId);
  expect(screen.getByRole('region', { name: 'Historical reference options' }).textContent).toBe(displayed);
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeEnabled();
  fireEvent.click(screen.getByRole('button', { name: 'Run AI analysis' }));
  await waitFor(() => expect(posts()).toHaveLength(2));
  expect(JSON.parse(String(posts()[1][1]?.body))).toEqual({ ...fixture.payload, idempotency_key: expect.any(String), language: 'en' });
  purpose('Results & evidence');
  expect(screen.getByText('AI 분석 수락 확인 중')).toBeVisible();
  purpose('AI investigation');
  expect(screen.getByLabelText('Historical scope')).toHaveValue(scopeId);
  expect(screen.getByLabelText('Historical scope')).toBeDisabled();
  expect(screen.getByRole('region', { name: 'Historical reference options' }).textContent).toBe(displayed);
  fireEvent.click(screen.getByRole('button', { name: 'AI 분석 실행 중…' }));
  expect(posts()).toHaveLength(2);
  await act(async () => pending.resolve(Response.json({ error: { code: 'BASELINE_REVISION_CONFLICT', message: 'Reference changed' } }, { status: 409 })));
  expect(await screen.findByText(/Stale reference/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  purpose('Work information');
  purpose('AI investigation');
  expect(screen.getByLabelText('Historical scope')).toHaveValue(scopeId);
  expect(screen.getByRole('button', { name: 'Run AI analysis' })).toBeDisabled();
  expect(screen.queryByText(/Reference pinned/)).not.toBeInTheDocument();
  expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith('/preview'))).toHaveLength(1);
  expect(posts()).toHaveLength(2);
});
