import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import AIInvestigationPanel from '../src/AIInvestigationPanel';
import { InvestigationConclusion, InvestigationEvidence } from '../src/InvestigationResult';
import { parseInvestigation } from '../src/investigationContract';
import { investigationApi } from '../src/investigationApi';
import { investigationError } from '../src/investigationLifecycle';
import { fixture, freshFixture, producer } from './investigationFixtures';

function revealLimitations(label: string) {
  for (let page = 0; page < 10; page++) {
    if (screen.queryByText('SOURCE_FIELDS_UNAVAILABLE', { exact: true })) return;
    const next = screen.queryByRole('button', { name: `다음 / Next ${label}` });
    if (!next || next.hasAttribute('disabled')) break;
    fireEvent.click(next);
  }
  expect(screen.getByText('SOURCE_FIELDS_UNAVAILABLE', { exact: true })).toBeVisible();
}

it('shows known retained zero and unknown scope separately on mixed evidence', () => {
  const evidence = parseInvestigation('Evidence', freshFixture('mixed_peer_flow_samples'));
  render(<InvestigationEvidence evidence={evidence}/>);
  expect(screen.getByText(/Scope unavailable 1/)).toBeVisible();
  expect(screen.getByText(/Known matches are retained; scope eligibility remains uncertain/)).toBeVisible();
  expect(screen.getAllByText('확인 불가 / Unknown')).toHaveLength(4);
  expect(screen.getByText(/Retained 1/)).toBeVisible();
  revealLimitations('evidence limitations');
});

it.each(['cohort', 'cohort_unknown'])('shows excluded input rows even with %s cohort and never adds them to peer totals', name => {
  const evidence = parseInvestigation('Evidence', freshFixture(name + '_compare_peer_cohort'));
  render(<InvestigationEvidence evidence={evidence}/>);
  expect(screen.getByText(`관측된 비교 피어 / Observed comparison peers ${evidence.cohort_total} · 생략 / Omitted ${evidence.cohort_omitted}`)).toBeVisible();
  expect(screen.getByText(/Excluded input rows 1 — not additional peers/)).toBeVisible();
  expect(screen.getByText(/Comparison coverage is incomplete/)).toBeVisible();
  revealLimitations('evidence limitations');
});

it.each(['mixed', 'cohort'])('shows qualified TraceResult %s quality and limitations without hiding known facts', name => {
  const result = parseInvestigation('InvestigationResult', freshFixture('result_' + name));
  render(<InvestigationConclusion result={result} openEvidence={vi.fn()}/>);
  expect(screen.getByText('Needs review')).toBeVisible();
  expect(screen.getByText(/Some source fields or comparison inputs are unavailable; observed facts are qualified/)).toBeVisible();
  const issued = within(screen.getByRole('region', { name: '발급된 근거 / Issued evidence' }));
  expect(issued.getAllByText(new RegExp(`Scope unavailable ${result.counts.scope_unavailable}`))).toHaveLength(result.evidence_quality.length);
  expect(within(screen.getByRole('region', { name: '관측 사실 / Observed facts' })).getByText('matched_rows')).toBeVisible();
  revealLimitations('limitations');
});

it.each([
  ['unknown', 'UNAVAILABLE', 'Scope eligibility is unknown', false],
  ['partial', 'NOT_FOUND_IN_INSPECTED_SCOPE', 'Not found in the inspected partial source', false],
  ['absent', 'NOT_OBSERVED', 'Not observed in this inspected source scope', false],
  ['mixed', 'OBSERVED', 'Known matches are retained; scope eligibility remains uncertain', true],
  ['zero', 'OBSERVED', 'Scope unavailable 0', true],
] as const)('renders real %s preview, retaining qualified-positive admission only', async (name, status, explanation, admissible) => {
  const preview = parseInvestigation('SourcePreview', freshFixture('preview_' + name));
  const posts: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') posts.push(url);
    if (url.endsWith('/capabilities')) return Response.json(fixture('capabilities'));
    if (url.includes('?limit=5')) return Response.json({ items: [], next_cursor: null });
    if (url.endsWith('/source-preview')) return new Response(producer.additional.fixtures['preview_' + name]);
    throw new Error('No admission was requested');
  }));
  render(<AIInvestigationPanel jobId="job"/>);
  fireEvent.change(screen.getByLabelText('대상 IP / Target IP'), { target: { value: preview.scope.target_ip } });
  if (preview.scope.traffic_direction) fireEvent.change(screen.getByLabelText('방향 / Direction'), { target: { value: preview.scope.traffic_direction } });
  await waitFor(() => expect(screen.getByRole('button', { name: '범위 미리보기 / Preview scope' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: '범위 미리보기 / Preview scope' }));
  const region = await screen.findByRole('region', { name: '출처 미리보기 / Source preview' });
  expect(within(region).getByRole('heading', { name: `${preview.scope.target_ip} · ${status}` })).toBeVisible();
  expect(within(region).getByText(new RegExp(explanation))).toBeVisible();
  const start = within(region).getByRole('button', { name: '조사 시작 / Start investigation' });
  if (admissible) expect(start).toBeEnabled();
  else { expect(start).toBeDisabled(); fireEvent.click(start); }
  expect(posts).toHaveLength(1);
});

it.each([
  ['unknown', 'TARGET_SCOPE_UNAVAILABLE', 'Scope eligibility is unknown'],
  ['partial', 'TARGET_NOT_FOUND_IN_INSPECTED_SCOPE', 'Not found in the inspected partial source'],
  ['absent', 'TARGET_NOT_OBSERVED', 'Not observed in this inspected source scope'],
] as const)('explains actual %s admission errors without treating unknown as absence', async (name, code, explanation) => {
  const request = parseInvestigation('InvestigationRun', fixture('run_queued')).request;
  vi.stubGlobal('fetch', vi.fn(async () => new Response(producer.additional.fixtures['error_' + name], { status: 422 })));
  let caught: unknown;
  try { await investigationApi.create('job', JSON.stringify(request), new AbortController().signal); }
  catch (error) { caught = error; }
  expect(caught).toMatchObject({ status: 422, code });
  expect(investigationError(caught)).toContain(explanation);
  expect(investigationError(caught)).toContain(code);
});
