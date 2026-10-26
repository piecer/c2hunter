import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { projectNetworkReport } from '../src/networkReportValidation';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import NetworkPatternReport from '../src/NetworkPatternReport';
import { ReportLanguageContext } from '../src/reportLanguageContext';
import { evidenceSignature } from '../src/networkEvidenceContext';
import { readFileSync } from 'node:fs';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import { patternLabel } from '../src/reportTranslations';

const python = process.env.C2HUNTER_PYTHON ?? resolve('../.venv/bin/python');
const generate = () => JSON.parse(execFileSync(python, ['tests/network_family_fixture.py'], { encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1024 * 1024 }));
const bundle = generate();
const legacy = JSON.parse(readFileSync('tests/fixtures/network-family-legacy.json', 'utf8'));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));

it.each([1, 5, 6, 7, 100])('validates all six observed families at limit %s and preserves exact bytes', limit => {
  const report = bundle.cases[`limit-${limit}`].report;
  const bytes = JSON.stringify(report);
  const result = projectNetworkReport(report);
  expect(result.familyCoverage.state).toBe('valid');
  expect(report.family_coverage.families).toHaveLength(6);
  expect(result.slots).toHaveLength(limit);
  expect(JSON.stringify(report)).toBe(bytes);
});

it('preserves canonical report and AI bytes across real public jobs', () => {
  const second = generate();
  for (const key of Object.keys(bundle.cases)) {
    for (const field of ['report', 'ai']) expect(JSON.stringify(second.cases[key][field])).toBe(JSON.stringify(bundle.cases[key][field]));
  }
  expect(second.cases.dominant.job.id).not.toBe(bundle.cases.dominant.job.id);
});

it('keeps genuine pre-change producer bytes and IDs as unknown family coverage', () => {
  const bytes = JSON.stringify(legacy);
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={legacy}/></ReportLanguageContext>);
  expect(screen.getByText(/Family selection coverage was not recorded/)).toBeVisible();
  expect(projectNetworkReport(legacy).familyCoverage.state).toBe('absent');
  expect(projectNetworkReport(legacy).slots[19].issue?.id).toBe('pattern-20');
  expect(projectNetworkReport(legacy).slots[19].issue?.pattern).toBe('udp_duplicate_candidates');
  expect(JSON.stringify(legacy)).toBe(bytes);
});

it.each(['null', 'version', 'policy', 'root-extra', 'rows-null', 'overflow', 'duplicate', 'unknown', 'object-enum', 'array-enum', 'negative', 'fraction', 'unsafe', 'zero', 'row-sum', 'total', 'retained-pattern', 'row-extra', 'reverse', 'missing'])('atomically rejects malformed present family metadata: %s', fault => {
  const r = structuredClone(bundle.cases.dominant.report), f = r.family_coverage, row = f.families[0];
  if (fault === 'null') r.family_coverage = null;
  if (fault === 'version') f.version = ['network-family-coverage-v1'];
  if (fault === 'policy') f.selection_policy = { toString: null };
  if (fault === 'root-extra') f.extra = null;
  if (fault === 'rows-null') f.families = null;
  if (fault === 'overflow') f.families = Array(7).fill(row);
  if (fault === 'duplicate') f.families.push(row);
  if (fault === 'unknown') row.pattern = 'new-pattern';
  if (fault === 'object-enum') row.pattern = { toString: null };
  if (fault === 'array-enum') row.pattern = ['matched_resets'];
  if (fault === 'negative') row.omitted_groups = -1;
  if (fault === 'fraction') row.observed_groups = 1.5;
  if (fault === 'unsafe') row.observed_groups = Number.MAX_SAFE_INTEGER + 1;
  if (fault === 'zero') { row.observed_groups = 0; row.retained_groups = 0; }
  if (fault === 'row-sum') row.omitted_groups++;
  if (fault === 'total') { row.observed_groups++; row.omitted_groups++; }
  if (fault === 'retained-pattern') { row.retained_groups = 0; row.omitted_groups = 1; f.families[1].retained_groups++; f.families[1].omitted_groups--; }
  if (fault === 'row-extra') row.extra = null;
  if (fault === 'reverse') f.families.reverse();
  if (fault === 'missing') delete row.pattern;
  const bytes = JSON.stringify(r), projection = projectNetworkReport(r);
  expect(projection.familyCoverage).toEqual({ state: 'invalid' });
  expect(projection.slots.filter(s => s.issue)).toHaveLength(20);
  expect(JSON.stringify(r)).toBe(bytes);
});

it.each(['root-getter', 'root-hidden', 'root-inherited', 'row-getter', 'row-inherited', 'array-getter', 'array-hole', 'array-extra', 'symbol', 'toJSON', 'oversized-getter'])('rejects non-data metadata without executing hooks: %s', fault => {
  const r = structuredClone(bundle.cases.dominant.report), f = r.family_coverage;
  const getter = vi.fn(() => { throw new Error('metadata hook executed'); });
  if (fault === 'root-getter') Object.defineProperty(r, 'family_coverage', {get:getter, enumerable:true});
  if (fault === 'root-hidden') Object.defineProperty(r, 'family_coverage', {value:f, enumerable:false});
  if (fault === 'root-inherited') { delete r.family_coverage; Object.setPrototypeOf(r, {family_coverage:f}); }
  if (fault === 'row-getter') Object.defineProperty(f.families[0], 'pattern', {get:getter, enumerable:true});
  if (fault === 'row-inherited') { const row = f.families[0]; delete row.pattern; Object.setPrototypeOf(row, {pattern:'matched_resets'}); }
  if (fault === 'array-getter') Object.defineProperty(f.families, '0', {get:getter, enumerable:true});
  if (fault === 'array-hole') f.families.length++;
  if (fault === 'array-extra') f.families.extra = null;
  if (fault === 'symbol') f[Symbol('unknown')] = null;
  if (fault === 'toJSON') Object.defineProperty(f, 'toJSON', {get:getter});
  if (fault === 'oversized-getter') { f.families.length = 7; Object.defineProperty(f.families, '0', {get:getter, enumerable:true}); }
  expect(projectNetworkReport(r).familyCoverage).toEqual({state:'invalid'});
  evidenceSignature(projectNetworkReport(r));
  expect(getter).not.toHaveBeenCalled();
});

it.each(['en', 'ko'] as const)('keeps every retained maximum group reachable with bounded mounted DOM (%s)', language => {
  const report = bundle.cases['limit-100'].report;
  render(<ReportLanguageContext value={language}><NetworkPatternReport report={report}/></ReportLanguageContext>);
  const count = () => expect(document.querySelectorAll('*').length).toBeLessThan(500);
  count();
  fireEvent.click(screen.getByRole('button', {name:language === 'en' ? 'Coverage details and limitations' : '분석 범위 상세 및 한계'}));
  const coverage = screen.getByRole('region', {name:language === 'en' ? 'Family selection coverage' : '종류별 선택 범위'});
  for (const row of report.family_coverage.families) expect(coverage).toHaveTextContent(patternLabel(language, row.pattern));
  count();
  fireEvent.click(screen.getByRole('button', {name:language === 'en' ? 'View all anomaly items' : '전체 이상 항목 보기'}));
  const ids: string[] = [];
  for (let page = 0; page < 13; page++) {
    for (const article of screen.getAllByRole('article')) {
      ids.push(article.querySelector('code')!.textContent!);
      fireEvent.click(within(article).getByRole('button', {name:language === 'en' ? /representative evidence/ : /대표 증거/}));
      count();
      expect(screen.queryAllByRole('region', {name:language === 'en' ? 'Representative flow evidence' : '대표 흐름 증거'})).toHaveLength(1);
      expect(screen.queryByRole('region', {name:language === 'en' ? 'Family selection coverage' : '종류별 선택 범위'})).toBeNull();
    }
    if (page < 12) fireEvent.click(screen.getByRole('button', {name:language === 'en' ? 'Next groups' : '다음 그룹'}));
  }
  expect(ids).toEqual(report.issues.map((i: {id:string}) => i.id));
});

async function openAI() {
  fireEvent.click(await screen.findByRole('button', {name:'Open AI interpretation'}));
  fireEvent.click(await screen.findByRole('button', {name:'View full AI text'}));
}

async function setupApp(report = structuredClone(bundle.cases.dominant.report)) {
  const job = {...structuredClone(bundle.cases.dominant.job), network_anomaly:report};
  const run = {id:'family-run', analysis_job_id:job.id, dataset_id:job.dataset_id, analysis_kind:'NETWORK_ANOMALY', status:'COMPLETED', network_input:bundle.cases.dominant.ai, network_interpretation:{schema_version:'network-interpretation-v1', kind:'MODEL_INTERPRETATION', language:'en', summary:'Synthetic family citation control.', possible_causes:[{hypothesis:'Capture duplication is possible.', issue_ids:['pattern-20'], uncertainty:'Not a model quality evaluation.'}], prioritized_checks:[], correlations:[], limitations:['Synthetic control only.']}};
  localStorage.setItem('c2hunter-token', 'family-fixture-token'); localStorage.setItem('c2hunter-report-language','en');
  const fetcher = vi.fn(async (input: unknown, init?: RequestInit) => {
    expect(init?.method ?? 'GET').toBe('GET');
    const path = String(input);
    if (path.endsWith('/ai-capabilities')) return Response.json({available:true, network_interpretation:true, remote:false});
    if (path.endsWith('/ai-runs/family-run')) return Response.json(run);
    if (path.endsWith(`/${job.id}/ai-runs`)) return Response.json({items:[run]});
    if (path.endsWith(`/analysis-jobs/${job.id}`)) return Response.json(job);
    return Response.json({items:[]});
  });
  vi.stubGlobal('fetch',fetcher);
  const client = new QueryClient({defaultOptions:{queries:{retry:false,staleTime:Infinity}}}); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading',{name:'Anomaly observed'});
  await waitFor(() => expect(client.isFetching()).toBe(0));
  await openAI();
  return {client,job,run,fetcher};
}

it.each(['absent', 'null', 'extra', 'valid-change'])('latches same-job family %s A→B→A with captured callback and fresh-run recovery', async fault => {
  const {client,job,run,fetcher} = await setupApp();
  const button = () => screen.getByRole('button',{name:'pattern-20'});
  const captured = Object.values(button()).find(v => v && typeof v === 'object' && 'onClick' in v) as {onClick: () => void};
  expect(captured.onClick).toBeTypeOf('function');
  fireEvent.click(button());
  expect(screen.getByRole('region',{name:'Representative flow evidence'})).toHaveFocus();
  const changed = structuredClone(job), f = changed.network_anomaly.family_coverage;
  if (fault === 'absent') delete changed.network_anomaly.family_coverage;
  if (fault === 'null') changed.network_anomaly.family_coverage = null;
  if (fault === 'extra') f.extra = null;
  if (fault === 'valid-change') { f.families[0].observed_groups++; f.families[0].omitted_groups++; f.families[1].observed_groups--; f.families[1].omitted_groups--; }
  const before = fetcher.mock.calls.length;
  for (const value of [changed,job]) {
    await act(async () => {client.setQueryData(['job',job.id],value); await new Promise(resolve => setTimeout(resolve,0));});
    await openAI();
    act(() => captured.onClick());
    expect(button()).toBeDisabled(); fireEvent.click(button());
    expect(screen.queryByRole('region',{name:'Representative flow evidence'})).toBeNull();
  }
  const fresh = {...run,id:'family-fresh',network_interpretation:{...run.network_interpretation,summary:'Fresh family review.'}};
  await act(async () => {client.setQueryData(['ai-run',fresh.id],fresh); client.setQueryData(['ai-runs',job.id],{items:[fresh,run]}); await new Promise(resolve => setTimeout(resolve,0));});
  await screen.findByText('Fresh family review.');
  fireEvent.click(screen.getByRole('button',{name:'View full AI text'}));
  expect(button()).toBeEnabled(); fireEvent.click(button());
  expect(screen.getByRole('region',{name:'Representative flow evidence'})).toHaveFocus();
  expect(fetcher.mock.calls).toHaveLength(before);
  expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
});

it('keeps unchanged family semantics actionable on metadata-only refetch', async () => {
  const {client,job,fetcher} = await setupApp();
  fireEvent.click(screen.getByRole('button',{name:'pattern-20'}));
  const before = fetcher.mock.calls.length;
  await act(async () => {client.setQueryData(['job',job.id],{...structuredClone(job),description:'metadata only'}); await new Promise(resolve => setTimeout(resolve,0));});
  await openAI();
  const button = screen.getByRole('button',{name:'pattern-20'});
  expect(button).toBeEnabled(); fireEvent.click(button);
  expect(screen.getByRole('region',{name:'Representative flow evidence'})).toHaveFocus();
  expect(fetcher.mock.calls).toHaveLength(before);
});

it('accepts safe-integer maximum arithmetic without unsafe sum coercion', () => {
  const r = structuredClone(bundle.cases.dominant.report);
  r.summary.issue_count = Number.MAX_SAFE_INTEGER;
  r.summary.omitted_issue_count = Number.MAX_SAFE_INTEGER - 20;
  r.family_coverage.families[1].observed_groups = Number.MAX_SAFE_INTEGER - 1;
  r.family_coverage.families[1].omitted_groups = Number.MAX_SAFE_INTEGER - 20;
  expect(projectNetworkReport(r).familyCoverage.state).toBe('valid');
  r.family_coverage.families[0].observed_groups++;
  r.family_coverage.families[0].omitted_groups++;
  expect(projectNetworkReport(r).familyCoverage.state).toBe('invalid');
});

it.each(['empty', 'normal'])('accepts zero observed families without confusing %s coverage', name => {
  const r = bundle.cases[name].report;
  expect(projectNetworkReport(r).familyCoverage).toEqual({state:'valid',value:r.family_coverage});
  expect(r.family_coverage.families).toEqual([]);
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={r}/></ReportLanguageContext>);
  expect(screen.getByRole('heading',{name:name === 'normal' ? 'No clear anomaly observed' : 'Insufficient data'})).toBeVisible();
});

it('cannot invent clear from present invalid metadata on an otherwise normal report', () => {
  const r = structuredClone(bundle.cases.normal.report); r.family_coverage = null;
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={r}/></ReportLanguageContext>);
  expect(screen.queryByRole('heading',{name:'No clear anomaly observed'})).toBeNull();
  expect(screen.getByRole('heading',{name:'Insufficient data'})).toBeVisible();
});

it('explains observed but unretained families lazily without invented retrieval', () => {
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={bundle.cases['limit-1'].report}/></ReportLanguageContext>);
  expect(screen.getByText(/Observed families without retained groups:/)).toHaveTextContent('5');
  expect(screen.queryByRole('region', { name: 'Family selection coverage' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Coverage details and limitations' }));
  const region = screen.getByRole('region', { name: 'Family selection coverage' });
  expect(region).toHaveTextContent('Observed, but no group retained');
  expect(region).toHaveTextContent('not a risk ranking');
  expect(region).toHaveTextContent('not capture-wide totals');
});

it('distinguishes absent invalid and valid consumed metadata in the evidence signature', () => {
  const a = structuredClone(bundle.cases.dominant.report);
  const absent = structuredClone(a); delete absent.family_coverage;
  const bad = structuredClone(a); bad.family_coverage.extra = null;
  const signatures = [a, absent, bad].map(v => evidenceSignature(projectNetworkReport(v)));
  expect(new Set(signatures).size).toBe(3);
});

it('locally reports invalid metadata without erasing positive evidence', () => {
  const r = structuredClone(bundle.cases.dominant.report);
  r.family_coverage = null;
  render(<ReportLanguageContext value="en"><NetworkPatternReport report={r}/></ReportLanguageContext>);
  expect(screen.getByText(/Invalid family coverage/)).toBeVisible();
  expect(screen.getByRole('heading', {name:'Anomaly observed'})).toBeVisible();
  expect(screen.getAllByTestId('top-observation')).toHaveLength(3);
});
it('accepts real producer family metadata through stored public GET and AI input', () => {
  const value = bundle.cases.dominant;
  expect(value.job.network_anomaly).toEqual(value.report);
  expect(value.report.issues.filter((i: {pattern: string}) => i.pattern === 'matched_resets')).toHaveLength(1);
  expect(value.ai.issues.map((i: {id: string}) => i.id)).toEqual(value.report.issues.map((i: {id: string}) => i.id));
  expect(projectNetworkReport(value.report)).toMatchObject({ familyCoverage: { state: 'valid', value: value.report.family_coverage }, summaryTrusted: true });
});
