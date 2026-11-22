import { readFileSync } from 'node:fs';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, it, vi } from 'vitest';
import DDoSAttackPanel from '../src/DDoSAttackPanel';
import * as exports from '../src/ddosExport';
import App from '../src/App';
import { api } from '../src/api';

const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
const openFinding = () => fireEvent.click(screen.getByRole('button', { name: /Show detailed evidence/ }));
const inspect = () => fireEvent.click(screen.getByRole('button', { name: /Inspect candidate/ }));
const handler = (node: HTMLElement) => (node as unknown as Record<string, { onClick: () => void }>)[Object.keys(node).find(key => key.startsWith('__reactProps'))!].onClick;

it.each(['deep-field', 'oversized-findings', 'null-report', 'deep-extra'])('fails closed before snapshotting JSON-compatible %s', shape => {
  let malformed = structuredClone(report);
  if (shape === 'null-report') malformed = null;
  else if (shape === 'deep-field' || shape === 'deep-extra') {
    let nested: unknown = 'malformed';
    for (let i = 0; i < 12000; i++) nested = { nested };
    if (shape === 'deep-extra') malformed.extra = nested;
    else malformed.findings[0].metrics.measurement_precision = nested;
  } else malformed.findings = Array(10001).fill(malformed.findings[0]);
  const stringify = vi.spyOn(JSON, 'stringify');
  expect(() => render(<DDoSAttackPanel report={malformed}/>)).not.toThrow();
  expect(screen.getByRole('alert')).toHaveTextContent('Unsupported DDoS report');
  expect(stringify.mock.calls.some(([value]) => value === malformed || Array.isArray(value) && value[0] === malformed)).toBe(false);
});

it('does not traverse unrelated JSON job metadata when deriving source authority', () => {
  let metadata: unknown = 'irrelevant';
  for (let i = 0; i < 12000; i++) metadata = { metadata };
  const job = { id: 'A', dataset_id: 'dataset-A', metadata };
  expect(() => render(<DDoSAttackPanel report={report} job={job}/>)).not.toThrow();
  openFinding();
  expect(screen.getByRole('region', { name: 'DDoS finding evidence' })).toBeVisible();
});

it('retains the candidate controller selection and export refusal while its heavy body is absent', () => {
  vi.spyOn(exports, 'downloadDDoSExport').mockReturnValue(false);
  render(<DDoSAttackPanel report={report} job={{ id: 'A', dataset_id: 'dataset-A' }}/>);
  openFinding(); inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Download reviewed candidate JSON' }));
  expect(screen.getByRole('alert')).toHaveTextContent('Export refused');
  fireEvent.click(screen.getByRole('button', { name: /Hide detailed evidence/ }));
  expect(screen.queryByRole('region', { name: 'Candidate inspection' })).not.toBeInTheDocument();
  expect(screen.queryByText('Evaluated conditions (AND):')).not.toBeInTheDocument();
  openFinding();
  expect(screen.getByRole('region', { name: 'Candidate inspection' })).toBeVisible();
  expect(screen.getByRole('alert')).toHaveTextContent('Export refused');
  expect(exports.downloadDDoSExport).toHaveBeenCalledTimes(1);
});

it('keeps unchanged inline job projections authorized but permanently retires captured authority across source ABA', () => {
  const create = vi.fn(() => 'blob:owned');
  vi.stubGlobal('URL', class extends URL { static createObjectURL = create; static revokeObjectURL = vi.fn(); });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  const actual = exports.downloadDDoSExport;
  let captured: Parameters<typeof actual> | undefined;
  vi.spyOn(exports, 'downloadDDoSExport').mockImplementation((...args) => { captured = args; return actual(...args); });
  const job = { id: 'A', dataset_id: 'dataset-A' };
  const { rerender } = render(<DDoSAttackPanel report={report} job={{ ...job }}/>);
  openFinding(); inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Download reviewed candidate JSON' }));
  expect(create).toHaveBeenCalledTimes(1);
  rerender(<DDoSAttackPanel report={report} job={{ ...job }}/>);
  expect(actual(...captured!)).toBe(true);
  rerender(<DDoSAttackPanel report={report} job={{ ...job, dataset_id: 'replacement' }}/>);
  rerender(<DDoSAttackPanel report={report} job={{ ...job }}/>);
  act(() => expect(actual(...captured!)).toBe(false));
  expect(create).toHaveBeenCalledTimes(2);
});

it.each(['report-time', 'job-id', 'dataset', 'source-type', 'capture', 'link-types', 'topology'])('fences in-place %s changes and permanently retires after rendered ABA', field => {
  const ownedReport = structuredClone(report);
  const job = { id: 'A', dataset_id: 'dataset-A', source_type: 'PCAP_UPLOAD', source: { sha256: 'a'.repeat(64), link_types: [1] }, internal_networks: ['10.0.0.0/8'] };
  let authority!: () => boolean;
  vi.spyOn(exports, 'downloadDDoSExport').mockImplementation((...args) => { authority = args[4]; return false; });
  const { rerender } = render(<DDoSAttackPanel report={ownedReport} job={job}/>);
  openFinding(); inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Download reviewed candidate JSON' }));
  expect(authority()).toBe(true);
  const before = structuredClone({ report: ownedReport, job });
  if (field === 'report-time') ownedReport.summary.first_seen = '2020-01-01T00:00:00Z';
  if (field === 'job-id') job.id = 'B';
  if (field === 'dataset') job.dataset_id = 'dataset-B';
  if (field === 'source-type') job.source_type = 'LIVE';
  if (field === 'capture') job.source.sha256 = 'b'.repeat(64);
  if (field === 'link-types') job.source.link_types = [101];
  if (field === 'topology') job.internal_networks = ['10.0.0.0/9'];
  expect(authority()).toBe(false);
  rerender(<DDoSAttackPanel report={ownedReport} job={job}/>);
  Object.assign(ownedReport, before.report); Object.assign(job, before.job);
  rerender(<DDoSAttackPanel report={ownedReport} job={job}/>);
  expect(authority()).toBe(false);
  openFinding(); inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Download reviewed candidate JSON' }));
  expect(authority()).toBe(true);
});

it('uses one lazy detail across actual App finding → PCAP → AI → finding while keeping coverage available', async () => {
  const job = JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8'));
  localStorage.setItem('c2hunter-token', 'owned-fixture');
  const fetcher = vi.fn(async (input: unknown) => Response.json(String(input).endsWith(`/analysis-jobs/${job.id}`) ? job
    : String(input).endsWith('/ai-capabilities') ? { available: true, ddos_interpretation: true, remote: false, provider: 'fixture', model_name: 'fixture' }
      : { items: [] }));
  vi.stubGlobal('fetch', fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('region', { name: 'DDoS at a glance' });
  expect(screen.queryByRole('button', { name: 'Review window 1' })).not.toBeInTheDocument();
  openFinding(); inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Open PCAP review windows' }));
  expect(screen.queryByRole('region', { name: 'DDoS finding evidence' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Review window 1' }));
  expect(screen.getByRole('region', { name: 'Candidate evidence' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Review window 1' })).not.toBeInTheDocument();
  const guide = screen.getByRole('region', { name: 'PCAP review guidance' });
  fireEvent.click(within(guide).getByRole('button', { name: 'PCAP coverage and limitations' }));
  expect(screen.getByRole('region', { name: 'PCAP coverage and limitations' })).toHaveTextContent('Temporal reply evidence is heuristic');
  openFinding();
  expect(screen.queryByRole('button', { name: 'Run DDoS AI interpretation' })).not.toBeInTheDocument();
  expect(screen.getByRole('region', { name: 'Candidate inspection' })).toBeVisible();
  expect(screen.getByRole('region', { name: 'PCAP coverage and limitations' })).toBeVisible();
  expect(fetcher.mock.calls.every(call => String(call[0]).startsWith('/api/v1/'))).toBe(true);
  client.clear();
});

it('pins pending AI admission, normal-reference submission and refused export through surface switches without replay or cancellation', async () => {
  const job = JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8'));
  const normal = { id: 'normal-reference', dataset_id: 'normal-dataset', name: 'Operator reference', status: 'COMPLETED' };
  const accepted = { id: 'accepted-ai', status: 'QUEUED', analysis_kind: 'DDOS_ATTACK', language: 'en' };
  localStorage.setItem('c2hunter-token', 'owned-fixture');
  vi.spyOn(api, 'get').mockImplementation(async path => path === `/analysis-jobs/${job.id}` ? job
    : path === '/ai-capabilities' ? { available: true, ddos_interpretation: true, remote: true, destination: 'https://model.invalid', provider: 'fixture', model_name: 'fixture' }
      : path === '/ai-runs/accepted-ai' ? accepted : path.startsWith('/analysis-jobs?') ? { items: [normal], total: 1, page: 1, page_size: 20 } : { items: [] });
  let finishAI!: (value: unknown) => void, rejectReference!: (reason: Error) => void;
  const pendingAI = new Promise(resolve => { finishAI = resolve; });
  const pendingReference = new Promise((_, reject) => { rejectReference = reject; });
  const post = vi.spyOn(api, 'post').mockImplementation(path => (path.endsWith('/reanalyze') ? pendingReference : pendingAI) as Promise<never>);
  let exported: Parameters<typeof exports.downloadDDoSExport> | undefined;
  vi.spyOn(exports, 'downloadDDoSExport').mockImplementation((...args) => { exported = args; return false; });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('region', { name: 'DDoS at a glance' });
  fireEvent.change(screen.getByLabelText('Normal reference action'), { target: { value: 'select' } });
  fireEvent.click(await screen.findByRole('radio'));
  const form = screen.getByRole('heading', { name: 'DDoS threshold 재분석' }).closest('form')!;
  fireEvent.submit(form);
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
  openFinding(); inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Download reviewed candidate JSON' }));
  fireEvent.click(screen.getByRole('button', { name: 'Open PCAP review windows' }));
  fireEvent.click(screen.getByRole('button', { name: 'Review window 1' }));
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  fireEvent.click(screen.getByLabelText('I consent to this remote destination.'));
  const start = screen.getByRole('button', { name: 'Run DDoS AI interpretation' });
  await waitFor(() => expect(start).toBeEnabled());
  const capturedStart = handler(start);
  act(() => { capturedStart(); capturedStart(); });
  await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
  openFinding();
  expect(screen.getByRole('region', { name: 'Candidate inspection' })).toBeVisible();
  expect(screen.getByText(/Export refused/)).toBeVisible();
  expect(exported![4]()).toBe(true);
  expect(screen.getByLabelText('Normal reference action')).toBeDisabled();
  expect(screen.getByRole('radio')).toBeChecked();
  expect(screen.getByRole('radio')).toBeDisabled();
  fireEvent.submit(form);
  fireEvent.click(screen.getByRole('button', { name: 'Open PCAP review windows' }));
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  expect(screen.getByLabelText('I consent to this remote destination.')).toBeChecked();
  expect(screen.getByRole('button', { name: 'Starting…' })).toBeDisabled();
  act(() => capturedStart());
  expect(post).toHaveBeenCalledTimes(2);
  await act(async () => { finishAI(accepted); rejectReference(new Error('Reference eligibility rejected')); });
  expect(await screen.findByText('Reference eligibility rejected')).toBeVisible();
  expect(await screen.findByRole('button', { name: 'Cancel AI run' })).toBeVisible();
  openFinding();
  expect(screen.getByRole('button', { name: 'Cancel AI run' })).toBeVisible();
  expect(screen.getByRole('radio')).toBeChecked();
  expect(post.mock.calls.map(([path]) => path)).toEqual([`/analysis-jobs/${job.id}/reanalyze`, `/analysis-jobs/${job.id}/ai-runs`]);
  expect(post.mock.calls[0][1]).toHaveProperty('ddos_normal_reference', { job_id: normal.id, dataset_id: normal.dataset_id });
  expect(post.mock.calls[1][1]).toMatchObject({ analysis_kind: 'DDOS_ATTACK', language: 'en', allow_remote: true });
  client.clear();
});

it.each(['success', 'error'])('keeps hidden admission visibly pending through deferred %s without replay', async outcome => {
  const job = JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8'));
  const accepted = { id: 'deferred-ai', status: 'QUEUED', analysis_kind: 'DDOS_ATTACK', language: 'en' };
  localStorage.setItem('c2hunter-token', 'owned-fixture');
  vi.spyOn(api, 'get').mockImplementation(async path => path === `/analysis-jobs/${job.id}` ? job
    : path === '/ai-capabilities' ? { available: true, ddos_interpretation: true, remote: false }
      : path === '/ai-runs/deferred-ai' ? accepted : { items: [] });
  let resolve!: (value: unknown) => void, reject!: (error: Error) => void;
  const pending = new Promise((yes, no) => { resolve = yes; reject = no; });
  const post = vi.spyOn(api, 'post').mockReturnValue(pending as Promise<never>);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('region', { name: 'DDoS at a glance' });
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  const start = screen.getByRole('button', { name: 'Run DDoS AI interpretation' });
  await waitFor(() => expect(start).toBeEnabled());
  fireEvent.click(start);
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
  openFinding();
  expect(screen.getByText('AI request pending — admission not yet confirmed.')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Return to DDoS AI interpretation' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Open PCAP review windows' }));
  expect(screen.getByText('AI request pending — admission not yet confirmed.')).toBeVisible();
  await act(async () => { if (outcome === 'success') resolve(accepted); else reject(new Error('Deferred rejection')); });
  if (outcome === 'success') expect(await screen.findByText('QUEUED')).toBeVisible();
  else expect(await screen.findByText('AI admission unconfirmed. Review the request before trying again.')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Return to DDoS AI interpretation' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Return to DDoS AI interpretation' }));
  expect(post).toHaveBeenCalledTimes(1);
  client.clear();
});

it.each(['settle', 'retire'])('keeps deferred cancellation truthful across hidden detail and source %s', async lifetime => {
  const job = JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8'));
  const accepted = { id: 'cancel-ai', status: 'QUEUED', analysis_kind: 'DDOS_ATTACK', language: 'en' };
  localStorage.setItem('c2hunter-token', 'owned-fixture');
  vi.spyOn(api, 'get').mockImplementation(async path => path === `/analysis-jobs/${job.id}` ? job
    : path === '/ai-capabilities' ? { available: true, ddos_interpretation: true, remote: false }
      : path === '/ai-runs/cancel-ai' ? accepted : path.endsWith('/ai-runs') ? { items: [accepted] } : { items: [] });
  let finish!: (value: unknown) => void;
  const pending = new Promise(resolve => { finish = resolve; });
  const post = vi.spyOn(api, 'post').mockReturnValue(pending as Promise<never>);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const invalidate = vi.spyOn(client, 'invalidateQueries');
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel AI run' }));
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
  openFinding();
  expect(screen.getByText('AI cancellation pending — stopping is not yet confirmed.')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Cancel AI run' })).toBeDisabled();
  if (lifetime === 'retire') {
    act(() => client.setQueryData(['job', job.id], { ...job, dataset_id: 'replacement' }));
    await waitFor(() => expect(screen.queryByRole('region', { name: 'DDoS finding evidence' })).not.toBeInTheDocument());
    act(() => client.setQueryData(['job', job.id], job));
    await screen.findByRole('region', { name: 'DDoS at a glance' });
  }
  await act(async () => { accepted.status = 'CANCELLED'; finish({ status: 'CANCELLED' }); });
  if (lifetime === 'settle') expect(await screen.findByText('CANCELLED')).toBeVisible();
  else expect(invalidate).not.toHaveBeenCalled();
  expect(post.mock.calls).toEqual([['/ai-runs/cancel-ai/cancel', { reason: 'operator requested from web console' }]]);
  client.clear();
});

it.each(['dataset', 'capture', 'topology', 'report', 'invalid-report', 'route', 'auth'])('retires detached export, PCAP and AI callbacks after real %s loss, including cached ABA', async change => {
  const job = { ...JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/positive.job.json', 'utf8')), name: 'Source A' };
  const other = { ...JSON.parse(readFileSync('../controller/tests/fixtures/pcap_attack_guidance/ack.job.json', 'utf8')), name: 'Source B' };
  localStorage.setItem('c2hunter-token', 'owned-fixture');
  vi.spyOn(api, 'get').mockImplementation(async path => path === `/analysis-jobs/${job.id}` ? job : path === `/analysis-jobs/${other.id}` ? other
    : path === '/ai-capabilities' ? { available: true, ddos_interpretation: true, remote: false }
      : path.startsWith('/analysis-jobs?') ? { items: [job, other], total: 2 } : { items: [] });
  const post = vi.spyOn(api, 'post').mockResolvedValue({});
  let exported: Parameters<typeof exports.downloadDDoSExport> | undefined;
  vi.spyOn(exports, 'downloadDDoSExport').mockImplementation((...args) => { exported = args; return false; });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(['job', job.id], job); client.setQueryData(['job', other.id], other);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[`/analyses/${job.id}`]}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('region', { name: 'DDoS at a glance' });
  openFinding(); inspect();
  fireEvent.click(screen.getByRole('button', { name: 'Download reviewed candidate JSON' }));
  fireEvent.click(screen.getByRole('button', { name: 'Open PCAP review windows' }));
  const pcap = handler(screen.getByRole('button', { name: 'Review window 1' }));
  fireEvent.click(screen.getByRole('button', { name: 'Open DDoS AI interpretation' }));
  const start = screen.getByRole('button', { name: 'Run DDoS AI interpretation' });
  await waitFor(() => expect(start).toBeEnabled());
  const ai = handler(start);
  expect(exported![4]()).toBe(true); // mounted-hidden positive control
  if (change === 'route') {
    fireEvent.click(screen.getByRole('link', { name: 'Back to analysis history' }));
    fireEvent.click(await screen.findByRole('link', { name: 'Source B' }));
    await screen.findByRole('region', { name: 'DDoS at a glance' });
    fireEvent.click(screen.getByRole('link', { name: 'Back to analysis history' }));
    fireEvent.click(await screen.findByRole('link', { name: 'Source A' }));
    await screen.findByRole('region', { name: 'DDoS at a glance' });
  } else if (change === 'auth') {
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  } else {
    const replacement = structuredClone(job);
    if (change === 'dataset') replacement.dataset_id += '-new';
    if (change === 'capture') replacement.source = { ...replacement.source, sha256: 'f'.repeat(64) };
    if (change === 'topology') replacement.internal_networks = ['10.0.0.0/9'];
    if (change === 'report') replacement.ddos_attack = other.ddos_attack;
    if (change === 'invalid-report') replacement.ddos_attack.version = 'unknown';
    act(() => { client.setQueryData(['job', job.id], replacement); });
    await waitFor(() => expect(screen.queryByRole('region', { name: 'Candidate inspection' })).not.toBeInTheDocument());
    act(() => { client.setQueryData(['job', job.id], job); });
    await screen.findByRole('region', { name: 'DDoS at a glance' });
  }
  act(() => { pcap(); ai(); });
  expect(exported![4]()).toBe(false);
  expect(screen.queryByRole('region', { name: 'Candidate evidence' })).not.toBeInTheDocument();
  expect(post).not.toHaveBeenCalled();
  client.clear();
});
