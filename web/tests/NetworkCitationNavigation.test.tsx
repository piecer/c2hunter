import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import App from '../src/App';
import NetworkAnomalyPanel from '../src/NetworkAnomalyPanel';
import { useNetworkEvidence, type EvidenceContext } from '../src/networkEvidenceContext';
const fixture = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_report_fixture.py', '--citation'], { encoding: 'utf8', maxBuffer: 20000000 }));
const maximum = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_report_fixture.py', '--maximum'], { encoding: 'utf8', maxBuffer: 20000000 }));
const clients: QueryClient[] = [];
afterEach(() => clients.splice(0).forEach(c => c.clear()));
async function setup(report = structuredClone(fixture.many), run = structuredClone(fixture.run)) {
  localStorage.setItem('c2hunter-token', 'fixture-token');
  localStorage.setItem('c2hunter-report-language', 'en');
  const job = { id: 'citation-job', dataset_id: 'citation-dataset', name: 'Citation investigation', status: 'COMPLETED', mode: 'PCAP_UPLOAD', source_type: 'PCAP_UPLOAD', analysis: { module: 'network_anomaly' }, network_anomaly: report };
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: unknown, init?: RequestInit) => {
    const path = String(input); calls.push(`${init?.method ?? 'GET'} ${path}`);
    if (path.endsWith('/ai-capabilities')) return Response.json({ available: true, network_interpretation: true, remote: false });
    if (path.endsWith('/ai-runs/citation-run')) return Response.json(run);
    if (path.endsWith('/citation-job/ai-runs')) return Response.json({ items: [{ ...run, id: 'citation-run' }] });
    if (path.endsWith('/analysis-jobs/citation-job')) return Response.json(job);
    return Response.json({ items: [] });
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/citation-job']}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('heading', { name: 'Citation investigation' });
  await waitFor(() => expect(client.isFetching()).toBe(0));
  await full();
  return { calls, client, job };
}
async function full() {
  fireEvent.click(await screen.findByRole('button', { name: 'Open AI interpretation' }));
  fireEvent.click(await screen.findByRole('button', { name: 'View full AI text' }));
}
it('retires captured navigation callbacks even when the original report object returns', () => {
  localStorage.setItem('c2hunter-report-language', 'en');
  let captured: EvidenceContext | undefined;
  function Probe() { captured = useNetworkEvidence(); return null; }
  const a = fixture.many, b = structuredClone(a), job = { id: 'citation-job', status: 'COMPLETED' };
  b.issues[19].examples[0].facts.tcp_sequence++;
  const view = render(<NetworkAnomalyPanel job={job} report={a}><Probe/></NetworkAnomalyPanel>);
  const old = captured!;
  act(() => old.navigate(19));
  expect(screen.getByRole('region', { name: 'Representative flow evidence' })).toHaveFocus();
  view.rerender(<NetworkAnomalyPanel job={job} report={b}><Probe/></NetworkAnomalyPanel>);
  expect(screen.queryByRole('region', { name: 'Representative flow evidence' })).not.toBeInTheDocument();
  view.rerender(<NetworkAnomalyPanel job={job} report={a}><Probe/></NetworkAnomalyPanel>);
  expect(old.current()).toBe(false);
  act(() => old.navigate(19));
  expect(screen.queryByRole('region', { name: 'Representative flow evidence' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'View all anomaly items' })).toHaveAttribute('aria-expanded', 'false');
  const live = captured!; view.unmount(); expect(live.current()).toBe(false);
});
it.each([0, 10, 20])('navigates section citation %s by keyboard to exact raw ordinal page and focused evidence without requests', async section => {
  const { calls } = await setup();
  const id = fixture.many.issues[19].id;
  const before = [...calls];
  const links = within(screen.getByRole('article', { name: 'Full AI interpretation' })).getAllByRole('button', { name: id });
  links[section].focus();
  await userEvent.keyboard(section === 10 ? ' ' : '{Enter}');
  expect(screen.getByText('Page 3 of 3')).toBeVisible();
  const evidence = screen.getByRole('region', { name: 'Representative flow evidence' });
  expect(evidence).toHaveFocus(); expect(evidence.id).toBe('network-evidence-19');
  expect(evidence.closest('article')).toHaveTextContent(id);
  expect(screen.queryByRole('article', { name: 'Full AI interpretation' })).not.toBeInTheDocument();
  expect(calls).toEqual(before);
});
it('keeps legacy source-less saved hypotheses visible but navigation non-actionable', async () => {
  const run = structuredClone(fixture.run); delete run.analysis_job_id;
  await setup(undefined, run);
  expect(screen.getAllByText('Capture duplication is possible.')).toHaveLength(10);
  expect(screen.getAllByRole('button', { name: fixture.many.issues[19].id })[0]).toBeDisabled();
  expect(screen.getAllByText(/Cannot navigate: provenance does not match the current report/).length).toBeGreaterThan(0);
});
it.each(['fact', 'measurement', 'measurement-version', 'summary-cause'])('latches an observed same-job %s change across A→B→A until a new verified run', async field => {
  // Lifecycle needs one citation, not the maximum DOM already exercised below.
  const run = structuredClone(fixture.run);
  for (const key of ['possible_causes', 'prioritized_checks', 'correlations']) run.network_interpretation[key] = [{ ...run.network_interpretation[key][0], issue_ids: [fixture.many.issues[19].id] }];
  const { client, job } = await setup(undefined, run);
  const changed = structuredClone(job);
  if (field === 'fact') changed.network_anomaly.issues[0].examples[0].facts.tcp_sequence++;
  if (field === 'measurement') changed.network_anomaly.issues[0].examples[0].measurements.rtt_excluded.ambiguous++;
  if (field === 'measurement-version') delete changed.network_anomaly.measurement_version;
  if (field === 'summary-cause') changed.network_anomaly.summary.suspected_cause.code = 'service_refusal_or_policy';
  act(() => { client.setQueryData(['job', job.id], changed); });
  await full();
  expect(screen.getAllByRole('button', { name: fixture.many.issues[19].id })[0]).toBeDisabled();
  act(() => { client.setQueryData(['job', job.id], job); });
  await full();
  expect(screen.getAllByRole('button', { name: fixture.many.issues[19].id })[0]).toBeDisabled();
  const next = { ...run, id: 'new-verified-run', network_interpretation: { ...run.network_interpretation, summary: 'New verified run summary.' } };
  act(() => { client.setQueryData(['ai-run', next.id], next); client.setQueryData(['ai-runs', job.id], { items: [next, fixture.run] }); });
  await screen.findByText('New verified run summary.');
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  expect(screen.getAllByRole('button', { name: fixture.many.issues[19].id })[0]).toBeEnabled();
});
it.each(['quality-extra', 'quality-absent-to-null', 'quality-removed', 'measurement-extra', 'rtt-stats-extra', 'rtt-sources-extra', 'rtt-excluded-extra', 'direction-extra', 'direction-quality-extra', 'metric-quality-extra', 'ttl-extra', 'measurement-removed', 'measurement-added', 'legacy-reasons-overflow'])('latches consumed qualification %s through actual App replacement until a fresh run', async fault => {
  const report = structuredClone(fixture.many), run = structuredClone(fixture.run);
  const id = report.issues[19].id;
  const original = structuredClone(report.issues[19].examples[0].measurements);
  if (fault === 'quality-absent-to-null' || fault === 'legacy-reasons-overflow') delete report.issues[19].examples[0].measurements.metric_quality;
  if (fault === 'legacy-reasons-overflow') report.issues[19].examples[0].measurements.reasons = Array(7).fill('NO_UNAMBIGUOUS_RTT');
  if (fault === 'measurement-added') delete report.issues[19].examples[0].measurements;
  for (const key of ['possible_causes', 'prioritized_checks', 'correlations']) run.network_interpretation[key] = [{ ...run.network_interpretation[key][0], issue_ids: [id] }];
  const { client, job, calls } = await setup(report, run);
  const button = () => screen.getAllByRole('button', { name: id })[0];
  const region = () => screen.queryByRole('region', { name: 'Representative flow evidence' });
  const captured = Object.values(button()).find(value => value && typeof value === 'object' && 'onClick' in value) as { onClick: () => void };
  expect(captured.onClick).toBeTypeOf('function');
  fireEvent.click(button()); expect(region()).toHaveFocus();
  expect(region()).toHaveTextContent('Detailed measurement analysis');
  const changed = structuredClone(job), example = changed.network_anomaly.issues[19].examples[0], m = example.measurements;
  if (fault === 'quality-extra') m.metric_quality.extra = null;
  if (fault === 'quality-absent-to-null') m.metric_quality = null;
  if (fault === 'quality-removed') delete m.metric_quality;
  if (fault === 'measurement-extra') m.extra = null;
  if (fault === 'rtt-stats-extra') m.observed_rtt_ms.extra = null;
  if (fault === 'rtt-sources-extra') m.rtt_sources.extra = null;
  if (fault === 'rtt-excluded-extra') m.rtt_excluded.extra = null;
  if (fault === 'direction-extra') m.interarrival_variation_ms.extra = null;
  if (fault === 'direction-quality-extra') m.metric_quality.interarrival_variation_ms.extra = null;
  if (fault === 'metric-quality-extra') m.metric_quality.ttl_observed.a_to_b.extra = null;
  if (fault === 'ttl-extra') m.ttl_observed.a_to_b.extra = null;
  if (fault === 'measurement-removed') delete example.measurements;
  if (fault === 'measurement-added') example.measurements = original;
  if (fault === 'legacy-reasons-overflow') m.reasons.push('NO_UNAMBIGUOUS_RTT');
  const rawA = JSON.stringify(job), rawB = JSON.stringify(changed), before = [...calls];
  const replace = async (value: typeof job) => {
    await act(async () => { client.setQueryData(['job', job.id], value); await new Promise(resolve => setTimeout(resolve, 0)); });
    await full();
  };
  await replace(changed);
  act(() => captured.onClick()); expect(region()).toBeNull();
  expect(button()).toBeDisabled(); fireEvent.click(button()); expect(region()).toBeNull();
  await replace(job); expect(button()).toBeDisabled();
  const fresh = { ...run, id: 'fresh-qualification-run', created_at: '2026-10-25T00:00:00Z', network_interpretation: { ...run.network_interpretation, summary: 'Fresh qualification review.' } };
  await act(async () => { client.setQueryData(['ai-run', fresh.id], fresh); client.setQueryData(['ai-runs', job.id], { items: [fresh, run] }); await new Promise(resolve => setTimeout(resolve, 0)); });
  await screen.findByText('Fresh qualification review.');
  fireEvent.click(screen.getByRole('button', { name: 'View full AI text' }));
  expect(button()).toBeEnabled(); fireEvent.click(button()); expect(region()).toHaveFocus();
  expect(region()?.id).toBe('network-evidence-19'); expect(screen.getByText('Page 3 of 3')).toBeVisible();
  expect(calls).toEqual(before); expect(JSON.stringify(job)).toBe(rawA); expect(JSON.stringify(changed)).toBe(rawB);
});
it('keeps byte-identical qualification usable on a rebuilt metadata-only job response', async () => {
  const run = structuredClone(fixture.run), id = fixture.many.issues[19].id;
  for (const key of ['possible_causes', 'prioritized_checks', 'correlations']) run.network_interpretation[key] = [{ ...run.network_interpretation[key][0], issue_ids: [id] }];
  const { client, job, calls } = await setup(undefined, run);
  fireEvent.click(screen.getAllByRole('button', { name: id })[0]);
  const before = [...calls];
  await act(async () => { client.setQueryData(['job', job.id], { ...structuredClone(job), description: 'metadata only' }); await new Promise(resolve => setTimeout(resolve, 0)); });
  await full();
  const button = screen.getAllByRole('button', { name: id })[0];
  expect(button).toBeEnabled(); fireEvent.click(button);
  expect(screen.getByRole('region', { name: 'Representative flow evidence' })).toHaveFocus();
  expect(calls).toEqual(before);
});
it.each(['job', 'dataset', 'input', 'detail-id', 'duplicate', 'malformed-duplicate', 'unknown', 'input-pattern', 'input-count', 'input-time', 'input-duplicate', 'input-too-many'])('refuses unbound %s citations without extra requests', async fault => {
  const report = structuredClone(fixture.many), run = structuredClone(fixture.run);
  const id = report.issues[19].id;
  if (fault === 'job') run.analysis_job_id = 'other';
  if (fault === 'dataset') run.dataset_id = 'other';
  if (fault === 'input') delete run.network_input;
  if (fault === 'detail-id') run.id = 'wrong-detail';
  if (fault === 'duplicate' || fault === 'malformed-duplicate') { report.issues[0].id = id; if (fault === 'malformed-duplicate') report.issues[0].scope = null; }
  if (fault === 'unknown') run.network_interpretation.possible_causes[0].issue_ids = ['https://invalid.example/not-an-id'];
  if (fault === 'input-pattern') run.network_input.issues[19].pattern = 'syn_retransmissions';
  if (fault === 'input-count') run.network_input.issues[19].event_count++;
  if (fault === 'input-time') run.network_input.issues[19].last_seen = 'different';
  if (fault === 'input-duplicate') run.network_input.issues[0].id = id;
  if (fault === 'input-too-many') run.network_input.issues.push(run.network_input.issues[0]);
  const { calls } = await setup(report, run);
  const before = [...calls];
  const button = screen.getAllByRole('button', { name: fault === 'unknown' ? 'https://invalid.example/not-an-id' : id })[0];
  expect(button).toBeDisabled(); fireEvent.click(button); expect(calls).toEqual(before);
});
it('refuses output citations outside the actual first20 input and even forged minimum facts for ordinal100', async () => {
  const report = structuredClone(maximum.many), run = structuredClone(maximum.run);
  const last = report.issues[99];
  run.network_interpretation.possible_causes[0].issue_ids = [last.id];
  run.network_input.issues[19] = { ...run.network_input.issues[19], ...Object.fromEntries(['id', 'pattern', 'event_count', 'affected_flow_count', 'affected_host_count', 'first_seen', 'last_seen'].map(k => [k, last[k]])) };
  await setup(report, run);
  expect(screen.getByRole('button', { name: last.id })).toBeDisabled();
});
it.each([10, 20])('bounds actual mounted maximum100×10 report and %s×20×3 AI controls including hidden descendants', async count => {
  const run = structuredClone(maximum.run);
  if (count === 20) for (const key of ['possible_causes', 'prioritized_checks', 'correlations']) run.network_interpretation[key] = [...run.network_interpretation[key], ...run.network_interpretation[key]];
  const { calls } = await setup(maximum.many, run);
  const measure = () => expect(document.querySelectorAll('*').length).toBeLessThanOrEqual(2500);
  measure();
  fireEvent.click(screen.getAllByRole('button', { name: maximum.many.issues[19].id })[0]);
  expect(screen.getByText('Page 3 of 13')).toBeVisible(); measure();
  expect(screen.getAllByRole('region', { name: 'Representative flow evidence' })).toHaveLength(1);
  expect(screen.queryByRole('article', { name: 'Full AI interpretation' })).not.toBeInTheDocument();
  for (let page = 2; page < 13; page++) {
    for (const button of screen.getAllByRole('button', { name: /representative evidence/ })) {
      fireEvent.click(button); measure();
      expect(screen.queryAllByRole('region', { name: 'Representative flow evidence' }).length).toBeLessThanOrEqual(1);
    }
    if (page < 12) fireEvent.click(screen.getByRole('button', { name: 'Next groups' }));
  }
  expect(screen.getByText(maximum.many.issues[99].id)).toBeVisible();
  expect(calls.filter(c => !c.startsWith('GET '))).toEqual([]);
});
it('deduplicates citation controls within an item and preserves raw ordinal through invalid siblings', async () => {
  const report = structuredClone(fixture.many), run = structuredClone(fixture.run);
  report.issues[0].scope = null;
  run.network_interpretation.possible_causes = [{ ...run.network_interpretation.possible_causes[0], issue_ids: [report.issues[19].id, report.issues[19].id] }];
  run.network_interpretation.prioritized_checks = []; run.network_interpretation.correlations = [];
  await setup(report, run);
  const buttons = screen.getAllByRole('button', { name: report.issues[19].id }); expect(buttons).toHaveLength(1);
  fireEvent.click(buttons[0]);
  expect(screen.getByRole('region', { name: 'Representative flow evidence' }).id).toBe('network-evidence-19');
});
