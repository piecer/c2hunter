import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';
import { projectNetworkReport } from '../src/networkReportValidation';
const fixtures = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_report_fixture.py'], { encoding: 'utf8' }));
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
function freeze(value: unknown): void {
  if (value && typeof value === 'object') { Object.freeze(value); Object.values(value).forEach(freeze); }
}
it('rejects contradictory saved summary without inventing a healthy conclusion and preserves raw input', () => {
  const report = structuredClone(fixtures.normal);
  Object.assign(report.summary, { scanned_records: 0, evaluated_records: 999, displayed_issue_count: 7 });
  freeze(report); const raw = JSON.stringify(report);
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByRole('heading', { name: 'Insufficient data' })).toBeVisible();
  expect(screen.getByText(/Invalid or inconsistent report data/)).toBeVisible();
  expect(screen.queryByRole('heading', { name: 'No clear anomaly observed' })).not.toBeInTheDocument();
  expect(JSON.stringify(report)).toBe(raw);
});
it.each(['missing', 'incomplete'])('accepts real producer %s insufficiency without false invalid-data feedback', name => {
  render(<NetworkAnomalyPanel report={fixtures[name]}/>);
  expect(screen.queryByText(/Invalid or inconsistent report data/)).not.toBeInTheDocument();
});
it('keeps the unmodified real producer clear control', () => {
  render(<NetworkAnomalyPanel report={fixtures.normal as NetworkAnomalyReport}/>);
  expect(screen.getByRole('heading', { name: 'No clear anomaly observed' })).toBeVisible();
});
it.each(['null-example', 'endpoint', 'facts', 'scope', 'summary', 'pattern'])('isolates malformed %s and preserves independent positive evidence', fault => {
  const report = structuredClone(fixtures.syn_reset);
  const first = report.issues[0];
  if (fault === 'null-example') first.examples.unshift(null);
  if (fault === 'endpoint') first.examples[0].endpoint_a = null;
  if (fault === 'facts') first.examples[0].facts = [1, 2];
  if (fault === 'scope') first.scope = null;
  if (fault === 'summary') report.summary = null;
  if (fault === 'pattern') first.pattern = 'future-pattern';
  freeze(report);
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getAllByTestId('top-observation').length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole('button', { name: 'View all anomaly items' }));
  for (const button of screen.getAllByRole('button', { name: /Show representative evidence/ })) fireEvent.click(button);
  expect(screen.getAllByText(/Invalid|Unsupported/i).length).toBeGreaterThan(0);
  expect(screen.getByRole('region', { name: 'Representative flow evidence' })).toBeVisible();
});
it('preflights oversize issue arrays without traversing their elements', () => {
  const report = structuredClone(fixtures.syn_reset);
  report.issues = Array(101);
  Object.defineProperty(report.issues, 0, { get: () => { throw Error('oversize traversed'); } });
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByText(/Report structure limit exceeded/)).toBeVisible();
  expect(document.querySelectorAll('*').length).toBeLessThan(500);
});
it('rejects an oversize example collection but retains its issue observation', () => {
  const report = structuredClone(fixtures.syn_reset);
  report.issues[0].examples = Array(11).fill(null);
  render(<NetworkAnomalyPanel report={report}/>);
  openFirst();
  expect(screen.getByText(/Example collection limit exceeded/)).toBeVisible();
  expect(screen.getByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
});
it('preflights oversize warnings and never interprets additive fact fields', () => {
  const report = structuredClone(fixtures.syn_reset);
  report.warnings = Array(2049);
  Object.defineProperty(report.warnings, 0, { get: () => { throw Error('warnings traversed'); } });
  Object.defineProperty(report.issues[0].examples[0].facts, 'future', { enumerable: true, get: () => { throw Error('additive fact traversed'); } });
  render(<NetworkAnomalyPanel report={report}/>);
  openFirst();
  expect(screen.getByText(/Warning collection limit exceeded/)).toBeVisible();
});
it('rejects unknown report versions rather than opening them as legacy', () => {
  render(<NetworkAnomalyPanel report={{ ...fixtures.normal, version: 'future-version' }}/>);
  expect(screen.getByText(/Unsupported report version/)).toBeVisible();
  expect(screen.queryByRole('button', { name: /legacy flow/ })).not.toBeInTheDocument();
});
it.each([true, -1, Number.MAX_SAFE_INTEGER + 1, null, '7'])('rejects invalid summary counter %s', bad => {
  const report = structuredClone(fixtures.normal); report.summary.scanned_records = bad;
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByText(/Invalid or inconsistent report data/)).toBeVisible();
});
it('preserves missing optional metadata rather than synthesizing a zero', () => {
  const report = structuredClone(fixtures.normal);
  delete report.summary.tracking_limited_records; delete report.summary.counts_are_lower_bounds;
  delete report.measurement_version; delete report.summary.suspected_cause;
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByRole('heading', { name: 'No clear anomaly observed' })).toBeVisible();
});
it('keeps upstream lower-bound positive evidence with zero local tracking losses', () => {
  const upstream = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/network_report_fixture.py', '--upstream'], { encoding: 'utf8' }));
  render(<NetworkAnomalyPanel report={upstream}/>);
  expect(screen.getByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(screen.queryByText(/Invalid or inconsistent report data/)).not.toBeInTheDocument();
  expect(screen.getByText(/Counts are lower bounds/)).toBeVisible();
});
it('shows missing facts as not reported rather than zero', () => {
  const report = structuredClone(fixtures.syn_reset);
  delete report.issues[0].examples[0].facts;
  render(<NetworkAnomalyPanel report={report}/>); openFirst();
  expect(screen.getByText(/Numeric facts not reported/)).toBeVisible();
});
it.each(['verdict-object', 'verdict-array', 'protocol-object', 'protocol-array'])('rejects non-string %s without coercion or losing independent evidence', fault => {
  const report = structuredClone(fixtures.syn_reset);
  const bad = fault.endsWith('object') ? JSON.parse('{"toString":null}') : [fault.startsWith('verdict') ? report.summary.verdict : report.issues[0].scope.protocol];
  if (fault.startsWith('verdict')) report.summary.verdict = bad;
  else report.issues[0].scope.protocol = bad;
  freeze(report); const raw = JSON.stringify(report);
  const projection = projectNetworkReport(report);
  expect(projection.summaryTrusted).toBe(false);
  expect(projection.slots[1].issue?.id).toBe(report.issues[1].id);
  if (fault.startsWith('protocol')) expect(projection.slots[0].invalid).toBe(true);
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByText(/Invalid or inconsistent report data/)).toBeVisible();
  expect(screen.getAllByTestId('top-observation').length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole('button', { name: 'View all anomaly items' }));
  fireEvent.click(screen.getAllByRole('button', { name: /Show representative evidence/ }).at(-1)!);
  expect(screen.getByRole('region', { name: 'Representative flow evidence' })).toBeVisible();
  expect(JSON.stringify(report)).toBe(raw);
});
export function openFirst() {
  fireEvent.click(screen.getAllByRole('button', { name: /Inspect evidence/ })[0]);
}
