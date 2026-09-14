import { openGroups, openCoverage } from './reportDisclosure';
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';

beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));
import NetworkAnomalyPanel from '../src/NetworkAnomalyPanel';

const report = {
  version: 'network-pattern-report-v1',
  summary: { verdict: 'anomaly_observed', narrative: 'Repeated SYN observations.', scanned_records: 100, skipped_records: 0, evaluated_records: 100, incomplete_records: 0, flow_count: 25, suspect_flow_count: 24, detailed_flow_count: 1, issue_count: 1, displayed_issue_count: 1, omitted_issue_count: 0, coverage_complete: true, truncated: false },
  flows: [], warnings: [], limitations: ['Single-vantage observation.'],
  issues: [{ id: 'syn-1', pattern: 'syn_retransmissions', title: 'SYN retransmissions', severity: 'observation', scope: { sensor_id: 'sensor-1', interface_id: 0, protocol: 'TCP', peer: { ip: '203.0.113.1', port: 443 } }, event_count: 48, affected_flow_count: 24, affected_host_count: 12, first_seen: '2026-09-11T00:00:00Z', last_seen: '2026-09-11T00:01:00Z', examples: [{ endpoint_a: { ip: '10.0.0.1', port: 50000 }, endpoint_b: { ip: '203.0.113.1', port: 443 }, event_count: 2 }], omitted_examples: 23, evidence: ['Repeated SYN sequence observed.'], uncertainty: ['Capture loss cannot be excluded.'], next_checks: ['Compare a second observation point.'] }],
};

it('presents one overall verdict and grouped scope, with only real examples expanded lazily', () => {
  const { container } = render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(screen.getByText(/24 affected flows/)).toBeVisible();
  expect(screen.getByText(/48 events/)).toBeVisible();
  expect(screen.queryByText(/10.0.0.1/)).not.toBeInTheDocument();
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  openGroups();
  fireEvent.click(screen.getByRole('button', { name: /Show representative evidence/ }));
  expect(screen.getByText(/Capture loss cannot be excluded/)).toBeVisible();
  expect(screen.getByText(/Compare a second observation point/)).toBeVisible();
  expect(screen.getByText(/10.0.0.1:50000/)).toBeVisible();
  expect(screen.getByText(/23.*examples omitted/)).toBeVisible();
  expect(container.querySelectorAll('*').length).toBeLessThan(500);
});

it.each([
  { ...report, summary: { ...report.summary, verdict: 'no_clear_anomaly', coverage_complete: false } },
  { ...report, summary: { ...report.summary, verdict: 'no_clear_anomaly', skipped_records: 2 } },
  { ...report, summary: {} },
  { ...report, summary: { verdict: 'anomaly_observed' } },
  { ...report, warnings: ['UNSUPPORTED_WARNING'] },
  { ...report, issues: [{ ...report.issues[0], pattern: 'invented_pattern' }] },
])('fails closed for unknown, inconsistent or incomplete report semantics', value => {
  render(<NetworkAnomalyPanel report={value}/>);
  expect(screen.getByRole('heading', { name: 'Insufficient data' })).toBeVisible();
  expect(screen.queryByText('No clear anomaly observed')).not.toBeInTheDocument();
});

it('bounds large reports and clears previous and stale expanded evidence', () => {
  const large = { ...report, summary: { ...report.summary, issue_count: 1000, displayed_issue_count: 1000, omitted_issue_count: 2, truncated: true }, issues: Array.from({ length: 1000 }, (_, i) => ({ ...report.issues[0], id: String(i), examples: Array.from({ length: 100 }, () => report.issues[0].examples[0]) })) };
  const { container, rerender } = render(<NetworkAnomalyPanel report={large}/>);
  openGroups();
  expect(screen.getByText(/992 retained groups not shown on this page/)).toBeVisible();
  expect(screen.getByText(/Report truncated/)).toBeVisible();
  expect(screen.getAllByRole('button', { name: /representative evidence/ })).toHaveLength(8);
  for (const button of screen.getAllByRole('button', { name: /representative evidence/ })) {
    fireEvent.click(button);
    expect(screen.getAllByRole('region', { name: 'Representative flow evidence' })).toHaveLength(1);
    expect(container.querySelectorAll('*').length).toBeLessThan(500);
  }
  rerender(<NetworkAnomalyPanel report={{ ...report }}/>);
  expect(screen.queryByRole('region', { name: 'Representative flow evidence' })).not.toBeInTheDocument();
});

it('shows bounded numeric producer facts without interpreting missing values as zero', () => {
  const facts = { tcp_sequence: 101, tcp_acknowledgment: 0, tcp_window: 8192, transport_payload_length: 3, icmp_type: 3, icmp_code: 1 };
  render(<NetworkAnomalyPanel report={{ ...report, issues: [{ ...report.issues[0], examples: [{ ...report.issues[0].examples[0], facts }] }] }}/>);
  openGroups();
  fireEvent.click(screen.getByRole('button', { name: /Show representative evidence/ }));
  for (const [key, value] of Object.entries(facts)) expect(screen.getByText(`${key}: ${value}`)).toBeVisible();
});

it('preserves positive findings while prominently labeling producer resource-limited lower bounds', () => {
  render(<NetworkAnomalyPanel report={{ ...report, warnings: ['FLOW_TRACKING_LIMIT_REACHED', 'CORRELATION_LIMIT_REACHED', 'ICMP_QUOTE_LIMIT_REACHED', 'OBSERVATION_LIMIT_REACHED'], summary: { ...report.summary, tracking_limited_records: 25, counts_are_lower_bounds: true, coverage_complete: false } }}/>);
  expect(screen.getByRole('heading', { name: 'Anomaly observed' })).toBeVisible();
  expect(screen.getByText(/25 records.*tracking/i)).toBeVisible();
  expect(screen.getByText(/Counts are lower bounds/i)).toBeVisible();
  openCoverage();
  expect(screen.getByText(/FLOW_TRACKING_LIMIT_REACHED/)).toBeVisible();
  expect(screen.getByText(/CORRELATION_LIMIT_REACHED/)).toBeVisible();
});

it('explicitly discloses unsupported legacy latency and measurement features', () => {
  render(<NetworkAnomalyPanel report={report}/>);
  openCoverage();
  expect(screen.getByText(/RTT\/latency, interarrival dispersion and TTL measurements are not computed by this pattern-first producer/)).toBeVisible();
});

it('marks old saved reports as legacy rather than deriving an overall verdict', () => {
  render(<NetworkAnomalyPanel report={{ version: 'network-anomaly-v1', summary: {}, flows: [], warnings: [], limitations: [] }}/>);
  expect(screen.getByText(/Legacy report/)).toBeVisible();
  expect(screen.queryByRole('table')).not.toBeInTheDocument();
  expect(screen.getByText(/overall verdict is unavailable/i)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: /Show legacy/ }));
  expect(screen.getByText(/No supported flows/)).toBeVisible();
});
