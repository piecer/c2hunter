import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { factLabels } from '../src/reportTranslations';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';

const python = process.env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
const generate = () => execFileSync(python, ['tests/network_report_fixture.py'], { encoding: 'utf8' });
const fixtures = JSON.parse(generate()) as Record<string, NetworkAnomalyReport>;
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));

it('shows a distinct low-confidence cause hypothesis and lazy supporting measurements from the actual producer', () => {
  render(<NetworkAnomalyPanel report={fixtures.syn_reset}/>);
  const article = within(screen.getAllByRole('article')[0]);
  expect(article.getByRole('heading', { name: 'Possible cause — hypothesis' })).toBeVisible();
  expect(article.getByText(/Low causal confidence/)).toBeVisible();
  expect(screen.queryByText(/measurements are not computed/)).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  fireEvent.click(article.getByRole('button'));
  expect(article.getByRole('region', { name: 'Supporting measurements' })).toBeVisible();
  expect(article.getByText(/Interarrival dispersion \(ms\)/)).toBeVisible();
  expect(article.getByText(/IPv4 TTL \/ IPv6 Hop Limit/)).toBeVisible();
});

it('presents the actual leading hypothesis in the overall report without inventing one for controls', () => {
  const { rerender } = render(<NetworkAnomalyPanel report={fixtures.supporting}/>);
  expect(screen.getByRole('heading', { name: 'Leading possible cause — hypothesis' })).toBeVisible();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(screen.getByRole('heading', { name: '주요 가능한 원인 — 가설' })).toBeVisible();
  rerender(<NetworkAnomalyPanel report={fixtures.normal}/>);
  expect(screen.queryByRole('heading', { name: '주요 가능한 원인 — 가설' })).not.toBeInTheDocument();
});

it('keeps every actual measurement fact key translatable in Korean', () => {
  const keys = new Set<string>();
  const visit = (value: unknown) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) for (const [key, child] of Object.entries(value)) { keys.add(key); visit(child); }
  };
  for (const report of Object.values(fixtures)) for (const issue of report.issues ?? []) for (const example of issue.examples) visit(example.measurements);
  expect(keys.size).toBeGreaterThan(20);
  for (const key of keys) expect(factLabels[key], key).toMatch(/[가-힣]|→/);
});

it('displays real eligible RTT, exclusion counts and directional dispersion without making an AI request', () => {
  const fetcher = vi.fn();
  vi.stubGlobal('fetch', fetcher);
  render(<NetworkAnomalyPanel report={fixtures.supporting}/>);
  fireEvent.click(screen.getByRole('button'));
  const detail = screen.getByRole('region', { name: 'Supporting measurements' });
  expect(detail).toHaveTextContent('Observed RTT (ms) — Samples: 2 · mean / min / max: 100 / 100 / 100 · dispersion (population stddev): 0');
  expect(detail).toHaveTextContent('Eligible RTT samples: SYN/ACK 1 · Data/ACK 1. Excluded candidate matches: ambiguous / retransmitted 1');
  expect(detail).toHaveTextContent('A → B: Samples: 3 · mean / min / max: 166.666667 / 100 / 200 · dispersion (population stddev): 47.140452');
  expect(detail).toHaveTextContent('B → A: Samples: 2 · mean / min / max: 250 / 200 / 300 · dispersion (population stddev): 50');
  expect(fetcher).not.toHaveBeenCalled();
});

it('distinguishes absent RTT from zero when the actual producer excludes retransmitted candidates', () => {
  render(<NetworkAnomalyPanel report={fixtures.ambiguous_rtt}/>);
  fireEvent.click(screen.getByRole('button'));
  const detail = screen.getByRole('region', { name: 'Supporting measurements' });
  expect(detail).toHaveTextContent('Observed RTT (ms) — Samples: 0 · mean / min / max: Unknown / Unknown / Unknown');
  expect(detail).toHaveTextContent('ambiguous / retransmitted 1');
  expect(detail).toHaveTextContent('NO_UNAMBIGUOUS_RTT');
});

it('explains missing metadata rather than displaying invented zero TTL values', () => {
  render(<NetworkAnomalyPanel report={fixtures.missing_metadata}/>);
  fireEvent.click(screen.getByRole('button'));
  const detail = screen.getByRole('region', { name: 'Supporting measurements' });
  expect(detail).toHaveTextContent('A → B: Samples 0 · min / max Unknown / Unknown · changes 0 · missing 2');
  expect(detail).toHaveTextContent('TTL / Hop Limit metadata is missing. (MISSING_TTL)');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(detail).toHaveTextContent('알 수 없음 / 알 수 없음');
  expect(detail).toHaveTextContent('TTL / 홉 제한 메타데이터가 없습니다. (MISSING_TTL)');
});

it('labels actual IPv6 hop limits and preserves measured zero and variation without route claims', () => {
  render(<NetworkAnomalyPanel report={fixtures.ipv6_hop_limit}/>);
  fireEvent.click(screen.getByRole('button'));
  const detail = screen.getByRole('region', { name: 'Supporting measurements' });
  expect(detail).toHaveTextContent('IPv4 TTL / IPv6 Hop Limit');
  expect(detail).toHaveTextContent('A → B: Samples 3 · min / max 0 / 64 · changes 2 · missing 0');
  expect(detail).toHaveTextContent('variation is not proof of route changes');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(detail).toHaveTextContent('IPv4 TTL / IPv6 홉 제한');
  expect(detail).toHaveTextContent('최소 / 최대 0 / 64 · 변화 2');
});

it.each(['normal', 'missing', 'incomplete'])('does not invent a cause or metric panel for the actual %s control', name => {
  render(<NetworkAnomalyPanel report={fixtures[name]}/>);
  expect(screen.queryByRole('heading', { name: 'Possible cause — hypothesis' })).not.toBeInTheDocument();
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
});

it('does not upgrade old saved reports and clears new measurements on report replacement', () => {
  const old = structuredClone(fixtures.supporting);
  delete old.measurement_version;
  const { rerender } = render(<NetworkAnomalyPanel report={fixtures.supporting}/>);
  fireEvent.click(screen.getByRole('button'));
  expect(screen.getByRole('region', { name: 'Supporting measurements' })).toBeVisible();
  rerender(<NetworkAnomalyPanel report={old}/>);
  expect(screen.getByText(/measurements are not computed/)).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Possible cause — hypothesis' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button'));
  expect(screen.getByText('tcp_sequence: 104')).toBeVisible();
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
});

it('bounds new reports to eight groups and three lazily mounted examples with one detail owner', () => {
  const base = fixtures.supporting;
  const issue = base.issues![0];
  const report = { ...base, issues: Array.from({ length: 1000 }, () => ({ ...issue, examples: Array.from({ length: 100 }, () => issue.examples[0]) })) };
  const { container, rerender } = render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getAllByRole('article')).toHaveLength(8);
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
  for (const button of screen.getAllByRole('button', { name: /representative evidence/ })) {
    fireEvent.click(button);
    expect(screen.getAllByRole('region', { name: 'Representative flow evidence' })).toHaveLength(1);
    expect(screen.getAllByRole('region', { name: 'Supporting measurements' })).toHaveLength(3);
    expect(container.querySelectorAll('*').length).toBeLessThan(500);
  }
  rerender(<NetworkAnomalyPanel report={fixtures.normal}/>);
  expect(screen.queryByRole('region', { name: 'Supporting measurements' })).not.toBeInTheDocument();
});

it('fails closed for unsupported cause codes and suppresses untrusted cause and measurement prose', () => {
  const report = structuredClone(fixtures.supporting);
  report.issues![0].suspected_cause = { code: 'future', confidence: 'high', summary: 'POISON' };
  report.issues![0].detailed_analysis = ['POISON'];
  report.issues![0].examples[0].measurements = { reasons: ['POISON'], observed_rtt_ms: { count: 0, mean: 123, min: 123, max: 123 } };
  const { container } = render(<NetworkAnomalyPanel report={report}/>);
  const article = within(screen.getByRole('article'));
  expect(article.getByText(/no supported cause hypothesis/)).toBeVisible();
  expect(article.queryByText(/Low causal confidence/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button'));
  expect(container).not.toHaveTextContent('POISON');
  expect(screen.getByRole('region', { name: 'Supporting measurements' })).not.toHaveTextContent('123');
});
