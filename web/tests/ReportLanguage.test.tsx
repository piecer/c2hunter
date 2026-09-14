import { openGroups, openEvidence, openCoverage } from './reportDisclosure';
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { diagnostics, patterns, warnings, factLabels } from '../src/reportTranslations';
import type { NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';
import NetworkAnomalyPanel from '../src/NetworkAnomalyPanel';

it('defaults the report to Korean and switches immediately using one accessible selector', () => {
  render(<NetworkAnomalyPanel report={{ version: 'network-anomaly-v1', summary: {}, flows: [], warnings: [], limitations: [] }}/>);
  expect(screen.getByRole('heading', { name: '이전 형식 보고서' })).toBeVisible();
  expect(screen.getAllByRole('combobox')).toHaveLength(1);
  fireEvent.change(screen.getByRole('combobox', { name: '보고서 언어 / Report language' }), { target: { value: 'en' } });
  expect(screen.getByRole('heading', { name: 'Legacy report' })).toBeVisible();
  expect(localStorage.getItem('c2hunter-report-language')).toBe('en');
});


const python = process.env.C2HUNTER_TEST_PYTHON ?? (existsSync('../.venv/bin/python') ? resolve('../.venv/bin/python') : 'python3');
const producer = (flag?: string) => JSON.parse(execFileSync(python, ['tests/network_report_fixture.py', ...(flag ? [flag] : [])], { encoding: 'utf8' }));
it('independently matches the actual producer diagnostic, pattern, warning and fact contract', () => {
  const contract = producer('--contract');
  expect(Object.keys(patterns).sort()).toEqual(contract.patterns);
  expect(Object.fromEntries(Object.entries(diagnostics).map(([key, pairs]) => [key, pairs.map(([en]) => en)]))).toEqual(contract.diagnostics);
  expect(Object.keys(warnings).sort()).toEqual(contract.warnings);
  for (const key of contract.facts) expect(factLabels[key]).toMatch(/[가-힣]/);
});
const legacyFixture = producer('--legacy') as NetworkAnomalyReport;
it('explains the real legacy per-flow correlation limit in both languages', () => {
  const report = producer('--legacy-limited') as NetworkAnomalyReport;
  expect(report.summary.scanned_records).toBe(257);
  expect(report.flows[0].warnings).toContain('FLOW_STATE_LIMIT_REACHED');
  render(<NetworkAnomalyPanel report={report}/>);
  fireEvent.click(screen.getByRole('button'));
  expect(screen.getByText('흐름별 연관 분석 상태 추적 한도에 도달하여 해당 흐름의 추가 전송 패턴을 평가하지 못했습니다. (FLOW_STATE_LIMIT_REACHED)')).toBeVisible();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
  expect(screen.getByText('The per-flow correlation state tracking limit was reached; additional transport patterns in this flow were not evaluated. (FLOW_STATE_LIMIT_REACHED)')).toBeVisible();
});
it('localizes the real legacy producer with one selector and unchanged metrics', () => {
  const original = JSON.stringify(legacyFixture);
  const { container } = render(<NetworkAnomalyPanel report={legacyFixture}/>);
  fireEvent.click(screen.getByRole('button'));
  expect(screen.getByRole('table', { name: '양방향 네트워크 흐름' })).toBeVisible();
  expect(screen.getByRole('columnheader', { name: '관찰된 RTT (ms)' })).toBeVisible();
  for (const text of legacyFixture.limitations) expect(container.textContent).not.toContain(text);
  expect(container.textContent).not.toContain('원문:');
  expect(screen.getAllByRole('combobox')).toHaveLength(1);
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
  for (const text of legacyFixture.limitations) expect(container.textContent).toContain(text);
  expect(JSON.stringify(legacyFixture)).toBe(original);
});
const fixtures = producer() as Record<string, NetworkAnomalyReport>;
it.each(Object.entries(fixtures))('localizes real producer %s without changing observations', (_name, report) => {
  const original = JSON.stringify(report);
  const { container } = render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByText('전체 네트워크 보고서')).toBeVisible();
  openGroups();
  openCoverage();
  const coverage = [report.summary.narrative, ...report.limitations];
  for (const text of coverage) expect(container.textContent).not.toContain(text);
  expect(container.textContent).not.toContain('원문');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
  for (const text of coverage) expect(container.textContent).toContain(text);
  for (const [index, issue] of (report.issues ?? []).entries()) {
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
    openEvidence(index);
    const prose = [...issue.evidence, ...issue.uncertainty, ...issue.next_checks];
    for (const text of prose) expect(container.textContent).not.toContain(text);
    expect(container.textContent).not.toContain('원문');
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
    for (const text of prose) expect(container.textContent).toContain(text);
  }
  expect(screen.getByText('OVERALL NETWORK REPORT')).toBeVisible();
  expect(JSON.stringify(report)).toBe(original);
});
it.each(['en', 'ko', 'invalid', 'EN', ''])('validates stored preference %s', value => {
  localStorage.setItem('c2hunter-report-language', value);
  render(<NetworkAnomalyPanel/>);
  expect(screen.getByRole('combobox')).toHaveValue(value === 'en' ? 'en' : 'ko');
});
it('works when storage reads and writes throw', () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked'); });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked'); });
  render(<NetworkAnomalyPanel/>);
  expect(screen.getByRole('combobox')).toHaveValue('ko');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
  expect(screen.getByRole('heading', { name: 'Overall network report' })).toBeVisible();
});
it('retains expansion, literal evidence and saved preference through both language changes and remount', () => {
  const report = fixtures.syn_reset;
  const { unmount } = render(<NetworkAnomalyPanel report={report}/>);
  openEvidence();
  const region = screen.getByRole('region', { name: '대표 흐름 증거' });
  const rawEndpoint = report.issues![0].examples[0].endpoint_a.ip;
  expect(region).toHaveTextContent(rawEndpoint);
  expect(region).toHaveTextContent('TCP 확인 번호: 101');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
  expect(screen.getByRole('region', { name: 'Representative flow evidence' })).toBe(region);
  expect(region).toHaveTextContent('tcp_acknowledgment: 101');
  unmount();
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByRole('combobox')).toHaveValue('en');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'ko' } });
  expect(localStorage.getItem('c2hunter-report-language')).toBe('ko');
  expect(screen.getByRole('heading', { name: '이상 징후 관찰됨' })).toBeVisible();
});
it.each(Object.entries(warnings))('localizes coverage warning %s while retaining its code', (code, [en, ko]) => {
  const report = { ...fixtures.syn_reset, warnings: [code] };
  render(<NetworkAnomalyPanel report={report}/>);
  openCoverage();
  expect(screen.getByText(`${ko} (${code})`)).toBeVisible();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } });
  expect(screen.getByText(`${en} (${code})`)).toBeVisible();
});
it('fails closed for unknown codes without hiding their original spelling', () => {
  const report = structuredClone(fixtures.syn_reset);
  report.warnings = ['FUTURE_WARNING'];
  report.issues![0].pattern = 'future_pattern';
  render(<NetworkAnomalyPanel report={report}/>);
  expect(screen.getByRole('heading', { name: '데이터 부족' })).toBeVisible();
  openCoverage();
  expect(screen.getByText(/원문: FUTURE_WARNING/)).toBeVisible();
  expect(screen.getByText('원문: future_pattern')).toBeVisible();
});
it('preserves unknown producer prose and fact keys as visibly untranslated raw text', () => {
  const report = structuredClone(fixtures.syn_reset);
  report.issues![0].evidence.push('<unknown> future evidence');
  report.issues![0].examples[0].facts = { future_fact: 123 };
  render(<NetworkAnomalyPanel report={report}/>);
  openEvidence();
  expect(screen.getByText('원문: <unknown> future evidence')).toBeVisible();
  openEvidence();
  expect(screen.getByText('원문: future_fact: 123')).toBeVisible();
});
