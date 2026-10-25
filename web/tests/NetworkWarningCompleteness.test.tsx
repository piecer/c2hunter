import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import NetworkAnomalyPanel, { type NetworkAnomalyReport } from '../src/NetworkAnomalyPanel';
import { warningLabel, warnings as registry } from '../src/reportTranslations';

const python = process.env.C2HUNTER_PYTHON ?? process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python');
const witness = JSON.parse(execFileSync(python, ['tests/network_warning_fixture.py'], { encoding: 'utf8' })) as { report: NetworkAnomalyReport; origins: Record<string, string> };
const originalCodes = [
  'CORRELATION_LIMIT_REACHED', 'FLOW_TRACKING_LIMIT_REACHED', 'ICMP_QUOTE_LIMIT_REACHED',
  'INCOMPLETE_ICMP_QUOTE', 'INCOMPLETE_PACKET_EVIDENCE', 'INCOMPLETE_RECORDS',
  'NON_MONOTONIC_TIMESTAMPS', 'OBSERVATION_LIMIT_REACHED', 'ONE_DIRECTION_OBSERVED',
];

it.each(['en', 'ko'] as const)('exposes every real producer warning in %s while retaining positive findings and lazy bounds', language => {
  expect(witness.report.warnings).toEqual(originalCodes);
  expect(Object.keys(witness.origins)).toContain('c2hunter_analysis.network_report');
  localStorage.setItem('c2hunter-report-language', language);
  const { container } = render(<NetworkAnomalyPanel report={witness.report}/>);
  expect(screen.getByRole('heading', { name: language === 'en' ? 'Anomaly observed' : '이상 징후 관찰됨' })).toBeVisible();
  expect(container.querySelector('#network-coverage')).toBeNull();
  expect(screen.queryByRole('article')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: language === 'en' ? 'Coverage details and limitations' : '분석 범위 상세 및 한계' }));
  const coverage = screen.getByRole('region', { name: language === 'en' ? 'Analysis coverage' : '분석 범위' });
  for (const code of originalCodes) expect(within(coverage).getByText(warningLabel(language, code))).toBeVisible();
  expect(within(coverage).queryByText(/additional coverage warnings omitted|추가 분석 범위 경고/)).not.toBeInTheDocument();
  expect(container.querySelectorAll('*').length).toBeLessThan(140 + Object.keys(registry).length);
});

it.each(['en', 'ko'] as const)('keeps all registered warnings unique and bounded despite unknown/duplicate input in %s', language => {
  localStorage.setItem('c2hunter-report-language', language);
  const codes = Object.keys(registry);
  // Unsupported input must not crowd out a recognized warning or make it clear.
  const warnings = [...Array.from({ length: 1000 }, (_, index) => `UNKNOWN_${index}`), '__proto__', 'constructor', ...codes, ...codes];
  const { container } = render(<NetworkAnomalyPanel report={{ ...witness.report, warnings }}/>);
  expect(screen.getByRole('heading', { name: language === 'en' ? 'Insufficient data' : '데이터 부족' })).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: language === 'en' ? 'Coverage details and limitations' : '분석 범위 상세 및 한계' }));
  const coverage = screen.getByRole('region', { name: language === 'en' ? 'Analysis coverage' : '분석 범위' });
  for (const code of codes) expect(within(coverage).getAllByText(warningLabel(language, code))).toHaveLength(1);
  expect(within(coverage).getByText(/Unsupported coverage warning|지원하지 않는 분석 범위 경고/)).toBeVisible();
  expect(coverage.querySelector('ul')!.children).toHaveLength(codes.length + 2);
  expect(container.querySelectorAll('*').length).toBeLessThan(140 + codes.length);
});
