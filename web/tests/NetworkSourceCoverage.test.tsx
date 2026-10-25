import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { render, screen } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import NetworkAnomalyPanel from '../src/NetworkAnomalyPanel';
import { warningLabel } from '../src/reportTranslations';
import { openCoverage } from './reportDisclosure';

const python = process.env.C2HUNTER_TEST_PYTHON || resolve('../.venv/bin/python');
const wire = JSON.parse(execFileSync(python, ['tests/network_source_coverage_fixture.py'], { encoding: 'utf8' }));
const codes = ['PARSER_SKIPPED_PACKETS', 'CAPTURE_PACKET_LIMIT_REACHED', 'SENSOR_DROPS_REPORTED', 'SENSOR_CLOCK_SKEW', 'PARTIAL_CAPTURE', 'SENSOR_CAPTURE_QUALITY_UNAVAILABLE'];
beforeEach(() => localStorage.setItem('c2hunter-report-language', 'en'));

it.each(['en', 'ko'] as const)('renders every upstream qualifier without discarding genuine findings (%s)', language => {
  localStorage.setItem('c2hunter-report-language', language);
  const { report, ai } = wire.cases.positive_partial;
  expect(new Set(report.warnings)).toEqual(new Set(codes));
  expect(ai.warnings).toEqual(report.warnings);
  expect(ai.summary.coverage_complete).toBe(false);
  render(<NetworkAnomalyPanel report={report} />);
  expect(screen.getByRole('heading', { name: language === 'en' ? 'Anomaly observed' : '이상 징후 관찰됨' })).toBeVisible();
  openCoverage();
  for (const code of codes) {
    expect(screen.getByText(warningLabel(language, code))).toBeVisible();
    expect(warningLabel(language, code)).not.toMatch(/Unsupported|지원하지 않는/);
  }
});

it('does not describe a quiet retained prefix as a complete capture', () => {
  render(<NetworkAnomalyPanel report={wire.cases.quiet_partial.report} />);
  expect(screen.getByRole('heading', { name: 'Insufficient data' })).toBeVisible();
  expect(screen.queryByText('No clear anomaly observed')).not.toBeInTheDocument();
});

it('preserves the native no-omission control', () => {
  render(<NetworkAnomalyPanel report={wire.cases.normal.report} />);
  expect(screen.getByRole('heading', { name: 'No clear anomaly observed' })).toBeVisible();
});
