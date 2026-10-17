import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { isDDoSAttackReport, type DDoSAttackReport } from '../src/ddosReportContract';

const native = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8')) as DDoSAttackReport;
const scenarios = JSON.parse(readFileSync('tests/fixtures/ddos-report-scenarios.json', 'utf8')) as Record<string, DDoSAttackReport>;
const copy = () => structuredClone(native);
function transformTimes(report: DDoSAttackReport, transform: (value: string) => string) {
  for (const item of [report.summary, ...report.findings]) {
    for (const key of ['first_seen', 'last_seen'] as const) {
      if (typeof item[key] === 'string') item[key] = transform(item[key]);
    }
  }
}

it('retains the actual current v4 producer report and every saved scenario', () => {
  expect(isDDoSAttackReport(native)).toBe(true);
  for (const report of Object.values(scenarios)) expect(isDDoSAttackReport(report)).toBe(true);
});
it('rejects a finding starting one microsecond before the report', () => {
  const report = copy();
  report.summary.first_seen = '2026-09-15T00:00:00.000001+00:00';
  expect(isDDoSAttackReport(report)).toBe(false);
});
it('accepts exact fractional containment but rejects one microsecond beyond its end', () => {
  const report = copy();
  report.findings[0].last_seen = '2026-09-15T00:00:27.000789+00:00';
  report.summary.last_seen = report.findings[0].last_seen;
  expect(isDDoSAttackReport(report)).toBe(true);
  report.summary.last_seen = '2026-09-15T00:00:27.000788+00:00';
  expect(isDDoSAttackReport(report)).toBe(false);
});
it('rejects reversed sub-millisecond finding bounds', () => {
  const report = copy();
  report.findings[0].first_seen = '2026-09-15T00:00:00.000002+00:00';
  report.findings[0].last_seen = '2026-09-15T00:00:00.000001+00:00';
  expect(isDDoSAttackReport(report)).toBe(false);
});
it.each(['2026-02-30', '1900-02-29', '2026-04-31', '0000-09-15'])('rejects an invalid calendar date: %s', date => {
  const report = copy();
  transformTimes(report, stamp => date + stamp.slice(10));
  expect(isDDoSAttackReport(report)).toBe(false);
});
it.each(['2024-02-29', '2000-02-29', '1900-02-28', '0001-09-15', '0099-09-15', '9999-09-15', '1969-09-15'])('preserves valid calendar dates: %s', date => {
  const report = copy();
  transformTimes(report, stamp => date + stamp.slice(10));
  expect(isDDoSAttackReport(report)).toBe(true);
});
it.each(['', '.123456'])('rejects timezone-free times with fraction %s', fraction => {
  const report = copy();
  transformTimes(report, stamp => stamp.replace('+00:00', fraction));
  expect(isDDoSAttackReport(report)).toBe(false);
});
it.each(['Z', '+09:00', '-03:30'])('preserves equivalent explicit timezone %s', zone => {
  const report = copy();
  const end = zone === '+09:00' ? '2026-09-15T09:00:27+09:00'
    : zone === '-03:30' ? '2026-09-14T20:30:27-03:30' : '2026-09-15T00:00:27Z';
  report.findings[0].last_seen = end;
  expect(isDDoSAttackReport(report)).toBe(true);
});
it.each(['2026-02-30T00:00:00Z', '2026-09-15T00:00:00', '2026-09-15T24:00:00Z', '2026-09-15T00:60:00Z', '2026-09-15T00:00:60Z', '2026-09-15T00:00:00+24:00'])('rejects invalid summary-only time: %s', stamp => {
  const report = structuredClone(scenarios.insufficient_evidence);
  expect(report.findings).toHaveLength(0);
  report.summary.first_seen = stamp;
  report.summary.last_seen = stamp;
  expect(isDDoSAttackReport(report)).toBe(false);
});
it('rejects reversed summary-only bounds at microsecond precision', () => {
  const report = structuredClone(scenarios.insufficient_evidence);
  report.summary.first_seen = '2026-09-15T00:00:00.000002Z';
  report.summary.last_seen = '2026-09-15T00:00:00.000001Z';
  expect(isDDoSAttackReport(report)).toBe(false);
});
it('retains the no-findings null-summary compatibility', () => {
  const report = structuredClone(scenarios.insufficient_evidence);
  report.summary.first_seen = null;
  report.summary.last_seen = null;
  expect(isDDoSAttackReport(report)).toBe(true);
});
