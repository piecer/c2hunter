import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { ddosSourceSnapshot } from '../src/ddosSourceSnapshot';
import { isDDoSAttackReport, sha256, type DDoSAttackReport } from '../src/ddosReportContract';
import { buildDDoSExport, passiveSelection, type ExportJob } from '../src/ddosExport';
import { canonicalPredicate } from '../src/ddosSignatures';
import { falsePositiveCodes } from '../src/ddosReportTranslations';

const fixture = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_source_limits_fixture.py'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
const report: DDoSAttackReport = fixture.report;
const job: ExportJob = fixture.source;
// Consumer-accepted Cartesian stress shape, deliberately not called producer
// output: the producer can publish fewer patterns/signatures than the decoder.
function maximalReport(longValues = true): DDoSAttackReport {
  const value = structuredClone(report);
  const corpus: { report: DDoSAttackReport; accepted: boolean }[] = JSON.parse(readFileSync('tests/fixtures/ddos-signature-corpus.json', 'utf8'));
  const measured = corpus.find(row => row.accepted && row.report.normal_reference !== null && row.report.normal_reference !== undefined)!.report;
  const normal = structuredClone(measured.findings[0].signature_candidates![0].evaluation!.normal);
  Object.assign(normal.reference!, { job_id: 'j'.repeat(200), dataset_id: 'd'.repeat(200), selected_by: 'u'.repeat(128), selected_at: 't'.repeat(64) });
  value.normal_reference = normal.reference;
  for (const finding of value.findings) {
    finding.common_patterns = Array.from({ length: 8 }, () => ({ ...finding.common_patterns![0], values: Array(16).fill(longValues ? '\u0000'.repeat(128) : '') }));
    const signature = finding.signature_candidates![0];
    signature.evaluation!.normal = normal;
    signature.source_ports = Array.from({ length: 16 }, (_, i) => i);
    signature.evaluation!.predicate.source_ports = signature.source_ports;
    signature.id = `ddos-sig-${sha256(canonicalPredicate(signature.evaluation!.predicate)).slice(0, 16)}`;
    finding.signature_candidates = Array.from({ length: 4 }, () => structuredClone(signature));
  }
  return value;
}

it.each([true, false])('keeps accepted report aggregate maxima (long strings %s) independent of export limits', longValues => {
  const value = maximalReport(longValues);
  expect(isDDoSAttackReport(value)).toBe(true);
  const snapshot = ddosSourceSnapshot(value, job);
  expect(snapshot).not.toBeNull();
  expect(JSON.parse(snapshot!).findings).toEqual(value.findings);
  if (longValues) expect(buildDDoSExport(value, value.findings[0].id, value.findings[0].signature_candidates![0].id, { id: 'j', dataset_id: 'd' }, () => true)).toBeNull();
});

it('admits maximum legacy signature arrays without applying v4-only restrictions', () => {
  const value = maximalReport();
  value.version = 'ddos-attack-report-v3'; value.catalog_version = 'ddos-taxonomy-v3';
  delete value.normal_reference;
  for (const finding of value.findings) for (const signature of finding.signature_candidates!) {
    delete signature.evaluation;
    signature.destination_ports = Array.from({ length: 16 }, (_, i) => i);
    signature.packet_size_range = [0, 65535];
    signature.payload_prefix_hashes = Array(8).fill('f'.repeat(64));
    signature.false_positive_codes = Object.keys(falsePositiveCodes).slice(0, 4);
  }
  expect(isDDoSAttackReport(value)).toBe(true);
  expect(ddosSourceSnapshot(value, job)).not.toBeNull();
});

it.each(['v1', 'v2', 'v3', 'v4'])('retains established %s optional-absence and legacy shapes', version => {
  const value = JSON.parse(readFileSync(`tests/fixtures/ddos-report-contract${version === 'v4' ? '' : '-' + version}.json`, 'utf8'));
  if (version !== 'v4') expect(Object.hasOwn(value, 'normal_reference')).toBe(false);
  expect(isDDoSAttackReport(value)).toBe(true);
  expect(ddosSourceSnapshot(value)).not.toBeNull();
  expect(ddosSourceSnapshot(value, { id: 'only-id' })).not.toBeNull();
  if (version === 'v1' || version === 'v2') {
    value.findings[0].metrics.measurement_precision = [value.findings[0].metrics.measurement_precision];
    expect(isDDoSAttackReport(value)).toBe(true);
    expect(ddosSourceSnapshot(value, { id: 'legacy-coercion' })).not.toBeNull();
  }
});

it.each(['networks', 'links', 'findings', 'characters', 'keys', 'depth', 'nodes', 'null', 'nonfinite'])(
  'rejects bounded malformed %s before semantic serialization', kind => {
    const value = structuredClone(report), source = structuredClone(job);
    if (kind === 'networks') source.internal_networks!.push('10.0.0.0/8');
    if (kind === 'links') source.source!.link_types!.push(65536);
    if (kind === 'findings') value.findings.push(value.findings[0]);
    if (kind === 'characters') source.id = 'x'.repeat(40000);
    if (kind === 'keys') value.summary = Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['key' + i, 0]));
    if (kind === 'depth') { let nested: unknown = 0; for (let i = 0; i < 12000; i++) nested = { nested }; value.summary.first_seen = nested; }
    if (kind === 'nodes') value.summary.first_seen = Array.from({ length: 100 }, () => Array.from({ length: 100 }, () => Array(100).fill(0)));
    if (kind === 'nonfinite') value.summary.packet_count = Infinity;
    const stringify = vi.spyOn(JSON, 'stringify');
    expect(ddosSourceSnapshot(kind === 'null' ? null : value, source)).toBeNull();
    expect(stringify).not.toHaveBeenCalled();
  },
);

it('admits the actual parser full link census independently of passive-export restrictions', () => {
  expect(job.source!.link_types).toHaveLength(65536);
  expect(isDDoSAttackReport(report)).toBe(true);
  const ordinaryTopology = { ...job, internal_networks: fixture.long_ipv6 };
  expect(ddosSourceSnapshot(report, ordinaryTopology)).not.toBeNull();
  expect(passiveSelection(report.findings[0].signature_candidates![0].evaluation!.predicate, ordinaryTopology).status).toBe('REFUSED');
});

it('preserves normalized 64-code-point scoped networks with combined maximum source fields', () => {
  expect(job.internal_networks).toHaveLength(256);
  expect(job.internal_networks!.every(n => n.length === 124)).toBe(true);
  const oneLink = { ...job, source: { ...job.source, link_types: [101] } };
  const snapshot = ddosSourceSnapshot(report, oneLink);
  expect(snapshot).not.toBeNull();
  expect(JSON.parse(snapshot!).source).toEqual(oneLink);
  const combined = ddosSourceSnapshot(report, job);
  expect(combined).not.toBeNull();
  expect(JSON.parse(combined!).source).toEqual(job);
});
