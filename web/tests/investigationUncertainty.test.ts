import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, it, vi } from 'vitest';
import { parseInvestigation } from '../src/investigationContract';
import { investigationApi } from '../src/investigationApi';
import { fixture, freshFixture, producer } from './investigationFixtures';

const expectedProducerRoot = resolve(process.env.C2HUNTER_INVESTIGATION_PRODUCER_ROOT
  ?? resolve(dirname(fileURLToPath(import.meta.url)), '../..'));

it('keeps sealed 19+5 membership separate from fresh socket-free producer witnesses and verifies nested origins', () => {
  expect(producer.counts).toEqual({ ai_investigation_service: 19, ai_investigation: 5 });
  expect(Object.keys(producer.fixtures)).toHaveLength(24);
  expect(producer.isolated).toBe(1);
  expect(producer.additional.mode).toBe('FRESH_IN_MEMORY_SCRIPTED_ACTIONS_NO_HTTP_NO_INFERENCE');
  for (const origin of Object.values(producer.origins)) expect(origin.startsWith(expectedProducerRoot + '/')).toBe(true);
  for (const name of ['ai_investigation', 'ai_investigation_http', 'ai_investigation_evidence', 'repositories', 'schemas']) {
    expect(producer.origins['c2hunter_controller.' + name]).toBeTruthy();
  }
  for (const [name, raw] of Object.entries(producer.additional.fixtures)) {
    if (name.startsWith('error_')) continue;
    const kind = name.startsWith('preview_') ? 'SourcePreview' : name.startsWith('run_') ? 'InvestigationRun' : name.startsWith('result_') ? 'InvestigationResult' : 'Evidence';
    expect(parseInvestigation(kind, JSON.parse(raw))).toEqual(JSON.parse(raw));
  }
});

it.each([
  ['source_preview', 'OBSERVED', false], ['source_preview_unavailable', 'UNAVAILABLE', false],
  ['source_preview_partial', 'NOT_FOUND_IN_INSPECTED_SCOPE', false], ['preview_absent', 'NOT_OBSERVED', true],
] as const)('accepts actual API producer bytes for %s (%s)', async (name, status, fresh) => {
  const raw = fresh ? producer.additional.fixtures[name] : producer.fixtures['ai_investigation_service/' + name];
  const expected = JSON.parse(raw);
  vi.stubGlobal('fetch', vi.fn(async () => new Response(raw, { headers: { 'content-type': 'application/json' } })));
  expect((await investigationApi.preview('job', expected.scope, new AbortController().signal)).status).toBe(status);
});

it('preserves known mixed rows separately from uncertain eligibility and never fabricates exact totals', () => {
  const preview = parseInvestigation('SourcePreview', freshFixture('preview_mixed'));
  expect(preview.status).toBe('OBSERVED');
  expect(preview.counts).toMatchObject({ inspected: 2, matched: 1, scope_unavailable: 1, not_observed: 0 });
  const evidence = parseInvestigation('Evidence', freshFixture('mixed_peer_flow_samples'));
  expect(evidence.samples).toHaveLength(1);
  expect(evidence.samples[0].row.total_bytes).toBe(0);
  for (const name of ['matched_rows', 'total_bytes', 'packet_count', 'sensor_count', 'outbound_rows']) {
    expect(evidence.metrics.find(m => m.name === name)).toMatchObject({ value: null, observed_rows: 1, unavailable_rows: 1 });
  }
  const zero = parseInvestigation('Evidence', freshFixture('zero_peer_overview'));
  expect(zero.metrics.find(m => m.name === 'total_bytes')).toMatchObject({ value: 0, unavailable_rows: 0 });
  const absent = parseInvestigation('Evidence', freshFixture('absent_peer_overview'));
  expect(absent.metrics.every(m => m.value === 0 && m.unavailable_rows === 0)).toBe(true);
});

it('counts excluded cohort inputs as rows, not peers, retaining known comparisons', () => {
  const evidence = parseInvestigation('Evidence', freshFixture('cohort_compare_peer_cohort'));
  expect(evidence.status).toBe('OBSERVED');
  expect(evidence.cohort_unavailable_rows).toBe(1);
  expect(evidence.cohort_total).toBe(3);
  expect(evidence.cohort_total).toBe(evidence.cohort.length + evidence.cohort_omitted);
  expect(evidence.cohort.some(p => p.ip === '10.0.0.3')).toBe(false);
  expect(evidence.limitations).toContain('SOURCE_FIELDS_UNAVAILABLE');
});

const malformed = [undefined, null, true, false, -1, 8193, 0.5, '1', {}, Infinity, NaN] as const;
it.each(malformed)('rejects malformed/missing uncertainty counters %j on actual producer controls', bad => {
  for (const name of ['mixed_peer_overview', 'cohort_compare_peer_cohort']) {
    for (const field of ['scope_unavailable', 'cohort_unavailable_rows']) {
      const evidence = parseInvestigation('Evidence', freshFixture(name));
      const target = field === 'scope_unavailable' ? evidence.counts : evidence;
      if (bad === undefined) Reflect.deleteProperty(target, field);
      else Object.assign(target, { [field]: bad });
      expect(() => parseInvestigation('Evidence', evidence), `${name}:${field}`).toThrow();
    }
  }
});

it.each(['preview', 'result', 'quality', 'run-quality'])('rejects missing uncertainty at %s without defaulting to zero', placement => {
  const kind = placement === 'preview' ? 'SourcePreview' : placement === 'run-quality' ? 'InvestigationRun' : 'InvestigationResult';
  const value = JSON.parse(producer.additional.fixtures[placement === 'preview' ? 'preview_mixed' : placement === 'run-quality' ? 'run_mixed' : 'result_mixed']);
  parseInvestigation(kind, value);
  const counts = placement === 'quality' ? value.evidence_quality[0].counts : placement === 'run-quality' ? value.result.evidence_quality[0].counts : value.counts;
  delete counts.scope_unavailable;
  expect(() => parseInvestigation(kind, value)).toThrow();
});

it.each(['inspected', 'matched', 'cohort_total', 'cohort_as_peers', 'unknown-key', 'exact-zero'])('rejects contradictory %s after a positive real witness', mutation => {
  const evidence = parseInvestigation('Evidence', freshFixture(mutation === 'exact-zero' ? 'mixed_peer_overview' : 'cohort_compare_peer_cohort'));
  if (mutation === 'inspected') evidence.counts.inspected += 1;
  if (mutation === 'matched') { evidence.counts.matched += 1; evidence.counts.inspected += 1; }
  if (mutation === 'cohort_total') evidence.cohort_total += 2;
  if (mutation === 'cohort_as_peers') evidence.cohort_total += evidence.cohort_unavailable_rows;
  if (mutation === 'unknown-key') Object.assign(evidence.counts, { unknown_scope: 0 });
  if (mutation === 'exact-zero') evidence.metrics[0].value = 0;
  expect(() => parseInvestigation('Evidence', evidence)).toThrow();
});

it('rejects missing cohort arrays with the contract error rather than a renderer exception', () => {
  const evidence = parseInvestigation('Evidence', freshFixture('cohort_compare_peer_cohort'));
  Reflect.deleteProperty(evidence, 'cohort');
  expect(() => parseInvestigation('Evidence', evidence)).toThrow('Invalid investigation response');
});

it('retains TraceResult quality counts and aggregate limitations without inventing Quality fields', () => {
  const mixed = parseInvestigation('InvestigationResult', freshFixture('result_mixed'));
  expect(mixed.counts.scope_unavailable).toBe(1);
  expect(mixed.evidence_quality.every(q => q.counts.scope_unavailable === 1)).toBe(true);
  expect(mixed.facts[0].value).toBeNull();
  for (const name of ['mixed', 'cohort']) {
    const result = parseInvestigation('InvestigationResult', freshFixture('result_' + name));
    expect(result.limitations).toContain('SOURCE_FIELDS_UNAVAILABLE');
    expect(result.evidence_quality.every(q => Object.keys(q).sort().join(',') === 'counts,evidence_id,status,tool')).toBe(true);
    Object.assign(result.evidence_quality[0], { cohort_unavailable_rows: 1 });
    expect(() => parseInvestigation('InvestigationResult', result)).toThrow();
  }
  expect(parseInvestigation('SourcePreview', fixture('source_preview')).counts.scope_unavailable).toBe(0);
});
