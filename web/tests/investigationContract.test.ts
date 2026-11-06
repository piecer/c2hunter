import { expect, it } from 'vitest';
import { parseInvestigation, normalizeScope, parsePage } from '../src/investigationContract';
import { fixture } from './investigationFixtures';
import type { InvestigationRun, Evidence } from '../src/investigationTypes';
import schemas from '../src/investigationSchemas.json';
import { producer } from './investigationFixtures';

it('accepts every source-bound producer byte witness before mutations (14 original service + 5 evidence minimum)', () => {
  expect(producer.schemas).toEqual(schemas);
  expect(producer.counts.ai_investigation_service).toBeGreaterThanOrEqual(14);
  expect(producer.counts.ai_investigation).toBe(5);
  expect(Object.keys(producer.fixtures)).toHaveLength(Object.values(producer.counts).reduce((sum, value) => sum + value, 0));
  for (const [path, bytes] of Object.entries(producer.fixtures)) {
    const name = path.split('/')[1];
    const kind = name.startsWith('run_') ? 'InvestigationRun' : name.startsWith('step_') ? 'InvestigationStep'
      : name.startsWith('result_') ? 'InvestigationResult' : name === 'capabilities' ? 'InvestigationCapabilities'
        : name.startsWith('source_preview') ? 'SourcePreview' : 'Evidence';
    expect(parseInvestigation(kind, JSON.parse(bytes))).toEqual(JSON.parse(bytes));
  }
});

it('normalizes IP/time scope explicitly without collapsing microseconds', () => {
  const scope = (fixture('run_queued') as InvestigationRun).scope;
  expect(normalizeScope({ ...scope, target_ip: '2001:0db8:0:0:0:0:0:1', start_time: '2026-01-01T09:00:00.123456+09:00', end_time: '2026-01-01T00:00:01Z' })).toEqual({ ...scope, start_time: '2026-01-01T00:00:00.123456+00:00', end_time: '2026-01-01T00:00:01.000000+00:00' });
  expect(() => normalizeScope({ ...scope, start_time: '2026-02-30T00:00:00Z' })).toThrow();
  expect(() => normalizeScope({ ...scope, start_time: '2026-01-02T00:00:00Z', end_time: '2026-01-01T00:00:00Z' })).toThrow();
});

it('rejects arbitrary extras recursively on real producer nested shapes', () => {
  for (const name of ['run_completed', 'run_failed', 'peer_flow_samples', 'peer_timeline', 'peer_protocol_observations', 'compare_peer_cohort']) {
    const original = fixture(name);
    const kind = name.startsWith('run_') ? 'InvestigationRun' : 'Evidence';
    parseInvestigation(kind, original);
    const paths: (string | number)[][] = [];
    const visit = (value: unknown, path: (string | number)[]) => {
      if (!value || typeof value !== 'object') return;
      if (!Array.isArray(value)) paths.push(path);
      Object.entries(value).forEach(([key, next]) => visit(next, [...path, Array.isArray(value) ? Number(key) : key]));
    };
    visit(original, []);
    for (const path of paths) {
      const mutated = structuredClone(original);
      let target = mutated as Record<string | number, unknown>;
      path.forEach(key => { target = target[key] as Record<string | number, unknown>; });
      target.untrusted_extra = 'not accepted';
      expect(() => parseInvestigation(kind, mutated), `${name}:${path.join('.')}`).toThrow();
    }
  }
});

it.each(['status', 'infinity', 'unsafe', 'negative', 'metric-ref', 'foreign-cite', 'foreign-source', 'scope', 'active-result', 'empty-completed'])('rejects %s mutations after a valid producer control', mutation => {
  const run = parseInvestigation('InvestigationRun', fixture('run_completed'));
  if (!run.result || 'kind' in run.result) throw new Error('fixture');
  if (mutation === 'status') Object.assign(run, { status: 'FINISHED' });
  if (mutation === 'infinity') run.created_at = Infinity;
  if (mutation === 'unsafe') run.progress.source_bytes = Number.MAX_SAFE_INTEGER + 1;
  if (mutation === 'negative') run.result.counts.inspected = -1;
  if (mutation === 'metric-ref') run.result.facts[0].ref = 'javascript:alert(1)';
  if (mutation === 'foreign-cite') run.result.support[0].evidence_ids = ['a'.repeat(64)];
  if (mutation === 'foreign-source') run.result.source.job_id = 'other';
  if (mutation === 'scope') run.scope.target_ip = '10.0.0.3';
  if (mutation === 'active-result') run.status = 'QUEUED';
  if (mutation === 'empty-completed') run.result = null;
  expect(() => parseInvestigation('InvestigationRun', run)).toThrow();
});

it('preserves absent versus null optional source metadata and rejects wrong references', () => {
  const evidence = parseInvestigation('Evidence', fixture('peer_flow_samples')) as Evidence;
  expect(evidence.samples[0].row.tls_fingerprint).toBeNull();
  delete evidence.samples[0].row.tls_fingerprint;
  expect(Object.hasOwn(parseInvestigation('Evidence', evidence).samples[0].row, 'tls_fingerprint')).toBe(false);
  evidence.samples[0].ref.source_sha256 = 'b'.repeat(64);
  expect(() => parseInvestigation('Evidence', evidence)).toThrow();
});

it.each(['   ', '\u0000bad'])('rejects invalid question text %j without treating it as executable markup', question => {
  const run = parseInvestigation('InvestigationRun', fixture('run_queued'));
  expect(() => parseInvestigation('InvestigationRequest', { ...run.request, question })).toThrow();
  expect(parseInvestigation('InvestigationRequest', { ...run.request, question: '<script>not executable</script>' }).question).toBe('<script>not executable</script>');
});

it.each(['missing', 'zero-timeout', 'long-model', 'mismatched-result', 'mismatched-progress'])('rejects captured execution %s after accepting actual producer bytes', mutation => {
  const run = parseInvestigation('InvestigationRun', fixture('run_completed'));
  if (!run.result) throw new Error('fixture');
  if (mutation === 'missing') Reflect.deleteProperty(run, 'execution');
  if (mutation === 'zero-timeout') run.execution.model_settings.timeout_seconds = 0;
  if (mutation === 'long-model') run.execution.model = '한'.repeat(200);
  if (mutation === 'mismatched-result') run.result.execution.model_config_sha256 = 'a'.repeat(64);
  if (mutation === 'mismatched-progress') run.result.progress.model_calls = 0;
  expect(() => parseInvestigation('InvestigationRun', run)).toThrow();
});

it.each(['FAILED', 'CANCELLED', 'COMPLETED'])('rejects a mismatched %s result union cleanly', status => {
  const run = parseInvestigation('InvestigationRun', fixture('run_' + status.toLowerCase()));
  if (status === 'FAILED') {
    // Queue expiry and worker exit are legitimate reason-only FAILED runs.
    expect(parseInvestigation('InvestigationRun', { ...run, result: null, reason: 'QUEUE_EXPIRED' }).result).toBeNull();
    run.result = (fixture('run_completed') as InvestigationRun).result;
    if (run.result) run.progress = run.result.progress;
  }
  if (status === 'CANCELLED') { run.result = (fixture('run_completed') as InvestigationRun).result; if (run.result) run.progress = run.result.progress; }
  if (status === 'COMPLETED') {
    run.result = (fixture('run_failed') as InvestigationRun).result;
    if (run.result) { Reflect.deleteProperty(run.result, 'kind'); run.progress = run.result.progress; }
  }
  expect(() => parseInvestigation('InvestigationRun', run)).toThrow('Invalid investigation response');
});

it('requires actual bounded page cursors and rejects oversized/mismatched prefixes', () => {
  const run = parseInvestigation('InvestigationRun', fixture('run_queued'));
  expect(parsePage('InvestigationRun', { items: [run], next_cursor: run.id }).next_cursor).toBe(run.id);
  expect(() => parsePage('InvestigationRun', { items: [run], next_cursor: 'a'.repeat(64) })).toThrow();
  expect(() => parsePage('InvestigationRun', { items: Array(6).fill(run), next_cursor: null })).toThrow();
  expect(() => parsePage('InvestigationRun', { items: [], next_cursor: run.id })).toThrow();
});
