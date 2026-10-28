import { parseNumericRun, currentNumericSource } from './networkNumericEvidence';
import { createContext, useContext } from 'react';
import { patterns } from './reportTranslations';
import { projectNetworkReport, record, safeCount } from './networkReportValidation';
import { parseMeasurementQuality } from './networkMeasurementQuality';
export type NetworkEvidenceJob = { id: string; dataset_id?: string; status: string };
export type EvidenceRun = { id: string; analysis_job_id?: string; dataset_id?: string; analysis_kind: string; status: string; network_input?: unknown };
export type EvidenceContext = {
  job?: NetworkEvidenceJob;
  projection: ReturnType<typeof projectNetworkReport>;
  generation: object;
  current: () => boolean;
  selection?: { index: number };
  navigate: (index: number) => void;
};
export const NetworkEvidenceContext = createContext<EvidenceContext | undefined>(undefined);
export const useNetworkEvidence = () => useContext(NetworkEvidenceContext);
// A local change detector for the bounded fields this screen consumes, NOT a
// report digest or proof of arbitrary stored bytes. Completed jobs are immutable
// in the supported API; remounting establishes a new local observation baseline.
export function evidenceSignature(projection: EvidenceContext['projection']): string {
  const scalar = (v: unknown) => typeof v === 'string' ? v.slice(0, 2000) : typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'boolean' || v === null ? v : null;
  const fields = (v: unknown, keys: readonly string[]) => keys.map(k => scalar(record(v)?.[k]));
  const notes = (v: unknown, limit: number) => Array.isArray(v) ? v.slice(0, limit).map(scalar) : null;
  const stats = (v: unknown) => fields(v, ['count', 'mean', 'min', 'max', 'stddev', 'changes', 'missing']);
  const measurement = (v: unknown) => {
    const m = record(v);
    // Share the renderer's atomic qualification semantics, including absence and
    // closed-shape rejection. Only its validated, bounded result is serialized.
    return [parseMeasurementQuality(m), fields(m, ['status', 'coverage_complete']), notes(m?.reasons, 7), Array.isArray(m?.reasons) && m.reasons.length > 7, stats(m?.observed_rtt_ms), fields(m?.rtt_sources, ['syn_ack', 'data_ack']), fields(m?.rtt_excluded, ['ambiguous', 'nonpositive_time', 'nonexact_ack']), ...['interarrival_variation_ms', 'ttl_observed'].map(k => ['a_to_b', 'b_to_a'].map(d => stats(record(m?.[k])?.[d])))];
  };
  return JSON.stringify([projection.familyCoverage, projection.version, projection.measurementVersion, fields(projection.summary, ['narrative']), fields(projection.summary.suspected_cause, ['code', 'confidence']), projection.summaryTrusted, projection.issueLimit, projection.warningLimit, fields(projection.summary, ['verdict', 'scanned_records', 'evaluated_records', 'skipped_records', 'incomplete_records', 'flow_count', 'suspect_flow_count', 'detailed_flow_count', 'issue_count', 'displayed_issue_count', 'omitted_issue_count', 'coverage_complete', 'truncated', 'tracking_limited_records', 'counts_are_lower_bounds']), [...projection.knownWarnings], projection.unsupportedWarnings, projection.limitations, [...projection.ids], projection.slots.map(s => {
    const i = s.issue;
    return [s.index, s.invalid, s.examplesInvalid, s.examplesExceeded, s.notesMissing, i && [i.id, i.pattern, i.severity, i.scope, i.event_count, i.affected_flow_count, i.affected_host_count, i.omitted_examples, i.first_seen, i.last_seen, i.evidence, i.uncertainty, i.next_checks, fields(i.suspected_cause, ['code', 'confidence']), i.examples.map(e => [e.endpoint_a, e.endpoint_b, e.event_count, e.facts, e.icmpDetails, measurement(e.measurements)])]];
  })]);
}
export function citationTarget(context: EvidenceContext | undefined, run: EvidenceRun | undefined, selectedId: string | undefined, id: string): { index?: number; reason?: 'source' | 'input' | 'ambiguous' } {
  if (!context?.current() || !context.job || !run || run.id !== selectedId || run.analysis_job_id !== context.job.id || context.job.status !== 'COMPLETED' || run.status !== 'COMPLETED' || run.analysis_kind !== 'NETWORK_ANOMALY' || (run.dataset_id !== undefined && context.job.dataset_id !== undefined && run.dataset_id !== context.job.dataset_id)) return { reason: 'source' };
  const input = record(run.network_input);
  if (input?.schema_version === 'network-ai-input-v2') {
    const parsed = parseNumericRun(run);
    if (!parsed || !currentNumericSource(context, run, selectedId, parsed)) return { reason: 'source' };
    if (!(parsed.input.issues as { id: string }[]).some(i => i.id === id)) return { reason: 'input' };
    const slot = context.projection.slots.find(s => s.issue?.id === id);
    return slot ? { index: slot.index } : { reason: 'source' };
  }
  if (input?.schema_version !== 'network-ai-input-v1' || !Array.isArray(input.issues) || input.issues.length > 20) return { reason: 'source' };
  const items = new Map<string, Record<string, unknown>>();
  for (const raw of input.issues) {
    const i = record(raw);
    if (!i || typeof i.id !== 'string' || !i.id.length || i.id.length > 100 || items.has(i.id) || typeof i.pattern !== 'string' || !Object.hasOwn(patterns, i.pattern) || !['event_count', 'affected_flow_count', 'affected_host_count'].every(k => safeCount(i[k])) || !['first_seen', 'last_seen'].every(k => typeof i[k] === 'string' && (i[k] as string).length <= 64)) return { reason: 'source' };
    items.set(i.id, i);
  }
  const source = items.get(id);
  if (!source) return { reason: 'input' };
  if (context.projection.ids.get(id) !== 1) return { reason: 'ambiguous' };
  const slot = context.projection.slots.find(s => s.issue?.id === id);
  if (slot && slot.index >= 20) return { reason: 'input' };
  if (!slot?.issue || slot.invalid || !['pattern', 'event_count', 'affected_flow_count', 'affected_host_count', 'first_seen', 'last_seen'].every(k => source[k] === slot.issue![k as keyof typeof slot.issue])) return { reason: 'source' };
  return { index: slot.index };
}
