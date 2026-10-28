// Closed v2 consumer. Integer observations remain decimal strings / BigInt.
import type { EvidenceContext, EvidenceRun } from './networkEvidenceContext';
import { patterns } from './reportTranslations';
export type Obj = Record<string, unknown>;
export type NumericRun = EvidenceRun & { network_interpretation?: unknown; network_numeric_evidence?: unknown };
export type NumericRow = { section: string; item_index: number | null; reference_index: number; reference: Obj; value: string; unit: string; qualifiers: Obj };
export type NumericResult = { input: Obj; output: Obj; rows: NumericRow[] };
const fail = (): never => { throw new Error('Invalid numeric evidence'); };
const countMax = 9223372036854775807n;
export const summaryFields = ['scanned_records', 'skipped_records', 'evaluated_records', 'incomplete_records', 'tracking_limited_records', 'flow_count', 'suspect_flow_count', 'detailed_flow_count', 'issue_count', 'displayed_issue_count', 'omitted_issue_count'];
const issueFields = ['event_count', 'affected_flow_count', 'affected_host_count'];
const maxima: Record<string, bigint> = { tcp_sequence: 4294967295n, tcp_acknowledgment: 4294967295n, tcp_window: 65535n, transport_payload_length: 4294967295n, icmp_type: 255n, icmp_code: 255n };
const directions = ['a_to_b', 'b_to_a'];
const gaps = ['INCOMPLETE_PACKET_EVIDENCE', 'NON_MONOTONIC_TIMESTAMPS', 'CORRELATION_LIMIT_REACHED'];
const reasons = [...gaps, 'MISSING_TTL', 'NO_UNAMBIGUOUS_RTT', 'NOT_TCP', 'ONE_DIRECTION_OBSERVED'];
export function object(v: unknown): Obj {
  if (!v || typeof v !== 'object' || Array.isArray(v) || ![Object.prototype, null].includes(Object.getPrototypeOf(v))) return fail();
  const keys = Reflect.ownKeys(v);
  if (keys.length > 64 || keys.some(k => typeof k !== 'string' || !Object.getOwnPropertyDescriptor(v, k)?.enumerable || !Object.hasOwn(Object.getOwnPropertyDescriptor(v, k)!, 'value'))) return fail();
  return v as Obj;
}
function closed(v: unknown, keys: string[], optional: string[] = []): Obj {
  const o = object(v);
  if (keys.some(k => !Object.hasOwn(o, k)) || Object.keys(o).some(k => !keys.includes(k) && !optional.includes(k))) return fail();
  return o;
}
// Only absence of a declared optional field supplies the empty default.
// Validate the owner first: an accessor is never an absent data property.
function issueList(owner: Obj, key: string, max: number): unknown[] {
  const o = object(owner);
  const optional = key === 'observed_measurements' || key === 'detailed_analysis';
  return list(optional && !Object.hasOwn(o, key) ? [] : o[key], max);
}
function list(v: unknown, max: number): unknown[] {
  if (!Array.isArray(v) || Object.getPrototypeOf(v) !== Array.prototype || v.length > max || Reflect.ownKeys(v).length !== v.length + 1) return fail();
  for (let i = 0; i < v.length; i++) if (!Object.hasOwn(Object.getOwnPropertyDescriptor(v, String(i)) ?? {}, 'value')) return fail();
  return v;
}
export function scalar(v: unknown, max: number, min = 0): string {
  if (typeof v !== 'string' || v.length > max * 2) return fail();
  let n = 0;
  for (const c of v) { const p = c.codePointAt(0)!; if (p >= 0xd800 && p <= 0xdfff || ++n > max) return fail(); }
  return n >= min ? v : fail();
}
function dec(v: unknown, max = countMax): bigint {
  if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(v)) return fail();
  const n = BigInt(v); return n <= max ? n : fail();
}
function small(v: unknown, max = Number.MAX_SAFE_INTEGER): number { return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max ? v : fail(); }
function bool(v: unknown): boolean { return typeof v === 'boolean' ? v : fail(); }
function finite(v: unknown): number { return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : fail(); }
function texts(v: unknown, max: number, length = 400, min = 0): string[] { return list(v, max).map(x => scalar(x, length, min)); }
// Stable structural comparison only; not a Python-canonical digest claim.
function stable(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stable((v as Obj)[k])).join(',') + '}';
}
function bounded(v: unknown, budget: number): void {
  let left = budget;
  const visit = (x: unknown, depth: number) => {
    if (--left < 0 || depth > 16) fail();
    if (typeof x === 'string') { scalar(x, budget); left -= [...x].length; }
    else if (Array.isArray(x)) for (const c of list(x, 100)) visit(c, depth + 1);
    else if (x && typeof x === 'object') for (const c of Object.values(object(x))) visit(c, depth + 1);
    else if (typeof x === 'number' ? !Number.isFinite(x) : x !== null && typeof x !== 'boolean') fail();
    if (left < 0) fail();
  }; visit(v, 0);
}
function quality(n: bigint, rtt: boolean, handshake: boolean, selected: boolean): Obj {
  const rs = n === 0n ? ['NO_SAMPLES'] : n === 1n ? ['SINGLE_SAMPLE'] : [];
  if (handshake) rs.push('HANDSHAKE_ONLY'); if (rtt) rs.push('BIDIRECTIONAL_RTT_NOT_ESTABLISHED'); if (selected) rs.push('SELECTION_BIAS_POSSIBLE');
  return { status: n === 0n ? 'unavailable' : n === 1n ? 'limited_samples' : 'observed_samples', reasons: rs };
}
function stats(v: unknown, ttl = false): Obj {
  const s = closed(v, ttl ? ['count', 'min', 'max', 'changes', 'missing'] : ['count', 'min', 'max', 'mean', 'stddev']);
  const n = dec(s.count);
  if (ttl) {
    const changes = dec(s.changes); dec(s.missing);
    if (changes > (n > 0n ? n - 1n : 0n)) fail();
    if (n === 0n) { if (s.min !== null || s.max !== null) fail(); }
    else if (dec(s.min, 255n) > dec(s.max, 255n)) fail();
  } else if (n === 0n) { if (['min', 'max', 'mean', 'stddev'].some(k => s[k] !== null)) fail(); }
  else {
    if (finite(s.min) > finite(s.mean) || finite(s.mean) > finite(s.max)) fail();
    if (n === 1n) { if (s.stddev !== null && s.stddev !== 0) fail(); } else finite(s.stddev);
  }
  return s;
}
function measurement(v: unknown): Obj {
  const m = closed(v, ['observed_rtt_ms', 'rtt_sources', 'rtt_excluded', 'interarrival_variation_ms', 'ttl_observed', 'coverage_complete', 'status', 'reasons'], ['metric_quality']);
  bool(m.coverage_complete); if (!['observed', 'insufficient_evidence', 'unsupported'].includes(String(m.status))) fail();
  const rs = texts(m.reasons, 7); if (rs.some(r => !reasons.includes(r))) fail();
  const selected = rs.some(r => gaps.includes(r));
  const sources = closed(m.rtt_sources, ['syn_ack', 'data_ack']), excluded = closed(m.rtt_excluded, ['ambiguous', 'nonpositive_time', 'nonexact_ack']);
  const syn = dec(sources.syn_ack), data = dec(sources.data_ack), excludedCounts = Object.values(excluded).map(x => dec(x));
  const rtt = stats(m.observed_rtt_ms); if (dec(rtt.count) !== syn + data) fail();
  const expected: Obj = { observed_rtt_ms: quality(dec(rtt.count), true, syn > 0n && data === 0n, selected || excludedCounts.some(n => n > 0n)) };
  for (const key of ['interarrival_variation_ms', 'ttl_observed']) {
    const metrics = closed(m[key], directions), q: Obj = {};
    for (const d of directions) { const s = stats(metrics[d], key === 'ttl_observed'); q[d] = quality(dec(s.count), false, false, selected || key === 'ttl_observed' && dec(s.missing) > 0n); }
    expected[key] = q;
  }
  if (Object.hasOwn(m, 'metric_quality') && stable(m.metric_quality) !== stable(expected)) fail();
  return m;
}
// Producer measurement statistics are floats even when integral. Account for
// Python's .0 and exponent spelling without converting observation strings.
// This is a byte-admission encoder, never a digest/authentication comparison.
function inputBytes(v: unknown): number {
  const encode = (x: unknown, floating = false): string => {
    if (typeof x === 'number' && floating) {
      if (Object.is(x, -0)) return '-0.0';
      if (x !== 0 && (Math.abs(x) < 1e-4 || Math.abs(x) >= 1e16)) {
        const [mantissa, exponent] = x.toExponential().split('e');
        const n = Number(exponent);
        return mantissa + 'e' + (n < 0 ? '-' : '+') + String(Math.abs(n)).padStart(2, '0');
      }
      return String(x) + (Number.isInteger(x) ? '.0' : '');
    }
    if (Array.isArray(x)) return '[' + x.map(c => encode(c)).join(',') + ']';
    if (x && typeof x === 'object') {
      const o = x as Obj, stats = Object.hasOwn(o, 'count') && Object.hasOwn(o, 'mean');
      return '{' + Object.keys(o).map(k => JSON.stringify(k) + ':' + encode(o[k], stats && ['min', 'max', 'mean', 'stddev'].includes(k))).join(',') + '}';
    }
    return JSON.stringify(x);
  };
  return new TextEncoder().encode(encode(v)).length;
}
function input(v: unknown): Obj {
  bounded(v, 24000);
  if (inputBytes(v) > 24000) fail();
  const b = closed(v, ['schema_version', 'language', 'summary', 'issues', 'warnings', 'limitations', 'omitted_input_issues', 'input_detail_counts', 'projection_notice']);
  if (b.schema_version !== 'network-ai-input-v2' || !['ko', 'en'].includes(String(b.language))) fail();
  const s = closed(b.summary, [...summaryFields, 'coverage_complete', 'counts_are_lower_bounds', 'truncated', 'verdict'], ['suspected_cause']);
  const n = Object.fromEntries(summaryFields.map(k => [k, dec(s[k])]));
  for (const k of ['coverage_complete', 'counts_are_lower_bounds', 'truncated']) bool(s[k]);
  if (!['anomaly_observed', 'no_clear_anomaly', 'insufficient_evidence'].includes(String(s.verdict)) || n.scanned_records !== n.skipped_records + n.evaluated_records + n.incomplete_records || n.issue_count !== n.displayed_issue_count + n.omitted_issue_count || n.detailed_flow_count > n.suspect_flow_count || n.suspect_flow_count > n.flow_count || n.flow_count > n.scanned_records || n.tracking_limited_records > n.incomplete_records || n.tracking_limited_records > 0n && (!s.counts_are_lower_bounds || !s.truncated)) fail();
  const cause = (v: unknown) => { const c = closed(v, ['code', 'confidence', 'summary']); if (!['response_visibility_or_filtering', 'service_refusal_or_policy', 'loss_reordering_or_capture_duplication', 'application_repeat_or_capture_duplication', 'reported_network_or_policy_error'].includes(String(c.code)) || c.confidence !== 'low') fail(); scalar(c.summary, 400); };
  if (s.suspected_cause !== undefined && s.suspected_cause !== null) cause(s.suspected_cause);
  texts(b.warnings, 20); texts(b.limitations, 4); scalar(b.projection_notice, 2000);
  const issues = list(b.issues, 20), seen = new Set();
  const detail = closed(b.input_detail_counts, ['available', 'retained', 'omitted', 'capped_example_entries', 'capped_diagnostic_entries', 'clipped_text_characters']);
  Object.values(detail).forEach(x => small(x));
  if (small(detail.available, 420) - small(detail.retained) !== small(detail.omitted) || BigInt(issues.length) + BigInt(small(b.omitted_input_issues)) !== n.displayed_issue_count) fail();
  let retained = 0;
  for (const raw of issues) {
    const i = closed(raw, ['id', 'pattern', ...issueFields, 'first_seen', 'last_seen', 'observed_facts', 'evidence', 'uncertainty', 'next_checks'], ['observed_measurements', 'suspected_cause', 'detailed_analysis']);
    const id = scalar(i.id, 100, 1); if (seen.has(id) || typeof i.pattern !== 'string' || !Object.hasOwn(patterns, i.pattern)) fail(); seen.add(id);
    issueFields.forEach(k => dec(i[k])); scalar(i.first_seen, 64); scalar(i.last_seen, 64);
    for (const k of ['evidence', 'uncertainty', 'next_checks', 'detailed_analysis']) retained += texts(issueList(i, k, 4), 4).length;
    if (Object.hasOwn(i, 'suspected_cause')) { cause(i.suspected_cause); retained++; }
    for (const [key, payload] of [['observed_facts', 'facts'], ['observed_measurements', 'measurements']]) {
      const ordinals = new Set();
      for (const rawWrapper of issueList(i, key, 2)) {
        const w = closed(rawWrapper, ['example_index', payload]), ordinal = small(w.example_index, 1);
        if (ordinals.has(ordinal)) fail(); ordinals.add(ordinal); retained++;
        if (payload === 'measurements') measurement(w[payload]);
        else for (const [k, v] of Object.entries(closed(w[payload], [], Object.keys(maxima)))) dec(v, maxima[k]);
      }
    }
  }
  if (retained !== detail.retained) fail();
  return b;
}
function resolve(ref: Obj, b: Obj): { value: string | number; unit: string; qualifiers: Obj } {
  const s = object(b.summary), kind = ref.kind;
  const q: Obj = { scope: kind === 'summary_count' ? 'report' : kind === 'issue_count' ? 'issue' : 'representative_flow', report_coverage_complete: s.coverage_complete, counts_are_lower_bounds: s.counts_are_lower_bounds, measurement_coverage_complete: null, measurement_status: null, sample_count: null, quality_status: null, quality_reasons: [], measurement_reasons: [], rtt_sources: null, rtt_excluded: null };
  if (kind === 'summary_count') {
    closed(ref, ['kind', 'field']); const k = scalar(ref.field, 50); if (!summaryFields.includes(k)) return fail();
    return { value: s[k] as string, unit: summaryFields.indexOf(k) < 5 ? 'records' : summaryFields.indexOf(k) < 8 ? 'flows' : 'issues', qualifiers: q };
  }
  const id = scalar(ref.issue_id, 100, 1), i = list(b.issues, 20).map(object).find(i => i.id === id); if (!i) return fail();
  if (kind === 'issue_count') {
    closed(ref, ['kind', 'field', 'issue_id']); const k = scalar(ref.field, 50), index = issueFields.indexOf(k); if (index < 0) return fail();
    return { value: i[k] as string, unit: ['events', 'flows', 'hosts'][index], qualifiers: q };
  }
  const ordinal = small(ref.example_index, 1), fact = kind === 'example_fact';
  if (!fact && kind !== 'measurement') return fail();
  const wrapper = issueList(i, fact ? 'observed_facts' : 'observed_measurements', 2).map(object).find(w => w.example_index === ordinal); if (!wrapper) return fail();
  if (fact) {
    closed(ref, ['kind', 'issue_id', 'example_index', 'field']); const k = scalar(ref.field, 50); if (!Object.hasOwn(maxima, k)) return fail();
    const v = object(wrapper.facts)[k]; dec(v, maxima[k]); return { value: v as string, unit: k === 'transport_payload_length' ? 'bytes' : 'raw', qualifiers: q };
  }
  closed(ref, ['kind', 'issue_id', 'example_index', 'metric', 'direction', 'statistic']);
  const m = object(wrapper.measurements), metric = scalar(ref.metric, 50), stat = scalar(ref.statistic, 30);
  const allowed: Record<string, string[]> = { observed_rtt_ms: ['count', 'min', 'max', 'mean', 'stddev'], interarrival_variation_ms: ['count', 'min', 'max', 'mean', 'stddev'], ttl_observed: ['count', 'min', 'max', 'changes', 'missing'], rtt_sources: ['syn_ack', 'data_ack'], rtt_excluded: ['ambiguous', 'nonpositive_time', 'nonexact_ack'] };
  if (!Object.hasOwn(allowed, metric) || !allowed[metric].includes(stat)) return fail();
  const directional = metric === 'ttl_observed' || metric === 'interarrival_variation_ms';
  if (directional ? !directions.includes(String(ref.direction)) : ref.direction !== null) return fail();
  const data = object(directional ? object(m[metric])[String(ref.direction)] : m[metric]);
  const count = directional ? data.count : object(m.observed_rtt_ms).count;
  const value = data[stat]; if (value === null || value === undefined || stat === 'stddev' && dec(count) < 2n) return fail();
  let quality: Obj | undefined;
  if (m.metric_quality !== undefined) { const raw = object(m.metric_quality)[directional ? metric : 'observed_rtt_ms']; quality = object(directional ? object(raw)[String(ref.direction)] : raw); }
  Object.assign(q, { measurement_coverage_complete: m.coverage_complete, measurement_status: m.status, sample_count: count, quality_status: quality?.status ?? 'not_provided', quality_reasons: quality?.reasons ?? [], measurement_reasons: m.reasons, rtt_sources: directional ? null : m.rtt_sources, rtt_excluded: directional ? null : m.rtt_excluded });
  const ttlUnits: Record<string, string> = { count: 'observations', min: 'ttl', max: 'ttl', changes: 'changes', missing: 'count' };
  return { value: value as string | number, unit: metric === 'rtt_sources' || metric === 'rtt_excluded' ? 'count' : metric === 'ttl_observed' ? ttlUnits[stat] : stat === 'count' ? 'samples' : 'ms', qualifiers: q };
}
// Only own-data run metadata enters selection, polling and the status display.
// Keep the object identity for reconciliation; validate payloads separately once
// per render, never via a generic clone/stringify that could execute hooks.
export function networkRunRecord<T>(value: T): T | undefined {
  try {
    const r = object(value);
    bounded(Object.fromEntries(Object.entries(r).filter(([k]) => !['network_input', 'network_interpretation', 'network_numeric_evidence'].includes(k))), 32768);
    for (const key of ['id', 'status', 'analysis_kind']) scalar(r[key], 32768, 1);
    for (const key of ['language', 'analysis_job_id', 'dataset_id', 'created_at', 'completed_at', 'provider', 'model_name', 'error_code', 'error_message']) {
      if (r[key] !== undefined && r[key] !== null) scalar(r[key], 32768);
    }
    return value;
  } catch { return undefined; }
}
export function networkRunItems<T>(value: { items: T[] } | undefined): T[] {
  try { return list(object(value).items, 100).map(v => networkRunRecord(v as T)).filter((v): v is T => v !== undefined); }
  catch { return []; }
}
export type NetworkDisplay = { version: 'v2' | 'legacy' | 'invalid'; output?: Obj; numeric?: NumericResult };
export function networkRunDisplay(run: NumericRun | undefined): NetworkDisplay {
  try {
    const r = object(run);
    if (r.status !== 'COMPLETED') return { version: 'invalid' };
    const out = object(r.network_interpretation);
    const source = Object.hasOwn(r, 'network_input') ? object(r.network_input) : undefined;
    const top = Object.hasOwn(r, 'input_schema_version') ? r.input_schema_version : undefined;
    // Classify all three OWN data markers together. Unknown/present-null values
    // and any v2 binding cannot be retried as a legacy interpretation.
    if (top === 'network-ai-input-v2' || source?.schema_version === 'network-ai-input-v2' || out.schema_version === 'network-interpretation-v2') {
      const numeric = parseNumericRun(run!);
      return { version: 'v2', numeric, output: numeric?.output };
    }
    if (Object.hasOwn(r, 'input_schema_version') && top !== 'network-ai-input-v1' || source && source.schema_version !== 'network-ai-input-v1' || out.schema_version !== 'network-interpretation-v1') return { version: 'invalid' };
    // Legacy has no numeric trust claim, but it still needs a bounded data-only
    // display value. Retain historical absence of new source provenance and
    // the renderer's 20-item/2000-character clipping behavior.
    bounded(out, 200000);
    if (source) bounded(source, 24000);
    if (out.kind !== 'MODEL_INTERPRETATION' || !['en', 'ko'].includes(String(out.language))) fail();
    scalar(out.summary, 200000);
    texts(out.limitations, 100, 200000);
    for (const section of ['possible_causes', 'prioritized_checks', 'correlations']) {
      for (const raw of list(out[section], 100)) {
        const item = object(raw);
        texts(item.issue_ids, 100, 200000);
        for (const key of section === 'possible_causes' ? ['hypothesis', 'uncertainty'] : section === 'prioritized_checks' ? ['priority', 'check'] : ['interpretation']) scalar(item[key], 200000);
      }
    }
    return { version: 'legacy', output: out };
  } catch { return { version: 'invalid' }; }
}
export function parseNumericRun(run: NumericRun): NumericResult | undefined {
  try {
    const r = object(run);
    if (r.input_schema_version !== 'network-ai-input-v2') return fail();
    const b = input(run.network_input); bounded(run.network_interpretation, 200000); bounded(run.network_numeric_evidence, 32768);
    const out = closed(run.network_interpretation, ['schema_version', 'kind', 'language', 'summary', 'summary_numeric_refs', 'possible_causes', 'prioritized_checks', 'correlations', 'limitations']);
    if (out.schema_version !== 'network-interpretation-v2' || out.kind !== 'MODEL_INTERPRETATION' || out.language !== b.language) return fail();
    scalar(out.summary, 1200, 1); if (texts(out.limitations, 12, 1200, 1).length < 1) fail();
    const groups: { section: string; index: number | null; refs: unknown[]; ids?: string[] }[] = [{ section: 'summary', index: null, refs: list(out.summary_numeric_refs, 3) }];
    const supplied = list(b.issues, 20).map(i => object(i).id);
    for (const section of ['possible_causes', 'prioritized_checks', 'correlations']) list(out[section], 10).forEach((raw, index) => {
      const keys = section === 'possible_causes' ? ['hypothesis', 'uncertainty'] : section === 'prioritized_checks' ? ['priority', 'check'] : ['interpretation'];
      const item = closed(raw, [...keys, 'issue_ids', 'numeric_refs']); keys.forEach(k => scalar(item[k], 1200, 1));
      if (section === 'prioritized_checks' && !['HIGH', 'MEDIUM', 'LOW'].includes(String(item.priority))) fail();
      const ids = texts(item.issue_ids, 20, 100, 1); if (new Set(ids).size !== ids.length || ids.some(id => !supplied.includes(id)) || ids.length < (section === 'correlations' ? 2 : section === 'possible_causes' ? 1 : 0)) fail();
      groups.push({ section, index, refs: list(item.numeric_refs, 3), ids });
    });
    const e = closed(run.network_numeric_evidence, ['schema_version', 'run_id', 'analysis_job_id', 'dataset_id', 'input_sha256', 'items']);
    if (e.schema_version !== 'network-numeric-evidence-v1' || e.run_id !== run.id || e.analysis_job_id !== run.analysis_job_id || e.dataset_id !== (run.dataset_id ?? null) || !/^[0-9a-f]{64}$/.test(scalar(e.input_sha256, 64))) fail();
    // Direct source re-resolution below is authoritative; the supplied digest is not authentication.
    if (new TextEncoder().encode(JSON.stringify(e)).length > 32768) fail();
    const rows = list(e.items, 24), expectedRows: NumericRow[] = [];
    for (const g of groups) {
      const seen = new Set();
      g.refs.forEach((raw, ri) => {
        const ref = object(raw), key = stable(ref);
        if (seen.has(key) || ref.issue_id !== undefined && g.ids && !g.ids.includes(String(ref.issue_id))) fail(); seen.add(key);
        const expected = resolve(ref, b), row = closed(rows[expectedRows.length], ['section', 'item_index', 'reference_index', 'reference', 'value', 'unit', 'qualifiers']);
        const value = scalar(row.value, 32, 1);
        if (row.section !== g.section || row.item_index !== g.index || row.reference_index !== ri || stable(row.reference) !== key || row.unit !== expected.unit || stable(row.qualifiers) !== stable(expected.qualifiers)) fail();
        if (typeof expected.value === 'string' ? value !== expected.value : !/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?$/.test(value) || !Number.isFinite(Number(value)) || Number(value) !== expected.value) fail();
        expectedRows.push(row as NumericRow);
      });
    }
    if (rows.length !== expectedRows.length) fail();
    return { input: b, output: out, rows: expectedRows };
  } catch { return undefined; }
}
// The legacy report projection filters examples. Refuse any filtered/malformed
// slot rather than treating a compacted array position as an original ordinal.
export function currentNumericSource(context: EvidenceContext | undefined, run: NumericRun, selectedId: string | undefined, parsed: NumericResult): boolean {
  try {
    if (!context?.current() || !context.job || context.job.status !== 'COMPLETED' || run.status !== 'COMPLETED' || run.analysis_kind !== 'NETWORK_ANOMALY' || selectedId !== run.id || run.analysis_job_id !== context.job.id || (run.dataset_id ?? null) !== (context.job.dataset_id ?? null) || !context.projection.summaryTrusted) return false;
    const sameInt = (source: unknown, current: unknown) => { const n = small(current); return dec(source) === BigInt(n); };
    const summary = object(parsed.input.summary);
    if (!summaryFields.every(k => sameInt(summary[k], context.projection.summary[k])) || !['coverage_complete', 'counts_are_lower_bounds', 'truncated', 'verdict'].every(k => summary[k] === context.projection.summary[k])) return false;
    const matchMeasurement = (wire: unknown, raw: unknown, integer = false): boolean => {
      if (wire === null) return raw === null;
      if (Array.isArray(wire)) return stable(wire) === stable(raw);
      if (typeof wire === 'object') {
        const a = object(wire), b = object(raw); if (Object.keys(a).length !== Object.keys(b).length) return false;
        return Object.keys(a).every(k => matchMeasurement(a[k], b[k], typeof a[k] === 'string' && /^(0|[1-9][0-9]*)$/.test(a[k] as string)));
      }
      return integer ? sameInt(wire, raw) : wire === raw;
    };
    for (const raw of list(parsed.input.issues, 20)) {
      const i = object(raw), slot = context.projection.slots.find(s => s.issue?.id === i.id), target = slot?.issue;
      if (!slot || slot.index >= 20 || slot.invalid || slot.examplesInvalid || slot.examplesExceeded || !target || context.projection.ids.get(String(i.id)) !== 1) return false;
      if (!issueFields.every(k => sameInt(i[k], target[k as keyof typeof target])) || !['pattern', 'first_seen', 'last_seen'].every(k => i[k] === target[k as keyof typeof target])) return false;
      for (const [key, payload] of [['observed_facts', 'facts'], ['observed_measurements', 'measurements']]) for (const rawWrapper of issueList(i, key, 2)) {
        const w = object(rawWrapper), example = target.examples[small(w.example_index, 1)]; if (!example) return false;
        if (payload === 'measurements') { if (!matchMeasurement(w.measurements, example.measurements)) return false; }
        else { const facts = object(w.facts); if (!Object.keys(facts).every(k => sameInt(facts[k], example.facts?.[k]))) return false; }
      }
    }
    return true;
  } catch { return false; }
}
