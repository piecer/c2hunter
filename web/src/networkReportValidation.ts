import { patterns, warnings as warningCodes } from './reportTranslations';
import type { PatternIssue } from './NetworkPatternReport';
import { parseICMPDetails } from './networkICMPDetails';
// Modern saved-report consumer projection. Never repair or mutate producer data.
export const record = (value: unknown): Record<string, unknown> | undefined => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
export const safeCount = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const summaryCounts = ['scanned_records', 'evaluated_records', 'skipped_records', 'incomplete_records', 'flow_count', 'suspect_flow_count', 'detailed_flow_count', 'issue_count', 'displayed_issue_count', 'omitted_issue_count'] as const;
export function trustedSummary(value: unknown, issueLength: number): boolean {
  const s = record(value);
  if (!s || !summaryCounts.every(key => safeCount(s[key]))) return false;
  const n = (key: typeof summaryCounts[number]) => s[key] as number;
  if (typeof s.verdict !== 'string' || !['anomaly_observed', 'no_clear_anomaly', 'insufficient_evidence'].includes(s.verdict) || typeof s.coverage_complete !== 'boolean' || typeof s.truncated !== 'boolean') return false;
  // Subtraction avoids unsafe intermediate sums at MAX_SAFE_INTEGER.
  if (n('evaluated_records') > n('scanned_records') || n('skipped_records') > n('scanned_records') || n('incomplete_records') > n('scanned_records') || n('scanned_records') - n('skipped_records') - n('incomplete_records') !== n('evaluated_records')) return false;
  if (n('displayed_issue_count') !== issueLength || n('issue_count') - n('displayed_issue_count') !== n('omitted_issue_count')) return false;
  if (n('detailed_flow_count') > n('suspect_flow_count') || n('suspect_flow_count') > n('flow_count') || n('flow_count') > n('scanned_records')) return false;
  if (s.counts_are_lower_bounds !== undefined && typeof s.counts_are_lower_bounds !== 'boolean') return false;
  if (s.tracking_limited_records !== undefined && (!safeCount(s.tracking_limited_records) || s.tracking_limited_records > n('incomplete_records') || (s.tracking_limited_records > 0 && (s.counts_are_lower_bounds !== true || s.truncated !== true)))) return false;
  return true;
}
const string = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;
const boundedString = (v: unknown, max = 2000) => typeof v === 'string' ? v.slice(0, max) : '';
const endpoint = (v: unknown) => {
  const e = record(v);
  return e && string(e.ip, 45) && (e.port === null || (safeCount(e.port) && e.port <= 65535)) ? { ip: e.ip, port: e.port as number | null } : undefined;
};
export const factMaxima = { tcp_sequence: 4294967295, tcp_acknowledgment: 4294967295, tcp_window: 65535, transport_payload_length: 4294967295, icmp_type: 255, icmp_code: 255 } as const;
export type ProjectedIssue = { index: number; unsupportedPattern?: string; issue?: PatternIssue; invalid: boolean; examplesInvalid: boolean; examplesExceeded: boolean; notesMissing: boolean };
type FamilyRow = { pattern: string; observed_groups: number; retained_groups: number; omitted_groups: number };
type FamilyCoverage = { version: 'network-family-coverage-v1'; selection_policy: 'family-first-v1'; families: FamilyRow[] };
type FamilyResult = { state: 'absent' | 'invalid' } | { state: 'valid'; value: FamilyCoverage };
const ownData = (value: object, key: PropertyKey): PropertyDescriptor | undefined => {
  const d = Object.getOwnPropertyDescriptor(value, key);
  return d?.enumerable && Object.hasOwn(d, 'value') ? d : undefined;
};
const closedData = (value: unknown, keys: string[]): Record<string, unknown> | undefined => {
  const r = record(value);
  if (!r || ![Object.prototype, null].includes(Object.getPrototypeOf(r)) || Reflect.ownKeys(r).length !== keys.length || !keys.every(k => ownData(r, k))) return undefined;
  return r;
};
function parseFamilyCoverage(report: Record<string, unknown>, summary: Record<string, unknown>, slots: ProjectedIssue[]): FamilyResult {
  if (!('family_coverage' in report)) return { state: 'absent' };
  const invalid: FamilyResult = { state: 'invalid' };
  const root = ownData(report, 'family_coverage');
  const data = closedData(root?.value, ['version', 'selection_policy', 'families']);
  if (!data || data.version !== 'network-family-coverage-v1' || data.selection_policy !== 'family-first-v1') return invalid;
  const rows = data.families;
  // Bound before index traversal, and never invoke metadata accessors/hooks.
  if (!Array.isArray(rows) || rows.length > 6 || Object.getPrototypeOf(rows) !== Array.prototype || Reflect.ownKeys(rows).length !== rows.length + 1) return invalid;
  if (!trustedSummary(summary, slots.length) || slots.some(s => !s.issue || s.invalid)) return invalid;
  const families: FamilyRow[] = [];
  let previous = '';
  let observed = 0, retained = 0, omitted = 0;
  for (let index = 0; index < rows.length; index++) {
    const row = closedData(ownData(rows, String(index))?.value, ['pattern', 'observed_groups', 'retained_groups', 'omitted_groups']);
    if (!row || typeof row.pattern !== 'string' || !Object.hasOwn(patterns, row.pattern) || row.pattern <= previous || !safeCount(row.observed_groups) || row.observed_groups === 0 || !safeCount(row.retained_groups) || !safeCount(row.omitted_groups) || row.observed_groups - row.retained_groups !== row.omitted_groups) return invalid;
    if (slots.filter(s => s.issue?.pattern === row.pattern).length !== row.retained_groups) return invalid;
    previous = row.pattern;
    observed += row.observed_groups; retained += row.retained_groups; omitted += row.omitted_groups;
    if (![observed, retained, omitted].every(safeCount)) return invalid;
    families.push({ pattern: row.pattern, observed_groups: row.observed_groups, retained_groups: row.retained_groups, omitted_groups: row.omitted_groups });
  }
  if (observed !== summary.issue_count || retained !== summary.displayed_issue_count || omitted !== summary.omitted_issue_count) return invalid;
  return { state: 'valid', value: { version: 'network-family-coverage-v1', selection_policy: 'family-first-v1', families } };
}
export function projectNetworkReport(value: unknown) {
  const r = record(value) ?? {};
  const summary = record(r.summary) ?? {};
  const issueLimit = Array.isArray(r.issues) && r.issues.length > 100;
  const warningLimit = Array.isArray(r.warnings) && r.warnings.length > 2048;
  const rawIssues: unknown[] = Array.isArray(r.issues) && !issueLimit ? r.issues : [];
  const rawWarnings: unknown[] = Array.isArray(r.warnings) && !warningLimit ? r.warnings : [];
  const ids = new Map<string, number>();
  const knownWarnings = new Set<string>();
  let unsupportedWarnings = 0;
  let firstUnsupported = '';
  for (const w of rawWarnings) {
    if (typeof w === 'string' && Object.hasOwn(warningCodes, w)) knownWarnings.add(w);
    else { if (!unsupportedWarnings) firstUnsupported = boundedString(w, 320); unsupportedWarnings++; }
  }
  const slots: ProjectedIssue[] = rawIssues.map((raw, index) => {
    const i = record(raw);
    if (i && string(i.id, 100)) ids.set(i.id, (ids.get(i.id) ?? 0) + 1);
    const s = record(i?.scope);
    const peer = endpoint(s?.peer);
    const core = i && typeof i.pattern === 'string' && Object.hasOwn(patterns, i.pattern) && i.severity === 'observation' && s && string(s.sensor_id, 256) && (s.interface_id === null || (safeCount(s.interface_id) && s.interface_id <= 4294967295)) && typeof s.protocol === 'string' && ['TCP', 'UDP', 'ICMP', 'ICMPV6'].includes(s.protocol) && peer && ['event_count', 'affected_flow_count', 'affected_host_count', 'omitted_examples'].every(k => safeCount(i[k])) && string(i.first_seen, 64) && string(i.last_seen, 64);
    if (!core) return { index, unsupportedPattern: typeof i?.pattern === 'string' && !Object.hasOwn(patterns, i.pattern) ? i.pattern.slice(0, 320) : undefined, invalid: true, examplesInvalid: false, examplesExceeded: false, notesMissing: false };
    const examplesExceeded = Array.isArray(i.examples) && i.examples.length > 10;
    let examplesInvalid = !Array.isArray(i.examples);
    const examples: PatternIssue['examples'] = [];
    if (Array.isArray(i.examples) && !examplesExceeded) for (const rawExample of i.examples) {
      const e = record(rawExample);
      const a = endpoint(e?.endpoint_a), b = endpoint(e?.endpoint_b);
      if (!e || !a || !b || !safeCount(e.event_count)) { examplesInvalid = true; continue; }
      const facts: Record<string, number> = {};
      const f = record(e.facts);
      if (e.facts !== undefined && !f) examplesInvalid = true;
      if (f) for (const key of Object.keys(factMaxima) as (keyof typeof factMaxima)[]) {
        const n = f[key];
        if (n === undefined) continue;
        if (safeCount(n) && n <= factMaxima[key]) facts[key] = n;
        else examplesInvalid = true;
      }
      examples.push({ endpoint_a: a, endpoint_b: b, event_count: e.event_count, facts: e.facts === undefined ? undefined : facts, measurements: e.measurements, icmpDetails: parseICMPDetails(e, e.event_count, i.pattern as string) });
    }
    const notes = (v: unknown) => Array.isArray(v) ? v.slice(0, 4).filter((s): s is string => typeof s === 'string').map(s => s.slice(0, 2000)) : [];
    const notesMissing = ['evidence', 'uncertainty', 'next_checks'].some(k => !Array.isArray(i[k]));
    const issue: PatternIssue = { id: string(i.id, 100) ? i.id : '', pattern: i.pattern as string, title: '', severity: 'observation', scope: { sensor_id: s.sensor_id as string, interface_id: s.interface_id as number | null, protocol: s.protocol as string, peer }, event_count: i.event_count as number, affected_flow_count: i.affected_flow_count as number, affected_host_count: i.affected_host_count as number, omitted_examples: i.omitted_examples as number, first_seen: i.first_seen as string, last_seen: i.last_seen as string, examples, evidence: notes(i.evidence), uncertainty: notes(i.uncertainty), next_checks: notes(i.next_checks), suspected_cause: i.suspected_cause };
    return { index, issue, invalid: !issue.id, examplesInvalid, examplesExceeded, notesMissing };
  });
  // Only validated ASCII primitives are encoded. Key order does not change byte
  // count; include envelope keys, omission counters, arrays and separators.
  const detailExamples = slots.flatMap(s => s.issue?.examples ?? []);
  const validDetails = detailExamples.flatMap(e => e.icmpDetails?.state === 'valid' ? [{icmp_details:e.icmpDetails.value}] : []);
  if (validDetails.reduce((n,d) => n + d.icmp_details.samples.length, 0) > 2048 || JSON.stringify(validDetails).length > 262144) {
    for (const e of detailExamples) if (e.icmpDetails?.state === 'valid') e.icmpDetails = {state:'invalid'};
  }
  const structure = r.version === 'network-pattern-report-v1' && Array.isArray(r.issues) && !issueLimit && Array.isArray(r.warnings) && !warningLimit && Array.isArray(r.limitations);
  const summaryTrusted = structure && trustedSummary(summary, rawIssues.length) && unsupportedWarnings === 0 && slots.every(s => Boolean(s.issue));
  return { familyCoverage: parseFamilyCoverage(r, summary, slots), version: boundedString(r.version, 64), measurementVersion: boundedString(r.measurement_version, 64), summary, slots, ids, issueLimit, warningLimit, knownWarnings, unsupportedWarnings, firstUnsupported, summaryTrusted, warningsCount: rawWarnings.length, limitations: Array.isArray(r.limitations) ? r.limitations.slice(0, 8).filter((s): s is string => typeof s === 'string').map(s => s.slice(0, 2000)) : [] };
}
