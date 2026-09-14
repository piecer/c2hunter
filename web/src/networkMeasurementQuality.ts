// Additive qualification is accepted atomically, never inferred for legacy reports.
export type QualityStatus = 'unavailable' | 'limited_samples' | 'observed_samples';
export type QualityReason = 'NO_SAMPLES' | 'SINGLE_SAMPLE' | 'HANDSHAKE_ONLY' | 'BIDIRECTIONAL_RTT_NOT_ESTABLISHED' | 'SELECTION_BIAS_POSSIBLE';
export type MetricQuality = { status: QualityStatus; reasons: QualityReason[] };
type Directions = { a_to_b: MetricQuality; b_to_a: MetricQuality };
export type MeasurementQuality = { observed_rtt_ms: MetricQuality; interarrival_variation_ms: Directions; ttl_observed: Directions };
const directions = ['a_to_b', 'b_to_a'] as const;
const gapReasons = ['INCOMPLETE_PACKET_EVIDENCE', 'NON_MONOTONIC_TIMESTAMPS', 'CORRELATION_LIMIT_REACHED'];
const coverageReasons = [...gapReasons, 'MISSING_TTL', 'NO_UNAMBIGUOUS_RTT', 'NOT_TCP', 'ONE_DIRECTION_OBSERVED'];
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (v: unknown, key: string): unknown => {
  const d = record(v) ? Object.getOwnPropertyDescriptor(v, key) : undefined;
  return d?.enumerable && Object.hasOwn(d, 'value') ? d.value : undefined;
};
const closed = (v: unknown, keys: string[]) => record(v) && Reflect.ownKeys(v).length === keys.length && keys.every(k => own(v, k) !== undefined);
const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const number = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0;
function stats(v: unknown): boolean {
  if (!closed(v, ['count', 'min', 'max', 'mean', 'stddev'])) return false;
  const n = own(v, 'count'), min = own(v, 'min'), max = own(v, 'max'), mean = own(v, 'mean'), sd = own(v, 'stddev');
  if (!count(n)) return false;
  if (!n) return min === null && max === null && mean === null && sd === null;
  return number(min) && number(max) && number(mean) && min <= mean && mean <= max && (n === 1 ? sd === null || sd === 0 : number(sd));
}
function ttl(v: unknown): boolean {
  if (!closed(v, ['count', 'min', 'max', 'changes', 'missing'])) return false;
  const n = own(v, 'count'), min = own(v, 'min'), max = own(v, 'max'), changes = own(v, 'changes');
  if (!count(n) || !count(changes) || !count(own(v, 'missing')) || changes > Math.max(0, n - 1)) return false;
  return n === 0 ? min === null && max === null : count(min) && count(max) && min <= max && max <= 255;
}
function expected(n: number, rtt: boolean, handshake: boolean, selected: boolean): MetricQuality {
  const reasons: QualityReason[] = n === 0 ? ['NO_SAMPLES'] : n === 1 ? ['SINGLE_SAMPLE'] : [];
  if (handshake) reasons.push('HANDSHAKE_ONLY');
  if (rtt) reasons.push('BIDIRECTIONAL_RTT_NOT_ESTABLISHED');
  if (selected) reasons.push('SELECTION_BIAS_POSSIBLE');
  return { status: n === 0 ? 'unavailable' : n === 1 ? 'limited_samples' : 'observed_samples', reasons };
}
function matches(value: unknown, wanted: MetricQuality): boolean {
  if (!closed(value, ['status', 'reasons']) || own(value, 'status') !== wanted.status) return false;
  const reasons = own(value, 'reasons');
  return Array.isArray(reasons) && reasons.length <= 5 && reasons.length === wanted.reasons.length && wanted.reasons.every((r, i) => Object.getOwnPropertyDescriptor(reasons, String(i))?.value === r);
}
export function parseMeasurementQuality(m: unknown): MeasurementQuality | 'not_provided' | 'invalid' {
  if (!record(m) || !Object.hasOwn(m, 'metric_quality')) return 'not_provided';
  const q = own(m, 'metric_quality');
  const keys = ['observed_rtt_ms', 'interarrival_variation_ms', 'ttl_observed'];
  if (!closed(m, [...keys, 'metric_quality', 'rtt_sources', 'rtt_excluded', 'coverage_complete', 'status', 'reasons']) || !closed(q, keys)) return 'invalid';
  if (typeof own(m, 'coverage_complete') !== 'boolean' || !['observed', 'insufficient_evidence', 'unsupported'].includes(String(own(m, 'status')))) return 'invalid';
  const coverage = own(m, 'reasons');
  if (!Array.isArray(coverage) || coverage.length > 7 || coverage.some(r => typeof r !== 'string' || !coverageReasons.includes(r))) return 'invalid';
  const selected = gapReasons.some(r => coverage.includes(r));
  const sources = own(m, 'rtt_sources'), excluded = own(m, 'rtt_excluded'), rtt = own(m, 'observed_rtt_ms');
  if (!closed(sources, ['syn_ack', 'data_ack']) || !closed(excluded, ['ambiguous', 'nonpositive_time', 'nonexact_ack']) || !stats(rtt)) return 'invalid';
  const syn = own(sources, 'syn_ack'), data = own(sources, 'data_ack');
  const exclusions = ['ambiguous', 'nonpositive_time', 'nonexact_ack'].map(k => own(excluded, k));
  if (!count(syn) || !count(data) || !exclusions.every(count) || syn + data !== own(rtt, 'count')) return 'invalid';
  const wantedRTT = expected(own(rtt, 'count') as number, true, syn > 0 && data === 0, selected || exclusions.some(n => n > 0));
  if (!matches(own(q, 'observed_rtt_ms'), wantedRTT)) return 'invalid';
  const result: MeasurementQuality = { observed_rtt_ms: wantedRTT, interarrival_variation_ms: {} as Directions, ttl_observed: {} as Directions };
  for (const key of ['interarrival_variation_ms', 'ttl_observed'] as const) {
    const metrics = own(m, key), quality = own(q, key);
    if (!closed(metrics, [...directions]) || !closed(quality, [...directions])) return 'invalid';
    for (const d of directions) {
      const metric = own(metrics, d);
      if (!(key === 'ttl_observed' ? ttl(metric) : stats(metric))) return 'invalid';
      const wanted = expected(own(metric, 'count') as number, false, false, selected || (key === 'ttl_observed' && (own(metric, 'missing') as number) > 0));
      if (!matches(own(quality, d), wanted)) return 'invalid';
      result[key][d] = wanted;
    }
  }
  return result;
}
