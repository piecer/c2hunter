import { parseDDoSTimestamp } from './ddosReportTime';

export const guidanceRegistry = {
  family: ['SYN_CONCENTRATION', 'PAYLOAD_FREE_ACK_BURST', 'RST_BURST', 'UDP_BURST', 'ICMP_BURST'],
  reason: ['SYN_SHARE_HIGH', 'ABSOLUTE_VOLUME', 'RELATIVE_RATE_INCREASE'],
  uncertainty: ['INTENT_AND_IMPACT_UNCONFIRMED', 'REVERSE_VISIBILITY_UNKNOWN', 'WITHIN_CAPTURE_BASELINE_UNAVAILABLE', 'WITHIN_CAPTURE_NOT_KNOWN_NORMAL', 'LOW_SOURCE_DIVERSITY', 'SHORT_OBSERVATION'],
  alternative: ['LEGITIMATE_CONNECTION_SURGE', 'EXPECTED_SERVICE_BURST', 'MIDDLEBOX_OR_SERVER_RESETS', 'ASYMMETRIC_TCP_CAPTURE'],
  next_check: ['CHECK_BIDIRECTIONAL_CAPTURE', 'CHECK_SYN_BACKLOG', 'CHECK_TCP_STATE', 'CHECK_SERVICE_REQUEST_RESPONSE', 'CHECK_ICMP_OPERATIONS'],
  coverage: ['INPUT_LIMIT', 'PARSER_GAPS', 'SENSOR_DROPS', 'CLOCK_SKEW', 'CAPTURE_PARTIAL', 'CAPTURE_QUALITY_UNKNOWN', 'DUPLICATE_CAPTURE_POSSIBLE', 'DDOS_COVERAGE_LIMITED', 'INELIGIBLE_RECORDS', 'RECORDS_REJECTED', 'WINDOW_STATE_LIMIT', 'RESPONSE_STATE_LIMIT'],
  limitation: ['REVIEW_NOT_ATTACK_CLASSIFICATION', 'NO_CANDIDATE_NOT_CLEAN', 'L7_NOT_ASSESSED', 'OBSERVED_SOURCES_NOT_ACTORS'],
} as const;
export type GuidanceCode = typeof guidanceRegistry[keyof typeof guidanceRegistry][number];
export type GuidanceCandidate = {
  family: typeof guidanceRegistry.family[number]; role: 'VICTIM_SIDE_INBOUND' | 'PARTICIPANT_SIDE_OUTBOUND';
  target: { ip: string; port: number | null; protocol: 'TCP' | 'UDP' | 'ICMP' | 'ICMPV6' };
  window_start: string; window_end: string; first_seen: string; last_seen: string;
  packet_count: number; byte_count: number; source_count: number; source_count_is_lower_bound: boolean;
  source_examples: string[]; syn_only_count: number; ack_only_count: number; rst_count: number;
  payload_packet_count: number; payload_visibility_complete: boolean;
  baseline_window_count: number; baseline_packet_count: number;
  reason_codes: typeof guidanceRegistry.reason[number][]; uncertainty_codes: typeof guidanceRegistry.uncertainty[number][];
  alternative_codes: typeof guidanceRegistry.alternative[number][]; next_check_codes: typeof guidanceRegistry.next_check[number][];
};
export type GuidanceSummary = {
  scanned_records: number; evaluated_records: number; rejected_record_count: number; packet_count: number; byte_count: number;
  eligible_packet_count: number; excluded_record_count: number; retained_target_count: number; retained_window_count: number;
  omitted_observation_count: number; response_state_count: number; response_omitted_count: number;
  suppressed_handshake_window_count: number; qualifying_window_count: number; candidate_count: number; omitted_candidate_count: number;
  coverage_complete: boolean; first_seen: string | null; last_seen: string | null;
};
export type PcapGuidance = {
  version: 'pcap-attack-guidance-v1'; job_id: string; dataset_id: string;
  status: 'REVIEW_CANDIDATES' | 'NO_CANDIDATE' | 'INSUFFICIENT_OBSERVATION'; summary: GuidanceSummary;
  candidates: GuidanceCandidate[]; coverage_codes: typeof guidanceRegistry.coverage[number][];
  limitations: typeof guidanceRegistry.limitation[number][];
};
export type GuidanceResult = { state: 'VALID'; guide: PcapGuidance } | { state: 'INVALID' } | { state: 'UNAVAILABLE' };
// Validate descriptors before reading values: malformed present metadata must not
// become historical absence through lossy copying or execute getters/toJSON.
type ObjectValue = Record<string, unknown>;
type Check = (value: unknown) => boolean;
const count: Check = value => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const limit = (max: number, min = 0): Check => value => count(value) && (value as number) >= min && (value as number) <= max;
const bool: Check = value => typeof value === 'boolean';
const member = (values: readonly string[]): Check => value => typeof value === 'string' && values.includes(value);
function plain(value: unknown): value is ObjectValue {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) return false;
  return Reflect.ownKeys(value).every(key => {
    const d = Object.getOwnPropertyDescriptor(value, key)!;
    return typeof key === 'string' && d.enumerable && 'value' in d;
  });
}
function shape(value: unknown, fields: Record<string, Check>): boolean {
  return plain(value) && Reflect.ownKeys(value).length === Object.keys(fields).length
    && Object.entries(fields).every(([key, check]) => Object.hasOwn(value, key) && check(value[key]));
}
function list(check: Check, max: number, min = 0): Check {
  return value => {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length < min || value.length > max) return false;
    if (Reflect.ownKeys(value).length !== value.length + 1) return false;
    for (let i = 0; i < value.length; i++) {
      const d = Object.getOwnPropertyDescriptor(value, String(i));
      if (!d || !d.enumerable || !('value' in d) || !check(d.value)) return false;
    }
    return true;
  };
}
const same = (a: readonly unknown[], b: readonly unknown[]) => a.length === b.length && a.every((v, i) => v === b[i]);
const sortedUnique = (values: string[]) => same(values, [...new Set(values)].sort());
const integer = (value: number) => BigInt(value);
const total = (...values: number[]) => values.reduce((sum, value) => sum + integer(value), 0n);
const id: Check = v => typeof v === 'string' && Array.from(v).length >= 1 && Array.from(v).length <= 128 && !/[\uD800-\uDFFF]/u.test(v);
const timestamp: Check = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(v) && parseDDoSTimestamp(v) !== null;
const instant = (v: string) => parseDDoSTimestamp(v)!;
const maybeTime: Check = v => v === null || timestamp(v);
// Python ipaddress canonical spellings (lowercase hex, earliest longest
// zero run; IPv4-mapped addresses use dotted decimal in the supported runtime).
function address(value: unknown): boolean {
  if (typeof value !== 'string' || value.length < 2 || value.length > 39) return false;
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) return value.split('.').every(v => Number(v) <= 255);
  if (value.startsWith('::ffff:') && value.includes('.')) return /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value.slice(7)) && value.slice(7).split('.').every(v => Number(v) <= 255);
  if (!/^[0-9a-f:]+$/.test(value)) return false;
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (![...left, ...right].every(v => /^[0-9a-f]{1,4}$/.test(v))) return false;
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return false;
  const words = [...left, ...Array(missing).fill('0'), ...right].map(v => Number.parseInt(v, 16).toString(16));
  if (words.slice(0, 5).every(v => v === '0') && words[5] === 'ffff') return false;
  let start = -1, length = 1;
  for (let i = 0; i < 8;) {
    if (words[i] !== '0') { i++; continue; }
    const begin = i; while (i < 8 && words[i] === '0') i++;
    if (i - begin > length) { start = begin; length = i - begin; }
  }
  const canonical = start < 0 ? words.join(':') : `${words.slice(0, start).join(':')}::${words.slice(start + length).join(':')}`;
  return value === canonical;
}
const summaryFields = {
  scanned_records: count, evaluated_records: count, rejected_record_count: count, packet_count: count, byte_count: count,
  eligible_packet_count: count, excluded_record_count: count, retained_target_count: limit(256), retained_window_count: limit(8192),
  omitted_observation_count: count, response_state_count: limit(8192), response_omitted_count: count,
  suppressed_handshake_window_count: count, qualifying_window_count: count, candidate_count: limit(32), omitted_candidate_count: limit(256),
  coverage_complete: bool, first_seen: maybeTime, last_seen: maybeTime,
};
const candidateFields = {
  family: member(guidanceRegistry.family), role: member(['VICTIM_SIDE_INBOUND', 'PARTICIPANT_SIDE_OUTBOUND']),
  target: (v: unknown) => shape(v, { ip: address, port: v => v === null || limit(65535)(v), protocol: member(['TCP', 'UDP', 'ICMP', 'ICMPV6']) }),
  window_start: timestamp, window_end: timestamp, first_seen: timestamp, last_seen: timestamp,
  packet_count: limit(Number.MAX_SAFE_INTEGER, 32), byte_count: count, source_count: limit(32, 1), source_count_is_lower_bound: bool,
  source_examples: list(address, 8, 1), syn_only_count: count, ack_only_count: count, rst_count: count,
  payload_packet_count: count, payload_visibility_complete: bool, baseline_window_count: limit(511), baseline_packet_count: count,
  reason_codes: list(member(guidanceRegistry.reason), 1, 1), uncertainty_codes: list(member(guidanceRegistry.uncertainty), 6, 3),
  alternative_codes: list(member(guidanceRegistry.alternative), 1, 1), next_check_codes: list(member(guidanceRegistry.next_check), 2, 2),
};
function candidateValid(c: GuidanceCandidate): boolean {
  const start = instant(c.window_start), end = instant(c.window_end), first = instant(c.first_seen), last = instant(c.last_seen);
  if (end - start !== 5000000n || start % 5000000n !== 0n || !(start <= first && first <= last && last < end)) return false;
  if (c.source_examples.length !== Math.min(8, c.source_count) || !sortedUnique(c.source_examples) || c.source_count > c.packet_count || (c.source_count_is_lower_bound && c.source_count !== 32)) return false;
  if (total(c.syn_only_count, c.ack_only_count, c.rst_count) > integer(c.packet_count) || c.payload_packet_count > c.packet_count) return false;
  // Count actually occupied earlier windows, never invented idle samples.
  // The 32-packet floor belongs only to the candidate window.
  if (c.baseline_window_count === 0 ? c.baseline_packet_count !== 0 : c.baseline_window_count < 3 || c.baseline_packet_count < c.baseline_window_count) return false;
  const tcp = ['SYN_CONCENTRATION', 'PAYLOAD_FREE_ACK_BURST', 'RST_BURST'].includes(c.family);
  if (tcp && c.target.protocol !== 'TCP') return false;
  let alternative = 'EXPECTED_SERVICE_BURST', check = 'CHECK_SERVICE_REQUEST_RESPONSE';
  if (c.family === 'SYN_CONCENTRATION') {
    if (integer(c.syn_only_count) * 5n < integer(c.packet_count) * 4n || !same(c.reason_codes, ['SYN_SHARE_HIGH'])) return false;
    alternative = 'LEGITIMATE_CONNECTION_SURGE'; check = 'CHECK_SYN_BACKLOG';
  } else {
    if (same(c.reason_codes, ['ABSOLUTE_VOLUME'])) { if (c.packet_count < 1000) return false; }
    else if (same(c.reason_codes, ['RELATIVE_RATE_INCREASE'])) {
      if (c.baseline_window_count < 3 || integer(c.packet_count) * integer(c.baseline_window_count) < 5n * integer(c.baseline_packet_count)) return false;
    } else return false;
    if (c.family === 'PAYLOAD_FREE_ACK_BURST') {
      if (integer(c.ack_only_count) * 5n < integer(c.packet_count) * 4n || c.payload_packet_count !== 0 || !c.payload_visibility_complete) return false;
      alternative = 'ASYMMETRIC_TCP_CAPTURE'; check = 'CHECK_TCP_STATE';
    } else if (c.family === 'RST_BURST') {
      if (integer(c.rst_count) * 5n < integer(c.packet_count) * 4n) return false;
      alternative = 'MIDDLEBOX_OR_SERVER_RESETS'; check = 'CHECK_TCP_STATE';
    } else if (c.family === 'UDP_BURST') { if (c.target.protocol !== 'UDP') return false; }
    else if (c.family === 'ICMP_BURST') { if (!['ICMP', 'ICMPV6'].includes(c.target.protocol)) return false; check = 'CHECK_ICMP_OPERATIONS'; }
  }
  if (c.target.protocol !== 'TCP' && (c.syn_only_count || c.ack_only_count || c.rst_count)) return false;
  const uncertainty = ['INTENT_AND_IMPACT_UNCONFIRMED', 'REVERSE_VISIBILITY_UNKNOWN', c.baseline_window_count ? 'WITHIN_CAPTURE_NOT_KNOWN_NORMAL' : 'WITHIN_CAPTURE_BASELINE_UNAVAILABLE'];
  if (c.source_count < 20) uncertainty.push('LOW_SOURCE_DIVERSITY');
  if (last - first < 3000000n) uncertainty.push('SHORT_OBSERVATION');
  return same(c.uncertainty_codes, uncertainty.sort()) && same(c.alternative_codes, [alternative]) && same(c.next_check_codes, ['CHECK_BIDIRECTIONAL_CAPTURE', check]);
}
function guideValid(g: PcapGuidance): boolean {
  const s = g.summary;
  if (total(s.eligible_packet_count, s.excluded_record_count) !== integer(s.evaluated_records)
    || total(s.evaluated_records, s.rejected_record_count) > integer(s.scanned_records)
    || s.eligible_packet_count > s.packet_count || s.retained_target_count > s.retained_window_count || s.retained_window_count > s.eligible_packet_count
    || s.omitted_observation_count > s.eligible_packet_count || s.response_omitted_count > s.eligible_packet_count || s.response_state_count > s.eligible_packet_count
    || total(s.response_state_count, s.response_omitted_count) > integer(s.eligible_packet_count)
    || total(s.qualifying_window_count, s.suppressed_handshake_window_count) > integer(s.retained_window_count)
    || total(s.candidate_count, s.omitted_candidate_count) > integer(s.retained_target_count)
    || total(s.candidate_count, s.omitted_candidate_count) > integer(s.qualifying_window_count) || s.candidate_count !== g.candidates.length) return false;
  if (!sortedUnique(g.coverage_codes) || s.coverage_complete !== !g.coverage_codes.length || !same(g.limitations, guidanceRegistry.limitation)) return false;
  const coveragePairs = [[s.excluded_record_count, 'INELIGIBLE_RECORDS'], [s.rejected_record_count, 'RECORDS_REJECTED'], [s.omitted_observation_count, 'WINDOW_STATE_LIMIT'], [s.response_omitted_count, 'RESPONSE_STATE_LIMIT']] as const;
  if (coveragePairs.some(([n, code]) => Boolean(n) !== g.coverage_codes.includes(code))) return false;
  if (g.status !== (g.candidates.length ? 'REVIEW_CANDIDATES' : s.eligible_packet_count >= 32 ? 'NO_CANDIDATE' : 'INSUFFICIENT_OBSERVATION')) return false;
  if (s.evaluated_records ? s.first_seen === null || s.last_seen === null : s.first_seen !== null || s.last_seen !== null) return false;
  if (s.first_seen !== null && s.last_seen !== null && instant(s.first_seen) > instant(s.last_seen)) return false;
  const keys = new Set<string>();
  for (const c of g.candidates) {
    const key = JSON.stringify([c.role, c.target.ip, c.target.port, c.target.protocol]);
    if (keys.has(key) || !candidateValid(c)) return false;
    keys.add(key);
    if (s.first_seen === null || s.last_seen === null || instant(c.first_seen) < instant(s.first_seen) || instant(c.last_seen) > instant(s.last_seen)
      || total(c.baseline_packet_count, c.packet_count) > integer(s.eligible_packet_count)) return false;
    // Exact floor division matters before the Unix epoch: BigInt division
    // truncates toward zero. The fixed window may enclose the actual bounds.
    const first = instant(s.first_seen);
    const firstWindow = first - ((first % 5000000n + 5000000n) % 5000000n);
    const earlierSlots = (instant(c.window_start) - firstWindow) / 5000000n;
    if (c.baseline_window_count + 1 > s.retained_window_count || integer(c.baseline_window_count) > earlierSlots) return false;
  }
  if (total(...g.candidates.flatMap(c => [c.baseline_window_count, 1])) > integer(s.retained_window_count)
    || total(...g.candidates.flatMap(c => [c.baseline_packet_count, c.packet_count])) > integer(s.eligible_packet_count) - integer(s.omitted_observation_count)
    || total(...g.candidates.map(c => c.byte_count)) > integer(s.byte_count)) return false;
  // Key order does not affect byte length. All numeric fields are validated
  // integers; JSON.stringify normalizes integral floats and negative zero.
  return new TextEncoder().encode(JSON.stringify(g) + '\n').length <= 131072;
}
export function validatePcapGuidanceJob(job: unknown): GuidanceResult {
  const invalid: GuidanceResult = { state: 'INVALID' };
  if (!plain(job)) return invalid;
  if (!Object.hasOwn(job, 'pcap_attack_guidance')) return { state: 'UNAVAILABLE' };
  if (job.source_type !== 'PCAP_UPLOAD' || !plain(job.analysis) || job.analysis.module !== 'ddos_attack') return invalid;
  const value = job.pcap_attack_guidance;
  if (!shape(value, {
    version: v => v === 'pcap-attack-guidance-v1', job_id: id, dataset_id: id,
    status: member(['REVIEW_CANDIDATES', 'NO_CANDIDATE', 'INSUFFICIENT_OBSERVATION']),
    summary: v => shape(v, summaryFields), candidates: list(v => shape(v, candidateFields), 32),
    coverage_codes: list(member(guidanceRegistry.coverage), 12), limitations: list(member(guidanceRegistry.limitation), 4, 4),
  })) return invalid;
  const guide = value as PcapGuidance;
  if (!guideValid(guide) || guide.job_id !== job.id || guide.dataset_id !== job.dataset_id) return invalid;
  for (const [field, observed] of [['packet_count', guide.summary.packet_count], ['flow_count', guide.summary.scanned_records]] as const) {
    if (Object.hasOwn(job, field) && (!count(job[field]) || observed > (job[field] as number))) return invalid;
  }
  if (!plain(job.ddos_attack) || !plain(job.ddos_attack.summary)) return invalid;
  const summary = job.ddos_attack.summary;
  for (const field of ['scanned_records', 'evaluated_records', 'packet_count', 'byte_count'] as const) if (guide.summary[field] !== summary[field]) return invalid;
  if (guide.summary.rejected_record_count !== summary.skipped_records) return invalid;
  for (const field of ['first_seen', 'last_seen'] as const) {
    const expected = typeof summary[field] === 'string' ? parseDDoSTimestamp(summary[field]) : null;
    if (typeof summary[field] === 'string' && expected === null) return invalid;
    if ((guide.summary[field] === null ? null : instant(guide.summary[field])) !== expected) return invalid;
  }
  if (guide.coverage_codes.includes('DDOS_COVERAGE_LIMITED') !== !summary.coverage_complete) return invalid;
  return { state: 'VALID', guide };
}
