import { parseDDoSTimestamp } from './ddosReportTime';
import { type Evaluation, validEvaluation, canonicalPredicate, validFlagProfile, validReference } from './ddosSignatures';
import { type Axis, type AxisEvidence, validV3Classification } from './ddosEvidence';
import { attackTypes, classificationConfidences, commonPatternTypes, deliveryMechanisms,
  falsePositiveCodes, limitations, metricLabels, objectives, recommendations, roles,
  signatureKinds, sourceAuthenticities, sourcePopulations, uncertainties, warnings } from './ddosReportTranslations';

export type DDoSRecommendation = {
  code: string; priority: number; scope: string; rationale_code: string; caveat_code: string;
  requires_human_approval: boolean;
};
export type DDoSClassification = {
  delivery_mechanism: string; source_population: string; source_authenticity: string;
  confidence: string; evidence?: AxisEvidence; axes?: Record<string, Axis>;
};
export type DDoSCommonPattern = {
  id: string; type: string; support_count: number; support_ratio: number; values: string[];
};
export type DDoSSignatureCandidate = {
  id: string; kind: string; protocol: string; source_ports: number[]; destination_ports: number[];
  packet_size_range: [number, number] | null; payload_prefix_hashes: string[];
  evaluation?: Evaluation;
  tcp_flag_profile: string | null; confidence: string; false_positive_codes: string[];
  requires_human_approval: boolean;
};
export type DDoSFinding = {
  id: string; attack_type: string; attack_role: string; target: { ip: string; port: number | null };
  protocol: string; objective: string; likelihood: string; severity: string; confidence: string;
  first_seen: string; last_seen: string; metrics: Record<string, unknown>; evidence_codes: string[];
  uncertainty_codes: string[]; recommendation_codes: string[];
  classification?: DDoSClassification; common_patterns?: DDoSCommonPattern[];
  signature_candidates?: DDoSSignatureCandidate[];
};
export type DDoSAttackReport = {
  version: string; catalog_version: string; verdict: string; confidence: string;
  primary_finding_id: string | null; summary: Record<string, unknown>; findings: DDoSFinding[];
  recommendations: DDoSRecommendation[]; warnings: string[]; limitations: string[];
  omitted_finding_count: number;
  normal_reference?: Evaluation['normal']['reference'];
};

const evidenceCodes = new Set(['VOLUME_GATE_MET', 'DISTRIBUTED_SOURCE_GATE_MET', 'OVERLAPPING_ATTACK_VECTORS']);
const safeInteger = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const evidenceKnown = (code: unknown) => typeof code === 'string' && (evidenceCodes.has(code) || (
  code.endsWith('_SHAPE') && Object.hasOwn(attackTypes, code.slice(0, -6))
));
const plain = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const onlyKeys = (value: Record<string, unknown>, allowed: readonly string[]) => Object.keys(value).every(key => allowed.includes(key));
const knownArray = (value: unknown, registry: Record<string, unknown>, maximum: number) => Array.isArray(value)
  && value.length <= maximum && value.every(code => typeof code === 'string' && Object.hasOwn(registry, code));
const timestamps = (value: unknown) => parseDDoSTimestamp(value) !== null;
const reportKeys = ['version', 'catalog_version', 'verdict', 'confidence', 'primary_finding_id', 'summary', 'findings', 'recommendations', 'warnings', 'limitations', 'omitted_finding_count', 'normal_reference'] as const;
const findingKeysV1 = ['id', 'attack_type', 'attack_role', 'target', 'protocol', 'objective', 'likelihood', 'severity', 'confidence', 'first_seen', 'last_seen', 'metrics', 'evidence_codes', 'uncertainty_codes', 'recommendation_codes'] as const;
const findingKeysV2 = [...findingKeysV1, 'classification', 'common_patterns', 'signature_candidates'] as const;
const classificationKeys = ['delivery_mechanism', 'source_population', 'source_authenticity', 'confidence'] as const;
const commonPatternKeys = ['id', 'type', 'support_count', 'support_ratio', 'values'] as const;
const signatureKeys = ['id', 'kind', 'protocol', 'source_ports', 'destination_ports', 'packet_size_range', 'payload_prefix_hashes', 'tcp_flag_profile', 'confidence', 'false_positive_codes', 'requires_human_approval'] as const;
const recommendationKeys = ['code', 'priority', 'scope', 'rationale_code', 'caveat_code', 'requires_human_approval'] as const;
const summaryKeys = ['scanned_records', 'evaluated_records', 'skipped_records', 'incomplete_records', 'target_count', 'finding_count', 'displayed_finding_count', 'packet_count', 'byte_count', 'first_seen', 'last_seen', 'coverage_complete', 'counts_are_lower_bounds', 'truncated', 'primary_attack_type', 'primary_objective'] as const;
const ratioMetrics = new Set(['syn_only_ratio', 'ack_only_ratio', 'rst_ratio', 'fin_ratio', 'payload_packet_ratio', 'response_ratio', 'reflection_source_port_ratio', 'icmp_echo_request_ratio', 'ip_id_monotonic_ratio']);
const integerMetrics = new Set(['packet_count', 'byte_count', 'record_count', 'distinct_sources', 'distinct_sensors', 'dominant_reflection_source_port', 'icmp_type_observed_packets', 'component_finding_count', 'hop_limit_min', 'hop_limit_max', 'network_identity_observed_records', 'network_identity_anomaly_records', 'ip_id_observed_count', 'ip_id_distinct_count']);
const commonRecommendationCodes = ['PRESERVE_CAPTURE_AND_LOGS', 'VERIFY_SERVICE_IMPACT', 'CONTACT_UPSTREAM_PROVIDER', 'MONITOR_RECOVERY_AND_FALSE_POSITIVES'];
const outboundRecommendationCodes = ['ISOLATE_INTERNAL_SOURCES', 'APPLY_EGRESS_RATE_LIMIT', 'ENFORCE_EGRESS_ANTISPOOFING'];
const typeRecommendationCodes: Record<string, string[]> = {
  TCP_SYN_FLOOD: ['ENABLE_SYN_PROXY_OR_COOKIES', 'APPLY_EDGE_SYN_RATE_LIMIT', 'CHECK_SYN_BACKLOG_AND_CONNTRACK'],
  UDP_FLOOD: ['ENGAGE_SCRUBBING_OR_FLOWSPEC', 'FILTER_OR_RATE_LIMIT_UNUSED_UDP_SERVICES'],
  POSSIBLE_REFLECTION_AMPLIFICATION: ['ENGAGE_SCRUBBING_OR_FLOWSPEC', 'FILTER_OR_RATE_LIMIT_UNUSED_UDP_SERVICES', 'VALIDATE_REFLECTION_SOURCE_PORTS'],
  ICMP_ECHO_FLOOD: ['RATE_LIMIT_NONESSENTIAL_ICMP', 'PRESERVE_PMTUD_AND_REQUIRED_ICMP'],
  ICMP_FLOOD: ['RATE_LIMIT_NONESSENTIAL_ICMP', 'PRESERVE_PMTUD_AND_REQUIRED_ICMP'],
  TCP_ACK_FLOOD: ['APPLY_STATEFUL_TCP_VALIDATION', 'RATE_LIMIT_INVALID_TCP_FLAGS', 'CHECK_MIDDLEBOX_RESET_SOURCES'],
  TCP_RST_FLOOD: ['APPLY_STATEFUL_TCP_VALIDATION', 'RATE_LIMIT_INVALID_TCP_FLAGS', 'CHECK_MIDDLEBOX_RESET_SOURCES'],
  MULTI_VECTOR: ['ENGAGE_SCRUBBING_OR_FLOWSPEC'],
};
export const sha256 = (text: string) => {
  const primes: number[] = [];
  for (let candidate = 2; primes.length < 64; candidate += 1) {
    if (primes.every(prime => candidate % prime !== 0)) primes.push(candidate);
  }
  const fraction = (value: number) => ((value - Math.floor(value)) * 0x100000000) >>> 0;
  const hash = primes.slice(0, 8).map(prime => fraction(Math.sqrt(prime)));
  const constants = primes.map(prime => fraction(Math.cbrt(prime)));
  const bytes = new TextEncoder().encode(text);
  const padded = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64);
  padded.set(bytes); padded[bytes.length] = 0x80;
  new DataView(padded.buffer).setUint32(padded.length - 4, bytes.length * 8);
  const rotate = (value: number, bits: number) => value >>> bits | value << (32 - bits);
  for (let offset = 0; offset < padded.length; offset += 64) {
    const words = new Uint32Array(64);
    const view = new DataView(padded.buffer, offset, 64);
    for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(index * 4);
    for (let index = 16; index < 64; index += 1) {
      const s0 = rotate(words[index - 15], 7) ^ rotate(words[index - 15], 18) ^ words[index - 15] >>> 3;
      const s1 = rotate(words[index - 2], 17) ^ rotate(words[index - 2], 19) ^ words[index - 2] >>> 10;
      words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index += 1) {
      const upper = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
      const choice = e & f ^ ~e & g;
      const first = (h + upper + choice + constants[index] + words[index]) >>> 0;
      const lower = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
      const majority = a & b ^ a & c ^ b & c;
      const second = (lower + majority) >>> 0;
      [a, b, c, d, e, f, g, h] = [(first + second) >>> 0, a, b, c, (d + first) >>> 0, e, f, g];
    }
    [a, b, c, d, e, f, g, h].forEach((value, index) => { hash[index] = (hash[index] + value) >>> 0; });
  }
  return hash.map(value => value.toString(16).padStart(8, '0')).join('');
};
const metricMaximum: Record<string, number> = {
  packet_count: Number.MAX_SAFE_INTEGER, byte_count: Number.MAX_SAFE_INTEGER,
  record_count: 2_000_000, duration_seconds: 315_537_897_600,
  average_packets_per_second: Number.MAX_SAFE_INTEGER, average_bits_per_second: 1e18,
  peak_packets_per_second: Number.MAX_SAFE_INTEGER, peak_bits_per_second: 1e18,
  baseline_packets_per_second: Number.MAX_SAFE_INTEGER, baseline_ratio: 1e18, robust_z_score: 1e18,
  distinct_sources: 2_000_000, distinct_sensors: 2_000_000,
  dominant_reflection_source_port: 65_535, average_packet_bytes: Number.MAX_SAFE_INTEGER,
  amplification_ratio: 1e9, icmp_type_observed_packets: Number.MAX_SAFE_INTEGER,
  component_finding_count: 4096, hop_limit_min: 255, hop_limit_max: 255,
  network_identity_observed_records: 2_000_000, network_identity_anomaly_records: 2_000_000,
  ip_id_observed_count: Number.MAX_SAFE_INTEGER, ip_id_distinct_count: Number.MAX_SAFE_INTEGER,
};
const upstreamActions = new Set(['CONTACT_UPSTREAM_PROVIDER', 'ENGAGE_SCRUBBING_OR_FLOWSPEC']);
const validIp = (value: unknown) => {
  if (typeof value !== 'string' || value.length < 2 || value.length > 45) return false;
  if (value.includes('.')) {
    const parts = value.split('.');
    return parts.length === 4 && parts.every(part => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
  }
  if (!value.includes(':') || !/^[0-9A-Fa-f:]+$/.test(value)) return false;
  try { return new URL(`http://[${value}]/`).hostname.length > 2; } catch { return false; }
};
function validClassification(value: unknown): value is DDoSClassification {
  return plain(value) && onlyKeys(value, classificationKeys)
    && Object.hasOwn(deliveryMechanisms, String(value.delivery_mechanism))
    && Object.hasOwn(sourcePopulations, String(value.source_population))
    && Object.hasOwn(sourceAuthenticities, String(value.source_authenticity))
    && Object.hasOwn(classificationConfidences, String(value.confidence));
}
function validCommonPatterns(value: unknown): value is DDoSCommonPattern[] {
  return Array.isArray(value) && value.length <= 8 && value.every(item => plain(item)
    && onlyKeys(item, commonPatternKeys) && /^ddos-pattern-[0-9a-f]{16}$/.test(String(item.id))
    && Object.hasOwn(commonPatternTypes, String(item.type)) && safeInteger(item.support_count)
    && Number(item.support_count) <= Number.MAX_SAFE_INTEGER && typeof item.support_ratio === 'number'
    && Number.isFinite(item.support_ratio) && item.support_ratio >= 0 && item.support_ratio <= 1
    && Array.isArray(item.values) && item.values.length <= 16
    && item.values.every(entry => typeof entry === 'string' && entry.length <= 128));
}
function validPorts(value: unknown): value is number[] {
  return Array.isArray(value) && value.length <= 16
    && value.every(port => safeInteger(port) && port <= 65_535);
}
function validSignatures(value: unknown, v4 = false): value is DDoSSignatureCandidate[] {
  return Array.isArray(value) && value.length <= 4 && value.every(item => plain(item)
    && onlyKeys(item, v4 ? [...signatureKeys, 'evaluation'] : signatureKeys)
    && (!v4 || validEvaluation(item.evaluation) && item.confidence === 'low'
      && item.packet_size_range === null && Array.isArray(item.payload_prefix_hashes) && !item.payload_prefix_hashes.length
      && item.protocol === item.evaluation.predicate.protocol
      && validFlagProfile(item.tcp_flag_profile, item.evaluation.predicate.tcp_flags)
      && JSON.stringify(item.source_ports) === JSON.stringify(item.evaluation.predicate.source_ports ?? [])
      && JSON.stringify(item.destination_ports) === JSON.stringify(item.evaluation.predicate.destination_ports ?? [])
      && item.id === `ddos-sig-${sha256(canonicalPredicate(item.evaluation.predicate)).slice(0, 16)}`) && /^ddos-sig-[0-9a-f]{16}$/.test(String(item.id))
    && Object.hasOwn(signatureKinds, String(item.kind)) && ['TCP', 'UDP', 'ICMP', 'ICMPV6', 'MULTIPLE'].includes(String(item.protocol))
    && validPorts(item.source_ports) && validPorts(item.destination_ports)
    && (item.packet_size_range === null || Array.isArray(item.packet_size_range)
      && item.packet_size_range.length === 2 && item.packet_size_range.every(size => safeInteger(size) && size <= 65_535)
      && Number(item.packet_size_range[0]) <= Number(item.packet_size_range[1]))
    && Array.isArray(item.payload_prefix_hashes) && item.payload_prefix_hashes.length <= 8
    && item.payload_prefix_hashes.every(hash => typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash))
    && (item.tcp_flag_profile === null || typeof item.tcp_flag_profile === 'string' && Object.hasOwn(attackTypes, item.tcp_flag_profile))
    && Object.hasOwn(classificationConfidences, String(item.confidence))
    && Array.isArray(item.false_positive_codes) && item.false_positive_codes.length >= 1
    && knownArray(item.false_positive_codes, falsePositiveCodes, 4)
    && item.requires_human_approval === true);
}
function validMetrics(value: unknown): boolean {
  if (!plain(value) || Object.keys(value).length > 40 || !onlyKeys(value, Object.keys(metricLabels))) return false;
  return Object.entries(value).every(([key, metric]) => {
    if (key === 'amplification_ratio') return metric === null;
    if (metric == null) return true;
    if (key === 'measurement_precision') return ['PACKET', 'AGGREGATED_FLOW', 'MIXED'].includes(String(metric));
    if (key === 'direction_source') return ['OBSERVED', 'INTERNAL_CIDR'].includes(String(metric));
    if (key === 'peak_is_lower_bound' || key === 'network_identity_values_truncated') return typeof metric === 'boolean';
    if (key === 'component_types') return knownArray(metric, attackTypes, 8);
    if (typeof metric !== 'number' || !Number.isFinite(metric) || metric < 0 || metric > 1e18) return false;
    if (integerMetrics.has(key) && !Number.isSafeInteger(metric)) return false;
    if (metricMaximum[key] !== undefined && metric > metricMaximum[key]) return false;
    if (key === 'component_finding_count' && metric < 2) return false;
    return !ratioMetrics.has(key) || metric <= 1;
  });
}
export function isDDoSAttackReport(value: unknown): value is DDoSAttackReport {
  if (!plain(value) || !onlyKeys(value, reportKeys)) return false;
  const report = value as unknown as DDoSAttackReport;
  const v4 = report.version === 'ddos-attack-report-v4' && report.catalog_version === 'ddos-taxonomy-v4';
  const v3 = v4 || report.version === 'ddos-attack-report-v3' && report.catalog_version === 'ddos-taxonomy-v3';
  const v2 = report.version === 'ddos-attack-report-v2' && report.catalog_version === 'ddos-taxonomy-v2';
  const modern = v2 || v3;
  const v1 = report.version === 'ddos-attack-report-v1' && report.catalog_version === 'ddos-taxonomy-v1';
  if (!v1 && !modern) return false;
  if (v4 !== Object.hasOwn(report, 'normal_reference') || v4 && !validReference(report.normal_reference)) return false;
  if (!['attack_likely', 'suspicious_traffic', 'no_clear_attack', 'insufficient_evidence'].includes(report.verdict)
    || !['high', 'medium', 'low', 'unknown'].includes(report.confidence)) return false;
  if (!plain(report.summary) || !onlyKeys(report.summary, summaryKeys)) return false;
  const countKeys = ['scanned_records', 'evaluated_records', 'skipped_records', 'incomplete_records', 'target_count', 'finding_count', 'displayed_finding_count', 'packet_count', 'byte_count'];
  if (!countKeys.every(key => safeInteger(report.summary[key]))
    || Number(report.summary.scanned_records) > 2_000_001 || Number(report.summary.evaluated_records) > 2_000_000
    || Number(report.summary.skipped_records) > 2_000_000 || Number(report.summary.incomplete_records) > 2_000_000
    || Number(report.summary.target_count) > 4096 || Number(report.summary.finding_count) > 6144
    || Number(report.summary.displayed_finding_count) > 100 || Number(report.summary.packet_count) > Number.MAX_SAFE_INTEGER
    || Number(report.summary.byte_count) > Number.MAX_SAFE_INTEGER
    || typeof report.summary.coverage_complete !== 'boolean'
    || typeof report.summary.counts_are_lower_bounds !== 'boolean'
    || typeof report.summary.truncated !== 'boolean'
    || !(report.summary.first_seen === null || timestamps(report.summary.first_seen))
    || !(report.summary.last_seen === null || timestamps(report.summary.last_seen))
    || !(report.summary.primary_attack_type === null || typeof report.summary.primary_attack_type === 'string' && Object.hasOwn(attackTypes, report.summary.primary_attack_type))
    || !(report.summary.primary_objective === null || typeof report.summary.primary_objective === 'string' && Object.hasOwn(objectives, report.summary.primary_objective))) return false;
  const reportStart = parseDDoSTimestamp(report.summary.first_seen);
  const reportEnd = parseDDoSTimestamp(report.summary.last_seen);
  if (reportStart !== null && reportEnd !== null && reportStart > reportEnd) return false;
  const inReportWindow = (first: unknown, last: unknown): boolean => {
    const start = parseDDoSTimestamp(first), end = parseDDoSTimestamp(last);
    return start !== null && end !== null && reportStart !== null && reportEnd !== null
      && start <= end && start >= reportStart && end <= reportEnd;
  };
  if (!Array.isArray(report.findings) || report.findings.length > 100
    || !Array.isArray(report.recommendations) || report.recommendations.length > 18
    || !knownArray(report.warnings, warnings, 16) || !knownArray(report.limitations, limitations, 8)
    || !safeInteger(report.omitted_finding_count) || report.omitted_finding_count > 6144) return false;
  const ids = new Set<string>();
  if (!report.findings.every(item => plain(item) && onlyKeys(item, modern ? findingKeysV2 : findingKeysV1)
    && (!modern || (v3 ? validV3Classification(item.classification) : validClassification(item.classification))
      && validCommonPatterns(item.common_patterns) && validSignatures(item.signature_candidates, v4)
      && (!v4 || item.signature_candidates!.every(s => s.evaluation!.predicate.target_ip === item.target?.ip
        && s.evaluation!.predicate.direction === (item.attack_role === 'VICTIM_SIDE_INBOUND' ? 'INBOUND' : 'OUTBOUND')
        && (item.attack_type === 'MULTI_VECTOR' || s.evaluation!.predicate.protocol === item.protocol
          && JSON.stringify(s.evaluation!.predicate.destination_ports) === JSON.stringify(item.target?.port === null ? null : [item.target?.port])))))
    && /^ddos-[0-9a-f]{16}$/.test(item.id) && !ids.has(item.id) && Boolean(ids.add(item.id))
    && Object.hasOwn(attackTypes, item.attack_type) && Object.hasOwn(roles, item.attack_role)
    && Object.hasOwn(objectives, item.objective) && ['TCP', 'UDP', 'ICMP', 'ICMPV6', 'MULTIPLE'].includes(item.protocol)
    && ['LIKELY', 'POSSIBLE'].includes(item.likelihood)
    && ['MEDIUM', 'HIGH', 'CRITICAL'].includes(item.severity) && ['high', 'medium', 'low'].includes(item.confidence)
    && plain(item.target) && Object.keys(item.target).length === 2
    && onlyKeys(item.target, ['ip', 'port']) && Object.hasOwn(item.target, 'ip')
    && Object.hasOwn(item.target, 'port') && validIp(item.target.ip)
    && (item.target.port === null || safeInteger(item.target.port) && item.target.port <= 65535)
    && inReportWindow(item.first_seen, item.last_seen)
    && validMetrics(item.metrics) && Array.isArray(item.evidence_codes) && item.evidence_codes.length <= 8 && item.evidence_codes.every(evidenceKnown)
    && knownArray(item.uncertainty_codes, uncertainties, 8) && knownArray(item.recommendation_codes, recommendations, 8))) return false;
  if (v4) {
    let sample: string | undefined;
    for (const finding of report.findings) for (const signature of finding.signature_candidates!) {
      if (canonicalPredicate(signature.evaluation!.normal.reference) !== canonicalPredicate(report.normal_reference)) return false;
      const a = signature.evaluation!.attack;
      const packets = a.eligible_packets + a.unknown_packets;
      if (a.sampled_records + a.omitted_records !== report.summary.evaluated_records
        || packets > Number(report.summary.packet_count)
        || Number(report.summary.packet_count) - packets < a.omitted_records
        || (a.omitted_records === 0 && packets !== report.summary.packet_count)) return false;
      const identity = JSON.stringify([a.sampled_records, a.omitted_records, a.sample_bytes, a.evidence_digest, packets]);
      if (sample !== undefined && sample !== identity) return false;
      sample = identity;
    }
  }
  const baseMetrics = ['packet_count', 'byte_count', 'record_count', 'duration_seconds', 'average_packets_per_second', 'average_bits_per_second', 'peak_packets_per_second', 'peak_bits_per_second', 'peak_is_lower_bound', 'measurement_precision', 'baseline_packets_per_second', 'baseline_ratio', 'robust_z_score', 'distinct_sources', 'distinct_sensors', 'direction_source'];
  const identityMetrics = ['hop_limit_min', 'hop_limit_max', 'network_identity_observed_records', 'network_identity_anomaly_records', 'ip_id_observed_count', 'ip_id_distinct_count', 'ip_id_monotonic_ratio', 'network_identity_values_truncated'];
  const sampleLimited = new Set<string>();
  for (const item of report.findings) {
    const multi = item.attack_type === 'MULTI_VECTOR';
    const familyMetrics = multi ? ['component_types', 'component_finding_count']
      : item.attack_type.startsWith('TCP_') ? ['syn_only_ratio', 'ack_only_ratio', 'rst_ratio', 'fin_ratio', 'payload_packet_ratio', 'response_ratio']
        : ['UDP_FLOOD', 'POSSIBLE_REFLECTION_AMPLIFICATION'].includes(item.attack_type) ? ['dominant_reflection_source_port', 'reflection_source_port_ratio', 'average_packet_bytes', 'amplification_ratio']
          : ['icmp_type_observed_packets', 'icmp_echo_request_ratio'];
    const expectedMetrics = [...(multi ? [] : baseMetrics), ...familyMetrics, ...(modern && !multi ? identityMetrics : [])];
    if (Object.keys(item.metrics).length !== expectedMetrics.length
      || !expectedMetrics.every(key => Object.hasOwn(item.metrics, key))) return false;
    if (!multi) {
      const requiredValues = ['packet_count', 'byte_count', 'record_count', 'duration_seconds', 'average_packets_per_second', 'average_bits_per_second', 'peak_is_lower_bound', 'measurement_precision', 'distinct_sources', 'distinct_sensors', 'direction_source'];
      if (requiredValues.some(key => item.metrics[key] === null)) return false;
      const baselineUnavailable = item.metrics.baseline_ratio === null && item.metrics.robust_z_score === null;
      if (item.uncertainty_codes.includes('BASELINE_UNAVAILABLE') !== baselineUnavailable) return false;
      if (item.likelihood === 'LIKELY' && (baselineUnavailable
        || ['TCP_RESPONSE_VISIBILITY_UNKNOWN', 'TCP_PAYLOAD_VISIBILITY_UNKNOWN', 'SUBSTANTIAL_TCP_RESPONSES_OBSERVED']
          .some(code => item.uncertainty_codes.includes(code)))) return false;
    }
    if (multi) {
      const componentTypes = item.metrics.component_types as string[];
      if (componentTypes.length < 2 || new Set(componentTypes).size !== componentTypes.length
        || componentTypes.includes('MULTI_VECTOR')
        || Number(item.metrics.component_finding_count) < componentTypes.length) return false;
    } else if (Number(item.metrics.record_count) < 100 || Number(item.metrics.duration_seconds) < 10) {
      sampleLimited.add(item.id);
    }
    const expectedEvidence = multi ? ['OVERLAPPING_ATTACK_VECTORS']
      : ['VOLUME_GATE_MET', 'DISTRIBUTED_SOURCE_GATE_MET', `${item.attack_type}_SHAPE`];
    if (item.evidence_codes.length !== expectedEvidence.length
      || expectedEvidence.some(code => !item.evidence_codes.includes(code))) return false;
    const expectedProtocols = multi ? ['MULTIPLE'] : item.attack_type.startsWith('TCP_') ? ['TCP']
      : ['UDP_FLOOD', 'POSSIBLE_REFLECTION_AMPLIFICATION'].includes(item.attack_type) ? ['UDP'] : ['ICMP', 'ICMPV6'];
    if (!expectedProtocols.includes(item.protocol)) return false;
    const requiredUncertainty: Record<string, string[]> = {
      TCP_ACK_FLOOD: ['ACK_TRAFFIC_MAY_BE_LEGITIMATE'],
      TCP_RST_FLOOD: ['RESETS_MAY_BE_DEFENSIVE_RESPONSES'],
      POSSIBLE_REFLECTION_AMPLIFICATION: ['AMPLIFICATION_RATIO_UNOBSERVED', 'SOURCE_SPOOFING_UNCONFIRMED'],
      MULTI_VECTOR: ['SHARED_TARGET_DOES_NOT_PROVE_SHARED_ACTOR'],
    };
    const mandatoryUncertainty = requiredUncertainty[item.attack_type] ?? [];
    if (!mandatoryUncertainty.every(code => item.uncertainty_codes.includes(code))
      || multi && item.uncertainty_codes.some(code => ![
        ...mandatoryUncertainty,
        'BOTNET_ATTRIBUTION_UNCONFIRMED',
        'SOURCE_SPOOFING_NOT_CONFIRMED',
      ].includes(code))) return false;
    if (item.attack_type.startsWith('TCP_')) {
      if (['syn_only_ratio', 'ack_only_ratio', 'rst_ratio', 'fin_ratio', 'payload_packet_ratio'].some(key => item.metrics[key] === null)) return false;
      if (item.attack_type === 'TCP_SYN_FLOOD'
        && ((item.metrics.response_ratio === null) !== item.uncertainty_codes.includes('TCP_RESPONSE_VISIBILITY_UNKNOWN'))) return false;
    }
    if (['UDP_FLOOD', 'POSSIBLE_REFLECTION_AMPLIFICATION'].includes(item.attack_type)
      && ['reflection_source_port_ratio', 'average_packet_bytes'].some(key => item.metrics[key] === null)) return false;
    if (['ICMP_ECHO_FLOOD', 'ICMP_FLOOD'].includes(item.attack_type)) {
      if (item.metrics.icmp_type_observed_packets === null || item.metrics.icmp_echo_request_ratio === null) return false;
      const partialTypes = Number(item.metrics.icmp_type_observed_packets) < Number(item.metrics.packet_count);
      if (item.uncertainty_codes.includes('ICMP_TYPE_UNAVAILABLE') !== partialTypes) return false;
    }
    if (!['VICTIM_SIDE_INBOUND', 'PARTICIPANT_SIDE_OUTBOUND'].includes(item.attack_role)
      || item.attack_type === 'POSSIBLE_REFLECTION_AMPLIFICATION'
        && (item.attack_role !== 'VICTIM_SIDE_INBOUND' || item.likelihood !== 'POSSIBLE')) return false;
    if (v3) {
      const c = item.classification!;
      const e = c.evidence!;
      if ((!multi && (e.observed_sources !== item.metrics.distinct_sources || Number(e.sample_count) + Number(e.omitted_samples) + Number(e.unobserved_packets) !== Number(item.metrics.packet_count)
        || Number(e.invalid_source_records) > Number(item.metrics.record_count)
        || e.identity_variation_records !== item.metrics.network_identity_anomaly_records || e.component_count !== 0))
        || (multi && e.component_count !== item.metrics.component_finding_count)
        || (item.attack_type === 'POSSIBLE_REFLECTION_AMPLIFICATION' && Number(e.response_samples) <= Number(e.matched_response_samples))
        || item.uncertainty_codes.includes('BOTNET_ATTRIBUTION_UNCONFIRMED') !== (c.source_population === 'BOTNET_LIKE_COORDINATION')
        || item.uncertainty_codes.includes('SOURCE_SPOOFING_NOT_CONFIRMED') !== (c.source_authenticity === 'SPOOFING_SUSPECTED')
        || (!report.summary.coverage_complete && e.coverage_limited !== true)) return false;
    }
    if (v2) {
      const classification = item.classification!;
      const observed = Number(item.metrics.network_identity_observed_records ?? 0);
      const anomalies = Number(item.metrics.network_identity_anomaly_records ?? 0);
      const spoofingSuspected = observed > 0 && anomalies / observed >= 0.20;
      const componentTypes = multi ? item.metrics.component_types as string[] : [];
      const includesReflection = componentTypes.includes('POSSIBLE_REFLECTION_AMPLIFICATION');
      const expectedDelivery = multi
        ? includesReflection ? 'MIXED' : 'DIRECT_DISTRIBUTED'
        : item.attack_type === 'POSSIBLE_REFLECTION_AMPLIFICATION'
          ? 'REFLECTION_AMPLIFICATION' : 'DIRECT_DISTRIBUTED';
      const expectedPopulation = item.attack_role === 'PARTICIPANT_SIDE_OUTBOUND'
        ? 'BOTNET_LIKE_COORDINATION'
        : item.attack_type === 'POSSIBLE_REFLECTION_AMPLIFICATION'
          ? 'REFLECTOR_SET'
          : multi && includesReflection ? 'MIXED' : 'DISTRIBUTED_UNATTRIBUTED';
      const spoofingLimited = item.uncertainty_codes.includes('SOURCE_SPOOFING_NOT_CONFIRMED');
      const allowedAuthenticity = multi
        ? spoofingLimited ? ['SPOOFING_SUSPECTED', 'MIXED']
          : item.attack_role === 'PARTICIPANT_SIDE_OUTBOUND' ? ['SOURCE_CONSISTENT']
            : ['SPOOFING_UNCONFIRMED']
        : [spoofingSuspected ? 'SPOOFING_SUSPECTED'
          : item.attack_role === 'PARTICIPANT_SIDE_OUTBOUND' ? 'SOURCE_CONSISTENT'
            : 'SPOOFING_UNCONFIRMED'];
      const allowedClassificationConfidences = multi
        && item.attack_role === 'VICTIM_SIDE_INBOUND'
        && classification.source_authenticity === 'MIXED'
        ? ['low', 'medium']
        : [multi
          ? item.attack_role === 'PARTICIPANT_SIDE_OUTBOUND'
            || classification.source_authenticity === 'SPOOFING_SUSPECTED' ? 'medium' : 'low'
          : spoofingSuspected || item.attack_role === 'PARTICIPANT_SIDE_OUTBOUND'
            || item.attack_type === 'POSSIBLE_REFLECTION_AMPLIFICATION' ? 'medium' : 'low'];
      if (classification.delivery_mechanism !== expectedDelivery
        || classification.source_population !== expectedPopulation
        || !allowedAuthenticity.includes(classification.source_authenticity)
        || !allowedClassificationConfidences.includes(classification.confidence)
        || item.uncertainty_codes.includes('BOTNET_ATTRIBUTION_UNCONFIRMED')
          !== (expectedPopulation === 'BOTNET_LIKE_COORDINATION')
        || spoofingLimited !== ['SPOOFING_SUSPECTED', 'MIXED'].includes(classification.source_authenticity)) return false;
    }
    const expectedSeverity = multi && item.likelihood === 'LIKELY' ? 'CRITICAL'
      : multi || item.likelihood === 'LIKELY' ? 'HIGH' : 'MEDIUM';
    if (item.severity !== expectedSeverity) return false;
    if (multi && item.likelihood === 'POSSIBLE' && item.confidence === 'high') return false;
    if (item.evidence_codes.includes('DISTRIBUTED_SOURCE_GATE_MET')
      && Number(item.metrics.distinct_sources) < 1) return false;
    const averageBytes = Number(item.metrics.byte_count) / Math.max(1, Number(item.metrics.packet_count));
    const expectedObjective = item.attack_type === 'TCP_SYN_FLOOD' ? 'CONNECTION_STATE_EXHAUSTION'
      : ['TCP_ACK_FLOOD', 'TCP_RST_FLOOD'].includes(item.attack_type) ? 'PACKET_PROCESSING_EXHAUSTION'
        : item.attack_type === 'POSSIBLE_REFLECTION_AMPLIFICATION' ? 'REFLECTED_BANDWIDTH_EXHAUSTION'
          : multi ? 'MULTI_RESOURCE_EXHAUSTION'
            : averageBytes < 128 ? 'PACKET_PROCESSING_EXHAUSTION' : 'BANDWIDTH_EXHAUSTION';
    if (item.objective !== expectedObjective) return false;
    const identity = multi
      ? `${item.attack_role}|${item.target.ip}|MULTI_VECTOR|${[...(item.metrics.component_types as string[])].sort().join('|')}`
      : `${item.attack_role}|${item.target.ip}|${item.target.port === null ? 'None' : item.target.port}|${item.protocol}|${item.attack_type}`;
    if (item.id !== `ddos-${sha256(identity).slice(0, 16)}`) return false;
    const expectedRecommendations = [
      ...typeRecommendationCodes[item.attack_type],
      ...(item.attack_role === 'PARTICIPANT_SIDE_OUTBOUND' ? outboundRecommendationCodes : []),
      ...commonRecommendationCodes,
    ].filter((code, index, values) => values.indexOf(code) === index).slice(0, 8);
    if (item.recommendation_codes.length !== expectedRecommendations.length
      || expectedRecommendations.some((code, index) => item.recommendation_codes[index] !== code)) return false;
  }
  const actionCodes = new Set<string>();
  if (!report.recommendations.every((item, index) => plain(item) && onlyKeys(item, recommendationKeys)
    && Object.hasOwn(recommendations, item.code) && !actionCodes.has(item.code) && Boolean(actionCodes.add(item.code))
    && item.priority === index + 1 && item.scope === (upstreamActions.has(item.code) ? 'UPSTREAM' : 'LOCAL') && item.requires_human_approval === true
    && item.rationale_code === `${item.code}_RATIONALE` && item.caveat_code === `${item.code}_CAVEAT`)) return false;
  const referenced = new Set(report.findings.flatMap(item => item.recommendation_codes));
  if (report.findings.some(item => item.evidence_codes.length !== new Set(item.evidence_codes).size
    || item.uncertainty_codes.length !== new Set(item.uncertainty_codes).size
    || item.recommendation_codes.length !== new Set(item.recommendation_codes).size)) return false;
  if (referenced.size !== actionCodes.size || [...referenced].some(code => !actionCodes.has(code))) return false;
  if ((report.findings.length > 0) !== (typeof report.primary_finding_id === 'string' && ids.has(report.primary_finding_id))) return false;
  const primary = report.findings.find(item => item.id === report.primary_finding_id);
  if ((primary?.attack_type ?? null) !== report.summary.primary_attack_type
    || (primary?.objective ?? null) !== report.summary.primary_objective) return false;
  if (Number(report.summary.evaluated_records) + Number(report.summary.skipped_records)
      > Number(report.summary.scanned_records)
    || report.summary.finding_count !== report.findings.length + report.omitted_finding_count
    || report.summary.displayed_finding_count !== report.findings.length) return false;
  const baseFindings = report.findings.filter(item => item.attack_type !== 'MULTI_VECTOR');
  const baseTargets = new Set(baseFindings.map(item => `${item.attack_role}|${item.target.ip}|${item.target.port}|${item.protocol}`));
  if (baseTargets.size > Number(report.summary.target_count)
    || baseFindings.reduce((total, item) => total + Number(item.metrics.packet_count), 0) > Number(report.summary.packet_count)
    || baseFindings.reduce((total, item) => total + Number(item.metrics.byte_count), 0) > Number(report.summary.byte_count)) return false;
  const warningCodes = new Set(report.warnings);
  const lowerBoundCodes = new Set(['INPUT_RECORD_LIMIT_REACHED', 'TARGET_LIMIT_REACHED', 'BUCKET_LIMIT_REACHED', 'FINDING_LIMIT_REACHED', 'PARSER_SKIPPED_PACKETS', 'SENSOR_DROPS_REPORTED', 'PARTIAL_CAPTURE']);
  const coverageCodes = new Set([...lowerBoundCodes, 'SENSOR_CLOCK_SKEW', 'SENSOR_CAPTURE_QUALITY_UNAVAILABLE', 'DUPLICATE_CAPTURE_NOT_EXCLUDED']);
  const expectedLowerBound = [...lowerBoundCodes].some(code => warningCodes.has(code))
    || Number(report.summary.skipped_records) > 0 || Number(report.summary.incomplete_records) > 0;
  const expectedCoverage = Number(report.summary.evaluated_records) > 0
    && Number(report.summary.skipped_records) === 0 && Number(report.summary.incomplete_records) === 0
    && ![...coverageCodes].some(code => warningCodes.has(code));
  if (report.summary.counts_are_lower_bounds !== expectedLowerBound || report.summary.coverage_complete !== expectedCoverage
    || report.summary.truncated !== (report.omitted_finding_count > 0 || expectedLowerBound)) return false;
  const mandatoryLimitations = Object.keys(limitations);
  if (report.warnings.length !== new Set(report.warnings).size
    || report.limitations.length !== mandatoryLimitations.length
    || new Set(report.limitations).size !== mandatoryLimitations.length
    || mandatoryLimitations.some(code => !report.limitations.includes(code))) return false;
  const evidenceLimited = !expectedCoverage;
  const hasLikely = report.findings.some(item => item.likelihood === 'LIKELY');
  if (hasLikely && (evidenceLimited || report.findings.some(item => item.likelihood === 'LIKELY' && sampleLimited.has(item.id)))) return false;
  const expectedVerdict = report.findings.length
    ? (hasLikely ? 'attack_likely' : 'suspicious_traffic')
    : expectedCoverage && !warningCodes.has('SAMPLE_WINDOW_SHORT') && !warningCodes.has('DOS_LIKE_TRAFFIC')
      ? 'no_clear_attack' : 'insufficient_evidence';
  const expectedConfidence = expectedVerdict === 'attack_likely' ? 'high'
    : expectedVerdict === 'suspicious_traffic' ? (evidenceLimited || report.findings.every(item => item.confidence === 'low') ? 'low' : 'medium')
      : expectedVerdict === 'no_clear_attack' ? 'low' : 'unknown';
  if (report.verdict !== expectedVerdict || report.confidence !== expectedConfidence
    || report.findings.some(item => {
      const expected = evidenceLimited || sampleLimited.has(item.id) ? 'low'
        : item.likelihood === 'LIKELY' ? 'high' : item.attack_type === 'MULTI_VECTOR' ? item.confidence : 'medium';
      return item.confidence !== expected;
    })) return false;
  return 120 + Math.min(8, report.findings.length) * 16 + report.recommendations.length * 2
    + report.warnings.length * 2 + report.limitations.length * 2 <= 500;
}
