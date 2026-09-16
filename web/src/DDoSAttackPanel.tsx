import { useEffect, useState } from 'react';
import ReportLanguageScope from './ReportLanguage';
import { useReportLanguage } from './reportLanguageContext';
import {
  attackTypes, choose, limitations, metricLabels, objectives, recommendationCaveats,
  recommendations, recommendationScopes, roles,
  uncertainties, warnings,
} from './ddosReportTranslations';

export type DDoSRecommendation = {
  code: string; priority: number; scope: string; rationale_code: string; caveat_code: string;
  requires_human_approval: boolean;
};
export type DDoSFinding = {
  id: string; attack_type: string; attack_role: string; target: { ip: string; port: number | null };
  protocol: string; objective: string; likelihood: string; severity: string; confidence: string;
  first_seen: string; last_seen: string; metrics: Record<string, unknown>; evidence_codes: string[];
  uncertainty_codes: string[]; recommendation_codes: string[];
};
export type DDoSAttackReport = {
  version: string; catalog_version: string; verdict: string; confidence: string;
  primary_finding_id: string | null; summary: Record<string, unknown>; findings: DDoSFinding[];
  recommendations: DDoSRecommendation[]; warnings: string[]; limitations: string[];
  omitted_finding_count: number;
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
const timestamps = (value: unknown) => typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value));
const reportKeys = ['version', 'catalog_version', 'verdict', 'confidence', 'primary_finding_id', 'summary', 'findings', 'recommendations', 'warnings', 'limitations', 'omitted_finding_count'] as const;
const findingKeys = ['id', 'attack_type', 'attack_role', 'target', 'protocol', 'objective', 'likelihood', 'severity', 'confidence', 'first_seen', 'last_seen', 'metrics', 'evidence_codes', 'uncertainty_codes', 'recommendation_codes'] as const;
const recommendationKeys = ['code', 'priority', 'scope', 'rationale_code', 'caveat_code', 'requires_human_approval'] as const;
const summaryKeys = ['scanned_records', 'evaluated_records', 'skipped_records', 'incomplete_records', 'target_count', 'finding_count', 'displayed_finding_count', 'packet_count', 'byte_count', 'first_seen', 'last_seen', 'coverage_complete', 'counts_are_lower_bounds', 'truncated', 'primary_attack_type', 'primary_objective'] as const;
const ratioMetrics = new Set(['syn_only_ratio', 'ack_only_ratio', 'rst_ratio', 'fin_ratio', 'payload_packet_ratio', 'response_ratio', 'reflection_source_port_ratio', 'icmp_echo_request_ratio']);
const integerMetrics = new Set(['packet_count', 'byte_count', 'record_count', 'distinct_sources', 'distinct_sensors', 'dominant_reflection_source_port', 'icmp_type_observed_packets', 'component_finding_count']);
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
const sha256 = (text: string) => {
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
  component_finding_count: 4096,
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
function validMetrics(value: unknown): boolean {
  if (!plain(value) || Object.keys(value).length > 28 || !onlyKeys(value, Object.keys(metricLabels))) return false;
  return Object.entries(value).every(([key, metric]) => {
    if (key === 'amplification_ratio') return metric === null;
    if (metric == null) return true;
    if (key === 'measurement_precision') return ['PACKET', 'AGGREGATED_FLOW', 'MIXED'].includes(String(metric));
    if (key === 'direction_source') return ['OBSERVED', 'INTERNAL_CIDR'].includes(String(metric));
    if (key === 'peak_is_lower_bound') return typeof metric === 'boolean';
    if (key === 'component_types') return knownArray(metric, attackTypes, 8);
    if (typeof metric !== 'number' || !Number.isFinite(metric) || metric < 0 || metric > 1e18) return false;
    if (integerMetrics.has(key) && !Number.isSafeInteger(metric)) return false;
    if (metricMaximum[key] !== undefined && metric > metricMaximum[key]) return false;
    if (key === 'component_finding_count' && metric < 2) return false;
    return !ratioMetrics.has(key) || metric <= 1;
  });
}
function isDDoSAttackReport(value: unknown): value is DDoSAttackReport {
  if (!plain(value) || !onlyKeys(value, reportKeys)) return false;
  const report = value as unknown as DDoSAttackReport;
  if (report.version !== 'ddos-attack-report-v1' || report.catalog_version !== 'ddos-taxonomy-v1') return false;
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
  if (!Array.isArray(report.findings) || report.findings.length > 100
    || !Array.isArray(report.recommendations) || report.recommendations.length > 18
    || !knownArray(report.warnings, warnings, 16) || !knownArray(report.limitations, limitations, 8)
    || !safeInteger(report.omitted_finding_count) || report.omitted_finding_count > 6144) return false;
  const ids = new Set<string>();
  if (!report.findings.every(item => plain(item) && onlyKeys(item, findingKeys)
    && /^ddos-[0-9a-f]{16}$/.test(item.id) && !ids.has(item.id) && Boolean(ids.add(item.id))
    && Object.hasOwn(attackTypes, item.attack_type) && Object.hasOwn(roles, item.attack_role)
    && Object.hasOwn(objectives, item.objective) && ['TCP', 'UDP', 'ICMP', 'ICMPV6', 'MULTIPLE'].includes(item.protocol)
    && ['LIKELY', 'POSSIBLE'].includes(item.likelihood)
    && ['MEDIUM', 'HIGH', 'CRITICAL'].includes(item.severity) && ['high', 'medium', 'low'].includes(item.confidence)
    && plain(item.target) && Object.keys(item.target).length === 2
    && onlyKeys(item.target, ['ip', 'port']) && Object.hasOwn(item.target, 'ip')
    && Object.hasOwn(item.target, 'port') && validIp(item.target.ip)
    && (item.target.port === null || safeInteger(item.target.port) && item.target.port <= 65535)
    && timestamps(item.first_seen) && timestamps(item.last_seen) && Date.parse(item.first_seen) <= Date.parse(item.last_seen)
    && validMetrics(item.metrics) && Array.isArray(item.evidence_codes) && item.evidence_codes.length <= 8 && item.evidence_codes.every(evidenceKnown)
    && knownArray(item.uncertainty_codes, uncertainties, 8) && knownArray(item.recommendation_codes, recommendations, 8))) return false;
  const baseMetrics = ['packet_count', 'byte_count', 'record_count', 'duration_seconds', 'average_packets_per_second', 'average_bits_per_second', 'peak_packets_per_second', 'peak_bits_per_second', 'peak_is_lower_bound', 'measurement_precision', 'baseline_packets_per_second', 'baseline_ratio', 'robust_z_score', 'distinct_sources', 'distinct_sensors', 'direction_source'];
  const sampleLimited = new Set<string>();
  for (const item of report.findings) {
    const multi = item.attack_type === 'MULTI_VECTOR';
    const familyMetrics = multi ? ['component_types', 'component_finding_count']
      : item.attack_type.startsWith('TCP_') ? ['syn_only_ratio', 'ack_only_ratio', 'rst_ratio', 'fin_ratio', 'payload_packet_ratio', 'response_ratio']
        : ['UDP_FLOOD', 'POSSIBLE_REFLECTION_AMPLIFICATION'].includes(item.attack_type) ? ['dominant_reflection_source_port', 'reflection_source_port_ratio', 'average_packet_bytes', 'amplification_ratio']
          : ['icmp_type_observed_packets', 'icmp_echo_request_ratio'];
    const expectedMetrics = [...(multi ? [] : baseMetrics), ...familyMetrics];
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
      || multi && (item.uncertainty_codes.length !== mandatoryUncertainty.length)) return false;
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
    || baseFindings.reduce((total, item) => total + Number(item.metrics.byte_count), 0) > Number(report.summary.byte_count)
    || report.findings.length > 0 && (report.summary.first_seen === null || report.summary.last_seen === null
      || report.findings.some(item => Date.parse(item.first_seen) < Date.parse(String(report.summary.first_seen))
        || Date.parse(item.last_seen) > Date.parse(String(report.summary.last_seen))))) return false;
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
function format(value: unknown, language: 'ko' | 'en'): string {
  if (value == null) return language === 'ko' ? '관찰되지 않음' : 'Not observed';
  if (typeof value === 'number' && Number.isFinite(value)) return value.toLocaleString('en-US', { maximumFractionDigits: 20 });
  if (typeof value === 'string' && value.length <= 80) return value;
  if (typeof value === 'boolean') return value ? (language === 'ko' ? '예' : 'Yes') : (language === 'ko' ? '아니요' : 'No');
  if (Array.isArray(value) && value.length <= 8 && value.every(item => typeof item === 'string')) return value.join(', ');
  return language === 'ko' ? '표시할 수 없음' : 'Unavailable';
}

function Content({ report, detailOwner, setDetailOwner, ownerPrefix }: {
  report: DDoSAttackReport;
  detailOwner: string | undefined;
  setDetailOwner: (owner: string | undefined) => void;
  ownerPrefix: string;
}) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [page, setPage] = useState(0);
  if (!isDDoSAttackReport(report)) return <section className="panel ddos-report" role="alert">{t('Unsupported DDoS report. Review coverage and update the client.', '지원되지 않는 DDoS 보고서입니다. 분석 범위를 확인하고 클라이언트를 업데이트하세요.')}</section>;
  const coverageKey = `${ownerPrefix}:coverage`;
  const coverageOpen = detailOwner === coverageKey;
  const findings = report.findings;
  const primary = findings.find(item => item.id === report.primary_finding_id) ?? findings[0];
  const actionByCode = new Map(report.recommendations.map(item => [item.code, item]));
  const priorityActions = (primary?.recommendation_codes ?? []).map(code => actionByCode.get(code)).filter(Boolean).slice(0, 3) as DDoSRecommendation[];
  const heading = report.verdict === 'attack_likely' ? t('DDoS attack likely', 'DDoS 공격 가능성 높음')
    : report.verdict === 'suspicious_traffic' ? t('Suspicious DDoS-shaped traffic observed', '의심스러운 DDoS 형태 관찰')
      : report.verdict === 'no_clear_attack' && report.summary.coverage_complete === true ? t('No clear DDoS attack observed', '뚜렷한 DDoS 공격 징후 없음')
        : t('Insufficient evidence for a DDoS conclusion', 'DDoS 결론을 위한 증거 부족');
  const visible = findings.slice(page * 8, page * 8 + 8);
  const pageCount = Math.max(1, Math.ceil(findings.length / 8));
  return <section className="panel ddos-report" aria-labelledby="ddos-heading">
    <section className="network-glance ddos-glance" role="region" aria-label={t('DDoS at a glance', 'DDoS 한눈에 보기')}>
      <p className="eyebrow">DDoS ATTACK TRAFFIC REPORT</p><h2 id="ddos-heading">{heading}</h2>
      <p>{report.verdict === 'no_clear_attack' ? t('No supported DDoS shape was observed; this does not prove a healthy service.', '지원되는 DDoS 형태가 관찰되지 않았지만 서비스가 정상임을 입증하지는 않습니다.') : t('This is a defensive traffic-shape assessment, not actor attribution or proof of service impact.', '이는 방어 목적의 트래픽 형태 평가이며 공격자 귀속이나 서비스 영향의 입증이 아닙니다.')}</p>
      {primary && <div className="ddos-primary"><h3>{choose(language, attackTypes[primary.attack_type])}</h3>
        <p><strong>{t('Observed role', '관찰 역할')}</strong> — {choose(language, roles[primary.attack_role])}</p>
        <p><strong>{t('Target', '대상')}</strong> — <code>{primary.target.ip}{primary.target.port == null ? '' : `:${primary.target.port}`}</code> · {primary.protocol}</p>
        <p><strong>{t('Likely defensive objective — hypothesis', '추정 방어 목적 — 가설')}</strong> — {choose(language, objectives[primary.objective])}</p>
        <h3>{t('Priority response', '우선 대응')}</h3><ol>{priorityActions.map(item => <li key={item.code}>{choose(language, recommendations[item.code])} <small>{choose(language, recommendationScopes[item.scope])} · {choose(language, recommendationCaveats[item.code])} · {t('Human approval required', '운영자 승인 필요')}</small></li>)}</ol>
      </div>}
      {(report.warnings.length > 0 || report.summary.coverage_complete !== true) && <p className="warning">{t('Coverage is incomplete or qualified; absence of additional findings is not a clean result.', '분석 범위가 불완전하거나 조건부입니다. 추가 발견이 없더라도 정상 결과로 해석할 수 없습니다.')}</p>}
    </section>
    <button type="button" className="secondary" aria-expanded={coverageOpen} onClick={() => setDetailOwner(coverageOpen ? undefined : coverageKey)}>{t('Analysis coverage and limitations', '분석 범위와 한계')}</button>
    {coverageOpen && <section role="region" aria-label={t('DDoS analysis coverage', 'DDoS 분석 범위')}><h3>{t('Coverage and limitations', '분석 범위 및 한계')}</h3>
      <p>{format(report.summary.evaluated_records, language)} {t('records evaluated', '개 레코드 평가')} · {format(report.summary.skipped_records, language)} {t('skipped', '개 제외')} · {format(report.summary.incomplete_records, language)} {t('incomplete', '개 불완전')}</p>
      <ul>{report.warnings.map(code => <li key={code}>{choose(language, warnings[code])} <code>{code}</code></li>)}{report.limitations.map(code => <li key={code}>{choose(language, limitations[code])}</li>)}</ul>
    </section>}
    <h3>{t('Attack findings', '공격 발견 항목')}</h3>
    {!findings.length && <p>{t('No DDoS finding was retained. Check coverage before interpreting this result.', '보존된 DDoS 발견 항목이 없습니다. 결과 해석 전 분석 범위를 확인하세요.')}</p>}
    {visible.map(item => {
      const findingKey = `${ownerPrefix}:finding:${item.id}`;
      const open = detailOwner === findingKey;
      return <article className="panel compact" key={item.id}><h4>{choose(language, attackTypes[item.attack_type])}</h4>
        <p><span className={`badge ${item.severity.toLowerCase()}`}>{item.likelihood} · {item.severity}</span> <code>{item.target.ip}{item.target.port == null ? '' : `:${item.target.port}`}</code></p>
        <p>{choose(language, objectives[item.objective])}</p>
        <button className="secondary" aria-expanded={open} onClick={() => setDetailOwner(open ? undefined : findingKey)}>{open ? t('Hide detailed evidence', '상세 근거 숨기기') : t('Show detailed evidence', '상세 근거 보기')} — {choose(language, attackTypes[item.attack_type])}</button>
        {open && <section role="region" aria-label={t('DDoS finding evidence', 'DDoS 발견 근거')}>
          <h5>{t('Measured facts', '측정 사실')}</h5><dl>{Object.entries(item.metrics).map(([key, value]) => <div key={key}><dt>{choose(language, metricLabels[key])}</dt><dd>{format(value, language)}</dd></div>)}</dl>
          <h5>{t('Uncertainty', '불확실성')}</h5><ul>{item.uncertainty_codes.map(code => <li key={code}>{choose(language, uncertainties[code])}</li>)}</ul>
          <h5>{t('Recommended responses', '권장 대응')}</h5><ul>{item.recommendation_codes.map(code => { const action = actionByCode.get(code)!; return <li key={code}>{choose(language, recommendations[code])} — {choose(language, recommendationScopes[action.scope])} — {choose(language, recommendationCaveats[code])} — {t('Human approval required', '운영자 승인 필요')}</li>; })}</ul>
          <p>{t('Observed time', '관찰 시각')}: {item.first_seen} → {item.last_seen}</p>
        </section>}
      </article>;
    })}
    {pageCount > 1 && <nav className="pagination" aria-label={t('DDoS finding pages', 'DDoS 발견 항목 페이지')}><button className="secondary" disabled={page === 0} onClick={() => { setPage(page - 1); setDetailOwner(undefined); }}>{t('Previous', '이전')}</button><span role="status" aria-live="polite">{page + 1} / {pageCount}</span><button className="secondary" disabled={page + 1 >= pageCount} onClick={() => { setPage(page + 1); setDetailOwner(undefined); }}>{t('Next', '다음')}</button></nav>}
  </section>;
}

export default function DDoSAttackPanel({ report, detailOwner, setDetailOwner }: {
  report: DDoSAttackReport;
  detailOwner?: string;
  setDetailOwner?: (owner: string | undefined) => void;
}) {
  const [localOwner, setLocalOwner] = useState<string>();
  useEffect(() => {
    (setDetailOwner ?? setLocalOwner)(undefined);
  }, [report, setDetailOwner]);
  const signature = `${report.version}:${report.primary_finding_id ?? 'none'}:${String(report.summary?.finding_count ?? 'unknown')}`;
  return <ReportLanguageScope><Content
    report={report}
    detailOwner={setDetailOwner ? detailOwner : localOwner}
    setDetailOwner={setDetailOwner ?? setLocalOwner}
    ownerPrefix={`ddos:${signature}`}
  /></ReportLanguageScope>;
}
