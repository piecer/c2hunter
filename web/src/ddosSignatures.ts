export type MatchResult = {
  matched_records: number; eligible_records: number; unknown_records: number;
  matched_packets: number; eligible_packets: number; unknown_packets: number;
  record_match_rate: number | null; packet_match_rate: number | null;
  sampled_records: number; omitted_records: number; sample_bytes: number;
  record_limit: number; byte_limit: number; evidence_refs: string[]; evidence_digest: string;
};
export type Evaluation = {
  predicate: { target_ip: string; direction: string; protocol: string; source_ports: number[] | null;
    destination_ports: number[] | null; tcp_flags: Record<string, number> | null; length: { field: string; minimum: number; maximum: number } | null; protocol_fields: Record<string, number> };
  attack: MatchResult;
  normal: { status: string; result: MatchResult | null; reference: {
    coverage_limited: true; job_id: string; dataset_id: string; content_digest: string; record_count: number; selected_by: string; selected_at: string;
  } | null };
  confidence_basis: string; approval_conditions: string[]; exclusions: string[];
  invalidation: string[]; supported_export_targets: string[]; automatic_enforcement: false;
};
const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const keys = (v: Record<string, unknown>, names: string[]) => Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const hash = (v: unknown) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
export function canonicalPredicate(value: unknown): string {
  if (!object(value)) return JSON.stringify(value);
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalPredicate(value[k])}`).join(',')}}`;
}
export function validFlagProfile(profile: unknown, flags: unknown): boolean {
  const conditions: Record<string, Record<string, number>> = {
    TCP_SYN_FLOOD: { syn: 1, ack: 0 }, TCP_ACK_FLOOD: { syn: 0, ack: 1, rst: 0 },
    TCP_RST_FLOOD: { rst: 1 }, TCP_FIN_FLOOD: { fin: 1 },
  };
  const expected = typeof profile === 'string' && Object.hasOwn(conditions, profile) ? conditions[profile] : null;
  return canonicalPredicate(flags) === canonicalPredicate(expected);
}
function counts(value: unknown): value is MatchResult {
  if (!object(value) || !keys(value, ['matched_records', 'eligible_records', 'unknown_records', 'matched_packets', 'eligible_packets', 'unknown_packets', 'record_match_rate', 'packet_match_rate', 'sampled_records', 'omitted_records', 'sample_bytes', 'record_limit', 'byte_limit', 'evidence_refs', 'evidence_digest'])) return false;
  const c = value as unknown as MatchResult;
  if (!['matched_records', 'eligible_records', 'unknown_records', 'matched_packets', 'eligible_packets', 'unknown_packets', 'sampled_records', 'omitted_records', 'sample_bytes'].every(k => integer(value[k]))
    || c.record_limit !== 512 || c.byte_limit !== 262144 || c.sample_bytes < 2 || c.sample_bytes > c.byte_limit
    || c.sampled_records > c.record_limit || c.sampled_records !== c.eligible_records + c.unknown_records || !hash(c.evidence_digest)) return false;
  for (const unit of ['records', 'packets'] as const) {
    const matched = c[`matched_${unit}`], eligible = c[`eligible_${unit}`];
    const rate = unit === 'records' ? c.record_match_rate : c.packet_match_rate;
    if (matched > eligible || rate !== (eligible ? matched / eligible : null)) return false;
  }
  for (const state of ['matched', 'eligible', 'unknown'] as const) {
    if (c[`${state}_packets`] < c[`${state}_records`] || (c[`${state}_packets`] === 0) !== (c[`${state}_records`] === 0)) return false;
  }
  const unmatchedRecords = c.eligible_records - c.matched_records;
  const unmatchedPackets = c.eligible_packets - c.matched_packets;
  if (unmatchedPackets < unmatchedRecords || (unmatchedRecords === 0) !== (unmatchedPackets === 0)) return false;
  if (!Array.isArray(c.evidence_refs) || c.evidence_refs.length !== Math.min(8, c.matched_records)
    || !c.evidence_refs.every(ref => typeof ref === 'string' && /^(0|[1-9][0-9]{0,2}):[0-9a-f]{64}$/.test(ref) && Number(ref.split(':')[0]) < c.sampled_records)) return false;
  return new Set(c.evidence_refs.map(ref => ref.split(':')[0])).size === c.evidence_refs.length;
}
export function validEvaluation(value: unknown): value is Evaluation {
  if (!object(value) || !keys(value, ['predicate', 'attack', 'normal', 'confidence_basis', 'approval_conditions', 'exclusions', 'invalidation', 'supported_export_targets', 'automatic_enforcement'])) return false;
  const e = value as unknown as Evaluation, p = e.predicate, n = e.normal;
  if (!object(p) || !keys(p, ['target_ip', 'direction', 'protocol', 'source_ports', 'destination_ports', 'tcp_flags', 'length', 'protocol_fields'])
    || typeof p.target_ip !== 'string' || p.target_ip.length > 45 || !['INBOUND', 'OUTBOUND'].includes(p.direction)
    || !['TCP', 'UDP', 'ICMP', 'ICMPV6'].includes(p.protocol) || !object(p.protocol_fields)) return false;
  if (p.length !== null && (!object(p.length) || !keys(p.length, ['field', 'minimum', 'maximum'])
    || !['CAPTURED_FRAME_BYTES', 'IP_BYTES', 'TRANSPORT_PAYLOAD_BYTES'].includes(p.length.field)
    || !integer(p.length.minimum) || !integer(p.length.maximum) || p.length.maximum > 65535 || p.length.minimum > p.length.maximum)) return false;
  if (Object.keys(p.protocol_fields).length && (!['ICMP', 'ICMPV6'].includes(p.protocol) || !keys(p.protocol_fields, ['icmp_type']) || !integer(p.protocol_fields.icmp_type) || p.protocol_fields.icmp_type > 255)) return false;
  for (const ports of [p.source_ports, p.destination_ports]) {
    if (ports !== null && (!Array.isArray(ports) || !ports.length || ports.length > 16
      || !ports.every((port, i) => integer(port) && port <= 65535 && (!i || ports[i - 1] < port)))) return false;
  }
  if (p.tcp_flags !== null && (p.protocol !== 'TCP' || !object(p.tcp_flags) || !Object.keys(p.tcp_flags).length
    || !Object.entries(p.tcp_flags).every(([k, v]) => ['syn', 'ack', 'rst', 'fin'].includes(k) && (v === 0 || v === 1)))) return false;
  if (!counts(e.attack) || !object(n) || !keys(n, ['status', 'result', 'reference'])) return false;
  if (n.status === 'UNMEASURED') { if (n.result !== null || n.reference !== null) return false; }
  else if (n.status === 'MEASURED') {
    const r = n.reference;
    if (!counts(n.result) || !validReference(r) || r === null
      || r.record_count !== n.result.sampled_records || r.content_digest !== n.result.evidence_digest || n.result.omitted_records !== 0) return false;
  } else return false;
  return e.confidence_basis === 'RETAINED_EVIDENCE_NOT_ATTACK_PROBABILITY' && e.automatic_enforcement === false
    && same(e.approval_conditions, ['VERIFY_TARGET_OWNERSHIP', 'REVIEW_NORMAL_TRAFFIC', 'HUMAN_APPROVAL'])
    && same(e.exclusions, ['LEGITIMATE_SHARED_SERVICES', 'INCOMPLETE_OBSERVATIONS'])
    && same(e.invalidation, ['DATASET_OR_TOPOLOGY_CHANGE', 'REVALIDATE_BEFORE_EACH_USE'])
    && same(e.supported_export_targets, ['STRUCTURED_JSON']);
}

export function validReference(r: unknown): r is Evaluation['normal']['reference'] {
  return r === null || object(r) && keys(r, ['job_id', 'dataset_id', 'content_digest', 'record_count', 'selected_by', 'selected_at', 'coverage_limited'])
    && r.coverage_limited === true
    && (['job_id', 'dataset_id', 'selected_by', 'selected_at'] as const).every(k => typeof r[k] === 'string' && (r[k] as string).length > 0 && (r[k] as string).length <= ({ selected_by: 128, selected_at: 64, job_id: 200, dataset_id: 200 }[k]))
    && hash(r.content_digest) && integer(r.record_count) && r.record_count >= 1 && r.record_count <= 512;
}
