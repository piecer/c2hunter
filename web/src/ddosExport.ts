import { isDDoSAttackReport, sha256 } from './ddosReportContract';
import { type Evaluation, validEvaluation } from './ddosSignatures';

export type ExportJob = { id: string; dataset_id?: string; source_type?: string; internal_networks?: string[]; source?: { sha256?: string; link_types?: number[] } };
type Selection = { version: 'ddos-packet-selection-v1'; status: 'REFUSED' | 'EXACT_OFFLINE'; reason: string; expression?: string; capture_sha256?: string; link_type?: number; internal_networks?: string[] };
const encoder = new TextEncoder();
export const DDOS_EXPORT_MAX_BYTES = 65536;

// Validate data descriptors before invoking any report guard or encoder. No raw
// report clone, getter, toJSON hook, private reference or arbitrary job metadata.
function boundedData(value: unknown, maxBytes: number, optionalValues = false): boolean {
  let bytes = 0, nodes = 0;
  const seen = new Set<object>();
  const visit = (v: unknown, depth: number): boolean => {
    if (++nodes > 100000 || depth > 16) return false;
    if (v === undefined) return optionalValues;
    if (v === null || typeof v === 'boolean') return true;
    if (typeof v === 'number') return Number.isFinite(v);
    if (typeof v === 'string') {
      if (v.length > maxBytes) return false;
      bytes += encoder.encode(v).length;
      return bytes <= maxBytes;
    }
    if (typeof v !== 'object' || seen.has(v)) return false;
    seen.add(v);
    if (Object.getPrototypeOf(v) !== (Array.isArray(v) ? Array.prototype : Object.prototype)) return false;
    const keys = Reflect.ownKeys(v);
    if (keys.length > 10000) return false;
    for (const key of keys) {
      if (typeof key !== 'string' || key === 'toJSON') return false;
      if (Array.isArray(v) && key === 'length') continue;
      const descriptor = Object.getOwnPropertyDescriptor(v, key)!;
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || !visit(key, depth + 1) || !visit(descriptor.value, depth + 1)) return false;
    }
    return !Array.isArray(v) || keys.length === v.length + 1;
  };
  return visit(value, 0);
}
function ipv4(value: string): number | null {
  if (!/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(value)) return null;
  const octets = value.split('.').map(Number);
  return octets.some(n => n > 255) ? null : octets.reduce((total, n) => total * 256 + n, 0);
}
export function passiveSelection(predicate: Evaluation['predicate'], job: ExportJob): Selection {
  const refuse = (reason: string): Selection => ({ version: 'ddos-packet-selection-v1', status: 'REFUSED', reason });
  if (!boundedData(predicate, 8192) || !boundedData(job, 16384, true)) return refuse('INVALID_CONTEXT');
  const fields = ['target_ip', 'direction', 'protocol', 'source_ports', 'destination_ports', 'tcp_flags', 'length', 'protocol_fields'];
  if (!predicate || typeof predicate !== 'object' || Object.keys(predicate).length !== fields.length || !fields.every(key => Object.hasOwn(predicate, key)) || typeof predicate.target_ip !== 'string' || !predicate.protocol_fields || typeof predicate.protocol_fields !== 'object' || Array.isArray(predicate.protocol_fields)) return refuse('INVALID_PREDICATE');
  if (job.source_type !== 'PCAP_UPLOAD' || !/^[0-9a-f]{64}$/.test(job.source?.sha256 ?? '')) return refuse('UPLOADED_CAPTURE_IDENTITY_REQUIRED');
  if (predicate.protocol !== 'UDP' || predicate.tcp_flags !== null || predicate.length !== null || Object.keys(predicate.protocol_fields).length) return refuse('OBSERVATION_DEPENDENT_OR_UNSUPPORTED_CONDITIONS');
  const target = ipv4(predicate.target_ip);
  if (target === null) return refuse('IPV4_UDP_ONLY');
  if (!['INBOUND', 'OUTBOUND'].includes(predicate.direction)) return refuse('DIRECTION_UNSUPPORTED');
  const links = job.source?.link_types;
  if (!links || links.length !== 1 || ![1, 101].includes(links[0])) return refuse('ETHERNET_OR_RAW_IPV4_CAPTURE_REQUIRED');
  const networks = job.internal_networks;
  if (!Array.isArray(networks) || !networks.length || networks.length > 32 || networks.some(n => typeof n !== 'string' || n.length > 200)) return refuse('BOUNDED_IPV4_NETWORK_CONTEXT_REQUIRED');
  const cidrs: { address: number; mask: number }[] = [];
  for (const network of networks) {
    const pieces = network.split('/');
    const address = ipv4(pieces[0]);
    const prefix = pieces.length === 1 ? 32 : Number(pieces[1]);
    if (pieces.length > 2 || address === null || pieces.length === 2 && !/^(0|[1-9][0-9]?)$/.test(pieces[1]) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return refuse('BOUNDED_IPV4_NETWORK_CONTEXT_REQUIRED');
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    cidrs.push({ address: (address & mask) >>> 0, mask });
  }
  for (const ports of [predicate.source_ports, predicate.destination_ports]) {
    if (ports !== null && (!Array.isArray(ports) || !ports.length || ports.length > 16 || ports.some(p => !Number.isInteger(p) || p < 0 || p > 65535))) return refuse('PORT_CONDITION_UNSUPPORTED');
  }
  const tag = (offset: number) => `(${[0x8100, 0x88a8, 0x9100].map(n => `link[${offset}:2] = ${n}`).join(' or ')})`;
  const branches = links[0] === 101 ? [{ offset: 0, guard: '' }] : [
    { offset: 14, guard: 'link[12:2] = 2048' },
    { offset: 18, guard: `${tag(12)} and link[16:2] = 2048` },
    { offset: 22, guard: `${tag(12)} and ${tag(16)} and link[20:2] = 2048` },
  ];
  const expression = branches.map(({ offset: o, guard }) => {
    const header = `((link[${o}] & 15) * 4)`;
    const src = `(${cidrs.map(c => `(link[${o + 12}:4] & ${c.mask}) = ${c.address}`).join(' or ')})`;
    const dst = `(${cidrs.map(c => `(link[${o + 16}:4] & ${c.mask}) = ${c.address}`).join(' or ')})`;
    const parts = [guard, `(link[${o}] & 240) = 64`, `${header} >= 20`, `link[${o + 2}:2] >= ${header}`, `link[${o} + ${header} - 1] >= 0`, `link[${o + 9}] = 17`, `link[${o + 16}:4] = ${target}`, predicate.direction === 'INBOUND' ? `${dst} and not ${src}` : `${src} and not ${dst}`].filter(Boolean);
    if (predicate.source_ports !== null || predicate.destination_ports !== null) {
      // _decode_ipv4/_transport: first fragment, >=8 captured UDP bytes within
      // IP total_length. Do NOT require complete datagrams or use BPF inbound.
      parts.push(`(link[${o + 6}:2] & 8191) = 0`, `link[${o + 2}:2] >= ${header} + 8`, `link[${o} + ${header} + 7] >= 0`);
      for (const [ports, portOffset] of [[predicate.source_ports, 0], [predicate.destination_ports, 2]] as const) {
        if (ports !== null) parts.push(`(${ports.map(port => `link[${o} + ${header} + ${portOffset}:2] = ${port}`).join(' or ')})`);
      }
    }
    return `(${parts.join(' and ')})`;
  }).join(' or ');
  if (encoder.encode(expression).length > 16384) return refuse('FILTER_BYTE_LIMIT');
  return { version: 'ddos-packet-selection-v1', status: 'EXACT_OFFLINE', reason: 'SAME_CAPTURE_DECODED_IPV4_UDP_PREDICATE', expression, capture_sha256: job.source!.sha256, link_type: links[0], internal_networks: [...networks] };
}
export function buildDDoSExport(report: unknown, findingId: string, candidateId: string, job: ExportJob, current: () => boolean): string | null {
  if (!boundedData(report, 2097152) || !boundedData(job, 16384, true) || !current() || !isDDoSAttackReport(report) || typeof job.id !== 'string' || !job.id || job.id.length > 200 || typeof job.dataset_id !== 'string' || !job.dataset_id || job.dataset_id.length > 200) return null;
  const finding = report.findings.find(f => f.id === findingId);
  const candidate = finding?.signature_candidates?.find(c => c.id === candidateId);
  if (!finding || !candidate?.evaluation || !validEvaluation(candidate.evaluation)) return null;
  const value = {
    version: 'ddos-review-export-v1', report_version: report.version, catalog_version: report.catalog_version,
    report_digest_encoding: 'UTF8_JSON_STRINGIFY_VALIDATED_REPORT', report_content_sha256: sha256(JSON.stringify(report)),
    job_id: job.id, dataset_id: job.dataset_id, finding_id: finding.id, candidate_id: candidate.id,
    verdict: report.verdict, report_confidence: report.confidence, summary: report.summary,
    finding_confidence: finding.confidence, attack_type: finding.attack_type, likelihood: finding.likelihood, severity: finding.severity, classification: finding.classification,
    candidate_kind: candidate.kind, candidate_confidence: candidate.confidence,
    warnings: report.warnings, limitations: report.limitations, omitted_finding_count: report.omitted_finding_count,
    observation: { first_seen: finding.first_seen, last_seen: finding.last_seen, target: finding.target, role: finding.attack_role, uncertainty_codes: finding.uncertainty_codes },
    evaluation: candidate.evaluation, requires_human_approval: candidate.requires_human_approval,
    false_positive_codes: candidate.false_positive_codes,
    packet_selection_scope: 'MATCH_TRUE_ON_DECODED_PACKETS_OF_IDENTICAL_CAPTURE',
    evaluation_counts_scope: 'BOUNDED_RETAINED_RECORDS_NOT_ENTIRE_CAPTURE',
    packet_selection: passiveSelection(candidate.evaluation.predicate, job),
  };
  if (!boundedData(value, DDOS_EXPORT_MAX_BYTES)) return null;
  const text = JSON.stringify(value, null, 2) + '\n';
  return encoder.encode(text).length <= DDOS_EXPORT_MAX_BYTES && current() ? text : null;
}
export function downloadDDoSExport(report: unknown, findingId: string, candidateId: string, job: ExportJob, current: () => boolean, target: 'JSON' | 'BPF' = 'JSON'): boolean {
  let text = buildDDoSExport(report, findingId, candidateId, job, current);
  if (text === null || !['JSON', 'BPF'].includes(target)) return false;
  if (target === 'BPF') {
    const envelope = JSON.parse(text);
    if (envelope.packet_selection.status !== 'EXACT_OFFLINE') return false;
    // Prefix EVERY JSON line; user identifiers remain inert comments. This is
    // libpcap filter-file syntax, never a shell command or an automatic action.
    text = text.trimEnd().split('\n').map(line => '# ' + line).join('\n') + '\n' + envelope.packet_selection.expression + '\n';
  }
  if (encoder.encode(text).length > DDOS_EXPORT_MAX_BYTES || !current()) return false;
  const url = URL.createObjectURL(new Blob([text], { type: target === 'BPF' ? 'text/plain;charset=utf-8' : 'application/json;charset=utf-8' }));
  try {
    const anchor = document.createElement('a');
    anchor.href = url; anchor.download = target === 'BPF' ? `${candidateId}-passive-v1.bpf` : `${candidateId}-review-v1.json`;
    anchor.click();
  } catch { return false; } finally { URL.revokeObjectURL(url); }
  return true;
}
