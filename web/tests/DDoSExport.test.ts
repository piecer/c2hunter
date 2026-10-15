import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { buildDDoSExport, passiveSelection, downloadDDoSExport } from '../src/ddosExport';
const report = JSON.parse(readFileSync('tests/fixtures/ddos-report-contract.json', 'utf8'));
const finding = report.findings[0];
const candidate = finding.signature_candidates[0];
const job = { id: 'owner', dataset_id: 'dataset', source_type: 'PCAP_UPLOAD', internal_networks: ['10.0.0.0/8'], source: { sha256: 'a'.repeat(64), link_types: [1] } };
it('exports complete bounded candidate provenance without changing frozen producer capability', () => {
  const value = buildDDoSExport(report, finding.id, candidate.id, job, () => true);
  expect(value).not.toBeNull();
  const parsed = JSON.parse(value!);
  expect(parsed.version).toBe('ddos-review-export-v1');
  expect(parsed.evaluation).toEqual(candidate.evaluation);
  expect(parsed.evaluation.supported_export_targets).toEqual(['STRUCTURED_JSON']);
  expect(parsed.report_version).toBe(report.version);
  expect(parsed.report_content_sha256).toBe(createHash('sha256').update(JSON.stringify(report)).digest('hex'));
  expect(parsed.job_id).toBe('owner');
  expect(parsed.finding_id).toBe(finding.id);
  expect(parsed.candidate_confidence).toBe(candidate.confidence);
  expect(parsed.classification).toEqual(finding.classification);
  expect(parsed.packet_selection.status).toBe('REFUSED');
  expect(new TextEncoder().encode(value!).length).toBeLessThanOrEqual(65536);
});
it('denies stale owners, invalidated candidates, malformed predicates and hostile objects before URL allocation', () => {
  const create = vi.fn(); vi.stubGlobal('URL', { createObjectURL: create, revokeObjectURL: vi.fn() });
  expect(downloadDDoSExport(report, finding.id, candidate.id, job, () => false)).toBe(false);
  const broken = structuredClone(report); broken.findings[0].signature_candidates[0].evaluation.predicate.protocol = 'ANY';
  expect(buildDDoSExport(broken, finding.id, candidate.id, job, () => true)).toBeNull();
  expect(buildDDoSExport(report, finding.id, 'removed', job, () => true)).toBeNull();
  const undefinedMetric = structuredClone(report); undefinedMetric.findings[0].metrics.baseline_packets_per_second = undefined;
  expect(buildDDoSExport(undefinedMetric, finding.id, candidate.id, job, () => true)).toBeNull();
  let calls = 0; const poisoned = { ...report }; Object.defineProperty(poisoned, 'toJSON', { get() { calls++; return () => report; } });
  expect(buildDDoSExport(poisoned, finding.id, candidate.id, job, () => true)).toBeNull();
  expect(calls).toBe(0); expect(create).not.toHaveBeenCalled();
});
it('translates every supported UDP field with CIDR direction and refuses unsupported observation conditions', () => {
  const predicate = { ...candidate.evaluation.predicate, protocol: 'UDP', tcp_flags: null };
  const result = passiveSelection(predicate, job);
  expect(result.status).toBe('EXACT_OFFLINE');
  expect(result.expression).toContain('link[');
  for (const [key, value] of [['length', { field: 'CAPTURED_FRAME_BYTES', minimum: 1, maximum: 10 }], ['tcp_flags', { syn: 1 }], ['protocol_fields', { icmp_type: 8 }], ['target_ip', '2001:db8::1']] as const) {
    expect(passiveSelection({ ...predicate, [key]: value }, job).status).toBe('REFUSED');
  }
  expect(passiveSelection(predicate, { ...job, source_type: 'SENSOR_CAPTURE' }).status).toBe('REFUSED');
  expect(passiveSelection({ ...predicate, extra_condition: 'unsupported' } as typeof predicate, job).status).toBe('REFUSED');
});

it('downloads a separate passive filter only for an exact context-derived subset', () => {
  const udp = JSON.parse(readFileSync('tests/fixtures/ddos-report-scenarios.json', 'utf8')).possible_reflection;
  const f = udp.findings[0], c = f.signature_candidates[0];
  const create = vi.fn(() => 'blob:filter'), revoke = vi.fn();
  vi.stubGlobal('URL', class extends URL { static createObjectURL = create; static revokeObjectURL = revoke; });
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.download).toMatch(/-passive-v1\.bpf$/);
  });
  expect(downloadDDoSExport(udp, f.id, c.id, job, () => true, 'BPF')).toBe(true);
  expect(create).toHaveBeenCalledOnce(); expect(click).toHaveBeenCalledOnce(); expect(revoke).toHaveBeenCalledWith('blob:filter');
  expect(downloadDDoSExport(report, finding.id, candidate.id, job, () => true, 'BPF')).toBe(false);
  expect(create).toHaveBeenCalledOnce();
  click.mockImplementationOnce(() => { throw new Error('download unavailable'); });
  expect(downloadDDoSExport(udp, f.id, c.id, job, () => true, 'BPF')).toBe(false);
  expect(revoke).toHaveBeenCalledTimes(2);
});

it.each([1, 101])('compiles real libpcap filter for link %s and agrees with independent decoded-record replay', link => {
  for (const direction of ['INBOUND', 'OUTBOUND']) for (const constrained of [true, false]) {
    const predicate = { ...candidate.evaluation.predicate, target_ip: direction === 'INBOUND' ? '10.0.0.10' : '203.0.113.80', direction, protocol: 'UDP', tcp_flags: null, source_ports: constrained ? [53] : null, destination_ports: constrained ? [443] : null };
    const context = { ...job, source: { ...job.source, link_types: [link] } };
    const filter = passiveSelection(predicate, context);
    expect(filter.status).toBe('EXACT_OFFLINE');
    const receipt = JSON.parse(execFileSync(process.env.C2HUNTER_TEST_PYTHON ?? resolve('../.venv/bin/python'), ['tests/ddos_native_filter.py'], { input: JSON.stringify({ predicate, expression: filter.expression, networks: job.internal_networks, link }), encoding: 'utf8' }));
    console.info('Native offline predicate proof', JSON.stringify(receipt));
    expect(receipt.packets).toBeGreaterThan(50);
    expect(receipt.selected.length).toBeGreaterThan(0);
  }
});
