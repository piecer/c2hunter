import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { expect, it } from 'vitest';
import { validatePcapGuidanceJob, guidanceRegistry } from '../src/pcapAttackGuidance';

const root = resolve('..');
const fixtures = resolve(root, 'controller/tests/fixtures/pcap_attack_guidance');
const names = readdirSync(fixtures).filter(name => name.endsWith('.job.json')).sort();
const fixtureJob = (name: string) => JSON.parse(readFileSync(resolve(fixtures, `${name}.job.json`), 'utf8'));
function pythonOutcomes(wires: string[], mode = 'job') {
  const result = spawnSync(resolve(root, '.venv/bin/python'), ['-c', `
import json,sys,pathlib
import c2hunter_controller.pcap_attack_guidance_schema as schema
assert pathlib.Path(schema.__file__).resolve() == pathlib.Path(sys.argv[1]).resolve()
out=[]
for wire in json.load(sys.stdin):
 try:
  value=schema.validate_job_guidance(json.loads(wire)) if sys.argv[2]=='job' else schema.PcapAttackGuidance.model_validate(json.loads(wire))
  out.append('UNAVAILABLE' if value is None else 'VALID')
 except (ValueError,TypeError,OverflowError): out.append('INVALID')
print(json.dumps(out))
`, resolve(root, 'controller/src/c2hunter_controller/pcap_attack_guidance_schema.py'), mode], {
    input: JSON.stringify(wires), encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONPATH: ['controller/src', 'analysis/src', 'shared/src', 'sensor/worker/src'].map(p => resolve(root, p)).join(':') },
  });
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout);
}
type WireCase = { name: string; wire: string; expected: string };
function mutations(): WireCase[] {
  const cases: WireCase[] = [];
  const add = (name: string, edit: (job: ReturnType<typeof fixtureJob>) => void, expected = 'INVALID', fixture = 'relative_udp') => {
    const job = fixtureJob(fixture); edit(job); cases.push({ name, wire: JSON.stringify(job), expected });
  };
  add('historical absence', j => { delete j.pcap_attack_guidance; }, 'UNAVAILABLE');
  for (const [label, path] of [['guide', []], ['summary', ['summary']], ['candidate', ['candidates', 0]], ['target', ['candidates', 0, 'target']]] as const) {
    const object = path.reduce((v, k) => v[k], fixtureJob('relative_udp').pcap_attack_guidance);
    for (const key of Object.keys(object)) add(`${label} missing ${key}`, j => { const o = path.reduce((v, k) => v[k], j.pcap_attack_guidance); delete o[key]; });
    add(`${label} unknown`, j => { path.reduce((v, k) => v[k], j.pcap_attack_guidance).unknown = 'untrusted'; });
    for (const [key, value] of Object.entries(object)) {
      const bad = typeof value === 'number' ? [null, true, '1', 1.5, -1, 9007199254740992] : typeof value === 'boolean' ? [null, 0, 'false'] : [null, false, 7, {}];
      for (const invalid of bad) add(`${label}.${key}=${JSON.stringify(invalid)}`, j => { path.reduce((v, k) => v[k], j.pcap_attack_guidance)[key] = invalid; }, label === 'target' && key === 'port' && invalid === null ? 'VALID' : 'INVALID');
    }
  }
  for (const field of ['family', 'role']) add(`unknown ${field}`, j => { j.pcap_attack_guidance.candidates[0][field] = 'UNKNOWN'; });
  for (const field of ['reason_codes', 'uncertainty_codes', 'alternative_codes', 'next_check_codes', 'source_examples']) {
    for (const value of ['UNKNOWN', null, 2, {}, []]) add(`bad ${field} member ${JSON.stringify(value)}`, j => { j.pcap_attack_guidance.candidates[0][field][0] = value; });
  }
  for (const field of ['coverage_codes', 'limitations']) add(`unknown ${field}`, j => { j.pcap_attack_guidance[field][0] = 'UNKNOWN'; });
  for (const field of ['job_id', 'dataset_id']) {
    add(`foreign ${field}`, j => { j.pcap_attack_guidance[field] = 'foreign'; });
    add(`oversized ${field}`, j => { j.pcap_attack_guidance[field] = 'a'.repeat(129); });
  }
  add('wrong source', j => { j.source_type = 'LIVE'; });
  add('wrong module', j => { j.analysis.module = 'c2'; });
  add('job packet ceiling', j => { j.packet_count = 0; });
  add('job flow ceiling', j => { j.flow_count = 0; });
  add('job bool ceiling', j => { j.flow_count = true; });
  for (const field of ['scanned_records', 'evaluated_records', 'packet_count', 'byte_count', 'skipped_records']) add(`report mismatch ${field}`, j => { j.ddos_attack.summary[field] += 1; });
  for (const field of ['first_seen', 'last_seen']) add(`report time mismatch ${field}`, j => { j.ddos_attack.summary[field] = '2026-09-16T00:00:00+00:00'; });
  add('report coverage mismatch', j => { j.ddos_attack.summary.coverage_complete = false; });
  for (const field of ['eligible_packet_count', 'candidate_count', 'omitted_observation_count', 'excluded_record_count', 'retained_target_count', 'qualifying_window_count', 'response_omitted_count']) add(`conservation ${field}`, j => { j.pcap_attack_guidance.summary[field] += 100; });
  add('candidate duplicates', j => { j.pcap_attack_guidance.candidates.push(j.pcap_attack_guidance.candidates[0]); });
  add('oversized candidates', j => { j.pcap_attack_guidance.candidates = Array(33).fill(j.pcap_attack_guidance.candidates[0]); });
  add('source bound flag', j => { j.pcap_attack_guidance.candidates[0].source_count_is_lower_bound = true; });
  add('source examples reversed', j => { j.pcap_attack_guidance.candidates[0].source_examples.reverse(); });
  add('source examples duplicated', j => { j.pcap_attack_guidance.candidates[0].source_examples[1] = j.pcap_attack_guidance.candidates[0].source_examples[0]; });
  add('coverage null', j => { j.pcap_attack_guidance.coverage_codes = null; });
  add('nonTCP flags', j => { j.pcap_attack_guidance.candidates[0].syn_only_count = 1; });
  add('invented baseline', j => { j.pcap_attack_guidance.candidates[0].baseline_window_count = 0; });
  add('two prior windows', j => { j.pcap_attack_guidance.candidates[0].baseline_window_count = 2; });
  add('empty prior occupied window count', j => { j.pcap_attack_guidance.candidates[0].baseline_packet_count = 2; });
  add('baseline exceeds population', j => { j.pcap_attack_guidance.candidates[0].baseline_packet_count = 1000; });
  add('relative floor', j => { j.pcap_attack_guidance.candidates[0].packet_count = 100; });
  add('absolute floor', j => { j.pcap_attack_guidance.candidates[0].reason_codes = ['ABSOLUTE_VOLUME']; });
  add('UDP family TCP', j => { j.pcap_attack_guidance.candidates[0].target.protocol = 'TCP'; });
  add('invented payload absence', j => { j.pcap_attack_guidance.candidates[0].payload_visibility_complete = false; }, 'INVALID', 'ack');
  add('ACK payload present', j => { j.pcap_attack_guidance.candidates[0].payload_packet_count = 1; }, 'INVALID', 'ack');
  for (const [fixture, field] of [['positive', 'syn_only_count'], ['ack', 'ack_only_count'], ['rst', 'rst_count']]) add(`${fixture} shape`, j => { j.pcap_attack_guidance.candidates[0][field] = 0; }, 'INVALID', fixture);
  for (const stamp of ['2026-02-30T00:00:20.000000Z', '1900-02-29T00:00:20.000000Z', '0000-01-01T00:00:20.000000Z', '2026-09-15T00:00:20Z', '2026-09-15T00:00:20.000000+00:00', '2026-09-15T00:00:60.000000Z']) add(`bad UTC ${stamp}`, j => { j.pcap_attack_guidance.candidates[0].first_seen = stamp; });
  add('microsecond before window', j => { j.pcap_attack_guidance.candidates[0].first_seen = '2026-09-15T00:00:19.999999Z'; });
  add('exclusive window end', j => { j.pcap_attack_guidance.candidates[0].last_seen = j.pcap_attack_guidance.candidates[0].window_end; });
  add('report upper microsecond', j => { j.pcap_attack_guidance.summary.last_seen = '2026-09-15T00:00:23.974999Z'; j.ddos_attack.summary.last_seen = '2026-09-15T00:00:23.974999Z'; });
  add('report lower microsecond', j => { j.pcap_attack_guidance.summary.first_seen = '2026-09-15T00:00:20.000001Z'; j.ddos_attack.summary.first_seen = '2026-09-15T00:00:20.000001Z'; });
  for (const ip of ['010.0.0.1', 'bad', '2001:DB8::1', '2001:0db8::1', 'fe80::1%eth0', '::ffff:c000:201']) add(`noncanonical ip ${ip}`, j => { j.pcap_attack_guidance.candidates[0].target.ip = ip; });
  for (const ip of ['::', '::1', '2001:db8::1', '::ffff:192.0.2.1', '2001:db8:1:2:3:4:5:6']) add(`canonical ip ${ip}`, j => { j.pcap_attack_guidance.candidates[0].target.ip = ip; }, 'VALID');
  for (const [first, expected] of [['1969-12-31T00:00:09.999999Z', 'VALID'], ['1969-12-31T00:00:10.000000Z', 'INVALID']]) {
    const shifted = JSON.parse(readFileSync(resolve(fixtures, 'relative_udp.job.json'), 'utf8').replaceAll('2026-09-15', '1969-12-31'));
    shifted.pcap_attack_guidance.summary.first_seen = shifted.ddos_attack.summary.first_seen = first;
    cases.push({ name: `pre-epoch baseline slot boundary ${first}`, wire: JSON.stringify(shifted), expected });
  }
  add('response retained plus omitted cannot exceed observations', j => {
    const g = j.pcap_attack_guidance;
    g.summary.response_state_count = 200; g.summary.response_omitted_count = 100;
    g.coverage_codes = ['RESPONSE_STATE_LIMIT']; g.summary.coverage_complete = false;
  });
  add('baseline cannot exceed retained windows', j => { j.pcap_attack_guidance.summary.retained_window_count = 3; });
  add('baseline cannot precede capture', j => { j.pcap_attack_guidance.summary.first_seen = j.ddos_attack.summary.first_seen = '2026-09-15T00:00:10.000000Z'; });
  for (const kind of ['packets', 'windows']) add(`disjoint target baseline ${kind}`, j => {
    const g = j.pcap_attack_guidance;
    const second = structuredClone(g.candidates[0]); second.target.ip = '10.0.0.11'; g.candidates.push(second);
    g.summary.candidate_count = 2; g.summary.retained_target_count = 2; g.summary.qualifying_window_count = 2;
    g.summary.retained_window_count = kind === 'windows' ? 7 : 8;
    const population = kind === 'packets' ? 400 : 512;
    for (const key of ['scanned_records', 'evaluated_records', 'packet_count']) { g.summary[key] = population; j.ddos_attack.summary[key] = population; }
    g.summary.eligible_packet_count = population; g.summary.byte_count = j.ddos_attack.summary.byte_count = 20000;
  });
  add('quiet baseline one packet per occupied window', j => { j.pcap_attack_guidance.candidates[0].baseline_packet_count = 4; }, 'VALID', 'quiet_relative_udp');
  add('quiet baseline impossible empty occupied window', j => { j.pcap_attack_guidance.candidates[0].baseline_packet_count = 3; }, 'INVALID', 'quiet_relative_udp');
  add('quiet baseline conservation', j => { j.pcap_attack_guidance.candidates[0].baseline_packet_count = 21; }, 'INVALID', 'quiet_relative_udp');
  const raw = readFileSync(resolve(fixtures, 'relative_udp.job.json'), 'utf8');
  for (const [token, expected] of [['1.0', 'VALID'], ['1e0', 'VALID'], ['true', 'INVALID'], ['1.5', 'INVALID'], ['null', 'INVALID'], ['9007199254740992', 'INVALID']]) {
    const wire = raw.replace(/"candidate_count":1/g, `"candidate_count":${token}`); expect(wire).not.toBe(raw); cases.push({ name: `raw integer ${token}`, wire, expected });
  }
  for (const date of ['0001-01-01', '0099-12-31', '1969-12-31', '2000-02-29', '9999-12-31']) {
    const wire = readFileSync(resolve(fixtures, 'positive.job.json'), 'utf8').replaceAll('2026-09-15', date);
    cases.push({ name: `calendar boundary ${date}`, wire, expected: 'VALID' });
  }
  for (const token of ['-0', '-0.0', '0e0', '1e-999']) cases.push({ name: `raw zero ${token}`, wire: raw.replace(/"ack_only_count":0/g, `"ack_only_count":${token}`), expected: 'VALID' });
  for (const token of ['1e309', 'NaN', 'Infinity', '-Infinity', '0.1', '"0"']) cases.push({ name: `raw invalid ${token}`, wire: raw.replace(/"ack_only_count":0/g, `"ack_only_count":${token}`), expected: 'INVALID' });
  for (const token of ['9007199254740991', '9007199254740991.0', '9.007199254740991e15']) cases.push({ name: `raw safe maximum ${token}`, wire: raw.replace(/"byte_count":\d+/g, `"byte_count":${token}`), expected: 'VALID' });
  return cases;
}
it('matches Python on identical unrounded wire mutations with independent expected acceptance', () => {
  const cases = mutations();
  const python = pythonOutcomes(cases.map(c => c.wire));
  const observations = cases.map((c, index) => {
    let decoded: unknown;
    try { decoded = JSON.parse(c.wire); } catch { /* Invalid JSON syntax is not admitted. */ }
    const web = decoded === undefined ? 'INVALID' : validatePcapGuidanceJob(decoded).state;
    return { ...c, sha256: createHash('sha256').update(c.wire).digest('hex'), python: python[index], web };
  });
  if (process.env.PCAP_GUIDANCE_PARITY_EVIDENCE) writeFileSync(process.env.PCAP_GUIDANCE_PARITY_EVIDENCE, JSON.stringify(observations, null, 2) + '\n');
  for (const c of observations) {
    expect(c.python, `Python: ${c.name}`).toBe(c.expected);
    expect(c.web, `Web: ${c.name}`).toBe(c.expected);
  }
  console.info(JSON.stringify({ wireParity: { mutations: cases.length, producerPairs: names.length, valid: cases.filter(c => c.expected === 'VALID').length, invalid: cases.filter(c => c.expected === 'INVALID').length, unavailable: cases.filter(c => c.expected === 'UNAVAILABLE').length } }));
});
it('rejects malformed direct properties before invoking getters or serialization hooks', () => {
  let calls = 0;
  const edits = [
    (j: ReturnType<typeof fixtureJob>) => { Object.defineProperty(j, 'pcap_attack_guidance', { get() { calls++; return undefined; } }); },
    (j: ReturnType<typeof fixtureJob>) => { Object.defineProperty(j, 'pcap_attack_guidance', { value: null, enumerable: false }); },
    (j: ReturnType<typeof fixtureJob>) => { const guide = j.pcap_attack_guidance; delete j.pcap_attack_guidance; Object.setPrototypeOf(j, { pcap_attack_guidance: guide }); },
    (j: ReturnType<typeof fixtureJob>) => { Object.defineProperty(j.pcap_attack_guidance, 'job_id', { get() { calls++; return j.id; } }); },
    (j: ReturnType<typeof fixtureJob>) => { Object.defineProperty(j.pcap_attack_guidance, 'toJSON', { value() { calls++; return {}; }, enumerable: false }); },
    (j: ReturnType<typeof fixtureJob>) => { j.pcap_attack_guidance[Symbol('hidden')] = 1; },
    (j: ReturnType<typeof fixtureJob>) => { delete j.pcap_attack_guidance.candidates[0].source_examples[1]; },
    (j: ReturnType<typeof fixtureJob>) => { j.pcap_attack_guidance.candidates.length = 2; },
    (j: ReturnType<typeof fixtureJob>) => { j.pcap_attack_guidance.candidates.extra = 1; },
    (j: ReturnType<typeof fixtureJob>) => { Object.setPrototypeOf(j.pcap_attack_guidance.summary, { inherited: true }); },
  ];
  for (const edit of edits) { const job = fixtureJob('relative_udp'); edit(job); expect(validatePcapGuidanceJob(job).state).toBe('INVALID'); }
  expect(calls).toBe(0);
});
it('binds every fixture byte to the actual current producer without regenerating files', () => {
  const result = spawnSync(resolve(root, '.venv/bin/python'), ['-c', `
import sys,pathlib,json,hashlib
sys.path.insert(0,sys.argv[1])
import pcap_guidance_fixture_builder as builder
assert pathlib.Path(builder.__file__).resolve()==pathlib.Path(sys.argv[1],'pcap_guidance_fixture_builder.py').resolve()
actual=builder.generated()
assert set(actual)=={p.name for p in builder.FIXTURES.iterdir() if p.is_file()}
for name,wire in actual.items():
 assert builder.FIXTURES.joinpath(name).read_bytes()==wire, name
print(json.dumps({name:hashlib.sha256(wire).hexdigest() for name,wire in actual.items()},sort_keys=True))
`, resolve(root, 'controller/tests')], { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONPATH: ['controller/src', 'analysis/src', 'shared/src', 'sensor/worker/src'].map(p => resolve(root, p)).join(':') } });
  expect(result.status, result.stderr).toBe(0);
  expect(Object.keys(JSON.parse(result.stdout))).toHaveLength(names.length * 2 + 2);
  console.info(`producerFixtureDigests ${result.stdout.trim()}`);
});
it('accepts every exact producer job byte string and its identical guide without rewriting fixtures', () => {
  expect(names).toHaveLength(18);
  const wires = names.map(name => readFileSync(resolve(fixtures, name), 'utf8'));
  const guideWires = names.map(name => readFileSync(resolve(fixtures, name.replace('.job.', '.guide.')), 'utf8'));
  expect(pythonOutcomes(wires)).toEqual(names.map(() => 'VALID'));
  expect(pythonOutcomes(guideWires, 'guide')).toEqual(names.map(() => 'VALID'));
  for (const [index, wire] of wires.entries()) {
    const job = JSON.parse(wire);
    const result = validatePcapGuidanceJob(job);
    expect(result.state, names[index]).toBe('VALID');
    if (result.state === 'VALID') expect(result.guide).toEqual(JSON.parse(guideWires[index]));
    expect(validatePcapGuidanceJob({ ...job, pcap_attack_guidance: JSON.parse(guideWires[index]) }).state, `standalone guide ${names[index]}`).toBe('VALID');
  }
  expect(guidanceRegistry).toEqual(JSON.parse(readFileSync(resolve(fixtures, 'registry.json'), 'utf8')));
});
