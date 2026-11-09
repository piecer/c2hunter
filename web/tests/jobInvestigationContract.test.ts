import { expect, it } from 'vitest';
import schemas from '../src/jobInvestigationSchemas.json';
import { parseJob, parseJobWire, parseJobPage } from '../src/jobInvestigationContract';
import { producer, pythonAcceptance } from './jobInvestigationFixtures';

it('fresh generator equals shipped schemas and all 23 artifacts have an explicit consumer', () => {
  expect(producer.schemas).toEqual(schemas);
  const handled: string[] = [];
  for (const [name, raw] of Object.entries(producer.fixtures)) {
    if (name.startsWith('schema_')) expect(JSON.parse(raw)).toEqual(schemas[name.slice(7) as keyof typeof schemas]);
    else if (name === 'page_runs') parseJobPage('run', raw);
    else if (name === 'steps_page') parseJobPage('step', raw);
    else parseJobWire(name.startsWith('run_') ? 'run' : name.startsWith('step_') ? 'step' : name.startsWith('result_') ? 'result' : name.startsWith('evidence_') ? 'evidence' : 'capabilities', raw);
    handled.push(name);
  }
  expect(handled).toHaveLength(23);
});
it('identical original wire has independent Python/Web expectations, including integral spellings', () => {
  const raw = producer.fixtures.run_completed;
  const cases = [
    { raw, accepted: true },
    ...['1.0', '1e0'].map(token => ({raw: raw.replace('"selected_peers":1', `"selected_peers":${token}`), accepted: true})),
    ...['true','"1"','1.5','null'].map(token => ({raw: raw.replace('"selected_peers":1', `"selected_peers":${token}`), accepted: false})),
    {raw: raw.replace('"revision":', '"unknown":0,"revision":'), accepted: false},
    {raw: raw.replace('"revision":', '"revision":0,"revision":'), accepted: false},
    {raw: raw.replace('"reason":null', '"reason":"UNKNOWN_FUTURE_CODE"'), accepted: false},
    {raw: raw.replace('"capture_completeness":"UNKNOWN"', '"capture_completeness":"COMPLETE"'), accepted: false},
    {raw: raw.replace('"pool_sha256":"', '"pool_sha256":"0'), accepted: false},
  ].map(item => ({...item, kind:'run'}));
  const python = pythonAcceptance(cases);
  cases.forEach((item, i) => {
    expect(python[i].accepted, item.raw).toBe(item.accepted);
    let accepted = false; try { parseJobWire('run', item.raw); accepted = true; } catch { /* rejection */ }
    expect(accepted, item.raw).toBe(item.accepted);
  });
});
it('rejects hostile direct objects without invoking hooks or erasing malformed presence', () => {
  let calls = 0;
  for (const poison of [
    (v: object) => Object.defineProperty(v, 'id', {enumerable:true, get(){ calls++; return 'x'; }}),
    (v: object) => Object.defineProperty(v, 'toJSON', {value(){ calls++; }, enumerable:false}),
    (v: object) => Object.defineProperty(v, 'reason', {value:null, enumerable:false}),
    (v: object) => Object.setPrototypeOf(v, {foreign: true}),
    (v: object) => Object.defineProperty(v, Symbol('hidden'), {value:1}),
  ]) {
    const value = JSON.parse(producer.fixtures.run_completed); poison(value);
    expect(() => parseJob('run', value)).toThrow();
  }
  const value = JSON.parse(producer.fixtures.run_completed); delete value.pool.entries[0];
  expect(() => parseJob('run', value)).toThrow();
  expect(calls).toBe(0);
});
