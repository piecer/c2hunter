import { expect, it, vi } from 'vitest';
import { jobApi, captureJobRequest } from '../src/jobInvestigationApi';
import { parseJobWire } from '../src/jobInvestigationContract';
import { producer } from './jobInvestigationFixtures';
const signal = () => new AbortController().signal;
it('POST uses exact captured bytes, required null intent, auth and job route; no silent retry', async () => {
  const run=parseJobWire('run',producer.fixtures.run_queued);
  const body=JSON.stringify(run.request);
  const fetch=vi.fn().mockResolvedValue(new Response(producer.fixtures.run_queued));vi.stubGlobal('fetch',fetch);
  localStorage.setItem('c2hunter-token','test-token');
  expect((await jobApi.create('job',body,signal())).id).toBe(run.id);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0][0]).toBe('/api/v1/analysis-jobs/job/ai-job-investigations');
  expect(fetch.mock.calls[0][1].body).toBe(body);
  expect(new Headers(fetch.mock.calls[0][1].headers).get('authorization')).toBe('Bearer test-token');
  expect(JSON.parse(captureJobRequest('Question','en',false)).expected_source_sha256).toBeNull();
});
it('rejects foreign acknowledgments, changed immutable pool, terminal regression and duplicate raw members', async () => {
  const run=parseJobWire('run',producer.fixtures.run_completed);
  for(const raw of [producer.fixtures.run_queued,producer.fixtures.run_completed.replace('"owner_id":"','"owner_id":"other-'),producer.fixtures.run_completed.replace('"revision":','"revision":0,"revision":')]) {
    vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(raw)));
    await expect(jobApi.run('job',run,signal())).rejects.toThrow();
  }
});
it('saved evidence requires selected peer, issued ID, source and exact scope', async () => {
  const run=parseJobWire('run',producer.fixtures.run_completed), evidence=parseJobWire('evidence',producer.fixtures.evidence_protocol);
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(producer.fixtures.evidence_protocol)));
  expect((await jobApi.evidence('job',run,run.selection.peer_ids[0],evidence.evidence_id,signal())).evidence_id).toBe(evidence.evidence_id);
  await expect(jobApi.evidence('job',run,'f'.repeat(64),evidence.evidence_id,signal())).rejects.toThrow();
});
it('bounded stream rejects oversize before JSON and preserves authentication invalidation', async () => {
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('x',{headers:{'content-length':'262145'}})));
  await expect(jobApi.capabilities(signal())).rejects.toThrow();
  localStorage.setItem('c2hunter-token','test-token');
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('{}',{status:401})));
  await expect(jobApi.capabilities(signal())).rejects.toThrow();expect(localStorage.getItem('c2hunter-token')).toBeNull();
});

it('every saved-read route and cancel consumes the original authenticated producer bytes',async()=>{
  const queued=parseJobWire('run',producer.fixtures.run_queued),complete=parseJobWire('run',producer.fixtures.run_completed),cancelled=parseJobWire('run',producer.fixtures.run_cancelled);
  const fetch=vi.fn().mockImplementation(async(path:string,init?:RequestInit)=>{void init;return new Response(path.endsWith('/capabilities')?producer.fixtures.capabilities:path.includes('/steps?')?producer.fixtures.steps_page:path.endsWith('/cancel')?producer.fixtures.run_cancelled:path.includes('?limit=1')?producer.fixtures.page_runs:producer.fixtures.run_completed);});vi.stubGlobal('fetch',fetch);
  expect((await jobApi.capabilities(signal())).availability).toBe('CONFIGURED_NOT_PROBED');
  expect((await jobApi.history('job',null,signal())).items[0].id).toBe(complete.id);
  expect((await jobApi.run('job',queued,signal())).status).toBe('COMPLETED');
  expect((await jobApi.steps('job',complete,0,signal())).items.some(s=>s.origin==='AUTOMATIC_SEED')).toBe(true);
  expect((await jobApi.cancel('job',cancelled,signal())).status).toBe('CANCELLED');
  expect(fetch.mock.calls.at(-1)?.[0]).toBe(`/api/v1/analysis-jobs/job/ai-job-investigations/${cancelled.id}/cancel`);
  expect(fetch.mock.calls.at(-1)?.[1].method).toBe('POST');
});
