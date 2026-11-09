import { expect, it, vi } from 'vitest';
import { JobIntent, JobReads } from '../src/jobInvestigationLifecycle';
import { producer } from './jobInvestigationFixtures';
import { parseJobWire } from '../src/jobInvestigationContract';
it('retains exact submitted bytes and explicit null across owner changes; unrelated run cannot resolve intent', () => {
  const run=parseJobWire('run',producer.fixtures.run_queued), body=JSON.stringify(run.request);
  const store=new Map<string,string>();const storage={getItem:(k:string)=>store.get(k)??null,setItem:(k:string,v:string)=>{store.set(k,v);},removeItem:(k:string)=>{store.delete(k);}};
  const a=new JobIntent(storage);a.capture('job',body);
  const b=new JobIntent(storage);expect(b.pending()).toEqual({job:'job',body});
  expect(()=>b.capture('B',body)).toThrow();
  expect(()=>b.resolve({...run,id:'f'.repeat(64),request:{...run.request,idempotency_key:'other'}})).toThrow();
  expect(b.pending()).toEqual({job:'job',body});b.resolve(run);expect(b.pending()).toBeNull();
});
it.each(['post','history','poll','evidence','cancel'] as const)('retired %s result cannot publish after A→B→A', async channel => {
  const reads=new JobReads();let resolve!:(v:string)=>void;const publish=vi.fn();
  const pending=reads.request(channel,()=>new Promise<string>(r=>{resolve=r;}),publish,vi.fn());
  reads.retire();reads.retire();resolve('old-A');await pending;expect(publish).not.toHaveBeenCalled();
});
it('late timeout-ignoring promise cannot replace the timeout or newer detail', async () => {
  vi.useFakeTimers();const reads=new JobReads();let resolve!:(v:string)=>void;const success=vi.fn(),failure=vi.fn();
  const pending=reads.request('evidence',()=>new Promise<string>(r=>{resolve=r;}),success,failure,10);
  await vi.advanceTimersByTimeAsync(11);await pending;resolve('late');await Promise.resolve();
  expect(success).not.toHaveBeenCalled();expect(failure).toHaveBeenCalledTimes(1);reads.retire();vi.useRealTimers();
});

it('printable job IDs are preserved literally in a pending receipt',()=>{
  const body=JSON.stringify(parseJobWire('run',producer.fixtures.run_queued).request);
  const store=new Map<string,string>(),storage={getItem:(k:string)=>store.get(k)??null,setItem:(k:string,v:string)=>{store.set(k,v);},removeItem:(k:string)=>{store.delete(k);}};
  const intent=new JobIntent(storage);intent.capture('job/a?#',body);expect(intent.pending()?.job).toBe('job/a?#');
});
