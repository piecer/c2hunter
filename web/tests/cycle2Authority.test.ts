import { beforeEach, expect, it, vi } from 'vitest';
import { JobIntent, JobReads } from '../src/jobInvestigationLifecycle';
import { producer } from './jobInvestigationFixtures';
import { parseJobWire } from '../src/jobInvestigationContract';
const KEY='c2hunter-job-investigation-pending-v1';
const run=parseJobWire('run',producer.fixtures.run_queued),body=JSON.stringify(run.request);
beforeEach(()=>{sessionStorage.clear();localStorage.setItem('c2hunter-token','principal-A');});
it('receipt is authority-bound, retained without raw credentials and recoverable on A reload',()=>{
 const a=new JobIntent(sessionStorage);a.capture('job',body);const raw=sessionStorage.getItem(KEY)!;
 expect(raw).not.toContain('principal-A');localStorage.setItem('c2hunter-token','principal-B');
 const b=new JobIntent(sessionStorage);expect(()=>b.pending()).toThrow();expect(()=>b.capture('job',body)).toThrow();expect(()=>a.resolve(run)).toThrow();expect(sessionStorage.getItem(KEY)).toBe(raw);
 localStorage.setItem('c2hunter-token','principal-A');const reloaded=new JobIntent(sessionStorage);
 expect(reloaded.pending()).toEqual({job:'job',body});reloaded.capture('job',body);expect(sessionStorage.getItem(KEY)).toBe(raw);
 reloaded.resolve(run);expect(sessionStorage.getItem(KEY)).toBeNull();
});
it('in-flight acknowledgment cannot publish or resolve A receipt under B',async()=>{
 const intent=new JobIntent(sessionStorage);intent.capture('job',body);const raw=sessionStorage.getItem(KEY);
 let release!:(v:typeof run)=>void;const success=vi.fn((v:typeof run)=>intent.resolve(v)),failure=vi.fn(),reads=new JobReads();
 const task=reads.request('post',()=>new Promise<typeof run>(r=>{release=r;}),success,failure);
 localStorage.setItem('c2hunter-token','principal-B');release(run);await task;
 expect(success).not.toHaveBeenCalled();expect(failure).not.toHaveBeenCalled();expect(sessionStorage.getItem(KEY)).toBe(raw);reads.retire();
});
it.each(['get','set','remove'] as const)('storage %s failure cannot silently replace unresolved intent',fault=>{
 const a=new JobIntent(sessionStorage);a.capture('job',body);const raw=sessionStorage.getItem(KEY);
 const port={getItem:(k:string)=>{if(fault==='get')throw Error('denied');return sessionStorage.getItem(k);},setItem:()=>{throw Error('denied');},removeItem:()=>{throw Error('denied');}};
 const broken=new JobIntent(port);
 expect(()=>fault==='remove'?broken.resolve(run):broken.capture('job',body)).toThrow();expect(sessionStorage.getItem(KEY)).toBe(raw);
});
it('unbound legacy receipt remains blocked and intact, never reassigned to a principal',()=>{
 const raw=JSON.stringify({job:'job',body});sessionStorage.setItem(KEY,raw);const intent=new JobIntent(sessionStorage);
 expect(()=>intent.pending()).toThrow();expect(()=>intent.capture('job',body)).toThrow();expect(sessionStorage.getItem(KEY)).toBe(raw);
});
