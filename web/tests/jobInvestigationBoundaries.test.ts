import { expect, it } from 'vitest';
import { parseJobWire, parseJob } from '../src/jobInvestigationContract';
import { producer, pythonAcceptance } from './jobInvestigationFixtures';
it('action exact raw budgets and nested unique references obey the real Python action parser',()=>{
  const r=parseJobWire('run',producer.fixtures.run_completed),a=r.result?.kind==='RESULT'?r.result.assessments[0]:undefined;
  const select=JSON.stringify({action:'select_peers',pool_sha256:r.pool.pool_sha256,peer_ids:r.selection.peer_ids});
  const finish=JSON.stringify({action:'finish',assessments:[{peer_id:a!.peer_id,verdict:a!.verdict,support:a!.support,counterevidence:a!.counterevidence,uncertainty:a!.uncertainty,next_checks:a!.next_checks}]});
  const id=a!.support[0].evidence_ids[0];
  const cases=[{raw:select,accepted:true},{raw:' '.repeat(1025-select.length)+select,accepted:false},{raw:finish,accepted:true},{raw:finish.replace(`"evidence_ids":["${id}"]`,`"evidence_ids":["${id}","${id}"]`),accepted:false}].map(c=>({...c,kind:'action'}));
  const python=pythonAcceptance(cases);
  cases.forEach((c,i)=>{expect(python[i].accepted).toBe(c.accepted);let accepted=false;try{parseJobWire('action',c.raw);accepted=true;}catch{/*refuse*/}expect(accepted,c.raw).toBe(c.accepted);});
});
it('bounded depth/nodes/raw/cardinality and Unicode do not execute getters',()=>{
  expect(()=>parseJobWire('run',' '.repeat(65537))).toThrow();
  expect(()=>parseJobWire('run','['.repeat(40)+']'.repeat(40))).toThrow();
  expect(()=>parseJob('pool',{entries:Array(8193)})).toThrow();
  const r=JSON.parse(producer.fixtures.run_completed);r.request.question='\ud800';expect(()=>parseJob('run',r)).toThrow();
});

it('raw UTF8 byte ceilings include exact-limit and limit-plus-one without normalization',()=>{
  const cases=[] as {kind:'run'|'result'|'pool'|'request';raw:string;accepted:boolean}[];
  for(const [kind,raw,limit] of [['run',producer.fixtures.run_completed.trimEnd(),65536],['result',producer.fixtures.result_completed.trimEnd(),16384],['pool',producer.additional.pool_float_2,16384]] as const){
    const remaining=limit-new TextEncoder().encode(raw).length;
    cases.push({kind,raw:' '.repeat(remaining)+raw,accepted:true},{kind,raw:' '.repeat(remaining+1)+raw,accepted:false});
  }
  const request=parseJobWire('run',producer.fixtures.run_queued).request;
  for(const question of ['한😀<>&\\"\u2028\u2029','😀'.repeat(2000),'😀'.repeat(2001)])cases.push({kind:'request',raw:JSON.stringify({...request,question}),accepted:[...question].length<=2000});
  const answers=pythonAcceptance(cases);
  cases.forEach((c,i)=>{expect(answers[i].accepted).toBe(c.accepted);let web=false;try{parseJobWire(c.kind,c.raw);web=true;}catch{/* refusal */}expect(web).toBe(c.accepted);});
});
