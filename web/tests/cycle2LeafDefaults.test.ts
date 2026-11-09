import { expect,it } from 'vitest';
import { writeFileSync } from 'node:fs';
import type { JobContracts } from '../src/jobInvestigationTypes';
import { producer, pythonAcceptance } from './jobInvestigationFixtures';
import { parseJob,parseJobWire,decodeJobJSON,JobContractError } from '../src/jobInvestigationContract';

const cases:{name:string;raw:string;expected:boolean;kind:keyof JobContracts}[]=[];
const add=(name:string,raw:string,expected=true,kind:keyof JobContracts='run')=>cases.push({name,raw,expected,kind});
add('producer-completed-control',producer.fixtures.run_completed);
add('producer-max-control',producer.additional.run_max_completed);
// Existing leaf omission defaults are part of the approved contract.
for(const [name,path] of [['source-version',['source','version']],['nested-result-source-version',['result','source','version']],['quality-scope-unavailable',['result','assessments',0,'evidence_quality',0,'counts','scope_unavailable']],['quality-unavailable',['result','assessments',0,'evidence_quality',0,'counts','unavailable']]] as const){
 const v=JSON.parse(producer.fixtures.run_completed);let p:Record<string,unknown>=v;for(const key of path.slice(0,-1))p=p[key] as Record<string,unknown>;
 // Omit only an actual inherited default equal to its default.
 const key=path.at(-1)!;if(key!=='version')expect(p[key]).toBe(0);delete p[key];add(name,JSON.stringify(v));
}
const rawEvidence=producer.fixtures.evidence_protocol;
const ev=JSON.parse(rawEvidence);delete ev.counts.scope_unavailable;add('evidence-scope-unavailable',JSON.stringify(ev),true,'evidence');
const python=pythonAcceptance(cases);
const observations=cases.map((c,i)=>{let web=false,error='';try{parseJobWire(c.kind,c.raw);web=true;}catch(e){error=String(e);}return {...c,python:python[i],web,error};});
if(process.env.C2HUNTER_JOB_CORPUS_OUTPUT)writeFileSync(process.env.C2HUNTER_JOB_CORPUS_OUTPUT+'.leaf-defaults',JSON.stringify({observations,producer},null,2));
it.each(observations)('valid inherited leaf default: $name',c=>{expect(c.python.accepted).toBe(c.expected);expect(c.web).toBe(c.expected);});
it('own-descriptor poison never executes getters/hooks; scalar rejection is clean',()=>{
 let calls=0;const mutations=[(v:{source:object;pool:{entries:unknown[]}})=>Object.defineProperty(v.source,'version',{get(){calls++;return 'ip-evidence-v1';},enumerable:true}),(v:{source:object;pool:{entries:unknown[]}})=>Object.defineProperty(v.source,'toJSON',{value:()=>{calls++;return {};},enumerable:false}),(v:{source:object;pool:{entries:unknown[]}})=>Object.defineProperty(v,'hidden',{value:null}),(v:{source:object;pool:{entries:unknown[]}})=>Object.defineProperty(v,Symbol('hidden'),{value:null}),(v:{source:object;pool:{entries:unknown[]}})=>{delete v.pool.entries[0];}];
 for(const mutate of mutations){const v=JSON.parse(producer.fixtures.run_completed);mutate(v);expect(()=>parseJob('run',v)).toThrow(JobContractError);}expect(calls).toBe(0);
 for(const value of [null,0,1,true,[],{},'x'])expect(()=>parseJob('run',value)).toThrow(JobContractError);
 expect(()=>decodeJobJSON('{"a":1,"a":2}')).toThrow(JobContractError);
 expect(()=>decodeJobJSON('['.repeat(34)+']'.repeat(34))).toThrow(JobContractError);
 expect(()=>decodeJobJSON(JSON.stringify(Array(8193).fill(0)))).toThrow(JobContractError);
 expect(()=>decodeJobJSON(JSON.stringify(Array.from({length:3},()=>Array(7000).fill(0))))).toThrow(JobContractError);
});
