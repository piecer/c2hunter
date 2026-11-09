import { expect, it } from 'vitest';
import { writeFileSync } from 'node:fs';
import { parseJobWire } from '../src/jobInvestigationContract';
import type { JobContracts } from '../src/jobInvestigationTypes';
import { producer, pythonAcceptance } from './jobInvestigationFixtures';

type Case={name:string;kind:keyof JobContracts;raw:string;accepted:boolean};
const cases:Case[]=[];
const add=(name:string,kind:keyof JobContracts,raw:string,accepted:boolean)=>cases.push({name,kind,raw,accepted});
for(const [name,kind] of [['run_completed','run'],['run_partial','run'],['evidence_protocol','evidence'],['result_completed','result'],['step_seed','step'],['capabilities','capabilities']] as const){
  const raw=producer.fixtures[name];add(name,kind,raw,true);
  let quoted=false,escaped=false;
  for(let i=0;i<raw.length;i++){
    const c=raw[i];if(quoted){if(!escaped&&c==='"')quoted=false;if(!escaped&&c==='\\')escaped=true;else escaped=false;continue;}
    if(c==='"'){quoted=true;continue;}
    if(c==='{')add(`${name}:extra@${i}`,kind,raw.slice(0,i+1)+'"unknown_member":0,'+raw.slice(i+1),false);
  }
  // Original numeric token substrings are replaced directly, not parsed/serialized.
  for(const match of raw.matchAll(/"([a-z_]+)":(-?\d+)(?=[,}])/g)){
    const start=match.index!+match[0].lastIndexOf(match[2]);
    for(const suffix of ['.0','e0'])add(`${name}:${match[1]}:${start}:${suffix}`,kind,raw.slice(0,start)+match[2]+suffix+raw.slice(start+match[2].length),true);
    for(const token of ['true','"0"','9007199254740992','0.5'])add(`${name}:${match[1]}:${start}:${token}`,kind,raw.slice(0,start)+token+raw.slice(start+match[2].length),false);
  }
  for(const match of raw.matchAll(/"(status|kind|origin|mode|availability|version|unit|behavior_state|source_bytes_accounting)":"[^"]*"/g)){
    add(`${name}:code:${match.index}`,kind,raw.slice(0,match.index)+`"${match[1]}":"UNKNOWN_CODE"`+raw.slice(match.index!+match[0].length),false);
  }
}
add('surrogate question','request','{"version":"job-investigation-v1","mode":"JOB","experimental":true,"question":"\\ud800","language":"en","idempotency_key":"x","expected_source_sha256":null,"allow_remote":false,"baseline_mode":"off"}',false);

// Fresh oracle generation is a bounded collection prerequisite, not one giant
// test body competing with the unchanged 5s per-case deadline.
const answers=pythonAcceptance(cases);
const observations:{name:string;web:boolean;python:boolean;expected:boolean}[]=[];
it.each(cases.map((c,index)=>({...c,index})))('exact-byte parity: $name',c=>{
  let web=false;try{parseJobWire(c.kind,c.raw);web=true;}catch{/* closed refusal */}
  observations.push({name:c.name,web,python:answers[c.index].accepted,expected:c.accepted});
  expect(answers[c.index].accepted).toBe(c.accepted);
  expect(web).toBe(c.accepted);
});
it('accounts for every exact-byte corpus case',()=>{
  expect(observations).toHaveLength(cases.length);
  if(process.env.C2HUNTER_JOB_CORPUS_OUTPUT)writeFileSync(process.env.C2HUNTER_JOB_CORPUS_OUTPUT,JSON.stringify({cases,python:answers,observations}));
  console.log(JSON.stringify({corpus_cases:cases.length}));
});
