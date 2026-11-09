import { captureAuthentication, invalidateAuthentication } from './authentication';
import { ApiError } from './api';
import { assertJobIdentity, JobContractError, jobEqual, parseJobPage, parseJobWire } from './jobInvestigationContract';
import type { JobRun, JobRequest, JobStep } from './jobInvestigationTypes';

const base=(job:string)=>`/analysis-jobs/${encodeURIComponent(job)}/ai-job-investigations`;
const path=(job:string,id:string)=>`${base(job)}/${encodeURIComponent(id)}`;
/** Dedicated raw-byte boundary retains duplicate-member rejection for JOB only. */
async function request(path:string,signal:AbortSignal,body?:string,method='GET'):Promise<string>{
  const authority=captureAuthentication(),headers=new Headers({accept:'application/json'}),token=authority.token;
  if(token)headers.set('authorization',`Bearer ${token}`);if(body!==undefined)headers.set('content-type','application/json');
  const response=await fetch('/api/v1'+path,{method,signal,headers,body});
  invalidateAuthentication(response.status,authority,signal);
  const advertised=response.headers.get('content-length');
  if(advertised!==null&&/^\d+$/.test(advertised)&&Number(advertised)>262144){await response.body?.cancel();throw new JobContractError();}
  if(!response.body)throw new JobContractError();
  const reader=response.body.getReader(),chunks:Uint8Array[]=[];let total=0;
  try{for(;;){const part=await reader.read();if(part.done)break;total+=part.value.byteLength;if(total>262144){await reader.cancel();throw new JobContractError();}chunks.push(part.value);}}finally{reader.releaseLock();}
  if(!response.ok)throw new ApiError(`Job investigation request failed (${response.status}); server outcome may be unconfirmed`,response.status);
  const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
}
export const jobApi={
  async capabilities(signal:AbortSignal){return parseJobWire('capabilities',await request('/ai-job-investigations/capabilities',signal));},
  async create(job:string,captured:string,signal:AbortSignal){const submitted=parseJobWire('request',captured),r=parseJobWire('run',await request(base(job),signal,captured,'POST'));assertJobIdentity(r,job,undefined,submitted);return r;},
  async history(job:string,after:string|null,signal:AbortSignal){const page=parseJobPage('run',await request(`${base(job)}?limit=1${after?`&after=${encodeURIComponent(after)}`:''}`,signal));page.items.forEach(r=>assertJobIdentity(r,job));if(page.next_cursor!==null&&page.next_cursor===after)throw new JobContractError();return page;},
  async run(job:string,previous:JobRun,signal:AbortSignal){const r=parseJobWire('run',await request(path(job,previous.id),signal));assertJobIdentity(r,job,previous);return r;},
  async cancel(job:string,previous:JobRun,signal:AbortSignal){const r=parseJobWire('run',await request(path(job,previous.id)+'/cancel',signal,undefined,'POST'));assertJobIdentity(r,job,previous);return r;},
  async steps(job:string,run:JobRun,after:number,signal:AbortSignal){
    const page=parseJobPage('step',await request(path(job,run.id)+`/steps?limit=10&after=${after}`,signal));
    for(const s of page.items){if(s.sequence<=after)throw new JobContractError();assertStepPeer(run,s);}
    return page;
  },
  async evidence(job:string,run:JobRun,peer:string,id:string,signal:AbortSignal){
    const p=run.pool.entries.find(p=>p.peer_id===peer),a=run.result?.kind==='RESULT'?run.result.assessments.find(a=>a.peer_id===peer):undefined;
    if(!p||!run.selection.peer_ids.includes(peer)||!a?.evidence_quality.some(e=>e.evidence_id===id))throw new JobContractError();
    const e=parseJobWire('evidence',await request(path(job,run.id)+'/evidence/'+encodeURIComponent(id),signal));
    if(e.evidence_id!==id||!jobEqual(e.source,run.source)||!jobEqual(e.scope,{target_ip:p.ip,sensor_id:null,endpoint_side:'either',traffic_direction:null,start_time:null,end_time:null}))throw new JobContractError();
    const quality=a.evidence_quality.find(q=>q.evidence_id===id)!;
    if(e.tool!==quality.tool||e.status!==quality.status||!jobEqual(e.counts,quality.counts)||a.facts.filter(f=>f.ref.startsWith(id+':')).some(f=>!e.metrics.some(m=>jobEqual(m,f))))throw new JobContractError();
    return e;
  },
};
function assertStepPeer(run:JobRun,s:JobStep){
  // Invalid model attempts may record out-of-pool IDs with a refusal code, never evidence.
  if(s.evidence_id!==null&&(!s.peer_id||!run.selection.peer_ids.includes(s.peer_id)))throw new JobContractError();
  for(const key of ['model_calls','tool_calls','planning_responses','transport_attempts','source_records','source_bytes'] as const)if(s.progress[key]>run.progress[key])throw new JobContractError();
}
export function captureJobRequest(question:string,language:'ko'|'en',allowRemote:boolean):string{
  if(!globalThis.crypto?.getRandomValues)throw new Error('Secure request-key generation unavailable; new admission disabled');
  const key=Array.from(crypto.getRandomValues(new Uint8Array(24)),b=>b.toString(16).padStart(2,'0')).join('');
  const request:JobRequest={version:'job-investigation-v1',mode:'JOB',experimental:true,question,language,idempotency_key:key,expected_source_sha256:null,allow_remote:allowRemote,baseline_mode:'off'};
  const body=JSON.stringify(request);parseJobWire('request',body);return body;
}
