import schemas from './jobInvestigationSchemas.json';
import { parseInvestigation, literalIP } from './investigationContract';
import { jobSHA256 } from './jobInvestigationHash';
import { terminal } from './investigationTypes';
import type { JobContracts, JobPool, JobRun, JobResult, JobCoverage, JobAssessment } from './jobInvestigationTypes';

type Schema = { default?:unknown; $ref?:string; $defs?:Record<string,Schema>; type?:string; const?:unknown; enum?:unknown[]; anyOf?:Schema[]; oneOf?:Schema[]; properties?:Record<string,Schema>; required?:string[]; additionalProperties?:boolean; items?:Schema; minimum?:number; maximum?:number; exclusiveMinimum?:number; exclusiveMaximum?:number; minLength?:number; maxLength?:number; pattern?:string; minItems?:number; maxItems?:number };
export class JobContractError extends Error { constructor() { super('Invalid job investigation response (contract or identity mismatch)'); } }
function fail():never { throw new JobContractError(); }
const size = (s:string) => new TextEncoder().encode(s).length;
const obj = (v:unknown): v is Record<string,unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const unique = (v:unknown[]) => new Set(v).size === v.length;
function unicode(s:string) { for(let i=0;i<s.length;i++) { const c=s.charCodeAt(i); if(c>=0xd800&&c<=0xdbff) {const d=s.charCodeAt(++i);if(!(d>=0xdc00&&d<=0xdfff))fail();} else if(c>=0xdc00&&c<=0xdfff)fail(); } }
/** Validate descriptors BEFORE any enumeration/value read/stringification. */
function snapshot(value:unknown, depth=0, budget={nodes:0}): unknown {
  if(depth>32 || ++budget.nodes>20000) fail();
  if(value===null || typeof value==='boolean') return value;
  if(typeof value==='number') {if(!Number.isFinite(value))fail();return value;}
  if(typeof value==='string') {if(value.length>262144)fail();unicode(value);return value;}
  if(typeof value!=='object')fail();
  const array=Array.isArray(value), proto=Object.getPrototypeOf(value);
  if(proto!==(array?Array.prototype:Object.prototype) && !(proto===null&&!array))fail();
  const descriptors=Object.getOwnPropertyDescriptors(value), keys=Reflect.ownKeys(descriptors);
  if(keys.some(k=>typeof k!=='string'))fail();
  if(array) {
    if(value.length>8192 || keys.length!==value.length+1)fail();
    const result:unknown[]=[];
    for(let i=0;i<value.length;i++) {const d=descriptors[String(i)];if(!d||!d.enumerable||!('value'in d))fail();result.push(snapshot(d.value,depth+1,budget));}
    return result;
  }
  const result:Record<string,unknown>={};
  for(const key of keys as string[]) {const d=descriptors[key]; if(!d.enumerable||!('value'in d)||key==='toJSON')fail();unicode(key);Object.defineProperty(result,key,{value:snapshot(d.value,depth+1,budget),enumerable:true});}
  return result;
}
/** Duplicate-aware bounded decoder; original bytes are never JS-roundtripped for parity. */
export function decodeJobJSON(raw:string, limit=262144): unknown {
  if(typeof raw!=='string'||raw.length>limit||size(raw)>limit)fail();
  let pos=0,nodes=0;
  const space=()=>{while(/[\t\n\r ]/.test(raw[pos]??'x'))pos++;};
  function string():string {const start=pos++;let escaped=false;while(pos<raw.length){const c=raw[pos++];if(!escaped&&c==='"'){const value:unknown=JSON.parse(raw.slice(start,pos));if(typeof value!=='string')fail();unicode(value);return value;}if(!escaped&&c==='\\')escaped=true;else escaped=false;}return fail();}
  function value(depth:number):unknown {
    if(depth>32||++nodes>20000)fail();space();const c=raw[pos];
    if(c==='"')return string();
    if(c==='{'||c==='['){pos++;space();const array=c==='[',end=array?']':'}',items:unknown[]=[],record:Record<string,unknown>={};const keys=new Set<string>();
      if(raw[pos]===end){pos++;return array?items:record;}
      for(;;){space();if(array){if(items.length>=8192)fail();items.push(value(depth+1));}else{if(raw[pos]!=='"')fail();const key=string();if(keys.has(key))fail();keys.add(key);space();if(raw[pos++]!==':')fail();Object.defineProperty(record,key,{value:value(depth+1),enumerable:true});}space();const token=raw[pos++];if(token===end)return array?items:record;if(token!==',')fail();}
    }
    const token=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(raw.slice(pos));
    if(!token)fail();pos+=token[0].length;return JSON.parse(token[0]);
  }
  const result=value(0);space();if(pos!==raw.length)fail();return result;
}
function validate(s:Schema,v:unknown,root:Schema,depth=0):void {
  if(depth>48)fail();
  if(s.$ref){const ref=root.$defs?.[s.$ref.replace('#/$defs/','')];if(!ref)fail();return validate(ref,v,root,depth+1);}
  const branches=s.anyOf??s.oneOf;
  if(branches){if(!branches.some(b=>{try{validate(b,v,root,depth+1);return true;}catch{return false;}}))fail();return;}
  if('const'in s&&v!==s.const)fail();if(s.enum&&!s.enum.includes(v))fail();
  switch(s.type){
    case 'object': if(!obj(v)||s.additionalProperties!==false)fail();for(const k of s.required??[])if(!Object.hasOwn(v,k))fail();
      // Only established optional leaf defaults; required JOB fields never fill.
      for(const [k,shape] of Object.entries(s.properties??{}))if(!Object.hasOwn(v,k)&&!(s.required??[]).includes(k)&&Object.hasOwn(shape,'default'))Object.defineProperty(v,k,{value:snapshot(shape.default),enumerable:true});
      for(const[k,x]of Object.entries(v)){if(!Object.hasOwn(s.properties??{},k))fail();validate(s.properties![k],x,root,depth+1);}break;
    case 'array': if(!Array.isArray(v)||v.length<(s.minItems??0)||v.length>(s.maxItems??8192)||!s.items)fail();v.forEach(x=>validate(s.items!,x,root,depth+1));break;
    case 'string': if(typeof v!=='string'||[...v].length<(s.minLength??0)||[...v].length>(s.maxLength??262144)||(s.pattern&&!new RegExp(s.pattern).test(v)))fail();break;
    case 'integer': case 'number': if(typeof v!=='number'||!Number.isFinite(v)||(s.type==='integer'&&!Number.isSafeInteger(v))||v<(s.minimum??-Infinity)||v>(s.maximum??Infinity)||v<=(s.exclusiveMinimum??-Infinity)||v>=(s.exclusiveMaximum??Infinity))fail();break;
    case 'boolean':if(typeof v!=='boolean')fail();break;
    case 'null':if(v!==null)fail();break;
    default:if(!('const'in s)&&!s.enum)fail();
  }
}
export function jobCanonical(v:unknown):string {
  if(Array.isArray(v))return '['+v.map(jobCanonical).join(',')+']';
  if(obj(v))return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+jobCanonical(v[k])).join(',')+'}';
  return JSON.stringify(v);
}
export const jobEqual=(a:unknown,b:unknown)=>jobCanonical(a)===jobCanonical(b);
function floatSpelling(v:number):string {
  if(Object.is(v,-0))return '-0.0';
  const [mantissa, exp] = v.toExponential().split('e'), exponent=Number(exp);
  if(exponent < -4 || exponent >= 16) return mantissa+'e'+(exponent<0?'-':'+')+Math.abs(exponent).toString().padStart(2,'0');
  return Number.isInteger(v)?v.toFixed(1):v.toString();
}
// Python canonical byte sizes preserve float-vs-integer schema semantics. Pool
// hashing is separate: no Python/JS float spelling is used in that preimage.
function encoded(v:unknown,s:Schema,root:Schema):string {
  if(s.$ref)return encoded(v,root.$defs![s.$ref.replace('#/$defs/','')],root);
  const branches=s.anyOf??s.oneOf;
  if(branches){const b=branches.find(b=>{try{validate(b,v,root);return true;}catch{return false;}});if(!b)fail();return encoded(v,b,root);}
  if(obj(v))return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+encoded(v[k],s.properties![k],root)).join(',')+'}';
  if(Array.isArray(v))return '['+v.map(x=>encoded(x,s.items!,root)).join(',')+']';
  return typeof v==='number'&&s.type==='number'?floatSpelling(v):JSON.stringify(v);
}
export function poolCommitment(pool:JobPool):string {
  const {pool_sha256: omitted,...preimage}=pool;void omitted;
  const entries=pool.entries.map(p=>{let score:string|null=null;if(p.behavior_score!==null){const b=new ArrayBuffer(8);new DataView(b).setFloat64(0,p.behavior_score||0);score=Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('');}return {...p,behavior_score:score};});
  return jobSHA256(jobCanonical({...preimage,entries}));
}
function poolSemantics(p:JobPool){
  if(p.observed_peers!==p.entries.length+p.omitted_peers||p.omitted_identities!==(p.omitted_peers?'NOT_RETAINED':'NONE')||!unique(p.entries.map(e=>e.ip))||!unique(p.entries.map(e=>e.peer_id))||!jobEqual(p.limitations,['CAPTURE_COMPLETENESS_UNKNOWN','CURRENT_JOB_ONLY_NOT_VALIDATED','HISTORICAL_COMPARISON_UNSUPPORTED']))fail();
  const d=p.discovery,unknown=d.examined_peers===null&&d.excluded_peers===null,known=d.examined_peers!==null&&d.excluded_peers!==null;
  if(!(d.state==='UNAVAILABLE'?unknown:known)||d.state==='AVAILABLE'&&(d.warnings.length>0||d.excluded_peers!==0))fail();
  if(known && (d.examined_peers!+d.excluded_peers!>p.observed_peers || p.entries.filter(x=>x.behavior_state==='PRIORITIZED').length>d.examined_peers!))fail();
  const sorted=[...p.entries].sort((a,b)=>Number(b.behavior_state==='PRIORITIZED')-Number(a.behavior_state==='PRIORITIZED')||(b.behavior_score??0)-(a.behavior_score??0)||(a.ip<b.ip?-1:a.ip>b.ip?1:0));
  if(!jobEqual(sorted,p.entries))fail();
  for(const e of p.entries){
    if(!literalIP(e.ip)||e.ip.includes(':')&&new URL(`http://[${e.ip}]/`).hostname.slice(1,-1)!==e.ip)fail();
    if(e.matched_rows!==e.eligible_rows+e.suppressed_control_rows+e.eligibility_unavailable_rows||(e.behavior_state==='PRIORITIZED')!==(e.behavior_score!==null)||(e.behavior_score!==null&&e.behavior_score<0)||(d.state==='UNAVAILABLE')!==(e.behavior_state==='UNAVAILABLE')||e.peer_id!==jobSHA256(jobCanonical([p.source_sha256,e.ip])))fail();
  }
  if(poolCommitment(p)!==p.pool_sha256)fail();
  const s=schemas.pool as Schema;if(size(encoded(p,s,s))>16384)fail();
}
function coverage(c:JobCoverage){if(c.observed_peers!==c.pool_peers+c.pool_omitted_peers||c.pool_peers!==c.awaiting_selection_peers+c.not_selected_peers+c.selected_peers||c.selected_peers!==c.investigated_peers+c.not_investigated_peers)fail();}
function assessment(a:JobAssessment){
  const ids=a.evidence_quality.map(e=>e.evidence_id), facts=a.facts.map(f=>f.ref);
  if(!unique(ids)||!unique(facts)||a.facts.some(f=>!ids.includes(f.ref.split(':')[0])||f.ref.split(':')[1]!==f.name||f.unavailable_rows>0&&f.value!==null))fail();
  for(const e of a.evidence_quality){
    const c=e.counts;
    if(c.inspected!==c.matched+c.not_observed+c.scope_unavailable||c.matched!==c.retained+c.omitted+c.unavailable)fail();
    if(e.tool!=='compare_peer_cohort'&&c.matched&&e.status!==(c.unavailable===c.matched?'UNAVAILABLE':'OBSERVED'))fail();
  }
  for(const f of a.facts){
    const [id,name]=f.ref.split(':');
    const unit=f.name==='total_bytes'||f.name.endsWith('_bytes')?'bytes':f.name==='packet_count'?'packets':f.name==='sensor_count'?'sensors':'rows';
    if(!/^[a-f0-9]{64}$/.test(id)||f.ref!==`${id}:${name}`||name!==f.name||f.unit!==unit||(f.value===null)!==(f.unavailable_rows>0))fail();
    const c=a.evidence_quality.find(e=>e.evidence_id===id)!.counts, measured=f.observed_rows+f.unavailable_rows;
    if(measured>c.matched+c.scope_unavailable)fail();
    if(['matched_rows','total_bytes','packet_count','sensor_count','c2_eligible_rows','suppressed_control_rows','eligibility_unavailable_rows'].includes(f.name)&&measured!==c.matched+c.scope_unavailable)fail();
  }
  for(const i of [...a.support,...a.counterevidence])if(!unique(i.evidence_ids)||!unique(i.metric_refs)||i.evidence_ids.some(id=>!ids.includes(id))||i.metric_refs.some(ref=>!facts.includes(ref)||!i.evidence_ids.includes(ref.split(':')[0])))fail();
  if(a.mode==='FACTS_ONLY'&&(a.verdict!=='INCONCLUSIVE'||a.support.length||a.counterevidence.length||a.reason===null))fail();
  if(['SUSPICIOUS_C2','BENIGN_HYPOTHESIS'].includes(a.verdict)&&(!a.support.length||!a.counterevidence.length))fail();
}
function resultSemantics(r:JobResult){
  coverage(r.coverage);r.assessments.forEach(assessment);
  if(!jobEqual(r.limitations,['CAPTURE_COMPLETENESS_UNKNOWN','CURRENT_JOB_ONLY_NOT_VALIDATED','HISTORICAL_COMPARISON_UNSUPPORTED']))fail();
  const ids=r.assessments.flatMap(a=>a.evidence_quality.map(e=>e.evidence_id));
  if(!unique(r.assessments.map(a=>a.peer_id))||ids.length>12||!unique(ids)||r.assessments.reduce((n,a)=>n+a.facts.length,0)>24||r.coverage.investigated_peers!==r.assessments.filter(a=>a.mode==='MODEL_ASSISTED').length)fail();
  const s=schemas.result as Schema;if(size(encoded(r,s,s))>16384)fail();
}
function runSemantics(r:JobRun){
  poolSemantics(r.pool);coverage(r.coverage);const c=r.coverage,s=r.selection,entries=r.pool.entries;
  if(!unique(s.peer_ids)||(s.state==='PENDING')!==(s.peer_ids.length===0)||s.peer_ids.some(id=>!entries.some(e=>e.peer_id===id)))fail();
  if(r.source.job_id!==r.job_id||r.source.source_sha256!==r.pool.source_sha256||(r.request.expected_source_sha256!==null&&r.request.expected_source_sha256!==r.source.source_sha256)||c.selected_peers!==s.peer_ids.length||c.pool_peers!==entries.length||c.observed_peers!==r.pool.observed_peers||c.pool_omitted_peers!==r.pool.omitted_peers||c.awaiting_selection_peers!==(s.state==='PENDING'?entries.length:0))fail();
  const p=r.progress;
  if(p.transport_attempts>p.model_calls||p.planning_responses>p.transport_attempts||c.observed_peers>2*c.source_rows||entries.some(e=>e.matched_rows>c.source_rows)||![0,8650752].includes(p.source_bytes)||![0,c.source_rows].includes(p.source_records))fail();
  if((['INVESTIGATING','VALIDATING','COMPLETED','PARTIAL'].includes(r.status)||p.model_calls||p.tool_calls)&&(p.source_bytes!==8650752||p.source_records!==c.source_rows))fail();
  if(s.peer_ids.length&&(!p.planning_responses||!p.tool_calls))fail();
  if(r.status==='QUEUED'&&(s.peer_ids.length||[p.source_bytes,p.source_records,p.model_calls,p.tool_calls,p.transport_attempts,p.planning_responses].some(Boolean)))fail();
  const result=r.result;
  if(result&&r.reason!==null&&result.reason!==r.reason)fail();
  if(result&&(!jobEqual(result.execution,r.execution)||!jobEqual(result.progress,r.progress)))fail();
  if(result?.kind==='RESULT'){
    resultSemantics(result);
    for(const a of result.assessments)for(const q of a.evidence_quality){
      const entry=entries.find(e=>e.peer_id===a.peer_id);
      if(!entry||q.counts.inspected!==c.source_rows||q.counts.matched!==entry.matched_rows||q.counts.scope_unavailable!==0)fail();
    }
    if(!jobEqual(result.source,r.source)||result.pool_sha256!==r.pool.pool_sha256||result.language!==r.request.language||!jobEqual(result.coverage,c)||result.assessments.some(a=>!s.peer_ids.includes(a.peer_id)||a.verdict==='SUSPICIOUS_C2'&&entries.find(e=>e.peer_id===a.peer_id)!.eligible_rows===0))fail();
  }
  if(r.status==='COMPLETED'&&(result?.kind!=='RESULT'||!s.peer_ids.length||c.investigated_peers!==s.peer_ids.length||result.reason!==null||p.model_calls<2||p.transport_attempts<2))fail();
  if(r.status==='PARTIAL'&&result?.kind!=='RESULT'||['QUEUED','PREPARING','INVESTIGATING','VALIDATING','CANCELLED'].includes(r.status)&&result!==null||r.status==='FAILED'&&result?.kind==='RESULT')fail();
}
function leaves(v:unknown):void {
  if(Array.isArray(v)){v.forEach(leaves);return;}if(!obj(v))return;
  if(typeof v.question==='string'&&(!v.question.trim()||v.question.includes('\0')||size(v.question)>8000))fail();
  if(typeof v.model==='string'&&(size(v.model)>512||[...v.model].some(c=>c.charCodeAt(0)<32||c.charCodeAt(0)===127)))fail();
  if(Array.isArray(v.metric_refs)&&(!unique(v.metric_refs)||!Array.isArray(v.evidence_ids)||!unique(v.evidence_ids)))fail();
  Object.values(v).forEach(leaves);
}
function freeze<T>(value:T):T {if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
const limits:Record<keyof JobContracts,number>={run:65536,result:16384,step:131072,capabilities:131072,request:16384,pool:16384,evidence:32768,action:16384};
export function parseJob<K extends keyof JobContracts>(kind:K,input:unknown):JobContracts[K]{
  const value=snapshot(input), schema=schemas[kind] as Schema;validate(schema,value,schema);leaves(value);
  if(size(encoded(value,schema,schema))>limits[kind])fail();
  if(kind==='pool')poolSemantics(value as JobPool);
  if(kind==='result')resultSemantics(value as JobResult);
  if(kind==='run')runSemantics(value as JobRun);
  if(kind==='evidence')parseInvestigation('Evidence',value);
  if(kind==='step') {const s=value as JobContracts['step'];if(s.kind!=='TOOL'?[s.peer_id,s.tool,s.evidence_id,s.origin].some(x=>x!==null):s.tool===null||s.origin===null||s.origin==='AUTOMATIC_SEED'&&s.tool!=='peer_overview'||s.tool==='select_peers'&&(s.peer_id!==null||s.evidence_id!==null||s.origin!=='MODEL_REQUEST'))fail();}
  if(kind==='action'&&obj(value)) {if(value.action==='select_peers'&&(!unique(value.peer_ids as unknown[])||size(encoded(value,schema,schema))>1024))fail();if(Array.isArray(value.tools)&&!unique(value.tools.map(jobCanonical)))fail();if(Array.isArray(value.assessments)&&!unique(value.assessments.map(a=>(a as {peer_id:string}).peer_id)))fail();}
  return freeze(value as JobContracts[K]);
}
export function parseJobWire<K extends keyof JobContracts>(kind:K,raw:string):JobContracts[K]{const value=decodeJobJSON(raw,limits[kind]);if(kind==='action'&&obj(value)&&value.action==='select_peers'&&size(raw)>1024)fail();return parseJob(kind,value);}
export function parseJobPage<K extends 'run'|'step'>(kind:K,input:unknown):{items:JobContracts[K][];next_cursor:K extends 'run'?string|null:number|null}{
  const v=snapshot(typeof input==='string'?decodeJobJSON(input):input);if(!obj(v)||Object.keys(v).sort().join(',')!=='items,next_cursor'||!Array.isArray(v.items)||v.items.length>(kind==='run'?1:10))fail();
  const items=v.items.map(x=>parseJob(kind,x)),cursor=v.next_cursor;
  if(cursor!==null&&(kind==='run'?typeof cursor!=='string'||!/^[a-f0-9]{64}$/.test(cursor):typeof cursor!=='number'||!Number.isSafeInteger(cursor)||cursor<1||cursor>24))fail();
  if(cursor!==null&&(!items.length||cursor!==(kind==='run'?(items.at(-1) as JobRun).id:(items.at(-1) as JobContracts['step']).sequence)))fail();
  if(kind==='step'&&items.some((x,i)=>i>0&&(x as JobContracts['step']).sequence<=(items[i-1] as JobContracts['step']).sequence))fail();
  return {items,next_cursor:cursor} as ReturnType<typeof parseJobPage<K>>;
}
export function assertJobIdentity(r:JobRun,job:string,previous?:JobRun,request?:JobContracts['request']):void {
  if(r.job_id!==job||request&&!jobEqual(r.request,request))fail();
  if(!previous)return;
  for(const key of ['id','owner_id','job_id','created_at','request','source','execution','pool'] as const)if(!jobEqual(r[key],previous[key]))fail();
  if(r.revision<previous.revision||r.revision===previous.revision&&!jobEqual(r,previous)||terminal(previous.status)&&!jobEqual(r,previous))fail();
  for(const key of ['model_calls','tool_calls','planning_responses','transport_attempts','source_bytes','source_records'] as const)if(r.progress[key]<previous.progress[key])fail();
  if(previous.selection.state==='COMMITTED'&&!jobEqual(r.selection,previous.selection))fail();
}
