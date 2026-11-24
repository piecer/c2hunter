import { ApiError } from './api';
import { authenticationHeaders, captureAuthentication, currentAuthentication, invalidateAuthentication } from './authentication';
export type AuditFilters = {user_id?:string;action?:string;outcome?:string;target?:string;since?:number;until?:number;limit:number;offset:number};
export type AuditItem = {id:string;timestamp:number;actor_id:string|null;actor_name:string|null;actor_role:string|null;auth_kind:string;action:string;target:string;outcome:string;request_id:string|null;source_ip:string|null;status:number|null;job_id:string|null;details:Record<string,unknown>};
export const auditOutcomes=['started','succeeded','failed','denied','cancelled','unknown'];
export const auditActions=['account.bootstrap','account.create','account.update','account.reset','account.password_change','account.local_reset','auth.login','auth.login_limited','auth.logout','session.revoke','access.denied','audit.export','http.operation','job.lifecycle'];
const text=(v:unknown,max=200):v is string=>typeof v==='string'&&v.length<=max;
const nullable=(v:unknown)=>v===null||text(v);
export function isAuditItem(v:unknown):v is AuditItem {
 const a=v as AuditItem;
 if(!a||typeof a!=='object'||Object.keys(a).sort().join(',')!=='action,actor_id,actor_name,actor_role,auth_kind,details,id,job_id,outcome,request_id,source_ip,status,target,timestamp')return false;
 if(!text(a.id,32)||!/^[a-f0-9]{32}$/.test(a.id)||!Number.isFinite(a.timestamp)||!nullable(a.actor_id)||!nullable(a.actor_name)||!(a.actor_role===null||['VIEWER','ANALYST','ADMIN'].includes(a.actor_role))||!['session','bearer','system','unauthenticated'].includes(a.auth_kind)||!text(a.action,80)||!text(a.target,300)||!auditOutcomes.includes(a.outcome)||!nullable(a.request_id)||!nullable(a.source_ip)||!nullable(a.job_id)||!(a.status===null||Number.isInteger(a.status)&&a.status>=100&&a.status<=599))return false;
 if(!a.details||typeof a.details!=='object'||Array.isArray(a.details))return false;
 return Object.entries(a.details).every(([k,value])=>{
  if(k==='role')return typeof value==='string'&&['VIEWER','ANALYST','ADMIN'].includes(value);
  if(k==='active'||k==='must_change_password')return typeof value==='boolean';
  if(k==='count')return Number.isSafeInteger(value)&&Number(value)>=0;
  if(k==='intent_id')return text(value,32)&&/^[a-f0-9]{32}$/.test(value);
  if(k==='family')return typeof value==='string'&&['analysis','pcap_export','ai_run','ip_investigation','job_investigation'].includes(value);
  return (k==='domain_status'||k==='reason')&&text(value,80)&&/^[A-Za-z0-9_:-]+$/.test(value);
 });
}
/** One page only: count bytes before decoding, validate rows and continuation,
 * then publish only to the exact live authority that requested the export. */
export async function exportAuditPage(filters:AuditFilters):Promise<{total:number;nextOffset:number|null}> {
 const a=captureAuthentication();if(a.authKind!=='session'||a.role!=='ADMIN'||!a.csrfToken)throw new ApiError('Named administrator session required',403,'INSUFFICIENT_ROLE');
 const response=await fetch('/api/v1/admin/audit/export',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:authenticationHeaders(a,{'content-type':'application/json',accept:'application/x-ndjson'}),body:JSON.stringify(filters)});
 invalidateAuthentication(response.status,a);
 if(!response.ok)throw new ApiError('Audit export not confirmed',response.status,response.status===403?'INSUFFICIENT_ROLE':'SECURITY_UNAVAILABLE');
 const max=2*1024*1024,advertised=response.headers.get('content-length');
 if(advertised!==null&&(!/^\d+$/.test(advertised)||Number(advertised)>max)){await response.body?.cancel();throw new Error('Export size invalid');}
 if(!response.body)throw new Error('Export body missing');const reader=response.body.getReader(),chunks:Uint8Array[]=[];let size=0;
 try{for(;;){const r=await reader.read();if(r.done)break;size+=r.value.byteLength;if(size>max){await reader.cancel();throw new Error('Export exceeds limit');}chunks.push(r.value);}}finally{reader.releaseLock();}
 const data=new Uint8Array(size);let cursor=0;for(const part of chunks){data.set(part,cursor);cursor+=part.length;}
 const content=new TextDecoder('utf-8',{fatal:true}).decode(data),lines=content.trim()?content.trimEnd().split('\n'):[];
 if(lines.length>filters.limit||lines.some(line=>!isAuditItem(JSON.parse(line))))throw new Error('Invalid audit page');
 const totalHeader=response.headers.get('x-total-count'),nextHeader=response.headers.get('x-next-offset');
 if(totalHeader===null||!/^\d+$/.test(totalHeader)||!Number.isSafeInteger(Number(totalHeader)))throw new Error('Missing export count');
 const total=Number(totalHeader),nextOffset=nextHeader===null||nextHeader===''?null:Number(nextHeader);
 if(nextOffset!==null&&(!/^\d+$/.test(nextHeader!)||!Number.isSafeInteger(nextOffset)||nextOffset<=filters.offset||nextOffset>10000000||nextOffset>filters.offset+filters.limit))throw new Error('Invalid export continuation');
 if(!currentAuthentication(a))throw new DOMException('Retired export','AbortError');
 const url=URL.createObjectURL(new Blob([data],{type:'application/x-ndjson'}));
 try{const anchor=document.createElement('a');anchor.href=url;anchor.download=`c2hunter-audit-page-${filters.offset}.jsonl`;anchor.click();}finally{URL.revokeObjectURL(url);}
 return {total,nextOffset};
}
