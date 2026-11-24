import { useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { captureAuthentication } from './authentication';
import { accountPage, accountRequest, safeAccountError, useAccountOperation, useSecurityText } from './accountSecurity';
import { auditActions, auditOutcomes, exportAuditPage, isAuditItem, type AuditFilters } from './accountAudit';
import { AccountNotice, AccountPagination } from './AccountWidgets';
import ReportLanguageScope from './ReportLanguage';
export default function AccountAudit({own=false}:{own?:boolean}){return <ReportLanguageScope><Audit key={String(own)} own={own}/></ReportLanguageScope>;}
function Audit({own}:{own:boolean}){
 const t=useSecurityText(),a=captureAuthentication(),operation=useAccountOperation();
 const [filters,setFilters]=useState<AuditFilters>({limit:50,offset:0});const [validation,setValidation]=useState(''),[exported,setExported]=useState<{total:number;nextOffset:number|null}>();
 const params=new URLSearchParams(Object.entries(filters).map(([k,v])=>[k,String(v)]));
 const path=(own?'/auth/activity':'/admin/audit')+'?'+params;
 const q=useQuery({queryKey:['account-audit',a.epoch,own,filters],queryFn:async()=>accountPage(await accountRequest(path),isAuditItem,filters.limit),retry:false});
 const submit=(e:FormEvent<HTMLFormElement>)=>{
  e.preventDefault();const f=new FormData(e.currentTarget);const next:AuditFilters={limit:Number(f.get('limit')),offset:0};
  for(const key of ['action','outcome','target',...(!own?['user_id']:[])] as const){const value=String(f.get(key)??'').trim();if(value)Object.assign(next,{[key]:value});}
  for(const key of ['since','until'] as const){const value=String(f.get(key)??'');if(value){const time=new Date(value).getTime()/1000;if(!Number.isFinite(time)){setValidation(t('Use valid date and time filters.','유효한 날짜와 시간을 입력하세요.'));return;}next[key]=time;}}
  if(next.since!==undefined&&next.until!==undefined&&next.since>next.until){setValidation(t('Start time must not be after end time.','시작 시간은 종료 시간 이후일 수 없습니다.'));return;}
  setValidation('');setExported(undefined);setFilters(next);
 };
 return <section className="account-security"><header><p className="eyebrow">SECURITY ACTIVITY</p><h1>{own?t('My activity','내 활동'):t('Security audit','보안 감사')}</h1><p className="muted">{own?t('Only events attributed to your immutable account ID are shown.','변경 불가능한 내 계정 ID에 연결된 이벤트만 표시됩니다.'):t('Shared security history, ordered newest first. This is not a tamper-proof ledger.','최신순으로 정렬된 공유 보안 기록입니다. 데이터베이스 관리자에 대한 위변조 방지를 보장하지 않습니다.')}</p></header>
 {a.auditAvailable===false&&<p role="alert">{t('Audit storage is unavailable.','감사 저장소를 사용할 수 없습니다.')}</p>}
 <form method="get" className="panel account-filter" onSubmit={submit}>
 {!own&&<label>{t('Actor ID','행위자 ID')}<input name="user_id" maxLength={200}/></label>}
 <label>{t('Action','작업')}<select name="action"><option value="">{t('All actions','모든 작업')}</option>{auditActions.map(v=><option key={v}>{v}</option>)}</select></label>
 <label>{t('Outcome','결과')}<select name="outcome"><option value="">{t('All outcomes','모든 결과')}</option>{auditOutcomes.map(v=><option key={v}>{v}</option>)}</select></label>
 <label>{t('Target','대상')}<input name="target" maxLength={200}/></label><label>{t('Since (local time)','시작 (현지 시간)')}<input name="since" type="datetime-local"/></label><label>{t('Until (local time)','종료 (현지 시간)')}<input name="until" type="datetime-local"/></label>
 <label>{t('Page size','페이지 크기')}<select name="limit" defaultValue="50"><option value="25">25</option><option value="50">50</option><option value="100">100</option></select></label>
 <button type="submit" disabled={q.isFetching||operation.pending}>{t('Apply filters','필터 적용')}</button></form>
 {validation&&<p role="alert">{validation}</p>}<AccountNotice error={operation.error||(q.error?safeAccountError(q.error):undefined)}/>
 <div className="account-actions"><button type="button" className="secondary" disabled={q.isFetching||operation.pending} onClick={()=>void q.refetch()}>{t('Refresh activity','활동 새로고침')}</button>{!own&&<button type="button" disabled={!q.data||q.isError||q.isFetching||operation.pending} onClick={()=>void operation.run(async()=>{setExported(undefined);setExported(await exportAuditPage(filters));},'')}>{t('Export this page (JSONL)','현재 페이지 내보내기 (JSONL)')}</button>}</div>
 {!own&&<p className="muted">{t(`Export includes at most ${filters.limit} events from this page, not the entire history. Each export is audited.`, `내보내기는 전체 기록이 아닌 현재 페이지의 최대 ${filters.limit}개 이벤트입니다. 내보내기 자체도 감사됩니다.`)}</p>}
 {exported&&<p role="status">{t(`Exported one page. Matching events: ${exported.total}. Next export offset: ${exported.nextOffset??'none'}.`,`한 페이지를 내보냈습니다. 일치 이벤트: ${exported.total}. 다음 내보내기 오프셋: ${exported.nextOffset??'없음'}.`)}</p>}
 {q.isPending&&<p role="status">{t('Loading activity…','활동 불러오는 중…')}</p>}
 <AccountPagination offset={filters.offset} total={q.isError?undefined:q.data?.total} count={q.data?.items.length??0} pending={q.isFetching||operation.pending} limit={filters.limit} onChange={offset=>{setExported(undefined);setFilters({...filters,offset});}}/>
 {q.data&&!q.isError&&<ul className="account-list">{q.data.items.map(item=><li key={item.id}><div className="section-heading"><strong>{item.action}</strong><span className="badge">{item.outcome}</span></div><time dateTime={new Date(item.timestamp*1000).toISOString()}>{new Date(item.timestamp*1000).toLocaleString()}</time><dl><dt>{t('Actor','행위자')}</dt><dd>{item.actor_name??'—'} · {item.actor_role??item.auth_kind}<br/><code>{item.actor_id??'—'}</code></dd><dt>{t('Target','대상')}</dt><dd><code>{item.target}</code></dd><dt>{t('Request','요청')}</dt><dd><code>{item.request_id??'—'}</code> · {item.status??'—'}</dd>{item.job_id&&<><dt>{t('Job','작업')}</dt><dd><code>{item.job_id}</code></dd></>}</dl><details><summary>{t('Event details','이벤트 상세')}</summary><code>{item.id}</code><p>{t('Verified source IP','검증된 출발지 IP')}: {item.source_ip??'—'}</p><pre>{JSON.stringify(item.details,null,2)}</pre></details></li>)}</ul>}
 {q.data?.items.length===0&&<p>{t('No events match these filters.','필터와 일치하는 이벤트가 없습니다.')}</p>}
 </section>;
}
