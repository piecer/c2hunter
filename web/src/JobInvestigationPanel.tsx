import { useEffect, useRef, useState } from 'react';
import { jobApi, captureJobRequest } from './jobInvestigationApi';
import { JobIntent, JobReads } from './jobInvestigationLifecycle';
import { assertJobIdentity } from './jobInvestigationContract';
import { terminal, type Evidence } from './investigationTypes';
import { InvestigationEvidence } from './InvestigationResult';
import type { JobAssessment, JobCapabilities, JobRun, JobStep } from './jobInvestigationTypes';
import './jobInvestigation.css';

type Language='ko'|'en';
const errorText=(e:unknown)=>e instanceof Error?e.message:'Job investigation request failed';
function useReads(){const [reads]=useState(()=>new JobReads());useEffect(()=>()=>reads.retire(),[reads]);return reads;}
type EntryProps={jobId:string;sourceAvailable?:boolean};
export function JobInvestigationEntry({jobId,sourceAvailable=true}:EntryProps){
  const [open,setOpen]=useState(false);
  return open?<JobInvestigationPanel key={jobId} jobId={jobId} sourceAvailable={sourceAvailable}/>:<section className="panel job-investigation" aria-label="Experimental job investigation entry"><h2>실험적 작업 조사 / Experimental job investigation</h2><p>보존된 피어 일부를 조사합니다. 전체 작업의 C2 유무를 판정하지 않습니다. / Investigate a bounded subset of retained peers, not whether the entire job contains C2.</p><button type="button" onClick={()=>setOpen(true)}>실험적 조사 열기 / Open experimental investigation</button></section>;
}
export default function JobInvestigationPanel({jobId,sourceAvailable=true}:EntryProps){return <Session key={jobId} jobId={jobId} sourceAvailable={sourceAvailable}/>;}
function Session({jobId,sourceAvailable}:EntryProps){
  const reads=useReads();const [intent]=useState(()=>new JobIntent({getItem:key=>sessionStorage.getItem(key),setItem:(key,value)=>sessionStorage.setItem(key,value),removeItem:key=>sessionStorage.removeItem(key)}));
  const [language,setLanguage]=useState<Language>('ko'),[question,setQuestion]=useState('관측된 패턴, 반대 근거와 다음 확인 사항을 설명해 주세요.'),[remote,setRemote]=useState(false);
  const [cap,setCap]=useState<JobCapabilities>(),[error,setError]=useState(''),[capError,setCapError]=useState('');
  const [pending,setPending]=useState<{job:string;body:string}|null>(()=>{try{return intent.pending();}catch{return null;}});
  const [storageError,setStorageError]=useState(()=>{try{intent.pending();return '';}catch{return 'Admission intent is unreadable; new admission is blocked. History remains available.';}});
  const [busy,setBusy]=useState(false),busyRef=useRef(false);
  const [selected,setSelected]=useState<{run:JobRun;epoch:number}>();
  const epoch=useRef(0);const [history,setHistory]=useState<{items:JobRun[];next_cursor:string|null}>(),[historyError,setHistoryError]=useState('');
  const [after,setAfter]=useState<string|null>(null),[refresh,setRefresh]=useState(0);
  const l=(ko:string,en:string)=>language==='ko'?`${ko} / ${en}`:en;
  useEffect(()=>{void reads.request('capability',s=>jobApi.capabilities(s),setCap,e=>setCapError(errorText(e)));},[reads]);
  useEffect(()=>{
    setHistory(undefined);setHistoryError('');
    void reads.request('history',s=>jobApi.history(jobId,after,s),page=>{page.items.forEach(r=>assertJobIdentity(r,jobId));setHistory(page);},e=>setHistoryError(errorText(e)));
    return ()=>reads.retireChannel('history');
  },[jobId,after,refresh,reads]);
  const choose=(run:JobRun)=>{
    reads.retireChannel('post');busyRef.current=false;setBusy(false);
    setSelected({run,epoch:++epoch.current});
  };
  const submit=()=>{
    if(busyRef.current)return;
    try{
      const saved=intent.pending();if(saved&&saved.job!==jobId)throw new Error('Resolve the other job admission before starting another');
      if(!saved&&(!sourceAvailable||cap?.availability!=='CONFIGURED_NOT_PROBED'))return;
      const body=saved?.body??captureJobRequest(question,language,remote);
      intent.capture(jobId,body);setPending({job:jobId,body});busyRef.current=true;setBusy(true);setError('');
      void reads.request('post',s=>jobApi.create(jobId,body,s),run=>{
        busyRef.current=false;setBusy(false);setSelected({run,epoch:++epoch.current});
        try{intent.resolve(run);setPending(null);}catch(e){setStorageError(errorText(e));}
        setRefresh(v=>v+1);
      },e=>{busyRef.current=false;setBusy(false);setError(errorText(e));});
    }catch(e){setError(errorText(e));}
  };
  const ready=sourceAvailable&&cap?.availability==='CONFIGURED_NOT_PROBED'&&cap.dispatch_scope==='OWNED_CAPABLE_RUNTIME';
  return <section className="panel job-investigation" aria-label="Experimental job investigation">
    <header><h2>{l('실험적 작업 조사','Experimental job investigation')}</h2><p className="record-id">Job {jobId}</p><p>{l('전체 작업 결론은 확립되지 않았습니다. 제한된 관측 자료의 조사 가설입니다.','Whole-job conclusion is not established. This is a hypothesis from bounded observations.')}</p></header>
    {selected&&<RunView key={`${selected.run.id}:${selected.epoch}`} initial={selected.run} language={language}/>}
    <p role="status">{cap?`${cap.availability} — ${cap.reason??l('설정됨, 연결·모델 건강 상태 미검증','configured, not proof of model health')}`:capError||l('기능 확인 중','Checking capability')}</p>
    <p>{l('AI_JOB_INVESTIGATION_ENABLED 기본값은 false입니다. UI는 서버 설정을 변경하지 않습니다.','AI_JOB_INVESTIGATION_ENABLED defaults to false. This UI does not change server configuration.')}</p>
    <p>{l('수락 시 저장 출처를 한 번 고정합니다.','Pin the stored source once at admission.')} <code>expected_source_sha256=null</code> — {l('미리보기나 현재 캡처 검증이 아닙니다. 동일 요청 재시도에서도 null 의도를 유지합니다.','not a preview or capture validation; exact retries retain this null intent.')}</p>
    <p>{l('전역 한도','Run-global budgets')}: 6 model calls · 12 tools · 4 planning responses · 300s execution. {l('최대 32 피어 보존, 3 피어 선택. 자동 seed 조회는 AI 평가 완료가 아닙니다.','At most 32 retained peers, 3 selected. Automatic seed retrieval is not completed AI assessment.')}</p>
    <label>{l('표시 언어','Display language')}<select value={language} onChange={e=>setLanguage(e.target.value as Language)}><option value="ko">한국어</option><option value="en">English</option></select></label>
    {!sourceAvailable&&<p className="warning">{l('현재 출처를 사용할 수 없어 새 조사는 차단됩니다. 저장 이력과 동일 요청 복구는 별개입니다.','Current source is unavailable; new investigation is blocked. Saved history and exact-request recovery are independent.')}</p>}
    <form onSubmit={e=>{e.preventDefault();submit();}}><fieldset disabled={busy||Boolean(pending)||Boolean(storageError)}><legend>{l('새 조사 요청','New investigation request')}</legend>
      <label>{l('질문','Question')}<textarea maxLength={2000} rows={3} value={question} onChange={e=>setQuestion(e.target.value)} required/></label>
      <p>{l('새 요청의 보고서 언어','New request report language')}: {language}</p>
      <label><input type="checkbox" checked={remote} disabled={!cap?.remote_server_allowed} onChange={e=>setRemote(e.target.checked)}/>{l('원격 모델 전송에 명시적으로 동의','Explicitly allow remote model transfer')}</label>
      <button disabled={!ready||!question.trim()||!globalThis.crypto?.getRandomValues}>{l('실험적 조사 시작','Start experimental investigation')}</button>
    </fieldset></form>
    {pending&&<section className="warning" aria-label="Unconfirmed admission"><p>{l('수락 결과가 불확실하거나 확인 중입니다. 새 요청을 만들지 않고 정확한 본문·키·null 의도로만 재시도합니다.','Admission is unconfirmed or awaiting acknowledgment. Retry only the exact body, key and null intent; do not create a duplicate.')}</p><p>Job {pending.job}</p><button type="button" disabled={busy||pending.job!==jobId||Boolean(storageError)} onClick={submit}>{l('정확한 요청 재시도','Retry exact request')}</button><p>{l('화면 전환은 서버 작업을 취소하지 않습니다. 다른 작업을 선택해도 미확인 요청은 유지됩니다.','Navigation does not cancel server work. The unresolved request survives choosing another run.')}</p></section>}
    {busy&&<p role="status">{l('수락 확인 중','Awaiting admission acknowledgment')}</p>}{(error||storageError)&&<p role="alert">{error||storageError}</p>}
    <section aria-label="Job investigation history"><h3>{l('저장된 조사','Saved investigations')}</h3><p>{l('현재 기능·모델·출처가 없어도 저장된 이력과 근거는 별도로 읽습니다.','Saved history and evidence remain readable independently of current feature, model or source availability.')}</p>
      {historyError&&<p role="alert">{historyError}</p>}{history?.items.map(r=><article key={r.id}><button type="button" onClick={()=>choose(r)}>{l('저장된 조사 보기','View saved run')} {r.status} <code>{r.id}</code></button><p>{r.request.question}</p></article>)}{history?.items.length===0&&<p>{l('저장된 조사 없음','No saved runs')}</p>}
      <div className="job-actions"><button type="button" onClick={()=>{setAfter(null);setRefresh(n=>n+1);}}>{l('처음 이력 / 다시 읽기','First history / Refresh')}</button><button type="button" disabled={!history?.next_cursor} onClick={()=>setAfter(history!.next_cursor)}>{l('다음 이력','Next history')}</button></div>
    </section>
  </section>;
}
function RunView({initial,language}:{initial:JobRun;language:Language}){
  const [run,setRun]=useState(initial),current=useRef(initial),reads=useReads();
  const [error,setError]=useState(''),[paused,setPaused]=useState(false),[busy,setBusy]=useState(false);
  const [page,setPage]=useState(0),[peer,setPeer]=useState<string|null>(null),[provenance,setProvenance]=useState(false);
  const [steps,setSteps]=useState<{items:JobStep[];next_cursor:number|null}>(),[stepAfter,setStepAfter]=useState(0);
  const l=(ko:string,en:string)=>language==='ko'?`${ko} / ${en}`:en;
  const publish=(next:JobRun)=>{assertJobIdentity(next,initial.job_id,current.current);current.current=next;setRun(next);};
  useEffect(()=>{
    if(terminal(run.status)||paused)return;
    const timer=setTimeout(()=>{void reads.request('poll',s=>jobApi.run(initial.job_id,current.current,s),next=>{assertJobIdentity(next,initial.job_id,current.current);current.current=next;setRun(next);},e=>{setError(errorText(e));setPaused(true);});},2000);
    return ()=>{clearTimeout(timer);reads.retireChannel('poll');};
  },[run,paused,initial.job_id,reads]);
  const cancel=()=>{
    if(busy||terminal(current.current.status))return;
    setBusy(true);setPaused(true);reads.retireChannel('poll');
    const expected=current.current;
    void reads.request('cancel',s=>jobApi.cancel(initial.job_id,expected,s),next=>{publish(next);setBusy(false);setPaused(false);},e=>{setBusy(false);setError(errorText(e));});
  };
  const readSteps=(after:number)=>{setSteps(undefined);setStepAfter(after);void reads.request('steps',s=>jobApi.steps(initial.job_id,current.current,after,s),setSteps,e=>setError(errorText(e)));};
  const result=run.result?.kind==='RESULT'?run.result:undefined;
  const assessments=result?.assessments??[],completed=assessments.filter(a=>a.mode==='MODEL_ASSISTED');
  const verdict=completed.some(a=>a.verdict==='SUSPICIOUS_C2')?'SUSPICIOUS_C2':completed.some(a=>a.verdict==='NEEDS_REVIEW')?'NEEDS_REVIEW':completed.length&&completed.every(a=>a.verdict==='BENIGN_HYPOTHESIS')?'BENIGN_HYPOTHESIS':'INCONCLUSIVE';
  const c=run.coverage,selected=run.selection.peer_ids;
  return <section aria-label="Saved job investigation" className="job-run">
    <h3>{l('평가된 피어 범위의 결론','Scoped verdict for assessed peers')}: {verdict}</h3>
    <p>{run.status} · {l('AI 평가 완료','AI assessment complete')} {c.investigated_peers}/{c.selected_peers}. {l('전체 IP 검사나 C2 부재를 뜻하지 않습니다.','This does not mean all job IPs were inspected or C2 is absent.')}</p>
    {run.status==='COMPLETED'&&<p className="warning">{l('COMPLETED만으로 기한 내 COMMIT 완료나 실행 ACK를 증명하지 못합니다. 저장소를 다시 열어 읽은 경우에도 같습니다. 불확실한 COMMIT은 ACK 없이 격리되고 소유 슬롯을 유지합니다.','COMPLETED alone does not prove deadline-bounded COMMIT or acknowledged execution, including after reopening storage. An uncertain COMMIT is quarantined without ACK and retains its ownership slot.')}</p>}
    <p><strong>{l('핵심 패턴','Key patterns')}:</strong> {completed.flatMap(a=>a.support).map(i=>i.text).join(' · ')||l('모델 근거 패턴이 아직 확립되지 않았습니다.','No evidence-backed model pattern established yet.')}</p>
    <p><strong>{l('대안 원인','Alternative cause')}:</strong> {completed.flatMap(a=>a.counterevidence).map(i=>i.text).join(' · ')||l('대안 원인은 미확인입니다. 누락은 반대 근거가 아닙니다.','Alternative cause unconfirmed; missing counterevidence is not contrary evidence.')}</p>
    <p><strong>{l('다음 확인','Next check')}:</strong> {completed.flatMap(a=>a.next_checks).join(' · ')||l('선택 피어의 저장 근거와 출처 한계를 확인하세요.','Inspect the selected peer’s saved evidence and source limitations.')}</p>
    <p>{l('위 요약은 모델 가설이며 아래 관측 사실과 구분됩니다.','The summary above is model hypothesis, separate from observed facts below.')}</p>
    <p className="record-id">Run {run.id} · revision {run.revision}</p>
    <p className="warning">capture completeness: UNKNOWN · lineage: CURRENT_JOB_ONLY_NOT_VALIDATED · whole-job conclusion: NOT_ESTABLISHED</p>
    <p>{l('관측 피어','Observed peers')} {c.observed_peers} · pool {c.pool_peers} · {l('생략','omitted')} {c.pool_omitted_peers} ({run.pool.omitted_identities}) · {l('선택 대기','awaiting selection')} {c.awaiting_selection_peers} · NOT_SELECTED {c.not_selected_peers} · {l('선택 후 AI 미평가','selected, AI assessment incomplete')} {c.not_investigated_peers}. {l('미관측 피어 수','Unobserved peers')}: UNKNOWN (null).</p>
    <p>{l('출처','Source')} {c.source_status} · {c.source_rows} rows. {l('피어별 행은 합산 가능한 작업 flow 수가 아닙니다.','Per-peer rows are not additive job flow counts.')}</p>
    <p>{l('행동 우선순위는 확률·정상 판정이 아닙니다.','Behavior priority is neither probability nor evidence of normality.')} legacy membership: NOT_READ · historical comparison: UNSUPPORTED / off.</p>
    <p>Discovery {run.pool.discovery.state} · examined {run.pool.discovery.examined_peers??'UNKNOWN'} · excluded {run.pool.discovery.excluded_peers??'UNKNOWN'}</p>
    <ul>{[...run.pool.limitations,...run.pool.discovery.warnings,...(result?.limitations??[])].map((text,i)=><li key={i}>{text}</li>)}</ul>
    <p>{run.reason??result?.reason}</p><p>Model {run.progress.model_calls}/6 · tools {run.progress.tool_calls}/12 · plans {run.progress.planning_responses}/4 · transport {run.progress.transport_attempts}/12 · source records {run.progress.source_records} · reserved bytes {run.progress.source_bytes} (not measured)</p>
    {run.status==='CANCELLED'&&<p className="warning">{l('취소 상태는 물리적 종료나 비용 환불의 증거가 아닙니다.','CANCELLED is not proof of physical exit or a cost refund.')}</p>}
    {!terminal(run.status)&&<div className="job-actions"><button type="button" disabled={busy} onClick={cancel}>{l('이 조사 취소 요청','Request cancellation of this run')}</button>{paused&&<button type="button" onClick={()=>{setError('');setPaused(false);}}>{l('상태 읽기 재개','Resume status reads')}</button>}</div>}{error&&<p role="alert">{error}</p>}
    <h4>{l('보존된 피어','Retained peers')}</h4><div className="job-peer-page">{run.pool.entries.slice(page*8,page*8+8).map(p=>{
      const a=assessments.find(a=>a.peer_id===p.peer_id),status=run.selection.state==='PENDING'?'AWAITING_SELECTION':!selected.includes(p.peer_id)?'NOT_SELECTED':a?.mode==='MODEL_ASSISTED'?`AI_ASSESSMENT_COMPLETE · ${a.verdict}`:a?.mode==='FACTS_ONLY'?'FACTS_ONLY · NOT_INVESTIGATED':'SELECTED_NOT_ASSESSED';
      return <article key={p.peer_id}><h5>{p.ip}</h5><p>{status}</p><p>{p.behavior_state} {p.behavior_score??''} · matched {p.matched_rows} · eligible {p.eligible_rows} · suppressed {p.suppressed_control_rows} · unavailable {p.eligibility_unavailable_rows}</p><button type="button" aria-label={`Peer details ${p.peer_id}`} aria-expanded={peer===p.peer_id} onClick={()=>setPeer(peer===p.peer_id?null:p.peer_id)}>{l('피어 상세','Peer details')} <code>{p.peer_id}</code></button></article>;
    })}</div>
    <nav aria-label="Pool pages" className="job-actions"><button type="button" disabled={page===0} onClick={()=>{setPeer(null);setPage(p=>p-1);}}>{l('이전 피어','Previous peers')}</button><span>{page+1}/{Math.max(1,Math.ceil(run.pool.entries.length/8))}</span><button type="button" disabled={(page+1)*8>=run.pool.entries.length} onClick={()=>{setPeer(null);setPage(p=>p+1);}}>{l('다음 피어','Next peers')}</button></nav>
    {peer&&<PeerDetail key={`${run.id}:${peer}`} run={run} peer={peer} assessment={assessments.find(a=>a.peer_id===peer)} language={language}/>}
    <button type="button" aria-expanded={Boolean(steps)} onClick={()=>steps?setSteps(undefined):readSteps(0)}>{l('실행 기록','Execution receipts')}</button>
    {steps&&<section aria-label="Execution receipts">{steps.items.map(s=><article key={s.sequence}><p>{s.sequence} · {s.kind} · {s.tool} · {s.origin===null?'—':s.origin==='AUTOMATIC_SEED'?l('자동 조회 — 모델 지시 아님','AUTOMATIC_SEED — not model-directed'):l('모델 지시','MODEL_REQUEST')}</p><p>{s.peer_id} {s.evidence_id} {s.code}</p></article>)}<button type="button" disabled={stepAfter===0} onClick={()=>readSteps(0)}>{l('처음 기록','First receipts')}</button><button type="button" disabled={steps.next_cursor===null} onClick={()=>readSteps(steps.next_cursor!)}>{l('다음 기록','Next receipts')}</button></section>}
    <button type="button" aria-expanded={provenance} onClick={()=>setProvenance(!provenance)}>{l('출처·실행 바인딩','Source & execution bindings')}</button>
    {provenance&&<section aria-label="Immutable provenance"><p>{l('모델 태그는 불변 가중치 해시가 아닙니다.','A model tag is not an immutable weight digest.')}</p><pre>{JSON.stringify({request:run.request,source:run.source,pool_sha256:run.pool.pool_sha256,execution:run.execution},null,2)}</pre></section>}
  </section>;
}
function PeerDetail({run,peer,assessment:a,language}:{run:JobRun;peer:string;assessment?:JobAssessment;language:Language}){
  const reads=useReads();const [evidence,setEvidence]=useState<Evidence>(),[error,setError]=useState(''),[loading,setLoading]=useState(false);
  const trigger=useRef<HTMLButtonElement|null>(null);
  const l=(ko:string,en:string)=>language==='ko'?`${ko} / ${en}`:en;
  const open=(id:string,button:HTMLButtonElement)=>{trigger.current=button;setEvidence(undefined);setError('');setLoading(true);void reads.request('evidence',s=>jobApi.evidence(run.job_id,run,peer,id,s),e=>{setEvidence(e);setLoading(false);},e=>{setError(errorText(e));setLoading(false);});};
  const close=()=>{reads.retireChannel('evidence');setEvidence(undefined);setError('');setLoading(false);trigger.current?.focus();};
  return <section aria-label="Peer assessment detail"><h4>{l('피어 평가 상세','Peer assessment detail')}</h4><code>{peer}</code>{!a?<p>{l('AI 평가 미완료 — 정상 판정이 아닙니다.','AI assessment incomplete — not a benign verdict.')}</p>:<>
    <p>{a.mode} · {a.verdict} · {a.reason}</p><h5>{l('관측 사실','Observed facts')}</h5><dl>{a.facts.map(f=><div key={f.ref}><dt>{f.name}</dt><dd>{f.value??'UNKNOWN'} {f.unit} · observed {f.observed_rows} / unavailable {f.unavailable_rows}<code>{f.ref}</code></dd></div>)}</dl>
    <h5>{l('모델 가설','Model hypotheses')}</h5>{(['support','counterevidence'] as const).map(kind=><section key={kind}><h6>{kind}</h6>{a[kind].map((item,i)=><article key={i}><p>{item.text}</p>{item.metric_refs.map(ref=><code key={ref}>{ref}</code>)}<p>{l('근거 참조','Evidence references')}: {item.evidence_ids.join(', ')}</p></article>)}</section>)}
    <h5>{l('불확실성','Uncertainty')}</h5><ul>{a.uncertainty.map((s,i)=><li key={i}>{s}</li>)}</ul><h5>{l('다음 확인','Next checks')}</h5><ul>{a.next_checks.map((s,i)=><li key={i}>{s}</li>)}</ul>
    <h5>{l('발급된 근거','Issued evidence')}</h5>{a.evidence_quality.map(q=><article key={q.evidence_id}><p>{q.tool} · {q.status} · matched {q.counts.matched} / retained {q.counts.retained} / omitted {q.counts.omitted} / unavailable {q.counts.unavailable} / scope unavailable {q.counts.scope_unavailable}</p><button type="button" aria-label={`Evidence ${q.evidence_id}`} onClick={e=>open(q.evidence_id,e.currentTarget)}>{l('근거 보기','Evidence')} <code>{q.evidence_id}</code></button></article>)}
  </>}{(evidence||loading||error)&&<button type="button" onClick={close}>{l('근거 닫기','Close evidence')}</button>}{loading&&<p role="status">{l('근거 읽는 중','Loading evidence')}</p>}{error&&<p role="alert">{error}</p>}{evidence&&<InvestigationEvidence key={evidence.evidence_id} evidence={evidence}/>}</section>;
}
