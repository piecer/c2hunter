import { useEffect, useRef, useState } from 'react';
import { investigationApi } from './investigationApi';
import { investigationError, InvestigationOwner, useInvestigationOwner } from './investigationLifecycle';
import { InvestigationConclusion, InvestigationEvidence, InvestigationExecution, ScopeDetails } from './InvestigationResult';
import type { Evidence, InvestigationRun, InvestigationStep, Page } from './investigationTypes';
import { terminal } from './investigationTypes';

export default function InvestigationRunView({ initial }: { initial: InvestigationRun }) {
  const [run, setRun] = useState(initial);
  const latest = useRef(initial);
  const [pollError, setPollError] = useState('');
  const [pollEpoch, setPollEpoch] = useState(0);
  const [confirm, setConfirm] = useState(false);
  const [cancelSent, setCancelSent] = useState(false);
  const [cancelMessage, setCancelMessage] = useState('');
  const cancelOwner = useInvestigationOwner();
  const evidenceOwner = useInvestigationOwner();
  const [evidence, setEvidence] = useState<Evidence>();
  const [evidenceId, setEvidenceId] = useState('');
  const [evidenceError, setEvidenceError] = useState('');
  const [stepsOpen, setStepsOpen] = useState(false);
  const update = (value: InvestigationRun) => {
    if (value.revision < latest.current.revision) return;
    latest.current = value; setRun(value); setPollError('');
  };
  const isTerminal = terminal(run.status);
  useEffect(() => {
    const owner = new InvestigationOwner();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let retired = false;
    const read = () => {
      void owner.request(signal => investigationApi.run(initial.job_id, latest.current, signal), value => {
        if (retired) return;
        update(value);
        if (!terminal(value.status)) timer = setTimeout(read, 2000);
      }, error => { if (!retired && !terminal(latest.current.status)) setPollError(investigationError(error)); });
    };
    if (!isTerminal) read();
    return () => { retired = true; clearTimeout(timer); owner.cancel(); };
  }, [initial.job_id, initial.id, pollEpoch, isTerminal]);
  const openEvidence = (id: string) => {
    evidenceOwner.cancel(); setEvidence(undefined); setEvidenceId(id); setEvidenceError('');
    void evidenceOwner.request(signal => investigationApi.evidence(run.job_id, run, id, signal), setEvidence, error => setEvidenceError(investigationError(error)));
  };
  const cancel = () => {
    if (cancelSent) return;
    setCancelSent(true); setConfirm(false);
    void cancelOwner.request(signal => investigationApi.cancel(run.job_id, latest.current, signal), value => {
      update(value); setCancelMessage('취소 상태는 작업자 종료의 증명이 아닙니다. / Cancellation status does not prove worker release.');
    }, error => setCancelMessage(`${investigationError(error)} — 취소 결과 미확인 / cancellation unconfirmed`));
  };
  return <section className="investigation-run" aria-label="선택 조사 / Selected investigation">
    <div className="investigation-run-heading"><h3>{run.target_ip}</h3><p role="status">{run.status}{pollError ? ' · 상태 미확인 / status unconfirmed' : ''}</p><code>Run {run.id}</code><p>{run.request.question}</p><p className="muted">Language: {run.language} · Endpoint: {run.scope.endpoint_side} · Sensor: {run.scope.sensor_id ?? 'All'}</p></div>
    {pollError && <div role="alert"><p>{pollError}</p><button type="button" className="secondary" onClick={() => setPollEpoch(value => value + 1)}>상태 다시 읽기 / Retry status read</button></div>}
    {run.result && !('kind' in run.result) ? <InvestigationConclusion result={run.result} openEvidence={openEvidence}/> : <p>{run.result && 'kind' in run.result ? run.result.reason : run.reason ?? (terminal(run.status) ? '사용 가능한 결론 없음 / No conclusion available' : '서버 조사 대기 중 / Waiting for server investigation')}</p>}
    {evidenceId && <section className="investigation-evidence"><div className="investigation-actions"><h4>선택 근거 / Selected evidence</h4><button type="button" className="secondary" onClick={() => { evidenceOwner.cancel(); setEvidenceId(''); setEvidence(undefined); }}>근거 닫기 / Close evidence</button></div><code>{evidenceId}</code>{evidenceError ? <div role="alert"><p>{evidenceError}</p><button type="button" onClick={() => openEvidence(evidenceId)}>근거 다시 읽기 / Retry evidence</button></div> : evidence ? <InvestigationEvidence evidence={evidence}/> : <p role="status">근거 읽는 중 / Loading evidence</p>}</section>}
    <InvestigationExecution execution={run.execution}/>
    <ScopeDetails jobId={run.job_id} scope={run.scope} source={run.result && !('kind' in run.result) ? run.result.source : undefined}/>
    <button type="button" className="secondary" aria-expanded={stepsOpen} onClick={() => setStepsOpen(!stepsOpen)}>도구 실행 기록 / Tool receipts</button>
    {stepsOpen && <StepHistory key={`${run.id}:${terminal(run.status)}`} run={run} openEvidence={openEvidence}/>}
    {!terminal(run.status) && !cancelSent && <button type="button" className="danger" onClick={() => setConfirm(true)}>조사 취소 / Cancel investigation</button>}
    {confirm && !terminal(run.status) && <section role="group" aria-label="취소 확인 / Confirm cancellation"><p>되돌릴 수 없습니다. / Irreversible cancellation</p><p>Job {run.job_id} · IP {run.target_ip} · Run {run.id}</p><button type="button" className="danger" onClick={cancel}>이 조사 취소 확인 / Confirm cancel this run</button><button type="button" className="secondary" onClick={() => setConfirm(false)}>계속 조사 / Keep investigating</button></section>}
    {cancelMessage && <p role="status">{cancelMessage}</p>}
  </section>;
}
function StepHistory({ run, openEvidence }: { run: InvestigationRun; openEvidence: (id: string) => void }) {
  const owner = useInvestigationOwner();
  const [after, setAfter] = useState(0);
  const [epoch, setEpoch] = useState(0);
  const [page, setPage] = useState<Page<InvestigationStep, number>>();
  const [error, setError] = useState('');
  useEffect(() => {
    setPage(undefined); setError('');
    void owner.request(signal => investigationApi.steps(run.job_id, run, after, signal), setPage, value => setError(investigationError(value)));
    return () => owner.cancel();
  }, [run, owner, after, epoch]);
  return <section aria-label="도구 실행 기록 / Tool receipts"><p>서버의 도구·호출 영수증입니다. 모델의 내부 사고 과정이 아닙니다. / Execution receipts, not chain of thought.</p>{error && <p role="alert">{error}</p>}{page?.items.map(step => <article key={step.sequence}><p>#{step.sequence} · {step.kind} · {step.tool ?? step.code ?? '—'}</p>{step.evidence_id && <button type="button" className="secondary investigation-reference" onClick={() => openEvidence(step.evidence_id!)}>근거 보기 / Evidence {step.evidence_id}</button>}<small>Model calls {step.progress.model_calls} · Tool calls {step.progress.tool_calls} · Transport attempts {step.progress.transport_attempts}</small></article>)}<div className="investigation-actions"><button type="button" className="secondary" onClick={() => { setAfter(0); setEpoch(value => value + 1); }}>처음 / First receipts</button><button type="button" className="secondary" disabled={page?.next_cursor == null} onClick={() => setAfter(page!.next_cursor!)}>다음 / Next receipts</button><button type="button" className="secondary" onClick={() => setEpoch(value => value + 1)}>다시 읽기 / Read receipts again</button></div></section>;
}
