import { createPortal } from 'react-dom';
import { useReceiptTarget } from './investigationReceiptContext';
import { validatedIPSnapshot } from './investigationSnapshot';
import InvestigationEvidenceDetail from './InvestigationEvidenceDetail';
import { useInvestigationText } from './investigationLanguage';
import { useEffect, useRef, useState } from 'react';
import { investigationApi } from './investigationApi';
import { investigationError, InvestigationOwner, useInvestigationOwner } from './investigationLifecycle';
import { InvestigationConclusion, InvestigationEvidence, InvestigationExecution, ScopeDetails } from './InvestigationResult';
import type { Evidence, InvestigationRun, InvestigationStep, Page } from './investigationTypes';
import { terminal } from './investigationTypes';

export default function InvestigationRunView({ initial, visible = true, onCancelStart, canCancel = true, onRelease }: { initial: InvestigationRun; visible?: boolean; onCancelStart?: (run: InvestigationRun) => void; canCancel?: boolean; onRelease?: () => void }) {
  const l = useInvestigationText();
  const receiptTarget = useReceiptTarget();
  const [run, setRun] = useState(initial);
  const latest = useRef(initial);
  const [pollError, setPollError] = useState('');
  const [pollEpoch, setPollEpoch] = useState(0);
  const pollStopped = useRef(false);
  const [confirm, setConfirm] = useState(false);
  const [cancelSent, setCancelSent] = useState(false);
  const [cancelMessage, setCancelMessage] = useState('');
  const [cancelPending, setCancelPending] = useState(false);
  const [cancelUnconfirmed, setCancelUnconfirmed] = useState(false);
  const cancelOwner = useInvestigationOwner();
  const evidenceOwner = useInvestigationOwner();
  const [evidence, setEvidence] = useState<Evidence>();
  const [evidenceId, setEvidenceId] = useState('');
  const [selectedRef, setSelectedRef] = useState<string>();
  const evidenceTrigger = useRef<HTMLButtonElement | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const [evidenceError, setEvidenceError] = useState('');
  const [stepsOpen, setStepsOpen] = useState(false);
  const [executionOpen, setExecutionOpen] = useState(false);
  const update = (value: InvestigationRun) => {
    value = validatedIPSnapshot(value, latest.current);
    latest.current = value; setRun(value); setPollError('');
  };
  useEffect(() => {
    if (initial === latest.current) return;
    try {
      const next = validatedIPSnapshot(initial, latest.current);
      if (next.revision <= latest.current.revision) return;
      latest.current = next; setRun(next); setPollError('');
      if (pollStopped.current && !terminal(next.status)) setPollEpoch(value => value + 1);
    } catch { /* Ignore stale/foreign/malformed history; keep the mutation owner. */ }
  }, [initial]);
  const isTerminal = terminal(run.status);
  useEffect(() => {
    const owner = new InvestigationOwner();
    pollStopped.current = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let retired = false;
    const read = () => {
      void owner.request(signal => investigationApi.run(initial.job_id, latest.current, signal), value => {
        if (retired) return;
        update(value);
        if (!terminal(value.status)) timer = setTimeout(read, 2000);
      }, error => { if (!retired && !terminal(latest.current.status)) { pollStopped.current = true; setPollError(investigationError(error)); } });
    };
    if (!isTerminal) read();
    return () => { retired = true; clearTimeout(timer); owner.cancel(); };
  }, [initial.job_id, initial.id, pollEpoch, isTerminal]);
  const openEvidence = (reference: string, invoker?: HTMLButtonElement) => {
    const id = reference.split(':')[0];
    setSelectedRef(reference.includes(':') ? reference : undefined);
    if (invoker) evidenceTrigger.current = invoker;
    evidenceOwner.cancel(); setEvidence(undefined); setEvidenceId(id); setEvidenceError('');
    void evidenceOwner.request(signal => investigationApi.evidence(run.job_id, run, id, signal), setEvidence, error => setEvidenceError(investigationError(error)));
  };
  useEffect(() => {
    if (!visible) { evidenceOwner.cancel(); setEvidenceId(''); setEvidence(undefined); setStepsOpen(false); setExecutionOpen(false); setConfirm(false); }
  }, [visible, evidenceOwner]);
  const cancel = () => {
    if (cancelPending || cancelSent && !cancelUnconfirmed || terminal(latest.current.status) || !canCancel) return;
    onCancelStart?.(latest.current);
    setCancelPending(true); setCancelSent(true); setConfirm(false);
    void cancelOwner.request(signal => investigationApi.cancel(run.job_id, latest.current, signal), value => {
      update(value); setCancelPending(false); setCancelUnconfirmed(false); setCancelMessage('');
    }, error => { setCancelPending(false); setCancelUnconfirmed(true); setCancelMessage(investigationError(error)); });
  };
  const receipt = cancelSent && <section aria-label={l('취소 영수증', 'Cancellation receipt')}><code>{run.id}</code>{cancelPending ? <p role="status">{l('취소 수락 확인 중', 'Cancellation acknowledgment pending')}</p> : <><p role="status">{run.status} · {cancelUnconfirmed ? `${cancelMessage} — ${l("취소 결과 미확인", "cancellation unconfirmed")}` : l("취소 상태는 작업자 종료의 증명이 아닙니다.", "Cancellation status does not prove worker release.")}</p>{cancelUnconfirmed && isTerminal && <><p>{l('원래 취소 수락 응답은 여전히 미확인입니다. 관측된 종료 상태를 확인하면 클라이언트의 보존 슬롯만 해제됩니다. 물리적 작업자 종료는 확립되지 않았습니다.', 'Original cancellation acknowledgment remains unknown. Acknowledging the observed terminal state releases only the client retained slot; physical worker release is not established.')}</p>{onRelease && <button type="button" onClick={onRelease}>{l('관측된 종료 상태 확인', 'Acknowledge observed terminal outcome')}</button>}</>}{cancelUnconfirmed && !isTerminal && <button type="button" disabled={!canCancel} onClick={cancel}>{l('취소 재시도', 'Retry cancellation')}</button>}</>}</section>;
  const portalledReceipt = receiptTarget && receipt ? createPortal(receipt, receiptTarget) : null;
  if (!visible) return <section aria-label={l("IP 조사 실행 상태", "IP investigation run status")}><p role={cancelSent ? undefined : "status"}>{run.target_ip} · {run.status} · {l("AI 조사에서 실행 상세 확인", "Open AI investigation for run details")}</p>{pollError && <p role="alert">{pollError}  {l("· 상태 미확인", "status unconfirmed")}</p>}{portalledReceipt ?? receipt}<p>{l("관측 범위와 결론은 별개입니다. 화면 전환은 서버 작업을 취소하지 않습니다.", "Observation coverage and conclusions are separate. Navigation does not cancel server work.")}</p></section>;
  return <section className="investigation-run" aria-label={l("선택 조사", "Selected investigation")}>
    <div className="investigation-run-heading"><h3 ref={heading} tabIndex={-1}>{run.target_ip}</h3><p role="status">{run.status}{pollError ? l("· 상태 미확인", "status unconfirmed") : ''}</p><code>Run {run.id}</code><p>{run.request.question}</p><p className="muted">{l('언어', 'Language')}: {run.language} · {l('엔드포인트', 'Endpoint')}: {run.scope.endpoint_side} · {l('센서', 'Sensor')}: {run.scope.sensor_id ?? l('전체', 'All')}</p></div>
    {pollError && <div role="alert"><p>{pollError}</p><button type="button" className="secondary" onClick={() => setPollEpoch(value => value + 1)}>{l("상태 다시 읽기", "Retry status read")}</button></div>}
    {run.result && !('kind' in run.result) ? <InvestigationConclusion result={run.result} openEvidence={openEvidence}/> : <p>{run.result && 'kind' in run.result ? run.result.reason : run.reason ?? (terminal(run.status) ? l("사용 가능한 결론 없음", "No conclusion available") : l("서버 조사 대기 중", "Waiting for server investigation"))}</p>}
    {evidenceId && <InvestigationEvidenceDetail invoker={evidenceTrigger.current} fallback={heading.current} onClose={() => { evidenceOwner.cancel(); setEvidenceId(''); setEvidence(undefined); }}><code>{evidenceId}</code>{evidenceError ? <div role="alert"><p>{evidenceError}</p><button type="button" onClick={() => openEvidence(selectedRef ?? evidenceId)}>{l('근거 다시 읽기', 'Retry evidence')}</button></div> : evidence ? <InvestigationEvidence evidence={evidence} selectedRef={selectedRef}/> : <p role="status">{l('근거 읽는 중', 'Loading evidence')}</p>}</InvestigationEvidenceDetail>}
    <button type="button" aria-expanded={executionOpen} onClick={() => setExecutionOpen(!executionOpen)}>{l("실행·출처 상세", "Execution and source details")}</button>
    {executionOpen && <><InvestigationExecution execution={run.execution}/>
    <ScopeDetails jobId={run.job_id} scope={run.scope} source={run.result && !('kind' in run.result) ? run.result.source : undefined}/></>}
    <button type="button" className="secondary" aria-expanded={stepsOpen} onClick={() => setStepsOpen(!stepsOpen)}>{l("도구 실행 기록", "Tool receipts")}</button>
    {stepsOpen && <StepHistory key={`${run.id}:${terminal(run.status)}`} run={run} openEvidence={openEvidence}/>}
    {!terminal(run.status) && !cancelSent && <button type="button" className="danger" disabled={!canCancel} onClick={() => setConfirm(true)}>{l("조사 취소", "Cancel investigation")}</button>}
    {confirm && !terminal(run.status) && <section role="group" aria-label={l("취소 확인", "Confirm cancellation")}><p>{l("되돌릴 수 없습니다.", "Irreversible cancellation")}</p><p>Job {run.job_id} · IP {run.target_ip} · Run {run.id}</p><button type="button" className="danger" onClick={cancel}>{l("이 조사 취소 확인", "Confirm cancel this run")}</button><button type="button" className="secondary" onClick={() => setConfirm(false)}>{l("계속 조사", "Keep investigating")}</button></section>}
    {onRelease && isTerminal && !cancelPending && !cancelUnconfirmed && <button type="button" onClick={onRelease}>{l("확인한 실행 보관", "Acknowledge retained outcome")}</button>}
    {portalledReceipt ?? receipt}
  </section>;
}
function StepHistory({ run, openEvidence }: { run: InvestigationRun; openEvidence: (id: string, invoker?: HTMLButtonElement) => void }) {
  const l = useInvestigationText();
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
  return <section aria-label={l("도구 실행 기록", "Tool receipts")}><p>{l("서버의 도구·호출 영수증입니다. 모델의 내부 사고 과정이 아닙니다.", "Execution receipts, not chain of thought.")}</p>{error && <p role="alert">{error}</p>}{page?.items.map(step => <article key={step.sequence}><p>#{step.sequence} · {step.kind} · {step.tool ?? step.code ?? '—'}</p>{step.evidence_id && <button type="button" className="secondary investigation-reference" onClick={event => openEvidence(step.evidence_id!, event.currentTarget)}>{l("근거 보기", "Evidence")} {step.evidence_id}</button>}<small>Model calls {step.progress.model_calls} · Tool calls {step.progress.tool_calls} · Transport attempts {step.progress.transport_attempts}</small></article>)}<div className="investigation-actions"><button type="button" className="secondary" onClick={() => { setAfter(0); setEpoch(value => value + 1); }}>{l("처음", "First receipts")}</button><button type="button" className="secondary" disabled={page?.next_cursor == null} onClick={() => setAfter(page!.next_cursor!)}>{l("다음", "Next receipts")}</button><button type="button" className="secondary" onClick={() => setEpoch(value => value + 1)}>{l("다시 읽기", "Read receipts again")}</button></div></section>;
}
