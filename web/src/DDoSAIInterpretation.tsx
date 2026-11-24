import InterpretationCancellationReceipts from './InterpretationCancellationReceipts';
import { decodeDDoSInterpretation } from './ddosInterpretation';
import { createPortal } from 'react-dom';
import { useLayoutEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';
import { captureAuthentication, currentAuthentication, hasRole } from './authentication';
import RoleControl from './RoleControl';
import { useInterpretationAdmission } from './interpretationAdmission';
import InterpretationHistory from './InterpretationHistory';
import { useInterpretationRuns } from './useInterpretationRuns';
import { matchingInterpretationRecord } from './interpretationRuns';
import InterpretationProse from './InterpretationProse';
import { useReportLanguage } from './reportLanguageContext';
import { choose } from './reportTranslations';
import { useDDoSDetail } from './ddosDetailContext';

type Interpretation = {
  schema_version: 'ddos-interpretation-v1'; kind: 'MODEL_INTERPRETATION'; language: 'ko' | 'en';
  summary: string;
  risk_context: { interpretation: string; finding_ids: string[]; uncertainty: string }[];
  prioritized_checks: { priority: string; check: string; finding_ids: string[] }[];
  response_considerations: { consideration: string; finding_ids: string[]; requires_human_approval: true }[];
  limitations: string[];
};
type Run = { provider?: string; model_name?: string; completed_at?: string; analysis_job_id?: string; dataset_id?: string; created_at?: string; id: string; analysis_kind: string; status: string; language: 'ko' | 'en'; progress_percent?: number; error_code?: string; error_message?: string; ddos_interpretation?: Interpretation };
type Capabilities = { ddos_interpretation: boolean; available: boolean; provider: string; model_name: string; destination: string | null; remote: boolean; reason: string | null };
function newerRun(candidate: Run, previous?: Run, orderedRuns?: Run[]) {
  if (!previous || candidate.id === previous.id) return candidate;
  const candidateTime = Date.parse(candidate.created_at ?? '');
  const previousTime = Date.parse(previous.created_at ?? '');
  if (Number.isFinite(candidateTime) && Number.isFinite(previousTime) && candidateTime !== previousTime) {
    return candidateTime > previousTime ? candidate : previous;
  }
  // For legacy/matching timestamps, list order proves precedence only when it
  // includes the known run. A POST may arrive before any list contains its ID.
  return !orderedRuns || orderedRuns.some(run => run.id === previous.id) ? candidate : previous;
}
const activeStatuses = new Set(['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING']);
const boundedText = (value: unknown) => typeof value === 'string' ? (value.length > 2000 ? `${value.slice(0, 2000)}…` : value) : '';
const bounded = <T,>(value: T[]) => Array.isArray(value) ? value : [];
const proseText = (value: unknown) => typeof value === 'string' ? value : '';

export default function DDoSAIInterpretation({ jobId, completed }: { jobId: string; completed: boolean }) {
  const language = useReportLanguage();
  const admissionOwner = useInterpretationAdmission(jobId, 'DDOS_ATTACK');
  const { selectedId, setSelectedId, admission, start } = admissionOwner;
  const submitted = admissionOwner.knownRun as Run | undefined;
  const setSubmitted = admissionOwner.setKnownRun;
  const [newOpen, setNewOpen] = useState(false);
  const prosePosition = useRef({ section: 0, page: 0 });
  const [claimReturn, setClaimReturn] = useState<{ key: string; source?: string; id: string }>();
  const pendingFocus = useRef<string | undefined>(undefined);
  const selected = useQuery<Run, Error>({ queryKey: ['ai-run', selectedId], queryFn: () => api.get(`/ai-runs/${encodeURIComponent(selectedId!)}`), enabled: Boolean(selectedId), retry: false });
  const t = (en: string, ko: string) => choose(language, en, ko);
  const [localOpen, setLocalOpen] = useState(false);
  const shared = useDDoSDetail();
  const detailKey = `${shared?.prefix ?? jobId}:ai`;
  const open = shared ? shared.owner === detailKey : localOpen;
  const [authentication] = useState(captureAuthentication);
  const [ownerJob] = useState(jobId);
  const mounted = useRef(true);
  useLayoutEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const currentOwner = () => mounted.current && ownerJob === jobId && currentAuthentication(authentication) && (!shared || shared.current());
  const setOpen = (value: boolean) => { if (currentOwner()) { if (shared) shared.select(value ? detailKey : undefined); else setLocalOpen(value); } };
  const [consentedDestination, setConsentedDestination] = useState<string | null>(null);
  const capabilities = useQuery<Capabilities, Error>({ queryKey: ['ai-capabilities'], queryFn: () => api.get('/ai-capabilities'), enabled: hasRole('ANALYST'), retry: false });
  const config = capabilities.data;
  const allowRemote = Boolean(config?.remote && config.destination && consentedDestination === config.destination);
  const runs = useInterpretationRuns<Run>(jobId, 'DDOS_ATTACK');
  const displaySaved = runs.data?.items?.find(item => item.analysis_kind === 'DDOS_ATTACK');
  const saved = runs.data?.items?.find(row => row.analysis_kind === 'DDOS_ATTACK' && matchingInterpretationRecord(row, row, jobId)) ?? runs.data?.latestModule;
  const latest = saved ? newerRun(saved, submitted, runs.data?.items) : submitted;
  useLayoutEffect(() => { if (latest !== submitted) setSubmitted(latest); }, [latest, submitted, setSubmitted]);
  const detail = { ...admissionOwner.statusQuery, data: admissionOwner.statusQuery.data as Run | undefined };
  const controlled = latest && detail.data === undefined && !detail.isError ? latest : latest ? matchingInterpretationRecord(detail.data, latest, jobId) : undefined;
  const statusUnknown = Boolean(latest && (!controlled || detail.isError));
  const cancel = admissionOwner.cancellationFor(controlled?.id);
  const current = selectedId ? selected.data : latest ? controlled : displaySaved;
  const active = Boolean(controlled && activeStatuses.has(controlled.status));
  const canStart = completed && config?.available === true && config.ddos_interpretation === true
    && (!config.remote || allowRemote) && !capabilities.isError && runs.isSuccess && runs.data?.discovery === 'resolved' && !runs.discoveryError && !runs.continuationPending && !runs.isFetching && !detail.isError && !detail.isFetching && !statusUnknown && (!latest || detail.isSuccess) && !active;
  const result = current?.status === 'COMPLETED' ? decodeDDoSInterpretation(current.ddos_interpretation) : undefined;
  const navigationAllowed = currentOwner() && completed && current?.status === 'COMPLETED' && current.id === (selectedId ?? latest?.id ?? displaySaved?.id) && current.analysis_job_id === jobId && shared?.jobId === jobId && typeof current.dataset_id === 'string' && current.dataset_id.length > 0 && current.dataset_id === shared?.datasetId;
  // Public run responses omit ddos_input and carry no saved-report commitment.
  // IDs cannot authenticate historical measurements, even immediately after POST.
  const citations = (ids: string[], claim: string) => <span>{ids.map(id => <span key={id}><button type="button" className="secondary" disabled>{id}</button><button type="button" className="secondary" id={`ddos-claim:${jobId}:${claim}:${id}`} disabled={!navigationAllowed || !shared?.hasFinding?.(id)} onClick={event => { if (navigationAllowed && currentOwner() && shared?.hasFinding?.(id)) { setClaimReturn({ key: resultKey, source: shared.prefix, id: event.currentTarget.id }); shared.navigateFinding?.(id); } }}>{t('Inspect current report, not verified saved evidence:', '현재 보고서 조사 — 저장 근거 검증 아님:')} {id}</button></span>)}</span>;
  const resultKey = JSON.stringify([current?.id, result]);
  const [fullOwner, setFullOwner] = useState<string>();
  const [metadataOpen, setMetadataOpen] = useState(false);
  const [resultOwner, setResultOwner] = useState(resultKey);
  if (resultOwner !== resultKey) { setResultOwner(resultKey); setFullOwner(undefined); setMetadataOpen(false); prosePosition.current = { section: 0, page: 0 }; setClaimReturn(undefined); }
  useLayoutEffect(() => {
    if (open && pendingFocus.current && currentOwner()) { document.getElementById(pendingFocus.current)?.focus(); pendingFocus.current = undefined; }
  });
  const status = <>
    <InterpretationCancellationReceipts owner={admissionOwner}/>
    {(statusUnknown || detail.isError) && <button type="button" disabled={detail.isFetching} onClick={() => void detail.refetch()}>{t('Retry status lookup', '상태 조회 재시도')}</button>}
    {statusUnknown && <p role="status">{t('Current AI run status is unconfirmed.', '현재 AI 실행 상태를 확인할 수 없습니다.')}</p>}
    {start.isPending && <p role="status">{t('AI request pending — admission not yet confirmed.', 'AI 요청 대기 중 — 접수는 아직 확인되지 않았습니다.')}</p>}
    {admissionOwner.start.isError && <><p>{t('Retry preserves the original language, remote consent and request key.', '재시도는 원래 언어, 원격 동의와 요청 키를 유지합니다.')} {admissionOwner.start.variables?.body.language} · {admissionOwner.start.variables?.destination?.destination ?? '—'}</p><button type="button" disabled={admissionOwner.admissionRecovery === 'pending'} onClick={() => void admissionOwner.retryAdmission()}>{t('Retry exact AI request', '동일한 AI 요청 재시도')}</button></>}
    {admissionOwner.admissionRecovery === 'blocked' && <p role="status">{t('Original model destination or request receipt could not be confirmed; no new request is authorized.', '원래 모델 대상 또는 요청 응답을 확인하지 못했습니다. 새 요청은 허용되지 않습니다.')}</p>}
    {start.isError && <p role="status">{t('AI admission unconfirmed. Review the request before trying again.', 'AI 접수 미확인. 재시도 전에 요청을 확인하세요.')}</p>}
    {!open && (start.isPending || start.isError || current) && <button type="button" className="secondary" onClick={() => setOpen(true)}>{t('Return to DDoS AI interpretation', 'DDoS AI 해석으로 돌아가기')}</button>}
    {start.error && <p role="alert" className="error-text">{boundedText(start.error.message)}</p>}
    {controlled && <div className="ai-run-summary" role="status" aria-label={t('Latest AI run', '최신 AI 실행')}><span className={`badge ${active ? 'medium' : ''}`}>{language === 'ko' ? ({ QUEUED: '대기 중', PREPARING: '준비 중', ANALYZING: '해석 중', VALIDATING: '검증 중', COMPLETED: '완료', FAILED: '실패', CANCELLED: '취소됨' } as Record<string, string>)[controlled.status] ?? boundedText(controlled.status) : boundedText(controlled.status)}</span>{typeof controlled.progress_percent === 'number' && <progress max="100" value={Math.max(0, Math.min(100, controlled.progress_percent))}/>} {active && <RoleControl><button type="button" className="secondary" disabled={cancel.blocked || cancel.capacity || detail.isError} onClick={() => { if (currentOwner() && controlled) admissionOwner.requestCancellation(controlled, currentOwner); }}>{t('Cancel AI run', 'AI 실행 취소')}</button></RoleControl>}</div>}
    {current?.error_code && <p role="alert" className="error-text">{boundedText(current.error_code)}: {boundedText(current.error_message)}</p>}
  </>;
  return <section className="panel" aria-labelledby="ai-ddos-heading">
    <h2 id="ai-ddos-heading">{t('DDoS AI interpretation', 'DDoS AI 해석')}</h2>
    <button type="button" className="secondary" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? t('Close DDoS AI interpretation', 'DDoS AI 해석 닫기') : t('Open DDoS AI interpretation', 'DDoS AI 해석 열기')}</button>
    {!open && claimReturn?.key === resultKey && claimReturn.source === shared?.prefix && <button type="button" onClick={() => { if (!currentOwner()) return; pendingFocus.current = claimReturn.id; setOpen(true); }}>{t('Return to saved AI claim', '저장된 AI 주장으로 돌아가기')}</button>}
    {shared?.statusTarget ? createPortal(status, shared.statusTarget) : status}
    {open && <InterpretationHistory first={runs.data} jobId={jobId} kind="DDOS_ATTACK" selectedId={selectedId ?? latest?.id ?? displaySaved?.id} select={setSelectedId}/> }
    {open && runs.data?.discovery !== 'resolved' && <><p role="status">{t('Latest run is not yet confirmed; new admission is blocked.', '최신 실행 미확인 — 새 접수가 차단됩니다.')}</p>{runs.discoveryError && <><p role="alert">{t('Latest-run lookup failed; admission remains blocked.', '최신 실행 조회 실패 — 접수가 계속 차단됩니다.')}</p><button type="button" disabled={runs.isFetching || runs.continuationPending} onClick={() => void runs.refetch()}>{t('Retry latest-run lookup', '최신 실행 조회 재시도')}</button></>}{runs.data?.discovery === 'incomplete' ? <button type="button" disabled={runs.continuationPending || runs.isFetching} onClick={() => void runs.continueLookup()}>{t('Continue latest-run lookup', '최신 실행 조회 계속')}</button> : <button type="button" disabled={runs.isFetching} onClick={() => void runs.refetch()}>{t('Retry latest-run lookup', '최신 실행 조회 재시도')}</button>}</>}
    {open && selected.isError && <p role="alert">{t('Saved AI result could not be read.', '저장된 AI 결과를 읽지 못했습니다.')}</p>}
    {!completed && <p className="muted">{t('A completed DDoS report is required.', '완료된 DDoS 보고서가 필요합니다.')}</p>}
    {(capabilities.isError || runs.isError || detail.isError) && <p role="alert" className="error-text">{t('AI status lookup failed.', 'AI 상태 조회에 실패했습니다.')}</p>}
    {config && (!config.available || !config.ddos_interpretation) && <p role="alert" className="error-text">{t('DDoS AI interpretation is unavailable', 'DDoS AI 해석을 사용할 수 없습니다')}: {config.reason}</p>}
    {open && current?.status === 'COMPLETED' && !result && <p role="alert">{t('No validated interpretation is available for this run.', '이 실행의 검증된 해석 결과가 없습니다.')}</p>}
    {open && result && <>
      <p>{t('Saved-source verification is unavailable; finding IDs do not verify saved measurements.', '저장 원본 검증을 사용할 수 없습니다. 발견 ID는 저장된 측정값을 검증하지 않습니다.')}</p>
      <h3>{t('AI-generated interpretation — analyst review required', 'AI 생성 해석 — 분석가 검토 필요')}</h3>
      <InterpretationProse initialPosition={prosePosition.current} onPositionChange={value => { prosePosition.current = value; }} key={resultKey} summary={proseText(result.summary)} language={result.language} full={fullOwner === resultKey} setFull={value => setFullOwner(value ? resultKey : undefined)} title={t('Full DDoS AI interpretation', 'DDoS AI 해석 전체 원문')} sections={[
        { title: t('Risk context', '위험 문맥'), count: bounded(result.risk_context).length, render: index => { const item = result.risk_context[index]; return <><p lang={result.language}>{proseText(item.interpretation)}</p><p lang={result.language}>{proseText(item.uncertainty)}</p>{citations(item.finding_ids, `risk:${index}`)}</>; } },
        { title: t('Prioritized checks', '우선 확인 사항'), count: bounded(result.prioritized_checks).length, render: index => { const item = result.prioritized_checks[index]; return <><strong>{proseText(item.priority)}</strong><p lang={result.language}>{proseText(item.check)}</p>{citations(item.finding_ids, `check:${index}`)}</>; } },
        { title: t('Response considerations', '대응 검토 사항'), count: bounded(result.response_considerations).length, render: index => { const item = result.response_considerations[index]; return <><p lang={result.language}>{proseText(item.consideration)}</p><p>{t('human approval required', '운영자 승인 필요')}</p>{citations(item.finding_ids, `response:${index}`)}</>; } },
        { title: t('Limitations', '한계'), count: bounded(result.limitations).length, render: index => <p lang={result.language}>{proseText(result.limitations[index])}</p> },
      ]}/>
    </>}
    {open && result && <>
      <details key={`metadata:${resultKey}`} onToggle={event => setMetadataOpen(event.currentTarget.open)}><summary>{t('Saved run metadata', '저장 실행 메타데이터')}</summary>{metadataOpen && <>
        <p>{t('Saved run provider / model', '저장된 실행 제공자 / 모델')}: {boundedText(current?.provider) || t('Not reported', '보고되지 않음')} · {boundedText(current?.model_name) || t('Not reported', '보고되지 않음')}</p>
        <p>{t('Generated language', '생성 언어')}: {result.language === 'ko' ? '한국어' : 'English'} · {t('Completed at', '완료 시각')}: {boundedText(current?.completed_at) || '—'}</p>
        <p>{t('Existing AI output is not automatically translated. Changing report language changes labels only; use the manual button for a new interpretation.', '기존 AI 출력은 자동 번역되지 않습니다. 보고서 언어 변경은 항목명만 바꾸며 새 해석은 버튼으로 직접 요청하세요.')}</p>
      </>}</details>
    </>}
    {open && <RoleControl><button type="button" className="secondary" aria-expanded={newOpen} onClick={() => setNewOpen(!newOpen)}>{t('New AI interpretation', '새 AI 해석')}</button></RoleControl>}
    {hasRole('ANALYST') && open && newOpen && <>
      <p>{t('AI explains the saved deterministic report; it cannot change the verdict, attribute an actor, prove impact, or execute a response.', 'AI는 저장된 결정론적 보고서를 설명할 뿐 판정 변경, 공격자 귀속, 영향 입증, 대응 실행을 할 수 없습니다.')}</p>
      <p className="muted">{t('Manual only. Only a bounded report projection is sent; raw packets and payloads are excluded.', '수동 실행 전용입니다. 제한된 보고서 투영만 전송하며 원시 패킷과 페이로드는 제외합니다.')}</p>
      {config && <p>{config.provider} · {config.model_name} · {config.destination ?? t('Local or not reported', '로컬 또는 보고되지 않음')}</p>}
      {config?.remote && <label className="check"><input type="checkbox" checked={allowRemote} onChange={event => setConsentedDestination(event.target.checked ? config.destination : null)}/>{t('I consent to this remote destination.', '이 원격 대상 전송에 동의합니다.')}</label>}
      <button type="button" disabled={!canStart || start.isPending || start.isError} onClick={() => { if (currentOwner() && canStart && !admission.current) { admission.current = true; start.mutate({ destination: config ? { remote: config.remote, destination: config.destination, provider: config.provider, model_name: config.model_name } : undefined, current: admissionOwner.current, knownRunId: latest?.id, body: { idempotency_key: `web-ddos-${jobId}-${crypto.randomUUID()}`, analysis_kind: 'DDOS_ATTACK', language, allow_remote: allowRemote } }); } }}>{start.isPending ? t('Starting…', '시작 중…') : t('Run DDoS AI interpretation', 'DDoS AI 해석 실행')}</button>
    </>}
  </section>;
}
