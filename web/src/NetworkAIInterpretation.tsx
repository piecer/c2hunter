import InterpretationCancellationReceipts from './InterpretationCancellationReceipts';
import NetworkNumericEvidence from './NetworkNumericEvidence';
import { networkCitationScope } from './networkCitationScopes';
import { networkRunDisplay, networkRunRecord, networkRunItems, currentNumericSource } from './networkNumericEvidence';
import { citationTarget, evidenceSignature, useNetworkEvidence } from './networkEvidenceContext';
import { useReportDetail } from './reportDetailContext';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from './api';
import { captureAuthentication, currentAuthentication } from './authentication';
import { useInterpretationAdmission } from './interpretationAdmission';
import InterpretationHistory from './InterpretationHistory';
import { useInterpretationRuns } from './useInterpretationRuns';
import { matchingInterpretationRecord } from './interpretationRuns';
import InterpretationProse from './InterpretationProse';
import { useReportLanguage } from './reportLanguageContext';
import { choose } from './reportTranslations';

type Interpretation = { schema_version: 'network-interpretation-v1' | 'network-interpretation-v2'; kind: 'MODEL_INTERPRETATION'; language: 'ko' | 'en'; summary: string; possible_causes: { hypothesis: string; issue_ids: string[]; uncertainty: string }[]; prioritized_checks: { priority: string; check: string; issue_ids: string[] }[]; correlations: { interpretation: string; issue_ids: string[] }[]; limitations: string[] };
type FailureDiagnostic = { stage: 'MODEL_OUTPUT'; type: 'JSON_PARSE' | 'SCHEMA' | 'INVALID_CITATION' | 'INVALID_NUMERIC_REFERENCE' | 'LANGUAGE'; attempt_count: number; repair_count: number; output_bytes: number; provider_finish_reason?: 'stop' | 'length' | 'load' | 'unload' | 'tool_calls' | 'content_filter' | null };
type Run = { input_schema_version?: string; analysis_job_id?: string; dataset_id?: string; network_input?: unknown; network_numeric_evidence?: unknown; id: string; analysis_kind: string; status: string; language: 'ko' | 'en'; created_at?: string; completed_at?: string; provider?: string; model_name?: string; progress_percent?: number; error_code?: string; error_message?: string; failure_diagnostic?: FailureDiagnostic | null; network_interpretation?: Interpretation };
const activeStatuses = new Set(['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING']);
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
const boundedText = (value: unknown) => typeof value === 'string' ? (value.length > 2000 ? `${value.slice(0, 2000)}…` : value) : '';
const boundedItems = <T,>(value: T[]) => Array.isArray(value) ? value.slice(0, 20) : [];
type Capabilities = { network_interpretation: boolean; available: boolean; provider: string; model_name: string; destination: string | null; remote: boolean; reason: string | null };
export default function NetworkAIInterpretation({ jobId, completed }: { jobId: string; completed: boolean }) {
  const language = useReportLanguage();
  const admissionOwner = useInterpretationAdmission(jobId, 'NETWORK_ANOMALY');
  const { selectedId, setSelectedId, admission, start } = admissionOwner;
  const knownRun = admissionOwner.knownRun as Run | undefined;
  const setKnownRun = admissionOwner.setKnownRun;
  const [newOpen, setNewOpen] = useState(false);
  const selected = useQuery<Run, Error>({ queryKey: ['ai-run', selectedId], queryFn: () => api.get(`/ai-runs/${encodeURIComponent(selectedId!)}`), enabled: Boolean(selectedId), retry: false });
  const detail = useReportDetail();
  const evidence = useNetworkEvidence();
  const [authentication] = useState(captureAuthentication);
  const [ownerJob] = useState(jobId);
  const mounted = useRef(true);
  useLayoutEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const currentOwner = () => mounted.current && ownerJob === jobId && currentAuthentication(authentication) && (!evidence || evidence.current());
  const [expanded, setOpen] = useState(false);
  const open = expanded && (!detail || detail.owner === 'ai');
  const [fullOwner, setFullOwner] = useState<string>();
  const [metadataOpen, setMetadataOpen] = useState(false);
  const prosePosition = useRef({ section: 0, page: 0 });
  const [claimReturn, setClaimReturn] = useState<{ key: string; generation?: object; id: string }>();
  const pendingFocus = useRef<string | undefined>(undefined);
  const t = (en: string, ko: string) => choose(language, en, ko);
  const client = useQueryClient();
  const capabilities = useQuery<Capabilities, Error>({ queryKey: ['ai-capabilities'], queryFn: () => api.get('/ai-capabilities'), retry: false });
  const config = capabilities.data;
  const [consentedDestination, setConsentedDestination] = useState<string | null>(null);
  const allowRemote = Boolean(config?.remote && config.destination && consentedDestination === config.destination);
  const runs = useInterpretationRuns<Run>(jobId, 'NETWORK_ANOMALY');
  const items = runs.isSuccess ? networkRunItems(runs.data) : [];
  const displaySaved = items.find(run => run.analysis_kind === 'NETWORK_ANOMALY');
  const saved = items.find(row => row.analysis_kind === 'NETWORK_ANOMALY' && matchingInterpretationRecord(row, row, jobId)) ?? networkRunRecord(runs.data?.latestModule);
  // Keep the newest observed identity through lagging/failed lists, while letting
  // the authoritative list supersede a POST response as soon as it knows more.
  const known = networkRunRecord(knownRun);
  const latest = saved ? newerRun(saved, known, items) : known;
  useLayoutEffect(() => { if (latest !== knownRun) setKnownRun(latest); }, [latest, knownRun, setKnownRun]);
  const run = { ...admissionOwner.statusQuery, data: admissionOwner.statusQuery.data as Run | undefined };
  // A malformed detail is not permission to fall back to a valid list result.
  const controlled = latest && run.data === undefined && !run.isError ? latest : latest ? matchingInterpretationRecord(run.data, latest, jobId) : undefined;
  const statusUnknown = Boolean(latest && (!controlled || run.isError));
  const cancel = admissionOwner.cancellationFor(controlled?.id);
  // A previously read bounded result can remain visible when the status GET is
  // malformed. It supplies neither current status nor navigation authority.
  const current = selectedId ? networkRunRecord(selected.data) : latest ? controlled ?? latest : displaySaved;
  const active = Boolean(controlled && activeStatuses.has(controlled.status));
  const supportedSource = !evidence || evidence.projection.summaryTrusted && evidence.projection.familyCoverage.state !== 'invalid' && evidence.projection.slots.every(slot => !slot.invalid && !slot.examplesInvalid && !slot.examplesExceeded && !slot.notesMissing);
  const canStart = completed && supportedSource && config?.available === true && config.network_interpretation === true && (!config.remote || allowRemote) && !capabilities.isError && runs.isSuccess && runs.data?.discovery === 'resolved' && !runs.discoveryError && !runs.continuationPending && !runs.isFetching && !run.isError && !run.isFetching && !statusUnknown && (!latest || run.isSuccess) && !active;
  const display = networkRunDisplay(current);
  const numeric = display.numeric;
  const v2 = display.version === 'v2';
  const result = display.output as Interpretation | undefined;
  const proseText = (value: unknown) => typeof value === 'string' ? value : '';
  const retained = <T,>(value: T[]) => Array.isArray(value) ? value : [];
  // List GET and detail GET can carry identical saved output as different objects.
  // Preserve expansion across that handoff, but never revive changed output.
  const resultKey = JSON.stringify([current?.id, result]);
  const [resultOwner, setResultOwner] = useState(resultKey);
  if (resultOwner !== resultKey) {
    setResultOwner(resultKey);
    setFullOwner(undefined);
    setMetadataOpen(false);
    prosePosition.current = { section: 0, page: 0 };
    setClaimReturn(undefined);
  }
  const signature = evidence ? evidenceSignature(evidence.projection) : '';
  const numericKey = v2 && current?.status === 'COMPLETED' ? JSON.stringify(numeric ?? null) : undefined;
  const navigationAllowed = currentOwner() && networkCitationScope(client, authentication.epoch, jobId, current?.id, signature, numericKey) && Boolean(selectedId || !statusUnknown);
  const numericAllowed = navigationAllowed && !runs.isError && !run.isError && Boolean(current && numeric && currentNumericSource(evidence, current, selectedId ?? latest?.id ?? displaySaved?.id, numeric));
  const navigationOwner = useRef<object | undefined>(undefined);
  const navigationToken = { jobId, runId: current?.id, generation: evidence?.generation };
  navigationOwner.current = navigationToken;
  useEffect(() => () => { navigationOwner.current = undefined; }, []);
  useLayoutEffect(() => {
    if (open && pendingFocus.current && currentOwner()) { document.getElementById(pendingFocus.current)?.focus(); pendingFocus.current = undefined; }
  });
  const citations = (values: string[], claim: string) => {
    const ids = [...new Set(boundedItems(values).map(id => boundedText(id)))];
    // V2 source/output admission is atomic and already computed once per render.
    // Do not traverse the complete output again for each of 600 citation buttons.
    const targets = ids.map(id => v2 ? numericAllowed
      ? { index: evidence?.projection.slots.find(s => s.issue?.id === id)?.index }
      : { reason: 'source' as const }
      : citationTarget(navigationAllowed ? evidence : undefined, current, selectedId ?? latest?.id ?? displaySaved?.id, id));
    return <span>{ids.map((id, index) => <button type="button" className="secondary" key={id} id={`network-claim:${jobId}:${claim}:${index}`} disabled={targets[index].index === undefined} onClick={event => { if (navigationOwner.current !== navigationToken || !navigationAllowed || v2 && !numericAllowed) return; const target = citationTarget(evidence, current, selectedId ?? latest?.id ?? displaySaved?.id, id); if (target.index !== undefined) { setClaimReturn({ key: resultKey, generation: evidence?.generation, id: event.currentTarget.id }); evidence?.navigate(target.index); } }} style={{ overflowWrap: 'anywhere', maxWidth: '100%' }}>{id}</button>)}{targets.some(target => target.reason) && <small>{targets.some(target => target.reason === 'source') ? t('Cannot navigate: provenance does not match the current report.', '현재 보고서와 출처를 확인할 수 없어 이동할 수 없습니다.') : targets.some(target => target.reason === 'ambiguous') ? t('Cannot navigate: issue ID is missing or ambiguous.', '이슈 ID가 없거나 중복되어 이동할 수 없습니다.') : t('Not in this AI run input evidence.', '이 AI 실행의 입력 근거에 없음.')}</small>}</span>;
  };
  // Lookup only static labels; never echo unknown diagnostic values from older/newer servers.
  const failureLabels = new Map<string, string>([
    ['JSON_PARSE', t('Invalid JSON response', 'JSON 응답 해석 실패')],
    ['SCHEMA', t('Response schema mismatch', '응답 구조 검증 실패')],
    ['INVALID_CITATION', t('Invalid issue references', '이슈 참조 검증 실패')],
    ['INVALID_NUMERIC_REFERENCE', t('Invalid numeric references', '수치 참조 검증 실패')],
    ['LANGUAGE', t('Requested language mismatch', '요청 언어 불일치')],
  ]);
  const failureLabel = current?.status === 'FAILED' && current.error_code === 'MODEL_OUTPUT_INVALID' && current.failure_diagnostic?.stage === 'MODEL_OUTPUT' ? failureLabels.get(current.failure_diagnostic.type) : undefined;
  return <section className="panel" aria-labelledby="ai-network-heading">
    <h2 id="ai-network-heading">{t('AI interpretation', 'AI 해석')}</h2>
    <button type="button" className="secondary" aria-expanded={open} onClick={() => { setOpen(!open); detail?.claim('ai'); setFullOwner(undefined); }}>{open ? t('Close AI interpretation', 'AI 해석 닫기') : t('Open AI interpretation', 'AI 해석 열기')}</button>
    {!open && claimReturn?.key === resultKey && claimReturn.generation === evidence?.generation && <button type="button" onClick={() => { if (!currentOwner()) return; pendingFocus.current = claimReturn.id; setOpen(true); detail?.claim('ai'); }}>{t('Return to cited AI claim', '인용한 AI 주장으로 돌아가기')}</button>}
    {open && <InterpretationHistory first={runs.data} jobId={jobId} kind="NETWORK_ANOMALY" selectedId={selectedId ?? latest?.id ?? displaySaved?.id} select={setSelectedId}/> }
    {open && runs.data?.discovery !== 'resolved' && <><p role="status">{t('Latest run is not yet confirmed; new admission is blocked.', '최신 실행 미확인 — 새 접수가 차단됩니다.')}</p>{runs.discoveryError && <><p role="alert">{t('Latest-run lookup failed; admission remains blocked.', '최신 실행 조회 실패 — 접수가 계속 차단됩니다.')}</p><button type="button" disabled={runs.isFetching || runs.continuationPending} onClick={() => void runs.refetch()}>{t('Retry latest-run lookup', '최신 실행 조회 재시도')}</button></>}{runs.data?.discovery === 'incomplete' ? <button type="button" disabled={runs.continuationPending || runs.isFetching} onClick={() => void runs.continueLookup()}>{t('Continue latest-run lookup', '최신 실행 조회 계속')}</button> : <button type="button" disabled={runs.isFetching} onClick={() => void runs.refetch()}>{t('Retry latest-run lookup', '최신 실행 조회 재시도')}</button>}</>}
    {open && selected.isError && <p role="alert">{t('Saved AI result could not be read.', '저장된 AI 결과를 읽지 못했습니다.')}</p>}
    {!completed && <p className="muted">{t('A completed job with a saved network report is required.', '저장된 네트워크 보고서가 있는 완료된 작업에서만 실행할 수 있습니다.')}</p>}
    {capabilities.isLoading && <p role="status">{t('Checking AI availability…', 'AI 사용 가능 여부 확인 중…')}</p>}
    {(capabilities.isError || (config && (!config.available || !config.network_interpretation))) && <p role="alert" className="error-text">{t('AI interpretation is unavailable', 'AI 해석을 사용할 수 없습니다')}: {capabilities.error?.message ?? config?.reason ?? t('Not enabled', '비활성화됨')}</p>}
    {statusUnknown && <p role="status">{t('Current AI run status is unconfirmed.', '현재 AI 실행 상태를 확인할 수 없습니다.')}</p>}
    {start.isPending && <p role="status">{t('AI request pending — admission not yet confirmed.', 'AI 요청 대기 중 — 접수는 아직 확인되지 않았습니다.')}</p>}
    {admissionOwner.start.isError && <><p>{t('Retry preserves the original language, remote consent and request key.', '재시도는 원래 언어, 원격 동의와 요청 키를 유지합니다.')} {admissionOwner.start.variables?.body.language} · {admissionOwner.start.variables?.destination?.destination ?? '—'}</p><button type="button" disabled={admissionOwner.admissionRecovery === 'pending'} onClick={() => void admissionOwner.retryAdmission()}>{t('Retry exact AI request', '동일한 AI 요청 재시도')}</button></>}
    {admissionOwner.admissionRecovery === 'blocked' && <p role="status">{t('Original model destination or request receipt could not be confirmed; no new request is authorized.', '원래 모델 대상 또는 요청 응답을 확인하지 못했습니다. 새 요청은 허용되지 않습니다.')}</p>}
    {start.isError && <p role="status">{t('AI admission unconfirmed. Review the request before trying again.', 'AI 접수 미확인. 재시도 전에 요청을 확인하세요.')}</p>}
    {!open && (start.isPending || start.isError) && <button type="button" onClick={() => { setOpen(true); detail?.claim('ai'); }}>{t('Return to AI interpretation', 'AI 해석으로 돌아가기')}</button>}
    {start.error && <p role="alert" className="error-text">{t('AI run could not be started', 'AI 실행을 시작하지 못했습니다')}: {start.error.message}</p>}
    {runs.isLoading && <p role="status">{t('Loading saved AI runs…', '저장된 AI 실행 조회 중…')}</p>}
    {(runs.isError || run.isError) && <p role="alert" className="error-text">{t('Saved AI run could not be read; status is unconfirmed', '저장된 AI 실행을 읽지 못했습니다. 상태를 확인할 수 없습니다')}: {boundedText(runs.error?.message ?? run.error?.message)}</p>}
    {(statusUnknown || capabilities.isError || runs.isError || run.isError) && <button type="button" className="secondary" disabled={capabilities.isFetching || runs.isFetching || run.isFetching} onClick={() => { void capabilities.refetch(); void runs.refetch(); if (latest) void run.refetch(); }}>{t('Retry status lookup', '상태 조회 재시도')}</button>}
    {!runs.isLoading && !runs.isError && !current && <p className="muted">{t('No saved AI interpretation runs.', '저장된 AI 해석 실행이 없습니다.')}</p>}
    {controlled && <><div className="ai-run-summary" role="status" aria-label={t('Latest AI run', '최신 AI 실행')}><span className={`badge ${active ? 'medium' : ''}`}>{t(({ QUEUED: 'Queued', PREPARING: 'Preparing', ANALYZING: 'Analyzing', VALIDATING: 'Validating', COMPLETED: 'Completed', FAILED: 'Failed', CANCELLED: 'Cancelled' } as Record<string, string>)[controlled.status] ?? boundedText(controlled.status), ({ QUEUED: '대기 중', PREPARING: '준비 중', ANALYZING: '해석 중', VALIDATING: '검증 중', COMPLETED: '완료', FAILED: '실패', CANCELLED: '취소됨' } as Record<string, string>)[controlled.status] ?? boundedText(controlled.status))}</span><span>{t('Requested language', '요청 언어')}: {controlled.language === 'ko' ? '한국어' : 'English'}</span><span>{t('Run created', '실행 생성')}: {boundedText(controlled.created_at) || '—'}</span></div>
      {typeof controlled.progress_percent === 'number' && Number.isFinite(controlled.progress_percent) && <progress aria-label={t('AI interpretation progress', 'AI 해석 진행률')} max="100" value={Math.max(0, Math.min(100, controlled.progress_percent))}/>}

    </>}
    <InterpretationCancellationReceipts owner={admissionOwner}/>
    {current && <>
      {current.error_code && <p role="alert" className="error-text">{boundedText(current.error_code)}: {boundedText(current.error_message)}</p>}
      {failureLabel && <p className="error-text">{failureLabel}</p>}
      {current.status === 'COMPLETED' && !result && <p role="alert">{t('No validated interpretation is available for this run.', '이 실행의 검증된 해석 결과가 없습니다.')}</p>}
    </>}
      {active && <button type="button" className="secondary" disabled={cancel.blocked || cancel.capacity || run.isError} onClick={() => { if (currentOwner() && controlled) admissionOwner.requestCancellation(controlled, currentOwner); }}>{cancel.pending ? t('Requesting cancellation…', '취소 요청 중…') : t('Cancel AI run', 'AI 실행 취소')}</button>}
    {open && v2 && <NetworkNumericEvidence value={numeric} allowed={numericAllowed} navigate={(id, reference) => { if (navigationOwner.current !== navigationToken || !numericAllowed) return; const target = citationTarget(evidence, current, selectedId ?? latest?.id ?? displaySaved?.id, id); if (target.index !== undefined) { setFullOwner(undefined); evidence?.navigate(target.index, { exampleIndex: typeof reference.example_index === 'number' ? reference.example_index : undefined, measurement: reference.kind === 'measurement' ? reference.metric === 'ttl_observed' ? 'ttl' : reference.metric === 'interarrival_variation_ms' ? 'spacing' : 'rtt' : undefined }); } }}/> }
    {open && result && <><p>{v2 ? t('AI prose — numerical claims are unverified.', 'AI 원문 — 수치 주장은 검증되지 않았습니다.') : t('Legacy AI output — no verified numeric evidence.', '이전 AI 출력 — 검증된 수치 근거 없음.')}</p><p className="muted">{t('AI-generated interpretation — analyst review required; not a confirmed diagnosis.', 'AI 생성 해석 — 분석가 검토 필요; 확정 진단이 아닙니다.')}</p>
      <InterpretationProse initialPosition={prosePosition.current} onPositionChange={value => { prosePosition.current = value; }} key={resultKey} summary={proseText(result.summary)} language={result.language} full={fullOwner === resultKey} setFull={value => setFullOwner(value ? resultKey : undefined)} title={t('Full AI interpretation', 'AI 해석 전체 원문')} sections={[
        { title: t('Possible causes (AI hypotheses)', '가능한 원인 (AI 가설)'), count: retained(result.possible_causes).length, render: index => { const cause = result.possible_causes[index]; return <><p lang={result.language}>{proseText(cause?.hypothesis)}</p><strong>{t('Confidence / uncertainty', '신뢰도 / 불확실성')}</strong><p lang={result.language}>{proseText(cause?.uncertainty)}</p>{citations(cause?.issue_ids, `cause:${index}`)}</>; } },
        { title: t('Prioritized next checks', '우선순위별 다음 확인 사항'), count: retained(result.prioritized_checks).length, render: index => { const check = result.prioritized_checks[index]; return <><strong>{proseText(check?.priority)}</strong><p lang={result.language}>{proseText(check?.check)}</p>{citations(check?.issue_ids, `check:${index}`)}</>; } },
        { title: t('Possible correlations', '가능한 연관성'), count: retained(result.correlations).length, render: index => { const item = result.correlations[index]; return <><p lang={result.language}>{proseText(item?.interpretation)}</p>{citations(item?.issue_ids, `correlation:${index}`)}</>; } },
        { title: t('Limitations', '한계'), count: retained(result.limitations).length, render: index => <p lang={result.language}>{proseText(result.limitations[index])}</p> },
      ]}/>
      <details key={`metadata:${resultKey}`} onToggle={event => setMetadataOpen(event.currentTarget.open)}><summary>{t('Saved run metadata', '저장 실행 메타데이터')}</summary>{metadataOpen && <>
        <p>{t('Saved run provider / model', '저장된 실행 제공자 / 모델')}: {boundedText(current?.provider) || t('Not reported', '보고되지 않음')} · {boundedText(current?.model_name) || t('Not reported', '보고되지 않음')}</p>
        <p>{t('Generated language', '생성 언어')}: {result.language === 'ko' ? '한국어' : 'English'} · {t('Completed at', '완료 시각')}: {boundedText(current?.completed_at) || '—'}</p>
        <p>{t('Existing AI output is not automatically translated. Changing report language changes labels only; use the manual button for a new interpretation.', '기존 AI 출력은 자동 번역되지 않습니다. 보고서 언어 변경은 항목명만 바꾸며 새 해석은 버튼으로 직접 요청하세요.')}</p>
      </>}</details>
    </>}
    {open && <button type="button" className="secondary" aria-expanded={newOpen} onClick={() => setNewOpen(!newOpen)}>{t('New AI interpretation', '새 AI 해석')}</button>}
    {open && newOpen && <><div className="header-actions"><div><p className="eyebrow">{t('BOUNDED REPORT EVIDENCE', '제한된 보고서 증거')}</p></div><div className="ai-run-controls"><button type="button" disabled={!canStart || start.isPending || start.isError} onClick={() => { if (currentOwner() && canStart && !admission.current) { admission.current = true; start.mutate({ destination: config ? { remote: config.remote, destination: config.destination, provider: config.provider, model_name: config.model_name } : undefined, current: admissionOwner.current, knownRunId: latest?.id, body: { idempotency_key: `web-${jobId}-${crypto.randomUUID()}`, analysis_kind: 'NETWORK_ANOMALY', language, allow_remote: allowRemote } }); } }}>{start.isPending ? t('Starting…', '시작 중…') : t('AI interpretation', 'AI 해석')}</button></div></div>
    <p>{t('Observed facts are in the deterministic report above. AI offers possible causes and next checks, not proven root causes or attack classifications.', '관찰된 사실은 위의 결정론적 보고서에 있습니다. AI는 가능한 원인과 다음 확인 사항을 제안하며 근본 원인이나 공격 여부를 확정하지 않습니다.')}</p>
    <p className="muted">{t('Manual only. The server sends a bounded report context to the configured model, not raw packets or payload. No inference runs on page load or language change.', '수동 실행 전용입니다. 서버는 원시 패킷이나 페이로드 대신 제한된 보고서 문맥을 설정된 모델에 보냅니다. 페이지 로드나 언어 변경으로 AI가 실행되지 않습니다.')}</p>
    {config && <p>{t('Provider / model / destination', '제공자 / 모델 / 전송 대상')}: {config.provider} · {config.model_name} · {config.destination ?? t('Not reported', '보고되지 않음')}</p>}
    {config?.remote && <label className="check"><input type="checkbox" checked={allowRemote} disabled={!config.destination || start.isPending} onChange={event => setConsentedDestination(event.target.checked ? config.destination : null)}/>{t('I consent to sending bounded report evidence to this remote model destination.', '이 원격 모델 대상에 제한된 보고서 증거를 전송하는 데 동의합니다.')}</label>}
    </>}
  </section>;
}
